"use strict";

const $ = (selector) => document.querySelector(selector);
const escapeHTML = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
const icon = (name) => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const statuses = { new: "Новое", processing: "В обработке", analyzed: "Разобрано", confirmed: "Подтверждено", false_positive: "Ложное", error: "Ошибка" };
const modes = { llm: "LLM", hybrid: "LLM + правила", rules_only: "Только правила" };
const errorLabels = {
  not_configured: "LLM не настроен", credentials_rejected: "Провайдер отклонил ключ", permission_denied: "Провайдер запретил доступ",
  configuration_error: "Проверьте модель и URL провайдера", quota_or_rate_limit: "Квота или ограничение частоты провайдера",
  provider_busy: "Лимит одновременных обращений к LLM", timeout: "Таймаут LLM", network_error: "Ошибка соединения с LLM",
  provider_error: "Ошибка провайдера", invalid_response: "Ответ LLM не прошел проверку", unsupported_evidence: "Цитата не подтверждена источником",
  unsupported_action: "Действие вне Playbook", unsafe_content: "Недопустимое содержание ответа", response_too_large: "Слишком большой ответ",
  truncated_response: "Ответ прерван по лимиту токенов", cancelled: "Запрос отменен", storage_error: "Ошибка хранилища", lease_expired: "Истек срок выполнения",
};
const state = {
  alerts: [], alertTotal: 0, nextAlertCursor: null, alertsQuery: "", stats: null, view: "dashboard", token: "",
  authRequired: false, authBlocked: false, selected: null, analyses: [], shownAnalysis: null, busy: new Set(),
  history: [], historyHasMore: false, historyLoading: false, connected: false, networkFailure: 0,
  refreshing: false, loadingMore: false, refreshID: 0, detailID: 0, historyID: 0,
};
let toastTimer, searchTimer;

function dateTime(value, compact = false) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Время неизвестно";
  return new Intl.DateTimeFormat("ru-RU", compact ? { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" } : { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(date);
}
function badge(value, kind = "severity") {
  const allowed = kind === "status" ? Object.keys(statuses) : ["low", "medium", "high", "critical"];
  const safe = allowed.includes(value) ? value : "unknown";
  return `<span class="badge ${kind}-${safe} ${kind === "status" ? "status-badge" : ""}">${escapeHTML(kind === "status" ? statuses[safe] : safe === "unknown" ? "Не оценено" : safe[0].toUpperCase() + safe.slice(1))}</span>`;
}
function toast(message, error = false) {
  clearTimeout(toastTimer);
  $("#toast").textContent = message;
  $("#toast").classList.toggle("error", error);
  $("#toast").hidden = false;
  toastTimer = setTimeout(() => { $("#toast").hidden = true; }, 6000);
}
function connection(online) {
  state.connected = online;
  $("#connection").classList.toggle("offline", !online);
  $("#connection").innerHTML = `<span class="status-dot"></span>${online ? "Система онлайн" : "Нет соединения"}`;
  $("#offline-banner").hidden = online;
}
function lockProtectedData() {
  state.authBlocked = true;
  state.alerts = []; state.stats = null; state.history = []; state.analyses = [];
  state.alertTotal = 0; state.nextAlertCursor = null; state.selected = null; state.shownAnalysis = null;
  ++state.refreshID; ++state.historyID; ++state.detailID;
  state.refreshing = false; state.historyLoading = false;
  $("#refresh").disabled = false;
  $("#detail-body").replaceChildren();
  if ($("#detail-dialog").open) $("#detail-dialog").close();
  $("#auth-banner").hidden = false;
  renderStats(); renderAlerts(); renderHistory();
}
async function api(path, options = {}) {
  const failureVersion = state.networkFailure;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.method === "POST" && path.endsWith("/analyze") ? 185000 : 15000);
  let response;
  try {
    response = await fetch(path, { ...options, signal: controller.signal, headers: { "Content-Type": "application/json", ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}), ...options.headers } });
  } catch (error) {
    ++state.networkFailure;
    connection(false);
    throw new Error(error.name === "AbortError" ? "Запрос превысил время ожидания. Обновите событие перед повторным запуском." : "Нет соединения с backend.");
  } finally { clearTimeout(timer); }
  if (failureVersion === state.networkFailure) connection(true);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) {
      state.authRequired = true;
      if (!state.authBlocked) lockProtectedData();
      if (!$("#access-dialog").open) $("#access-dialog").showModal();
    }
    const error = new Error(typeof body.detail === "string" ? body.detail : `Ошибка запроса (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return body;
}
function queryValues() { return { q: $("#search").value.trim(), status: $("#status-filter").value }; }
function queryKey(values = queryValues()) { return JSON.stringify(values); }
function pageURL(values, limit, cursor = null) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (values.q) params.set("q", values.q);
  if (values.status) params.set("status", values.status);
  if (cursor) params.set("cursor", cursor);
  return "/api/alerts/page?" + params;
}
async function fetchAlertWindow(size) {
  const values = queryValues();
  const result = { items: [], total: 0, next_cursor: null, query: queryKey(values) };
  do {
    const page = await api(pageURL(values, Math.min(500, size - result.items.length), result.next_cursor));
    result.items.push(...page.items);
    result.total = page.total; result.next_cursor = page.next_cursor;
  } while (result.next_cursor && result.items.length < size);
  return result;
}
function route() {
  const view = location.hash.slice(1);
  state.view = ["dashboard", "alerts", "history"].includes(view) ? view : "dashboard";
  const titles = {
    dashboard: ["Dashboard", "Обзор безопасности", "Каждый сигнал — в контексте. Каждое решение — за вами."],
    alerts: ["Alerts", "Очередь событий", "Проверяйте признаки, разбирайте события и фиксируйте решения."],
    history: ["History", "История анализов", "Полная история выводов AI и решений аналитика."],
  };
  const [crumb, title, subtitle] = titles[state.view];
  $("#breadcrumb").textContent = crumb; $("#page-title").textContent = title; $("#page-subtitle").textContent = subtitle;
  document.querySelectorAll("[data-view]").forEach((link) => {
    const active = link.dataset.view === state.view;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  });
  $("#dashboard-content").hidden = state.view === "history";
  $("#history-content").hidden = state.view !== "history";
  $("#stats-grid").hidden = state.view === "history";
  $("#ingestion-info").hidden = state.view === "history";
  $("#insight-column").hidden = state.view !== "dashboard";
  $("#dashboard-content").classList.toggle("alerts-view", state.view === "alerts");
  $("#queue-title").firstChild.textContent = state.view === "dashboard" ? "Последние события " : "События ";
  $("#all-alerts").hidden = state.view !== "dashboard";
  document.documentElement.scrollTop = 0; document.body.scrollTop = 0;
  renderAlerts();
  if (state.view === "history" && !state.authBlocked) loadHistory();
}
function renderStats() {
  const stats = state.stats;
  for (const [name, value] of Object.entries({ total: stats?.total, high: stats?.high_risk, pending: stats?.pending, analyses: stats?.analyses })) $("#stat-" + name).textContent = value ?? "—";
  $("#nav-count").textContent = stats?.pending ?? 0;
  $("#queue-count").textContent = state.alertTotal;
  $("#ingestion-info").textContent = stats ? `Принято за 60 с: ${stats.received_last_minute ?? 0} · Последнее поступление: ${stats.last_ingested_at ? dateTime(stats.last_ingested_at, true) : "ещё нет событий"}` : "Ожидание данных о поступлении событий";
}
function syntheticLabel(raw) {
  try { return JSON.parse(raw).synthetic === true ? '<span class="synthetic-label">Синтетика</span>' : ""; }
  catch { return ""; }
}
function renderAlerts() {
  const alerts = state.view === "dashboard" ? state.alerts.slice(0, 5) : state.alerts;
  const list = $("#alert-list");
  if (state.authBlocked) {
    list.innerHTML = '<div class="empty-state">Для просмотра событий введите токен аналитика.</div>';
  } else if (!alerts.length) {
    const emptyDB = state.stats?.total === 0;
    list.innerHTML = `<div class="empty-state">${icon("pulse")}<p>${emptyDB ? "Очередь пока пуста. Добавьте свой лог или загрузите демо." : state.stats ? "События по выбранному фильтру не найдены во всей очереди." : "Загрузка событий…"}</p>${emptyDB ? '<button type="button" class="button primary" id="seed-demo">Загрузить 5 демо-событий</button>' : ""}</div>`;
  } else {
    list.innerHTML = alerts.map((alert) => `<button type="button" class="alert-row" data-alert="${escapeHTML(alert.id)}" aria-label="Открыть: ${escapeHTML(alert.event_type)}"><span class="event-info"><span class="event-name">${escapeHTML(alert.event_type)}</span><span class="event-meta"><span class="mono">${escapeHTML(alert.source_ip)}</span><span class="meta-separator"></span><span>${dateTime(alert.timestamp, true)}</span>${syntheticLabel(alert.raw_data)}</span></span>${badge(alert.latest_analysis?.severity)}${badge(alert.status, "status")}<svg class="icon row-arrow"><use href="#i-arrow"/></svg></button>`).join("");
  }
  if (state.view === "alerts" && state.nextAlertCursor && !state.authBlocked) list.insertAdjacentHTML("beforeend", '<button type="button" class="button subtle load-more" id="load-more-alerts">Загрузить ещё</button>');
  $("#queue-count").textContent = state.alertTotal;
  $("#list-caption").textContent = state.authBlocked ? "Доступ защищен" : `${alerts.length} из ${state.alertTotal} событий · поиск по всей очереди`;
}
function renderProvider(health) {
  const provider = health.provider || { state: health.llm_configured ? "not_checked" : "not_configured" };
  const titles = { not_configured: "Резервный режим готов", not_checked: "LLM настроен · ожидается проверка", ready: "LLM успешно отвечал", degraded: "Резервный режим · ошибка LLM" };
  $("#mode-title").textContent = titles[provider.state] || "Состояние LLM неизвестно";
  $("#mode-description").textContent = provider.last_error_code ? (errorLabels[provider.last_error_code] || provider.last_error_code) : provider.state === "ready" ? `Последний успешный ответ: ${dateTime(provider.last_success_at)}` : provider.state === "not_checked" ? "Ключ и модель заданы. Успешное обращение к провайдеру ещё не подтверждено." : "События анализируются локально по правилам — без API-ключа.";
}
async function refresh({ silent = false } = {}) {
  if (silent && (state.refreshing || state.loadingMore || state.authBlocked)) return false;
  if (!silent) { clearTimeout(searchTimer); searchTimer = null; }
  const requestID = ++state.refreshID;
  state.refreshing = true;
  if (!silent) $("#refresh").disabled = true;
  try {
    const [page, stats, health] = await Promise.all([fetchAlertWindow(silent ? Math.max(100, state.alerts.length) : 100), api("/api/stats"), api("/api/health")]);
    if (requestID !== state.refreshID || page.query !== queryKey()) return false;
    state.authRequired = Boolean(health.auth_required); state.authBlocked = false;
    $("#auth-banner").hidden = true;
    state.alerts = page.items; state.alertTotal = page.total; state.nextAlertCursor = page.next_cursor; state.alertsQuery = page.query; state.stats = stats;
    renderStats(); renderAlerts(); renderProvider(health);
    $("#updated-at").textContent = "Обновлено " + new Date().toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });
    if (state.view === "history") await loadHistory(false, { silent });
    return true;
  } catch (error) { if (!silent) toast(error.message, true); return false; }
  finally { if (requestID === state.refreshID) { state.refreshing = false; $("#refresh").disabled = false; } }
}
function scheduleSearch() {
  clearTimeout(searchTimer); ++state.refreshID; state.refreshing = false; state.nextAlertCursor = null;
  $("#refresh").disabled = false;
  $("#list-caption").textContent = "Поиск по всей очереди…";
  searchTimer = setTimeout(() => { searchTimer = null; refresh(); }, 250);
}
function pollEvents() {
  if (document.visibilityState !== "visible" || state.historyLoading || state.authBlocked || searchTimer || document.querySelector("dialog[open]")) return;
  return refresh({ silent: true });
}
async function loadMoreAlerts(button) {
  if (state.loadingMore || !state.nextAlertCursor) return;
  if (state.alertsQuery !== queryKey()) return refresh();
  state.loadingMore = true; state.refreshing = false;
  const requestID = ++state.refreshID;
  $("#refresh").disabled = false; button.disabled = true;
  try {
    const page = await api(pageURL(queryValues(), 100, state.nextAlertCursor));
    if (requestID !== state.refreshID) return;
    state.alerts = [...new Map([...state.alerts, ...page.items].map((row) => [row.id, row])).values()];
    state.alertTotal = page.total; state.nextAlertCursor = page.next_cursor;
    renderAlerts();
  } catch (error) { toast(error.message, true); button.disabled = false; }
  finally { state.loadingMore = false; }
}
async function loadHistory(append = false, { silent = false } = {}) {
  if (state.authBlocked || (silent && state.historyLoading)) return;
  state.historyLoading = true;
  const requestID = ++state.historyID;
  if (!silent) $("#refresh-history").disabled = true;
  try {
    const size = !append && silent ? Math.max(100, state.history.length) : 100;
    const start = append ? state.history.length : 0;
    const requests = [];
    for (let offset = 0; offset <= size; offset += 200) requests.push(api(`/api/history?limit=${Math.min(200, size + 1 - offset)}&offset=${start + offset}`));
    const rows = (await Promise.all(requests)).flat();
    if (requestID !== state.historyID) return;
    state.history = append ? state.history.concat(rows.slice(0, size)) : rows.slice(0, size);
    state.historyHasMore = rows.length > size;
    renderHistory();
  } catch (error) { if (!silent) toast(error.message, true); }
  finally { if (requestID === state.historyID) { state.historyLoading = false; $("#refresh-history").disabled = false; if ($("#load-more-history")) $("#load-more-history").disabled = false; } }
}
function renderHistory() {
  if (state.authBlocked) { $("#history-list").innerHTML = '<div class="empty-state">Для просмотра истории нужен токен аналитика.</div>'; return; }
  $("#history-list").innerHTML = state.history.length ? state.history.map((entry) => {
    const analysis = entry.analysis;
    return `<article class="history-row"><div class="history-top"><button type="button" data-alert="${escapeHTML(analysis.alert_id)}" data-analysis="${escapeHTML(analysis.id)}">${escapeHTML(entry.event_type)}</button>${badge(analysis.severity)}</div><div class="history-meta"><span class="mono">${escapeHTML(entry.source_ip)}</span><span>${dateTime(analysis.created_at)}</span><span>${escapeHTML(modes[analysis.analysis_mode])}</span></div><p class="history-summary">${escapeHTML(analysis.summary)}</p><div class="history-meta"><span>Текущий статус события:</span>${badge(entry.current_status, "status")}</div>${entry.decisions.length ? entry.decisions.map((decision) => `<p class="history-decision">${escapeHTML(decision.decision === "confirmed" ? "Аналитик подтвердил инцидент" : "Аналитик отметил ложное срабатывание")} · ${dateTime(decision.created_at)}${decision.comment ? "<br>" + escapeHTML(decision.comment) : ""}</p>`).join("") : '<p class="history-meta">По этой версии анализа решение аналитика не сохранено.</p>'}</article>`;
  }).join("") + (state.historyHasMore ? '<button type="button" class="button subtle load-more" id="load-more-history">Загрузить ещё</button>' : "") : `<div class="empty-state">${icon("clock")}История пока пуста. Откройте событие и запустите первый анализ.</div>`;
}
async function openDetail(alertID, analysisID = null) {
  const requestID = ++state.detailID;
  const dialog = $("#detail-dialog");
  if (!dialog.open) dialog.showModal();
  $("#detail-title").textContent = "Загрузка события…";
  $("#detail-body").innerHTML = '<p class="loading-status"><span class="spinner"></span>Получаем контекст и историю…</p>';
  try {
    const [detail, analyses] = await Promise.all([api(`/api/alerts/${alertID}`), api(`/api/alerts/${alertID}/analyses`)]);
    if (requestID !== state.detailID || !dialog.open) return;
    state.selected = detail; state.analyses = analyses;
    state.shownAnalysis = analyses.find((item) => item.id === analysisID) || analyses[0] || null;
    renderDetail();
  } catch (error) {
    if (requestID === state.detailID && !state.authBlocked) {
      $("#detail-title").textContent = "Не удалось загрузить событие";
      $("#detail-body").innerHTML = `<p class="notice danger">${escapeHTML(error.message)}</p><button type="button" class="button subtle" data-alert="${escapeHTML(alertID)}">Повторить загрузку</button>`;
    }
  }
}
function prettyLog(raw) { try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; } }
function renderRules(findings) {
  return findings.length ? findings.map((rule) => `<article class="rule-card ${rule.kind === "context" ? "context" : ""}"><div class="rule-heading"><span class="rule-id">${escapeHTML(rule.id)}</span><strong>${escapeHTML(rule.description)}</strong></div>${rule.evidence.map((item) => `<p>${escapeHTML(item.description)}<br><span class="source-ref">${escapeHTML(item.source)}</span></p>`).join("")}</article>`).join("") : '<p class="detail-context">В поддерживаемом формате формальные признаки не выявлены. Это не подтверждает безопасность.</p>';
}
function renderAttempts(attempts) {
  const labels = { processing: "Выполняется", succeeded: "Завершена", failed: "Ошибка", abandoned: "Прервана" };
  return `<section class="detail-section"><h3>${icon("clock")}История попыток анализа</h3>${attempts.length ? attempts.map((attempt) => `<article class="attempt-entry"><strong>${escapeHTML(labels[attempt.status])}</strong><span>${dateTime(attempt.started_at)}</span><p>${escapeHTML(modes[attempt.analysis_mode] || "Результат не сохранен")}${attempt.provider_error_code || attempt.error_code ? " · " + escapeHTML(errorLabels[attempt.provider_error_code || attempt.error_code] || "Ошибка обработки") : ""}</p><code>${escapeHTML(attempt.id)}</code></article>`).join("") : '<p class="detail-context">Попытки учитываются с версии 2.1. Более ранние результаты сохранены в истории анализов.</p>'}</section>`;
}
function renderResult(analysis, allowDecision) {
  const fallback = analysis.analysis_mode === "rules_only";
  const evidence = analysis.evidence.map((item) => `<li>${escapeHTML(item.description)}${item.quote ? `<blockquote class="evidence-quote">${escapeHTML(item.quote)}</blockquote>` : ""}<br><span class="source-ref">${escapeHTML(item.source)}</span></li>`).join("") || '<li>Доказательств недостаточно.</li>';
  const decision = allowDecision ? `<form id="decision-form" class="decision-form"><h3>Решение аналитика</h3><label class="field">Комментарий<textarea name="comment" rows="2" maxlength="1000" placeholder="Контекст проверки и основание решения"></textarea></label><div class="decision-buttons"><button type="submit" name="decision" value="confirmed" class="button confirm">${icon("check")}Подтвердить инцидент</button><button type="submit" name="decision" value="false_positive" class="button benign">${icon("close")}Ложное срабатывание</button></div><p class="decision-note">Сохраняется ваше решение. Изменения инфраструктуры не выполняются.</p><p id="decision-error" class="form-error" role="alert" hidden></p></form>` : '<p class="decision-note">Архивная версия или активный анализ. Решение принимается по последнему завершенному результату.</p>';
  return `<section class="result-card"><div class="result-header"><div class="generated-label">${icon(fallback ? "code" : "spark")}${fallback ? "Сформировано Rule Engine · без LLM" : "Сгенерировано ИИ · предварительный вывод"}</div>${badge(analysis.severity)}</div>${fallback ? `<div class="notice">Резервный анализ по правилам. ${escapeHTML(analysis.limitations[0])}</div>` : ""}<p class="analysis-summary">${escapeHTML(analysis.summary)}</p><div class="result-columns"><section><h3>Проверяемые признаки</h3><ul class="evidence-list">${evidence}</ul></section><section><h3>Рекомендованные действия</h3><ol class="action-list">${analysis.recommended_actions.map((action) => `<li>${escapeHTML(action)}</li>`).join("")}</ol></section></div><div class="result-metrics"><p>Ложное срабатывание<strong>${analysis.false_positive_score === null ? "Нет достоверной оценки" : escapeHTML(analysis.false_positive_score)}</strong></p><p>Самооценка уверенности модели<strong>${analysis.confidence === null ? "Не применяется" : Math.round(analysis.confidence * 100) + "% · не вероятность атаки"}</strong></p><p>Режим анализа<strong>${escapeHTML(modes[analysis.analysis_mode])}</strong></p></div><h3>Ограничения анализа</h3><ul class="limitation-list">${analysis.limitations.map((item) => `<li>${escapeHTML(item)}</li>`).join("")}</ul><p class="result-footnote">${dateTime(analysis.created_at)} · Playbook ${escapeHTML(analysis.playbook_version)}${analysis.model_name ? " · Модель " + escapeHTML(analysis.model_name) : ""}<br>ID анализа: ${escapeHTML(analysis.id)}</p>${decision}</section>`;
}
function renderDetail() {
  const detail = state.selected;
  if (!detail) return;
  const busy = state.busy.has(detail.id) || detail.status === "processing";
  const latest = state.analyses[0], analysis = state.shownAnalysis;
  const snapshot = analysis ? analysis.rule_findings : detail.rule_findings;
  $("#detail-title").textContent = detail.event_type;
  const versions = state.analyses.length ? `<div class="analysis-switcher"><label for="analysis-version">Версия анализа</label><select id="analysis-version">${state.analyses.map((item, index) => `<option value="${escapeHTML(item.id)}" ${analysis?.id === item.id ? "selected" : ""}>${index === 0 ? "Последний · " : "Архив · "}${dateTime(item.created_at)} · ${escapeHTML(modes[item.analysis_mode])}</option>`).join("")}</select></div>` : "";
  const decisions = detail.decisions.length ? detail.decisions.map((item) => `<article class="decision-entry">${badge(item.decision, "status")}<small> · ${dateTime(item.created_at)}</small>${item.comment ? `<p>${escapeHTML(item.comment)}</p>` : ""}<small>Анализ: ${escapeHTML(item.analysis_id)}</small></article>`).join("") : '<p class="detail-context">Решения ещё не принимались. Результат AI не подтверждает инцидент человеком.</p>';
  $("#detail-body").innerHTML = `<div class="detail-meta"><span class="mono">${escapeHTML(detail.source_ip)}</span><span>${dateTime(detail.timestamp)}</span>${badge(detail.status, "status")}${syntheticLabel(detail.raw_data)}</div><p class="detail-context">Событие ${escapeHTML(detail.id)}<br>Источники относятся к переданному логу. Внешний контекст автоматически не проверяется.</p><section class="detail-section"><h3>${icon("code")}Исходный лог · секреты замаскированы</h3><pre class="raw-log">${escapeHTML(prettyLog(detail.raw_data))}</pre></section>${versions}<section class="detail-section"><h3>${icon("shield")}${analysis ? "Правила на момент выбранного анализа" : "Сработавшие правила"} <span class="count-pill">${snapshot.length}</span></h3>${renderRules(snapshot)}</section><div class="analyze-bar"><div><strong>${busy ? "Анализ выполняется…" : latest ? "Повторный анализ" : "Собрать картину события"}</strong><p>${busy ? "Повторный запуск заблокирован." : latest ? "Будет создана новая версия. История сохранится." : "Правила + AI при доступности провайдера"}</p></div><button type="button" id="analyze-button" class="button primary" ${busy || !detail.raw_data.trim() ? "disabled" : ""}>${busy ? '<span class="spinner"></span>' : icon("spark")}${busy ? "Анализируем…" : "Анализировать с ИИ"}</button></div>${detail.status === "processing" ? '<button type="button" class="button subtle" id="reload-detail">Обновить состояние</button>' : ""}${analysis ? renderResult(analysis, latest?.id === analysis.id && !busy) : ""}${renderAttempts(detail.attempts || [])}<section class="detail-section"><h3>${icon("clock")}История решений аналитика</h3>${decisions}</section>`;
}
async function runAnalysis() {
  const id = state.selected?.id;
  if (!id || state.busy.has(id)) return;
  state.busy.add(id); renderDetail();
  try {
    const result = await api(`/api/alerts/${id}/analyze`, { method: "POST" });
    toast(result.analysis_mode === "rules_only" ? "Анализ по правилам сохранен. LLM не использовался." : "Анализ сохранен. Требуется решение аналитика.");
  } catch (error) { toast(error.message, true); }
  finally {
    state.busy.delete(id); await refresh();
    if ($("#detail-dialog").open && state.selected?.id === id) await openDetail(id);
  }
}
async function saveDecision(form, submitter) {
  const detail = state.selected, analysis = state.shownAnalysis;
  if (!detail || !analysis || !submitter) return;
  const comment = new FormData(form).get("comment");
  form.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  try {
    await api(`/api/alerts/${detail.id}/decision`, { method: "POST", body: JSON.stringify({ analysis_id: analysis.id, decision: submitter.value, comment }) });
    toast("Решение аналитика сохранено в истории."); await refresh();
    if (state.selected?.id === detail.id) await openDetail(detail.id, analysis.id);
  } catch (error) {
    const target = $("#decision-error");
    if (target) { target.textContent = error.message; target.hidden = false; }
    form.querySelectorAll("button").forEach((button) => { button.disabled = false; });
  }
}
function validateLog() {
  const raw = $("#raw-input").value, length = [...raw].length;
  $("#char-count").textContent = `${length} / 2000`;
  $("#char-count").classList.toggle("over-limit", length > 2000);
  $("#save-log").disabled = !raw.trim() || length > 2000;
  $("#log-error").hidden = length <= 2000;
  if (length > 2000) $("#log-error").textContent = "Максимальный размер лога — 2000 символов.";
}
document.addEventListener("click", async (event) => {
  const close = event.target.closest("[data-close]");
  if (close) { document.getElementById(close.dataset.close).close(); return; }
  const row = event.target.closest("[data-alert]");
  if (row) { await openDetail(row.dataset.alert, row.dataset.analysis); return; }
  const button = event.target.closest("button");
  if (!button) return;
  if (["access-button", "access-button-mobile", "auth-open"].includes(button.id)) $("#access-dialog").showModal();
  if (button.id === "analyze-button") await runAnalysis();
  if (button.id === "reload-detail") await openDetail(state.selected.id);
  if (button.id === "seed-demo") {
    button.disabled = true;
    try { const result = await api("/api/demo/seed", { method: "POST" }); toast(`Демо-событий добавлено: ${result.created}`); await refresh(); }
    catch (error) { toast(error.message, true); button.disabled = false; }
  }
  if (button.id === "load-more-alerts") await loadMoreAlerts(button);
  if (button.id === "load-more-history") { button.disabled = true; await loadHistory(true); }
});
document.addEventListener("change", (event) => {
  if (event.target.id === "analysis-version") { state.shownAnalysis = state.analyses.find((item) => item.id === event.target.value); renderDetail(); }
});
document.addEventListener("submit", (event) => {
  if (event.target.id === "decision-form") { event.preventDefault(); saveDecision(event.target, event.submitter); }
});
$("#refresh").addEventListener("click", refresh);
$("#refresh-history").addEventListener("click", () => loadHistory());
$("#search").addEventListener("input", scheduleSearch);
$("#status-filter").addEventListener("change", () => refresh());
$("#raw-input").addEventListener("input", validateLog);
$("#detail-dialog").addEventListener("close", () => { ++state.detailID; });
$("#add-log").addEventListener("click", () => {
  const form = $("#log-form"); form.reset();
  const now = new Date();
  form.elements.timestamp.value = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  $("#log-error").hidden = true; validateLog(); $("#log-dialog").showModal();
});
$("#log-form").addEventListener("submit", async (event) => {
  event.preventDefault(); if ($("#save-log").disabled) return;
  const values = Object.fromEntries(new FormData(event.target)); values.timestamp = new Date(values.timestamp).toISOString();
  $("#save-log").disabled = true;
  try {
    const alert = await api("/api/alerts", { method: "POST", body: JSON.stringify(values) });
    $("#log-dialog").close(); toast("Событие добавлено. Можно приступать к анализу."); await refresh(); await openDetail(alert.id);
  } catch (error) { $("#log-error").textContent = error.message; $("#log-error").hidden = false; $("#save-log").disabled = false; }
});
$("#access-form").addEventListener("submit", async (event) => {
  event.preventDefault(); state.token = new FormData(event.target).get("token").trim(); event.target.reset();
  $("#access-dialog").close();
  if (await refresh()) toast("Доступ к событиям подтвержден.");
});
$("#clear-token").addEventListener("click", () => {
  state.token = ""; $("#access-form").reset(); $("#access-dialog").close();
  if (state.authRequired) lockProtectedData();
  toast("Токен удален из памяти вкладки.");
});
window.addEventListener("hashchange", route);
window.addEventListener("online", refresh);
window.addEventListener("offline", () => connection(false));
document.addEventListener("visibilitychange", pollEvents);
window.setInterval(pollEvents, 3000);
route(); refresh();
