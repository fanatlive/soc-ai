// DOM interaction tests; these do not replace visual tests in a real browser.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { JSDOM } from "jsdom";

const html = await readFile(new URL("../frontend/index.html", import.meta.url), "utf8");
const app = await readFile(new URL("../frontend/app.js", import.meta.url), "utf8");
const alertID = "a0000000-0000-4000-8000-000000000001";
const analysisID = "b0000000-0000-4000-8000-000000000001";
const stamp = "2026-11-06T04:00:00Z";
const analysis = { id: analysisID, alert_id: alertID, severity: "critical", summary: "Нужна проверка аналитика.", evidence: [{ description: "Серия входов", source: "rule:R001" }], recommended_actions: ["Проверить IdP"], confidence: null, false_positive_score: null, limitations: ["LLM не настроен"], analysis_mode: "rules_only", model_name: null, playbook_version: "soc-mvp-2.0", created_at: stamp, rule_findings: [] };
const alert = { id: alertID, timestamp: stamp, created_at: stamp, source_ip: "203.0.113.42", event_type: "Тестовый вход", raw_data: '{"synthetic":true}', status: "new", latest_analysis: null, rule_findings: [], decisions: [] };

async function waitFor(predicate) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail("DOM condition was not reached");
}

async function setup(overrides = {}) {
  const dom = new JSDOM(html, { url: "http://localhost/", runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;
  const intervals = [];
  window.setInterval = (callback, delay) => { intervals.push({ callback, delay }); return intervals.length; };
  window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  window.HTMLDialogElement.prototype.close = function () { this.open = false; this.dispatchEvent(new window.Event("close")); };
  const requests = [];
  let analyses = [];
  let detail = structuredClone({ ...alert, ...overrides.alert });
  window.fetch = async (path, options = {}) => {
    requests.push({ path, options });
    if (overrides.fetch) {
      const special = await overrides.fetch(path, options);
      if (special) return special;
    }
    let result;
    if (path === "/api/health") result = { llm_configured: false };
    else if (path === "/api/stats") result = { total: 1, high_risk: analyses.length ? 1 : 0, pending: analyses.length ? 0 : 1, analyses: analyses.length };
    else if (path.startsWith("/api/alerts/page?")) return alertPage([detail], path);
    else if (path.startsWith("/api/history?")) result = analyses.map((item) => ({ analysis: item, event_type: detail.event_type, source_ip: detail.source_ip, current_status: detail.status, decisions: detail.decisions }));
    else if (path.endsWith("/analyze")) {
      analyses = [structuredClone(analysis), ...analyses];
      detail.status = "analyzed";
      detail.latest_analysis = analyses[0];
      result = analyses[0];
    } else if (path.endsWith("/analyses")) result = analyses;
    else if (path.endsWith("/decision")) {
      const data = JSON.parse(options.body);
      detail.status = data.decision;
      result = { ...data, id: "decision-test", alert_id: alertID, created_at: stamp };
      detail.decisions = [result, ...detail.decisions];
    } else if (path === "/api/alerts" && options.method === "POST") {
      detail = { ...detail, ...JSON.parse(options.body) };
      result = detail;
    } else if (path === `/api/alerts/${alertID}`) result = detail;
    else throw new Error(`Unexpected API path: ${path}`);
    return { ok: true, status: 200, json: async () => structuredClone(result) };
  };
  window.eval(app);
  await waitFor(() => overrides.expectAuth ? !window.document.querySelector("#auth-banner").hidden : overrides.expectOffline ? !window.document.querySelector("#toast").hidden : window.document.querySelector("#stat-total").textContent !== "—");
  return { dom, window, document: window.document, requests, intervals };
}

test("dashboard shows real data, search and navigation work", async (t) => {
  const { dom, window, document } = await setup();
  t.after(() => dom.window.close());
  assert.equal(document.querySelectorAll(".alert-row").length, 1);
  assert.equal(document.querySelector("#stat-high").textContent, "0");
  const search = document.querySelector("#search");
  search.value = "missing";
  search.dispatchEvent(new window.Event("input"));
  await waitFor(() => document.querySelectorAll(".alert-row").length === 0);
  assert.match(document.querySelector("#alert-list").textContent, /не найдены/);
  window.location.hash = "history";
  await waitFor(() => !document.querySelector("#history-content").hidden);
  assert.match(document.querySelector("#history-list").textContent, /История пока пуста/);
});

test("log form blocks empty or oversized data, then saves and opens event", async (t) => {
  const { dom, window, document, requests } = await setup();
  t.after(() => dom.window.close());
  document.querySelector("#add-log").click();
  assert.equal(document.querySelector("#save-log").disabled, true);
  const raw = document.querySelector("#raw-input");
  raw.value = "я".repeat(2001);
  raw.dispatchEvent(new window.Event("input"));
  assert.equal(document.querySelector("#save-log").disabled, true);
  assert.match(document.querySelector("#log-error").textContent, /2000/);
  raw.value = "synthetic custom log";
  raw.dispatchEvent(new window.Event("input"));
  const form = document.querySelector("#log-form");
  form.elements.event_type.value = "Пользовательский лог";
  form.elements.source_ip.value = "192.0.2.5";
  form.dispatchEvent(new window.SubmitEvent("submit", { bubbles: true, cancelable: true }));
  await waitFor(() => document.querySelector("#detail-title").textContent === "Пользовательский лог");
  assert.equal(requests.filter((request) => request.path === "/api/alerts" && request.options.method === "POST").length, 1);
  assert.equal(document.querySelector("#log-dialog").open, false);
});

test("analysis locks repeated clicks and preserves a human decision in history", async (t) => {
  const { dom, window, document, requests } = await setup();
  t.after(() => dom.window.close());
  document.querySelector(".alert-row").click();
  await waitFor(() => document.querySelector("#analyze-button"));
  document.querySelector("#analyze-button").click();
  assert.equal(document.querySelector("#analyze-button").disabled, true);
  document.querySelector("#analyze-button").click();
  await waitFor(() => document.querySelector("#decision-form"));
  assert.equal(requests.filter((request) => request.path.endsWith("/analyze")).length, 1);
  assert.match(document.querySelector(".result-card").textContent, /без LLM/);
  assert.match(document.querySelector(".result-card").textContent, /Нет достоверной оценки/);
  const form = document.querySelector("#decision-form");
  form.elements.comment.value = "Сверено с синтетическим IdP";
  form.dispatchEvent(new window.SubmitEvent("submit", { bubbles: true, cancelable: true, submitter: form.querySelector('[value="confirmed"]') }));
  await waitFor(() => document.querySelector(".decision-entry"));
  assert.match(document.querySelector(".decision-entry").textContent, /Сверено с синтетическим IdP/);
  document.querySelector('[data-close="detail-dialog"]').click();
  window.location.hash = "history";
  await waitFor(() => document.querySelector(".history-decision"));
  assert.match(document.querySelector(".history-decision").textContent, /Аналитик подтвердил/);
});

test("untrusted event names and logs are displayed as text", async (t) => {
  const hostile = '<img src=x onerror="globalThis.compromised=true">';
  const { dom, document } = await setup({ alert: { event_type: hostile, raw_data: hostile } });
  t.after(() => dom.window.close());
  assert.equal(document.querySelector("#alert-list img"), null);
  document.querySelector(".alert-row").click();
  await waitFor(() => document.querySelector(".raw-log"));
  assert.equal(document.querySelector(".raw-log").textContent, hostile);
  assert.equal(document.querySelector("#detail-body img"), null);
});

test("backend failure shows connection error without a client crash", async (t) => {
  const { dom, document } = await setup({ expectOffline: true, fetch: async (path) => { if (path.startsWith("/api/alerts/page?")) throw new Error("offline"); } });
  t.after(() => dom.window.close());
  await waitFor(() => !document.querySelector("#toast").hidden);
  assert.match(document.querySelector("#toast").textContent, /Нет соединения/);
  assert.equal(document.querySelector("#offline-banner").hidden, false);
});

test("token is used in headers and never stored in browser storage", async (t) => {
  const { dom, window, document, requests } = await setup();
  t.after(() => dom.window.close());
  document.querySelector("#access-button-mobile").click();
  const form = document.querySelector("#access-form");
  form.elements.token.value = "synthetic-token";
  form.dispatchEvent(new window.SubmitEvent("submit", { bubbles: true, cancelable: true }));
  document.querySelector("#refresh").click();
  await waitFor(() => requests.some((request) => request.options.headers?.Authorization === "Bearer synthetic-token"));
  await waitFor(() => !document.querySelector("#refresh").disabled);
  assert.equal(window.localStorage.length, 0);
  assert.equal(window.sessionStorage.length, 0);
  assert.equal(form.elements.token.value, "");
});

const response = (data) => ({ ok: true, status: 200, json: async () => structuredClone(data) });

function alertPage(rows, path) {
  const params = new URL(path, "http://localhost").searchParams;
  const query = (params.get("q") || "").toLocaleLowerCase("ru");
  const status = params.get("status");
  const filtered = rows.filter((row) => (!status || row.status === status) && [row.event_type, row.source_ip, row.id].some((value) => value.toLocaleLowerCase("ru").includes(query)));
  const offset = Number(params.get("cursor") || 0), limit = Number(params.get("limit"));
  return response({ items: filtered.slice(offset, offset + limit), total: filtered.length, next_cursor: offset + limit < filtered.length ? String(offset + limit) : null });
}

test("new events and counters appear automatically without clearing the search", async (t) => {
  let incoming = false;
  const next = { ...alert, id: "a0000000-0000-4000-8000-000000000002", event_type: "Новый внешний лог" };
  const { dom, window, document, intervals } = await setup({ fetch: async (path) => {
    if (!incoming) return;
    if (path.startsWith("/api/alerts/page?")) return alertPage([next, alert], path);
    if (path === "/api/stats") return response({ total: 2, pending: 2, high_risk: 0, analyses: 0 });
  } });
  t.after(() => dom.window.close());
  assert.equal(intervals[0].delay, 3000);
  document.querySelector("#search").value = "203.0.113";
  document.querySelector("#search").dispatchEvent(new window.Event("input"));
  incoming = true;
  await waitFor(() => document.querySelectorAll(".alert-row").length === 2);
  await intervals[0].callback();
  assert.equal(document.querySelector("#stat-total").textContent, "2");
  assert.equal(document.querySelector("#stat-pending").textContent, "2");
  assert.equal(document.querySelectorAll(".alert-row").length, 2);
  assert.match(document.querySelector(".alert-row").textContent, /Новый внешний лог/);
  assert.equal(document.querySelector("#search").value, "203.0.113");
});

test("automatic updates preserve an open draft and pause for hidden tabs", async (t) => {
  const { dom, document, requests, intervals } = await setup();
  t.after(() => dom.window.close());
  document.querySelector("#add-log").click();
  document.querySelector("#raw-input").value = "unsaved draft";
  const before = requests.length;
  await intervals[0].callback();
  assert.equal(requests.length, before);
  assert.equal(document.querySelector("#raw-input").value, "unsaved draft");
  document.querySelector('[data-close="log-dialog"]').click();
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
  await intervals[0].callback();
  assert.equal(requests.length, before);
});

test("automatic refresh does not launch overlapping requests", async (t) => {
  let hold = false;
  let release;
  const waiting = new Promise((resolve) => { release = resolve; });
  const { dom, requests, intervals } = await setup({ fetch: async (path) => {
    if (hold && path === "/api/stats") { await waiting; return response({ total: 1, pending: 1, high_risk: 0, analyses: 0 }); }
  } });
  t.after(() => dom.window.close());
  hold = true;
  const before = requests.length;
  const pending = intervals[0].callback();
  await intervals[0].callback();
  assert.equal(requests.length - before, 3);
  release();
  await pending;
});

test("automatic refresh keeps the expanded alert window", async (t) => {
  let rows = Array.from({ length: 201 }, (_, index) => ({ ...alert, id: `a0000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`, event_type: `Событие ${index + 1}` }));
  const { dom, window, document, requests, intervals } = await setup({ fetch: async (path) => {
    if (path.startsWith("/api/alerts/page?")) {
      const params = new URL(path, "http://localhost").searchParams;
      return alertPage(rows, path);
    }
    if (path === "/api/stats") return response({ total: rows.length, pending: rows.length, high_risk: 0, analyses: 0 });
  } });
  t.after(() => dom.window.close());
  window.location.hash = "alerts";
  await waitFor(() => document.querySelector("#load-more-alerts"));
  document.querySelector("#load-more-alerts").click();
  await waitFor(() => document.querySelectorAll(".alert-row").length === 200);
  rows.unshift({ ...alert, id: "new-arrival", event_type: "Новый лог во время просмотра" });
  await intervals[0].callback();
  assert.equal(document.querySelectorAll(".alert-row").length, 200);
  assert.match(document.querySelector(".alert-row").textContent, /Новый лог во время просмотра/);
  assert(requests.some((request) => request.path === "/api/alerts/page?limit=200"));
});

test("completed analyses appear automatically in History", async (t) => {
  let incoming = false;
  const { dom, window, document, intervals } = await setup({ fetch: async (path) => {
    if (incoming && path.startsWith("/api/history?")) return response([{ analysis, event_type: alert.event_type, source_ip: alert.source_ip, current_status: "analyzed", decisions: [] }]);
  } });
  t.after(() => dom.window.close());
  window.location.hash = "history";
  await waitFor(() => !document.querySelector("#history-content").hidden);
  await waitFor(() => !document.querySelector("#refresh-history").disabled);
  incoming = true;
  await intervals[0].callback();
  assert.equal(document.querySelectorAll(".history-row").length, 1);
  assert.match(document.querySelector(".history-row").textContent, /Нужна проверка аналитика/);
});

test("background updates do not interrupt a pending history request", async (t) => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const { dom, window, document, requests, intervals } = await setup({ fetch: async (path) => {
    if (path.startsWith("/api/history?")) { await pending; return response([]); }
  } });
  t.after(() => dom.window.close());
  window.location.hash = "history";
  await waitFor(() => requests.some((request) => request.path.startsWith("/api/history?")));
  const before = requests.length;
  await intervals[0].callback();
  assert.equal(requests.length, before);
  release();
  await waitFor(() => !document.querySelector("#refresh-history").disabled);
});

test("server search and status find an older alert beyond the first hundred", async (t) => {
  const rows = Array.from({ length: 150 }, (_, i) => ({ ...alert, id: `row-${i}`, event_type: i === 149 ? "Архивный инцидент" : `Событие ${i}`, status: i === 149 ? "confirmed" : "new" }));
  const { dom, window, document, requests } = await setup({ fetch: async (path) => {
    if (path.startsWith("/api/alerts/page?")) return alertPage(rows, path);
    if (path === "/api/stats") return response({ total: 150, pending: 149, high_risk: 0, analyses: 0 });
  } });
  t.after(() => dom.window.close());
  const search = document.querySelector("#search"), status = document.querySelector("#status-filter");
  search.value = "АРХИВНЫЙ";
  search.dispatchEvent(new window.Event("input"));
  await waitFor(() => document.querySelector("#alert-list").textContent.includes("Архивный инцидент"));
  status.value = "confirmed";
  status.dispatchEvent(new window.Event("change"));
  await waitFor(() => requests.some(({ path }) => new URL(path, "http://localhost").searchParams.get("status") === "confirmed"));
  await waitFor(() => !document.querySelector("#refresh").disabled);
  assert.equal(document.querySelectorAll(".alert-row").length, 1);
  assert.equal(document.querySelector("#queue-count").textContent, "1");
  assert.equal(document.querySelector("#stat-total").textContent, "150");
});

test("protected reads request a token and clearing it removes protected screen data", async (t) => {
  const { dom, window, document } = await setup({ expectAuth: true, fetch: async (path, options) => {
    if (path === "/api/health") return response({ auth_required: true, llm_configured: false });
    if (options.headers?.Authorization !== "Bearer synthetic-access-token") return { ok: false, status: 401, json: async () => ({ detail: "Требуется токен аналитика" }) };
  } });
  t.after(() => dom.window.close());
  assert.equal(document.querySelectorAll(".alert-row").length, 0);
  assert.equal(document.querySelector("#access-dialog").open, true);
  const form = document.querySelector("#access-form");
  form.elements.token.value = "synthetic-access-token";
  form.dispatchEvent(new window.SubmitEvent("submit", { bubbles: true, cancelable: true }));
  await waitFor(() => document.querySelectorAll(".alert-row").length === 1);
  document.querySelector("#clear-token").click();
  assert.equal(document.querySelectorAll(".alert-row").length, 0);
  assert.equal(document.querySelector("#stat-total").textContent, "—");
  assert.equal(document.querySelector("#auth-banner").hidden, false);
  assert.equal(window.localStorage.length + window.sessionStorage.length, 0);
});

test("configured LLM is not shown as verified before a successful response", async (t) => {
  const { dom, document } = await setup({ fetch: async (path) => {
    if (path === "/api/health") return response({ llm_configured: true, provider: { state: "not_checked" } });
  } });
  t.after(() => dom.window.close());
  assert.match(document.querySelector("#mode-title").textContent, /ожидается проверка/);
  assert.match(document.querySelector("#mode-description").textContent, /ещё не подтверждено/);
});

test("archived results show their rule snapshot, escaped quotes and attempt failures", async (t) => {
  const rule = (id, description) => ({ id, description, kind: "indicator", evidence: [] });
  const older = { ...analysis, id: "older-analysis", rule_findings: [rule("R001", "Старый снимок правил")], evidence: [{ description: "Цитата лога", source: "raw_data", quote: "<img src=x onerror=alert(1)>" }] };
  const { dom, window, document } = await setup({ alert: {
    rule_findings: [rule("R003", "Текущее правило")],
    attempts: [{ id: "failed-attempt", status: "failed", started_at: stamp, error_code: "unsupported_evidence" }],
  }, fetch: async (path) => {
    if (path.endsWith("/analyses")) return response([analysis, older]);
  } });
  t.after(() => dom.window.close());
  document.querySelector(".alert-row").click();
  await waitFor(() => document.querySelector("#analysis-version"));
  const selector = document.querySelector("#analysis-version");
  selector.value = older.id;
  selector.dispatchEvent(new window.Event("change", { bubbles: true }));
  assert.match(document.querySelector(".rule-card").textContent, /Старый снимок/);
  assert.equal(document.querySelector(".evidence-quote").textContent, "<img src=x onerror=alert(1)>");
  assert.equal(document.querySelector("#detail-body img"), null);
  assert.match(document.querySelector(".attempt-entry").textContent, /Цитата не подтверждена/);
  assert.equal(document.querySelector("#decision-form"), null);
});
