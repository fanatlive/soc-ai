<div align="center">

# 🛡️ SOC AI Triage

**Первичный разбор событий безопасности: проверяемые правила + ИИ-контекст.<br>Окончательное решение — всегда за аналитиком.**

[![Tests](https://github.com/fanatlive/soc-ai/actions/workflows/tests.yml/badge.svg)](https://github.com/fanatlive/soc-ai/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-storage-003B57?logo=sqlite&logoColor=white)
![LLM](https://img.shields.io/badge/LLM-OpenAI--compatible-00ff41)
![Status](https://img.shields.io/badge/status-local%20MVP-lightgrey)

<img src="docs/screenshots/dashboard.png" alt="Панель SOC AI Triage" width="880">

</div>

---

## ✨ Что это

SOC-аналитик получает поток алертов и тратит время на рутину: понять, что произошло, насколько это опасно и что проверить дальше. **SOC AI Triage** делает первичный разбор за него — и показывает, на чём основан вывод:

- 🔎 **шесть детерминированных правил** находят признаки в сыром логе (брутфорс, PowerShell с опасными флагами, сканирование портов и др.);
- 🤖 **LLM** (любой OpenAI-совместимый API) объясняет контекст, но каждое доказательство — это **точная цитата из лога**, проверенная сервером;
- 🧑‍💻 **решение принимает человек**: «Подтвердить инцидент» или «Ложное срабатывание» — с историей по каждой версии анализа;
- 🛟 **без ключа LLM всё работает** — честный резервный режим `rules_only`, а в интерфейсе всегда подписан источник результата.

> Приложение **не исполняет команды и не меняет инфраструктуру**: рекомендации — только текст.

## 📸 Как выглядит

<div align="center">
<img src="docs/screenshots/analysis.png" alt="Результат анализа события" width="780">
<br><sub>Результат анализа: цитаты-доказательства, рекомендации, ограничения и решение аналитика</sub>
</div>

## 🧠 Как это работает

```mermaid
flowchart LR
    A[Сырой лог<br/>JSON / key=value / текст] --> B[Маскирование секретов]
    B --> C[Rule Engine<br/>R001–R006]
    C --> D{LLM настроен?}
    D -- да --> E[LLM-анализ<br/>JSON + цитаты]
    D -- нет / ошибка --> F[rules_only<br/>резервный разбор]
    E --> G[Проверка ответа<br/>цитаты · действия · безопасность]
    G --> H[Анализ сохранён в SQLite]
    F --> H
    H --> I[Решение аналитика<br/>confirmed / false_positive]
```

| Режим | Что означает |
| --- | --- |
| `hybrid` | LLM получил результаты правил и дополнил их контекстом |
| `llm` | LLM работал без сработавших правил |
| `rules_only` | LLM не использовался (нет ключа, ошибка провайдера, таймаут) |

### Правила

| ID | Что находит |
| --- | --- |
| `R001` | Серия неудачных входов — возможный Brute Force |
| `R002` | Успешный вход после серии неудачных — возможная компрометация |
| `R003` | PowerShell с потенциально опасными параметрами |
| `R004` | Соединения со множеством портов за 60 секунд — возможное сканирование |
| `R005` | IP из доверенной сети (контекст; не доказывает безопасность) |
| `R006` | В логе указан подтверждённый корпоративный VPN (контекст) |

## 🚀 Быстрый старт

Нужен Python **3.11+**. Ключ LLM для запуска не требуется. Node.js не нужен: скомпилированный Tailwind уже в проекте, CDN и внешних шрифтов нет.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

<details>
<summary>Windows PowerShell</summary>

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
</details>

Откройте **http://127.0.0.1:8000** — при первом старте создадутся пять синтетических демо-событий. Спецификация API: `/openapi.json`.

## 🐧 Развёртывание на Linux (Arch)

```bash
sudo pacman -S --needed python git            # Python в Arch новее 3.11, venv уже входит в пакет
git clone https://github.com/fanatlive/soc-ai.git && cd soc-ai
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env && nano .env
```

В `.env` вставьте ключ. Если открывать сайт **с другого компьютера**, нужны ещё три строки — иначе сервер ответит `400` (чужой Host), `401` (нет токена) или `403` (чужой Origin):

```env
LLM_API_KEY=ваш_ключ
API_TOKEN=сгенерируйте: openssl rand -hex 24
ALLOWED_HOSTS=IP_СЕРВЕРА,localhost,127.0.0.1
ALLOWED_ORIGINS=http://IP_СЕРВЕРА:8000
```

```bash
python -m tools.check_llm                                           # проверка ИИ с этого сервера: ключ, модель, сеть, регион
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000       # запуск
sudo ufw allow 8000/tcp                                             # если включён firewall (или правило nftables/iptables)
```

Откройте `http://IP_СЕРВЕРА:8000`, нажмите значок 🔑 в левом нижнем углу и введите `API_TOKEN`. Сервер должен иметь выход в интернет к хосту LLM-провайдера.

<details>
<summary>Автозапуск через systemd</summary>

Файл `/etc/systemd/system/soc-ai.service` (проект лежит в `/opt/soc-ai`, venv создан там же):

```ini
[Unit]
Description=SOC AI Triage
After=network-online.target

[Service]
WorkingDirectory=/opt/soc-ai
ExecStart=/opt/soc-ai/.venv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now soc-ai
journalctl -u soc-ai -f          # логи
```
</details>

> После любого изменения `.env` сервер нужно перезапустить. Для публичного доступа поставьте перед сервисом nginx с TLS: токен по обычному HTTP передаётся открытым текстом.

## 🔌 Подключение LLM

Заполните три переменные в `.env` и **перезапустите сервер**:

```env
LLM_API_KEY=ваш_ключ
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai   # или https://api.openai.com/v1
LLM_MODEL=gemini-3.5-flash                          # обязательно: без модели LLM считается ненастроенным
LLM_FALLBACK_MODELS=gemini-3.1-flash-lite           # необязательно: запасная модель на случай перегрузки (HTTP 5xx)
```

В `.env.example` уже прописаны рабочие значения для Gemini — достаточно вставить ключ.

Подойдёт любой провайдер с контрактом `POST {LLM_BASE_URL}/chat/completions` и `response_format=json_object` (OpenAI, Gemini через OpenAI-совместимый endpoint и т. п.). Состояние провайдера видно в `GET /api/health` → `provider.state`: `not_configured` · `not_checked` · `ready` · `degraded`.

> 💡 Если провайдер перегружен (HTTP 503) или отвечает ошибкой, приложение не падает, а сохраняет разбор по правилам — с понятной причиной в интерфейсе. Если основная модель перегружена, сервер автоматически пробует модели из `LLM_FALLBACK_MODELS`.

## 🧪 Проверка и нагрузка

```bash
python -m pytest -q            # 120 тестов backend
npm install && npm run test:ui # 16 DOM-тестов интерфейса (jsdom)
```

Генератор синтетических логов отправляет запросы в настоящий API с заданной скоростью:

```bash
python -m tools.generate_events --rate 25 --seconds 10            # приём логов
python -m tools.generate_events --rate 3 --seconds 8 --analyze    # + анализ (вызывает LLM)
python -m tools.check_llm                                         # диагностика подключения к LLM
```

## 🔐 Безопасность

- Секреты из `.env` не попадают ни в ответы API, ни в промпт LLM; чувствительные поля в логах маскируются.
- Недоверенный лог передаётся модели отдельным полем, ответ проверяется Pydantic; у модели **нет инструментов** и доступа к shell.
- Строгий CSP (`script-src 'self'`), HTML из логов экранируется.
- По умолчанию сервер слушает только `127.0.0.1`; для внешнего доступа задайте `API_TOKEN` (≥ 24 символов), `ALLOWED_HOSTS` и `ALLOWED_ORIGINS`.
- `false_positive_score` всегда `null`: данных для честной оценки нет; `confidence` LLM — лишь самооценка модели.

## 📁 Структура

```text
backend/    FastAPI, правила, сервис ИИ, SQLite-модели и миграции
frontend/   панель на чистом JS + Tailwind (скомпилирован), тема в cyber.css
tools/      генератор синтетических логов
tests/      pytest и jsdom-тесты
docs/       руководство, технический отчёт, скриншоты
```

## 📚 Документация

| Документ | О чём |
| --- | --- |
| [Полное руководство](docs/MANUAL_RU.md) | Настройка `.env`, формат логов, API, миграции, безопасность, тесты |
| [Технический отчёт](docs/TECHNICAL_IMPROVEMENTS_RU.md) | Что было исправлено и границы проверки |
| [Аудит](AUDIT.md) | Результаты аудита и найденные риски |
| [ТЗ для презентации](docs/PRESENTATION_BRIEF_RU.md) | Сценарий демонстрации MVP |

## ⚠️ Границы MVP

Не входят: интеграции с SIEM, автоматическая блокировка и реагирование, обучение моделей, сложная корреляция событий. Все демо-события синтетические.

---

<div align="center"><sub>AI помогает. Аналитик решает.</sub></div>
