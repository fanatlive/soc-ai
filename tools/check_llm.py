"""Проверка подключения к LLM теми же настройками (.env), что использует сервер.

    python -m tools.check_llm

Выводит понятный диагноз: нет ключа/модели, неверный ключ, недоступная модель или регион,
перегрузка провайдера, нет сети с этого сервера. Сам ключ нигде не печатается.
"""
import sys
import time

import httpx

from backend.config import Settings

HINTS = {
    400: "Провайдер не принял запрос. Чаще всего неверный ключ (Gemini отвечает 400 INVALID_ARGUMENT), реже — регион сервера или имя модели.",
    401: "Ключ отклонён. Проверьте LLM_API_KEY (без кавычек и пробелов) и что ключ от того же провайдера, что LLM_BASE_URL.",
    403: "Доступ запрещён: проверьте права ключа и регион сервера (часть провайдеров блокирует IP некоторых стран).",
    404: "Не найдено: проверьте LLM_MODEL (точное имя модели) и LLM_BASE_URL.",
    429: "Превышена квота или частота запросов. Подождите минуту или смените ключ/модель.",
}


def check_model(settings: Settings, model: str) -> tuple[bool, str]:
    url = settings.llm_base_url.rstrip("/") + "/chat/completions"
    body = {"model": model, "max_tokens": 20, "messages": [{"role": "user", "content": "Ответь одним словом: ок"}]}
    started = time.monotonic()
    try:
        response = httpx.post(url, headers={"Authorization": f"Bearer {settings.llm_api_key}"}, json=body,
                              timeout=min(settings.llm_timeout_seconds, 60), follow_redirects=False)
    except httpx.TimeoutException:
        return False, "таймаут: сервер не дождался ответа (медленная сеть или перегрузка провайдера)"
    except httpx.HTTPError as exc:
        return False, f"нет соединения ({type(exc).__name__}): проверьте интернет, DNS, firewall и прокси на этом сервере"
    elapsed = time.monotonic() - started
    if response.status_code < 300:
        return True, f"OK, ответ за {elapsed:.1f} с"
    detail = response.text.replace(settings.llm_api_key, "***")[:200].replace("\n", " ")
    if response.status_code >= 500:
        hint = "Провайдер перегружен или недоступен (временная ошибка). Включите резервную модель в LLM_FALLBACK_MODELS."
    else:
        hint = HINTS.get(response.status_code, "Неожиданный ответ провайдера.")
    return False, f"HTTP {response.status_code}: {hint}\n      ответ провайдера: {detail}"


def main() -> int:
    settings = Settings.from_env()
    print(f"Провайдер: {settings.llm_base_url}")
    if not settings.llm_api_key:
        print("✗ LLM_API_KEY пуст — задайте ключ в .env и перезапустите сервер.")
        return 1
    if not settings.llm_model:
        print("✗ LLM_MODEL пуст — без модели LLM считается ненастроенным (пример: gemini-3.5-flash).")
        return 1
    results = []
    for index, model in enumerate((settings.llm_model, *settings.llm_fallback_models)):
        ok, message = check_model(settings, model)
        role = "основная" if index == 0 else "резервная"
        print(f"{'✓' if ok else '✗'} {role} модель {model}: {message}")
        results.append(ok)
    if results[0]:
        print("\nLLM работает. Перезапустите сервер, если меняли .env.")
        return 0
    if any(results[1:]):
        print("\nОсновная модель недоступна, но резервная работает — сервер переключится на неё автоматически.")
        return 0
    print("\nLLM не работает с этого сервера — приложение будет использовать резервный разбор по правилам.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
