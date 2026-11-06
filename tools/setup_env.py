"""Подготовка .env одной командой: ключ LLM и (по желанию) настройки доступа по сети.

    python -m tools.setup_env            # локальный запуск
    python -m tools.setup_env --remote   # доступ с других компьютеров: токен, ALLOWED_HOSTS, ALLOWED_ORIGINS

Ключ берётся из переменной окружения LLM_API_KEY или запрашивается; сам ключ нигде не печатается.
"""
import argparse
import getpass
import os
import re
import secrets
import socket
import sys
from pathlib import Path

ENV = Path(__file__).resolve().parent.parent / ".env"
EXAMPLE = ENV.with_name(".env.example")


def get_value(text: str, key: str) -> str:
    match = re.search(rf"^{key}=(.*)$", text, re.M)
    return match.group(1).strip() if match else ""


def set_value(text: str, key: str, value: str) -> str:
    line = f"{key}={value}"
    pattern = re.compile(rf"^{key}=.*$", re.M)
    if pattern.search(text):
        return pattern.sub(lambda _: line, text, count=1)
    return text.rstrip("\n") + "\n" + line + "\n"


def local_ip() -> str:
    try:  # пакеты не отправляются: так узнаётся адрес сетевого интерфейса
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--remote", action="store_true", help="разрешить доступ с других компьютеров")
    parser.add_argument("--ip", help="адрес сервера для ALLOWED_HOSTS/ORIGINS (по умолчанию определяется сам)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    args = parser.parse_args()

    text = (ENV if ENV.exists() else EXAMPLE).read_text(encoding="utf-8")
    if not get_value(text, "LLM_API_KEY"):
        key = os.environ.get("LLM_API_KEY", "").strip()
        if not key and sys.stdin.isatty():
            key = getpass.getpass("Вставьте API-ключ Gemini (ввод скрыт; Enter — работать без ИИ): ").strip()
        if key:
            text = set_value(text, "LLM_API_KEY", key.strip("\"'"))
            print("✓ Ключ сохранён в .env")
        else:
            print("! Ключ не задан — будет работать только разбор по правилам. Добавьте LLM_API_KEY в .env позже.")
    if args.remote:
        ip = args.ip or local_ip()
        token = get_value(text, "API_TOKEN")
        if len(token) < 24:
            token = secrets.token_hex(24)
            text = set_value(text, "API_TOKEN", token)
        text = set_value(text, "ALLOWED_HOSTS", f"{ip},localhost,127.0.0.1")
        text = set_value(text, "ALLOWED_ORIGINS", f"http://{ip}:{args.port}")
        print(f"✓ Доступ по сети: http://{ip}:{args.port}")
        print(f"  Токен для входа (значок 🔑 в интерфейсе): {token}")
    ENV.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
