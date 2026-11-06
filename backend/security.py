"""Redaction is applied at ingestion, before LLM calls, and before API serialization."""
import json
import re

from starlette.responses import JSONResponse

SECRET_NAMES = r"(?:password|passwd|pwd|passphrase|(?:x[-_](?:goog[-_])?|llm[-_]|gemini[-_])?api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?(?:token|id)|token|client[_-]?secret|secret|authorization|cookie|set-cookie|private[_-]?key)"
SENSITIVE_KEYS = {"password", "passwd", "pwd", "passphrase", "apikey", "xapikey", "xgoogapikey", "llmapikey", "geminiapikey", "accesstoken", "refreshtoken", "idtoken", "sessiontoken", "sessionid", "token", "clientsecret", "secret", "authorization", "cookie", "setcookie", "privatekey"}
JSON_SECRET = re.compile(r'(?i)(["\']' + SECRET_NAMES + r'["\']\s*:\s*)("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')')
ASSIGNMENT = re.compile(r'(?i)(\b' + SECRET_NAMES + r'\b["\']?\s*[=:]\s*)("[^"\n]*"|\'[^\'\n]*\'|[^\s,;}]+)')


def sensitive_key(key: str) -> bool:
    return re.sub(r"[^a-z0-9]", "", key.casefold()) in SENSITIVE_KEYS


def redact_text(value: str, known_secrets: tuple[str, ...] = ()) -> str:
    for secret in sorted((item for item in known_secrets if item), key=len, reverse=True):
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", value, flags=re.S)
    value = JSON_SECRET.sub(lambda m: m[1] + '"[REDACTED]"', value)
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
    value = ASSIGNMENT.sub(lambda m: m[1] + '"[REDACTED]"', value)
    value = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "[REDACTED]", value)
    value = re.sub(r"(?i)(--(?:password|token|api-key)\s+)(\S+)", r"\1[REDACTED]", value)
    return value


def redact(value: str, known_secrets: tuple[str, ...] = ()) -> str:
    try:
        parsed = json.loads(value)
        if isinstance(parsed, (dict, list)):
            return json.dumps(scrub_tree(parsed, known_secrets), ensure_ascii=False, separators=(",", ":"))
    except (ValueError, TypeError, RecursionError):
        pass
    lines = value.splitlines()
    if len(lines) > 1:
        try:
            records = [json.loads(line) for line in lines if line.strip()]
            if records and all(isinstance(item, (dict, list)) for item in records):
                return "\n".join(json.dumps(scrub_tree(item, known_secrets), ensure_ascii=False, separators=(",", ":")) for item in records)
        except (ValueError, TypeError, RecursionError):
            pass
    return redact_text(value, known_secrets)


def scrub_tree(value, known_secrets: tuple[str, ...] = ()):
    if isinstance(value, str):
        return redact(value, known_secrets)
    if isinstance(value, list):
        return [scrub_tree(item, known_secrets) for item in value]
    if isinstance(value, dict):
        return {key: "[REDACTED]" if sensitive_key(str(key)) else scrub_tree(item, known_secrets) for key, item in value.items()}
    return value


class BodyLimitMiddleware:
    """Buffer at most 16 KiB before handing API mutations to JSON validation."""
    def __init__(self, app, max_bytes=16384):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"} or not scope["path"].startswith("/api/"):
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            data = message.get("body", b"")
            size += len(data)
            if size > self.max_bytes:
                return await JSONResponse(status_code=413, content={"detail": "Размер HTTP-запроса превышает 16 КиБ; лог ограничен 2000 символами."})(scope, receive, send)
            chunks.append(data)
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        return await self.app(scope, bounded_receive, send)
