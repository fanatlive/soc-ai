"""Send synthetic security logs to the real, local ingestion API at a fixed rate."""
import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import json
import math
import time
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from backend.config import ROOT, Settings


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--rate", type=int, default=25, help="Requests per second, 1–100")
    parser.add_argument("--seconds", type=int, default=10, help="Duration of each phase, 1–60 seconds")
    parser.add_argument("--analyze", action="store_true", help="Also analyze every accepted event, in a separate phase at the same rate")
    args = parser.parse_args()
    url = urlparse(args.url)
    if url.scheme != "http" or url.hostname not in {"127.0.0.1", "localhost", "::1"} or url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
        parser.error("Тест разрешен только для локального HTTP origin без пути и учетных данных")
    if not 1 <= args.rate <= 100 or not 1 <= args.seconds <= 60:
        parser.error("rate: 1–100; seconds: 1–60")
    return args


def event_payload(template, sequence, run_id, now, rate=25):
    original = datetime.fromisoformat(template["timestamp"].replace("Z", "+00:00"))
    shift = now - original

    def rebase(value):
        if isinstance(value, list):
            return [rebase(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key in {"at", "timestamp"} and isinstance(item, str):
                    result[key] = (datetime.fromisoformat(item.replace("Z", "+00:00")) + shift).isoformat()
                else:
                    result[key] = rebase(item)
            return result
        return value

    raw = rebase(json.loads(template["raw_data"]))
    raw.update(synthetic=True, test_run=run_id, sequence=sequence)
    return {
        "timestamp": now.isoformat(), "source_ip": template["source_ip"],
        "event_type": f"Тест {rate}/с · #{sequence:03d} · {template['event_type']}"[:80],
        "raw_data": json.dumps(raw, ensure_ascii=False, separators=(",", ":")),
    }


async def paced_requests(client, items, rate, send):
    results = []
    started = time.perf_counter()

    async def one(index, item):
        await asyncio.sleep(max(0, started + index / rate - time.perf_counter()))
        sent = time.perf_counter()
        try:
            response = await send(client, item)
            status = str(response.status_code)
            if response.is_success:
                data = response.json()
            else:
                data = None
        except (httpx.HTTPError, ValueError) as exc:
            status, data = type(exc).__name__, None
        results.append({"second": math.floor(sent - started), "status": status, "data": data})

    await asyncio.gather(*(one(index, item) for index, item in enumerate(items)))
    return results


def phase_summary(results):
    return {"requests": len(results), "statuses": dict(Counter(row["status"] for row in results)),
            "requests_per_second": dict(sorted(Counter(row["second"] for row in results).items()))}


async def run(args):
    settings = Settings.from_env()
    headers = {"Authorization": f"Bearer {settings.api_token}"} if settings.api_token else {}
    limits = httpx.Limits(max_connections=100, max_keepalive_connections=25)
    async with httpx.AsyncClient(base_url=args.url.rstrip("/"), headers=headers, limits=limits,
                                 timeout=135, follow_redirects=False, trust_env=False) as client:
        health = await client.get("/api/health")
        health.raise_for_status()
        before = await client.get("/api/stats")
        before.raise_for_status()
        templates = json.loads((ROOT / "backend" / "seed_alerts.json").read_text(encoding="utf-8"))
        count = args.rate * args.seconds
        run_id = "load-test-" + uuid4().hex[:12]
        started = datetime.now(timezone.utc)
        payloads = [event_payload(templates[index % len(templates)], index + 1, run_id, started, args.rate) for index in range(count)]

        async def create(client, payload):
            return await client.post("/api/alerts", json=payload)

        created = await paced_requests(client, payloads, args.rate, create)
        ids = [row["data"]["id"] for row in created if row["data"] is not None]
        report = {"run_id": run_id, "target": args.url, "before": before.json(), "ingestion": phase_summary(created)}
        print(json.dumps({"run_id": run_id, "created": len(ids), "phase": "ingestion"}, ensure_ascii=False), flush=True)

        if args.analyze and ids:
            async def analyze(client, alert_id):
                return await client.post(f"/api/alerts/{alert_id}/analyze")

            analyses = await paced_requests(client, ids, args.rate, analyze)
            report["analysis"] = {**phase_summary(analyses),
                "modes": dict(Counter(row["data"]["analysis_mode"] for row in analyses if row["data"])),
                "severities": dict(Counter(row["data"]["severity"] for row in analyses if row["data"]))}

        # Verify persisted IDs through the read API, rather than trusting POST counts.
        found = set()
        for offset in range(0, max(count + before.json()["total"], 1), 500):
            page = await client.get(f"/api/alerts?limit=500&offset={offset}")
            page.raise_for_status()
            rows = page.json()
            found.update(row["id"] for row in rows if run_id in row["raw_data"])
            if len(found) >= len(ids) or len(rows) < 500:
                break
        after = await client.get("/api/stats")
        after.raise_for_status()
        report.update(verified_saved_events=len(found), after=after.json())
        print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
        failures = len(ids) != count or found != set(ids)
        if args.analyze:
            failures |= report.get("analysis", {}).get("statuses") != {"200": len(ids)}
        return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(run(arguments())))
    except httpx.HTTPError:
        raise SystemExit("Не удалось обратиться к локальному API. Проверьте сервер, порт и API_TOKEN.")
