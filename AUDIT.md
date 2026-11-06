# SOC AI Triage audit

**Follow-up, 2026-11-06:** The findings below retain the original audit evidence. Engineering changes and regression checks are documented in [the technical improvement report](docs/TECHNICAL_IMPROVEMENTS_RU.md). A01–A05 and A07–A09 have targeted fixes; A06 has stronger evidence/action constraints, while free-text semantic correctness still requires analyst review.

Date: 2026-11-06 (Asia/Almaty)

The main fixes to prioritize are structured secret masking, reliable rule correlation, and server-side filtering. The existing regression suite passes, but additional synthetic reproductions exposed cases outside its coverage.

The audit covered backend/API code, rule evaluation, LLM response handling, frontend data loading, configuration, and installed dependencies. Application code, the running server, and the application database were left unchanged. Reproductions used temporary databases and synthetic inputs. LLM tests used httpx MockTransport; no Gemini request was made and no `.env` values were printed.

**Checks completed**

| Check | Result |
| --- | --- |
| Python suite | 70 passed; one Starlette/httpx TestClient deprecation warning |
| Frontend suite | 12 passed |
| JavaScript syntax | Passed |
| Python dependency consistency | `pip check` passed |
| npm dependency audit, including dev dependencies | No advisories reported |
| Installed Python dependency audit | Findings only in the virtual environment's pip 25.3; details below |
| `.env` file mode | 0600 |
| Existing source archive | Does not contain `.env` |
| Credential-pattern scan of application/test source | Only the explicitly fake OpenAI-style key in test_api.py matched |

Priorities below describe engineering urgency, not CVSS scores. P1 should be addressed before processing real security logs; P2 affects correctness, resilience, or deployment safety; P3 improves diagnosis and operation.

**A01 — P1: Common JSON secret formats bypass masking**

Location: `backend/security.py:6`, `backend/security.py:24`, `backend/main.py:189`, `backend/ai_service.py:57`.

Reproduced inputs:

```json
{"password":123456}
{"headers":{"X-API-Key":"audit-fake-header-value"}}
{"password":{"value":"audit-fake-nested-value"}}
```

All three were stored unchanged and returned unchanged by the create API. A mocked LLM transport also received the numeric password unchanged. JSON_SECRET recognizes a narrow set of exact names with quoted scalar values; scrub_tree recursively processes values without inspecting sensitive dictionary keys.

Impact: credentials in normal structured-log formats can remain in SQLite, API responses, and outbound LLM requests. Exact configured secrets are separately replaced, so this finding concerns other credentials present in imported logs.

Recommended change: parse valid JSON/JSONL, normalize sensitive key names, and replace the complete associated value regardless of its type. Cover common headers such as X-API-Key. Preserve the text redactor as a fallback for plain logs. Apply the same redaction policy at ingestion, serialization, and the provider boundary.

Regression checks: numeric, array, nested-object, mixed-case and header credentials must be absent from storage, API output and captured provider requests. Include tests that verify valid JSON remains parseable after masking.

**A02 — P2: PowerShell detection combines unrelated records**

Location: `backend/rule_engine.py:120`, `backend/playbooks.py:28`.

Reproduction:

```json
{"events":[
  {"command":"powershell.exe Get-Date"},
  {"command":"other-tool.exe -ExecutionPolicy Bypass -WindowStyle Hidden"}
]}
```

Observed: R003 fires with policy_bypass and hidden_window and rules_only assigns High. The structured PowerShell command has neither parameter. The fallback then scans the entire serialized JSON and combines PowerShell from the first record with parameters from the second.

Recommended change: bind process identity and suspicious parameters to one command field/record. For parsed structured logs, evaluate those command fields individually. For unstructured input, evaluate individual command-bearing lines rather than concatenating the whole document. Keep evidence linked to the matched record.

**A03 — P2: A null username is treated as a known account**

Location: `backend/rule_engine.py:84`, `backend/rule_engine.py:108`.

Reproduction: a failed_login aggregate of 10 attempts followed by successful_login, with user=null on both records, within the supported window.

Observed: R001 and R002 fire and the result is High. Converting the raw value with str() turns null into the nonempty string "None", bypassing the intended requirement for a known matching user. Booleans and compound JSON values can similarly become nonempty account names.

Recommended change: validate account names before correlation. Only accept a nonblank string as a known user; keep null/missing/invalid values explicitly unknown. R001 may still describe an unattributed failure burst, but R002 must not assert a same-account sequence without that identity.

**A04 — P2: Filters can hide existing older alerts**

Location: `frontend/app.js:90`, `frontend/app.js:113`, `backend/main.py:170`.

Reproduction: a 150-alert fixture with its only confirmed alert at position 150. Initial loading fetches 100 alerts. Selecting Confirmed produces zero visible rows and no status parameter is sent to the API. Searching the known name of alert 150 also produces zero results.

Impact: analysts can be told that no matching events exist even when the matching event is stored. This is especially relevant now that the local load test has pushed the queue beyond one page.

Recommended change: perform status and text filtering in the backend and apply pagination to the filtered result set. Return the filtered total. Preserve search/status during polling, and consider a stable created_at/id cursor so new arrivals do not shift offset pages.

Regression check: matching events beyond the first page must be found directly, without requiring the analyst to load the unfiltered backlog first.

**A05 — P2: SQLite contention blocks the async server loop**

Location: `backend/main.py:209`, `backend/database.py:21`; related polling writes at `backend/main.py:40`.

The async analyze route executes synchronous session operations directly. In an isolated reproduction, a temporary SQLite write lock was held for about 450 ms while an analysis request ran. An independent async heartbeat scheduled for 30 ms resumed after 480.4 ms; the analysis eventually returned 200.

Impact: a blocked database operation can delay unrelated async work. The configured SQLite busy wait can last up to 15 seconds. The earlier successful 25/s test does not rule out this contention case.

Recommended change: move each short database transaction into a synchronous helper invoked through the thread pool, with its own session; alternatively adopt an async database driver. Do not share a live Session between threads. Keep the existing atomic claim/token checks. Move expired-lease cleanup away from every read/poll request, or only write when expiration actually needs recovery.

Regression check: a blocked write should not stall an independent heartbeat or unrelated request handling.

**A06 — P2: Valid JSON does not establish trustworthy LLM evidence/actions**

Location: `backend/ai_service.py:54`, `backend/ai_service.py:83`, `backend/schemas.py:64`.

A synthetic mocked response invented an unrelated IP and privileged login, claimed that a human analyst had confirmed the incident, and recommended deleting audit logs/backups. The response was accepted because its fields were structurally valid and its evidence source was the permitted label raw_data.

This reproduces a validator gap, not a claim that a live Gemini model produced that answer. The application does not execute the recommendation, and analyst status remains separately controlled. Those are useful safeguards, but the text can still mislead an analyst.

Recommended change: ground evidence in server-issued record identifiers plus exact supporting excerpts/fields. Validate that references and quoted values exist in the supplied data. Resolve recommended action IDs to vetted Playbook text instead of accepting arbitrary operational instructions. Treat free-form conclusions as unverified, and retain human confirmation solely as application-owned state.

Regression checks: nonexistent facts cannot become validated evidence merely by citing raw_data; unapproved destructive actions cannot enter recommended_actions.

**A07 — P2 for external deployment: Read APIs are anonymous even with API_TOKEN**

Location: `backend/main.py:100`, `backend/main.py:170`, `backend/main.py:194`.

With API_TOKEN set, an unauthenticated synthetic external client received 200 for alert listing and alert details, while a write received 401. Analyses/history are likewise read endpoints without the write dependency.

This matches the documented MVP's write-only token policy; it is a deployment-hardening gap rather than a violation of that stated contract. Default loopback binding limits current exposure. It becomes a confidentiality issue if the app is served externally without the authenticated reverse proxy described in README.

Recommended change before network exposure: authenticate reads as well as writes, leaving only a minimal liveness response public. Keep token configuration, UI login behavior and documentation consistent with that policy.

**A08 — P3: Provider failures lose actionable diagnostic information**

Location: `backend/ai_service.py:93`, `frontend/app.js:125`.

Mocked HTTP 401, 429 and 500 responses all produced the same fallback explanation. The UI's availability label is based on whether key/model strings are present, not a successful provider operation.

Recommended change: keep fallback, but expose sanitized reason codes such as credentials_rejected, quota_or_rate_limit, timeout and provider_error. Record the last successful LLM analysis and the current analysis's actual mode. Never expose provider headers, keys or an unredacted error body. Add bounded concurrency/backoff for provider rate limits.

**A09 — Tooling: Update the environment's pip installer**

The application environment contains pip 25.3. pip-audit returned ten entries representing five distinct advisory IDs, all attached to pip: PYSEC-2026-1796, PYSEC-2026-2875, PYSEC-2026-2876, PYSEC-2026-196 and PYSEC-2026-3721. It reported no advisories for the installed application/framework packages in this scan.

These findings concern package installation/download workflows. They are not evidence of a remotely exploitable FastAPI endpoint. The PyPA advisory for PYSEC-2026-3721 lists 26.2 as a fixed version; GitHub lists 26.2.0. [PyPA advisory](https://github.com/pypa/advisory-database/blob/main/vulns/pip/PYSEC-2026-3721.yaml), [reviewed advisory](https://github.com/advisories/GHSA-qwm4-qh6w-59xr).

Recommended change: upgrade the installer to a current patched release (at least 26.2.0 for the reported set), then rerun the scan. Add the installer upgrade step to environment setup. The audit did not modify the project environment or requirements.

**Suggested implementation order**

1. Fix structured masking and add end-to-end privacy regression cases.
2. Correct R003 record binding and R002 account normalization.
3. Move filtering/pagination to the server; add a regression with more than 100 alerts.
4. Add evidence provenance and vetted Playbook action IDs.
5. Remove blocking database work from the async route and unnecessary polling writes.
6. Improve provider diagnostics and bound provider concurrency.
7. Apply the read-authentication policy before external deployment; patch installer tooling.

**Further improvements within the MVP's scope**

- Show last ingestion time, events received per time window and a distinct synthetic-data label. Count events accepted by the ingestion API separately from HTTP health checks so the load-test behavior is clear.
- Add append-only analysis-attempt records with safe error codes and request IDs. Currently successful analyses are retained, but a later successful retry obscures the reason for a prior failed attempt.
- When viewing an archived analysis, display its stored rule_findings snapshot. The current details panel recomputes rules using today's engine/configuration, which can differ from the historical result.
- Add CI for the advertised Python versions/operating systems and automated browser checks at 360 px. Include the adversarial cases above; passing the current happy-path suite is insufficient coverage for them.
- Plan schema migrations before changing persisted models. create_all creates missing tables but is not a schema migration strategy for existing databases.

No application fixes were applied as part of this audit. The live Gemini integration, physical mobile devices and Windows/Linux execution were not exercised in this audit run.
