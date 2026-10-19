# Controlled Detection Validation Scripts

These scripts validate EDR4's passive rules against the local OWASP Juice Shop instance. They are intentionally bounded and hard-coded to `http://127.0.0.1:3000`. They refuse non-loopback or non-port-3000 targets.

Start EDR4 in one terminal:

```bash
cd "$HOME/edr4"
source .venv/bin/activate
python3 main.py
```

Run one test at a time from another terminal:

```bash
cd "$HOME/edr4"
.venv/bin/python scripts/test_request_rate.py
.venv/bin/python scripts/test_auth_401.py
.venv/bin/python scripts/test_status_anomaly.py
.venv/bin/python scripts/test_url_sqli.py
.venv/bin/python scripts/test_process_state.py
```

The first four generate controlled local HTTP telemetry. The process-state script is entirely synthetic: it reads the real MainPID but never signals, stops, restarts, or modifies a process.

Keep EDR4 running in the first terminal while invoking a test. Detection findings
appear in the EDR4 terminal, not as output from the traffic-generation script.
Duplicate findings for the same rule and scope are suppressed for the configured
cooldown period. With the default configuration, wait 60 seconds before repeating
the same test. Requests generated during the cooldown are still collected and
persisted; only the duplicate finding is suppressed.

Verify persisted live findings:

```bash
.venv/bin/python scripts/verify_detections.py --since-minutes 10 \
  --expect request_rate \
  --expect repeated_auth_401 \
  --expect status_anomaly \
  --expect url_sqli
```

`test_process_state.py` validates the rule in-process and does not inject synthetic findings into the running EDR or its database.

Email delivery has a separate, explicit validation command. It sends one
external message and therefore requires both a valid local `alerts.cfg` and the
`--send` confirmation flag:

```bash
.venv/bin/python scripts/test_email_notification.py --send
```

The command prints only immediate SMTP accepted/refused counts. It does not
display addresses, credentials, SMTP responses, or message content. An
accepted recipient can still be filtered, quarantined, or rejected later by
the destination mail system.

## Scripts

| Script | Purpose | Default bound |
|---|---|---:|
| `test_request_rate.py` | Trigger global and per-source rate thresholds through a REST endpoint confirmed to reach Morgan | 35 requests, maximum 60 |
| `test_auth_401.py` | Trigger repeated authentication-like 401 threshold | 5 attempts, maximum 10 |
| `test_status_anomaly.py` | Trigger elevated 5xx ratio on a missing API route | 20 requests, maximum 30 |
| `test_url_sqli.py` | Trigger privacy-preserving URL SQLi metadata and detection | One local GET request |
| `test_process_state.py` | Validate PID/state/unavailable handling synthetically | No HTTP or process changes |
| `test_email_notification.py` | Send one explicit Gmail SMTP configuration test | Exactly one email with `--send` |
| `verify_detections.py` | Summarize recent SQLite detection events | Maximum 24-hour lookback |

## Safety and privacy

- Use only on the university-controlled Juice Shop VM.
- Keep the target fixed to loopback.
- Do not increase the hard request bounds.
- Do not run these scripts against public or third-party systems.
- The dummy login values are intentionally invalid and are never printed.
- EDR4 does not ingest request bodies, raw query values, cookies, or Authorization headers.
- The URL SQLi script sends one encoded, non-destructive test string to the local search endpoint. It does not print the input or response body and does not modify application data.
- These scripts do not test XSS, RCE, file upload, or destructive denial-of-service behavior.
- Findings are passive; the response manager remains disabled.
- The email test is the only script that communicates with an external service;
  it never runs without the explicit `--send` flag.
