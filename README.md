# EDR4 Telemetry Prototype

EDR4 is a lightweight educational telemetry prototype for the Ubuntu VM running OWASP Juice Shop. It implements:

> **Collect → Normalise → Display → Persist**

It observes the existing host and application telemetry. It does not modify Juice Shop, block traffic, quarantine files, terminate processes, alter firewall rules, or perform any other active response.

For first-time setup, follow [INSTALL.md](INSTALL.md).

## Quick start

```bash
cd "$HOME/edr4"
source .venv/bin/activate
python3 main.py
```

Verbose mode displays redacted structured event data:

```bash
python3 main.py --verbose
```

Stop cleanly with Ctrl+C.

## Architecture

```text
Morgan --------\
Journal --------> Event Queue -> Central Consumer -> Console
Process --------/                              \--> SQLite
System --------/                               \--> Detection Engine [passive]
                                                       |
                                                       \--> Response Manager [inactive]
```

Each collector runs in an isolated thread and publishes a common `TelemetryEvent` into a thread-safe queue. The central consumer handles console rendering, persistence, and passive detection. Collectors never write directly to SQLite.

Every event contains:

- UUID event ID
- timezone-aware UTC timestamp
- hostname
- event type and source
- severity
- concise message
- source-specific structured data

## Current collectors

### Morgan HTTP

Follows the newest file matching the configured `access.log.*` glob, starts at EOF by default, and follows rotation or replacement.

Collected fields include timestamp, client/source field, method, path, query presence, query key names, status, response size, sanitized referrer, user agent, and privacy-preserving URL SQLi indicator metadata.

Raw query values are inspected transiently for a small set of URL SQLi patterns and then discarded. Request bodies, cookies, and Authorization headers are not ingested.

### Juice Shop journal

Runs `journalctl -u juice-shop.service -f -n 0 -o json` and normalizes timestamp, priority, unit, PID, identifier, and message. Malformed records are skipped and a failed journal follower is retried.

### Juice Shop process

Resolves the current process dynamically with:

```text
systemctl show juice-shop.service -p MainPID --value
```

It collects PID, PPID, process name, username, status, create time, CPU, memory, RSS, thread count, and direct child count. PID changes and service disappearance are handled without restarting EDR4.

### System and network

Collects host CPU, memory, disk, load average, interface counters and rates, and aggregate TCP state counts. It uses psutil first and falls back to `ss` for TCP state counts if permissions prevent psutil access.

Individual sockets are not printed in normal mode.

## Console modes

Normal mode is event-focused. It shows startup and shutdown messages, passive
detection findings, service-state changes, collector/storage errors, and
warning-or-higher HTTP and journal events. Routine successful HTTP requests and
recurring process, system, and network snapshots are still collected and
persisted according to policy, but do not fill the console.

For example, a request-rate validation produces concise findings such as:

```text
20:19:42 WARNING [DETECTION] Per-source HTTP request-rate threshold exceeded: 20 requests/10s src=127.0.0.1
20:19:42 WARNING [DETECTION] HTTP request-rate threshold exceeded: 30 requests/10s
```

Verbose mode shows every telemetry sample and additionally includes event UUIDs
and redacted structured data such as PPID, thread count, response size,
query-key names, packet rates, and connection-state distributions.

Verbose mode does not disable privacy controls.

## Configuration

Settings are in `config.toml`.

| Setting | Default | Purpose |
|---|---:|---|
| `general.service` | `juice-shop.service` | Service used for PID and journal discovery |
| `general.poll_interval_seconds` | `5` | Process and system/network collection interval |
| `general.network_interface` | `ens33` | Interface used for network counters |
| `collectors.morgan.path` | `/home/juice/juice-shop/logs/access.log.*` | Rotation-aware log glob |
| `collectors.morgan.start_at_end` | `true` | Avoid replaying historical HTTP records |
| `storage.path` | `data/edr4.db` | SQLite database path, relative to the project |
| `storage.metric_persist_interval_seconds` | `15` | Persistence interval for periodic snapshots |
| `storage.retention_days` | `3` | Event retention period |
| `storage.cleanup_interval_seconds` | `3600` | Runtime cleanup interval |

Collectors and individual passive rules can be disabled using their `enabled` keys. Response remains disabled.

Command-line `--verbose` overrides the console setting.

## Passive detection rules

Detection is enabled by default and does not change the host, application, firewall, files, or processes. Findings are displayed as `[DETECTION]` events and persisted to SQLite with the source event ID and rule metadata.

| Rule | Default behavior |
|---|---|
| URL SQLi indicators | Warn when decoded URL path or query data contains SQLi-like boolean expressions, UNION SELECT, stacked statements, delay functions, schema enumeration, or correlated SQL comments |
| Request rate | Warn at 30 total requests in 10 seconds or 20 requests from one source in 10 seconds |
| Repeated auth-like 401 | Warn after 5 HTTP 401 responses from one source in 60 seconds on a path containing `/login` or `/authenticate` |
| Status anomaly | After at least 20 requests in 60 seconds, warn when 4xx responses reach 50% or error when 5xx responses reach 20% |
| Process state | Report service loss, PID replacement, or entry into configured abnormal states such as `zombie`, `stopped`, or `dead` |

Each rule/scope has a default 60-second cooldown to reduce repeated findings. State is kept in memory and resets when EDR4 restarts.

These are heuristics, not proof of an attack. Tune them using observed normal traffic before treating findings as operational alerts. A repeated authentication-like 401 finding is deliberately not labelled as confirmed brute force, and URL SQLi findings are labelled as possible attempts.

## SQLite storage

The default database is:

```text
$HOME/edr4/data/edr4.db
```

SQLite uses WAL mode. The `events` table is indexed by timestamp, event type, source, and severity.

- Every Morgan HTTP event is persisted.
- Every journal event received while running is persisted.
- Every passive detection finding is persisted.
- Process, system, and network events are shown every poll only in verbose mode and persist approximately every 15 seconds.
- Retention cleanup runs at startup and approximately hourly, not on every insert.

A safe summary query using Python:

```bash
.venv/bin/python - <<'PY'
import sqlite3

connection = sqlite3.connect("data/edr4.db")
for row in connection.execute(
    "SELECT event_type, severity, COUNT(*) "
    "FROM events GROUP BY event_type, severity ORDER BY event_type, severity"
):
    print(row)
connection.close()
PY
```

Avoid casually printing complete `data_json` or journal messages from shared databases. Although redaction is applied, free-form source data should still be handled as telemetry with restricted access.

## Privacy and redaction

The primary privacy control is limiting collection:

- no HTTP request bodies
- no raw query values
- no cookie headers
- no Authorization headers
- no session or authentication token collection

Referrer query strings are removed. Only ordinary-looking query key names are retained; unusual components become `[unusual_key]`. URL values are decoded only inside the parser to derive SQLi indicator categories and input locations, then discarded before the event enters the queue. SQLi-like path content is replaced with `[REDACTED_SQLI_INPUT]`. Obvious secret-bearing path segments are replaced with `[REDACTED]`. Free-form strings and structured data receive additional key/pattern redaction and length limits before console output and SQLite storage.

Redaction is best effort, not a guarantee. Restrict access to both console output and `data/edr4.db`.

## Running tests

```bash
cd "$HOME/edr4"
.venv/bin/python -m unittest discover -s tests -v
```

The tests cover:

- valid and malformed Morgan lines
- status and response-size parsing
- query stripping and key extraction
- removal of sensitive query values
- unusual query-component handling
- secret-like path redaction
- URL SQLi metadata extraction without payload retention
- URL SQLi detector behavior and cooldown
- database creation and JSON persistence
- unique event IDs
- storage redaction
- retention cleanup
- request-rate global/per-source windows and cooldowns
- repeated authentication-like 401 thresholds
- 4xx/5xx status-ratio anomalies
- process PID, availability, and abnormal-state changes

Tests do not modify or attack Juice Shop.

## Controlled validation scripts

Bounded, localhost-only validation scripts are available under `scripts/` for URL SQLi metadata, request-rate, repeated auth-like 401, status-anomaly, and synthetic process-state testing. Keep EDR4 running in one terminal, then follow [scripts/README.md](scripts/README.md) from another terminal.

The scripts are intended only for the university-controlled VM. They do not accept a remote target, and the process-state test never controls or modifies the real Juice Shop process.

## Shutdown behavior

SIGINT and SIGTERM signal every collector, terminate the journal follower, stop follow/poll loops, drain queued events, commit pending SQLite writes, and close the database.

Expected shutdown:

```text
EDR4 shutting down...
Collectors stopped.
Database closed.
```

## Project layout

```text
edr4/
├── main.py
├── config.toml
├── requirements.txt
├── INSTALL.md
├── README.md
├── collectors/        # Morgan, journal, process, system/network
├── core/              # event model, queue, config, logging, redaction
├── detection/         # passive rules, cooldowns and detection engine
├── response/          # inactive interfaces for later rounds
├── scripts/           # controlled localhost-only detector validation
├── storage/           # SQLite database and persistence policy
├── tests/             # unit tests
└── data/edr4.db       # runtime telemetry database
```

## Current limitations

- No filesystem monitoring.
- No automated or active response.
- No HTTP body, request-size, or response-latency telemetry.
- Journal collection starts with new records and does not replay history.
- TCP information may be incomplete under restricted permissions.
- Morgan starts at EOF by default.
- Retention state and metric throttling are local to each running EDR process.
- Detection windows and cooldown state reset when EDR4 restarts.
- Default thresholds are initial heuristics and require baseline-driven tuning.
- This is a university prototype, not a hardened production EDR.

## Development boundaries

Do not add blocking, firewall changes, process termination, quarantine, service modification, or attack-generation behavior. Findings remain passive telemetry; the response manager performs no actions.
