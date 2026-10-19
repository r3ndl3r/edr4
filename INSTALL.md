# Installing EDR4

This guide installs the EDR4 telemetry prototype for a team member on an Ubuntu host running OWASP Juice Shop. EDR4 is currently a foreground Python application; do not create a systemd unit for it yet.

## 1. Prerequisites

EDR4 expects:

- Ubuntu or a similar Linux distribution using systemd
- Python with built-in `tomllib` support
- `systemctl`, `journalctl`, and `ss`
- A running OWASP Juice Shop systemd service
- Read access to the Juice Shop Morgan access logs and journal
- Enough disk space for the Python environment and short-retention SQLite database

Check the host before installing:

```bash
python3 -c 'import tomllib; print("Python TOML support available")'
command -v systemctl journalctl ss
systemctl show juice-shop.service \
  -p LoadState -p ActiveState -p MainPID -p WorkingDirectory
df -h "$HOME"
```

`MainPID` may change and must not be copied into configuration. EDR4 resolves it dynamically.

## 2. Obtain the project

Copy or check out the `edr4` directory into the team member's home directory. The expected default location on the current VM is:

```text
/home/juice/edr4
```

The code can run elsewhere, but absolute paths in `config.toml` must match that host's Juice Shop deployment.

```bash
cd "$HOME/edr4"
```

## 3. Install venv support

First try creating the environment without installing anything globally:

```bash
python3 -m venv .venv
```

If Ubuntu reports that `ensurepip` is unavailable, install the matching venv package:

```bash
sudo apt-get update
sudo apt-get install -y python3-venv
```

Then recreate the environment:

```bash
python3 -m venv --clear .venv
```

Do not install psutil into the system Python and do not run pip with sudo.

## 4. Install the Python dependency

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -c 'import psutil; print(psutil.__version__)'
```

`requirements.txt` intentionally contains only psutil.

## 5. Verify host paths and permissions

Review `config.toml` and confirm these settings for the target host:

```toml
[general]
service = "juice-shop.service"
network_interface = "ens33"

[collectors.morgan]
path = "/home/juice/juice-shop/logs/access.log.*"
```

Check the configured interface and telemetry sources:

```bash
ip -brief address
systemctl show juice-shop.service -p MainPID --value
ls -l /home/juice/juice-shop/logs/access.log.*
journalctl -u juice-shop.service -n 1 -o json --no-pager
```

If the journal command reports insufficient permissions, check group membership:

```bash
id -nG
```

On the current VM, membership in `adm` permits the required reads. Ask the system administrator to grant the narrowest appropriate access if needed. Do not make the logs world-readable and do not change Juice Shop permissions merely to bypass an error.

## 6. Configure optional Gmail alerts

Email alerts are optional. When `alerts.cfg` is absent, EDR4 continues normally
with email disabled.

Create the local credential file directly with owner-only permissions:

```bash
cd "$HOME/edr4"
install -m 600 alerts.cfg.example alerts.cfg
nano alerts.cfg
```

Enter only the Gmail username, Gmail app password, and comma-separated
recipients:

```ini
[gmail]
username = sender@gmail.com
app_password = gmail-application-password
recipients = first@example.com, second@example.com
```

Use a Gmail app password, not the account's ordinary password. The Google
account must support app passwords and have two-step verification enabled.

Confirm permissions and Git exclusion before starting EDR4:

```bash
stat -c '%a %U %n' alerts.cfg
git check-ignore -v alerts.cfg
```

The mode must be `600` or stricter and the owner must be the user running EDR4.
The real file is ignored by Git; `alerts.cfg.example` is the safe team template.

To send exactly one external configuration-test message:

```bash
.venv/bin/python scripts/test_email_notification.py --send
```

The script does not print addresses, credentials, message content, or raw SMTP
responses. It reports immediate accepted/refused counts, but SMTP acceptance
does not prove final inbox delivery. Check junk mail, institutional quarantine,
and the sending account for a delayed bounce when a recipient does not receive
the test message.

## 7. Run the tests

```bash
cd "$HOME/edr4"
.venv/bin/python -m unittest discover -s tests -v
```

All tests should end with `OK`.

## 8. First run

Activate the environment and start EDR4:

```bash
cd "$HOME/edr4"
source .venv/bin/activate
python3 main.py
```

Or run it without activation:

```bash
cd "$HOME/edr4"
.venv/bin/python main.py
```

Expected startup indicators include all four collectors marked `ON`, detection
marked `enabled (passive)`, response marked `disabled`, and email alerts marked
either `disabled` or enabled with a recipient count. Normal mode intentionally
suppresses routine process/system/network snapshots; use `--verbose` when
validating every collector sample.

Make one benign request to verify the live Morgan pipeline if normal traffic is not already present:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:3000/rest/products/search?q=edr4-install-check'
```

Because Morgan starts at EOF by default, the request must occur after EDR4 starts. The fixed query value is benign, and EDR4 stores only the query key. Do not perform attack testing as part of installation verification.

Stop with Ctrl+C. A clean shutdown reports:

```text
EDR4 shutting down...
Collectors stopped.
Database closed.
```

## 9. Verify SQLite persistence

The default database is `data/edr4.db`. Verify it using Python, which does not require the optional SQLite command-line utility:

```bash
.venv/bin/python - <<'PY'
import sqlite3

connection = sqlite3.connect("data/edr4.db")
print("journal_mode:", connection.execute("PRAGMA journal_mode").fetchone()[0])
print("events:", connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
print("types:", connection.execute(
    "SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY event_type"
).fetchall())
connection.close()
PY
```

The journal mode should be `wal`. Restart EDR4 and confirm the event count does not reset.

## 10. Troubleshooting

### Email alerts are disabled

- Confirm `alerts.cfg` exists in the project root.
- Confirm it contains only the `[gmail]` section and the three required keys.
- Confirm it is owned by the EDR user and has mode `600`.
- Confirm the Gmail account supports app passwords.
- Use the explicit test-email script to distinguish configuration and network
  failures from detection-threshold behavior.

EDR4 deliberately continues collecting telemetry when email configuration or
delivery fails.

### `ModuleNotFoundError: psutil`

The wrong Python interpreter is running. Activate `.venv` or use:

```bash
.venv/bin/python main.py
```

### No HTTP events

- Confirm the configured log glob matches an existing file.
- Confirm the file is readable.
- Generate a benign request after EDR4 starts.
- Remember that `start_at_end = true` intentionally avoids replaying old logs.

### No journal events

The collector only receives messages written after it starts. A quiet Juice Shop service may produce no journal events while EDR4 is running. Confirm access with:

```bash
journalctl -u juice-shop.service -n 1 -o json --no-pager
```

### Process collector reports no MainPID

```bash
systemctl status juice-shop.service --no-pager
systemctl show juice-shop.service -p MainPID --value
```

EDR4 keeps retrying and automatically attaches after the service returns.

### Interface rates remain zero or interface is missing

Use `ip -brief address` to find the active interface and update `general.network_interface` in `config.toml`.

### Database or disk errors

```bash
df -h "$HOME"
ls -ld "$HOME/edr4/data"
```

The current default retention is three days because the VM has limited disk capacity. Avoid increasing retention until storage impact has been measured.

## 11. Uninstallation

EDR4 has no system service and makes no runtime system configuration changes.
Stop the foreground process before removing the project. The SQLite database
contains telemetry; preserve or delete it only according to the university
project's data-handling requirements.

If Gmail alerts were enabled, revoke the dedicated Gmail app password and
securely remove the local `alerts.cfg` as part of decommissioning.
