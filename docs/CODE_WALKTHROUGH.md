# EDR4 Code Walkthrough

This guide is for team members who are new to Python. It explains how an event
moves through EDR4 and where to look when changing a collector, detector, or
storage behavior.

## Recommended reading order

1. `config.toml` — runtime settings and enabled components.
2. `core/events.py` — the common event structure.
3. `collectors/base.py` and `core/event_bus.py` — how collector threads publish.
4. One collector, such as `collectors/morgan.py`.
5. `main.py` — how the pipeline connects the components.
6. `detection/engine.py` and `detection/rules.py` — passive findings.
7. `storage/database.py` — persistence and retention.

## Event flow

```text
Collector thread
    |
    | creates TelemetryEvent
    v
EventBus queue
    |
    | central consumer in main.py
    +--> normal/verbose console filtering
    +--> SQLite persistence policy
    +--> each enabled detection rule
              |
              +--> detection event --> console and SQLite
              +--> inactive response manager
```

Collectors do not call SQLite or detection rules directly. This separation
keeps collection running if another part of the pipeline is slow or fails.

## Python concepts used by EDR4

### Type hints

An annotation such as `event: TelemetryEvent` describes the expected value. A
return annotation such as `-> list[Detection]` means the function returns a
list of `Detection` objects. Python does not enforce these hints at runtime;
they help readers, editors, and static-analysis tools.

`Path | None` means the value is either a `Path` or `None`. Code must check for
`None` before using it as a path.

### Dataclasses

`TelemetryEvent` and `Detection` are dataclasses. The decorator creates normal
initialization and comparison behavior from the declared fields. `frozen=True`
makes instances immutable after creation, preventing one pipeline stage from
silently changing an event already seen by another stage.

### Threads and the queue

Each collector subclasses `threading.Thread`. Collection is I/O-bound, so a
blocked journal or log read does not stop the other collectors. `EventBus`
wraps `queue.Queue`, which is safe for multiple threads. The queue is bounded
to provide backpressure instead of allowing unlimited memory growth.

The shared `threading.Event` is a shutdown flag. Calling `set()` wakes waiting
collectors and tells each loop to finish.

### Exceptions

Collector loops catch expected operating-system and permission errors so one
source cannot terminate EDR4. Narrow exception handlers are preferred. Broad
handlers exist only at collector/rule isolation boundaries and must log the
failure before retrying.

### Monotonic time

Intervals use `time.monotonic()` because it only moves forward. Wall-clock
changes cannot accidentally make persistence or cleanup intervals negative.
Event timestamps still use timezone-aware UTC because they represent when an
observation occurred.

### Sliding windows

Rate and status detectors use `collections.deque`. New observations are added
to the right; observations older than the configured window are removed from
the left. This keeps memory bounded to recent activity.

## Privacy boundaries

Privacy is enforced in layers:

1. Collectors avoid request bodies, cookie headers, authorization headers, and
   raw query values.
2. `create_event()` redacts messages and structured data before publication.
3. Console rendering redacts verbose data again.
4. SQLite storage redacts again before serialization.

The Morgan collector may inspect a bounded query value transiently to derive
SQLi indicator categories. The value is discarded before the event is created.
Do not move raw query content into the event dictionary for debugging.

## Key modules

| Module | Responsibility |
|---|---|
| `main.py` | Startup, central consumer, persistence, detection and shutdown |
| `collectors/morgan.py` | HTTP access-log parsing, rotation and URL metadata |
| `collectors/journal.py` | Structured Juice Shop journal records |
| `collectors/process.py` | Dynamic service PID and process metrics |
| `collectors/system.py` | Host metrics, network rates and TCP states |
| `core/events.py` | Common event model and first redaction boundary |
| `core/event_bus.py` | Thread-safe collector-to-consumer queue |
| `detection/rules.py` | Passive stateful detection rules |
| `storage/database.py` | SQLite schema, inserts, throttling and retention |

## Safe change workflow

1. Change one component at a time.
2. Add or update a unit test for the behavior.
3. Run `.venv/bin/python -m unittest discover -s tests -v`.
4. Run `git diff --check`.
5. For collector changes, validate against the real host without modifying
   Juice Shop or system configuration.
6. Confirm that no sensitive values entered console output or SQLite.

Detection rules are evidence heuristics, not proof of an attack. Response code
must remain inactive unless a later implementation round explicitly authorizes
and reviews active actions.
