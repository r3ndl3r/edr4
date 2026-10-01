# EDR4 Code Documentation Standard

EDR4 uses conventional Python docstrings and comments to make telemetry,
security, privacy, and lifecycle behavior understandable to contributors with
different levels of Python experience.

## Module documentation

Every Python module starts with a docstring that identifies its purpose. Modules
with orchestration, security, persistence, or external integration behavior
also describe their principal responsibilities and integration points.

```python
"""Rotation-aware HTTP access-log collection.

Responsibilities:
- Discover and follow the active access log.
- Normalize request metadata without retaining query values.

Integration points:
- Publishes TelemetryEvent objects to EventBus.
- Supplies sanitized metadata to passive detection rules.
"""
```

## Classes and functions

Classes receive a concise responsibility docstring. Public functions and
non-obvious private helpers document:

- what the operation does;
- important parameters;
- the return value;
- relevant failure, privacy, or state behavior.

Short lifecycle methods may use a one-line docstring when their contract is
obvious from the surrounding class. Longer functions use `Args`, `Returns`,
`Raises`, or `Behavior` sections only when those details add useful information.

## Inline comments

Comments explain why the code exists, especially for:

- privacy and redaction boundaries;
- security decisions;
- retry, cooldown, rotation, and shutdown behavior;
- fallbacks caused by permissions or platform differences;
- state transitions that are not obvious from the code.

Do not narrate ordinary syntax or repeat names already expressed clearly by the
code. Comments must be updated when behavior changes.

## Privacy language

Documentation must distinguish transient inspection from retained telemetry.
Never place real passwords, tokens, cookies, authorization values, request
bodies, or sensitive query values in comments, examples, fixtures, or logs.
Synthetic test values must be clearly identifiable as non-production data.

## Tests and validation scripts

Test modules state the component or contract being validated. Test names explain
the expected behavior. Live validation scripts document their safety boundary,
target restriction, and whether they generate traffic or use synthetic events.
