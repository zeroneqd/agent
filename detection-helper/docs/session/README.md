# Session State

> **Purpose.** JSON-based pipeline coordination between agents. Eliminates
redundant telemetry lookups — each agent reads what the previous confirmed.

## Storage

- **File:** `docs/session/state.json` (JSON, not markdown)
- **Format:** Machine-readable, agents call `tools.session.Session` methods
- **Auto-expiry:** 24 hours — stale sessions are reset automatically

## API (Python)

```python
from tools.session import Session

s = Session()

# Read prior agent results
confirmed = s.get_confirmed_primitives()  # list of verified primitives
tables = s.get_confirmed_tables()          # set of table names
status = s.get_status()                    # empty | decomposed | telemetry_confirmed | ...

# Write this agent's results
s.write_phase("telemetry", {"primitives_verified": [...]})
# Status auto-advances: empty → decomposed → telemetry_confirmed → rules_written → validated

# Start fresh
s.reset()
```

## Rules

- Every agent reads `Session` at start, writes phase before responding
- Never overwrite previous phases — only append
- Human-readable view: `python -m tools.session` prints current state
