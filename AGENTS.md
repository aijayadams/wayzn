# Wayzn HA Integration — Governing Principles

Stated by the user 2026-08-12. These outrank any implementation convenience. They apply to this integration and the wider dog door system it serves.

1. **Not lying matters.** State honesty above all. If the state cannot be proven fresh, report "unknown"/unavailable — never confidently show a stale state. A wrong "open" is worse than an honest "unknown".
2. **Open is preferable to fast oscillations.** When state is uncertain, bias toward open/known-safe. Never flip-flop to chase shaky signals.
3. **Oscillating is an error.** Rapid open/close cycling is a system fault. Detect it, log it, alert on it — never silently tolerate flapping.
4. **Never lock a dog out.** The failsafe bias is always toward open. Assumed state must never suppress an open command — commands are the only rescue path when belief is wrong.

Corollaries learned from incidents:
- Assume no single signal source is trustworthy: cross-check server-sent events against direct polls, and trust the poll on disagreement (and say so loudly in logs).
- Anomalies must be surfaced to the user, not silently self-healed.
- Self-healing backs off and caps retries; never hammer Firebase auth (2026-08-11 rate-limit incident).

## Working in this repo

- Two backends: the Wayzn cloud (`coordinator.py`, docs/PROTOCOL.md) and local mode (`local_coordinator.py`,
  `local_entity.py`), which talks to a door running the wayzn-brain firmware. The local API contract is
  [docs/API.md in aijayadams/wayzn-afterlife](https://github.com/aijayadams/wayzn-afterlife/blob/main/docs/API.md),
  and the firmware lives there too: change the API and this integration together, and keep new fields
  additive so an older door or integration keeps working.
- Door-specific values (travel, stall allowance, detector thresholds) are door settings exposed as HA
  entities, never constants in the firmware.
- Tests: `pip install -r requirements-dev.txt && python -m pytest -q tests`. Run them before every push.
- `main` is what gets deployed: keep it working, and merge finished work into it.
- The rules for working on the door itself (ask before moving it, flash only while it is still) are in
  wayzn-afterlife's AGENTS.md. Notes about one particular home stay out of this public repo.
