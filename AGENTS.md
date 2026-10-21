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
