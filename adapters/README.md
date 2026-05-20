# Adapter Contracts

`cat-agents-stability` uses adapters to observe multiple planes without owning their core state machines.

Planned adapter boundaries:

- `workflow`: read `trading-agents-workflow` state and invoke public reconcile/incident actions.
- `openclaw`: read Gateway health, cron state, sessions, channel status, and plugin load state.
- `hermers`: read profile readiness, ACP worker/session health, and future Hermers IM ownership.
- `telegram`: detect consumer drift, delivery receipts, outbox pressure, and duplicate polling/webhook risks.
- `systemd`: check process liveness and service restart history.
- `codex`: expose local MCP tools and audit local control-plane actions.

Adapters must return structured findings. Mutating actions require explicit risk classification and policy gates.

