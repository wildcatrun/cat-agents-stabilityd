# Cat Agents Stability Plugin Architecture

## Target Model

`cat-agents-stability` is a companion governance plugin for `trading-agents-workflow`.

It has multiple installation surfaces:

```text
Local Mac Codex MCP
  -> cat-agents-stability MCP tools
  -> SSH / local CLI / future Gateway API

OpenClaw Gateway
  -> cat-agents-stability OpenClaw plugin
  -> stability CLI / latest policy / findings / guarded doctor

systemd
  -> cat-agents-stabilityd daemon
  -> observes Gateway even when Gateway plugins are unavailable

Hermers agents framework
  -> Hermers adapter/probe contract
  -> profile readiness / ACP turn quality / IM ownership drift
```

## Non-Goals

- Do not embed `trading-agents-workflow`.
- Do not implement a second workflow scheduler.
- Do not directly rewrite workflow SQLite internals.
- Do not make the stability plugin the only liveness proof for itself.
- Do not use local Codex as an agent return inbox.

## Component Ownership

`trading-agents-workflow` owns:

- workflow state machines
- dispatch and runtime bridge
- message_flow state
- telegram_outbox delivery
- Human Gate records and buttons
- workflow-native schedules
- public reconcile and incident actions

`cat-agents-stability` owns:

- probes and snapshots
- policy lanes and soft-pressure decisions
- findings and action log
- runbook generation
- drift checks against desired state
- low-risk cleanup/repair only when policy permits
- incident escalation evidence

Cat-brain `main` owns:

- semantic incident command
- workflow governance judgement
- evidence completeness
- Human Gate escalation decisions

## Write Discipline

The stability package may write its own state:

- `/home/flashcat/.openclaw/stability/latest.json`
- `/home/flashcat/.openclaw/stability/policy.json`
- `/home/flashcat/.openclaw/stability/lane-policy.json`
- `/home/flashcat/.openclaw/stability/events.jsonl`
- `/home/flashcat/.openclaw/stability/actions.jsonl`
- `/home/flashcat/.openclaw/stability/state.db`

Workflow writes must go through `trading-agents-workflow` public actions.

## Action Risk Levels

- P3: read-only checks and findings.
- P2: idempotent reconcile, incident record, stale temp cleanup.
- P1: cron disable/enable, adapter switch, config mutation. Requires explicit authorization or Human Gate.
- P0: Gateway restart, runtime migration, production-server or trading-impacting changes. Requires explicit authorization and rollback path.

