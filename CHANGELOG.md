# Candidate change log

## 1.0.0-rc.1 — unqualified development candidate

This local checkpoint is not a release, deployment, or authorization to enable
new runtime actions. Release eligibility still requires the complete G2 matrix,
isolated Linux evidence, configuration/runtime compatibility, shadow and
observation recovery, measured budgets, review, and separate rollout approval.

- Preserve the existing cron/session/worker/profile/Gateway repair capabilities
  behind their authorization, protection, identity, cooldown and ledger gates.
- Add durable intent-first action accounting, bounded collectors, independently
  scoped runtime capabilities, authenticated fixed-node observations and
  generation-consistent evidence. Event receipts do not establish delivery or
  Human Gate approval.
- Add opt-in event protocol v2: atomic observations, finite retry generations,
  durable export receipts, bounded JSONL rotation, immutable archive receipts,
  permanent retirement frontiers and crash reconciliation. The flag remains off.
- Add non-activating offline migration and observation recovery packages. Preserve
  legacy history, action ledger, control state and increment evidence; reject
  source drift, unknown schema, incomplete export or inconsistent witness/archive.
  An arbitrary old writer ignores the new marker: rollback must externally stop
  writers and keep actuators and event writes off; this package does not start it.
- Correct Hermes process-only false readiness: registry-derived profiles require
  fresh Gateway state and matching process identity plus connected Telegram for
  the explicitly limited local connectivity snapshot. Semantic execution,
  consumer progress and actuator qualification remain unverified.

Package, OpenClaw manifest and MCP server report the candidate version together.
State protocols, policy contracts and evidence schemas retain independent version
numbers. Declared dependency minimums do not establish compatibility with every
future runtime. Known local and Linux fixture results must be read within their
recorded source/scope; production, live activation and real model/IM calls are not
part of this candidate's qualification.
