# Cat Agents Stability

`cat-agents-stability` is the companion governance package for `trading-agents-workflow`.

It is not a replacement for the workflow engine. It provides stability probes, lane policy, findings, runbooks, incident support, and guarded low-risk diagnostics across OpenClaw Gateway, Hermers runtime, workflow receipts, IM delivery, cron, sessions, data freshness, and production readiness.

## Package Shape

```text
cat-agents-stabilityd/
  bin/                         # Python stabilityd and CLI
  index.js                     # OpenClaw plugin tool wrapper
  scripts/cat_agents_stability_mcp.py
  policies/                    # Desired state and lane policy inputs
  systemd/                     # External daemon bootstrap units
  docs/                        # Governance docs and deployment matrix
  adapters/                    # Adapter contract docs
  hermers/                     # Hermers installation contract docs
```

## Runtime Surfaces

- OpenClaw plugin: exposes `cat_agents_stability` as a governed Gateway tool.
- External daemon: `cat-agents-stabilityd.service` keeps observing when Gateway is degraded or down.
- Local Codex MCP: exposes read and dry-run tools to the local Codex control panel.
- Hermers adapter package: defines the governance contract for Hermers profile/IM/runtime probes without moving workflow state into Hermers.
- Runtime adapter governance: derives cat-system members from `trading-agents-workflow.runtime_agents`, then records platform-specific readiness evidence and performs policy-gated repairs through OpenClaw, Hermers/Hermes, Codex, and future runtime adapters. Hermers `warm` / `cold` / `hibernate` profile-mode output can drive stabilityd repair candidates only for registry-derived, managed, unprotected profiles, and execution must go through the Hermers profile-scoped lifecycle adapter.

## Desired State

`policies/desired-state.json` is the package-level desired-state registry for install surfaces, Codex MCP registration, workflow boundary rules, runtime ownership, temporary route-shell allowances, and future Hermers IM cutover targets. Cat-system member scope comes from `trading-agents-workflow.runtime_agents`; platform-local profile lists or systemd units are diagnostic inputs only.

Use read-only drift checks before changing deployment state:

```bash
bin/cat-agents-stability desired-state
bin/cat-agents-stability drift
bin/cat-agents-stability workflow-evidence
bin/cat-agents-stability profile-modes
```

`workflow-evidence` writes `stability-evidence-latest.json` and `stability-evidence-latest.md` into `trading-agents-workflow/governance-logs/` so cat-brain `main` can consume stability facts during heartbeat governance.

Direct actuator authority is policy-gated, not removed. When runtime pressure is still light, stabilityd should produce structured evidence and repair candidates for Cat Brain `main`. When cron/session/worker/profile pressure threatens runtime availability, `cat-agents-stabilityd.service` is the external repair layer and may execute controlled cron stale/lease repair, eligible session reset, orphan ACP worker reap, Hermers profile lifecycle repair through the Hermers CLI adapter, and Gateway restarts. These actions require registry scope, protected-member checks, an explicit `CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_ALLOWLIST` blast-radius limit for profile lifecycle execution, cooldown/restart-storm gates where applicable, backups or action ledger entries, and post-check evidence.

Operator judgment warning: long quiet periods are not evidence that stabilityd is unnecessary. On 2026-05-23 Flashcat explicitly identified an operator error: because stabilityd had been stable and effective for a long time, its core governance value was underestimated and excessive authority removal was temporarily approved. Future requests to remove or delegate stabilityd deep governance must first prove how mechanical pressure will be reduced when Cat Brain or other runtime agents are already degraded.

## Boundary With trading-agents-workflow

`cat-agents-stability` may read workflow state and call public workflow actions. It must not directly mutate workflow internals such as `mixed_meeting_dispatches`, `message_flows`, `runtime_runs`, or `control_loop_jobs`.

For any agent-related governance, readiness, lifecycle, routing, or stability question, the package must start with the global `runtime_agents` registry and then call runtime-specific adapters. It must not define cat-system membership, protection policy, dispatch priority, or residency policy from Hermers profiles, OpenClaw agent lists, Codex sessions, systemd units, or local directories.

Allowed repair path examples:

- `workflow.dispatch.reconcile`
- `workflow.message_flow.reconcile`
- `incident.state`
- repair candidate evidence consumed by Cat Brain governance heartbeat/tasks
- explicit Human Gate or authorized operator action for high-impact changes

## Local Checks

```bash
npm run check
npm run smoke:mcp
npm run smoke:drift
```
