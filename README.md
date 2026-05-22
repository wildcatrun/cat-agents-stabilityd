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
- Hermers profile modes: evaluates managed profile runtime residency (`warm`, `cold`, `hibernate`) and can hibernate explicitly managed idle profiles while protecting active or critical profiles.

## Desired State

`policies/desired-state.json` is the package-level desired-state registry for install surfaces, Codex MCP registration, workflow boundary rules, runtime ownership, temporary route-shell allowances, and future Hermers IM cutover targets.

Use read-only drift checks before changing deployment state:

```bash
bin/cat-agents-stability desired-state
bin/cat-agents-stability drift
bin/cat-agents-stability workflow-evidence
bin/cat-agents-stability profile-modes
```

`workflow-evidence` writes `stability-evidence-latest.json` and `stability-evidence-latest.md` into `trading-agents-workflow/governance-logs/` so cat-brain `main` can consume stability facts during heartbeat governance.

## Boundary With trading-agents-workflow

`cat-agents-stability` may read workflow state and call public workflow actions. It must not directly mutate workflow internals such as `mixed_meeting_dispatches`, `message_flows`, `runtime_runs`, or `control_loop_jobs`.

Allowed repair path examples:

- `workflow.dispatch.reconcile`
- `workflow.message_flow.reconcile`
- `incident.state`
- explicit Human Gate or authorized operator action for high-impact changes

## Local Checks

```bash
npm run check
npm run smoke:mcp
npm run smoke:drift
```
