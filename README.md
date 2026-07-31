# Cat Agents Stability

`cat-agents-stability` is the companion governance package for `trading-agents-workflow`.

It is not a replacement for the workflow engine. It provides stability probes, lane policy, findings, runbooks, incident support, and guarded low-risk diagnostics across OpenClaw Gateway, Hermers runtime, workflow receipts, IM delivery, cron, sessions, OAuth/auth readiness, data freshness, and production readiness.

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
bin/cat-agents-stability auth-readiness
bin/cat-agents-stability auth-maintenance
```

`workflow-evidence` writes `stability-evidence-latest.json` and `stability-evidence-latest.md` into `trading-agents-workflow/governance-logs/` so cat-brain `main` can consume stability facts during heartbeat governance.

`auth-readiness` reports redacted OAuth readiness for Codex CLI, OpenClaw OAuth profiles, and Hermers profile auth files. It records token presence, file metadata, and decoded JWT expiry only; it must not print access tokens, refresh tokens, API keys, or secrets. Expiry and refresh-token findings feed the `auth` lane so cat-brain `main` can include OAuth health in daily and 8H stability reports.

OpenClaw OAuth probing defaults to agent `main` to keep the daemon lightweight. Set `CAT_AGENTS_STABILITY_AUTH_OPENCLAW_AGENT_IDS=main,cat_claw,...` only when additional OpenClaw agent auth stores need explicit monitoring. `CAT_AGENTS_STABILITY_AUTH_OPENCLAW_AGENT_LIMIT` and `CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_TIMEOUT_SECONDS` bound daemon cost. Use `cat-agents-stability auth-readiness --fresh` for an immediate one-off resample.

`auth-maintenance` converts auth findings into a governed repair plan. It identifies mirror-from-mac-codex, reauth, sync, and token-copy-drift cleanup candidates. Default mode remains observe-only, and development-server stabilityd must not become the refresh-token owner.

`cat-agents-stability auth-maintenance --dry-run --action-id codex_cli_mirror_required` shows the maintenance decision without side effects. `--execute` records blocked execution decisions unless the operator also passes `--allow-mirror` for a mirrorable action. `--allow-mirror` runs the governed mac-codex mirror script, which requires a fresh local access token, records id token freshness, writes redacted evidence, and pushes only mirrored access/id tokens plus the non-secret refresh placeholder to development-server runtime stores.

### mac-codex OAuth Source

`mac-codex` is the canonical OpenAI/Codex OAuth refresh owner. The Mac-side Codex auth file keeps the real refresh token; dev-server Codex CLI, Hermers profiles, and OpenClaw receive only a mirror containing the current access/id token plus the non-secret marker `MAC_CODEX_BROKER_REFRESH_DISABLED` in refresh-token fields. This avoids multi-runtime refresh-token rotation conflicts while preserving runtime access until the next mirror sync.

Run a local source preflight first:

```bash
python3 scripts/mac_codex_oauth_mirror.py --local-preflight
```

Apply the mirror after reviewing the summary:

```bash
python3 scripts/mac_codex_oauth_mirror.py --apply
```

The mirror script writes a server-side ops artifact and backups before mutation. It must not print token values. If access token TTL is too short, refresh local mac-codex first, then mirror again.

The same mirror path is also available through the stability CLI on mac-codex:

```bash
bin/cat-agents-stability auth-maintenance --fresh
bin/cat-agents-stability auth-mirror
bin/cat-agents-stability auth-mirror --apply
```

Do not run the mirror from a host that lacks the canonical mac-codex Codex auth file. A failed preflight is expected when the local `id_token` is expired; refresh the mac-codex Codex login first, then run the mirror again.

mac-codex also has a launchd maintenance wrapper:

```bash
scripts/mac_codex_oauth_mirror_maintenance.sh
```

The wrapper first asks the development server for a fresh auth-maintenance plan. It runs `auth-mirror --apply` only when that plan contains auth maintenance actions, so routine checks do not create repeated OpenClaw SQLite backups.

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
npm run smoke:auth
npm run smoke:mcp
npm run smoke:drift
```
