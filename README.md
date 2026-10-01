# Cat Agents Stability

`cat-agents-stability` is the companion governance package for `trading-agents-workflow`.

It is not a replacement for the workflow engine. It provides stability probes, lane policy, findings, runbooks, incident support, and guarded low-risk diagnostics across OpenClaw Gateway, Hermers runtime, workflow receipts, IM delivery, cron, sessions, OAuth/auth readiness, data freshness, and production readiness.

## Package Shape

```text
cat-agents-stabilityd/
  bin/                         # Python stabilityd and CLI
  index.js                     # OpenClaw plugin tool wrapper
  scripts/cat_agents_stability_mcp.py
  scripts/mac_codex_oauth_mirror_maintenance.py # local mac-codex adapter routed through the CLI
  launchd/                     # macOS trigger template; policy remains in the plugin adapter
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

OAuth auth targets are derived from active `trading-agents-workflow.runtime_agents` entries: Hermers profiles come from their registered profile endpoints, and OpenClaw agents require a valid `openclaw-agent:<agent_id>` endpoint. Active OpenClaw rows with an invalid ID or endpoint are excluded and retained as registry warning evidence. `CAT_AGENTS_STABILITY_AUTH_OPENCLAW_AGENT_IDS` is only an extra-scope consistency check; unregistered IDs cause a Human Gate instead of becoming mirror targets. `CAT_AGENTS_STABILITY_AUTH_OPENCLAW_AGENT_LIMIT` and `CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_TIMEOUT_SECONDS` bound probe cost; if the limit or a failed/partial probe leaves routable registry targets unobserved, source-wide mirror is gated. Use `cat-agents-stability auth-readiness --fresh` for an immediate one-off resample.

`auth-maintenance` converts auth findings into a governed repair plan. It identifies mirror-from-mac-codex, reauth, sync, and token-copy-drift cleanup candidates. The plan explicitly labels which access/id-token mirrors are eligible for the mac-codex adapter. Development-server stabilityd remains observe-only and never owns or rotates the refresh token.

`cat-agents-stability auth-maintenance --dry-run --action-id codex_cli_mirror_required` shows the maintenance decision without side effects. The server-side `--execute` path does not acquire or refresh credentials. The mac-codex adapter consumes only actions marked `localAutomation.eligible`, with no Human Gate, then writes redacted local status and server-side backups/evidence. It pushes only access/id tokens plus the non-secret refresh placeholder to development-server runtime stores.

### mac-codex OAuth Source

`mac-codex` is the canonical OpenAI/Codex OAuth refresh owner. The Mac-side Codex auth file keeps the real refresh token; dev-server Codex CLI, Hermers profiles, and OpenClaw receive only a mirror containing the current access/id token plus the non-secret marker `MAC_CODEX_BROKER_REFRESH_DISABLED` in refresh-token fields. This avoids multi-runtime refresh-token rotation conflicts while preserving runtime access until the next mirror sync.

Run a local source preflight first:

```bash
python3 scripts/mac_codex_oauth_mirror.py --local-preflight
```

`mac_codex_oauth_mirror.py` is the stabilityd adapter's mirror implementation; it is not a separate scheduler. For the unattended path, use the plugin CLI:

```bash
bin/cat-agents-stability auth-maintenance-local
```

The adapter follows the server-generated policy plan, refreshes through Codex CLI only in its native window, and writes a server-side ops artifact with backups before any mirror mutation. It must not print token values.

The stabilityd package owns the local maintenance adapter, available through its CLI on mac-codex:

```bash
bin/cat-agents-stability auth-maintenance-local
bin/cat-agents-stability auth-maintenance --fresh
bin/cat-agents-stability auth-mirror
```

`auth-maintenance-local` checks the local auth file and reads the server's latest durable maintenance plan every 15 seconds. Stabilityd refreshes OpenClaw auth observations every 15 minutes during normal operation, every 60 seconds once a token is within 24 hours of expiry, and every 30 seconds within 15 minutes of expiry or after expiry. When a fresh eligible server action appears, the Mac adapter mirrors that request promptly and runs a forced postcheck. If the request plan is stale, it forces a current probe before applying. A forced baseline probe also runs every 15 minutes, or immediately after the Mac source token changes. Repeated actions from the same already-postchecked server snapshot are suppressed, while a newer server snapshot can request the same target again. At the Codex refresh window (five minutes before access-token expiry), the adapter waits 15 seconds and rechecks shared auth before deciding whether to invoke Codex CLI; that lets another local Codex process refresh first and avoids a redundant refresh-token use. Any CLI turn uses the fixed `CODEX_HOME`, ignores user config/rules, and disables local execution, browser, app, and image tools. Transient apply failures back off from one to fifteen minutes and reuse the same backup artifact for the same failed token generation and target scope. Retain the three newest successful backup artifacts and keep incomplete artifacts until recovery. It does not implement an OAuth endpoint or copy the refresh token. If the refresh token is revoked or interactive login/MFA is required, it records that the source needs user reauthentication.

The macOS LaunchAgent is only a scheduler: it wakes this plugin CLI at login, every 15 seconds, and when `~/.codex/auth.json` changes. Routine plan reads use the latest persisted stabilityd plan and do not force OpenClaw CLI probes; the server daemon uses an adaptive 15-minute, 60-second, or 30-second cache based on token expiry. The adapter keeps the fixed public IP (`106.54.53.146`) as the primary SSH path and uses the dev-server Tailscale hostname only after an SSH transport failure. Latest redacted state is written to `reports/auth-mirror/latest.json`; the server-side mirror artifact contains backups, stabilityd action ids, and an index. The compatibility shell entrypoint routes into the same CLI:

```bash
scripts/mac_codex_oauth_mirror_maintenance.sh
```

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
