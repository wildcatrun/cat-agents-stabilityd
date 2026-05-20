# Implementation Roadmap

## Current Baseline

As of this package baseline, `cat-agents-stability` has four install surfaces:

- Local Codex MCP server: `scripts/cat_agents_stability_mcp.py`
- OpenClaw plugin wrapper: `index.js` plus `openclaw.plugin.json`
- External daemon/CLI: `bin/cat-agents-stability` and `bin/cat_agents_stabilityd.py`
- Hermers contract docs: `hermers/README.md`

The package is intentionally a companion to `trading-agents-workflow`, not a container for it.

## Phase 1: Package and Read-Only Control Plane

Status: implemented.

- GitHub source package exists.
- Local Codex MCP can list tools and query remote status.
- OpenClaw plugin wrapper exposes read actions and guarded no-action diagnostics.
- Server candidate checkout exists separately from the live daemon directory.

Exit criteria:

- `npm run check` passes locally and on the server candidate checkout.
- Local Codex config contains both MCP servers:
  - `trading-agents-workflow`
  - `cat-agents-stability`
- No live service or Gateway behavior is changed by the candidate checkout.

## Phase 2: OpenClaw Plugin Activation

Not yet active by default.

Activation steps require current-state confirmation and rollback path:

1. Confirm current Gateway plugin paths and `cat-agents-stabilityd.service` status.
2. Back up `/home/flashcat/.openclaw/openclaw.json`.
3. Add `/home/flashcat/cat-agents-stabilityd.git-checkout` to OpenClaw plugin load paths or plugin entries.
4. Run `openclaw config validate`.
5. Restart Gateway during a cron-safe window.
6. Verify `cat_agents_stability` tool is registered and read actions work.

Rollback:

- restore the backed up `openclaw.json`
- restart Gateway
- keep `cat-agents-stabilityd.service` on the original live directory

## Phase 3: Live Daemon Git Cutover

Not yet active.

The current systemd daemon still points at `/home/flashcat/cat-agents-stabilityd`.

Cutover options:

- conservative: update systemd `ExecStart` to the Git checkout after backing up the live directory
- lower-risk interim: keep live daemon path, periodically diff it against the Git checkout

Cutover requires:

- backup of `/home/flashcat/cat-agents-stabilityd`
- `npm run check` on checkout
- `cat-agents-stability status` before/after
- `systemctl daemon-reload` only if the unit file changes
- no automatic Gateway restart setting drift

## Phase 4: Hermers Adapter

Not yet implemented as runtime code.

Next build target:

- Hermers-side probe command returning profile readiness JSON
- ACP turn quality probe
- future IM ownership drift probe for migrated agents
- no direct workflow DB writes

Hermers direct IM migration is explicitly out of scope for this roadmap until separately authorized.

## Phase 5: Desired State Registry

Planned.

Add a versioned desired-state file describing:

- agent runtime ownership
- dormant OpenClaw legacy identities
- legal workflow ingress adapters
- cron/heartbeat ownership
- Telegram consumer ownership
- return policies

The stability plugin should report drift, not silently mutate high-impact state.

