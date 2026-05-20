# Desired State Registry

`policies/desired-state.json` is the stable contract for what `cat-agents-stability` expects to exist around `trading-agents-workflow`.

It is intentionally read-only governance data. The drift checker reports mismatches; it does not mutate workflow tables, OpenClaw config, Telegram consumers, Hermers profiles, cron jobs, or systemd units.

## Current Phase

The current enforcement phase is `pre-hermers-im-cutover`.

That means the six Hermers ACP agents must be active in `runtime_agents` as `hermes_acp`, while their OpenClaw `openclaw_route_shell` records are treated as temporary observations, not hard drift. The future target is still recorded: after an explicit Hermers IM cutover, those OpenClaw identities should become dormant legacy workspaces with IM/workflow ingress disabled.

## Drift Command

```bash
bin/cat-agents-stability desired-state
bin/cat-agents-stability drift
```

The drift command checks:

- Required package files for the Codex plugin, MCP server, OpenClaw plugin, daemon, docs, and Hermers contract.
- Local Codex MCP registration when running on the Mac host where `/Users/Flashcat/.codex/config.toml` exists.
- `runtime_agents` required active records for OpenClaw and Hermers ACP agents.
- Forbidden retired ids such as `catclaw`.
- Temporary route-shell records that remain allowed only until a separately authorized Hermers IM migration.

## MCP Surface

Local Codex exposes the same checks through:

- `stability_desired_state`
- `stability_drift_check`

Both tools accept `source=local` or `source=remote`. Remote checks run on the development server through the existing SSH-controlled MCP path.

## Boundary

Drift findings can be consumed by cat-brain `main` and by Human Gate evidence packages. They are not instructions to auto-fix high-impact state.

Allowed fixes still go through the normal risk gates:

- P3: read-only finding
- P2: workflow public reconcile or incident action
- P1: explicit authorization or Human Gate
- P0: explicit authorization, current-state confirmation, and rollback path
