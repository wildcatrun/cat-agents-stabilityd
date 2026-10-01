# Deployment Matrix

## Local Mac Codex

Purpose: control panel and redundant observation path.

Install surface:

- `.codex-plugin/plugin.json`
- `.mcp.json`
- `scripts/cat_agents_stability_mcp.py`
- `bin/cat-agents-stability auth-maintenance-local`
- `launchd/ai.flashcat.cat-agents-stability-auth-mirror.plist`

Capabilities:

- read remote stability status, findings, lanes, actions, runbook
- run `doctor` in no-action mode
- run desired-state drift checks
- generate workflow governance evidence for cat-brain consumption
- inspect package status
- fetch server package snapshot
- run the stabilityd-owned mac-codex auth adapter; LaunchAgent is only its minute-level trigger
- let Codex CLI itself refresh the local credential near expiry, then mirror only plan-approved access/id tokens to server runtime stores

Restrictions:

- no direct workflow table writes
- no automatic Gateway restart
- no Hermers agent execution
- no local Codex as return inbox
- no refresh-token copy to the dev server; revoked-token or interactive-login cases require the account owner

## OpenClaw Gateway

Purpose: governed in-Gateway tool access close to workflow and IM routing.

Install surface:

- `openclaw.plugin.json`
- `index.js`
- `bin/cat-agents-stability`
- `bin/cat_agents_stabilityd.py`

Tool:

- `cat_agents_stability`

Default behavior:

- read actions are allowed
- `desired-state` and `drift` are read-only
- `workflow-evidence` writes a governed evidence artifact under `trading-agents-workflow/governance-logs/`
- `doctor`, `once`, and `repair` default to no-action/dry-run unless `allowMutatingActions=true`

## systemd

Purpose: thin external supervisor and probe runner.

Install surface:

- `systemd/cat-agents-stabilityd.service`
- optional review timer/service

Rules:

- systemd starts the daemon and records process liveness
- stability logic remains in the package
- automatic Gateway restart remains disabled unless policy and explicit environment allow it

## Hermers

Purpose: Hermers-side stability adapter and profile/IM/runtime probe contract.

Install surface:

- `hermers/README.md`
- future Hermers plugin/adapter package
- `policies/desired-state.json` target state after explicit Hermers IM cutover

Capabilities:

- profile readiness checks
- ACP session/turn quality checks
- Telegram consumer ownership drift detection
- outbound delivery receipt checks

Restrictions:

- does not own workflow state
- does not create a parallel IM audit system
- does not replace `trading-agents-workflow` message_flow contract
