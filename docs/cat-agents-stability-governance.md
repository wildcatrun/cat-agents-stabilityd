# Cat Agents Stability Governance Plan

Date: 2026-04-30
Target server: flashcat@106.54.53.146
Scope: cat-system runtime stability, including OpenClaw Gateway, OpenClaw cron/session/channel, Hermers profile/ACP, trading-agents-workflow runtime receipt, IM delivery, and downstream trading runtime readiness.

2026-05-20 rename note: `openclaw-stabilityd` has been superseded by `cat-agents-stabilityd`. OpenClaw is now one domain inside the broader stability plane, not the naming or governance boundary. The broader mapping is maintained at `/Users/Flashcat/multi-agent-hedge-fund-framework/research-notes/2026-05-17-cat-system-stability-governance-references.md`.

## Objective

Replace the current collection of autonomous watchdog, guard, audit, and controller scripts with a single stability control plane:

- One daemon owns health decisions and mutation authorization.
- Collectors only collect facts.
- Analyzers only produce structured findings.
- Actuators are the only code paths that mutate state or restart services.
- Every decision and action is written to an append-only event ledger.
- Policy fails closed when stale.

The current scripts are treated as source material, not as permanent boundaries.

## Soft Governance Research Synthesis

The useful external practices converge on the same operating model:

- SRE monitoring separates symptoms from causes. Symptoms protect users and operators; internal signals choose the recovery action.
- Overload control prefers backpressure, load shedding, priority, and graceful degradation before restart.
- Queue systems are governed by age, lag, lease ownership, retry budget, and worker heartbeat, not by raw error volume.
- Resilience patterns such as circuit breaker, bulkhead, rate limiter, retry budget, and queue-based load leveling are more useful for soft failures than a generic watchdog.
- Agent runtime observability should trace sessions, tool calls, memory/context pressure, handoffs, latency, and error type. Those traces should inform scheduling and isolation, not create many independent mutators.

Cat-system interpretation:

- OpenClaw Gateway is not only a process; it is a runtime hub for channel ingress, cron delivery, session execution, route-shell entry, and agent coordination.
- Hermers is a real execution runtime. Its profile gateways, ACP workers, runtime receipts, and model/output failure modes must be governed directly, not masked by workflow fallback.
- Soft governance should therefore manage work entering and moving through Gateway and Hermers, not merely watch whether Gateway is alive.
- The main internal failure sources are `cron`, `session`, `channel`, and `hermers`. Soft governance must primarily diagnose and act on those domains.
- Gateway and resource findings are usually secondary signals: they show pressure amplification or runtime damage, but they should not distract from identifying whether pressure entered through cron scheduling, session execution, channel delivery, or Hermers runtime execution.
- The system should avoid both extremes:
  - monitor-only governance that observes degradation until hard failure
  - over-active governance that repeatedly restarts or mutates state during recoverable pressure

Important correction to the initial design:

- A single global health mode is useful as a safety summary, but it is too coarse to be the primary control surface.
- The primary soft-governance control surface should be lane/workload scoped:
  - direct/operator lane
  - control-plane lane
  - background cron lane
  - channel-provider lane
  - session-store maintenance lane
  - resource-cleanup lane
- Global policy remains the safety gate. Lane policy decides the least disruptive local action.
- Lane policy should always expose primary pressure domains:
  - `cron`
  - `session`
  - `channel`
- Secondary domains:
  - `gateway`
  - `resource`

Reference material used:

- Google SRE, Monitoring Distributed Systems: symptom-versus-cause monitoring, black-box plus white-box signals, latency/traffic/errors/saturation, low-noise actionable alerting.
- Google SRE, Handling Overload and Cascading Failures: overload should be contained with prioritization, load shedding, and graceful degradation before collapse.
- AWS Builders Library, Timeouts, retries, and backoff with jitter: retries can amplify overload; use retry budgets, backoff, jitter, and avoid synchronized periodic work.
- Microsoft Azure Architecture Center, Circuit Breaker pattern: stop repeated calls likely to fail, use open/half-open/closed states, and prevent cascading failures.
- Microsoft Azure Architecture Center, Bulkhead pattern: isolate critical consumers and resource pools so one failing workload does not take down the whole system.
- Microsoft Azure Architecture Center, Queue-Based Load Leveling pattern: buffer and rate-control work so spikes do not overwhelm the service; do not reintroduce overload at the worker side.

## 2026-05-20 Hermers Runtime Research Update

External research scope:

- Hermes official Messaging Gateway, Gateway Internals, ACP Internals, ACP editor integration, Agent Loop Internals, and Cron Troubleshooting documentation.
- systemd service and kill semantics.
- Kubernetes liveness/readiness/startup probe semantics.
- OpenTelemetry signal and log-correlation semantics.
- Temporal durable execution, Airflow scheduler heartbeat health checks, and Prefect work-pool / work-queue concurrency controls.

Research facts that matter to the cat system:

- Hermes Gateway is a long-lived messaging process and service-managed runtime. It can be installed as a user service or system service; keeping both installed can make start/stop/status behavior ambiguous. Multiple `HERMES_HOME` installations also map to different service names. Cat governance must therefore check the exact profile service, home directory, PID, and process identity, not just "a Hermes process exists".
- Hermes Gateway also performs its own background maintenance: cron ticking, session expiry, memory flush, and cache refresh. Hermes cron troubleshooting says automatic jobs require a running gateway, and a regular CLI session does not fire gateway cron. This proves Hermes cron can be useful inside a Hermers profile, but it is not a sufficient cross-agent workflow scheduler for OpenClaw + trading-agents-workflow + ACP production dispatch.
- Hermes ACP is an async JSON-RPC stdio adapter around a synchronous `AIAgent`. Stdout is transport and human-readable logs go to stderr. `AIAgent` runs in a worker thread while ACP I/O lives on the main event loop. This makes stdout pollution, thread/event-loop bridge stalls, cancellation gaps, and orphan worker processes real production failure classes.
- ACP sessions are scoped to the running ACP server process and keep session state in an in-memory manager while the server runs. They also reuse Hermes configuration, provider resolution, credentials, skills, and state DB. A healthy service process therefore does not prove that the intended ACP session, cwd, provider, or credentials are ready.
- The Hermes agent loop has strict message role alternation and provider-facing request rules. It supports interruptible API calls by abandoning the API thread and discarding partial response. Therefore `Operation interrupted`, empty output, partial output, malformed history, provider timeout, provider auth drift, and rate/credit failure must be classified as runtime failure or incomplete output unless a final agent message is present.
- systemd mature service governance favors explicit restart policy, watchdogs for daemons that can notify progress, and cgroup-aware kill behavior. `KillMode=control-group` or `mixed` prevents subprocess escape; `KillMode=process` or `none` lets children outlive the service and is not appropriate for agent runtimes that launch tools or workers.
- Kubernetes mature probe design separates startup, liveness, and readiness. For the cat system this maps directly to: process/service active is liveness; ACP check, provider config, profile cwd, queue acceptance, and last successful final output are readiness; startup grace is separate. Restarting a live-but-not-ready service can cause cascades if readiness would have been the right control.
- Temporal, Airflow, and Prefect all converge on the same operating ideas: durable state, heartbeat-based health, retry budget, idempotency keys, queues, priorities, concurrency limits, and explicit worker readiness. The cat system should copy those control patterns without importing a new workflow engine into the hot path.
- OpenTelemetry's trace/metric/log correlation model maps cleanly to cat-system evidence. Every dispatched message should carry `trace_id`, `workflow_id`, `dispatch_id`, `profile`, `runtime`, `message_flow_id`, and delivery receipt identifiers so Gateway logs, workflow DB rows, ACP runs, stability findings, and Telegram delivery can be joined.

Hermers failure modes that `cat-agents-stabilityd` must recognize:

- `hermers_profile_service_ambiguous`: both user and system service, wrong `HERMES_HOME`, wrong profile service name, stale PID file, or gateway process not matching the registered profile.
- `hermers_profile_alive_not_ready`: service active but ACP check, provider resolver, profile cwd, permissions, or model credentials are not ready.
- `hermers_acp_transport_unavailable`: ACP backend missing, wrong module path, stdout pollution, JSON-RPC startup failure, or `--check` failure.
- `hermers_acp_worker_stuck`: runtime run exceeds timeout, cancellation does not complete, child process remains after the parent exits, or process group is not reaped.
- `hermers_incomplete_output`: `Operation interrupted`, empty final output, partial final output, malformed provider response, or no final assistant message.
- `hermers_session_scope_drift`: session exists only in a restarted ACP process, cwd/model/history does not match the dispatch, or resume/fork uses unexpected state.
- `hermers_provider_degraded`: provider auth expired, provider rate/credit failure, network timeout, model fallback drift, or strict message alternation rejection.
- `hermers_cron_misplaced`: cron/heartbeat is registered inside a Hermers profile but the official cat workflow state expects `trading-agents-workflow` durable dispatch and receipt.
- `hermers_return_path_gap`: runtime produced a result but `telegram_outbox` or source-chat delivery receipt is absent.

Required governance controls:

- Treat Hermers as a first-class runtime domain, not an OpenClaw child process and not a CLI fallback.
- Keep route-shell as an ingress and audit shell only. It may acknowledge receipt with `trace_id`, but it cannot satisfy formal agent-result semantics.
- For `workflow_ingress_adapter=acp`, fail closed when ACP is unavailable. CLI can run only when registry explicitly selects the CLI adapter or a separately governed fallback is approved.
- Keep workflow-level schedule intent, evidence expectations, receipt requirements, and heartbeat governance in `trading-agents-workflow`. Runtime-local cron execution remains owned by the runtime platform; its outputs must flow back through workflow/messageflow receipts before they are treated as system truth.
- Read `trading-agents-workflow` runtime receipts as a Hermers readiness signal: a single recent `runtime_runs.status=failed` becomes a Hermers observation with sample dispatch evidence, while repeated failures crossing the burst threshold become Hermers pressure.
- Observe ACP worker orphaning as runtime evidence. Stabilityd may reap eligible orphan ACP workers after policy approval and PID/cmd/profile revalidation, because orphan workers can keep pressure high after the owning runtime path is already gone.
- Use three-layer health:
  - liveness: service/process/PID/cgroup exists
  - readiness: ACP backend, profile home, cwd, provider, queue acceptance, and small non-side-effect check are valid
  - completion: final agent output plus outbound delivery receipt
- Use queue/bulkhead controls for cron and heartbeat fan-out. Protect direct/operator, Human Gate, and critical heartbeat lanes before background research/report lanes.
- Use retry budgets and idempotency keys. Never retry side-effecting agent actions blindly.
- Write incidents for stuck message flow, not only stuck process. A Hermers run that reaches runtime completion but not outbound delivery must become communication-plane incident evidence.
- Emit correlated evidence that can join Gateway route logs, workflow DB, runtime run, ACP worker process, stability finding, and Telegram receipt.

Cat Brain active governance role:

- `cat-agents-stabilityd` supplies mechanical facts, policy, lane state, repair candidates, runbook evidence, Human Gate packages, and controlled external repairs. It does not replace governance judgment, but it must remain capable of reducing mechanical pressure when agent runtimes are too degraded to repair themselves.
- Stabilityd direct actuator authority is policy-gated, not removed. Light pressure can become structured repair candidates for Cat Brain; severe cron/session/worker/profile/Gateway pressure can be repaired by stabilityd itself with evidence refs, protected-member checks, cooldown/restart-storm gates, rollback notes, and action ledger entries.
- Cat Brain `main` is the active cat-agents administrator, governance officer, Incident Commander, and runtime-level repair coordinator. Its 30min heartbeat, 4h report, daily governance report, and explicit workflow tasks must consume `cat-agents-stabilityd` status, lanes, findings, actions, repair candidates, and workflow readiness as evidence.
- Cat Brain may act as the repair entrypoint for runtime-level fixes, but it must do so through the owning runtime adapter, `runtime_agents` registry, workflow receipt, and authorization/Human Gate rules. It is the governed runtime repair coordinator; stabilityd is the diagnostic/evidence plane and external repair actuator for cron/session/worker/profile/Gateway pressure.
- Cat Brain must create or update incident state when Hermers is degraded, ACP is unavailable, stale dispatches persist, runtime output is incomplete, or outbound delivery is missing.
- Cat Brain may ask Cat Claw to report to Flashcat or open Human Gate when the required action crosses operational authority. It must not impersonate the backend service layer to restart Gateway/Hermers from inside runtime, rewrite profile config, kill workers, reset sessions, or migrate cron ownership without explicit authorization and rollback evidence.
- Governance quality is multi-layered:
  - systemd/user services provide process liveness and bounded restart semantics
  - `cat-agents-stabilityd` provides cross-runtime mechanical stability facts, repair candidates, and policy-gated external repairs
  - `trading-agents-workflow` provides durable dispatch/messageflow/receipt closure
  - Cat Brain provides semantic governance, incident command, repair coordination, and evidence sufficiency
  - Cat Claw provides secretary review, Human Gate packaging, and user-facing delivery receipt
  - Codex provides Flashcat's control panel, deployment discipline, and high-impact ops guardrail

2026-05-23 operator judgment warning:

- Flashcat explicitly identified a mistaken judgment during this governance cycle: because stabilityd had kept the system stable for a long period, it became easy to forget the pre-stabilityd failure mode where frequent cron/session/channel/runtime pressure could make Cat Brain itself ineffective.
- This is a standing caution, not a blame note. Stable operation is often proof that the external control plane is working, not proof that it can be removed.
- Any future request, even from Flashcat, to remove, disable, or delegate stabilityd deep governance must first answer the runtime-incapacitation question: if Cat Brain, Hermers profiles, OpenClaw sessions, or workflow workers are already overloaded or unavailable, which external actor will reduce mechanical pressure?
- If the proposed answer depends only on Cat Brain/runtime/workflow self-repair, the change is unsafe. Keep stabilityd's external repair layer or design an equivalent out-of-band replacement before reducing authority.

## Core Governance Principle

Cat agents stability should be governed primarily through soft-pressure control, not through restart-first recovery.

The purpose of soft-pressure governance is to keep OpenClaw operating smoothly enough that hard faults become rare. When soft governance works, queues are drained before they become stuck, heavy jobs yield before they block direct lanes, sessions recover before they require reset, and resource pressure is reduced before Gateway crosses a hard-failure threshold.

Restart has three distinct meanings and must not be blurred:

- Hard-fault restart: a normal recovery action for clear Gateway death conditions.
- Soft-pressure rescue restart: a last-attempt intervention when OpenClaw is technically alive but has lost realistic operating capacity after sustained failed soft governance.
- Routine soft-pressure governance: never restart-first; it should use backpressure, priority, isolation, throttling, cooperative deferral, lease hygiene, and focused operator findings.

Therefore the main engineering problem is not how to restart more safely. The main problem is how to make soft governance efficient, precise, and low-friction.

Soft governance quality is measured by:

- preventing direct/operator lanes from being blocked by heavy internal work
- reducing queue age and session backlog without interrupting useful runs
- distinguishing active long-running work from stuck work
- keeping control-plane jobs cooperative through explicit backpressure contracts
- avoiding noisy alerts and repeated low-value mutations
- making escalation rare, explainable, and auditable

Restart remains available as a rescue tool, but only after soft governance has had time to work and evidence shows the system is still approaching operational failure.

## Current Baseline

Existing server components:

- `/home/flashcat/scripts/openclaw_gateway_watchdog.sh`
- `/home/flashcat/scripts/openclaw_cron_guard.py`
- `/home/flashcat/scripts/openclaw_cron_audit.py`
- `/home/flashcat/scripts/openclaw_session_guard.py`
- `/home/flashcat/scripts/openclaw_health_controller.py`
- `/home/flashcat/scripts/openclaw_cron_run_wrapper.py`

Existing systemd units:

- `openclaw-gateway.service`
- `openclaw-gateway-watchdog.service`
- `openclaw-cron-guard.timer`
- `openclaw-session-guard.timer`
- `openclaw-health-controller.timer`
- `openclaw-maintenance-update-check.timer`
- `openclaw-backup.timer`

Important issue found on 2026-04-30:

- `/home/flashcat/.openclaw/cron/health/gateway-watchdog.json` was stale since `2026-04-22 04:28:05 CST`.
- `cron_guard` and `cron_run_wrapper` still trusted that stale file for `canMutateCronState`.
- Restart authority was split between `openclaw_gateway_watchdog.sh` and `openclaw_health_controller.py`.
- `openclaw_gateway_watchdog.sh` restarted gateway by launching a raw `node ... gateway --port 23466` process instead of using `systemctl restart openclaw-gateway.service`.

## Target Architecture

### Main Service

New daemon:

`cat-agents-stabilityd.service`

Install path:

- `/home/flashcat/cat-agents-stabilityd/bin/cat_agents_stabilityd.py`
- `/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability`

State paths:

- `/home/flashcat/.openclaw/stability/state.db`
- `/home/flashcat/.openclaw/stability/latest.json`
- `/home/flashcat/.openclaw/stability/policy.json`
- `/home/flashcat/.openclaw/stability/events.jsonl`
- `/home/flashcat/.openclaw/stability/actions.jsonl`

Compatibility output:

- `/home/flashcat/.openclaw/cron/health/gateway-watchdog.json`

The compatibility file is written by the new daemon only while older cron wrappers or tools still read it.

### Components

Collectors:

- `GatewayCollector`
- `CronCollector`
- `SessionCollector`
- `ChannelCollector`
- `HermersCollector`
- `ResourceCollector`
- `ConfigCollector`

Analyzers:

- `GatewayAnalyzer`
- `CronAnalyzer`
- `SessionAnalyzer`
- `ChannelAnalyzer`
- `HermersAnalyzer`
- `ResourceAnalyzer`
- `RuntimeAnalyzer`

Policy engine:

- Computes global mode and severity.
- Produces mutation permissions.
- Applies cooldown and restart storm protection.
- Fails closed when policy is stale.

Actuators:

- `GatewayActuator`
- `CronActuator`
- `SessionActuator`
- `HermersActuator`
- `ResourceActuator`

Hermers runtime governance boundary:

- Allowed by default: record findings, classify stale dispatch/messageflow state, reap eligible orphan ACP workers, reap eligible idle Hermers profile LSP helper processes, and perform policy-gated Hermers profile lifecycle repair through the Hermers profile-scoped CLI adapter for registry-derived managed profiles.
- Hermers LSP idle reap is scoped to helper processes such as `pyright-langserver --stdio` under `~/.hermes/profiles/<profile>/lsp/`. It must not stop the Hermers profile gateway, ACP workers, OpenClaw Gateway, or workflow runtime state. Default threshold is 4 hours of observed CPU-tick inactivity, not process elapsed time. Before SIGTERM, stabilityd must revalidate PID, profile path, live parent gateway command, and unchanged CPU ticks after the snapshot. This helper reap does not use the profile lifecycle allowlist because it is not a profile residency transition, but it must still record action-ledger evidence.
- Profile runtime mode is stabilityd-coordinated, not a separate agent runtime controller. `cat-agents-stabilityd` records warm/cold/hibernate observations and may request Hermers profile gateway stop/start only through `hermes -p <profile> gateway stop|start` when the profile is registry-derived, explicitly lifecycle-allowlisted for stabilityd execution, unprotected, idle, has no active workflow/runtime evidence, has fresh profile-matching runtime-owned `safeToHibernate` evidence before stop, and passes action cooldown. Profile lifecycle execution defaults to observe-only unless `CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTUATE=1` is explicitly set; the lifecycle allowlist defaults to empty and must be set with `CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_ALLOWLIST`. This allowlist is only a stabilityd blast-radius limiter, not a cat-system membership or residency policy source.
- Hermers Gateway restart is a service-level actuator inside the Hermers adapter boundary. `cat-agents-stabilityd.service` may request `hermes -p <profile> gateway restart` when the restart actuator is enabled and cooldown/restart-history gates pass.
- Disabled by default: rewrite profile config, migrate cron ownership, switch runtime adapter, or start/stop profiles outside the Hermers profile-scoped adapter and stabilityd profile-mode policy. These require explicit operator/Human Gate authorization.

## Hermers Profile Runtime Modes

2026-05-23 resource optimization lesson:

- The 4C/8G development server did not show CPU saturation or kernel OOM. The risk was memory commitment and swap pressure from multiple long-lived Hermers profile gateways plus OpenClaw Gateway.
- Stopping one low-priority profile (`catears`) released roughly 0.9-1.1 GiB of usable headroom and reduced swap pressure without restarting Gateway or touching active trading workflow state.
- The original stop action was issued by `cat-agents-stabilityd` through `systemctl --user stop`, not by Hermers itself. That path is now treated as a boundary mistake for profile lifecycle work. Future profile lifecycle actions must go through the Hermers profile-scoped adapter (`hermes -p <profile> gateway stop|start|restart`) or remain blocked as repair candidates until Hermers exposes a stronger native warm/cold/hibernate API.
- Workflow runtime/dispatch evidence is not sufficient proof that a Hermers profile is idle. Telegram ingress, profile-local cron, and runtime-owned queues can create useful work without a current `trading-agents-workflow` dispatch row.
- The profile-mode actuator is retained as an external stability repair path because it can still act when agent runtimes are under pressure. It must remain registry-first, protected-member aware, cooldown-limited, evidence-driven, and routed through the owning runtime adapter rather than direct platform bypass.

Runtime mode definitions:

- `hot`: profile has active ACP workers, active workflow runtime rows, or active dispatch evidence. It must not be stopped.
- `warm`: profile service is expected active and no cold/hibernate observation is present.
- `cold`: profile has been idle beyond the cold threshold. This constrains readiness/admission evidence but does not stop the service by itself.
- `hibernate`: observation that the profile appears idle beyond the hibernate threshold. It becomes authority to request Hermers profile gateway stop only when the profile is registry-derived, managed, unprotected, has no active work evidence, and the runtime-owned state explicitly reports fresh, profile-matching `safeToHibernate=true`; it does not suppress service-down readiness findings by itself.

Profile observation source:

- Cat-system member observation starts from `trading-agents-workflow.runtime_agents`, not from a Hermers-only list.
- Hermers profile observations are derived primarily from active `runtime_agents` records with `platform=hermers`, an explicit workflow ingress adapter such as `acp`, dispatch eligibility, and an endpoint reference such as `hermes-profile:<profile>`. Legacy `runtime=hermers`, `runtime=hermes`, `runtime=hermes_acp`, or `hermers-profile:<profile>` endpoint aliases are read compatibility signals only; desired-state may accept them as migration-compatible observations, but `preferredEndpointRef` remains the canonical `hermes-profile:<profile>` target.
- If the workflow registry is unavailable or empty, stabilityd emits a registry-unavailable finding and does not synthesize a Hermers member list.
- Cold threshold defaults to 30 minutes idle.
- Hibernate threshold defaults to 8 hours idle.
- `cold` and `hibernate` are readiness observations for workflow. For stabilityd they are repair candidates; actual stop/start execution still requires the profile-mode gates and the Hermers profile-scoped lifecycle adapter.

Configuration:

- `CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ENABLED=1|0`
- `CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_ALLOWLIST=catnose,catears` or another explicit stabilityd execution allowlist; empty by default, and `*` should be used only after a Human Gate/operator decision. Legacy `CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_MANAGED` is accepted only as a compatibility alias.
- `CAT_AGENTS_STABILITY_HERMERS_PROFILE_PROTECTED_IDS=main,cat_heart,catheart,cat_claw` for profiles or agent ids that stabilityd must never lifecycle-actuate. Legacy `CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_PROTECTED` is accepted only as a compatibility alias.
- `CAT_AGENTS_STABILITY_HERMERS_PROFILE_COLD_IDLE_SECONDS=1800`
- `CAT_AGENTS_STABILITY_HERMERS_PROFILE_HIBERNATE_IDLE_SECONDS=28800`

State and evidence:

- `/home/flashcat/.openclaw/stability/hermers-profile-modes.json`
- `cat-agents-stability profile-modes`
- `cat-agents-stability lanes`, under `domains.hermers.profileRuntimeModes`

Unified agent lifecycle policy:

- `trading-agents-workflow` is a workflow scheduler and evidence plane, not the runtime platform for cat-system members.
- Cat-system members run inside OpenClaw, Hermers/Hermes, Codex, or other registered runtimes. Runtime residency is owned by those platforms.
- Unified lifecycle language is governance vocabulary for readiness, dispatch admission, receipt, Human Gate evidence, and stabilityd external repair. It must map to runtime-domain observations and policy-gated stabilityd/runtime controls instead of creating platform-local membership policy.
- Hermers/Hermes, OpenClaw, Codex, and future runtimes are platform adapters under the global `runtime_agents` registry. They must not define separate cat-system member policy from their own local profile lists.
- Runtime-specific checks can inspect service names, profile files, cron state, sessions, or ACP workers only after the target members are selected from the global registry.
- OpenClaw session scanning is registry-scoped. `cat-agents-stabilityd` must read `trading-agents-workflow.runtime_agents` first, derive active OpenClaw members, and only then inspect `.openclaw/agents/<agent>/sessions/sessions.json` for those members. Dormant `openclaw_route_shell` records and migrated Hermers agents are historical evidence paths, not active session-governance targets.
- The workflow may export `registry/runtime-agents.snapshot.json` as an atomic read-only fallback for stabilityd when SQLite is temporarily unavailable. The snapshot is derived evidence from `runtime_agents`, not a separate desired-state authority.
- Protected member requirements such as `main`, `catheart` / `cat_heart`, and `cat_claw` must be enforced by stabilityd and runtime-specific protection policy; workflow must not override them, and stabilityd profile lifecycle actions must skip them.

Safety rules:

- Never infer that every profile is safe to hibernate. Warm/cold/hibernate execution requires registry-derived membership, an explicit stabilityd lifecycle allowlist entry, protected-member exclusion, no active workers/runtime rows/dispatch evidence, reliable activity probe, fresh profile-matching runtime-owned `safeToHibernate=true`, explicit actuator enablement, and action cooldown.
- Never stop a profile with active ACP workers, active workflow runtime rows, active dispatch evidence, pending Telegram ingress, profile-local cron work, or runtime-owned queue work.
- Absence of workflow activity is not proof of runtime idleness. It is only one signal.
- Workflow activity probe failure blocks lifecycle conclusions. If the workflow DB or `runtime_agents` registry is missing, locked, schema-drifted, or unreadable, stabilityd emits a registry/probe finding and does not make member lifecycle claims.
- A service being inactive is not by itself proof of intentional hibernation. `cat-agents-stabilityd` must not suppress `hermers_gateway_service_down` from its own historical hibernate records.
- Do not use systemd hard memory caps or Node heap caps as the first response when the problem is agent runtime residency. Prefer runtime-native lifecycle evidence, workflow admission control, and session/context externalization first.
- Human/operator-critical residency or protection requirements must be expressed through `runtime_agents`, runtime-owned policy, or explicit Flashcat instruction, not through stabilityd-local profile classes.

## State Machine

Supported modes:

- `healthy`
- `degraded`
- `gateway-unreachable`
- `channel-stalled`
- `delivery-failing`
- `cron-congested`
- `cron-state-corrupt`
- `session-stuck`
- `agent-runtime-degraded`
- `hermers-unavailable`
- `hermers-degraded`
- `message-flow-stuck`
- `resource-pressure`
- `recovery-needed`
- `cooldown`
- `restart-storm`
- `manual-approval-required`

## Policy Contract

`policy.json` format:

```json
{
  "schemaVersion": 1,
  "updatedAt": "2026-04-30T17:30:00+0800",
  "updatedAtEpoch": 1777541400,
  "validUntilEpoch": 1777541580,
  "mode": "degraded",
  "severity": "high",
  "canMutateCronState": false,
  "canResetSession": false,
  "canRestartGateway": false,
  "canRunBulkCron": false,
  "shouldPauseNonCriticalCron": true,
  "cooldownUntilEpoch": 1777543200,
  "reasons": []
}
```

Rules:

- Any missing policy is treated as deny.
- Any expired policy is treated as deny.
- Cron stale/lease repair, eligible session reset, orphan worker termination, Hermers-adapter profile lifecycle actions, and Gateway restart are inside the controlled stabilityd actuator boundary when policy gates allow them.
- Gateway restart is inside the controlled service-level actuator boundary for OpenClaw Gateway and Hermers Gateway, subject to explicit policy, evidence, cooldown, restart-storm/history gates, action ledger, and post-check evidence.
- Runtime config edits, model routing changes, profile config rewrites, membership changes, and trading-side effects remain outside stabilityd's automatic actuator boundary.

## Recovery Policy

P3 observe:

- Single transient failures.
- Offset stale with no pending messages.
- Low resource warning.

P2 warn:

- Repeated non-user-visible failures.
- Audit high findings without direct backlog.

P1 local repair:

- Expired cron leases.
- Stale running cron state.
- Old tmp files.
- Stale session entries that are inactive and not heavy.

P0 controlled restart:

- Gateway service down.
- Gateway port down.
- Health endpoint failure.

Hard-fault restart precision:

- Gateway hard-fault restart candidates are limited to:
  - `gateway_service_down`
  - `gateway_port_down`
  - `gateway_health_endpoint_failed`
- Gateway health endpoint success requires HTTP 2xx/3xx. HTTP 4xx/5xx is treated as health failure, not success.
- The policy distinguishes a restart candidate from executable authority:
  - `restartCandidate`
  - `gatewayRestartEnabled`
  - `restartBlockedReasons`
  - `canRestartGateway`
- `restart-storm`, cooldown, startup grace, and disabled actuator can block an otherwise valid restart candidate.
- Startup grace depends on parsing systemd `ExecMainStartTimestamp`; systemd timestamps such as `Fri 2026-05-01 05:56:30 CST` must parse correctly so a just-started Gateway is not mistaken for hard failure.
- Resource pressure, child accumulation, cron congestion, session backlog, and channel lag are not hard-fault restart conditions by themselves.

P0 manual:

- Restart storm.
- Auth repair.
- Config rewrite.
- Bulk session cleanup.
- Cron migration.
- Channel stalled with pending backlog after sustained streak.
- Cron and session pressure agreeing on unhealthy runtime after sustained streak.

## Cutover Plan

This implementation performs the five requested steps in one deployment window:

1. Install read/write `cat-agents-stabilityd`.
2. Write new `policy.json`, `latest.json`, event ledger, and compatibility watchdog health file.
3. Disable old autonomous timers/services:
   - `openclaw-gateway-watchdog.service`
   - `openclaw-cron-guard.timer`
   - `openclaw-session-guard.timer`
   - `openclaw-health-controller.timer`
4. Keep low-risk existing services:
   - `openclaw-gateway.service`
   - `openclaw-backup.timer`
   - `openclaw-maintenance-update-check.timer`
5. Verify:
   - `systemctl status cat-agents-stabilityd.service`
   - `/home/flashcat/.openclaw/stability/latest.json`
   - `/home/flashcat/.openclaw/stability/policy.json`
   - `/home/flashcat/.openclaw/stability/events.jsonl`

## Actual Cutover Notes

Actual cutover was completed on 2026-04-30. The implementation followed the target architecture, but several operational details differ from the original plan and must be treated as the current source of truth.

### Account and Scheduling Boundary

- The development server account is `flashcat`.
- `flashcat` is the primary OpenClaw/Codex operations account on `106.54.53.146`.
- `flashcat` has sudo permission and was verified to support non-interactive sudo.
- `flashcat` has no user crontab: `crontab -l` returns `no crontab for flashcat`.
- No OpenClaw entries were found under `/etc/cron.d`, `/etc/cron.daily`, `/etc/cron.hourly`, or `/etc/cron.weekly`.
- OpenClaw runtime scheduling is split between:
  - `cat-agents-stabilityd.service` for stability governance.
  - systemd timers for low-risk maintenance.
  - OpenClaw internal Gateway cron for business cron jobs.

Current OpenClaw-related systemd timers intentionally kept:

- `openclaw-backup.timer`
- `openclaw-maintenance-update-check.timer`

Disabled legacy autonomous timers:

- `openclaw-cron-guard.timer`
- `openclaw-session-guard.timer`
- `openclaw-health-controller.timer`

### Legacy Watchdog Shutdown Detail

The original plan said to disable `openclaw-gateway-watchdog.service`. During cutover, the unit had `Restart=always`, and its systemd cgroup previously contained unrelated `nginx` processes because the old watchdog script had started gateway-related processes directly.

To avoid killing unrelated processes, the actual shutdown sequence was:

1. Disable `openclaw-gateway-watchdog.service`.
2. Inspect the service `MainPID`, cgroup, and process list.
3. Stop only after confirming the active cgroup no longer contained `nginx`.
4. Stop the disabled service normally with systemd.

Current state:

- `openclaw-gateway-watchdog.service` is disabled and inactive.
- `openclaw-gateway.service` remains enabled and active.
- Gateway restart authority is now owned by `cat-agents-stabilityd`.

### Compatibility Health File

The stale file problem was corrected by making the new daemon write:

`/home/flashcat/.openclaw/cron/health/gateway-watchdog.json`

This file is now compatibility output, not an independent source of truth. Older components that still read it receive fresh policy-derived fields:

- `canMutateCronState`
- `canRunBulkJobs`
- `shouldPauseCron`
- `needsRestart`
- `restartAllowed`
- `source: cat-agents-stabilityd`

The authoritative policy remains:

`/home/flashcat/.openclaw/stability/policy.json`

### Channel Collector Correction

The first dry-run did not fully discover Telegram accounts because the collector only inferred generic channel files. The implementation was corrected to read OpenClaw's actual configuration and offset layout:

- Account config source:
  - `/home/flashcat/.openclaw/openclaw.json`
  - `channels.telegram.accounts`
  - `bindings[].match.channel == telegram`
- Offset source:
  - `/home/flashcat/.openclaw/telegram/update-offset-<account>.json`

Verified Telegram accounts discovered:

- `default`
- `cat_brain`
- `cat_ears`
- `cat_eyes`
- `cat_gunclaw`
- `cat_heart`
- `cat_penclaw`
- `cat_shieldclaw`
- `cat_swordclaw`
- `cat_tail`
- `cat_voice`

Offset stale with `pendingCount=0` is warning-only. It must not trigger `channel-stalled` unless pending updates exist or API probes fail.

Follow-up correction on 2026-04-30 20:10 CST:

- `cat-agents-stabilityd` must not call Telegram `getUpdates` during normal checks.
- Gateway owns Telegram long polling. A second `getUpdates` caller can produce Telegram `409 Conflict` errors and make live sessions appear unresponsive.
- The stability channel collector now reads local offset files and config only by default.
- Optional Telegram API probing is limited to non-invasive methods such as `getMe`, gated behind `OPENCLAW_STABILITY_TELEGRAM_API_PROBE=1`.
- `pendingCount` is therefore `null` by default unless an explicitly safe probe mechanism is added later.
- Follow-up correction from the legacy `openclaw_health_controller.py` review:
  - channel provider health may use Gateway log markers such as Telegram network failures and channel stop timeouts
  - these are non-invasive observations because they do not call `getUpdates`
  - `telegram_provider_network_errors` can become channel evidence when current log-window failures are elevated
  - `telegram_channel_restart_limited` and `telegram_channel_restart_churn` become channel evidence when Telegram providers repeatedly stop and the Gateway health monitor reaches its restart budget
  - `telegram_channel_stop_slow` remains warning-only unless paired with real delivery lag or Gateway congestion

Incident note:

- At `2026-04-30 20:07 CST`, `cat_brain` Telegram traffic was routed to `agent:main:telegram:direct:8390724843` with `agentAccountId=cat_brain`.
- The message entered the main session, but Telegram delivery failed with `sendMessage failed` / `final reply failed`.
- A concurrent `getUpdates conflict` appeared immediately before the send failures.
- After disabling the invasive `getUpdates` probe and restarting `cat-agents-stabilityd`, no new `getUpdates conflict` entries were observed in the checked window.

Incident note, 2026-05-14:

- A VPN/proxy outage around 10:00 CST appears to have triggered Telegram provider instability.
- After the external network recovered, Gateway stayed alive but Telegram subchannels remained unhealthy: each account repeatedly logged `health-monitor: restarting (reason: stopped)` and then `hit 6 restarts/hour limit, skipping`.
- Direct symptom: Telegram messages to `cat_body` stopped receiving replies; `cat_body heartbeat` reported `Message failed`.
- The server proxy itself was healthy at diagnosis time: Telegram API and ChatGPT backend were reachable through `127.0.0.1:7890`.
- Manual remediation was one operator-authorized `systemctl restart openclaw-gateway.service`, which reinitialized Telegram providers and refreshed `/home/flashcat/.openclaw/telegram/update-offset-cat_body.json`.
- Governance correction: restart-limit churn is a real channel-failure signal. It must enter channel pressure even when `getUpdates` pending count is unavailable, because the consumer can be dead while the provider API is reachable.

### Stabilityd Runtime Correction

Follow-up correction on 2026-04-30 20:25 CST:

- `cat-agents-stabilityd` had an intermittent `TypeError: add_finding() missing 1 required positional argument: 'message'`.
- Root cause: the `gateway_health_endpoint_failed` finding missed the `component` argument.
- Impact: when the Gateway port was open but the health endpoint probe failed, one stability loop could be skipped.
- Fix: add `component="gateway"` to that finding and restart only `cat-agents-stabilityd.service`.
- Verification: remote `py_compile` passed; after restart, multiple stability loops completed without new `loop_error` entries.

### Gateway Restart Loop Incident

Observed on 2026-05-01 04:16 CST:

- `cat_brain 4h-report` failed because Gateway was restarted while the report was running.
- `cat-agents-stabilityd` triggered repeated `restart_gateway` actions with reason `cron-and-session-pressure`.
- Restart count in `actions.jsonl`: 20 total from `2026-04-30 17:53:54 CST` through `2026-05-01 04:08:53 CST`.
- The cadence was effectively every 30 minutes, which matched the default restart cooldown and therefore bypassed restart-storm protection.
- This is a stability governance failure, not a normal `cat_brain` workload failure.

Immediate mitigation applied:

- Added systemd override:
  - `/etc/systemd/system/cat-agents-stabilityd.service.d/disable-gateway-restart.conf`
  - `Environment=OPENCLAW_STABILITY_RESTART_GATEWAY=0`
- Restarted only `cat-agents-stabilityd.service`.
- Gateway restart actuator is now disabled; monitoring, findings, policy, session reset, cron state hygiene, and backpressure state remain active.

Current policy expectation after mitigation:

- `canRestartGateway=false`
- `deferControlPlaneHeavyReports=true` while the system remains under pressure.
- Any future re-enable of Gateway restart authority must first revise restart policy so sustained cron/session pressure cannot produce a 30-minute restart loop.

Permanent policy correction:

- Gateway restart is now a hard-fault-only action by default.
- Allowed automatic restart reasons by default:
  - `gateway_service_down`
  - `gateway_port_down`
  - `gateway_health_endpoint_failed`
- Soft pressure reasons no longer restart Gateway by default:
  - `cron-and-session-pressure`
  - `stuck-sessions-with-resource-pressure`
  - Telegram consumer lag
- Soft restart paths require explicit opt-in:
  - `OPENCLAW_STABILITY_SOFT_RESTART_GATEWAY=1`
- Restart-storm defaults were tightened:
  - window: 6 hours
  - max restarts: 2
- Restart-storm accounting only includes Gateway restarts successfully executed by `cat-agents-stabilityd` itself.
- Human-authorized restarts, Codex-authorized manual restarts, direct `systemctl restart openclaw-gateway.service`, and systemd/external restarts must not increment `restartStorm`.
- Server reboot and passive Gateway startup after host reboot must not increment `restartStorm`; Gateway `ExecMainStartTimestamp` and systemd restart counters are used only as health/startup-grace context, not as restart-storm history.
- Restart history source of truth:
  - `stabilityd_gateway_restart_history`
  - `stabilityd_last_gateway_restart_at`
- Policy field:
  - `restartHistorySource=cat-agents-stabilityd-owned-restarts-only`

Operational rule:

- `cron-and-session-pressure` should produce backpressure, cron throttling, repair requests, and human-visible findings, not Gateway restart.

### Soft Pressure Governance

Soft pressure means the OpenClaw runtime is still alive but less smooth: queue age grows, cron jobs run long, session backlog accumulates, direct replies slow down, or resource headroom narrows. It is not a service death condition. Treating soft pressure as a restart trigger is unsafe because it interrupts useful work and can convert slow progress into repeated failure.

External operating principle:

- SRE monitoring should prioritize user-visible symptoms, but recovery actions must match failure class. Overload is usually handled with backpressure, load shedding, priority, and graceful degradation, not process restarts.
- Agent observability should expose sessions, tool calls, latency, errors, memory, and handoffs as diagnostic context. These traces should help decide which lane is congested; they should not become a large set of independent mutators.
- Queue and worker systems are best governed by lag, age, lease, heartbeat, and retry budget. OpenClaw cron runs, channel offsets, and agent sessions should be treated with the same queue-control model.

Design goal:

- Soft pressure governance is a lubricant for OpenClaw's internal operating mechanism.
- It should reduce friction, keep control-plane entrypoints responsive, and preserve useful work already in flight.
- It should stay small, stable, and boring: a few high-signal inputs, conservative actions, explicit expiry, and clear audit output.
- It should make hard-fault recovery less likely by correcting runtime friction early.

Target soft-governance structure:

- Admission control: decide what new work may enter each lane.
- Prioritization: protect direct/operator and heartbeat work over heavy background reports.
- Backpressure contract: publish small machine-readable pressure state for cooperative jobs.
- Bulkheads: keep heavy cron/control-plane work from blocking direct sessions.
- Retry budget: prevent repeated retries from becoming self-inflicted load.
- Circuit breaker: stop repeatedly calling a degraded dependency or provider until a short probe succeeds.
- Lease hygiene: distinguish expired/stale ownership from active long-running work.
- Feedback controller: step actions up or down based on whether pressure improves.

Lane policies:

- Primary pressure-domain policy:
  - `cron`: govern schedules, queue age, running leases, concurrency, stale state, retry density, and non-critical job admission
  - `session`: govern stuck/failed/overflow sessions, reset eligibility, active-progress protection, heavy-but-active detection, and direct-session safety
  - `channel`: govern provider liveness, offset age, pending backlog, passive probes, provider backoff, and delivery symptoms without competing consumers
  - `hermers`: govern profile service readiness, ACP backend availability, ACP worker lifetime, runtime final output, and return-path receipt integrity
- Secondary pressure-domain policy:
  - `gateway`: treat as runtime hub health and escalation evidence
  - `resource`: treat as pressure amplifier and capacity signal
- Direct/operator lane:
  - highest priority
  - never bulk paused
  - should receive available capacity before heavy cron work
  - symptoms here have the strongest influence on severity
- Control-plane lane:
  - `cat_brain heartbeat` is critical health work and should continue under pressure
  - `cat_brain 4h-report` is heavy governance work and should cooperate with backpressure
  - long-term target is subagent or systemd isolation for heavy reports
- Background cron lane:
  - first candidate for deferral and concurrency reduction
  - non-critical jobs should read policy/backpressure before starting
  - stale running state should be repaired only when owner liveness is absent or lease expiry is clear
- Channel-provider lane:
  - monitor offset age and pending count without competing consumers
  - provider API probes must be low-impact and preferably non-consuming
  - channel lag alone is not restart evidence
  - provider restart-limit churn is channel pressure, because it means the Gateway health monitor can no longer self-heal the channel without operator or policy action
- Session-store lane:
  - reset only inactive, clearly stuck, or failed sessions
  - protect recent-progress and heavy-but-active sessions
  - suppress repeated no-op resets
- Resource lane:
  - prefer log cleanup, tmp cleanup, concurrency reduction, and cron pause before restart
  - resource exhaustion is a multiplier for escalation, not always an action by itself

Soft pressure signals:

- Direct lane latency or no-response symptom.
- Cron queue age, run duration, stale running leases, and retry density.
- Session backlog, session age, aborted-last-run count, and heavy-session concentration.
- Channel provider offset age and pending count, without invasive competing consumers.
- Channel provider restart churn:
  - `health-monitor: restarting (reason: stopped)` within the current log window
  - `health-monitor: hit ... restarts/hour limit`
  - stale offset for a direct account after restart-limit churn
- Hermers profile readiness, ACP check outcome, ACP worker age, orphan ACP worker count, incomplete output count, stale runtime runs, and missing outbound delivery receipt count.
- Resource headroom: disk, memory, swap, process count, and log growth.
- Control-plane contention: `cat_brain` heavy report active while direct/operator traffic needs responsiveness.

Signal precision rules:

- Prefer age, duration, pending count, lease owner, active process, and recent progress over raw error count.
- Treat a single signal as context, not authority.
- Require cross-signal agreement before mutation: for example cron pressure plus session backlog, or channel lag plus pending backlog.
- Separate direct/operator lane symptoms from background cron symptoms.
- Separate active heavy work from stuck work by checking recent progress and owner liveness.
- Use black-box symptoms to protect users and operators, and white-box signals to choose the least disruptive action.

Soft pressure actions:

- Defer low-priority or heavy cron jobs with a short reason marker.
- Pause non-critical cron while keeping heartbeat, backup, and operator-critical jobs available.
- Apply per-lane concurrency caps before global pauses.
- For sustained external-network failure, enter channel backoff: keep direct/operator lanes protected, limit background cron, and avoid repeated provider restarts while the network is still down.
- When the network becomes reachable again but Telegram providers remain restart-limited, require a channel-recovery action rather than waiting for stale offsets to age out.
- Extend or clean stale leases only when the owning process is gone or the lease is clearly expired.
- Emit compact operator findings and append-only audit records.
- Write backpressure state for cooperative jobs to read.
- Prefer subagent/systemd isolation for heavy control-plane reports over running them inside the same direct-response lane.
- As a last-resort rescue path, allow one controlled Gateway restart only when soft-pressure governance has clearly failed and the system has remained at collapse edge for a sustained window.
- Treat Hermers profile `warm -> cold -> hibernate` as a profile-mode governance stream before treating memory pressure as a Gateway restart problem; stabilityd may request residency changes only through the Hermers profile-scoped adapter for managed, unprotected, registry-derived profiles with runtime-owned hibernate safety evidence.
- Keep active development profiles protected; if a profile is doing visible work, stabilityd may observe it but must not reclaim it as memory headroom.

Action ladder:

- Level 0 observe: record finding, update streak, no mutation.
- Level 1 lubricate: write backpressure state, defer heavy jobs, reduce background concurrency.
- Level 2 repair local state: clear expired leases, mark stale runs, suppress duplicate missing-session resets.
- Level 3 isolate: move or route heavy control-plane work away from direct/operator lanes.
- Level 4 pause: pause non-critical cron while keeping heartbeat and operator-critical paths alive.
- Level 5 rescue restart: one controlled Gateway restart only after sustained collapse-edge evidence.

Feedback loop:

- Every soft action must have an expiry.
- Every soft action should define what improvement it expects: lower queue age, fewer pending direct replies, reduced heavy-job overlap, or lower resource pressure.
- If the expected improvement appears, step down automatically.
- If no improvement appears after the rescue window, escalate the diagnosis rather than repeating the same action.
- Action ledgers should explain why a softer action was chosen and why escalation was or was not allowed.

Efficiency rules:

- Prefer cheap local facts over expensive probes.
- Prefer deltas and trends over static thresholds.
- Track pressure half-life: after an action, pressure should visibly decay within a bounded window.
- Avoid high-cardinality alerting; keep detailed traces in evidence files and emit compact policy reasons.
- Keep every mutator behind one policy gate; collectors and analyzers must remain read-only.
- Use hysteresis: enter pressure mode quickly enough to protect the system, exit only after sustained improvement.

Implementation priorities:

- Add lane-scoped policy output next to the existing global policy:
  - `lanes.primaryPressureDomains.cron`
  - `lanes.primaryPressureDomains.session`
  - `lanes.primaryPressureDomains.channel`
  - `lanes.direct.admission`
  - `lanes.controlPlane.heavyReports`
  - `lanes.cron.maxConcurrency`
  - `lanes.cron.nonCriticalPaused`
  - `lanes.channel.probeMode`
  - `lanes.session.resetAllowed`
- Write a standalone machine-readable lane policy:
  - `/home/flashcat/.openclaw/stability/lane-policy.json`
- Lane policy must be treated as a short-lived contract:
  - includes `updatedAtEpoch`
  - includes `validUntilEpoch`
  - consumers must fail closed or fall back to conservative behavior if expired
- For long-term effectiveness, each primary pressure domain exposes a domain state:
  - `lanes.domains.cron.state`
  - `lanes.domains.cron.evidenceKeys`
  - `lanes.domains.cron.observationKeys`
  - `lanes.domains.cron.streakCounts`
  - `lanes.domains.cron.governanceAction`
  - `lanes.domains.session.state`
  - `lanes.domains.session.evidenceKeys`
  - `lanes.domains.session.streakCounts`
  - `lanes.domains.session.governanceAction`
  - `lanes.domains.channel.state`
  - `lanes.domains.channel.evidenceKeys`
  - `lanes.domains.channel.observationKeys`
  - `lanes.domains.channel.streakCounts`
  - `lanes.domains.channel.governanceAction`
  - `lanes.domains.hermers.state`
  - `lanes.domains.hermers.evidenceKeys`
  - `lanes.domains.hermers.observationKeys`
  - `lanes.domains.hermers.streakCounts`
  - `lanes.domains.hermers.governanceAction`
- Admission control must use current pressure evidence, not stale historical evidence:
  - Gateway log pressure defaults to a short window: `OPENCLAW_STABILITY_LOG_PRESSURE_WINDOW_SECONDS=900`.
  - `cron_audit_high_findings` is used only when the old audit report is fresh: `OPENCLAW_STABILITY_CRON_AUDIT_FRESH_SECONDS=3600`.
  - stale `cron_audit_high_findings` is treated as historical context, not current admission pressure.
  - This prevents old 24-hour log findings from keeping cron in `critical-only` after the active pressure has cleared.
- Reference extracted from old `openclaw_cron_audit.py`:
  - keep per-agent/per-job runtime buckets: recent run count, failure count, timeout-like failure count, heartbeat issues, error jobs, long-running jobs, slow jobs, max duration
  - promote `cron_heartbeat_unhealthy` to current cron pressure because heartbeat failure means the cron lane itself is unhealthy
  - keep `cron_heartbeat_slow`, `cron_long_running_jobs`, `cron_timeout_like_failures`, and `cron_orphan_run_logs` as observations first; these shape diagnosis and recovery speed without immediately closing cron
  - maintain a history window with `OPENCLAW_STABILITY_CRON_HISTORY_DAYS=7`, but do not let old history alone trigger restart or hard admission closure
- Reference extracted from old `openclaw_cron_guard.py`:
  - stale running state cleanup, expired lease reaping, job snapshots, tmp cleanup, and repair request enqueue remain valid actuator duties
  - repair requests must expose a policy gate (`ready` or `blocked`) derived from the current control-plane policy, not from the old watchdog file
  - orphan by-job log archiving and session janitor cleanup are useful maintenance ideas, but they are not restored as independent cron-guard authority; they should remain observations or future explicit actuators under the unified policy engine
- Reference extracted from old `openclaw_health_controller.py` and `openclaw_backup.sh`:
  - keep cgroup memory/swap and child process accumulation as hard resource facts
  - add trend samples so memory growth and child growth can be seen before hard thresholds
  - keep backup lock/partial/retention ideas as disk-governance inputs
  - expose `backup_disk_headroom_low` when the next backup may not have enough free space, but do not treat this as a restart reason
  - cross-signal escalation must prefer current cron/session/channel evidence over stale guard files
- In `restart-storm`, do not close cron completely while Gateway is alive. Keep `critical-only` admission with reduced concurrency so heartbeat/control-plane safety work can still run.
- Recovery ladder:
  - active cron pressure or resource/channel pressure: `critical-only`
  - restart-storm or cooldown without active cron pressure: `limited`
  - healthy and stable: `open`
  - This allows cron to recover before the restart-storm window fully expires, while still preventing bulk pressure from returning too quickly.
- Hysteresis state:
  - `lanes.recovery.domains.*.pressureStreak`
  - `lanes.recovery.domains.*.healthyStreak`
  - `lanes.recovery.cronRecoveryLimitedHealthyStreak`
  - `lanes.recovery.cronRecoveryOpenHealthyStreak`
  - cron must maintain healthy loops before moving from `limited` back to `open`.
- Convert heavy cron jobs to cooperative preflight checks against policy/backpressure.
- Cron wrapper integration:
  - `/home/flashcat/scripts/openclaw_cron_run_wrapper.py` reads `/home/flashcat/.openclaw/stability/lane-policy.json`.
  - If lane policy is expired or unreadable, wrapper falls back to its existing watchdog/admission behavior.
  - If `lanes.cron.admission=critical-only`, heartbeat/critical jobs remain eligible and ordinary jobs are recorded as `deferred`.
  - If `lanes.cron.admission=closed`, jobs are recorded as `deferred` rather than waiting indefinitely.
  - If `lanes.controlPlane.heavyReports=defer`, configured control-plane heavy report jobs are recorded as `deferred`.
  - Effective active concurrency is capped by `lanes.cron.maxConcurrency`.
  - Deferred runs are summarized in:
    - `/home/flashcat/.openclaw/cron/runtime/deferred-summary.json`
    - `/home/flashcat/.openclaw/cron/runtime/deferred-runs.jsonl`
- Add a small retry-budget ledger per job/session/provider.
- Add direct-lane symptom collection: last inbound timestamp, last delivered reply timestamp, and pending direct count if available without invasive provider consumption.
- Add explicit external-network recovery handling:
  - non-consuming probes for `https://api.telegram.org` and `https://chatgpt.com/backend-api/codex/models` through the configured proxy
  - classify sustained probe failure as `external_network_unavailable`
  - while unavailable, suppress noisy channel/session escalation and apply backpressure to non-critical cron
  - on probe recovery, check whether Telegram provider offset files and health-monitor logs resume normally
  - if provider restart limits persist after probe recovery, emit `telegram_channel_restart_limited` as channel evidence and escalate to the channel recovery runbook
- Keep `soft-pressure-rescue` as the final Level 5 action, but require evidence that Levels 1-4 were active and failed to improve pressure.

### External Network / VPN Failure Runbook

Purpose: handle long VPN/proxy outages without letting channel failures cascade into cron/session/resource failure, and recover quickly when the network returns.

Detection:

- Probe only non-consuming endpoints:
  - `curl -x http://127.0.0.1:7890 -I --max-time 12 https://api.telegram.org`
  - `curl -x http://127.0.0.1:7890 -I --max-time 12 https://chatgpt.com/backend-api/codex/models`
- Do not call Telegram `getUpdates`.
- Treat current-window Gateway log markers as channel evidence:
  - `telegram provider network failures`
  - `health-monitor: restarting (reason: stopped)`
  - `health-monitor: hit ... restarts/hour limit`
- Check direct-account offsets, especially:
  - `/home/flashcat/.openclaw/telegram/update-offset-cat_body.json`
  - `/home/flashcat/.openclaw/telegram/update-offset-main.json`

During outage:

- Mark channel lane constrained and apply provider backoff.
- Keep direct/operator and heartbeat lanes protected.
- Limit or defer non-critical cron and heavy reports so retries do not accumulate behind a dead provider.
- Suppress repeated session resets caused only by channel delivery failure.
- Do not restart Gateway while the external network probe is still failing unless Gateway itself meets hard-fault criteria.

After network recovery:

- Expect Telegram providers to resume within the Gateway health-monitor recovery window.
- If providers keep logging restart-limit hits or direct offsets remain stale after recovery, treat this as post-outage channel self-heal failure.
- Preferred operator action: one controlled `systemctl restart openclaw-gateway.service`, then verify provider startup, direct inbound, sendMessage success, and offset movement.
- Record the manual restart as operator-authorized recovery, not stabilityd-owned restart-storm history.

Success criteria:

- `openclaw-gateway.service` active.
- Stability mode no worse than `degraded/warning` and no active channel evidence after the log window clears.
- Telegram logs show provider start and `sendMessage ok`.
- The affected direct account offset updates after a new message.
- `cat_body heartbeat` and other critical heartbeats return to `ok` on the next scheduled run.

Forbidden soft pressure actions:

- Do not restart Gateway for `cron-and-session-pressure`.
- Do not restart Gateway for session backlog alone.
- Do not restart Gateway for Telegram offset staleness alone.
- Do not restart Gateway for any single soft-pressure signal.
- Do not perform invasive provider polling that competes with the real consumer.
- Do not repeatedly reset active or recently active sessions just because they are heavy.
- Do not turn every observed metric into an alert or a mutating guard.

Soft-pressure rescue restart:

- This is the final backup path between normal soft-pressure governance and hard-fault restart.
- It exists for the case where Gateway is technically alive, port and health thresholds have not crossed hard-fault limits, but OpenClaw is no longer realistically able to operate.
- It must require multiple independent symptoms, sustained across a long window, with no improvement after ordinary backpressure has had time to work.
- It must still obey global restart controls:
  - no startup grace period
  - no active cooldown
  - no restart storm
  - restart history limit
  - `OPENCLAW_STABILITY_RESTART_GATEWAY`
- Current code-level rescue condition:
  - `severity=critical`
  - sustained soft-pressure streak threshold: `OPENCLAW_STABILITY_SOFT_RESCUE_STREAK`, default `20` daemon loops
  - plus either:
    - sustained cron audit pressure and sustained session backlog, together with sustained resource exhaustion or gateway congestion
    - sustained channel consumer lag together with sustained resource exhaustion
- Rescue restart reason:
  - `soft-pressure-rescue`
- Normal soft restart paths remain disabled unless explicitly opted in with `OPENCLAW_STABILITY_SOFT_RESTART_GATEWAY=1`.
- Rescue restart can be disabled independently with `OPENCLAW_STABILITY_SOFT_RESCUE_RESTART=0`.

Exit conditions:

- Backpressure must expire automatically.
- A soft-pressure mode should clear after queue age, active heavy jobs, and direct-lane responsiveness return below thresholds for a sustained window.
- If pressure persists across multiple windows, the next step is diagnosis and capacity/isolation work, not repeated recovery action.

Current implementation boundary:

- Gateway restart is inside the stabilityd service-level actuator boundary, because the Gateway runs outside the agent runtime and runtime self-restart is a higher-risk control path.
- The OpenClaw Gateway restart actuator is enabled by code default and can still be disabled by deployment environment with `OPENCLAW_STABILITY_RESTART_GATEWAY=0`; valid `canRestartGateway` policy executes `systemctl restart openclaw-gateway.service`.
- Hermers Gateway restart is similarly policy-gated by `CAT_AGENTS_STABILITY_RESTART_HERMERS_GATEWAY=1` / `OPENCLAW_STABILITY_RESTART_HERMERS_GATEWAY=1`, only targets registered Hermers profiles through `hermes -p <profile> gateway restart`, and records its own cooldown/restart-history window.
- Ordinary soft restart and soft-pressure rescue signals remain gated; they may execute only when the specific restart policy allows them and global cooldown/restart-history checks pass.
- `control-plane-backpressure.json` is the first cooperative soft-pressure interface. It should evolve into a small runtime contract used by heavy jobs, not a broad monitoring dump.

Current implementation gap:

- The daemon already has global policy and a control-plane backpressure contract.
- It now exposes first-version lane-scoped policy under both `policy.json.lanes` and `lane-policy.json`.
- Lane policy now includes TTL, primary pressure domains, domain evidence, streak counts, governance actions, and stabilization goals.
- `shouldPauseNonCriticalCron` remains as a compatibility field, but new consumers should prefer `lanes.cron.nonCriticalPaused`, `lanes.cron.admission`, and `lanes.cron.maxConcurrency`.
- Session pressure now requires live session-store evidence before producing `session_problem_backlog`.
- Stuck-session log entries that no longer map to live session store entries are downgraded to `session_problem_stale_log_observations`.
- Active or heavy sessions are recorded as `session_problem_protected_active` and are protected from reset.
- `canResetSession` is still mostly global and should become more session-class aware over time.
- Direct/operator lane symptoms are inferred indirectly and should become first-class.
- Retry budgets exist implicitly through cooldowns, but should become explicit per job/session/provider.

Session guard reference:

- The legacy `/home/flashcat/scripts/openclaw_session_guard.py` remains useful as source material, not as an autonomous controller.
- Valuable behavior absorbed into `cat-agents-stabilityd`:
  - separate failure and overflow scan windows
  - `sessionFile` based activity detection
  - active-progress protection
  - heavy-task protection
  - reset cooldown
  - backups before destructive session reset
- Behavior not copied directly:
  - autonomous timer ownership
  - independent mutation outside the stability policy
  - treating log-only evidence as sufficient without live session-store confirmation
- Current session soft-governance rule:
  - live session-store evidence is required for `session_problem_backlog`
  - missing live entry becomes `session_problem_stale_log_observations`
  - active/heavy sessions become `session_problem_protected_active`
  - only inactive, non-heavy, live problematic sessions can become reset candidates

Near-term correction:

- Keep the global policy as a safety envelope.
- Add lane policy incrementally without replacing the existing compatibility file.
- Treat `control-plane-backpressure.json` as the first lane contract.
- Extend the contract only when a real job or wrapper can consume it.
- Do not add broad metric dumps or alert spam.

### Cat Brain Main Session Observation

Observed on 2026-04-30 20:20-20:30 CST:

- Live Telegram direct traffic for `cat_brain` is stored under the main agent session key:
  - `agent:main:telegram:direct:8390724843`
  - session id `9bdcc966-407e-4420-a285-a18cc484f70c`
- This direct session was `status=done` and `abortedLastRun=false` after the incident.
- Current critical health findings were driven by main cron sessions, not by the direct Telegram session.
- Two recurring jobs create most of the main cron pressure:
  - `cat_brain heartbeat` (`d68d571d-3c38-4a5e-9c5c-7f5a4d00371d`), every 30 minutes, timeout 300s.
  - `cat_brain 4h-report` (`afd4bb03-7481-4d92-947f-845a3f112039`), every 4 hours, timeout 900s.
- Both jobs currently use `agentId=main`; their long runs and occasional timeouts can degrade main lane responsiveness even when the direct session is not stuck.

Decision notes from 2026-04-30:

- `cat_brain` is OpenClaw's internal control-plane coordinator, supervisor, dispatcher, and safety role. Its tasks are expected to be heavier than ordinary agents.
- Direct chat for `cat_brain` must be protected as an operator entrypoint.
- Do not weaken or remove `cat_brain heartbeat`; it is part of the control-plane health chain.
- Do not add hard `control-plane-critical` reset exemptions yet; revisit if ordinary session repair begins to interfere with `cat_brain`.
- Evaluate whether `cat_brain 4h-report` should move to a subagent-based runner or a systemd-backed runner. The goal is isolation, not reducing its governance responsibility.
- Implement conservative backpressure for heavy reports: under system pressure, defer the full 4h report and emit a short deferred note, while heartbeat and direct sessions continue.

Backpressure state path:

`/home/flashcat/.openclaw/stability/control-plane-backpressure.json`

Backpressure policy fields:

- `policy.deferControlPlaneHeavyReports`
- `policy.controlPlaneBackpressureUntilEpoch`
- legacy compatibility:
  - `gateway-watchdog.json.deferControlPlaneHeavyReports`
  - `gateway-watchdog.json.controlPlaneBackpressureActive`

Initial heavy report job:

- `cat_brain 4h-report` (`afd4bb03-7481-4d92-947f-845a3f112039`)

Initial non-deferred control-plane health job:

- `cat_brain heartbeat` (`d68d571d-3c38-4a5e-9c5c-7f5a4d00371d`)

### Session Actuator Correction

The first live run repeatedly attempted to reset stuck cron session keys that were already absent from session stores. These attempts did not mutate files, but they polluted the action ledger.

The daemon was corrected to:

- Record `not_found` session reset results in the same cooldown registry as real resets.
- Suppress repeated reset attempts for the same missing session key during `SESSION_RESET_COOLDOWN_SECONDS`.
- Suppress duplicate high-severity event ledger entries for the same finding key for 300 seconds.

This correction is important: action ledger entries should represent meaningful attempted recovery, not repeated scans of stale log lines.

### Historical Controlled Restart

After legacy controller cooldown expired, the new daemon executed one controlled Gateway restart:

- Time: `2026-04-30 17:53:54 CST`
- Action: `restart_gateway`
- Reason: `cron-and-session-pressure`
- Command path: `systemctl restart openclaw-gateway.service`
- Result: success
- New gateway start time: `2026-04-30 17:53:54 CST`

Post-restart verification:

- `openclaw-gateway.service` active/running.
- `cat-agents-stabilityd.service` active/running.
- `openclaw-gateway-watchdog.service` disabled/inactive.
- Legacy guard/controller timers disabled/inactive.

This event remains the intended service-layer pattern: Gateway restarts are centralized in `cat-agents-stabilityd.service`, rate-limited, audited, and performed through systemd when the restart actuator is enabled and policy gates pass.

### Current Health Interpretation

After cutover, current findings are expected to include some non-green conditions:

- `cron_audit_high_findings`
- `gateway_congestion_logs`
- `disk_pressure`
- `session_problem_backlog`
- Telegram offset stale warnings with `pendingCount=0`
- `session_stale_entries`

These are real signals but not all require immediate mutation. The policy engine currently uses cooldown, restart history, pending update checks, and streak thresholds to prevent restart storms and avoid turning stale logs into repeated destructive actions.

### 2026.5.x Upgrade Adaptation

OpenClaw was upgraded from `2026.4.26` to `2026.5.6` on 2026-05-07. The release line changed runtime/status/Codex/plugin behavior enough that stability governance must treat several old signals differently.

Adapted interpretation:

- Gateway hard health is judged by system-level `openclaw-gateway.service`, TCP port `23466`, and the local health endpoint. `openclaw gateway status --deep` may report the user-service scope as stopped on this server; that is not a Gateway outage while the system service is active.
- `openclaw health` event-loop utilization and CPU markers are secondary evidence only. They should not trigger restart or cron backpressure without primary `cron`, `session`, or `channel` pressure.
- OpenClaw native agent runtime `pi` is normal in 2026.5.x status/session surfaces. It is not a degraded runtime by itself.
- Legacy `cron-audit-latest.json` is no longer required for cron lane governance because stabilityd builds its own cron runtime summary from current job state and run logs. Set `OPENCLAW_STABILITY_LEGACY_CRON_AUDIT_REQUIRED=1` only if the old audit producer is intentionally restored.
- Telegram offset age without pending-update evidence is passive context, not backlog. Set `OPENCLAW_STABILITY_STALE_TELEGRAM_OFFSET_FINDING=1` only if stale local offsets should again produce warning findings.
- Codex quota/model issues are validated by actual `agentMeta.provider`, `agentMeta.model`, and fallback metadata, not by runtime label alone.

Post-adaptation validation on 2026-05-07:

- `cron.state=normal`
- `cron.admission=open`
- `channel.pressure=false`
- `direct.admission=open`
- `findingCount=2`
- remaining findings: backup disk headroom and stale failed session entries

### Current Operations Entry Points

Use these commands first during maintenance:

```bash
/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability status
/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability policy
/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability findings
/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability actions --limit 20
/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability events
/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability runbook
```

Systemd checks:

```bash
systemctl status cat-agents-stabilityd.service --no-pager
systemctl status openclaw-gateway.service --no-pager
systemctl list-timers --all | grep openclaw
```

Do not use `crontab -l` as the primary OpenClaw scheduling source. It is expected to be empty for `flashcat`.

### Scheduled Follow-Up Review

A one-time read-only review was scheduled for:

`2026-05-01 19:53:00 CST`

Purpose:

- Review the first 24 hours of `cat-agents-stabilityd` runtime.
- Inspect policy stability, restart behavior, event/action ledger quality, channel state, session backlog, and cron pressure.
- Decide the next correction batch manually rather than allowing the review job to mutate anything automatically.

Timer/service:

- `cat-agents-stability-review.timer`
- `cat-agents-stability-review.service`

Report script:

`/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability-review.sh`

Report output directory:

`/home/flashcat/cat-agents-stabilityd/reports/`

The review job is intentionally read-only. It gathers:

- `cat-agents-stability status`
- `policy`
- `findings`
- `actions --limit 50`
- `events`
- `runbook`
- relevant systemd status
- OpenClaw-related timers
- `flashcat` user crontab status
- `cat-agents-stabilityd` journal tail

## Rollback

If new daemon fails:

1. Stop it:
   - `sudo systemctl disable --now cat-agents-stabilityd.service`
2. Restore old units:
   - `sudo systemctl enable --now openclaw-gateway-watchdog.service`
   - `sudo systemctl enable --now openclaw-cron-guard.timer`
   - `sudo systemctl enable --now openclaw-session-guard.timer`
   - `sudo systemctl enable --now openclaw-health-controller.timer`
3. Leave `openclaw-gateway.service` running.

Backups are stored under:

`/home/flashcat/cat-agents-stabilityd/backups/<timestamp>/`
