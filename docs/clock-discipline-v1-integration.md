# Clock discipline candidate: not V18 completion

This namespace adds four SQLite tables at version 1. Installation is explicit and
transactional; partial/foreign versions refuse adoption. Existing ledger schema, config, timers and running services are unchanged. The
isolated candidate now also wires the daemon through this namespace. Existing
binaries do not consume this namespace: rollback to one loses timing protection,
so activation/rollback requires a version-aware deployment gate.

The host adapter must provide a stable real boot identity and process-independent
boot-relative milliseconds (Linux CLOCK_BOOTTIME), not a random process UUID or
wall-derived monotonic surrogate. Scope names, tolerance, recovery window and
history bound are trusted fixed policy. Tolerance/recovery numerical choices
remain unqualified; tests use small synthetic values, not production defaults.
Config drift refuses use rather than silently changing a persisted clock policy.

Caller uses its existing FULL SQLite connection and BEGIN IMMEDIATE transaction.
ClockDiscipline never commits, rolls back, changes PRAGMAs or closes this handle.
Call install once in a migration transaction. Call sample in the existing loop,
persist the result with existing evidence, then commit. A fixed boot anchor
catches cumulative small steps; quarantine uses a fixed new stability anchor,
not adjacent deltas. Recovery creates a fresh epoch and preserves all deadlines.
No timing-independent mechanical governance should depend on this proof.

Before actual effects and again after executing CAS, sample current clocks and
require usable proof, unchanged clock epoch in policy/grant/effect qualification,
remaining_ms==0 and history_count below the existing restart-storm policy limit.
A proof is timing evidence, never authority or a bearer capability. Sampling and
ledger CAS must share the existing transaction/lock boundary where possible;
SQLite write errors must abort authorizing the effect. Do not convert a known
no-effect refusal to uncertain. During an actual effect retain the existing
executing/uncertain recovery semantics; never roll back knowledge of a possible
effect merely because final timing persistence failed.

Only after command-level confirmed complete stabilityd-triggered effects, call
record_success in the SAME transaction as the ledger terminal receipt and legacy
KV/history mirror. A failed or unknown health postcheck does not erase a confirmed
restart: the hook runs for succeeded/failed/uncertain when operation is complete
and has an outcome reference. Partial/unknown operations never count as confirmed
restart history. Existing uncertainty remains reserved. history_scope may differ
from cooldown scope (per-profile Hermes cooldown, global Hermes storm counter).
Preflight calls preflight_capacity under the same exclusive writer boundary
held through effects; releasing that boundary requires a durable reservation
protocol, which this candidate does not implement.
A post-effect clock anomaly or persistence error must preserve the durable
executing/uncertain evidence and require reconciliation; it must not claim an
atomic terminal success or permit retry. OS passive starts never call this API.
Stable ledger action IDs prevent in-horizon duplicate recording; after history
expiry the existing durable ledger remains the permanent idempotency authority.
Do not call record_success for a previously terminal ledger row on replay.

For legacy import, caller explicitly maps active policy scopes/history into
conservative complete-duration windows once, then calls complete_legacy_import
in the SAME transaction (including an empty legacy mapping). The durable closed
marker refuses further imports; only after this marker may expiry prune scopes
and history, enabling bounded dynamic session-target churn. import_legacy_window covers cooldown; import_legacy_history imports only known
successful stabilityd restart IDs. The module persists the migration-complete marker with complete_legacy_import;
expired imported IDs cannot be reimported after closing it. Do not infer expiry from a
forward wall jump. Across a boot change all previously active windows/history
restart their original finite duration; already-expired-at-last-sample entries
may be removed. Same-boot daemon restart preserves anchor/deadline. Repeated real
host reboots can conservatively extend a window; this is intentionally not a
wall-credit loophole, and does not inhibit unrelated governance.

Focused fixtures prove core mechanics only. Actual daemon policy/authorizer/executor wiring, the Linux clock adapter, legacy
source mapping and before-effect/CAS-negative fixtures are now included. V18
closure still requires independent source review and Linux qualification of the
final integrated source; no live effect has been executed.

## Actual candidate hooks (not daemon activation)

ActionExecutor constructor takes optional trusted timing_check(conn,spec,record,
phase) and effect_timing(conn,spec,terminal_record,operation_result). Each check
runs inside ActionLedger.run_timing_check's BEGIN IMMEDIATE transaction, after
precheck/before executing CAS, then after refreshed final precheck/immediately
before operation. Only literal True approves; False/None commits an observation
and blocks known-no-effect. Exceptions also block without exposing their text.
Existing ledger records return before any timing/authorization callbacks.

ActionLedger.transition(transaction_hook=...) runs the effect hook after the
successful terminal CAS but before the same commit; hook failure rolls back
both timing changes and terminal receipt, leaving the durable executing claim.
It supports succeeded/failed/uncertain only, never arbitrary pre-operation states.
No callback is serialized into action input or read from the environment.

The ledger transaction is released before calling the external operation. The
daemon retains the existing actuation lock across the full executor call;
a check does not reserve capacity against a separate uncoordinated writer.
Daemon epoch binding, Linux cross-boot adapter and one-time legacy KV migration
are now wired in the isolated candidate, still requiring independent review. All malformed persisted timing rows
are validated before any expiry prune or boot reanchor; shape mismatch at install
refuses rather than adopting an older candidate namespace.

## Daemon bridge

The four actions are openclaw.gateway.restart, hermes.gateway.restart,
openclaw.session.reset and hermes.profile.lifecycle. Other actions do not call
this clock adapter. Existing policy durations remain authoritative: restart
cooldown and restart window, session-reset cooldown, and lifecycle cooldown.
Hermes cooldown is per profile; its storm counter is global across profiles.
Lifecycle scope includes profile plus targetMode. Session scopes use only the
existing key digest; no private session content enters this namespace.

Linux sampling uses /proc/sys/kernel/random/boot_id, CLOCK_BOOTTIME and wall time.
There is no fallback to wall-only or process-relative synthetic boot identity.
Candidate trusted constants are tolerance=2000ms, stable recovery=60000ms and
max 4096 hot scopes/history items. These are not configurable by action payload
or environment. 2s is intended to exceed ordinary syscall/slew noise and 60s to
require observed stable progress, not to change existing action windows. Their
production choice is explicitly pending review; no NTP trust claim is made.

Existing KV timestamps/history are conservatively imported once without giving
credit for their apparent wall age. Only recognized finite key families enter
timing scope; planned-state metadata is not a member/timing registry. Invalid
recognized records or excessive legacy size refuse migration and all four time
based effects, while time-independent governance continues. The migration
complete marker, namespace anchors and imports commit together. Bounded legacy
mirror arrays remain compatibility/display evidence, never timing authority.

Policy projection owns a short FULL transaction then restores a caller's NORMAL
setting; if a caller already owns a non-FULL transaction it does not change the
setting or commit caller data and reports unavailable. Clock checks during the
actual executor use its existing WAL/FULL ledger handle. Unavailable/quarantined
projection is explicitly reported in clockDiscipline; legacy candidate flags are
never authority to skip actual timing checks. After wall recovery the healthy
projection uses monotonic deadlines, so a future legacy wall timestamp cannot
keep a repaired host's mechanical governance permanently disabled.

run_once and standalone governed entry share governed_actuation_context and the
same existing lock file. Reuse requires matching pid, thread identity and
canonical lock path; copied context in another thread or inherited process
cannot bypass locking. A real effect fixture attempts a second flock while the
operation runs and confirms it is denied. Capacity preflight remains protected
by that existing exclusive actuation lock through operation and terminal commit.

Complete confirmed commands update monotonic cooldown/history AND legacy mirrors
in the same terminal ledger transaction even when health verification is failed
or unknown. Hibernate planned-state evidence is written only on succeeded health
verification, in that same transaction. The old operation/postcheck db_set calls
which committed timing state early are removed. Terminal persistence failure
leaves the durable executing claim and does not repeat the effect on replay.

Focused old session/protection/idempotency fixtures now declare a synthetic
Linux clock, install the previously absent daemon KV table, and use an isolated
lock path. They still execute the actual clock/core/ledger/actuator wrappers;
assertions inspect committed KV receipts instead of requiring the removed early
commit helper calls. They do not qualify actual live installations.
