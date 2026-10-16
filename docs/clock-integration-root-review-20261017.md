# V18 integration review

Candidate only; no installation, release, live configuration or service change.

Root reviewed the daemon diff, the two clock modules, executor/ledger hooks and
the V2 replay boundary. Independent boundary review found no remaining confirmed
blocking defect after the following corrections:

- Move clock metadata from the unrelated profile inventory return to the actual
  policy. The former referenced an undefined local; direct empty-inventory
  regression now exercises the real function.
- Require the policy's available clock epoch and execution-fence marker at both
  actual execution checks. Capturing a new epoch only at the first executor
  check would allow stale policy evidence across recovery. Missing/old epochs
  now block; historical receipts still require no fresh authority.

The actual bridge suite now has fourteen tests, passing normal and optimized.
It includes a confirmed effect followed by a wall jump during postcheck:
terminal/timing writes roll back, previous timing records remain unchanged, the
durable ledger stays executing, and historical replay cannot repeat the effect.
This is failure evidence requiring reconciliation, not an asserted success.

The fixed candidate values are reviewed as follows: 2000ms is an anomaly detector
tolerance, never wall-time credit against a monotonic deadline; 60000ms is a
stable-recovery interval producing a new epoch, never authority for an old
policy; 4096 is an explicit hot-record capacity with refusal rather than silent
eviction. Existing action cooldown/window durations remain unchanged. These
choices do not establish deployment resource/SLO approval: final Linux resource,
performance and installation qualification remain separate existing gates.

The V22 observer, log-failure and multinode fixtures are integrated into this
candidate. Root's nine-module clock/progress run passed 46 tests in each mode;
raw logs and hashes are in the G2 dossier's
`logs/clock-integration-root-20261017.json`. Separate legacy leaf fixtures passed
61 tests per mode, using real synthetic-clock observations before policy digest
construction, without mocking the production timing check.

These results are focused integration evidence. V18/V22 final acceptance still
requires the final committed-source Linux qualification. Old candidate results
are not inherited by the modified source.
