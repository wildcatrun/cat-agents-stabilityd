# V18 clock policy replay: explicit V2 compatibility boundary

The current offline policy gate is selected by
`tests/fixtures/compat/policy_replay_gate_v2.json`, schemaVersion 2 and
currentGate `clock-policy-scope-v2`. Unknown selectors refuse evaluation. Run
`PYTHONPATH=tests/stability_next python3 -m unittest test_current_policy_shadow test_clock_policy_v2`
and the same command with `python3 -O`. No test is skipped and no deployment is
triggered by these commands.

V1 remains historical evidence. Its original JSON fixture, original baseline and
candidate commit identities, source/function pins and all 203 scenarios are
unchanged. The original test explicitly supplies the historical candidate source
read from its original pinned commit, and still requires full policy/gate equality
except its four previously reviewed visibility extensions. V1 is not repinned to
the new policy or mislabeled as proof of unchanged current timing behavior.

V2 adds only one selected-function global dependency,
`mechanical_timing_projection`, as a trusted synthetic stub; and one policy field,
`clockDiscipline`. Its whole candidate source and each selected policy function
are separately pinned in `clock_policy_scope_v2.json`. The selected-function
loader refuses any other new global, changed source/function, decorator or
executable default. Module imports/body, collectors, runtime helpers and actuators
are never evaluated. Candidate pins identify a reviewable snapshot; a later
necessary source correction must fail this gate until its new V2 pin is explicitly
reviewed. This never changes V1 pins.

For each of the original 203 cases, V2 evaluates two independent clock scopes:

* Unavailable projection: the entire new policy, after removing the exact expected
  `clockDiscipline` field, plus its repair gate must equal the entire old pinned
  candidate output for the original case.
* Available projection with empty monotonic windows/history: the old pinned
  policy oracle receives the same independent case, with only the two legacy last
  restart timestamps and the two restart histories cleared. The entire candidate
  policy and repair gate must equal this oracle. There is no allowlist of changed
  output fields or nested protection exceptions.

Eight explicit OpenClaw phase snapshots add before-expiry, forward wall jump, backward
wall jump, recovery with a new epoch, monotonic expiry, backward recovery while a
legacy timestamp remains in the future, quarantine and restart-storm cases. For
healthy nonempty projection, the independent old policy oracle receives only the
mathematically equivalent remaining cooldown/history wall inputs. Assertions also
check the original wall-only candidate's decision: forward jump would permit a
restart early, and backward wall can continue to block after actual monotonic
expiry. The new outputs must differ in the required direction. These are pure
policy phase snapshots, not a claim that this replay proves temporal sampling or
actual side effects; the actual daemon/clock bridge fixtures cover those paths.

Two further Hermes phases derive profile names only from two explicit synthetic
runtime_agents rows. One profile has a nonzero monotonic cooldown; only the other
remains a restart candidate. The reference old-policy oracle clears the legacy
global last-restart timestamp, removes only the blocked profile from its input
snapshot and receives the equivalent global restart history. Full outputs must
match exactly. With one global restart there is remaining budget; with three,
the global storm gate blocks the otherwise eligible profile. No output field
wildcard or special protection allowance is used. Total V2 evaluations are 416.

An unavailable policy can retain a legacy *candidate* restart flag. V2 explicitly
expects that observation and `clockDiscipline.state=unavailable-or-quarantined`,
with no usable epoch. Neither available metadata nor a candidate flag is an
execution grant. Actual four time-dependent effects require matching fresh epoch
at both execution checks plus all existing authorization/protection/installation
gates. Historical receipts remain receipt lookups without new authority.

Negative tests mutate unrelated session/lease permissions, protected session
keys, nested cron lane state, repair gate, added execution authority and clock
metadata; all must be rejected by complete output equality. Source/function and
new-global mutation tests also fail closed. The V1 fixture digest is pinned by
V2, so modifying its scenario/pin evidence cannot silently satisfy the new gate.

This gate qualifies only the declared offline policy boundary. It does not
qualify Linux installation permissions, live readiness, clock constant values,
collector execution, durable action recovery or service activation. Independent
source review and the final Linux suite remain required.

The fixed 2s anomaly tolerance, 60s stable recovery and 4096 hot-row budget have
been reviewed as G2 candidate constants: tolerance supplies no wall-time cooldown
credit, recovery mints a new epoch which old policies cannot use, and quota failure
keeps unrelated governance available. Final installation/performance qualification
remains the existing Linux gate, not a request for an additional SLO programme.
