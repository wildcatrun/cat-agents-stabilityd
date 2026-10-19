# Hermes v0.22.2 installation binding

This deployment adapts the accepted stabilityd candidate to the official single-host Hermes Gateway at fixed release `d923a5eb487a17c0a68801bba9ef0f56c81040a8`, running Python 3.14.7. Targets come from the authoritative workflow `runtime_agents` registry; the installation declaration is not another member registry.

The packaged installation binds 18 reviewed source/metadata files, the official launcher command, host socket/peer identity, PM selected environment, dependency facts and its successful sync receipt. Bootstrap recovery/install/process/network side effects are refused during imports. A dependency or source generation change requires deliberate requalification, rather than automatic approval of measured hashes. The finite pinned loader imports its standard-library spec constructor before installing the finder, including on cold Python 3.14 entry.

The daemon uses the existing `control-3.14.7` environment with PyYAML 6.0.3. Hermes dependencies remain owned by official PM. The bridge is a one-shot SDK adapter, not a resident worker or independent message channel. Qualification never substitutes for policy, protected-member checks, action ledger, cooldown or post-check.

Deployment proceeds through the candidate Git branch and a fixed server commit. Stop the old writer before cutover and preserve a consistent stabilityd state backup. Retain current ledger/WAL and any later effects during recovery; do not overwrite them with an old snapshot or resume the old writer against the new state. Remove the temporary Hermes maintenance override only after actual installation qualification. Existing configured opt-ins, protection and allowlists remain authoritative; removal of a temporary override does not enable a previously disabled actuator.

OAuth mirror does not back up auth files, tokens or agent databases. Reauthorization is its recovery path. Normal code/configuration and stabilityd business-state upgrade recovery points are separate.

Operational provenance and finite acceptance evidence are maintained in `stability-governance/stabilityd-next/2026-10-19-hermes-upgrade/` in the unified framework repository. This file describes the deployment contract; it does not claim that an unexecuted deployment has passed.
