# Codex managed-package idle pool hotfix

This narrowly scoped resource patch targets the deployed `@openclaw/codex` 2026.9.7 compiled layout. It adds in-process, unreferenced housekeeping and uses the plugin's existing graceful retirement. It does not alter workflow, credentials, model routing, task prompts, Hermes policy, or runtime member scope.

`scripts/patch_codex_idle_pool.py` is dry-run by default and checks exact SHA-256 source hashes before generating or applying changes. Original files and a manifest are saved in the caller's timestamped ops artifact. Repeated application or unknown code fails without writing. The repository owns the patch source; the installed npm package remains upstream-owned. A package upgrade can replace the overlay: inspect and rebase the hotfix against that version rather than automatically applying it to unknown code.

Only local stdio clients with zero active leases/acquires, known empty runtime ownership maps, no outgoing/incoming RPC or unfinished decoding, no durable runtime-artifact binding, and no observed native execution are eligible. Unknown state blocks reclamation. Existing retained/adopted threads and native child work retain continuity.

Defaults: 5-minute idle TTL, 8 eligible idle clients per process, 60-second new-client grace, 30-second unreferenced sweep. The cap concerns idle unbound cache entries, not active task concurrency or all Codex processes. `OPENCLAW_CODEX_POOL_IDLE_TTL_MS=0` disables housekeeping; `OPENCLAW_CODEX_POOL_MAX_IDLE` changes the eligible cache budget. Counts, reasons, and launcher PIDs are logged without cache keys, arguments, credentials, thread IDs, or prompts.

Apply after successful tests, current-state checks, and a controlled Gateway reload window:

```sh
python3 scripts/patch_codex_idle_pool.py --setup-dir <managed-package>/dist/.setup --artifact-dir <task>/codex-patch --apply
```

Restore with the same script and artifact directory using `--rollback`, then reload the Gateway. Rollback verifies both backup and live patched hashes before writing; divergent live code is preserved for manual review. Do not use SIGUSR1 to attach a debugger to this Gateway.

Validation: `node scripts/test_codex_idle_pool.mjs`, generated candidate module syntax checks, and `node scripts/test_codex_pool_integration.mjs <candidate-directory>` exercise guarded eviction and the real lifecycle module with fake clients. No live requests are made by these tests.
