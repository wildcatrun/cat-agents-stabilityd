# Daemon inspection resource reduction

The 30-second governance loop and current cron/session/worker/profile/repair decisions remain unchanged. Only successful low-frequency CLI observations are cached in the daemon's process memory: OpenClaw version (900 seconds), healthy Gateway deep status (120 seconds), and plugin metadata (300 seconds). One-shot CLI/MCP diagnostics remain fresh.

The cache records `inspectionCache.checkedAtEpoch`, age, TTL, and whether a response was reused. A changed Gateway PID, configuration/file revision, or unhealthy current service/TCP/HTTP health bypasses deep/plugin caches. Failed refreshes discard the prior success; real failed connectivity and plugin errors are not retained. The already-classified `0.0.0.0` plaintext refusal may be reused only when the current runtime is independently healthy. Cron CLI status/list and repair evidence are not cached by this change.

Environment controls: `CAT_AGENTS_STABILITY_VERSION_PROBE_TTL_SECONDS`, `CAT_AGENTS_STABILITY_DEEP_PROBE_TTL_SECONDS`, `CAT_AGENTS_STABILITY_PLUGINS_PROBE_TTL_SECONDS`. Set each to zero to restore fresh probes. Default daemon mode is enabled by entering `daemon_loop`; there is no new service, timer, or persistent credential cache. Restart only stabilityd to load changed settings or code.

Tests: `python3 scripts/test_inspection_cache.py` and `python3 scripts/smoke_policy_gates.py`. Operational verification should compare scan cadence and cache metadata, cgroup CPU and sampled memory peaks, health/cron freshness, and repair policy before and after deployment. Short performance samples should be reported as samples rather than guarantees.
