// Managed-package resource hotfix. Contains no auth, routing, or task semantics.
import { performance } from 'node:perf_hooks';

function setting(name, fallback, minimum) {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number(raw);
  return Number.isSafeInteger(value) && value >= minimum ? value : fallback;
}
export const idlePoolPolicy = Object.freeze({
  ttlMs: setting('OPENCLAW_CODEX_POOL_IDLE_TTL_MS', 300000, 0),
  maxIdle: setting('OPENCLAW_CODEX_POOL_MAX_IDLE', 8, 0),
  graceMs: 60000,
  sweepMs: 30000,
});

export function touchIdlePoolEntry(entry, now = performance.now()) {
  entry.poolLastUseAt = now;
}

export function inspectIdlePoolEntry(entry, now = performance.now()) {
  const row = {
    pid: Number.isSafeInteger(entry.client?.child?.pid) ? entry.client.child.pid : null,
    activeLeases: entry.activeLeases,
    pendingAcquires: entry.pendingAcquires,
    artifactBound: entry.poolArtifactBound === true,
    idleMs: Number.isFinite(entry.poolLastUseAt) ? Math.max(0, now - entry.poolLastUseAt) : null,
    safe: false,
    reason: 'ownership-unknown',
  };
  if (!entry.client || entry.closeError || entry.client.closed) return row;
  if (row.pid === null || row.pid <= 0) return { ...row, reason: 'nonlocal-transport' };
  if (!Number.isSafeInteger(entry.activeLeases) || !Number.isSafeInteger(entry.pendingAcquires) || entry.activeLeases < 0 || entry.pendingAcquires < 0) return row;
  if (entry.activeLeases || entry.pendingAcquires) return { ...row, reason: 'leased-or-acquiring' };
  if (row.artifactBound) return { ...row, reason: 'durable-artifact-binding' };
  if (typeof entry.poolIdleGuard !== 'function') return row;
  const guard = entry.poolIdleGuard();
  if (!guard || guard.safe !== true) return { ...row, reason: guard?.reason ?? row.reason };
  return { ...row, safe: row.idleMs !== null && now >= entry.poolLastUseAt, reason: 'idle-unbound' };
}

export function sweepIdlePool(state, retire, policy = idlePoolPolicy, now = performance.now()) {
  const rows = [...state.clients.values()].map(entry => ({ entry, status: inspectIdlePoolEntry(entry, now) }));
  const idle = rows.filter(row => row.status.safe).sort((a, b) => b.status.idleMs - a.status.idleMs);
  let remaining = idle.length;
  const retiredPids = [];
  let failures = 0;
  if (policy.ttlMs > 0) for (const { entry, status } of idle) {
    if (status.idleMs < policy.graceMs || (status.idleMs < policy.ttlMs && remaining <= policy.maxIdle)) continue;
    // Recheck in this synchronous turn before calling existing graceful retirement.
    if (!inspectIdlePoolEntry(entry, now).safe) continue;
    try {
      const outcome = retire(entry.client);
      if (outcome?.closed) { remaining--; retiredPids.push(status.pid); }
    } catch { failures++; }
  }
  return { clientsBefore: rows.length, clientsAfter: state.clients.size, idleUnboundBefore: idle.length, retiredPids, failures, entries: rows.map(row => row.status) };
}

export function armIdlePoolSweep(state, retire) {
  if (!idlePoolPolicy.ttlMs || state.poolSweepTimer) return;
  state.poolSweepTimer = setInterval(() => {
    if (state.clients.size === 0) {
      clearInterval(state.poolSweepTimer);
      state.poolSweepTimer = undefined;
      return;
    }
    try {
      const summary = sweepIdlePool(state, retire);
      // Whitelisted counts/reasons/PIDs only: never print keys, args, auth, or prompts.
      console.info('[codex-pool-resource]', JSON.stringify(summary));
    } catch {
      console.warn('[codex-pool-resource] inspection failed; no forced cleanup');
    }
  }, idlePoolPolicy.sweepMs);
  state.poolSweepTimer.unref?.();
}
