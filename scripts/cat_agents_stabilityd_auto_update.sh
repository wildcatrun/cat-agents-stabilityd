#!/usr/bin/env bash
set -euo pipefail

CHECKOUT="${CAT_AGENTS_STABILITYD_CHECKOUT:-/home/flashcat/cat-agents-stabilityd.git-checkout}"
REMOTE="${CAT_AGENTS_STABILITYD_REMOTE:-origin}"
BRANCH="${CAT_AGENTS_STABILITYD_BRANCH:-main}"
SERVICE="${CAT_AGENTS_STABILITYD_SERVICE:-cat-agents-stabilityd.service}"
WORK_ROOT="${CAT_AGENTS_STABILITYD_UPDATE_WORK_ROOT:-/home/flashcat/multi-agent-hedge-fund-framework/ops-artifacts/codex-working/cat-agents-stabilityd-auto-update}"
RUN_USER="${CAT_AGENTS_STABILITYD_RUN_USER:-flashcat}"
RUN_GROUP="${CAT_AGENTS_STABILITYD_RUN_GROUP:-flashcat}"
LOCK_PATH="${CAT_AGENTS_STABILITYD_UPDATE_LOCK:-/run/lock/cat-agents-stabilityd-auto-update.lock}"
LATEST_PATH="${CAT_AGENTS_STABILITYD_LATEST_PATH:-/home/flashcat/.openclaw/stability/latest.json}"

install -d -o "${RUN_USER}" -g "${RUN_GROUP}" -m 0755 "${WORK_ROOT}/logs" "${WORK_ROOT}/worktrees"
stamp="$(date +%Y%m%dT%H%M%S%z)"
log_path="${WORK_ROOT}/logs/update-${stamp}.log"

log() {
  printf '%s %s\n' "$(date --iso-8601=seconds)" "$*" | tee -a "${log_path}"
}

exec 9>"${LOCK_PATH}"
if ! flock -n 9; then
  log "another auto-update run holds ${LOCK_PATH}; skipping"
  exit 0
fi

as_run_user() {
  runuser -u "${RUN_USER}" -- "$@"
}

wait_service_ready() {
  local min_epoch="$1"
  for _ in {1..20}; do
    if systemctl is-active --quiet "${SERVICE}" && as_run_user "${CHECKOUT}/bin/cat-agents-stability" status >>"${log_path}" 2>&1; then
      if python3 - "${LATEST_PATH}" "${min_epoch}" >>"${log_path}" 2>&1 <<'PY'
import json
import sys
import time

path = sys.argv[1]
min_epoch = int(sys.argv[2])
now = int(time.time())
with open(path, "r", encoding="utf-8") as fh:
    snapshot = json.load(fh)
completed = int(snapshot.get("completedAtEpoch") or 0)
policy = snapshot.get("policy") if isinstance(snapshot.get("policy"), dict) else {}
valid_until = int(policy.get("validUntilEpoch") or 0)
ok = (
    snapshot.get("schemaVersion") == 1
    and completed >= min_epoch
    and valid_until >= now
    and isinstance(snapshot.get("findings"), list)
)
print(json.dumps({
    "ready": ok,
    "completedAtEpoch": completed,
    "minEpoch": min_epoch,
    "validUntilEpoch": valid_until,
    "now": now,
    "severity": snapshot.get("severity"),
    "mode": policy.get("mode"),
    "findingCount": len(snapshot.get("findings") or []),
}, ensure_ascii=False))
raise SystemExit(0 if ok else 1)
PY
      then
        return 0
      fi
    fi
    sleep 3
  done
  return 1
}

cleanup_worktree() {
  if [[ -n "${worktree_path:-}" && -d "${worktree_path}" ]]; then
    as_run_user git -C "${CHECKOUT}" worktree remove --force "${worktree_path}" >/dev/null 2>&1 || true
  fi
}
trap cleanup_worktree EXIT

if [[ ! -d "${CHECKOUT}/.git" ]]; then
  log "checkout missing or not a git repository: ${CHECKOUT}"
  exit 2
fi

cd "${CHECKOUT}"

branch_name="$(as_run_user git -C "${CHECKOUT}" symbolic-ref --quiet --short HEAD || true)"
if [[ "${branch_name}" != "${BRANCH}" ]]; then
  log "checkout is not on ${BRANCH}; current=${branch_name:-detached}; refusing automatic update"
  exit 5
fi

if ! as_run_user git -C "${CHECKOUT}" diff --quiet || ! as_run_user git -C "${CHECKOUT}" diff --cached --quiet; then
  log "tracked working tree is dirty; refusing automatic update"
  as_run_user git -C "${CHECKOUT}" status --short | tee -a "${log_path}"
  exit 3
fi

log "fetching ${REMOTE} ${BRANCH}"
as_run_user git -C "${CHECKOUT}" fetch --prune "${REMOTE}" "${BRANCH}" >>"${log_path}" 2>&1

current="$(as_run_user git -C "${CHECKOUT}" rev-parse HEAD)"
target="$(as_run_user git -C "${CHECKOUT}" rev-parse "${REMOTE}/${BRANCH}")"
log "current=${current} target=${target}"

if [[ "${current}" == "${target}" ]]; then
  log "already up to date"
  exit 0
fi

base="$(as_run_user git -C "${CHECKOUT}" merge-base HEAD "${target}")"
if [[ "${base}" != "${current}" ]]; then
  log "remote is not a fast-forward from current HEAD; refusing automatic update"
  exit 4
fi

worktree_path="${WORK_ROOT}/worktrees/${target}"
rm -rf "${worktree_path}"
as_run_user git -C "${CHECKOUT}" worktree add --detach "${worktree_path}" "${target}" >>"${log_path}" 2>&1

log "validating target in temporary worktree"
as_run_user bash -lc "cd '${worktree_path}' && npm run check && npm run smoke:gates" >>"${log_path}" 2>&1

log "fast-forwarding active checkout to tested target ${target}"
as_run_user git -C "${CHECKOUT}" merge --ff-only "${target}" >>"${log_path}" 2>&1

log "restarting ${SERVICE}"
restart_epoch="$(date +%s)"
if ! systemctl restart "${SERVICE}" >>"${log_path}" 2>&1; then
  log "restart failed; rolling back to ${current}"
  as_run_user git -C "${CHECKOUT}" reset --hard "${current}" >>"${log_path}" 2>&1
  rollback_epoch="$(date +%s)"
  systemctl restart "${SERVICE}" >>"${log_path}" 2>&1 || true
  if wait_service_ready "${rollback_epoch}"; then
    systemctl is-active "${SERVICE}" | tee -a "${log_path}"
    log "rollback complete after restart failure"
  else
    log "rollback health check failed after restart failure"
  fi
  exit 6
fi

if wait_service_ready "${restart_epoch}"; then
  systemctl is-active "${SERVICE}" | tee -a "${log_path}"
  log "automatic update complete"
  exit 0
fi

log "post-update health check failed; rolling back to ${current}"
as_run_user git -C "${CHECKOUT}" reset --hard "${current}" >>"${log_path}" 2>&1
rollback_epoch="$(date +%s)"
systemctl restart "${SERVICE}" >>"${log_path}" 2>&1 || true
if wait_service_ready "${rollback_epoch}"; then
  systemctl is-active "${SERVICE}" | tee -a "${log_path}"
  log "rollback complete"
  exit 7
fi
log "rollback health check failed"
exit 8
