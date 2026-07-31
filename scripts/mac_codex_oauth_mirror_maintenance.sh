#!/bin/zsh
set -euo pipefail

ROOT="/Users/Flashcat/cat-agents-stabilityd"
CLI="$ROOT/bin/cat-agents-stability"
SERVER="flashcat@106.54.53.146"
SSH_KEY="/Users/Flashcat/.ssh/openclaw_server"
REMOTE_CLI="/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability"
LOG_DIR="$ROOT/reports/auth-mirror"
LOCK_DIR="$LOG_DIR/.lock"

mkdir -p "$LOG_DIR"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
plan_file="$LOG_DIR/$stamp-plan.json"
mirror_file="$LOG_DIR/$stamp-mirror.json"
latest_file="$LOG_DIR/latest.json"

ssh -i "$SSH_KEY" -o BatchMode=yes "$SERVER" "$REMOTE_CLI auth-maintenance --fresh" >"$plan_file"

mirror_action_count="$(python3 - "$plan_file" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
count = 0
for item in data.get("actions") or []:
    if not isinstance(item, dict) or item.get("humanGateRequired"):
        continue
    action_id = str(item.get("actionId") or "")
    kind = str(item.get("kind") or "")
    if action_id == "codex_cli_mirror_required" or action_id.startswith("hermers_"):
        if kind in {"mirror-from-mac-codex", "sync-or-refresh"}:
            count += 1
print(count)
PY
)"

if [[ "$mirror_action_count" -le 0 ]]; then
  python3 - "$plan_file" "$latest_file" <<'PY'
import json, sys, datetime as dt
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    plan = json.load(fh)
summary = {
    "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "status": "no-actions",
    "remotePlan": sys.argv[1],
    "remoteStatus": plan.get("status"),
    "remoteSeverity": plan.get("severity"),
    "actionCount": plan.get("actionCount"),
    "mirrorActionCount": 0,
    "tokenValuesRedacted": True,
}
with open(sys.argv[2], "w", encoding="utf-8") as fh:
    json.dump(summary, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
print(json.dumps(summary, ensure_ascii=False))
PY
  exit 0
fi

"$CLI" auth-mirror --apply >"$mirror_file"

python3 - "$plan_file" "$mirror_file" "$latest_file" <<'PY'
import json, sys, datetime as dt
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    plan = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    mirror = json.load(fh)
summary = {
    "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "status": mirror.get("result"),
    "remotePlan": sys.argv[1],
    "mirrorResult": sys.argv[2],
    "remoteStatus": plan.get("status"),
    "remoteSeverity": plan.get("severity"),
    "actionCount": plan.get("actionCount"),
    "mirrorActionCount": sum(
        1
        for item in plan.get("actions") or []
        if isinstance(item, dict)
        and not item.get("humanGateRequired")
        and (
            item.get("actionId") == "codex_cli_mirror_required"
            or str(item.get("actionId") or "").startswith("hermers_")
        )
        and item.get("kind") in {"mirror-from-mac-codex", "sync-or-refresh"}
    ),
    "mirrorSummary": mirror.get("summary"),
    "tokenValuesRedacted": True,
}
with open(sys.argv[3], "w", encoding="utf-8") as fh:
    json.dump(summary, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
print(json.dumps(summary, ensure_ascii=False))
PY
