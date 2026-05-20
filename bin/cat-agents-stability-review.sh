#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="/home/flashcat/cat-agents-stabilityd/reports"
STAMP="$(date '+%Y%m%dT%H%M%S%z')"
OUT="${REPORT_DIR}/stability-review-${STAMP}.txt"

mkdir -p "${REPORT_DIR}"

{
  echo "# Cat Agents Stability Review"
  echo
  echo "GeneratedAt: $(date '+%Y-%m-%d %H:%M:%S %Z %z')"
  echo "Host: $(hostname)"
  echo

  echo "## Stability Status"
  /home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability status || true
  echo

  echo "## Policy"
  /home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability policy || true
  echo

  echo "## Findings"
  /home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability findings || true
  echo

  echo "## Recent Actions"
  /home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability actions --limit 50 || true
  echo

  echo "## Recent Events"
  /home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability events || true
  echo

  echo "## Runbook"
  /home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability runbook || true
  echo

  echo "## Systemd Units"
  systemctl --no-pager status cat-agents-stabilityd.service openclaw-gateway.service openclaw-gateway-watchdog.service openclaw-cron-guard.timer openclaw-session-guard.timer openclaw-health-controller.timer || true
  echo

  echo "## OpenClaw Timers"
  systemctl --no-pager list-timers --all | grep -E 'openclaw|stability' || true
  echo

  echo "## User Crontab"
  crontab -l 2>&1 || true
  echo

  echo "## Stabilityd Journal Tail"
  journalctl -u cat-agents-stabilityd.service --since '24 hours ago' --no-pager -n 200 || true
} > "${OUT}"

echo "${OUT}"

