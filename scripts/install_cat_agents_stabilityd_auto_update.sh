#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:-/home/flashcat/cat-agents-stabilityd.git-checkout}"

install -o root -g root -m 0755 \
  "${REPO_ROOT}/scripts/cat_agents_stabilityd_auto_update.sh" \
  /usr/local/sbin/cat-agents-stabilityd-auto-update

install -o root -g root -m 0644 \
  "${REPO_ROOT}/systemd/cat-agents-stabilityd-update.service" \
  /etc/systemd/system/cat-agents-stabilityd-update.service

install -o root -g root -m 0644 \
  "${REPO_ROOT}/systemd/cat-agents-stabilityd-update.timer" \
  /etc/systemd/system/cat-agents-stabilityd-update.timer

systemctl daemon-reload
systemctl enable --now cat-agents-stabilityd-update.timer
systemctl list-timers --all cat-agents-stabilityd-update.timer --no-pager
