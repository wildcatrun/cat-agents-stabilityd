#!/bin/zsh
set -euo pipefail

exec /Users/Flashcat/cat-agents-stabilityd/bin/cat-agents-stability auth-maintenance-local "$@"
