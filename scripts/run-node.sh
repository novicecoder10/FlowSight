#!/usr/bin/env bash
# FlowSight needs Node >= 22.5 for node:sqlite. The failure mode on an older runtime is
# ERR_UNKNOWN_BUILTIN_MODULE, which reads like a missing package rather than a version
# problem, so select a suitable runtime here instead of relying on the caller's shell.
set -euo pipefail

REQUIRED_MAJOR=22
REQUIRED_MINOR=5

version_ok() {
  local v major minor
  v="$("$1" -p 'process.versions.node' 2>/dev/null)" || return 1
  major="${v%%.*}"; minor="${v#*.}"; minor="${minor%%.*}"
  [ "$major" -gt "$REQUIRED_MAJOR" ] && return 0
  [ "$major" -eq "$REQUIRED_MAJOR" ] && [ "$minor" -ge "$REQUIRED_MINOR" ]
}

if version_ok node; then
  exec node "$@"
fi

# Try nvm, non-interactively.
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
if [ -s "$NVM_DIR/nvm.sh" ]; then
  # shellcheck disable=SC1091
  . "$NVM_DIR/nvm.sh" >/dev/null 2>&1
  nvm use >/dev/null 2>&1 || nvm use "$REQUIRED_MAJOR" >/dev/null 2>&1 || true
  if version_ok node; then
    exec node "$@"
  fi
fi

# Fall back to any suitable nvm-installed binary without switching the shell.
if [ -d "$NVM_DIR/versions/node" ]; then
  for candidate in $(ls -1 "$NVM_DIR/versions/node" 2>/dev/null | sort -Vr); do
    bin="$NVM_DIR/versions/node/$candidate/bin/node"
    if [ -x "$bin" ] && version_ok "$bin"; then
      exec "$bin" "$@"
    fi
  done
fi

current="$(node -p 'process.versions.node' 2>/dev/null || echo 'not found')"
cat >&2 <<MSG
FlowSight requires Node >= ${REQUIRED_MAJOR}.${REQUIRED_MINOR} (node:sqlite); found ${current}.

Install it with:
  nvm install ${REQUIRED_MAJOR}     # then re-run, no 'nvm use' needed
MSG
exit 1
