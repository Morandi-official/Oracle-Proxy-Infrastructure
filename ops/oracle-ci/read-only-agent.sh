#!/usr/bin/env bash
# Non-root, read-only diagnostics. Does not change system or network state.
set -euo pipefail
[[ "$(id -un)" == oracle-ci ]] || { echo 'AGENT_ERROR=unexpected_user' >&2; exit 2; }
echo ORACLE_READONLY_AGENT=OK
if systemctl is-active --quiet wg-quick@wg0; then
  echo WG0_SERVICE=ACTIVE
else
  echo WG0_SERVICE=INACTIVE
fi
if ip link show wg0 >/dev/null 2>&1; then
  echo WG0_INTERFACE=PRESENT
else
  echo WG0_INTERFACE=ABSENT
fi
if ss -Hlun 'sport = :51820' | grep -q .; then
  echo UDP51820=LISTENING
else
  echo UDP51820=NOT_LISTENING
fi
