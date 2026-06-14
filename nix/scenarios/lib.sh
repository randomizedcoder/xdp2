# Shared bash helpers for the netconf-<scenario> writeShellApplications.
# Sourced verbatim via builtins.readFile from each scenario's Nix file.
#
# Contract:
# - The hosting writeShellApplication is invoked with `set -euo pipefail`
#   (writeShellApplication default), so helpers must be set -u safe.
# - SSH/log writes go to stderr; emit_env writes to stdout so callers
#   can `eval $(nix run .#netconf-<scenario> up 2>/dev/null)` to ingest
#   the resulting addresses/interfaces.

SSH() {
  ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 "$@"
}

ts() {
  date -u +%FT%TZ
}

log() {
  echo "$(ts) [scenario] $*" >&2
}

# Validate a list of env var names are all non-empty. Exit 64 on any miss.
require_env() {
  local missing=()
  local var
  for var in "$@"; do
    if [ -z "${!var:-}" ]; then
      missing+=("$var")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "ERROR: required env vars unset: ${missing[*]}" >&2
    exit 64
  fi
}

require_op() {
  case "${OP:-}" in
    up|down|verify) : ;;
    *)
      echo "ERROR: OP must be one of: up | down | verify (got '${OP:-<unset>}')" >&2
      exit 64
      ;;
  esac
}

# Print KEY=VALUE on stdout; orchestrator captures these.
emit_env() {
  printf '%s=%s\n' "$1" "$2"
}

# Best-effort cleanup on partial-up failure. Each scenario can override
# by re-defining cleanup_partial after sourcing this file. The default
# is a no-op; the scenario's `up` should set this to a function that
# tears down whatever it managed to create before the error.
cleanup_partial() {
  :
}
