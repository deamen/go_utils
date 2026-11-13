#!/usr/bin/env bash
# v2. Checks that claude runs inside a systemd unit with a token from a root-only file.
# Run as root:  ./check-agent-token.sh [agent-user] [other-user]
# Reuses /etc/ochell-agent.env if it exists; REPLACE=1 asks for a new token.
# Optional: CLAUDE_BIN=/full/path/to/claude  AGENT_ENV_FILE=...  KEEP=0 (delete the file afterwards)
set -u
AGENT=${1:-sxt}
OTHER=${2:-sps}
ENVF=${AGENT_ENV_FILE:-/etc/ochell-agent.env}
P="ochell-tok-$$"
pass=0; fail=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1"; [ -n "${2:-}" ] && echo "      got: $2"; fail=$((fail+1)); }
info() { echo "INFO  $1"; }

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
id "$AGENT" >/dev/null 2>&1 || { echo "no such user: $AGENT"; exit 2; }
id "$OTHER" >/dev/null 2>&1 || { echo "no such user: $OTHER"; exit 2; }

BIN=${CLAUDE_BIN:-$(runuser -l "$AGENT" -c 'command -v claude' 2>/dev/null | tail -1)}
[ -n "$BIN" ] || { echo "cannot find claude for $AGENT; set CLAUDE_BIN=/full/path/to/claude"; exit 2; }
info "claude binary: $BIN -> $(readlink -f "$BIN")"

CFG=$(mktemp -d /tmp/ochell-tok.XXXXXX); chown "$AGENT" "$CFG"
cleanup() { systemctl stop "$P-s" 2>/dev/null; rm -rf "$CFG"; [ "${KEEP:-1}" = 0 ] && rm -f "$ENVF"; }
trap cleanup EXIT
unit() {  # unit <name> <systemd-run options...> -- <command...>
  local name=$1; shift
  systemd-run --uid="$AGENT" --collect --quiet --wait --pipe --unit="$name" \
    --working-directory="$CFG" --setenv=CLAUDE_CONFIG_DIR="$CFG" "$@" 2>&1
}

# 0. can systemd execute the binary at all (exit 203 means it cannot)
LAUNCH=("$BIN")
out=$(unit "$P-v1" "$BIN" --version </dev/null); rc=$?
if [ $rc = 0 ]; then
  ok "0 systemd can execute claude directly ($out)"
else
  info "0 direct execution failed with exit $rc (203 = systemd could not execute the file)"
  info "0 SELinux mode: $(getenforce 2>/dev/null || echo unknown)"
  info "0 label: $(ls -Z "$(readlink -f "$BIN")" 2>/dev/null)"
  journalctl -u "$P-v1" -n 4 --no-pager -o cat 2>/dev/null | sed 's/^/      journal: /'
  command -v ausearch >/dev/null && ausearch -m avc -ts recent 2>/dev/null | grep -i denied | tail -3 | sed 's/^/      avc: /'
  out=$(unit "$P-v2" /usr/bin/env "$BIN" --version </dev/null); rc=$?
  if [ $rc = 0 ]; then
    ok "0 systemd can execute claude through /usr/bin/env ($out)"
    LAUNCH=(/usr/bin/env "$BIN")
  else
    bad "0 systemd cannot execute claude, directly or through /usr/bin/env" "exit $rc: $out"
    journalctl -u "$P-v2" -n 4 --no-pager -o cat 2>/dev/null | sed 's/^/      journal: /'
    echo; echo "passed $pass, failed $fail"; exit 1
  fi
fi

# token: reuse the file, or ask without echo
if [ -s "$ENVF" ] && [ "${REPLACE:-0}" != 1 ]; then
  info "reusing token file $ENVF (REPLACE=1 to enter a new token)"
else
  read -rs -p "Paste the token and press Enter (it is not shown): " TOKEN; echo
  [ -n "$TOKEN" ] || { echo "empty token"; exit 2; }
  case "$TOKEN" in
    sk-ant-api*) VAR=${TOKEN_VAR:-ANTHROPIC_API_KEY} ;;
    *)           VAR=${TOKEN_VAR:-CLAUDE_CODE_OAUTH_TOKEN} ;;
  esac
  ( umask 077; printf '%s=%s\n' "$VAR" "$TOKEN" > "$ENVF" ); chown root:root "$ENVF"; chmod 600 "$ENVF"
fi
TOKEN=$(head -1 "$ENVF" | cut -d= -f2-)
info "token variable: $(head -1 "$ENVF" | cut -d= -f1), length ${#TOKEN}"

run_agent() { local name=$1; shift; echo 'Reply with the single word: ready' | unit "$name" "$@" "${LAUNCH[@]}" -p; }

# 1. control: with an empty config directory and no token, the agent must refuse
out=$(run_agent "$P-c"); rc=$?
if [ $rc = 0 ]; then bad "1 control run succeeded without the token, so check 2 proves nothing" "$out"
elif [ $rc -ge 200 ]; then bad "1 control run did not start (exit $rc)" "$out"
else ok "1 without the token the agent refuses (exit $rc)"; fi
info "1 agent said: $(echo "$out" | head -2)"

# 2. with the token file, the run works
out=$(run_agent "$P-t" -p EnvironmentFile="$ENVF"); rc=$?
if [ $rc = 0 ]; then ok "2 agent runs in a unit with the token file"; else bad "2 agent runs in a unit with the token file" "exit $rc"; fi
info "2 agent said: $(echo "$out" | head -3)"

# 3. the token is not visible to another user
systemd-run --uid="$AGENT" --collect --quiet --unit="$P-s" -p EnvironmentFile="$ENVF" sleep 987657; sleep 1
shown=$(runuser -u "$OTHER" -- systemctl show "$P-s" 2>&1)
if echo "$shown" | grep -qF -- "$TOKEN"; then bad "3 token hidden in systemctl show"; else ok "3 token hidden in systemctl show"; fi
if runuser -u "$OTHER" -- cat "$ENVF" >/dev/null 2>&1; then bad "3 token file unreadable by $OTHER"; else ok "3 token file unreadable by $OTHER"; fi
systemctl stop "$P-s"

echo; echo "launch form that works: ${LAUNCH[*]}"
echo "passed $pass, failed $fail"
if [ "${KEEP:-1}" = 0 ]; then echo "token file will be deleted"; else echo "token file kept at $ENVF"; fi
[ $fail = 0 ]
