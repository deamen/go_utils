#!/usr/bin/env bash
# Checks that systemd transient units can run and stop an ochell agent.
# Run as root:  ./check-systemd-launcher.sh [agent-user] [other-user]
# Optional real agent run:
#   CLAUDE_BIN=/full/path/to/claude AGENT_ENV_FILE=/etc/ochell-agent.env ./check-systemd-launcher.sh sxt sps
set -u
AGENT=${1:-sxt}
OTHER=${2:-sps}
P="ochell-chk-$$"
pass=0; fail=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1"; [ -n "${2:-}" ] && echo "      got: $2"; fail=$((fail+1)); }
info() { echo "INFO  $1"; }
sr()   { systemd-run --uid="$AGENT" --collect --quiet "$@"; }

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
id "$AGENT" >/dev/null 2>&1 || { echo "no such user: $AGENT"; exit 2; }
id "$OTHER" >/dev/null 2>&1 || { echo "no such user: $OTHER"; exit 2; }
ENVF=$(mktemp /etc/ochell-chk.XXXXXX.env); chmod 600 "$ENVF"
echo 'TEST_TOKEN=dummy-secret-123' > "$ENVF"
cleanup() { rm -f "$ENVF"; systemctl stop "$P-3" "$P-4" "$P-7" 2>/dev/null; }
trap cleanup EXIT
echo "systemd $(systemctl --version | head -1 | awk '{print $2}'), agent user $AGENT, other user $OTHER"

# 1. start, stdin, stdout, exit code
out=$(echo hello | sr --wait --pipe sh -c 'id -un; cat; exit 7'); rc=$?
[ "$out" = "$AGENT"$'\n'hello ] && [ $rc = 7 ] && ok "1 start, stdin, stdout, exit code" || bad "1 start, stdin, stdout, exit code" "rc=$rc out=$out"

# 2. clean environment
out=$(SECRET=leak sr --wait --pipe --setenv=ORCH_TASK_KEY=T-1 env </dev/null)
if echo "$out" | grep -q '^ORCH_TASK_KEY=T-1$' && ! echo "$out" | grep -q SECRET; then ok "2 clean environment"; else bad "2 clean environment" "$out"; fi
info "2 PATH in unit: $(echo "$out" | sed -n 's/^PATH=//p')"

# 3. stop kills all children, including one that leaves the process group
sr --unit="$P-3" sh -c 'setsid sleep 987654 & sleep 987654'; sleep 1
n=$(pgrep -u "$AGENT" -f '^sleep 987654$' | wc -l)
systemctl stop "$P-3"; sleep 1
m=$(pgrep -u "$AGENT" -f '^sleep 987654$' | wc -l)
[ "$n" = 2 ] && [ "$m" = 0 ] && ok "3 stop kills all children" || bad "3 stop kills all children" "before=$n after=$m"

# 4. stop while attached: which exit code does the caller see
sr --unit="$P-4" --wait --pipe sleep 987655 </dev/null & pid=$!
sleep 2; systemctl stop "$P-4"; wait $pid; rc=$?
info "4 exit code seen after systemctl stop: $rc (0 means ochell cannot use the exit code to detect a stop)"

# 5. unit time limit
s=$(date +%s); sr --wait --pipe -p RuntimeMaxSec=3 sleep 100 </dev/null; rc=$?; e=$(( $(date +%s) - s ))
[ $e -lt 10 ] && ok "5 unit time limit stops the run after ${e}s" || bad "5 unit time limit" "took ${e}s"
info "5 exit code seen after time limit: $rc"

# 6. a secret from a root-only file reaches the unit
out=$(sr --wait --pipe -p EnvironmentFile="$ENVF" printenv TEST_TOKEN </dev/null)
[ "$out" = dummy-secret-123 ] && ok "6 secret from EnvironmentFile reaches the unit" || bad "6 secret from EnvironmentFile reaches the unit" "$out"

# 7. the secret is not visible to another user
sr --unit="$P-7" -p EnvironmentFile="$ENVF" --setenv=ORCH_TASK_KEY=T-1 sleep 987656; sleep 1
shown=$(runuser -u "$OTHER" -- systemctl show "$P-7" -p Environment -p EnvironmentFiles 2>&1)
if echo "$shown" | grep -q dummy-secret; then bad "7 secret hidden in systemctl show" "$shown"; else ok "7 secret hidden in systemctl show"; fi
echo "$shown" | grep -q 'ORCH_TASK_KEY=T-1' && info "7 values set with --setenv ARE visible to other users, as expected"
if runuser -u "$OTHER" -- cat "$ENVF" >/dev/null 2>&1; then bad "7 env file unreadable by $OTHER"; else ok "7 env file unreadable by $OTHER"; fi
if runuser -u "$OTHER" -- cat "/proc/$(systemctl show "$P-7" -p MainPID --value)/environ" >/dev/null 2>&1; then bad "7 process environment unreadable by $OTHER"; else ok "7 process environment unreadable by $OTHER"; fi
systemctl stop "$P-7"

# 8. does systemd rewrite arguments ($VAR and % specifiers)
out=$(sr --wait --pipe --setenv=OCHELL_X=EXPANDED /usr/bin/echo 'A${OCHELL_X}B' 'A$${OCHELL_X}B' 'A%hB' </dev/null)
set -- $out
info "8 argument 'A\${OCHELL_X}B'  arrived as: ${1:-<empty>}"
info "8 argument 'A\$\${OCHELL_X}B' arrived as: ${2:-<empty>}"
info "8 argument 'A%hB'           arrived as: ${3:-<empty>}"
[ "${1:-}" = 'A${OCHELL_X}B' ] && ok "8 arguments with \$ pass through unchanged" || info "8 systemd expands \$ in arguments: the launch script must escape \$ as \$\$, and the prompt must go on stdin"
if systemd-run --help 2>/dev/null | grep -q expand-environment; then info "8 --expand-environment is available on this systemd"; else info "8 --expand-environment is NOT available on this systemd"; fi

# 9. optional: a real agent with a token file
if [ -n "${CLAUDE_BIN:-}" ] && [ -n "${AGENT_ENV_FILE:-}" ]; then
  cfg=$(mktemp -d /tmp/ochell-chk.XXXXXX); chown "$AGENT" "$cfg"
  out=$(echo 'Reply with the single word: ready' | sr --wait --pipe -p EnvironmentFile="$AGENT_ENV_FILE" --setenv=CLAUDE_CONFIG_DIR="$cfg" "$CLAUDE_BIN" -p 2>&1); rc=$?
  [ $rc = 0 ] && ok "9 real agent run with token file" || bad "9 real agent run with token file" "rc=$rc out=$out"
  info "9 agent replied: $(echo "$out" | head -3)"
  rm -rf "$cfg"
else
  info "9 skipped: set CLAUDE_BIN and AGENT_ENV_FILE to run a real agent"
fi

echo; echo "passed $pass, failed $fail"
[ $fail = 0 ]
