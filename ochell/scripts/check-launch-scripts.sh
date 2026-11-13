#!/usr/bin/env bash
# Checks ochell-launch and ochell-stop against real systemd, as ochell calls
# them: through sudo, from the ochell user. Run as root on the VM, after
# installing the two scripts, /etc/ochell/launcher.conf and the sudoers entry:
#
#   ./check-launch-scripts.sh <ochell-user> [directory of the scripts]
#
# The agent user, the workspace root and the environment file are read from
# /etc/ochell/launcher.conf. Prints PASS, FAIL or INFO for each check.
set -u
OCHELL=${1:?usage: check-launch-scripts.sh <ochell-user> [script directory]}
BIN=${2:-/usr/local/libexec/ochell}
CONF=/etc/ochell/launcher.conf
P="chk$$"
pass=0; fail=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1"; [ -n "${2:-}" ] && echo "      got: $2"; fail=$((fail+1)); }
info() { echo "INFO  $1"; }

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
id "$OCHELL" >/dev/null 2>&1 || { echo "no such user: $OCHELL"; exit 2; }
[ -x "$BIN/ochell-launch" ] && [ -x "$BIN/ochell-stop" ] || { echo "scripts not found in $BIN"; exit 2; }
AGENT_USER=; WORKSPACE_ROOT=; ENV_FILE=
# shellcheck disable=SC1090
. "$CONF" || { echo "cannot read $CONF"; exit 2; }
W="$WORKSPACE_ROOT/ochell-check-$$"
# Every call goes the way ochell makes it: as the ochell user, through sudo.
launch() { runuser -u "$OCHELL" -- sudo -n "$BIN/ochell-launch" "$@"; }
stop()   { runuser -u "$OCHELL" -- sudo -n "$BIN/ochell-stop" "$@"; }
cleanup() { systemctl stop "ochell-run-$P-4" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
echo "systemd $(systemctl --version | head -1 | awk '{print $2}'), ochell user $OCHELL, agent user $AGENT_USER, workspace $WORKSPACE_ROOT"

# 1. start through sudo: user, stdin, stdout, working directory, exit code
out=$(echo hello | launch --task "$P-1" --workdir "$W" -- /bin/sh -c 'id -un; pwd; cat; exit 7' 2>&1); rc=$?
[ "$out" = "$AGENT_USER"$'\n'"$W"$'\n'hello ] && [ $rc = 7 ] && ok "1 runs as $AGENT_USER in the workspace, with stdin, stdout and exit code" || bad "1 start through sudo" "rc=$rc out=$out"

# 2. arguments and --setenv values with \$ reach the agent unchanged
out=$(launch --task "$P-2" --workdir "$W" --setenv 'ORCH_TASK_URL=u${HOME}v' -- /usr/bin/printf '%s|' 'A${HOME}B' '$HOME' '$$' '100%h' </dev/null 2>&1)
[ "$out" = 'A${HOME}B|$HOME|$$|100%h|' ] && ok "2 arguments with \$ and % reach the agent unchanged" || bad "2 arguments with \$ and %" "$out"
out=$(launch --task "$P-2b" --workdir "$W" --setenv 'ORCH_TASK_URL=u${HOME}v' -- /usr/bin/printenv ORCH_TASK_URL </dev/null 2>&1)
[ "$out" = 'u${HOME}v' ] && ok "2 a --setenv value with \$ is not expanded" || bad "2 --setenv value with \$" "$out"

# 3. isolation: the agent cannot read ochell's settings or the token file, and can write its workspace
if [ -n "$ENV_FILE" ]; then
  out=$(launch --task "$P-3a" --workdir "$W" -- /bin/cat "$ENV_FILE" </dev/null 2>&1); rc=$?
  [ $rc != 0 ] && ok "3 the agent cannot read $ENV_FILE" || bad "3 the agent can read $ENV_FILE"
  first=$(head -1 "$ENV_FILE" | cut -d= -f1)
  out=$(launch --task "$P-3b" --workdir "$W" -- /bin/sh -c "printenv $first | wc -c" </dev/null 2>&1)
  [ "${out:-0}" -gt 1 ] 2>/dev/null && ok "3 $first from $ENV_FILE reaches the agent" || bad "3 $first from $ENV_FILE reaches the agent" "$out"
else
  info "3 ENV_FILE is not set; token checks skipped"
fi
home=$(getent passwd "$OCHELL" | cut -d: -f6)
out=$(launch --task "$P-3c" --workdir "$W" -- /bin/ls "$home" </dev/null 2>&1); rc=$?
[ $rc != 0 ] && ok "3 the agent cannot list $home" || bad "3 the agent can list the home directory of $OCHELL" "$out"
out=$(launch --task "$P-3d" --workdir "$W/sub" -- /bin/sh -c 'touch result && echo written' </dev/null 2>&1)
[ "$out" = written ] && ok "3 the agent can write its working directory" || bad "3 the agent can write its working directory" "$out"

# 4. stop ends every process of the run, including one that left the process group
launch --task "$P-4" --workdir "$W" --stop-grace 5 -- /bin/sh -c 'setsid sleep 987654 & sleep 987654 & sleep 987654' </dev/null >/dev/null 2>&1 & pid=$!
sleep 2
n=$(pgrep -u "$AGENT_USER" -f '^sleep 987654$' | wc -l)
stop "$P-4"; src=$?
wait $pid; rc=$?
m=$(pgrep -u "$AGENT_USER" -f '^sleep 987654$' | wc -l)
[ "$n" = 3 ] && [ "$m" = 0 ] && [ $src = 0 ] && ok "4 stop ends all processes of the run" || bad "4 stop ends all processes of the run" "before=$n after=$m stop exit=$src"
info "4 exit code of the launch after a stop: $rc (ochell reports the outcome from its own record)"
stop "$P-4"; [ $? = 0 ] && ok "4 stopping a run that has ended is not an error" || bad "4 stopping a run that has ended"

# 5. refusals
check_refused() { local name=$1; shift; launch "$@" </dev/null >/dev/null 2>&1; local rc=$?; [ $rc = 250 ] && ok "5 refused: $name" || bad "5 not refused: $name" "exit $rc"; }
check_refused "bad task id"                    --task '../x' --workdir "$W" -- /bin/true
check_refused "working directory outside root" --task "$P-5" --workdir /etc -- /bin/true
check_refused "option hidden in the command"   --task "$P-5" --workdir "$W" -- --uid=root /bin/true
check_refused "option before --"               --task "$P-5" --workdir "$W" --uid=root -- /bin/true
check_refused "environment name not allowed"   --task "$P-5" --workdir "$W" --setenv LD_PRELOAD=/tmp/x -- /bin/true

# 6. a command that systemd cannot execute is reported with an exit code from 200
launch --task "$P-6" --workdir "$W" -- /nonexistent/agent </dev/null >/dev/null 2>&1; rc=$?
[ $rc -ge 200 ] && ok "6 a command that cannot be executed exits with $rc" || bad "6 a command that cannot be executed" "exit $rc"

# 7. the ochell user cannot start units on its own
if runuser -u "$OCHELL" -- systemd-run --no-ask-password --uid="$AGENT_USER" --wait --collect --quiet /bin/true 2>/dev/null; then
  bad "7 $OCHELL can create units without the scripts"
else
  ok "7 $OCHELL cannot create units without the scripts"
fi

echo; echo "passed $pass, failed $fail"
[ $fail = 0 ]
