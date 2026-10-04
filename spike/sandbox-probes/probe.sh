#!/usr/bin/env bash
# valetkey M0 spike: sandbox capability probes against @anthropic-ai/sandbox-runtime (srt).
#
# Every secret here is a DECOY created under $WORK. Nothing reads real credentials.
# Each case prints one line:
#   <case id> <ALLOWED|BLOCKED> want=<ALLOW|BLOCK|-> <ok|UNEXPECTED|info> rc=<n> cfg=<cfg> | <last output line>
# "want" is what valetkey's fence needs; "-" marks an informational case.
# Cases tagged "base:" run the same command outside the sandbox, to show the check is meaningful.
#
# Usage: probe.sh            (installs srt into $WORK/srt unless SRT is set)
# Env:   SRT_VERSION (default 0.0.78), SRT (path to an srt binary), SRT_PKG (its package root),
#        WORK (scratch dir; default mktemp)
set -u

SRT_VERSION="${SRT_VERSION:-0.0.78}"
OS="$(uname -s)"
WORK="${WORK:-$(mktemp -d)}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd -P)"
HERE="$(cd "$(dirname "$0")" && pwd -P)"
NETPY="$HERE/net.py"
LIBRUN="$HERE/lib-run.mjs"
REAL_HOME="$HOME"
REAL_TMP="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
FAKE="$WORK/fakehome"
PROJ="$WORK/proj"
CFG="$WORK/cfg"
OUT="$WORK/out"            # outside every write allowlist: a file appearing here proves an escape
# Unix socket paths are capped at 104 bytes on macOS, so the socket dirs live in a short /tmp dir.
SHORT="$(mktemp -d /tmp/vks.XXXXXX)"; SHORT="$(cd "$SHORT" && pwd -P)"
SOCKS="$SHORT/sockets"     # stands in for valetkey's sockets dir
SOCKS_OK="$SHORT/allowed"  # a socket dir on the allowlist
PIDS=""
UNEXPECTED=0
UID_="$(id -u)"

log() { printf '\n=== %s\n' "$*"; }

if [ -z "${SRT:-}" ]; then
  npm install --silent --prefix "$WORK/srt" "@anthropic-ai/sandbox-runtime@$SRT_VERSION" >/dev/null 2>&1 \
    || { echo "npm install of srt failed"; exit 2; }
  SRT="$WORK/srt/node_modules/.bin/srt"
  SRT_PKG="$WORK/srt/node_modules/@anthropic-ai/sandbox-runtime"
fi
SRT_PKG="${SRT_PKG:-$(cd "$(dirname "$(readlink -f "$SRT")")/.." && pwd -P)}"

# perl-based timeout: macOS has no coreutils timeout by default.
tmo() { perl -e 'alarm shift; exec @ARGV or die "exec: $!"' "$@"; }

# ---------------------------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------------------------
setup() {
  rm -rf "$FAKE" "$PROJ" "$CFG" "$OUT" "$WORK/secrets" "$WORK/outside-dir"
  mkdir -p "$FAKE/.config/gcloud" "$FAKE/.aws" "$FAKE/.ssh" "$FAKE/.cache" "$FAKE/Library/Caches" \
    "$FAKE/.claude/debug" "$FAKE/.npm/_logs" "$FAKE/.config/other" \
    "$PROJ" "$CFG" "$OUT" "$SOCKS" "$SOCKS_OK" "$WORK/secrets" "$WORK/outside-dir"
  # Decoy credentials mirroring real layouts. Dummy content only.
  printf '{"type":"authorized_user","client_id":"decoy","client_secret":"DECOY-GCLOUD-SECRET","refresh_token":"decoy"}\n' \
    > "$FAKE/.config/gcloud/application_default_credentials.json"
  printf '[default]\naws_access_key_id = AKIADECOYDECOYDECOY0\naws_secret_access_key = DECOY-AWS-SECRET\n' \
    > "$FAKE/.aws/credentials"
  printf 'DECOY-SSH-KEY\n' > "$FAKE/.ssh/id_ed25519"
  printf 'DECOY-PROJECT-SECRET\n' > "$WORK/secrets/decoy.txt"
  printf 'not secret\n' > "$FAKE/.config/other/readable.txt"
  : > "$PROJ/marker"
}

write_cfg() { cat > "$CFG/$1.json"; }

configs() {
  local empty_fs='"filesystem":{"denyRead":[],"allowRead":[],"allowWrite":[],"denyWrite":[]}'
  local nonet='"network":{"allowedDomains":[],"deniedDomains":[]}'
  # srt CLI built-in default (what srt uses when no settings file exists).
  write_cfg default <<JSON
{$nonet,$empty_fs}
JSON
  # network.allowedDomains absent. The srt CLI rejects this ("network.allowedDomains: Required"),
  # but the library (what embedders use) accepts it and then applies NO network restriction:
  # the Seatbelt profile gets "(allow network*)". Run through lib-run.mjs.
  write_cfg nonetkey <<JSON
{"network":{"deniedDomains":[]},$empty_fs}
JSON
  write_cfg denyread <<JSON
{$nonet,"filesystem":{"denyRead":["$FAKE/.config/gcloud","$FAKE/.aws","$FAKE/.ssh","$WORK/secrets"],"allowRead":[],"allowWrite":["$PROJ"],"denyWrite":[]}}
JSON
  write_cfg projwrite <<JSON
{$nonet,"filesystem":{"denyRead":[],"allowRead":[],"allowWrite":["."],"denyWrite":[]}}
JSON
  write_cfg sockallow <<JSON
{"network":{"allowedDomains":[],"deniedDomains":[],"allowUnixSockets":["$SOCKS_OK"]},$empty_fs}
JSON
  write_cfg sockall <<JSON
{"network":{"allowedDomains":[],"deniedDomains":[],"allowAllUnixSockets":true},$empty_fs}
JSON
  write_cfg localbind <<JSON
{"network":{"allowedDomains":[],"deniedDomains":[],"allowLocalBinding":true},$empty_fs}
JSON
  write_cfg tcpallow <<JSON
{"network":{"allowedDomains":["127.0.0.1:$PORT_A"],"deniedDomains":[]},$empty_fs}
JSON
  write_cfg domains <<JSON
{"network":{"allowedDomains":["github.com","*.github.com"],"deniedDomains":[]},$empty_fs}
JSON
  write_cfg denylink <<JSON
{$nonet,"filesystem":{"denyRead":[],"allowRead":[],"allowWrite":["$PROJ"],"denyWrite":["$PROJ/link-dir","$PROJ/link-file"]}}
JSON
  write_cfg denytarget <<JSON
{$nonet,"filesystem":{"denyRead":[],"allowRead":[],"allowWrite":["$PROJ"],"denyWrite":["$PROJ/real-dir","$PROJ/real-file"]}}
JSON
  write_cfg denyboth <<JSON
{$nonet,"filesystem":{"denyRead":[],"allowRead":[],"allowWrite":["$PROJ"],"denyWrite":["$PROJ/link-dir","$PROJ/link-file","$PROJ/real-dir","$PROJ/real-file"]}}
JSON
  if [ "$OS" = Darwin ]; then
    write_cfg docker <<JSON
{"network":{"allowedDomains":[],"deniedDomains":[],"allowUnixSockets":[$DOCKER_ALLOW]},$empty_fs}
JSON
    write_cfg kcdenyread <<JSON
{$nonet,"filesystem":{"denyRead":["$REAL_HOME/Library/Keychains"],"allowRead":[],"allowWrite":[],"denyWrite":[]}}
JSON
  fi
}

# ---------------------------------------------------------------------------------------------
# Case runners
# ---------------------------------------------------------------------------------------------
report() { # id rc want cfg output
  local id=$1 rc=$2 want=$3 cfg=$4 out=$5 verdict judge line
  if [ "$rc" = 0 ]; then verdict=ALLOWED; else verdict=BLOCKED; fi
  judge=info
  if [ "$want" = BLOCK ]; then if [ "$verdict" = BLOCKED ]; then judge=ok; else judge=UNEXPECTED; fi; fi
  if [ "$want" = ALLOW ]; then if [ "$verdict" = ALLOWED ]; then judge=ok; else judge=UNEXPECTED; fi; fi
  [ "$judge" = UNEXPECTED ] && UNEXPECTED=$((UNEXPECTED + 1))
  line="$(printf '%s\n' "$out" | grep -v '^\[Sandbox' | grep -v '^[[:space:]]*$' | tail -1 | tr -d '\r' | cut -c1-200)"
  line="${line//$WORK/\$WORK}"; line="${line//$SHORT/\$SHORT}"
  printf '%-46s %-7s want=%-5s %-10s rc=%-3s cfg=%-12s | %s\n' "$id" "$verdict" "$want" "$judge" "$rc" "$cfg" "$line"
}

# sbx <id> <want> <cfg> <command...>   run inside the srt CLI with the fake HOME, cwd = $PROJ
sbx() {
  local id=$1 want=$2 cfg=$3 out rc; shift 3
  out="$(cd "$PROJ" && HOME="$FAKE" tmo 30 "$SRT" --settings "$CFG/$cfg.json" -c "$*" 2>&1)"; rc=$?
  report "$id" "$rc" "$want" "$cfg" "$out"
}
# sbxh: same, with the real HOME (keychain, launchd and Docker need the real user context).
sbxh() {
  local id=$1 want=$2 cfg=$3 out rc; shift 3
  out="$(cd "$PROJ" && tmo 30 "$SRT" --settings "$CFG/$cfg.json" -c "$*" 2>&1)"; rc=$?
  report "$id" "$rc" "$want" "$cfg" "$out"
}
# lib: run through the srt library instead of the CLI (for configs the CLI refuses).
lib() {
  local id=$1 want=$2 cfg=$3 out rc; shift 3
  out="$(cd "$PROJ" && HOME="$FAKE" tmo 30 node "$LIBRUN" "$SRT_PKG" "$CFG/$cfg.json" "$*" 2>&1)"; rc=$?
  report "$id" "$rc" "$want" "lib:$cfg" "$out"
}
# base <id> <command...>   outside the sandbox
base() {
  local id=$1 out rc; shift
  out="$(cd "$PROJ" && tmo 30 bash -c "$*" 2>&1)"; rc=$?
  report "base:$id" "$rc" - none "$out"
}
# escaped <id> <file> <want>: after a launch attempt, did the payload run outside the sandbox?
escaped() {
  local id=$1 f=$2 want=${3:-BLOCK} i
  for i in 1 2 3 4 5 6; do [ -e "$f" ] && break; sleep 1; done
  if [ -e "$f" ]; then report "$id" 0 "$want" effect "payload ran outside the sandbox: $f exists"
  else report "$id" 1 "$want" effect "payload did not run ($f absent after 6s)"; fi
}

bg() { "$@" >/dev/null 2>&1 & PIDS="$PIDS $!"; }
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null; done
  if [ "$OS" = Darwin ]; then
    for l in submit.$$ base.$$; do launchctl remove "valetkey.spike.$l" 2>/dev/null; done
    for l in bootstrap.$$ bootstrap-base.$$; do launchctl bootout "gui/$UID_/valetkey.spike.$l" 2>/dev/null; done
    [ -n "${KC_CREATED:-}" ] && security delete-generic-password -s valetkey-spike-decoy -a spike >/dev/null 2>&1
  else
    systemctl --user stop "valetkey-spike-$$" "valetkey-spike-base-$$" 2>/dev/null
    [ -n "${DBUS_PID:-}" ] && kill "$DBUS_PID" 2>/dev/null
  fi
  rm -f "$REAL_TMP/valetkey-spike-probe-$$" "/tmp/valetkey-spike-probe-$$" "/tmp/claude/valetkey-spike-probe-$$"
  [ -n "${MADE_TMP_CLAUDE:-}" ] && rmdir /tmp/claude 2>/dev/null
  rm -rf "$SHORT"
}
trap cleanup EXIT

free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

# ---------------------------------------------------------------------------------------------
log "environment"
echo "os=$OS $(uname -r) arch=$(uname -m) srt=$("$SRT" --version 2>&1) node=$(node -v) python=$(python3 -V 2>&1)"
[ "$OS" = Darwin ] && echo "macos=$(sw_vers -productVersion)"
if [ "$OS" = Linux ]; then
  . /etc/os-release 2>/dev/null && echo "distro=$PRETTY_NAME"
  echo "bwrap=$(bwrap --version 2>&1) socat=$(socat -V 2>/dev/null | grep -m1 'socat version') rg=$(rg --version 2>/dev/null | head -1)"
  echo "kernel.unprivileged_userns_clone=$(sysctl -n kernel.unprivileged_userns_clone 2>&1)"
  echo "kernel.apparmor_restrict_unprivileged_userns=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>&1)"
  echo "user.max_user_namespaces=$(sysctl -n user.max_user_namespaces 2>&1)"
fi

setup
if [ "$OS" = Linux ]; then
  base userns-unshare 'unshare -Ur id -u'
  base userns-bwrap 'bwrap --ro-bind / / --dev /dev --proc /proc --unshare-user --unshare-net true && echo bwrap-ok'
fi
PORT_A="$(free_port)"; PORT_B="$(free_port)"
DOCKER_ALLOW='"/nonexistent"'
DOCKER_SOCKS=""
if [ "$OS" = Darwin ]; then
  ctx_host="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null | sed 's#^unix://##')"
  for s in /var/run/docker.sock "$REAL_HOME/.docker/run/docker.sock" "$ctx_host"; do
    [ -n "$s" ] && case " $DOCKER_SOCKS " in *" $s "*) ;; *) DOCKER_SOCKS="$DOCKER_SOCKS $s";; esac
  done
  echo "docker context host: ${ctx_host:-<none>}"
  # Allowlist only the current context's socket, to test the per-path allow.
  [ -n "$ctx_host" ] && DOCKER_ALLOW="\"$ctx_host\""
fi
configs
srt_smoke="$(cd "$PROJ" && HOME="$FAKE" tmo 60 "$SRT" --settings "$CFG/default.json" -c 'echo sandbox-ok' 2>&1)"
echo "srt smoke: $(printf '%s' "$srt_smoke" | tail -3 | tr '\n' ' ')"

# ---------------------------------------------------------------------------------------------
log "deny-read applies to child processes (go/no-go row 1)"
G="$FAKE/.config/gcloud/application_default_credentials.json"
base read-cat "cat $G"
sbx denyread.cat            BLOCK denyread "cat $G"
sbx denyread.python         BLOCK denyread "python3 -c 'print(open(\"$G\").read())'"
sbx denyread.node           BLOCK denyread "node -e 'console.log(require(\"fs\").readFileSync(\"$G\",\"utf8\"))'"
sbx denyread.aws-cat        BLOCK denyread "cat $FAKE/.aws/credentials"
sbx denyread.ssh-cat        BLOCK denyread "cat $FAKE/.ssh/id_ed25519"
sbx denyread.ls-dir-lists-file BLOCK denyread "ls -A $FAKE/.aws | grep credentials"
sbx denyread.project-secret BLOCK denyread "cat $WORK/secrets/decoy.txt"
sbx denyread.cp-to-proj     BLOCK denyread "cp $G $PROJ/stolen && cat $PROJ/stolen"
sbx denyread.symlink-alias  BLOCK denyread "ln -s $FAKE/.aws $PROJ/aws-alias && cat $PROJ/aws-alias/credentials"
sbx denyread.hardlink-alias BLOCK denyread "ln $FAKE/.aws/credentials $PROJ/aws-hard && cat $PROJ/aws-hard"
sbx denyread.sh-subshell    BLOCK denyread "sh -c 'sh -c \"cat $G\"'"
sbx denyread.control-ok     ALLOW denyread "cat $FAKE/.config/other/readable.txt"

# ---------------------------------------------------------------------------------------------
log "Q26 default write scope (cfg=default is srt's built-in default; HOME=\$WORK/fakehome)"
# srt points TMPDIR at /tmp/claude. Embedders create it; on Linux the sandbox cannot create it itself.
[ -d /tmp/claude ] || { MADE_TMP_CLAUDE=1; mkdir -p /tmp/claude; }
for t in "$PROJ/w" "/tmp/valetkey-spike-probe-$$" \
         "$REAL_TMP/valetkey-spike-probe-$$" "$FAKE/.cache/w" "$FAKE/Library/Caches/w" "$FAKE/.claude/w" \
         "$FAKE/.claude/debug/w" "$FAKE/.npm/_logs/w" "$FAKE/.config/w" "$FAKE/w" "$WORK/w"; do
  sbx "write.default:$(echo "$t" | sed "s#$FAKE#~#;s#$WORK#\$WORK#")" - default "touch $t && echo wrote"
done
sbx write.default:sandbox-TMPDIR - default "echo TMPDIR=\$TMPDIR; mkdir -p \"\$TMPDIR\" && touch \"\$TMPDIR/valetkey-spike-probe-$$\" && echo wrote:\$TMPDIR"
sbx write.projwrite:cwd ALLOW projwrite "touch $PROJ/w2 && echo wrote"
sbx write.projwrite:/tmp BLOCK projwrite "touch /tmp/valetkey-spike-probe-$$ && echo wrote"
sbx write.projwrite:mandatory-.git/hooks BLOCK projwrite "mkdir -p .git/hooks && touch .git/hooks/pre-commit && echo wrote"
sbx write.projwrite:mandatory-.claude/agents BLOCK projwrite "mkdir -p .claude/agents && touch .claude/agents/x.md && echo wrote"
mkdir -p "$PROJ/.claude" "$PROJ/.git"     # pre-created, as in a real project
sbx write.projwrite:.claude/settings.json - projwrite "echo '{}' > .claude/settings.json && echo wrote"
sbx write.projwrite:.claude/settings.local.json - projwrite "echo '{}' > .claude/settings.local.json && echo wrote"
sbx write.projwrite:.claude/hooks - projwrite "mkdir -p .claude/hooks && touch .claude/hooks/x.sh && echo wrote"
sbx write.projwrite:.claude/skills - projwrite "mkdir -p .claude/skills/x && touch .claude/skills/x/SKILL.md && echo wrote"
sbx write.projwrite:.claude/agents-precreated BLOCK projwrite "mkdir -p .claude/agents && touch .claude/agents/y.md && echo wrote"
sbx write.projwrite:.git/config BLOCK projwrite "echo '[core]' > .git/config && echo wrote"
sbx write.projwrite:.git/hooks-precreated BLOCK projwrite "mkdir -p .git/hooks && touch .git/hooks/post-checkout && echo wrote"
sbx write.projwrite:.mcp.json BLOCK projwrite "echo '{}' > .mcp.json && echo wrote"
sbx write.projwrite:.envrc - projwrite "echo 'true' > .envrc && echo wrote"
sbx write.projwrite:.vscode/tasks.json BLOCK projwrite "mkdir -p .vscode && echo '{}' > .vscode/tasks.json && echo wrote"
rm -f "/tmp/valetkey-spike-probe-$$" "$REAL_TMP/valetkey-spike-probe-$$"

# ---------------------------------------------------------------------------------------------
log "Q18 unix-socket connect: default-deny + per-path allowlist (sockets under \$SHORT)"
bg python3 "$NETPY" serve-unix "$SOCKS/broker.sock"
bg python3 "$NETPY" serve-unix "$SOCKS_OK/dev.sock"
sleep 1
ln -s "$SOCKS/broker.sock" "$SOCKS_OK/link-to-broker.sock"   # e.g. planted by the agent in a temp dir
base unix.sockets-dir "python3 $NETPY connect-unix $SOCKS/broker.sock"
sbx unix.default:sockets-dir          BLOCK default   "python3 $NETPY connect-unix $SOCKS/broker.sock"
sbx unix.allowlist:sockets-dir        BLOCK sockallow "python3 $NETPY connect-unix $SOCKS/broker.sock"
sbx unix.allowlist:allowed-sock       ALLOW sockallow "python3 $NETPY connect-unix $SOCKS_OK/dev.sock"
sbx unix.allowlist:dotdot-to-denied   BLOCK sockallow "python3 $NETPY connect-unix $SOCKS_OK/../sockets/broker.sock"
sbx unix.allowlist:symlink-in-allowed BLOCK sockallow "python3 $NETPY connect-unix $SOCKS_OK/link-to-broker.sock"
sbx unix.allowall:sockets-dir         -     sockall   "python3 $NETPY connect-unix $SOCKS/broker.sock"
lib unix.nonetkey:sockets-dir         -     nonetkey  "python3 $NETPY connect-unix $SOCKS/broker.sock"
sbx unix.default:nc-U                 BLOCK default   "nc -U -w 2 $SOCKS/broker.sock </dev/null && echo nc-connected"
sbx unix.projwrite:bind-in-sockets    BLOCK projwrite "python3 $NETPY bind-unix $SOCKS/fake.sock"
sbx unix.allowlist:bind-in-allowed    -     sockallow "python3 $NETPY bind-unix $SOCKS_OK/new.sock"
if [ "$OS" = Linux ]; then
  log "Q16 abstract unix sockets (Linux)"
  bg python3 "$NETPY" serve-abstract valetkey-spike-abs
  sleep 1
  base unix.abstract "python3 $NETPY connect-abstract valetkey-spike-abs"
  sbx unix.default:abstract  BLOCK default  "python3 $NETPY connect-abstract valetkey-spike-abs"
  sbx unix.allowall:abstract -     sockall  "python3 $NETPY connect-abstract valetkey-spike-abs"
  lib unix.nonetkey:abstract -     nonetkey "python3 $NETPY connect-abstract valetkey-spike-abs"
  echo "X11 sockets on host: $(ls /tmp/.X11-unix 2>/dev/null | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------------------------
log "Q18 localhost TCP (HTTP listeners on 127.0.0.1:A=$PORT_A and :B=$PORT_B, outside the sandbox)"
mkdir -p "$WORK/www"; echo pong > "$WORK/www/index.html"
bg python3 -m http.server --bind 127.0.0.1 --directory "$WORK/www" "$PORT_A"
bg python3 -m http.server --bind 127.0.0.1 --directory "$WORK/www" "$PORT_B"
for i in 1 2 3 4 5 6 7 8 9 10; do python3 "$NETPY" connect-tcp 127.0.0.1 "$PORT_B" >/dev/null 2>&1 && break; sleep 1; done
CURL="curl --noproxy '' -sS -m 5 -o /dev/null -w 'http=%{http_code}\n' --fail"
base tcp.raw-A "python3 $NETPY connect-tcp 127.0.0.1 $PORT_A"
sbx tcp.default:raw-A        BLOCK default   "python3 $NETPY connect-tcp 127.0.0.1 $PORT_A"
sbx tcp.default:bind         -     default   "python3 $NETPY bind-tcp 127.0.0.1 0"
sbx tcp.localbind:bind       -     localbind "python3 $NETPY bind-tcp 127.0.0.1 0"
sbx tcp.localbind:raw-A      -     localbind "python3 $NETPY connect-tcp 127.0.0.1 $PORT_A"
sbx tcp.localbind:raw-B      -     localbind "python3 $NETPY connect-tcp 127.0.0.1 $PORT_B"
sbx tcp.tcpallow:raw-A       -     tcpallow  "python3 $NETPY connect-tcp 127.0.0.1 $PORT_A"
sbx tcp.tcpallow:proxy-A     -     tcpallow  "$CURL http://127.0.0.1:$PORT_A/"
sbx tcp.tcpallow:proxy-B     BLOCK tcpallow  "$CURL http://127.0.0.1:$PORT_B/"
sbx tcp.default:proxy-A      BLOCK default   "$CURL http://127.0.0.1:$PORT_A/"
sbx tcp.default:curl-localhost BLOCK default "curl -sS -m 5 -o /dev/null -w 'http=%{http_code}\n' --fail http://localhost:$PORT_A/"
lib tcp.nonetkey:raw-A       -     nonetkey  "python3 $NETPY connect-tcp 127.0.0.1 $PORT_A"

# ---------------------------------------------------------------------------------------------
log "Q20 network filter: raw IPs, metadata, non-allowlisted domains"
base net.raw-1.1.1.1:443 "python3 $NETPY connect-tcp 1.1.1.1 443"
base net.raw-169.254.169.254:80 "python3 $NETPY connect-tcp 169.254.169.254 80"
META="h=\$(curl --noproxy '' -s -m 5 -D - -o /dev/null http://169.254.169.254/); echo \"\$h\" | head -1; echo \"\$h\" | grep -iq x-proxy-error && exit 1; [ -n \"\$h\" ]"
for cfg in default domains nonetkey; do
  run=sbx; [ "$cfg" = nonetkey ] && run=lib
  $run "net.$cfg:raw-169.254.169.254:80" BLOCK "$cfg" "python3 $NETPY connect-tcp 169.254.169.254 80"
  $run "net.$cfg:raw-1.1.1.1:443"        -     "$cfg" "python3 $NETPY connect-tcp 1.1.1.1 443"
  # Reached = any HTTP answer that is not srt's own refusal (X-Proxy-Error header).
  $run "net.$cfg:http-169.254.169.254"   BLOCK "$cfg" "$META"
  $run "net.$cfg:proxy-https-1.1.1.1"    -     "$cfg" "curl --noproxy '' -sS -m 8 -o /dev/null -w 'http=%{http_code}\n' https://1.1.1.1/"
  $run "net.$cfg:proxy-example.com"      -     "$cfg" "curl -sS -m 8 -o /dev/null -w 'http=%{http_code}\n' https://example.com/"
  $run "net.$cfg:proxy-github.com"       -     "$cfg" "curl -sS -m 8 -o /dev/null -w 'http=%{http_code}\n' https://github.com/"
done

# ---------------------------------------------------------------------------------------------
log "Q21 symlink semantics (link-dir -> real-dir, link-file -> real-file, all inside the writable project)"
sym_setup() {
  rm -rf "$PROJ/real-dir" "$PROJ/real-file" "$PROJ/link-dir" "$PROJ/link-file" "$PROJ/link-out" "$PROJ/moved" \
    "$PROJ/real-dir.bak" "$WORK/outside-dir"
  mkdir -p "$PROJ/real-dir" "$WORK/outside-dir"
  echo orig > "$PROJ/real-dir/f"; echo orig > "$PROJ/real-file"
  ln -s "$PROJ/real-dir" "$PROJ/link-dir"; ln -s "$PROJ/real-file" "$PROJ/link-file"
  ln -s "$WORK/outside-dir" "$PROJ/link-out"
}
for cfg in denylink denytarget denyboth; do
  w=-; [ $cfg = denyboth ] && w=BLOCK
  sym_setup; sbx "sym.$cfg:replace-dir-link"        $w $cfg "rm $PROJ/link-dir && ln -s $WORK/outside-dir $PROJ/link-dir && echo replaced"
  sym_setup; sbx "sym.$cfg:rename-dir-link"         $w $cfg "mv $PROJ/link-dir $PROJ/moved && ln -s /tmp $PROJ/link-dir && echo replaced"
  sym_setup; sbx "sym.$cfg:write-through-dir-link"  $w $cfg "echo x > $PROJ/link-dir/new && echo wrote"
  sym_setup; sbx "sym.$cfg:modify-through-dir-link" $w $cfg "echo x > $PROJ/link-dir/f && echo wrote"
  sym_setup; sbx "sym.$cfg:replace-file-link"       $w $cfg "rm $PROJ/link-file && ln -s /etc/hosts $PROJ/link-file && echo replaced"
  sym_setup; sbx "sym.$cfg:write-through-file-link" $w $cfg "echo x > $PROJ/link-file && echo wrote"
  sym_setup; sbx "sym.$cfg:write-target-file"       $w $cfg "echo x > $PROJ/real-file && echo wrote"
  sym_setup; sbx "sym.$cfg:write-target-dir"        $w $cfg "echo x > $PROJ/real-dir/f && echo wrote"
  sym_setup; sbx "sym.$cfg:replace-target-file"     $w $cfg "rm $PROJ/real-file && echo evil > $PROJ/real-file && echo replaced"
  sym_setup; sbx "sym.$cfg:rename-target-dir"       $w $cfg "mv $PROJ/real-dir $PROJ/real-dir.bak && mkdir $PROJ/real-dir && echo replaced"
done
# Deny-write the PARENT dir of a link instead (what valetkey could do for entries it owns).
sym_setup; mkdir -p "$PROJ/parent"; ln -s "$PROJ/real-file" "$PROJ/parent/link"
write_cfg denyparent <<JSON
{"network":{"allowedDomains":[],"deniedDomains":[]},"filesystem":{"denyRead":[],"allowRead":[],"allowWrite":["$PROJ"],"denyWrite":["$PROJ/parent"]}}
JSON
sbx "sym.denyparent:replace-link-in-denied-dir" BLOCK denyparent "rm $PROJ/parent/link && ln -s /etc/hosts $PROJ/parent/link && echo replaced"
sbx "sym.denyparent:rename-denied-dir"          BLOCK denyparent "mv $PROJ/parent $PROJ/parent2 && mkdir $PROJ/parent && echo replaced"
rm -rf "$PROJ/parent" "$PROJ/parent2"
sym_setup; sbx "sym.projwrite:write-through-link-out-of-scope" BLOCK projwrite "echo x > $PROJ/link-out/new && echo wrote"
sym_setup

# ---------------------------------------------------------------------------------------------
if [ "$OS" = Darwin ]; then
  log "Q4 keychain (decoy item valetkey-spike-decoy)"
  if security add-generic-password -s valetkey-spike-decoy -a spike -w decoy-value >/dev/null 2>&1; then KC_CREATED=1; fi
  base kc.find "security find-generic-password -s valetkey-spike-decoy -w"
  sbxh kc.default:find-w     BLOCK default    "security find-generic-password -s valetkey-spike-decoy -w"
  sbxh kc.default:find-meta  BLOCK default    "security find-generic-password -s valetkey-spike-decoy | grep -c svce"
  sbxh kc.denyread-Keychains BLOCK kcdenyread "security find-generic-password -s valetkey-spike-decoy -w"
  # srt has no switch to REMOVE a Mach service, so derive srt's own profile and drop lines by hand.
  (cd "$PROJ" && PROBE_DUMP_WRAPPED="$WORK/wrapped.txt" node "$LIBRUN" "$SRT_PKG" "$CFG/default.json" true >/dev/null 2>&1)
  python3 -c 'import shlex,sys; t=shlex.split(open(sys.argv[1]).read()); print(t[t.index("-p")+1])' "$WORK/wrapped.txt" > "$WORK/srt-default.sb"
  echo "srt default profile, Security-related mach-lookup lines: $(grep -E 'SecurityServer|securityd' "$WORK/srt-default.sb" | tr -s ' ' | tr '\n' ' ')"
  for drop in com.apple.SecurityServer com.apple.securityd.xpc 'com.apple.SecurityServer|com.apple.securityd.xpc'; do
    grep -vE "$drop" "$WORK/srt-default.sb" > "$WORK/custom.sb"
    out="$(sandbox-exec -p "$(cat "$WORK/custom.sb")" /usr/bin/security find-generic-password -s valetkey-spike-decoy -w 2>&1)"
    rc=1; [ "$out" = decoy-value ] && rc=0
    report "kc.srt-profile-minus:$drop" $rc BLOCK sandbox-exec "$out"
  done
  if [ -n "${KC_CREATED:-}" ]; then security delete-generic-password -s valetkey-spike-decoy -a spike >/dev/null 2>&1 && KC_CREATED=; fi

  log "Q15 Docker sockets"
  for s in $DOCKER_SOCKS; do
    base "docker:$s" "ls -l $s; python3 $NETPY connect-unix $s"
    sbxh "docker.default:$s"  BLOCK default "python3 $NETPY connect-unix $s"
    sbxh "docker.allowctx:$s" -     docker  "python3 $NETPY connect-unix $s"
  done
  sbxh docker.default:cli  BLOCK default "docker version --format '{{.Server.Version}}'"
  sbxh docker.allowctx:cli -     docker  "docker version --format '{{.Server.Version}}'"
  if [ -n "${CI:-}" ] && [ -z "$DOCKER_SOCKS" ]; then echo "docker: UNTESTED (no Docker on this runner)"; fi

  log "Q19 launchd / Apple Events"
  base launchctl.print-gui "launchctl print gui/$UID_ >/dev/null && echo gui-domain-ok"
  base launchctl.submit "launchctl submit -l valetkey.spike.base.$$ -- /usr/bin/touch $OUT/base-submit && echo submitted"
  escaped base:launchctl.submit:effect "$OUT/base-submit" -
  launchctl remove "valetkey.spike.base.$$" 2>/dev/null
  sbxh launchctl.list - default "echo jobs visible: \$(launchctl list | wc -l)"
  sbxh launchctl.submit BLOCK default "launchctl submit -l valetkey.spike.submit.$$ -- /usr/bin/touch $OUT/launchctl-submit"
  escaped launchctl.submit:effect "$OUT/launchctl-submit"
  launchctl remove "valetkey.spike.submit.$$" 2>/dev/null
  for kind in bootstrap bootstrap-base; do
    cat > "$WORK/$kind.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>valetkey.spike.$kind.$$</string>
<key>ProgramArguments</key><array><string>/usr/bin/touch</string><string>$OUT/launchctl-$kind</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PLIST
  done
  base launchctl.bootstrap "launchctl bootstrap gui/$UID_ $WORK/bootstrap-base.plist && echo bootstrapped"
  escaped base:launchctl.bootstrap:effect "$OUT/launchctl-bootstrap-base" -
  launchctl bootout "gui/$UID_/valetkey.spike.bootstrap-base.$$" 2>/dev/null
  sbxh launchctl.bootstrap BLOCK default "launchctl bootstrap gui/$UID_ $WORK/bootstrap.plist"
  escaped launchctl.bootstrap:effect "$OUT/launchctl-bootstrap"
  launchctl bootout "gui/$UID_/valetkey.spike.bootstrap.$$" 2>/dev/null
  printf '#!/bin/sh\ntouch %s/open-command\n' "$OUT" > "$WORK/x.command"; chmod +x "$WORK/x.command"
  sbxh open.command BLOCK default "open $WORK/x.command"
  escaped open.command:effect "$OUT/open-command"
  if [ -z "${CI:-}" ]; then
    sbxh osascript.terminal BLOCK default "osascript -e 'tell application \"Terminal\" to do script \"touch $OUT/osascript\"'"
    escaped osascript.terminal:effect "$OUT/osascript"
  else
    echo "osascript.terminal: UNTESTED in CI (Terminal automation needs interactive TCC consent)"
  fi
  sbxh osascript.system-events BLOCK default "osascript -e 'tell application \"System Events\" to get name of every process'"
fi

# ---------------------------------------------------------------------------------------------
if [ "$OS" = Linux ]; then
  log "Q16/Q19 D-Bus and systemd --user (Linux)"
  echo "DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-<unset>} XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-<unset>}"
  if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && command -v dbus-daemon >/dev/null; then
    dbus_out="$(dbus-daemon --session --fork --print-address=1 --print-pid=1)"
    DBUS_SESSION_BUS_ADDRESS="$(printf '%s\n' "$dbus_out" | sed -n 1p)"; export DBUS_SESSION_BUS_ADDRESS
    DBUS_PID="$(printf '%s\n' "$dbus_out" | sed -n 2p)"
    echo "started a private session bus: $DBUS_SESSION_BUS_ADDRESS"
  fi
  DB="dbus-send --session --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.ListNames >/dev/null && echo bus-reachable"
  base dbus.session "$DB"
  sbx dbus.default:session  BLOCK default "$DB"
  sbx dbus.allowall:session -     sockall "$DB"
  lib dbus.nonetkey:session -     nonetkey "$DB"
  if [ -S "/run/user/$UID_/bus" ]; then
    SB="dbus-send --bus=unix:path=/run/user/$UID_/bus --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.ListNames >/dev/null && echo bus-reachable"
    base dbus.user-bus "$SB"
    sbx dbus.default:user-bus  BLOCK default "$SB"
    sbx dbus.allowall:user-bus -     sockall "$SB"
  fi
  base systemd.user-status "systemctl --user is-system-running"
  base systemd.user-run "systemd-run --user --unit valetkey-spike-base-$$ /usr/bin/true && echo ran"
  sbx systemd.default:run BLOCK default "systemd-run --user --unit valetkey-spike-$$ /usr/bin/touch $OUT/systemd-run"
  escaped systemd.default:run:effect "$OUT/systemd-run"
  sbx systemd.allowall:run BLOCK sockall "systemd-run --user --unit valetkey-spike-$$ /usr/bin/touch $OUT/systemd-run2"
  escaped systemd.allowall:run:effect "$OUT/systemd-run2"
fi

log "done: $UNEXPECTED unexpected result(s)"
exit 0
