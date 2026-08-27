#!/usr/bin/env bash
# Black-box RFC harness using coturn turnutils_* against a live xturn server.
# Requires XTURN_SERVER_IP (advertised + listen bind). Optional XTURN_SERVER_IP6, XTURN_PEER_PORT.
set -euo pipefail

cd "$(dirname "$0")"

XTURN_SERVER_IP="${XTURN_SERVER_IP:-}"
XTURN_PEER_PORT="${XTURN_PEER_PORT:-3480}"
CASE_TIMEOUT="${CASE_TIMEOUT:-30}"
CASE_TIMEOUT_TLS="${CASE_TIMEOUT_TLS:-45}"
AUTH_USER="${AUTH_USER:-rfc}"
AUTH_PASS="${AUTH_PASS:-rfcpass}"
TURN_PORT="${TURN_PORT:-3478}"
TLS_PORT="${TLS_PORT:-5349}"
XTURN_API_PORT="${XTURN_API_PORT:-8880}"
# Packet count for success-path uclient runs. 5 is too small for jitter; 50 at
# the default 20 ms interval is ~1s of media after Allocate.
UCLIENT_MSGS="${UCLIENT_MSGS:-50}"
# One-hop LAN ceilings (ms / percent). TLS/TCP are looser than UDP ChannelData.
UDP_MAX_RTT_MS="${UDP_MAX_RTT_MS:-30}"
UDP_MAX_JITTER_MS="${UDP_MAX_JITTER_MS:-20}"
TCP_MAX_RTT_MS="${TCP_MAX_RTT_MS:-80}"
TCP_MAX_JITTER_MS="${TCP_MAX_JITTER_MS:-40}"
TLS_MAX_RTT_MS="${TLS_MAX_RTT_MS:-150}"
TLS_MAX_JITTER_MS="${TLS_MAX_JITTER_MS:-60}"
MAX_LOSS_PCT="${MAX_LOSS_PCT:-0}"

# PeerFilter forbids XOR-PEER-ADDRESS when peer IP equals server_ip.
if [[ -z "${XTURN_PEER_IP:-}" ]]; then
  if [[ "$XTURN_SERVER_IP" == "127.0.0.1" ]]; then
    XTURN_PEER_IP="127.0.0.2"
  else
    XTURN_PEER_IP="127.0.0.1"
  fi
fi

SERVER_PID=""
PEER_PID=""
PEER_ALIAS_IP=""

PASS=0
FAIL=0
SKIP=0
FAILED_NAMES=()
SPEED_ROWS=()

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

usage() {
  cat <<EOF
Usage: XTURN_SERVER_IP=<ip> $0

Environment:
  XTURN_SERVER_IP   (required) Bind and advertise this address on TURN/STUN ports
  XTURN_SERVER_IP6  (optional) Also listen/advertise IPv6 for -x / -Z cases
  XTURN_PEER_PORT   UDP peer port for turnutils_peer (default: 3480)
  XTURN_PEER_IP     Peer IP for -e (default: 127.0.0.2 when server is 127.0.0.1, else 127.0.0.1)
  CASE_TIMEOUT      Per-case timeout seconds (default: 30)
  AUTH_USER         TURN username (default: rfc)
  XTURN_API_PORT    Maru HTTP port (default: 8880)
  UCLIENT_MSGS      Messages per success-path uclient run (default: 50)
  UDP_MAX_RTT_MS / UDP_MAX_JITTER_MS   UDP ceilings (default: 30 / 20)
  TCP_MAX_RTT_MS / TCP_MAX_JITTER_MS   TCP/-T ceilings (default: 80 / 40)
  TLS_MAX_RTT_MS / TLS_MAX_JITTER_MS   -S ceilings (default: 150 / 60)
  MAX_LOSS_PCT      Max lost-packet percent on success paths (default: 0)

Runs mix run (MIX_ENV=dev), turnutils_peer, then stunclient/uclient matrix.
Success cases print uclient RTT / jitter / loss and fail if they exceed the
ceilings for that path (UDP vs TCP vs TLS). Negative / permission-loss cases
do not apply RTT ceilings.
EOF
}

require_cmd() {
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Missing required command: $cmd" >&2
      exit 1
    fi
  done
}

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$PEER_PID" ]] && kill -0 "$PEER_PID" 2>/dev/null; then
    kill "$PEER_PID" 2>/dev/null || true
    wait "$PEER_PID" 2>/dev/null || true
  fi
  if [[ -n "$PEER_ALIAS_IP" ]]; then
    ifconfig lo0 -alias "$PEER_ALIAS_IP" 2>/dev/null \
      || sudo -n ifconfig lo0 -alias "$PEER_ALIAS_IP" 2>/dev/null \
      || true
  fi
}

trap cleanup EXIT INT TERM

ensure_loopback_alias() {
  local ip=$1

  [[ "$ip" =~ ^127\. ]] || return 0
  [[ "$ip" == "127.0.0.1" ]] && return 0

  if ping -c1 -W1 "$ip" >/dev/null 2>&1; then
    return 0
  fi

  if ifconfig lo0 alias "$ip" 255.255.255.255 2>/dev/null \
    || sudo -n ifconfig lo0 alias "$ip" 255.255.255.255 2>/dev/null; then
    PEER_ALIAS_IP="$ip"
    return 0
  fi

  cat >&2 <<EOF
Error: peer IP $ip is not on loopback (required when XTURN_SERVER_IP=127.0.0.1).

On macOS run once:
  sudo ifconfig lo0 alias $ip 255.255.255.255

Or set XTURN_PEER_IP to another local address and export it before running.
EOF
  exit 1
}

wait_for_tcp_port() {
  local host=$1 port=$2 max=${3:-25}
  local i

  for ((i = 0; i < max; i++)); do
    if nc -z -w 1 "$host" "$port" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done

  return 1
}

free_udp_port() {
  local host=$1 port=$2
  local pids

  pids=$(lsof -nP -iUDP@"${host}:${port}" -t 2>/dev/null | sort -u || true)
  if [[ -z "$pids" ]]; then
    return 0
  fi

  echo "Freeing UDP ${host}:${port} (pids: ${pids//$'\n'/ })..."
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null || true
  sleep 0.5

  pids=$(lsof -nP -iUDP@"${host}:${port}" -t 2>/dev/null | sort -u || true)
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
    sleep 0.5
  fi
}

free_tcp_port() {
  local host=$1 port=$2
  local pids

  pids=$(lsof -nP -iTCP@"${host}:${port}" -sTCP:LISTEN -t 2>/dev/null | sort -u || true)
  if [[ -z "$pids" ]]; then
    return 0
  fi

  echo "Freeing ${host}:${port} (pids: ${pids//$'\n'/ })..."
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null || true
  sleep 0.5

  pids=$(lsof -nP -iTCP@"${host}:${port}" -sTCP:LISTEN -t 2>/dev/null | sort -u || true)
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
    sleep 0.5
  fi
}

wait_for_udp_peer() {
  local ip=$1 port=$2 pid=$3 max=${4:-10}
  local i

  for ((i = 0; i < max; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    if lsof -Pan -p "$pid" -i "UDP@${ip}:${port}" 2>/dev/null | grep -q UDP; then
      return 0
    fi
    sleep 0.5
  done

  return 1
}

run_timeout() {
  local secs=$1
  shift
  perl -e 'alarm shift; exec @ARGV or exit 127' "$secs" "$@"
}

uclient_ok() {
  local outfile=$1
  grep -qE 'tot_recv_msgs=[1-9][0-9]*' "$outfile" 2>/dev/null \
    || grep -qiE 'received data packets: [1-9]' "$outfile" 2>/dev/null
}

uclient_no_recv() {
  local outfile=$1
  grep -qE 'tot_recv_msgs=0' "$outfile" 2>/dev/null \
    || grep -qiE 'lost packets [0-9]+ \(100' "$outfile" 2>/dev/null
}

# Prints: send recv loss_pct rtt_avg rtt_min rtt_max jitter_avg (empty token if missing)
uclient_parse() {
  python3 - "$1" <<'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()

def last(pat, default=""):
    ms = re.findall(pat, text)
    return ms[-1] if ms else default

send = last(r"tot_send_msgs=(\d+)", "")
recv = last(r"tot_recv_msgs=(\d+)", "")
loss = last(r"Total lost packets \d+ \(([0-9.]+)%?\)", "")
rtt = last(r"Average round trip delay ([0-9.]+) ms", "")
rtt_min = last(r"Average round trip delay [0-9.]+ ms; min = (\d+) ms", "")
rtt_max = last(r"Average round trip delay [0-9.]+ ms; min = \d+ ms, max = (\d+) ms", "")
jitter = last(r"Average jitter ([0-9.]+) ms", "")
print(send, recv, loss, rtt, rtt_min, rtt_max, jitter)
PY
}

uclient_path_class() {
  local a
  local tls=0 tcp=0
  for a in "$@"; do
    case "$a" in
      -S) tls=1 ;;
      -t|-T) tcp=1 ;;
    esac
  done
  if (( tls )); then
    echo tls
  elif (( tcp )); then
    echo tcp
  else
    echo udp
  fi
}

uclient_format_stats() {
  local send=$1 recv=$2 loss=$3 rtt=$4 rtt_min=$5 rtt_max=$6 jitter=$7
  local parts=()
  [[ -n "$send" && -n "$recv" ]] && parts+=("recv=${recv}/${send}")
  [[ -n "$rtt" ]] && parts+=("rtt=${rtt}ms")
  [[ -n "$rtt_min" && -n "$rtt_max" ]] && parts+=("min=${rtt_min} max=${rtt_max}")
  [[ -n "$jitter" ]] && parts+=("jitter=${jitter}ms")
  [[ -n "$loss" ]] && parts+=("loss=${loss}%")
  (IFS=' '; echo "${parts[*]}")
}

# Returns a reason on stdout if ceilings are exceeded; empty = ok.
# Missing stats are not a ceiling fail (older uclient builds).
uclient_ceiling_reason() {
  local class=$1 rtt=$2 jitter=$3 loss=$4
  local max_rtt max_jitter
  case "$class" in
    tls) max_rtt=$TLS_MAX_RTT_MS; max_jitter=$TLS_MAX_JITTER_MS ;;
    tcp) max_rtt=$TCP_MAX_RTT_MS; max_jitter=$TCP_MAX_JITTER_MS ;;
    *) max_rtt=$UDP_MAX_RTT_MS; max_jitter=$UDP_MAX_JITTER_MS ;;
  esac

  python3 - "$class" "$rtt" "$jitter" "$loss" "$max_rtt" "$max_jitter" "$MAX_LOSS_PCT" <<'PY'
import sys
cls, rtt, jitter, loss, max_rtt, max_jitter, max_loss = sys.argv[1:]
reasons = []

def over(val, cap, label, unit):
    if val == "":
        return
    if float(val) > float(cap):
        reasons.append(f"{label}={val}{unit} > {cap} ({cls})")

over(rtt, max_rtt, "rtt", "ms")
over(jitter, max_jitter, "jitter", "ms")
over(loss, max_loss, "loss", "%")
print("; ".join(reasons))
PY
}

record() {
  local status=$1 name=$2
  local detail=${3:-}
  case "$status" in
    pass)
      PASS=$((PASS + 1))
      if [[ -n "$detail" ]]; then
        printf "${GREEN}PASS${NC}  %s  %s\n" "$name" "$detail"
      else
        printf "${GREEN}PASS${NC}  %s\n" "$name"
      fi
      ;;
    fail)
      FAIL=$((FAIL + 1))
      FAILED_NAMES+=("$name")
      if [[ -n "$detail" ]]; then
        printf "${RED}FAIL${NC}  %s  %s\n" "$name" "$detail"
      else
        printf "${RED}FAIL${NC}  %s\n" "$name"
      fi
      ;;
    skip)
      SKIP=$((SKIP + 1))
      printf "${YELLOW}SKIP${NC}  %s\n" "$name"
      ;;
  esac
}

run_stun_binding() {
  local name="RFC5389/8489 STUN Binding"
  local out
  out=$(mktemp)

  if run_timeout "$CASE_TIMEOUT" turnutils_stunclient -L "$XTURN_SERVER_IP" -p "$TURN_PORT" "$XTURN_SERVER_IP" >"$out" 2>&1; then
    if grep -qiE 'Mapped|mapped|XOR|reflexive' "$out"; then
      record pass "$name"
    else
      record fail "$name (no mapped address in output)"
      cat "$out" >&2
    fi
  else
    record fail "$name (stunclient exit $?)"
    cat "$out" >&2
  fi

  rm -f "$out"
}

run_uclient_success() {
  local timeout_secs=$CASE_TIMEOUT
  if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
    timeout_secs=$1
    shift
  fi
  local name=$1
  shift
  local slug class out stats send recv loss rtt rtt_min rtt_max jitter reason
  slug=$(printf '%s' "$name" | tr -cs 'A-Za-z0-9._-' '_')
  class=$(uclient_path_class "$@")
  out="tmp/uclient-${slug}.log"

  if run_timeout "$timeout_secs" turnutils_uclient "$@" "$XTURN_SERVER_IP" >"$out" 2>&1; then
    read -r send recv loss rtt rtt_min rtt_max jitter <<<"$(uclient_parse "$out")"
    stats=$(uclient_format_stats "$send" "$recv" "$loss" "$rtt" "$rtt_min" "$rtt_max" "$jitter")
    SPEED_ROWS+=("$name|$class|$stats")
    if uclient_ok "$out"; then
      reason=$(uclient_ceiling_reason "$class" "$rtt" "$jitter" "$loss")
      if [[ -n "$reason" ]]; then
        record fail "$name" "${stats}  ${reason}"
        tail -20 "$out" >&2
      else
        record pass "$name" "$stats"
      fi
    else
      record fail "$name" "no relayed traffic ${stats}"
      tail -20 "$out" >&2
    fi
  else
    record fail "$name (uclient exit $?)"
    tail -20 "$out" >&2
  fi
}

run_uclient_expect_fail() {
  local name=$1
  shift
  local out
  out=$(mktemp)

  if run_timeout "$CASE_TIMEOUT" turnutils_uclient "$@" "$XTURN_SERVER_IP" >"$out" 2>&1; then
    if uclient_ok "$out"; then
      record fail "$name (expected failure but traffic succeeded)"
      tail -20 "$out" >&2
    else
      record pass "$name"
    fi
  else
    record pass "$name"
  fi

  rm -f "$out"
}

run_uclient_permission_loss() {
  local name="RFC5766 permissions enforced (-I expect loss)"
  local out
  out=$(mktemp)

  if run_timeout "$CASE_TIMEOUT" turnutils_uclient "${UCLIENT_BASE[@]}" -I "$XTURN_SERVER_IP" >"$out" 2>&1; then
    if uclient_no_recv "$out"; then
      record pass "$name"
    else
      record fail "$name (received traffic without CreatePermission)"
      tail -15 "$out" >&2
    fi
  else
    record pass "$name"
  fi

  rm -f "$out"
}

if [[ -z "$XTURN_SERVER_IP" ]]; then
  usage >&2
  echo "Error: XTURN_SERVER_IP is required." >&2
  exit 1
fi

require_cmd turnutils_uclient turnutils_peer turnutils_stunclient curl mix perl nc lsof python3

mkdir -p tmp log

ensure_loopback_alias "$XTURN_PEER_IP"

UCLIENT_BASE=(
  -u "$AUTH_USER"
  -w "$AUTH_PASS"
  -e "$XTURN_PEER_IP"
  -r "$XTURN_PEER_PORT"
  -n "$UCLIENT_MSGS"
  -c
  -L "$XTURN_SERVER_IP"
)

echo "Starting turnutils_peer on ${XTURN_PEER_IP}:${XTURN_PEER_PORT}..."
turnutils_peer -L "$XTURN_PEER_IP" -p "$XTURN_PEER_PORT" -v >>tmp/turnutils-peer.log 2>&1 &
PEER_PID=$!

if ! wait_for_udp_peer "$XTURN_PEER_IP" "$XTURN_PEER_PORT" "$PEER_PID" 10; then
  echo "turnutils_peer did not bind ${XTURN_PEER_IP}:${XTURN_PEER_PORT}. Log:" >&2
  tail -20 tmp/turnutils-peer.log >&2 || true
  exit 1
fi

sleep 0.5

free_udp_port "$XTURN_SERVER_IP" "$TURN_PORT"
free_tcp_port 127.0.0.1 "$XTURN_API_PORT"
free_tcp_port "$XTURN_SERVER_IP" "$TURN_PORT"
if [[ -f certs/server.crt ]]; then
  free_tcp_port "$XTURN_SERVER_IP" "$TLS_PORT"
fi

echo "Starting xturn (MIX_ENV=dev, XTURN_SERVER_IP=${XTURN_SERVER_IP})..."
MIX_ENV=dev XTURN_SERVER_IP="$XTURN_SERVER_IP" XTURN_API_PORT="$XTURN_API_PORT" \
  ${XTURN_SERVER_IP6:+XTURN_SERVER_IP6="$XTURN_SERVER_IP6"} \
  mix run --no-halt >tmp/turnutils-server.log 2>&1 &
SERVER_PID=$!

if ! wait_for_tcp_port "$XTURN_SERVER_IP" "$TURN_PORT" 25; then
  echo "Server did not open ${XTURN_SERVER_IP}:${TURN_PORT} within 25s. Log:" >&2
  tail -40 tmp/turnutils-server.log >&2 || true
  exit 1
fi

if ! wait_for_tcp_port 127.0.0.1 "$XTURN_API_PORT" 25; then
  echo "API did not open 127.0.0.1:${XTURN_API_PORT} within 25s. Log:" >&2
  tail -40 tmp/turnutils-server.log >&2 || true
  exit 1
fi

echo "Registering TURN user via POST /auth..."
if ! curl -sf -X POST "http://127.0.0.1:${XTURN_API_PORT}/auth" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${AUTH_USER}\",\"password\":\"${AUTH_PASS}\",\"namespace\":\"/\",\"peer_id\":\"turnutils\"}" >/dev/null; then
  echo "Failed to create auth user on port ${XTURN_API_PORT}" >&2
  tail -20 tmp/turnutils-server.log >&2 || true
  exit 1
fi

echo ""
echo "=== turnutils RFC matrix ==="
echo ""

run_stun_binding

run_uclient_success "RFC5766 ChannelData (default)" "${UCLIENT_BASE[@]}"
run_uclient_success "RFC5766 Send indication (-s)" "${UCLIENT_BASE[@]}" -s
run_uclient_success "RFC5766 CreatePermission/ChannelBind (-G)" "${UCLIENT_BASE[@]}" -G
run_uclient_success "RFC5766 DONT-FRAGMENT (-g)" "${UCLIENT_BASE[@]}" -g
run_uclient_success "RFC5766 TURN over TCP (-t)" "${UCLIENT_BASE[@]}" -t
run_uclient_success "RFC8656 explicit IPv4 RAF (-X)" "${UCLIENT_BASE[@]}" -X

run_uclient_expect_fail "RFC5766 negative tests (-N)" "${UCLIENT_BASE[@]}" -N
# coturn -R randomly corrupts ~10% of packets; it is not REQUESTED-TRANSPORT=TCP.
run_uclient_expect_fail "Auth required (no credentials)" \
  -e "$XTURN_PEER_IP" -r "$XTURN_PEER_PORT" -n 3 -c -L "$XTURN_SERVER_IP"
run_uclient_expect_fail "Auth wrong password" \
  -u "$AUTH_USER" -w wrongpass -e "$XTURN_PEER_IP" -r "$XTURN_PEER_PORT" -n 3 -c -L "$XTURN_SERVER_IP"

run_uclient_permission_loss

# uclient -T uses UDP peer + TCP client/relay path (coturn ignores -e/-r for -T).
run_uclient_success "$CASE_TIMEOUT" "RFC6062 TCP relay (-T)" "${UCLIENT_BASE[@]}" -T

if [[ -n "${XTURN_SERVER_IP6:-}" ]]; then
  run_uclient_success "RFC8656 IPv6 relay (-x)" "${UCLIENT_BASE[@]}" -x
  run_uclient_success "RFC8656 dual allocation (-Z)" "${UCLIENT_BASE[@]}" -Z
else
  record skip "RFC8656 IPv6 relay (-x) [set XTURN_SERVER_IP6]"
  record skip "RFC8656 dual allocation (-Z) [set XTURN_SERVER_IP6]"
fi

if [[ -f certs/server.crt ]]; then
  run_uclient_success "$CASE_TIMEOUT_TLS" "TLS/DTLS TURN (-S :5349)" \
    "${UCLIENT_BASE[@]}" -S -p "$TLS_PORT" -E certs/server.crt -i certs/server.crt
  run_uclient_success "$CASE_TIMEOUT_TLS" "TLS-over-TCP TURN (-t -S :5349)" \
    "${UCLIENT_BASE[@]}" -t -S -p "$TLS_PORT" -E certs/server.crt -i certs/server.crt
else
  record skip "TLS/DTLS TURN (-S) [no certs/server.crt]"
  record skip "TLS-over-TCP TURN (-t -S) [no certs/server.crt]"
fi

if [[ "${XTURN_REST:-}" == "1" ]]; then
  rest_json=$(curl -sf "http://127.0.0.1:${XTURN_API_PORT}/auth/rest?username=${AUTH_USER}&ttl=300" || true)
  if [[ -n "$rest_json" ]]; then
  rest_user=$(printf '%s' "$rest_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["username"])')
  rest_pass=$(printf '%s' "$rest_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["password"])')
  run_uclient_success "TURN REST credentials" \
    -u "$rest_user" -w "$rest_pass" -e "$XTURN_PEER_IP" -r "$XTURN_PEER_PORT" -n "$UCLIENT_MSGS" -c -L "$XTURN_SERVER_IP"
  else
    record fail "TURN REST credentials (GET /auth/rest failed; set XTURN_REST=1 and shared_secret)"
  fi
fi

record skip "RFC6062 passive TCP (-P) [turnutils_peer is UDP-only]"

if [[ ${#SPEED_ROWS[@]} -gt 0 ]]; then
  echo ""
  echo "=== uclient speed (one TURN hop vs turnutils_peer) ==="
  for row in "${SPEED_ROWS[@]}"; do
    IFS='|' read -r n class stats <<<"$row"
    printf "  %-42s %-4s  %s\n" "$n" "$class" "$stats"
  done
fi

echo ""
echo "=== Summary: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped ==="

if [[ ${#FAILED_NAMES[@]} -gt 0 ]]; then
  echo "Failures:"
  for n in "${FAILED_NAMES[@]}"; do
    echo "  - $n"
  done
fi

if [[ "$FAIL" -gt 0 ]]; then
  echo "Server log tail:" >&2
  tail -30 tmp/turnutils-server.log >&2 || true
  exit 1
fi

exit 0
