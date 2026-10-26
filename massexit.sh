#!/usr/bin/env bash
# massexit — 一键把 VPN Gate 的可检测出口铺成一排 SOCKS5 节点
#
#   一条出口 = 一个 netns（内含 openvpn tun0）+ 母机上一个 SOCKS5 端口
#   布局参考 byJoey/fanout：监听留母机、出站 setns 进 netns；
#   这里做成命令行批量版 + 单进程分发器，几百个出口只占一份内存。
#
# 用法:
#   bash massexit.sh install --count 30     # 一键装机并铺 30 条出口
#   massexit status | links | sub | health | up 60 | down | swap 3
set -uo pipefail

APP=massexit
BASE=${MASSEXIT_BASE:-/var/lib/massexit}
CONF=$BASE/config
NODES=$BASE/nodes.tsv
EXITS_TSV=$BASE/exits.tsv
USED=$BASE/used_ips.txt
OVPN_DIR=$BASE/ovpn
LOG_DIR=$BASE/log
SLOT_DIR=$BASE/slots
RUN_DIR=$BASE/run
CRED=$BASE/socks.cred
OPT_DIR=/opt/massexit
DAEMON=$OPT_DIR/massexitd.py
UNIT=/etc/systemd/system/massexit.service
HTIMER=/etc/systemd/system/massexit-health.timer
HSVC=/etc/systemd/system/massexit-health.service
SELF=/opt/massexit/massexit.sh
RAW_URL=${MASSEXIT_RAW_URL:-https://raw.githubusercontent.com/76hvc/massexit/main}

# ---- 默认配置（可被 $BASE/config 覆盖）----
BASE_PORT=20000
COUNT=auto
PARALLEL=6
RESIDENTIAL_ONLY=1
MAX_TRIES=6
REFRESH_HOURS=6
PROBE_URLS="https://api.ipify.org https://ifconfig.me/ip https://ipinfo.io/ip"
MEM_PER_EXIT=30
HEALTH_SEC=300
HEALTH_PARALLEL=4

if [ -r "$CONF" ]; then . "$CONF"; fi

C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[36m'; C_D=$'\033[2m'; C_0=$'\033[0m'
if [ ! -t 1 ]; then C_R=; C_G=; C_Y=; C_B=; C_D=; C_0=; fi

log()  { printf '%s %s\n' "${C_D}$(date +%H:%M:%S)${C_0}" "$*"; }
ok()   { printf '%s %s\n' "${C_G}✓${C_0}" "$*"; }
warn() { printf '%s %s\n' "${C_Y}!${C_0}" "$*" >&2; }
die()  { printf '%s %s\n' "${C_R}✗${C_0}" "$*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "请用 root 运行"; }

ns_name()   { printf 'mx%s' "$1"; }
ns_subnet() { printf '10.%s.%s' "$((200 + $1 / 64))" "$(( ($1 % 64) * 4 ))"; }

# ---------------------------------------------------------------- 依赖
install_deps() {
  local pkgs="openvpn curl iproute2 iptables ca-certificates python3 coreutils util-linux procps"
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y -qq $pkgs >/dev/null 2>&1 || apt-get install -y $pkgs
  elif command -v dnf >/dev/null; then dnf install -y $pkgs
  elif command -v yum >/dev/null; then yum install -y $pkgs
  elif command -v pacman >/dev/null; then pacman -Sy --noconfirm $pkgs
  elif command -v apk >/dev/null; then apk add --no-cache $pkgs bash
  elif command -v zypper >/dev/null; then zypper -n install $pkgs
  else die "认不出包管理器，手动装一下: $pkgs"
  fi
  [ -e /dev/net/tun ] || die "/dev/net/tun 不存在：这台机器不给 tun，出不了隧道"
  modprobe tun 2>/dev/null || true
}

host_ip() {
  if [ -s "$BASE/host_ip" ]; then cat "$BASE/host_ip"; return; fi
  local ip u
  for u in $PROBE_URLS; do
    ip=$(curl -4 -fsS --max-time 8 "$u" 2>/dev/null | tr -d '[:space:]')
    if [ -n "$ip" ]; then printf '%s' "$ip" > "$BASE/host_ip"; echo "$ip"; return; fi
  done
}

# ---------------------------------------------------------------- 节点池
fetch_nodes() {
  mkdir -p "$OVPN_DIR" "$LOG_DIR" "$SLOT_DIR" "$RUN_DIR"
  local raw=$BASE/api.raw tmp=$BASE/api.tmp i
  : > "$tmp"
  # 每次 API 只回一百来个、而且是轮换的，多拉几遍合并去重能把池子撑大
  for i in 1 2 3 4 5 6; do
    curl -fsS --max-time 30 -A "massexit/1.0" "https://www.vpngate.net/api/iphone/" >> "$tmp" 2>/dev/null || true
  done
  if [ ! -s "$tmp" ]; then warn "VPN Gate 列表拉取失败，沿用缓存"; return 1; fi
  mv "$tmp" "$raw"

  python3 - "$raw" "$NODES" "$OVPN_DIR" <<'PY' || return 1
import base64, csv, io, os, re, sys
raw_path, nodes_path, ovpn_dir = sys.argv[1], sys.argv[2], sys.argv[3]
lines = []
with open(raw_path, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        line = line.rstrip("\n").rstrip("\r")
        if not line or line.startswith("*"):
            continue
        lines.append(line.lstrip("#"))
if len(lines) < 2:
    sys.exit("节点列表格式异常")
reader = csv.reader(io.StringIO("\n".join(lines)))
header = next(reader)
idx = {name.strip(): i for i, name in enumerate(header)}
for k in ["HostName", "IP", "CountryLong", "CountryShort", "Speed", "OpenVPN_ConfigData_Base64"]:
    if k not in idx:
        sys.exit("节点列表缺字段 %s" % k)

def cell(rec, key):
    i = idx.get(key)
    return rec[i] if i is not None and i < len(rec) else ""

best = {}
for rec in reader:
    host, b64 = cell(rec, "HostName"), cell(rec, "OpenVPN_ConfigData_Base64")
    if not host or not b64:
        continue
    try:
        cfg = base64.b64decode(b64).decode("utf-8", "replace")
        speed = float(cell(rec, "Speed") or 0)
    except Exception:
        continue
    ip = cell(rec, "IP")
    residential = not host.lower().startswith("public-vpn-") and not ip.startswith("219.100.37.")
    prev = best.get(host)
    if prev and prev["speed"] >= speed:
        continue
    proto = "udp"
    m = re.search(r"^\s*proto\s+(\S+)", cfg, re.M)
    if m:
        proto = m.group(1).lower()
    best[host] = {"ip": ip, "cc": cell(rec, "CountryShort"),
                  "country": cell(rec, "CountryLong").replace("\t", " "),
                  "speed": speed, "cfg": cfg, "res": residential, "proto": proto}

os.makedirs(ovpn_dir, exist_ok=True)
tmp_path = nodes_path + ".tmp"
with open(tmp_path, "w", encoding="utf-8") as out:
    for host, n in sorted(best.items(), key=lambda kv: -kv[1]["speed"]):
        fn = re.sub(r"[^A-Za-z0-9_.-]", "_", host)[:60] + ".ovpn"
        path = os.path.join(ovpn_dir, fn)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(n["cfg"])
        out.write("\t".join([host, n["ip"], n["cc"], n["country"],
                             "%.0f" % n["speed"], "1" if n["res"] else "0", path,
                             n["proto"]]) + "\n")
os.replace(tmp_path, nodes_path)
print("节点池: %d 个（家宽 %d）" % (len(best), sum(1 for n in best.values() if n["res"])))
PY
  date +%s > "$BASE/nodes.fetched"
}

ensure_nodes() {
  local age=999999 now f=0
  now=$(date +%s)
  [ -s "$BASE/nodes.fetched" ] && f=$(cat "$BASE/nodes.fetched")
  age=$(( now - f ))
  if [ ! -s "$NODES" ] || [ "$age" -gt $(( REFRESH_HOURS * 3600 )) ]; then
    log "更新 VPN Gate 节点池…"
    fetch_nodes || true
  fi
  [ -s "$NODES" ] || die "节点池为空，检查能不能访问 vpngate.net"
}

# 在锁里挑节点并立刻占用它的出口 IP，避免并发挑到同一个
pick_node() {
  (
    flock 9
    local host ip cc country speed res path proto hit="" pass
    for pass in udp any; do
      while IFS=$'\t' read -r host ip cc country speed res path proto; do
        [ -n "$host" ] || continue
        [ -f "$path" ] || continue
        if [ "$pass" = udp ] && [ "$proto" != udp ]; then continue; fi
        if [ "$RESIDENTIAL_ONLY" = 1 ] && [ "$res" != 1 ]; then continue; fi
        if [ -f "$USED" ] && grep -qxF "$ip" "$USED"; then continue; fi
        hit=$host$'\t'$ip$'\t'$cc$'\t'$country$'\t'$path
        break
      done < "$NODES"
      [ -n "$hit" ] && break
    done
    [ -n "$hit" ] || exit 1
    printf '%s\n' "$ip" >> "$USED"
    # 只留最近 80 条：节点池就一百来个，历史全留着的话换几轮就没得挑了
    tail -n 40 "$USED" > "$USED.tmp" 2>/dev/null && mv -f "$USED.tmp" "$USED"
    printf '%s\n' "$hit"
  ) 9>"$BASE/lock"
}

# ---------------------------------------------------------------- netns / openvpn
setup_netns() {
  local slot=$1 ns sub veth peer cidr
  ns=$(ns_name "$slot"); sub=$(ns_subnet "$slot")
  veth="mxv$slot"; peer="mxp$slot"; cidr="$sub.0/30"

  ip netns add "$ns" 2>/dev/null || true
  ip -n "$ns" link set lo up 2>/dev/null
  ip link add "$veth" type veth peer name "$peer" 2>/dev/null || true
  ip link set "$peer" netns "$ns" 2>/dev/null || true
  ip addr add "$sub.1/30" dev "$veth" 2>/dev/null
  ip link set "$veth" up 2>/dev/null
  ip -n "$ns" addr add "$sub.2/30" dev "$peer" 2>/dev/null
  ip -n "$ns" link set "$peer" up 2>/dev/null
  ip -n "$ns" route add default via "$sub.1" 2>/dev/null

  mkdir -p "/etc/netns/$ns"
  printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' > "/etc/netns/$ns/resolv.conf"

  sysctl -qw net.ipv4.ip_forward=1
  iptables -w 5 -t nat -C POSTROUTING -s "$cidr" -j MASQUERADE 2>/dev/null \
    || iptables -w 5 -t nat -A POSTROUTING -s "$cidr" -j MASQUERADE 2>/dev/null
  iptables -w 5 -C FORWARD -s "$cidr" -j ACCEPT 2>/dev/null \
    || iptables -w 5 -I FORWARD 1 -s "$cidr" -j ACCEPT 2>/dev/null
  iptables -w 5 -C FORWARD -d "$cidr" -j ACCEPT 2>/dev/null \
    || iptables -w 5 -I FORWARD 1 -d "$cidr" -j ACCEPT 2>/dev/null
  return 0
}

start_ovpn() {
  local slot=$1 cfg=$2 ns logf waited=0
  ns=$(ns_name "$slot")
  logf="$LOG_DIR/$ns.log"
  printf 'vpn\nvpn\n' > "$RUN_DIR/auth.txt"
  ip netns exec "$ns" openvpn \
    --config "$cfg" \
    --auth-user-pass "$RUN_DIR/auth.txt" \
    --auth-nocache \
    --dev tun0 \
    --connect-retry-max 1 \
    --connect-timeout 15 \
    --data-ciphers AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305 \
    --verb 3 \
    --daemon \
    --writepid "$RUN_DIR/$ns.pid" \
    --log "$logf" 9>&- 2>/dev/null || return 1
  while [ "$waited" -lt 30 ]; do
    if ip -n "$ns" -4 addr show tun0 2>/dev/null | grep -q 'inet '; then
      apply_pushed_dns "$ns"
      return 0
    fi
    sleep 1; waited=$((waited+1))
  done
  return 1
}

# 优先用 VPN 服务器自己推的 DNS（隧道内可达），再兜底公共 DNS。
# 只写 8.8.8.8 的话，节点一封 UDP 53，隧道里连域名都解析不了。
apply_pushed_dns() {
  local ns=$1 dns_file="/etc/netns/$1/resolv.conf" d seen=""
  mkdir -p "/etc/netns/$ns"
  {
    for d in $(grep -o 'dhcp-option DNS [0-9.]*' "$LOG_DIR/$ns.log" 2>/dev/null | awk '{print $3}' | sort -u); do
      case " $seen " in *" $d "*) continue ;; esac
      seen="$seen $d"
      printf 'nameserver %s\n' "$d"
    done
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n'
  } > "$dns_file" 2>/dev/null
  return 0
}

kill_ovpn() {
  local ns=$1 pidf pid
  pidf="$RUN_DIR/$ns.pid"
  if [ -s "$pidf" ]; then
    pid=$(cat "$pidf")
    kill "$pid" 2>/dev/null; sleep 0.3; kill -9 "$pid" 2>/dev/null
    rm -f "$pidf"
  fi
  pkill -f "openvpn.*$ns\.ovpn" 2>/dev/null
  pkill -f "netns exec $ns openvpn" 2>/dev/null
  return 0
}

teardown_slot() {
  local slot=$1 ns sub veth cidr
  ns=$(ns_name "$slot"); sub=$(ns_subnet "$slot"); veth="mxv$slot"; cidr="$sub.0/30"
  kill_ovpn "$ns"
  ip netns del "$ns" 2>/dev/null
  ip link del "$veth" 2>/dev/null
  iptables -w 5 -t nat -D POSTROUTING -s "$cidr" -j MASQUERADE 2>/dev/null
  iptables -w 5 -D FORWARD -s "$cidr" -j ACCEPT 2>/dev/null
  iptables -w 5 -D FORWARD -d "$cidr" -j ACCEPT 2>/dev/null
  rm -rf "/etc/netns/$ns"
  return 0
}

# 从 .ovpn 里取服务器地址（VPN Gate 的配置都是裸 IP）
ovpn_remote_ip() {
  awk '/^[[:space:]]*remote[[:space:]]/{print $2; exit}' "$1" 2>/dev/null
}

# netns 内的保险：只允许经 tun0 或回 VPN 服务器本身的流量出去。
# 隧道掉线时，其他流量一律 REJECT —— 宁可连不上，也不能漏出母机 IP。
install_killswitch() {
  local ns=$1 cfg=$2 srv
  srv=$(ovpn_remote_ip "$cfg")
  ip netns exec "$ns" iptables -w 5 -F OUTPUT 2>/dev/null
  ip netns exec "$ns" iptables -w 5 -A OUTPUT -o lo -j ACCEPT 2>/dev/null
  ip netns exec "$ns" iptables -w 5 -A OUTPUT -o tun0 -j ACCEPT 2>/dev/null
  [ -n "$srv" ] && ip netns exec "$ns" iptables -w 5 -A OUTPUT -d "$srv" -j ACCEPT 2>/dev/null
  ip netns exec "$ns" iptables -w 5 -A OUTPUT -j REJECT 2>/dev/null
  return 0
}

clear_fail() { rm -f "$BASE/fails/$1" 2>/dev/null; }

bump_fail() {
  local slot=$1 f n
  mkdir -p "$BASE/fails"
  f="$BASE/fails/$slot"
  n=0
  [ -f "$f" ] && n=$(cat "$f" 2>/dev/null || echo 0)
  n=$((n+1))
  printf '%s' "$n" > "$f"
  printf '%s' "$n"
}

# 不走 DNS 的探测：Cloudflare trace 端点支持 IP 字面量访问，回包里带 ip=
# （隧道内的 DNS 常常比隧道本身先挂，拿 DNS 判死会把好隧道误杀）
cf_trace_ip() {
  local ns=$1 out
  out=$(ip netns exec "$ns" curl -s -4 --max-time 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null \
        | sed -n 's/^ip=//p' | head -1 | tr -d '\r\n ')
  if [[ "$out" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then printf '%s' "$out"; return 0; fi
  return 1
}

# 体检用的快速探测：先打 IP 字面量，不行再退回域名；单轮只试一次，靠连续两轮判死
probe_exit_fast() {
  local ns=$1 out
  out=$(cf_trace_ip "$ns") && { printf '%s' "$out"; return 0; }
  out=$(ip netns exec "$ns" curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '\r\n ')
  if [[ "$out" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then printf '%s' "$out"; return 0; fi
  return 1
}

probe_exit() {
  local ns=$1 url out
  out=$(cf_trace_ip "$ns") && { printf '%s' "$out"; return 0; }
  for url in $PROBE_URLS; do
    out=$(ip netns exec "$ns" curl -4 -fsS --max-time 8 "$url" 2>/dev/null | tr -d '\r\n ')
    if [[ "$out" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then printf '%s' "$out"; return 0; fi
  done
  return 1
}

# ---------------------------------------------------------------- 槽位状态
slot_state_file() { printf '%s/%s.env' "$SLOT_DIR" "$1"; }

write_slot() {
  local slot=$1 port=$2 cc=$3 country=$4 exitip=$5 host=$6 status=$7
  {
    printf 'SLOT=%q\n' "$slot"
    printf 'PORT=%q\n' "$port"
    printf 'NS=%q\n' "$(ns_name "$slot")"
    printf 'CC=%q\n' "$cc"
    printf 'COUNTRY=%q\n' "$country"
    printf 'EXITIP=%q\n' "$exitip"
    printf 'HOSTNAME=%q\n' "$host"
    printf 'STATUS=%q\n' "$status"
    printf 'SINCE=%q\n' "$(date +%s)"
  } > "$(slot_state_file "$slot")"
}

read_slot() {
  local f; f=$(slot_state_file "$1")
  [ -f "$f" ] || return 1
  . "$f"
}

# 端口一旦分配就固定下来：换节点、重建进程都不改端口，
# 已经分发出去的客户端配置才不会失效。
slot_port() {
  local want=$BASE_PORT slot want_port port f other
  want=$1
  want_port=$((BASE_PORT + want))
  local f2 still=1
  while [ "$still" = 1 ]; do
    still=0
    for f2 in "$SLOT_DIR"/*.env; do
      [ -f "$f2" ] || continue
      other=$(basename "$f2" .env)
      [ "$other" = "$want" ] && continue
      port=$( . "$f2"; printf '%s' "${PORT:-}" )
      [ "$port" = "$want_port" ] && { want_port=$((want_port+1)); still=1; break; }
    done
  done
  printf '%s' "$want_port"
}

# 当前槽位已经分配过的端口（有就复用）
existing_port() {
  local f; f=$(slot_state_file "$1")
  [ -f "$f" ] || return 1
  ( . "$f"; [ -n "${PORT:-}" ] && printf '%s' "$PORT" )
}

sync_exits_tsv() {
  local tmp f
  # 并发建隧道时多个写入方会撞在同一个临时文件上，用唯一文件名避开
  tmp=$(mktemp "$BASE/exits.XXXXXX") || return 0
  : > "$tmp"
  for f in "$SLOT_DIR"/*.env; do
    [ -f "$f" ] || continue
    ( . "$f"; [ "${STATUS:-}" = up ] && printf '%s\t%s\t%s\n' "$SLOT" "$PORT" "$NS" >> "$tmp" )
  done
  mv "$tmp" "$EXITS_TSV"
}

# ---------------------------------------------------------------- 起一条出口
bring_up_slot() {
  local slot=$1 tries=0 port ns node host ip cc country path exitip hip
  ns=$(ns_name "$slot")
  port=$(existing_port "$slot") || port=$(slot_port "$slot")
  hip=$(host_ip)
  # 先把这条出口摘下来（分发器会关掉对应监听），重建期间客户端拿到的是明确的拒绝，
  # 而不是一个半成品连接。
  write_slot "$slot" "$port" "" "" "" "" down
  sync_exits_tsv
  while [ "$tries" -lt "$MAX_TRIES" ]; do
    tries=$((tries+1))
    if ! node=$(pick_node); then
      warn "slot $slot: 节点池没有可用节点了"
      return 1
    fi
    IFS=$'\t' read -r host ip cc country path <<< "$node"
    teardown_slot "$slot"
    if ! setup_netns "$slot"; then warn "slot $slot: netns 建立失败"; continue; fi
    # 保险先装：此刻只有"回 VPN 服务器"这一条路是通的，
    # tun0 还没起来之前任何连接都会被 REJECT，不会漏出母机 IP。
    install_killswitch "$ns" "$path"
    if ! start_ovpn "$slot" "$path"; then
      log "slot $slot: $host 连不上（候选 $tries）"
      teardown_slot "$slot"; continue
    fi
    if ! exitip=$(probe_exit "$ns"); then
      log "slot $slot: $host 探不到出口 IP（候选 $tries）"
      teardown_slot "$slot"; continue
    fi
    if [ "$exitip" = "$hip" ]; then
      log "slot $slot: $host 出口仍是母机 IP，判隧道没起（候选 $tries）"
      teardown_slot "$slot"; continue
    fi
    write_slot "$slot" "$port" "$cc" "$country" "$exitip" "$host" up
    clear_fail "$slot"
    sync_exits_tsv
    ok "slot $slot  port $port  $cc  $host  -> $exitip"
    return 0
  done
  warn "slot $slot: $MAX_TRIES 个候选都失败"
  write_slot "$slot" "$port" "" "" "" "" down
  return 1
}

auto_count() {
  local avail n
  avail=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
  n=$(( (avail - 200) / MEM_PER_EXIT ))
  [ "$n" -lt 4 ] && n=4
  [ "$n" -gt 80 ] && n=80
  printf '%s' "$n"
}

scale_to() {
  local want=$1 slot=0 running
  [ "$want" = auto ] && want=$(auto_count)
  ensure_nodes
  log "目标出口数: $want（并行 $PARALLEL）"
  mkdir -p "$SLOT_DIR"
  while [ "$slot" -lt "$want" ]; do
    if read_slot "$slot" 2>/dev/null && [ "${STATUS:-}" = up ] && [ -e "/var/run/netns/$(ns_name "$slot")" ]; then
      slot=$((slot+1)); continue
    fi
    ( bring_up_slot "$slot" ) &
    while :; do
      running=$(jobs -rp | wc -l)
      [ "$running" -lt "$PARALLEL" ] && break
      sleep 1
    done
    slot=$((slot+1))
  done
  wait
  sync_exits_tsv
}

# ---------------------------------------------------------------- 命令
cmd_install() {
  need_root
  local count=auto
  while [ $# -gt 0 ]; do
    case "$1" in
      --count) count=$2; shift 2 ;;
      --count=*) count=${1#*=}; shift ;;
      *) shift ;;
    esac
  done
  log "安装依赖…"
  install_deps
  mkdir -p "$BASE" "$SLOT_DIR" "$LOG_DIR" "$RUN_DIR" "$OVPN_DIR" "$OPT_DIR"
  printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-massexit.conf
  sysctl -qw net.ipv4.ip_forward=1

  if [ ! -f "$CONF" ]; then
    cat > "$CONF" <<EOF
# massexit 配置，改完执行 massexit restart
BASE_PORT=$BASE_PORT
COUNT=$count
PARALLEL=$PARALLEL
RESIDENTIAL_ONLY=$RESIDENTIAL_ONLY
MAX_TRIES=$MAX_TRIES
REFRESH_HOURS=$REFRESH_HOURS
MEM_PER_EXIT=$MEM_PER_EXIT
HEALTH_SEC=$HEALTH_SEC
PROBE_URLS="$PROBE_URLS"
EOF
  fi
  if [ ! -s "$CRED" ]; then
    printf 'msx:%s\n' "$(openssl rand -hex 8)" > "$CRED"
    chmod 600 "$CRED"
  fi

  # 本地目录里跑（clone 下来）就就地取材；curl | bash 那种没有实体文件，走远程
  local src=""
  [ -f "$0" ] && src="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
  if [ -n "$src" ] && [ -f "$src/lib/massexitd.py" ]; then
    install -m 0755 "$src/lib/massexitd.py" "$DAEMON"
  else
    log "拉取 massexitd.py…"
    curl -fsSL "$RAW_URL/lib/massexitd.py" -o "$DAEMON" || die "拿不到 massexitd.py"
    chmod 0755 "$DAEMON"
  fi
  if [ -f "$0" ]; then
    install -m 0755 "$0" "$SELF"
  else
    curl -fsSL "$RAW_URL/massexit.sh" -o "$SELF" || die "拿不到 massexit.sh"
    chmod 0755 "$SELF"
  fi

  cat > /usr/local/bin/massexit <<'WRAP'
#!/bin/sh
exec bash /opt/massexit/massexit.sh "$@"
WRAP
  chmod 0755 /usr/local/bin/massexit

  cat > "$UNIT" <<EOF
[Unit]
Description=massexit SOCKS5 multi-exit dispatcher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=MASSEXIT_BASE=$BASE
ExecStart=/usr/bin/env python3 $DAEMON
Restart=always
RestartSec=3
LimitNOFILE=131072

[Install]
WantedBy=multi-user.target
EOF

  cat > "$HSVC" <<'EOF'
[Unit]
Description=massexit health check

[Service]
Type=oneshot
TimeoutStartSec=0
ExecStart=/usr/local/bin/massexit health --quiet
EOF

  cat > "$HTIMER" <<EOF
[Unit]
Description=massexit 定时体检

[Timer]
OnBootSec=3min
OnUnitActiveSec=${HEALTH_SEC}s
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now massexit.service >/dev/null 2>&1
  systemctl enable --now massexit-health.timer >/dev/null 2>&1
  ok "服务已安装（python3 分发器 + systemd 定时体检）"

  log "铺出口…"
  scale_to "$count"
  cmd_info
}

cmd_up() {
  need_root
  local want=${1:-${COUNT:-auto}}
  mkdir -p "$SLOT_DIR" "$LOG_DIR" "$RUN_DIR" "$OVPN_DIR"
  scale_to "$want"
  systemctl start massexit.service >/dev/null 2>&1 || true
  sync_exits_tsv
  cmd_info
}

cmd_down() {
  need_root
  local f slot
  for f in "$SLOT_DIR"/*.env; do
    [ -f "$f" ] || continue
    slot=$(basename "$f" .env)
    teardown_slot "$slot"
    rm -f "$f"
  done
  : > "$EXITS_TSV"
  ok "所有出口已拆除"
}

cmd_status() {
  local f up
  printf '%-4s %-6s %-4s %-16s %-30s %s\n' SLOT PORT CC 出口IP 节点 状态
  for f in "$SLOT_DIR"/*.env; do
    [ -f "$f" ] || continue
    ( . "$f"
      mark="${C_R}down${C_0}"
      if [ "${STATUS:-}" = up ] && [ -e "/var/run/netns/$NS" ]; then mark="${C_G}up${C_0}"; fi
      printf '%-4s %-6s %-4s %-16s %-30s %s\n' "$SLOT" "${PORT:-}" "${CC:--}" "${EXITIP:--}" "${HOSTNAME:--}" "$mark" )
  done
  echo
  up=$(grep -c . "$EXITS_TSV" 2>/dev/null || echo 0)
  printf '监听中出口: %s   节点池: %s   母机 IP: %s\n' "$up" "$(wc -l < "$NODES" 2>/dev/null || echo 0)" "$(host_ip)"
}

cmd_links() {
  local f hip cred
  hip=$(host_ip)
  cred=$(cat "$CRED" 2>/dev/null || echo "msx:")
  for f in "$SLOT_DIR"/*.env; do
    [ -f "$f" ] || continue
    ( . "$f"
      [ "${STATUS:-}" = up ] || exit 0
      printf 'socks5h://%s@%s:%s#%s-%s\n' "$cred" "$hip" "${PORT}" "${CC:-XX}" "${EXITIP:-}" )
  done
}

cmd_sub() {
  if [ "${1:-}" = "--links" ]; then cmd_links; else cmd_links | base64 -w0; echo; fi
}

cmd_info() {
  local hip cred
  hip=$(host_ip)
  cred=$(cat "$CRED" 2>/dev/null || echo "msx:")
  echo
  printf '%s\n' "${C_B}== massexit 连接信息 ==${C_0}"
  printf '母机        %s\n' "$hip"
  printf 'SOCKS 认证  %s\n' "$cred"
  printf '出口数      %s\n' "$(grep -c . "$EXITS_TSV" 2>/dev/null || echo 0)"
  printf '端口范围    %s - %s\n' "$BASE_PORT" "$((BASE_PORT + 199))"
  echo
  printf '%s\n' "${C_B}== 全部节点 ==${C_0}"
  cmd_links
  echo
  printf '订阅 base64: massexit sub\n订阅明文    : massexit sub --links\n'
}

cmd_health() {
  local quiet=0
  [ "${1:-}" = --quiet ] && quiet=1
  exec 9>"$BASE/health.lock"
  # 定时任务抢不到锁就直接跳过（不然上一轮还没跑完，下一轮又叠上来一起重建）；
  # 手动跑的愿意等一会儿
  if [ "$quiet" = 1 ]; then
    flock -n 9 || { log "上轮体检还没跑完，这轮跳过"; return 0; }
  else
    flock -w 60 9 || { log "等不到体检锁，上轮还在跑"; return 0; }
  fi
  ensure_nodes 2>/dev/null || true

  local hip tmpd f slot ns port cc country host status cur old n
  local changed=0 total=0
  local -a broken=()
  hip=$(host_ip)
  tmpd=$(mktemp -d "$BASE/health.XXXXXX")

  # 探测并行跑：几十条出口一起掉线时，串行探测一条 14 秒能拖十分钟
  for f in "$SLOT_DIR"/*.env; do
    [ -f "$f" ] || continue
    total=$((total+1))
    slot=$(basename "$f" .env)
    (
      . "$f"
      cur=""
      if [ "${STATUS:-}" = up ] && [ -e "/var/run/netns/${NS}" ]; then
        cur=$(probe_exit_fast "${NS}" || true)
      fi
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$SLOT" "${NS}" "${PORT:-}" "${CC:-}" "${COUNTRY:-}" "${HOSTNAME:-}" "${EXITIP:-}" "${STATUS:-}" "$cur" \
        > "$tmpd/$(printf '%03d' "$SLOT")"
    ) &
    while [ "$(jobs -rp | wc -l)" -ge 10 ]; do sleep 0.2; done
  done
  wait

  # 结果顺序处理：判死、记 IP 变化、排队重建
  for f in "$tmpd"/*; do
    [ -f "$f" ] || continue
    IFS=$'\t' read -r slot ns port cc country host old status cur < "$f"
    if [ "$status" != up ] || [ -z "$cur" ] || [ "$cur" = "$hip" ]; then
      if [ "$status" != up ]; then
        log "slot $slot 掉线，进重建队列（端口 $port）"
        broken+=("$slot")
      else
        n=$(bump_fail "$slot")
        if [ "$n" -lt 2 ]; then
          log "slot $slot 首次探测失败（${cur:-空}），再观察一轮"
        else
          log "slot $slot 连续 $n 次不通，进重建队列（端口 $port 不变）"
          broken+=("$slot")
        fi
      fi
      continue
    fi
    clear_fail "$slot"
    if [ "$cur" != "$old" ]; then
      log "slot $slot 出口 IP 变化 $old -> $cur"
      write_slot "$slot" "$port" "$cc" "$country" "$cur" "$host" up
      changed=$((changed+1))
    fi
  done
  rm -rf "$tmpd"

  # 重建并行跑
  local s
  if [ "${#broken[@]}" -gt 0 ]; then
    for s in "${broken[@]}"; do
      [ -n "$s" ] || continue
      ( teardown_slot "$s"; bring_up_slot "$s" >/dev/null 2>&1 ) &
      while [ "$(jobs -rp | wc -l)" -ge "$HEALTH_PARALLEL" ]; do sleep 0.5; done
      changed=$((changed+1))
    done
    wait
  fi
  sync_exits_tsv
  [ "$quiet" = 0 ] && ok "体检完成: $total 条出口，修复 $changed 条"
  return 0
}

cmd_swap() {
  need_root
  local slot=${1:-0}
  read_slot "$slot" || die "没有 slot $slot"
  log "slot $slot 换节点（端口不变）…"
  teardown_slot "$slot"
  bring_up_slot "$slot" || die "slot $slot 换节点失败"
  sync_exits_tsv
  ok "slot $slot 已换好"
}

cmd_restart() {
  need_root
  local want=${1:-${COUNT:-auto}}
  cmd_down >/dev/null 2>&1
  printf '%s\n' "$want" > /dev/null
  cmd_up "$want" >/dev/null 2>&1
  systemctl restart massexit.service >/dev/null 2>&1
  sync_exits_tsv
  cmd_status
}

# 端到端自检：从本机走每条出口的 SOCKS 端口拿一次出口 IP，比对登记值
cmd_check() {
  local cred f tmpd s p c w g ok=0 bad=0
  cred=$(cat "$CRED" 2>/dev/null || echo "msx:")
  tmpd=$(mktemp -d /tmp/massexit-check.XXXXXX)
  for f in "$SLOT_DIR"/*.env; do
    [ -f "$f" ] || continue
    ( . "$f"
      got=$(curl -s --max-time 12 --socks5-hostname "$cred@127.0.0.1:${PORT}" https://api.ipify.org 2>/dev/null | tr -d '\r\n ')
      printf '%s\t%s\t%s\t%s\t%s\n' "$SLOT" "$PORT" "${CC:-?}" "${EXITIP:--}" "${got:--}" > "$tmpd/$(printf '%03d' "$SLOT")" ) &
    while [ "$(jobs -rp | wc -l)" -ge 10 ]; do sleep 0.3; done
  done
  wait
  printf '%-4s %-6s %-4s %-16s %-16s %s\n' SLOT PORT CC 登记IP 实测IP 结果
  for f in "$tmpd"/*; do
    [ -f "$f" ] || continue
    IFS=$'\t' read -r s p c w g < "$f"
    if [ "$g" = "$w" ]; then
      ok=$((ok+1)); printf '%-4s %-6s %-4s %-16s %-16s %s\n' "$s" "$p" "$c" "$w" "$g" ok
    else
      bad=$((bad+1)); printf '%-4s %-6s %-4s %-16s %-16s %s\n' "$s" "$p" "$c" "$w" "$g" "${C_R}异常${C_0}"
    fi
  done
  rm -rf "$tmpd"
  printf '\n正常 %s 条，异常 %s 条\n' "$ok" "$bad"
  [ "$bad" = 0 ]
}

cmd_logs() { journalctl -u massexit.service -n 100 --no-pager; }

cmd_uninstall() {
  need_root
  systemctl disable --now massexit-health.timer >/dev/null 2>&1
  systemctl disable --now massexit.service >/dev/null 2>&1
  cmd_down >/dev/null 2>&1
  rm -f "$UNIT" "$HSVC" "$HTIMER" /usr/local/bin/massexit /etc/sysctl.d/90-massexit.conf
  rm -rf "$OPT_DIR" "$BASE"
  systemctl daemon-reload >/dev/null 2>&1
  ok "已卸载"
}

usage() {
  cat <<'EOF'
massexit — VPN Gate 出口铺成 SOCKS5 节点（一条出口一个端口）

  install [--count N|auto]   一键装机 + 铺出口 + 打印全部节点
  up [N|auto]                补/铺到 N 条出口
  status                     出口一览
  links                      全部 socks5h:// 节点链接
  sub [--links]              订阅内容（默认 base64）
  info                       连接信息 + 全部节点
  health [--quiet]           体检并自动修复/换节点
  swap N                     第 N 条出口换一个新节点（端口不变）
  check                      端到端自检：每条出口实拿一次 IP 并比对
  restart [N|auto]           全部重建
  down                       拆掉所有出口
  logs                       服务日志
  uninstall                  卸载
EOF
}

main() {
  local cmd=${1:-help}
  [ $# -gt 0 ] && shift
  case "$cmd" in
    install) cmd_install "$@" ;;
    up) cmd_up "$@" ;;
    down) cmd_down ;;
    status) cmd_status ;;
    links) cmd_links ;;
    sub) cmd_sub "$@" ;;
    info) cmd_info ;;
    health) cmd_health "$@" ;;
    swap) cmd_swap "$@" ;;
    check) cmd_check ;;
    restart) cmd_restart "$@" ;;
    logs) cmd_logs ;;
    uninstall|remove) cmd_uninstall ;;
    version|-v|--version) echo "massexit 1.0" ;;
    help|-h|--help|*) usage ;;
  esac
}

mkdir -p "$BASE" 2>/dev/null
main "$@"
