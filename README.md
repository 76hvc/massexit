# massexit

把 VPN Gate 的可用出口，一次性铺成一排 SOCKS5 端口：**一个端口 = 一个出口 IP**。

设计照抄 [byJoey/fanout](https://github.com/byJoey/fanout) 的内核——每条隧道住在自己的
network namespace 里，母机只负责监听和转发——但换成了命令行批量版：

| | fanout | massexit |
|---|---|---|
| 交互 | 网页点一条开一条 | `massexit up 40` 一次铺满 |
| 进程 | 每条隧道一个 goroutine，单进程 | 单进程 Python 分发器 |
| 用途 | 给 3x-ui / Xray 挂节点链接 | 直接产出大量 `socks5h://` 节点与订阅 |
| 掉线兜底 | 比对出口 IP，连续两次不符自动换节点 | 同样体检 + netns 内 kill switch 防漏 |

## 原理

```
客户端 ──> 母机 SOCKS5 :20000 ──> setns(mx3) ──> openvpn tun0 ──> VPN Gate 节点 A
        ──> 母机 SOCKS5 :20001 ──> setns(mx1) ──> openvpn tun0 ──> VPN Gate 节点 B
```

* 每条出口一个 netns（`mx0`、`mx1`…），里面只跑一个 openvpn，默认路由被 tun0 吃掉。
* SOCKS5 监听留在母机（netns 的 loopback 和母机互不相通，监听放里面外面连不上）。
* 每来一个连接，分发器把**这个线程** `setns` 进目标 netns 再建 socket，出口就跟着隧道走。
  netns 是 per-thread 属性，切过的线程不影响别的连接。
* 一个 Python 进程管所有端口，40 条出口也只占十几 MB，`openvpn` 每个约 9 MB。

### 两条保险

1. **netns 内 kill switch**：OUTPUT 只放行 `lo`、`tun0` 和 VPN 服务器本身，其余 REJECT。
   隧道断了就**连不上**，不会偷偷从母机 IP 出去。
2. **出口 IP 体检**：探测打的是 `https://1.1.1.1/cdn-cgi/trace` 这类 IP 字面量端点，不依赖隧道内 DNS
   （隧道里 DNS 往往比隧道先挂，拿域名判死会误杀好隧道）；连续两轮不符或探不到就换节点，
   **端口不变**，已发出去的客户端配置继续能用。探测和重建都并行，几十条一起掉线也能一两轮修回来。

## 安装

要求 root、Linux、`/dev/net/tun` 可用（LXC 小鸡常被禁，`ls /dev/net/tun` 说没有就免谈）。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/76hvc/massexit/main/massexit.sh) install --count 30
```

一条命令做完：装依赖（openvpn / curl / iptables / python3，apt·dnf·yum·pacman·apk·zypper 都认）→
装 `massexitd` 分发器 + systemd 服务 → 拉 VPN Gate 列表 → 批量建隧道 → 打印全部节点。

装完命令就叫 `massexit`（软链在 `/usr/local/bin`）。

## 日常

| 命令 | 作用 |
|---|---|
| `massexit status` | 每条出口：槽位 / 端口 / 国家 / 出口 IP / 节点 / 状态 |
| `massexit links` | 全部 `socks5h://` 链接 |
| `massexit sub` | base64 订阅内容（加 `--links` 要明文） |
| `massexit up 60` | 补到 60 条，已有的不动 |
| `massexit health` | 手动体检，systemd timer 每 5 分钟也会跑 |
| `massexit check` | 端到端自检：每条出口实拿一次 IP 并与登记值比对 |
| `massexit swap 3` | 第 3 条换新节点，端口不变 |
| `massexit restart 20` | 全拆重建 |
| `massexit down` | 拆掉所有出口 |
| `massexit logs` | 分发器日志 |
| `massexit uninstall` | 卸干净 |

节点链接长这样：

```
socks5h://msx:鉴权口令@1.2.3.4:20000#JP-115.37.246.110
```

`socks5h` 表示域名交给出口侧解析（分发器在隧道内解析），不会泄露本地 DNS。

## 配置

`/var/lib/massexit/config`：

| 项 | 默认 | 说明 |
|---|---|---|
| `BASE_PORT` | 20000 | 起始端口；第 N 条出口 = BASE_PORT+N，分配后固定不变 |
| `PARALLEL` | 6 | 同时建几条隧道（2 核机器别开太大） |
| `RESIDENTIAL_ONLY` | 1 | 只用志愿者家宽，排除 VPN Gate 自营机房（`public-vpn-*`、`219.100.37.0/24`） |
| `MAX_TRIES` | 6 | 一个槽位连几个候选都失败就放弃本轮 |
| `REFRESH_HOURS` | 6 | 节点列表多久重拉一次 |
| `MEM_PER_EXIT` | 30 | 自动算出口数时每条预留多少 MB |
| `HEALTH_SEC` | 300 | 体检间隔 |
| `HEALTH_PARALLEL` | 4 | 体检时并行重建几条 |

```bash
massexit down && massexit up auto     # 改完配置这样重来
```

## 规模

VPN Gate 的 API 每次大约给 100 个节点（家宽 80-90），拉三份合并去重就是节点池上限；
一个出口一个出口 IP，所以天花板基本是**池子里还有多少没用过的 IP**。
内存按每个 openvpn ~9 MB 估，1 GB 小鸡跑到 40-50 条就差不多。

## 已知限制

* SOCKS5 只做 `CONNECT`（TCP），`UDP ASSOCIATE` 返回 0x07。QUIC 之类要走 TCP。
* VPN Gate 是志愿者节点，一批随时满员/下线（`AUTH_FAILED`，或者 `Inactivity timeout` 之后连不上），
  建隧道时会顺着候选往下试；已经连上的高峰期也可能被掐，所以要 5 分钟一轮体检兜着。
* 公网端口要自己放行（iptables / 云厂商安全组）。
* 没有流量统计和限速；要这些就前面再挂个 sing-box / xray。

## 许可

MIT。节点来自 [VPN Gate](https://www.vpngate.net/)（筑波大学学术实验项目），
本工具只是拉它的公开列表、用官方 openvpn 客户端连接。
