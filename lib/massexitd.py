#!/usr/bin/env python3
"""massexitd -- 单进程 SOCKS5 多出口分发器。

一条出口 = 一个 network namespace（里面有 openvpn 拉起的 tun0）
         + 母机上的一个 SOCKS5 监听端口。

监听必须留在母机侧（netns 里的 loopback 和母机互不相通），
出站 socket 在 setns 切进对应 netns 之后才创建，所以：
  * 隧道的路由劫持只影响自己的 netns，不会切断母机网络
  * 隧道之间互不干扰，各自一个出口 IP
  * 整个进程只占一份内存，几百个端口也不过几十 MB

出口清单从 <BASE>/exits.tsv 热加载（改文件不用重启进程）：
    slot <TAB> port <TAB> ns [<TAB> user:pass]

认证：<BASE>/socks.cred 一行 "user:pass"，文件不存在则不校验。
只做 CONNECT（TCP）；UDP ASSOCIATE 返回 0x07。
域名在本进程内、切进隧道之后解析，避免 DNS 泄露到母机。
"""
import ctypes
import errno
import os
import socket
import struct
import sys
import threading
import time

BASE = os.environ.get("MASSEXIT_BASE", "/var/lib/massexit")
EXITS_TSV = os.path.join(BASE, "exits.tsv")
CRED_FILE = os.path.join(BASE, "socks.cred")
NS_DIR = "/var/run/netns"

CLONE_NEWNET = 0x40000000
BUFSIZE = 65536
CONNECT_TIMEOUT = 15
HANDSHAKE_TIMEOUT = 25

try:
    _libc = ctypes.CDLL("libc.so.6", use_errno=True)
except OSError:  # pragma: no cover
    _libc = None

_log_lock = threading.Lock()


def log(msg):
    with _log_lock:
        sys.stdout.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
        sys.stdout.flush()


def setns_path(path):
    """把当前线程切进 path 指向的 netns。

    netns 是 per-thread 的：切了只影响调用线程，别的工作线程照旧在母机。
    所以每个连接线程都得自己切一次 —— socket 的归属在创建那一刻就定了。
    """
    fd = os.open(path, os.O_RDONLY)
    try:
        if _libc is not None:
            if _libc.setns(fd, CLONE_NEWNET) != 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))
        elif hasattr(os, "setns"):
            os.setns(fd, CLONE_NEWNET)
        else:  # pragma: no cover
            raise OSError(errno.ENOSYS, "setns 不可用")
    finally:
        os.close(fd)


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def parse_cred(raw):
    raw = (raw or "").strip()
    if not raw:
        return None
    user, _, password = raw.partition(":")
    return (user.encode(), password.encode())


class Exit(object):
    __slots__ = ("slot", "port", "ns", "ns_path", "listener", "cred")

    def __init__(self, slot, port, ns, cred):
        self.slot = slot
        self.port = port
        self.ns = ns
        self.ns_path = os.path.join(NS_DIR, ns)
        self.listener = None
        self.cred = cred

    def key(self):
        return (self.port, self.ns)


class Server(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.exits = {}
        self.mtime = -1.0

    # ---------- 配置热加载 ----------

    def load(self):
        try:
            with open(CRED_FILE) as fh:
                cred = parse_cred(fh.read())
        except OSError:
            cred = None

        wanted = {}
        try:
            with open(EXITS_TSV) as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line or line.startswith("#"):
                        continue
                    cols = line.split("\t")
                    if len(cols) < 3:
                        continue
                    try:
                        slot = int(cols[0])
                        port = int(cols[1])
                    except ValueError:
                        continue
                    ns = cols[2].strip()
                    if not ns:
                        continue
                    row_cred = parse_cred(cols[3]) if len(cols) > 3 else None
                    wanted[(port, ns)] = Exit(slot, port, ns, row_cred or cred)
        except OSError:
            wanted = {}

        with self.lock:
            added = [w for k, w in wanted.items() if k not in self.exits]
            dropped = [e for k, e in self.exits.items() if k not in wanted]
            for key, want in wanted.items():
                if key in self.exits:
                    self.exits[key].slot = want.slot
                    self.exits[key].cred = want.cred

        for ex in dropped:
            self.stop_exit(ex, "从配置移除")
        for ex in added:
            self.start_exit(ex)

    def reload_if_changed(self):
        try:
            mtime = os.path.getmtime(EXITS_TSV)
        except OSError:
            mtime = 0.0
        if mtime != self.mtime:
            self.mtime = mtime
            self.load()

    # ---------- 监听 ----------

    def start_exit(self, ex):
        if not os.path.exists(ex.ns_path):
            log("跳过 port=%d ns=%s: netns 还不存在" % (ex.port, ex.ns))
            return
        sock = None
        for attempt in range(6):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", ex.port))
                sock.listen(256)
                break
            except OSError as exc:
                if sock is not None:
                    sock.close()
                    sock = None
                if attempt == 5:
                    log("监听 port=%d 失败: %s" % (ex.port, exc))
                    return
                time.sleep(1)
        ex.listener = sock
        with self.lock:
            self.exits[ex.key()] = ex
        threading.Thread(target=self.accept_loop, args=(ex,), daemon=True).start()
        log("监听 port=%d -> netns %s (slot %d)" % (ex.port, ex.ns, ex.slot))

    def stop_exit(self, ex, why=""):
        with self.lock:
            self.exits.pop(ex.key(), None)
        if ex.listener is not None:
            try:
                ex.listener.close()
            except OSError:
                pass
            ex.listener = None
        log("关闭 port=%d (%s)" % (ex.port, why))

    def accept_loop(self, ex):
        while True:
            listener = ex.listener
            if listener is None:
                return
            try:
                conn, _addr = listener.accept()
            except OSError:
                return
            threading.Thread(target=self.serve_conn, args=(ex, conn), daemon=True).start()

    # ---------- 单条连接 ----------

    def serve_conn(self, ex, conn):
        target = "?"
        upstream = None
        try:
            conn.settimeout(HANDSHAKE_TIMEOUT)
            if not self.negotiate(conn, ex.cred):
                return
            cmd, host, port = self.read_request(conn)
            if cmd != 0x01:
                self.reply(conn, 0x07)  # 只支持 CONNECT
                return
            target = "%s:%s" % (host, port)

            origin = os.open("/proc/self/ns/net", os.O_RDONLY)
            try:
                setns_path(ex.ns_path)
                upstream = connect_in_ns(host, port)
            finally:
                os.close(origin)
            if upstream is None:
                self.reply(conn, 0x05)
                return

            self.reply(conn, 0x00)
            conn.settimeout(None)
            upstream.settimeout(None)
            log("conn port=%d -> %s" % (ex.port, target))
            relay(conn, upstream)
        except (ConnectionError, OSError, ValueError, LookupError) as exc:
            log("conn port=%d -> %s 失败: %s" % (ex.port, target, exc))
        except Exception as exc:  # 单条连接的意外不该带走监听
            log("conn port=%d -> %s 异常: %r" % (ex.port, target, exc))
        finally:
            for s in (conn, upstream):
                if s is None:
                    continue
                try:
                    s.close()
                except OSError:
                    pass

    def negotiate(self, conn, cred):
        head = read_exact(conn, 2)
        if head[0] != 0x05:
            return False
        methods = read_exact(conn, head[1])
        need = 0x02 if cred else 0x00
        if need not in methods:
            conn.sendall(b"\x05\xff")
            return False
        conn.sendall(bytes([0x05, need]))
        if not cred:
            return True
        ver = read_exact(conn, 2)
        if ver[0] != 0x01:
            return False
        user = read_exact(conn, ver[1])
        plen = read_exact(conn, 1)[0]
        password = read_exact(conn, plen)
        if (user, password) == cred:
            conn.sendall(b"\x01\x00")
            return True
        conn.sendall(b"\x01\x01")
        return False

    def read_request(self, conn):
        head = read_exact(conn, 4)
        if head[0] != 0x05:
            raise ValueError("版本不对")
        cmd, atyp = head[1], head[3]
        if atyp == 0x01:
            host = socket.inet_ntoa(read_exact(conn, 4))
        elif atyp == 0x03:
            host = read_exact(conn, read_exact(conn, 1)[0]).decode("ascii", "replace").rstrip(".")
        elif atyp == 0x04:
            host = socket.inet_ntop(socket.AF_INET6, read_exact(conn, 16))
        else:
            raise ValueError("atyp 不支持")
        port = struct.unpack("!H", read_exact(conn, 2))[0]
        return cmd, host, port

    def reply(self, conn, code):
        conn.sendall(b"\x05" + bytes([code, 0x00, 0x01]) + b"\x00\x00\x00\x00" + b"\x00\x00")


def connect_in_ns(host, port):
    """当前线程已经在目标 netns 里了，这里建 socket 就落在隧道内。"""
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    last = None
    for family, socktype, proto, _canon, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(CONNECT_TIMEOUT)
        try:
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last = exc
            sock.close()
    if last is not None:
        log("连接 %s:%s 失败: %s" % (host, port, last))
    return None


def relay(a, b):
    """双向转发；任一端关闭就收尾。"""
    done = threading.Event()

    def pump(src, dst):
        try:
            while not done.is_set():
                chunk = src.recv(BUFSIZE)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            done.set()
            for sock in (src, dst):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    back = threading.Thread(target=pump, args=(b, a), daemon=True)
    back.start()
    pump(a, b)
    back.join(timeout=5)


def main():
    srv = Server()
    log("massexitd 启动 exits=%s" % EXITS_TSV)
    srv.reload_if_changed()
    if not srv.exits:
        log("暂时没有出口，等 exits.tsv")
    while True:
        try:
            srv.reload_if_changed()
        except Exception as exc:  # 一次加载失败不该拖垮进程
            log("reload 失败: %s" % exc)
        time.sleep(3)


if __name__ == "__main__":
    main()
