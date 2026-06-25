#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fnTerm — 纯原生 Web 终端服务 (fnOS 统一网关版)

仅使用 Python 标准库实现：
  * 监听 Unix Domain Socket（由 fnOS 统一网关转发，无需暴露端口）
  * HTTP 静态文件服务（自动剥离网关前缀 /app/<appname>）
  * 手写 RFC6455 WebSocket 握手与帧编解码
  * pty.fork 分配真实伪终端，运行登录 shell
  * select 双向转发，TIOCSWINSZ 处理窗口尺寸
  * 读取统一网关注入的 X-Trim-* 头做鉴权

无任何第三方依赖、无需编译、不下载任何外部二进制（如 ttyd）。
"""

import base64
import hashlib
import json
import os
import pty
import select
import signal
import socket
import socketserver
import struct
import sys
import termios
import threading
import fcntl
import uuid
import time
import pwd
from urllib.parse import urlparse, parse_qs, unquote

# ----------------------------------------------------------------------------
# 配置（由环境变量注入，含本地调试默认值）
# ----------------------------------------------------------------------------
APPNAME = os.environ.get("FNTERM_APPNAME", "fnterm")
GATEWAY_PREFIX = os.environ.get("FNTERM_GATEWAY_PREFIX", "/app/fnnas-fnterm").rstrip("/")
SOCK_PATH = os.environ.get("FNTERM_SOCK", os.path.join(os.getcwd(), "app.sock"))
TCP_PORT = os.environ.get("FNTERM_TCP_PORT")  # 仅本地调试用


def _resolve_webroot():
    """解析网页根目录。优先用环境变量；否则在多个候选路径中探测含 index.html 的目录。
    兼容不同解包布局：target/ui、target/../ui、与脚本同级等。"""
    here = os.path.dirname(os.path.abspath(__file__))  # .../target/server
    candidates = []
    env = os.environ.get("FNTERM_WEBROOT")
    if env:
        candidates.append(env)
    candidates += [
        os.path.join(here, "..", "ui"),  # target/ui  (server 的上一级下的 ui)
        os.path.join(here, "ui"),  # target/server/ui
        os.path.join(here, "..", "..", "ui"),
        os.path.join(here, ".."),  # target 根目录直接放页面
    ]
    for c in candidates:
        c = os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "index.html")):
            return c
    # 兜底：环境变量值（即使不存在，便于日志暴露真实路径）
    return os.path.abspath(env) if env else os.path.abspath(os.path.join(here, "..", "ui"))


WEB_ROOT = _resolve_webroot()
# webroot 的 realpath，用于符号链接逃逸防护
WEB_ROOT_REAL = os.path.realpath(WEB_ROOT)
SHELL = os.environ.get("FNTERM_SHELL", os.environ.get("SHELL", "/bin/bash"))
# 是否要求网关鉴权头（fnOS 上为 1；本地调试设 0 放行）
REQUIRE_AUTH = os.environ.get("FNTERM_REQUIRE_AUTH", "1") == "1"
# 仅允许管理员使用（默认 1=仅管理员；root 终端必须默认收紧）
ADMIN_ONLY = os.environ.get("FNTERM_ADMIN_ONLY", "1") == "1"
# 终端运行身份：1=root 2=登录用户 3=应用用户（默认1）
TERM_USER_MODE = os.environ.get("TERM_USER_MODE", "3")
# 是否校验连接对端进程 UID（SO_PEERCRED）。默认开启，防止本地任意用户绕过网关直连。
PEERCRED_CHECK = os.environ.get("FNTERM_PEERCRED_CHECK", "1") == "1"
# 允许直连 socket 的对端 UID 白名单（逗号分隔）。默认 0(root)。
# 网关 nginx worker 通常是 www-data，安装脚本会把其 uid 注入此变量。
_allow_raw = os.environ.get("FNTERM_ALLOW_UIDS", "0")
ALLOW_UIDS = set()
for _p in _allow_raw.split(","):
    _p = _p.strip()
    if _p.isdigit():
        ALLOW_UIDS.add(int(_p))
# 允许的同源 Origin（逗号分隔的主机名/IP）。空=仅校验存在性时跳过。
# 默认信任：无 Origin（同源页面发起的 WS 浏览器可能不带）或与 Host 同源。
ALLOW_ORIGINS = set(
    o.strip().lower() for o in os.environ.get("FNTERM_ALLOW_ORIGINS", "").split(",") if o.strip()
)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# 独立日志文件（位于可写的 var 目录），不依赖 shell 重定向
LOGFILE = os.environ.get("FNTERM_LOGFILE", "")

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
}


def log(msg):
    import time as _t
    line = "[fnterm %s] %s\n" % (_t.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        sys.stderr.write(line)
        sys.stderr.flush()
    except Exception:
        pass
    if LOGFILE:
        try:
            with open(LOGFILE, "a") as f:
                f.write(line)
        except Exception:
            pass


# ----------------------------------------------------------------------------
# 路径处理：剥离网关前缀，得到应用内部路径
# ----------------------------------------------------------------------------
def strip_prefix(path):
    # 去掉查询串
    path = path.split("?", 1)[0]
    if GATEWAY_PREFIX and path.startswith(GATEWAY_PREFIX):
        path = path[len(GATEWAY_PREFIX):]
    if not path.startswith("/"):
        path = "/" + path
    return path


def safe_join(root, rel):
    """防目录穿透：解析后必须仍位于 root 之内（同时做 realpath 防符号链接逃逸）。"""
    rel = rel.lstrip("/")
    full = os.path.abspath(os.path.join(root, rel))
    # 第一层：字符串前缀校验
    if full != root and not full.startswith(root + os.sep):
        return None
    # 第二层：realpath 校验，防止 webroot 内的符号链接指向外部
    real = os.path.realpath(full)
    if real != WEB_ROOT_REAL and not real.startswith(WEB_ROOT_REAL + os.sep):
        return None
    return full


def get_peer_uid(sock):
    """通过 SO_PEERCRED 获取 Unix socket 对端进程的 UID。失败返回 None。"""
    try:
        # struct ucred { pid_t pid; uid_t uid; gid_t gid; } —— 3 个 int
        SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
        creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", creds)
        return uid
    except (OSError, AttributeError, struct.error):
        return None


def peer_allowed(sock):
    """校验连接对端是否为受信任进程（网关/root）。TCP 调试模式或关闭校验时放行。"""
    if not PEERCRED_CHECK or TCP_PORT:
        return True
    uid = get_peer_uid(sock)
    if uid is None:
        # 拿不到对端凭证时，保守起见：仅当本进程非 root 才放行；root 模式必须拒绝未知对端
        return os.getuid() != 0
    if uid == 0:
        return True  # root（网关常以 root 主进程或同属主）
    if uid == os.getuid():
        return True  # 与本服务同用户
    return uid in ALLOW_UIDS


def origin_allowed(headers):
    """校验 WebSocket 的 Origin（防跨站 WebSocket 劫持 CSWSH）。
    规则：无 Origin → 放行（同源页面 / 非浏览器客户端常不带）；
          有 Origin → 其主机必须与请求 Host 同源，或在 ALLOW_ORIGINS 白名单内。"""
    origin = headers.get("origin", "").strip()
    if not origin:
        return True
    # 提取 origin 的 host[:port]
    o = origin.lower()
    for scheme in ("https://", "http://"):
        if o.startswith(scheme):
            o = o[len(scheme):]
            break
    o_host = o.split("/", 1)[0]
    if o_host in ALLOW_ORIGINS:
        return True
    # 与 Host 头同源
    host = headers.get("host", "").strip().lower()
    if host and o_host == host:
        return True
    # 同主机名（忽略端口差异）
    if host and o_host.split(":", 1)[0] == host.split(":", 1)[0]:
        return True
    return False


# ----------------------------------------------------------------------------
# WebSocket 帧编解码（RFC6455）
# ----------------------------------------------------------------------------
def ws_send(sock, payload, opcode=0x2):
    """发送一帧（服务端→客户端，不掩码）。opcode 0x2=binary, 0x1=text, 0x8=close, 0xA=pong"""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    header = bytearray()
    header.append(0x80 | opcode)  # FIN + opcode
    n = len(payload)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header += struct.pack(">H", n)
    else:
        header.append(127)
        header += struct.pack(">Q", n)
    try:
        sock.sendall(bytes(header) + payload)
    except (BrokenPipeError, OSError):
        raise ConnectionError("ws send failed")


def ws_recv_frame(sock):
    """读取并解析一帧客户端数据，返回 (opcode, payload_bytes) 或 None(连接关闭)。"""

    def _read(n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    hdr = _read(2)
    if not hdr:
        return None
    b0, b1 = hdr[0], hdr[1]
    opcode = b0 & 0x0F
    masked = b1 & 0x80
    length = b1 & 0x7F
    if length == 126:
        ext = _read(2)
        if not ext:
            return None
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext = _read(8)
        if not ext:
            return None
        length = struct.unpack(">Q", ext)[0]
    mask = b"\x00\x00\x00\x00"
    if masked:
        mask = _read(4)
        if not mask:
            return None
    payload = _read(length) if length else b""
    if payload is None:
        return None
    if masked and payload:
        payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
    return opcode, payload


# ----------------------------------------------------------------------------
# PTY 会话：fork shell，select 双向转发
# ----------------------------------------------------------------------------
def set_winsize(fd, rows, cols):
    try:
        ws = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, ws)
    except OSError:
        pass


def _resolve_target_user(user_info):
    """根据配置和登录信息，返回终端最终运行的系统用户pwd对象
    user_info: 网关鉴权返回的用户字典
    """

    # 模式1：root 身份
    if TERM_USER_MODE == "1":
        return (['-l'], pwd.getpwuid(0))  # 改为列表

    # 模式2：登录系统用户
    if TERM_USER_MODE == "2":
        username = user_info.get("username")
        if username:
            try:
                return (['-l'], pwd.getpwnam(username))  # 空列表（无需-l，避免重复）
            except KeyError:
                log(f"登录用户 {username} 不存在于系统，回退到应用用户")

    # 模式3：应用专属用户（默认兜底）
    try:
        return ([], pwd.getpwnam(os.environ.get("TRIM_USERNAME", "fnterm")))  # 空列表
    except KeyError:
        log(f"应用用户不存在于系统")
    return ([], None)  # 空列表


def run_pty_session(sock, user, sid, args, target_pw):
    """在已完成握手的 WebSocket 连接上跑一个 PTY 会话（关联sid）。"""
    pid, master_fd = pty.fork()
    if pid == 0:
        # ----- 子进程：成为 shell -----
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env["LANG"] = env.get("LANG", "en_US.UTF-8")
        env["FNTERM_USER"] = str(user.get("username", ""))

        # 当前是 root 且目标非 root → 执行降权
        if os.getuid() == 0 and target_pw.pw_uid != 0:
            try:
                # 严格按 附属组→主组→UID 顺序执行，与 sshd 逻辑一致
                os.initgroups(target_pw.pw_name, target_pw.pw_gid)
                os.setgid(target_pw.pw_gid)
                os.setuid(target_pw.pw_uid)
                log(f"终端子进程降权到用户: {target_pw.pw_name} uid={target_pw.pw_uid}")
            except OSError as e:
                log(f"降权失败: {e}，保持当前身份运行")
        # 用最终身份更新环境变量，与 SSH 登录完全对齐
        pw = pwd.getpwuid(os.getuid())
        try:
            env["USER"] = pw.pw_name
            env["LOGNAME"] = pw.pw_name
            env["HOME"] = pw.pw_dir or env.get("HOME") or "/tmp"
            # 关键：如果用户原生shell是nologin/false，强制用我们指定的SHELL
            user_shell = pw.pw_shell
            if user_shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", ""):
                user_shell = SHELL
            env["SHELL"] = user_shell
        except Exception:
            env.setdefault("HOME", "/tmp")
            user_shell = SHELL
            env["SHELL"] = user_shell

        # 补齐 PATH
        base_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        env["PATH"] = base_path + (":" + env["PATH"] if env.get("PATH") else "")
        home = env.get("HOME") or "/tmp"
        try:
            os.chdir(home)
        except OSError:
            os.chdir("/")

        # 启动 Shell：修正参数列表，避免空字符串参数
        try:
            # 构建参数列表：shell路径 + 额外参数（列表拼接，空参数时仅保留shell路径）
            exec_args = [user_shell] + args
            os.execvpe(user_shell, exec_args, env)
        except OSError:
            # 回退逻辑：直接用bash启动
            try:
                os.execvpe(SHELL, [SHELL], env)
            except OSError:
                os.execvpe("/bin/sh", ["/bin/sh"], env)
        os._exit(127)

    # 父进程：注册会话到全局存储
    session = Session(sid, pid, master_fd, user)
    with SESSIONS_LOCK:
        SESSIONS[sid] = session

    log("pty session started sid=%s pid=%s user=%s" % (sid, pid, user.get("username")))
    sock.setblocking(True)
    try:
        while True:
            rlist, _, _ = select.select([sock, master_fd], [], [], 30)
            if sock in rlist:
                frame = ws_recv_frame(sock)
                if frame is None:
                    break
                opcode, data = frame
                if opcode == 0x8:  # close
                    break
                if opcode == 0x9:  # ping → pong
                    ws_send(sock, data, opcode=0xA)
                    continue
                if opcode in (0x1, 0x2):  # text / binary
                    if not data:
                        continue
                    cmd = data[0:1]
                    req_sid = data[1:14].decode("utf-8")
                    body = data[14:]

                    if req_sid != sid:
                        log(f"Discard cross-session cmd: cmd={cmd}, req_sid={req_sid}, session_sid={sid}")
                        continue
                    if cmd == b"0":  # 键盘输入
                        try:
                            os.write(master_fd, body)
                        except OSError:
                            log(f"intput err cmd={cmd}, req_sid={req_sid}, session_sid={sid}")
                    elif cmd == b"1":  # resize: JSON {cols,rows}
                        try:
                            info = json.loads(body.decode("utf-8"))
                            rows = max(1, min(1000, int(info["rows"])))
                            cols = max(1, min(1000, int(info["cols"])))
                            set_winsize(master_fd, rows, cols)
                        except (ValueError, KeyError, TypeError):
                            log(f"intput err cmd={cmd}, req_sid={req_sid}, session_sid={sid}")
                    elif cmd == b"2":  # 心跳 ping（应用层）
                        pass
            if master_fd in rlist:
                try:
                    out = os.read(master_fd, 65536)
                except OSError:
                    break
                if not out:
                    break
                try:
                    ws_send(sock, out, opcode=0x2)
                except ConnectionError:
                    break
    finally:
        # 会话结束：主动清理
        with SESSIONS_LOCK:
            if sid in SESSIONS:
                SESSIONS[sid].close()
                del SESSIONS[sid]
        log("pty session ended sid=%s pid=%s" % (sid, pid))


# 全局会话存储 + 线程锁
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


# 会话类：封装PTY进程、文件描述符等信息
class Session:
    def __init__(self, sid, pid, master_fd, user):
        self.sid = sid  # 会话唯一ID
        self.pid = pid  # PTY进程PID
        self.master_fd = master_fd  # PTY主文件描述符
        self.user = user  # 会话所属用户
        self.created_at = time.time()  # 创建时间
        self.status = "active"  # 状态：active/closed

    def close(self):
        """主动关闭会话，清理PTY和进程"""
        if self.status != "closed":
            self.status = "closed"
            # 关闭PTY文件描述符
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            # 终止PTY进程
            try:
                os.kill(self.pid, signal.SIGKILL)
            except OSError:
                pass
            # 回收进程资源
            try:
                os.waitpid(self.pid, 0)
            except OSError:
                pass
            log(f"session closed manually: sid={self.sid} pid={self.pid}")


# ----------------------------------------------------------------------------
# HTTP / WebSocket 请求处理
# ----------------------------------------------------------------------------
class Handler(socketserver.StreamRequestHandler):

    def _parse_request(self):
        line = self.rfile.readline(65536).decode("latin-1").strip()
        if not line:
            return None
        parts = line.split(" ")
        if len(parts) < 2:
            return None
        method, path = parts[0], parts[1]
        headers = {}
        while True:
            h = self.rfile.readline(65536).decode("latin-1")
            if h in ("\r\n", "\n", ""):
                break
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return method, path, headers

    def _send_http(self, status, body=b"", ctype="text/plain; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        out = ["HTTP/1.1 %s" % status,
               "Content-Type: %s" % ctype,
               "Content-Length: %d" % len(body),
               "Connection: close"]
        if extra:
            out += extra
        self.wfile.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
        if body:
            self.wfile.write(body)

    def _auth(self, headers):
        """读取统一网关注入的 X-Trim-* 头。返回 user dict 或 None(拒绝)。"""
        uid = headers.get("x-trim-userid")
        is_admin = headers.get("x-trim-isadmin") == "true"
        username = headers.get("x-trim-username")
        if REQUIRE_AUTH:
            if not uid:
                return None
            if ADMIN_ONLY and not is_admin:
                return None
        return {"uid": uid, "isAdmin": is_admin, "username": username}

    def handle(self):
        try:
            # ---- 第一道防线：校验连接对端进程身份（防本地用户绕过网关直连）----
            if not peer_allowed(self.connection):
                uid = get_peer_uid(self.connection)
                log("REJECT direct connection from uid=%s (not gateway/root)" % uid)
                self._send_http("403 Forbidden", "Forbidden: untrusted peer")
                return

            req = self._parse_request()
            if not req:
                return
            method, raw_path, headers = req

            raw_path_parse = urlparse(raw_path)
            inner = strip_prefix(unquote(raw_path_parse.path))
            qs_raw = parse_qs(raw_path_parse.query)

            query = {}
            for k, vlist in qs_raw.items():
                query[k] = unquote(vlist[0])

            user = self._auth(headers)
            if user is None:
                self._send_http("403 Forbidden", "Forbidden: gateway auth required")
                return

            # ========== 新增：会话管理API ==========
            # 1. 列出所有活跃会话: GET /api/sessions
            if inner == "/api/sessions" and method == "GET":
                with SESSIONS_LOCK:
                    session_list = []
                    for sid, sess in SESSIONS.items():
                        session_list.append({
                            "sid": sid,
                            "user": sess.user.get("username"),
                            "pid": sess.pid,
                            "created_at": sess.created_at,
                            "status": sess.status
                        })
                self._send_http("200 OK", json.dumps(session_list),
                                ctype="application/json")
                return
            # 2. 关闭指定会话: POST /api/sessions/{sid}/close
            elif inner.startswith("/api/sessions/") and inner.endswith("/close") and method == "POST":
                sid = inner.split("/")[3]  # /api/sessions/{sid}/close → 索引3为sid
                with SESSIONS_LOCK:
                    if sid in SESSIONS:
                        SESSIONS[sid].close()
                        del SESSIONS[sid]
                        self._send_http("200 OK", json.dumps({"ok": True, "msg": "session closed"}),
                                        ctype="application/json")
                    else:
                        self._send_http("404 Not Found", json.dumps({"ok": False, "msg": "session not found"}),
                                        ctype="application/json")
                return

            # ========== 原有WS逻辑（改造sid传递） ==========
            if inner.rstrip("/") == "/ws":
                if headers.get("upgrade", "").lower() != "websocket":
                    self._send_http("400 Bad Request", "expected websocket upgrade")
                    return
                # 防跨站 WebSocket 劫持（CSWSH）
                if not origin_allowed(headers):
                    log("REJECT ws: bad origin=%r host=%r" % (headers.get("origin"), headers.get("host")))
                    self._send_http("403 Forbidden", "cross-origin websocket rejected")
                    return
                if ADMIN_ONLY and not user["isAdmin"]:
                    self._send_http("403 Forbidden", "admin only")
                    return
                (args, target_pw) = _resolve_target_user(user)
                if target_pw is None:
                    self._send_http("403 Forbidden", "user mode err")
                    return
                # 从查询参数获取sid，无则生成
                sid = query.get("sid", str(uuid.uuid4()))
                key = headers.get("sec-websocket-key", "")
                accept = base64.b64encode(
                    hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
                resp = ("HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: %s\r\n\r\n" % accept)
                self.wfile.write(resp.encode("latin-1"))
                self.wfile.flush()
                run_pty_session(self.connection, user, sid, args, target_pw)  # 传递sid
                return

            # 健康检查
            if inner.rstrip("/") == "/healthz":
                self._send_http("200 OK", json.dumps({"ok": True, "user": user["username"]}),
                                ctype="application/json")
                return

            # 静态文件
            if method not in ("GET", "HEAD"):
                self._send_http("405 Method Not Allowed", "method not allowed")
                return
            rel = inner
            if rel in ("", "/"):
                rel = "/index.html"
            full = safe_join(WEB_ROOT, rel)
            if not full or not os.path.isfile(full):
                # SPA 回退到 index.html
                full = os.path.join(WEB_ROOT, "index.html")
                if not os.path.isfile(full):
                    # 诊断页：仅调试模式暴露 webroot 绝对路径；生产模式给通用提示，避免信息泄露
                    if TCP_PORT or not REQUIRE_AUTH:
                        diag = ("<!doctype html><meta charset=utf-8>"
                                "<body style='font-family:monospace;background:#1d1f21;color:#e06c75;padding:24px'>"
                                "<h2>fnTerm: 静态资源未找到</h2>"
                                "<p>WEB_ROOT = %s</p>"
                                "<p>请求路径 = %s</p>"
                                "<p>该目录下缺少 index.html，请检查打包布局。</p></body>"
                                % (WEB_ROOT, rel))
                    else:
                        diag = ("<!doctype html><meta charset=utf-8>"
                                "<body style='font-family:monospace;background:#1d1f21;color:#e06c75;padding:24px'>"
                                "<h2>fnTerm: 资源未找到</h2></body>")
                    self._send_http("404 Not Found", diag, ctype="text/html; charset=utf-8")
                    return
            ext = os.path.splitext(full)[1].lower()
            ctype = MIME.get(ext, "application/octet-stream")
            with open(full, "rb") as f:
                data = f.read()
            if method == "HEAD":
                data = b""
            self._send_http("200 OK", data, ctype=ctype)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # noqa
            log("handler error: %r" % e)
            try:
                self._send_http("500 Internal Server Error", "internal error")
            except Exception:
                pass


class ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)  # 避免僵尸（父进程显式 waitpid 时仍 OK）
    # 我们在会话里显式 waitpid，这里恢复默认以确保可回收
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)

    log("webroot resolved to %s (index.html exists=%s)"
        % (WEB_ROOT, os.path.isfile(os.path.join(WEB_ROOT, "index.html"))))

    if TCP_PORT:  # 本地调试模式
        addr = ("127.0.0.1", int(TCP_PORT))
        srv = ThreadingTCPServer(addr, Handler)
        log("listening on tcp %s:%s  webroot=%s" % (addr[0], addr[1], WEB_ROOT))
    else:
        if os.path.exists(SOCK_PATH):
            try:
                os.unlink(SOCK_PATH)
            except OSError:
                pass
        srv = ThreadingUnixServer(SOCK_PATH, Handler)
        try:
            # 0666：确保统一网关进程（可能以不同用户运行）可连接该 socket
            os.chmod(SOCK_PATH, 0o666)
        except OSError:
            pass
        log("listening on unix %s  prefix=%s  webroot=%s" % (SOCK_PATH, GATEWAY_PREFIX, WEB_ROOT))

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        if not TCP_PORT and os.path.exists(SOCK_PATH):
            try:
                os.unlink(SOCK_PATH)
            except OSError:
                pass


if __name__ == "__main__":
    try:
        log("=== fnTerm server boot ===  sock=%s webroot=%s prefix=%s py=%s"
            % (SOCK_PATH, WEB_ROOT, GATEWAY_PREFIX, sys.version.split()[0]))
        main()
    except Exception:
        import traceback

        log("FATAL boot error:\n" + traceback.format_exc())
        raise
