<div align="center">

# fnTerm 终端

**飞牛 fnOS 上的纯原生 Web 终端 — 类 iTerm 体验，零第三方依赖，不依赖 ttyd**

[![platform](https://img.shields.io/badge/platform-arm-blue)](#)
[![fnOS](https://img.shields.io/badge/fnOS-V1.1.3100+-orange)](#)
[![python](https://img.shields.io/badge/python-stdlib%20only-green)](#)
[![license](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

</div>

---

## 简介

**fnTerm** 是一个运行在 [飞牛 fnOS](https://www.fnnas.com/) 上的浏览器 Web 终端应用。它通过 fnOS **统一网关**接入，无需对外暴露任何端口；后端完全使用 **Python 标准库**实现真实的 PTY 伪终端，**零第三方依赖、无需编译、不下载 ttyd 等任何外部二进制**。前端基于 [xterm.js](https://xtermjs.org/)，提供与 iTerm 类似的全功能终端体验。

整个后端核心不到 600 行 Python，仅用 `pty` / `termios` / `fcntl` / `socket` / `socketserver` 等标准库，手写 RFC6455 WebSocket，因此在 ARM 设备上也能开箱即用，完全规避了 `node-pty` / `node-gyp` 在嵌入式平台的编译难题。

## 特性

- 🖥️ **真实 PTY** — `pty.fork` 启动登录 shell，支持交互式程序（vim / top / htop / ssh 等）。
- 🔌 **统一网关接入** — Unix Domain Socket + `gatewayPrefix`，不暴露端口，复用飞牛登录态。
- 🪶 **纯原生零依赖** — 后端仅 Python 标准库，前端 xterm.js 构建期内置，运行时不联网。
- 📐 **自适应窗口** — 浏览器尺寸变化实时同步到 PTY（`TIOCSWINSZ`）。
- 🔐 **多层安全** — `SO_PEERCRED` 对端校验 + WebSocket Origin 校验 + 默认仅管理员 + 目录穿透防护。
- 🎨 **iTerm 风格 UI** — 深色主题、交通灯、连接状态指示、清屏 / 重连。
- 🧰 **强诊断** — 服务自写日志、启动横幅、webroot 自动探测、前端保底错误提示。

## 架构

```
浏览器 (xterm.js)
   │  HTTP / WebSocket
   ▼
fnOS 统一网关 (nginx :5666/:5667)   ← 注入 X-Trim-* 鉴权头
   │  Unix Domain Socket 转发
   ▼
ptyserver.py  (Python stdlib, run-as root)
   │  pty.fork + select 双向转发
   ▼
登录 Shell (/bin/bash -l)
```

| 层 | 技术 | 文件 |
|---|---|---|
| 前端 | xterm.js + fit-addon + 原生 JS | `app/ui/index.html`、`app/ui/vendor/` |
| 后端 | Python stdlib（HTTP/WS/PTY） | `app/server/ptyserver.py` |
| 生命周期 | bash 脚本（启停/状态/诊断） | `cmd/main` |
| 打包元数据 | manifest / privilege / resource / 入口 | `manifest`、`config/`、`app/ui/config` |

## 安装

### 方式一：安装预编译的 `.fpk`

```bash
# 在飞牛设备上（SSH）
appcenter-cli stop fnnas.fnterm 2>/dev/null
appcenter-cli install-fpk fnnas.fnterm.fpk
appcenter-cli start fnnas.fnterm
```

安装后桌面会出现「fnTerm 终端」图标，点击即在窗口中打开终端。

> **依赖**：应用依赖 `python312` 运行时，应用中心会在安装时自动拉取。若设备自带 `/usr/bin/python3`，服务也能自动探测使用。

### 方式二：从源码构建

见下方 [构建](#构建)。

## 构建

需要飞牛官方打包工具 [`fnpack`](https://developer.fnnas.com/)（飞牛设备预置；本地可从 `static2.fnnas.com/fnpack/` 下载对应平台版本）。

```bash
git clone git@github.com:sbosp/fnnas.fnterm.git
cd fnnas.fnterm

# 打包成 .fpk
fnpack build
# → 生成 fnnas.fnterm.fpk
```

打包前请确保已清理临时产物：

```bash
rm -rf app/server/__pycache__ app.sock *.fpk
find . -name '.DS_Store' -delete
fnpack build
```

## 本地开发与调试

服务支持 **TCP 调试模式**，可在普通电脑上直接运行、用浏览器访问，无需飞牛环境：

```bash
# 以 TCP 模式启动（放行鉴权，便于本地查看 UI）
FNTERM_TCP_PORT=8799 \
FNTERM_GATEWAY_PREFIX="" \
FNTERM_WEBROOT="$PWD/app/ui" \
FNTERM_REQUIRE_AUTH=0 \
python3 app/server/ptyserver.py

# 浏览器打开 http://localhost:8799/
```

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `FNTERM_SOCK` | `./app.sock` | Unix socket 路径（生产由网关使用） |
| `FNTERM_TCP_PORT` | — | 设置后改用 TCP 监听（仅调试） |
| `FNTERM_GATEWAY_PREFIX` | `/app/fnterm` | 网关前缀，须与 `app/ui/config` 一致 |
| `FNTERM_WEBROOT` | 自动探测 | 前端静态资源目录 |
| `FNTERM_LOGFILE` | — | 服务自写日志文件路径 |
| `FNTERM_SHELL` | `$SHELL` 或 `/bin/bash` | 启动的 shell |
| `FNTERM_REQUIRE_AUTH` | `1` | 是否强制校验网关注入的 `X-Trim-*` 头 |
| `FNTERM_ADMIN_ONLY` | `1` | 是否仅管理员可用 |
| `FNTERM_PEERCRED_CHECK` | `1` | 是否校验连接对端进程 UID（防直连提权） |
| `FNTERM_ALLOW_UIDS` | `0` | 允许直连 socket 的 UID 白名单（逗号分隔） |
| `FNTERM_ALLOW_ORIGINS` | — | WebSocket 额外允许的 Origin 主机白名单 |

## WebSocket 协议

客户端 → 服务端：每帧首字节为操作码，其余为负载。

| 首字节 | 含义 | 负载 |
|---|---|---|
| `0` | 键盘输入 | 原始按键字节 |
| `1` | 调整窗口尺寸 | JSON `{"cols":N,"rows":M}` |
| `2` | 应用层心跳 | 空 |

服务端 → 客户端：PTY 输出以 **二进制帧**（opcode `0x2`）原样回传。

## 安全

> ⚠️ **本应用默认以 root 权限运行**，打开终端即拥有 NAS 的完全控制权。请仅授权给可信管理员。

fnTerm 针对网关 socket 模式的特性做了多层防护，详见 [SECURITY.md](SECURITY.md)：

1. **`SO_PEERCRED` 对端校验**（核心边界）— 仅允许网关进程与 root 直连 socket，阻止本地任意用户伪造 `X-Trim-*` 头绕过网关直接拿 root。
2. **WebSocket Origin 校验** — 拒绝跨站 WebSocket 升级，防 CSWSH 劫持。
3. **默认仅管理员** — `FNTERM_ADMIN_ONLY=1`。
4. **目录穿透防护** — `realpath` 二次校验，防符号链接逃逸。
5. **输入约束** — resize 行列数范围限制；生产模式不泄露内部路径。

如发现安全问题，请参阅 [SECURITY.md](SECURITY.md) 的报告流程。

## 目录结构

```
fnnas.fnterm/
├── manifest                 # 应用元数据（appname/version/平台/依赖）
├── config/
│   ├── privilege            # 运行身份（run-as: root）
│   └── resource             # 能力声明
├── app/
│   ├── ui/
│   │   ├── index.html       # 前端终端页面
│   │   ├── config           # 桌面入口 + 网关绑定
│   │   └── vendor/          # xterm.js / fit-addon（内置）
│   └── server/
│       └── ptyserver.py     # 后端 PTY + HTTP/WS 服务
├── cmd/                     # 生命周期脚本（main / install_* / ...）
├── wizard/install           # 安装向导
└── ICON.PNG / ICON_256.PNG  # 图标
```

## 常见问题

**Q：终端里 `sudo` 提示密码错误？**
A：本应用以 root 运行，**无需 `sudo`**，打开即 root。（应用专用用户模式下 `sudo` 无法使用，因为该系统账号无密码且不在 sudoers。）

**Q：桌面图标打开是空白 / 显示成了飞牛桌面？**
A：多为浏览器缓存旧版本，强制刷新或用无痕窗口重试。其余排查见 [SECURITY.md](SECURITY.md) 与 issues。

**Q：可以发布到飞牛应用中心吗？**
A：以 root 运行的第三方应用**不可上架**应用中心，但本地手动安装自用完全可行。若需上架，需改为 `run-as: package`。

## 致谢

- [xterm.js](https://github.com/xtermjs/xterm.js) — 前端终端组件
- [飞牛 fnOS 应用开放平台](https://developer.fnnas.com/) — 开发文档与工具链

