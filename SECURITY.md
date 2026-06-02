# 安全策略 Security Policy

## ⚠️ 重要提示：本应用以 root 权限运行

fnTerm 默认以 **root** 身份运行（`config/privilege` 中 `run-as: root`）。这意味着**任何能打开此终端的用户都拥有对 NAS 的完全控制权**。请务必：

- 仅在「应用设置」中授权给**可信的管理员账号**；
- 不要在多用户共享、对公网暴露或不受信任的环境中开放使用；
- 理解这是一个高权限运维工具，而非面向普通用户的应用。

## 威胁模型与防护

fnTerm 运行在 fnOS 统一网关之后，通过世界可写（`0666`）的 Unix Domain Socket 通信。这带来一个关键事实：

> **网关注入的 `X-Trim-*` 头本身不是安全边界。** 因为 socket 任何本地进程都能连接，这些头可被伪造。

为此 fnTerm 实施了多层防护：

| 威胁 | 防护措施 | 实现 |
|---|---|---|
| 本地用户绕过网关直连 socket 伪造管理员头拿 root | **`SO_PEERCRED` 校验连接对端进程 UID**，仅放行网关进程（www-data）与 root | `peer_allowed()` |
| 跨站 WebSocket 劫持（CSWSH） | **校验 `Origin`** 同源，拒绝跨站升级 | `origin_allowed()` |
| 非管理员访问 | **默认仅管理员**（`FNTERM_ADMIN_ONLY=1`） | `_auth()` |
| 目录穿透 / 符号链接逃逸读取任意文件 | `os.path.realpath` 二次校验，限制在 webroot 内 | `safe_join()` |
| 资源耗尽 / 信息泄露 | resize 行列数范围约束；生产模式不回显内部路径 | — |

详细分析见仓库提交历史与 `app/server/ptyserver.py` 注释。

## 受支持的版本

| 版本 | 是否受支持 |
|---|---|
| 1.0.8+ | ✅ 含完整安全加固 |
| < 1.0.8 | ❌ 缺少 `SO_PEERCRED` / Origin 校验，请升级 |

## 报告漏洞

如果你发现安全漏洞，**请勿直接公开 issue**，而是通过以下方式私下报告：

1. 在 GitHub 仓库使用 **Security Advisory**（Security → Report a vulnerability）；
2. 或通过仓库主页公开的联系方式联系维护者。

报告时请尽量包含：

- 受影响的版本；
- 复现步骤或 PoC；
- 影响范围与建议修复方向。

我们会尽快确认并在合理时间内修复。感谢你的负责任披露。

## 加固建议（部署方）

- 保持升级到最新版本；
- 在应用设置里关闭对非管理员的授权；
- 如无 root 需求，可将 `config/privilege` 改为 `run-as: package` 后重新打包，以最小权限运行；
- 定期检查 `var/fnterm.log` 中的 `REJECT` 记录，留意异常直连尝试。
