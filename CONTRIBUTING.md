# 贡献指南 Contributing

感谢你对 fnTerm 的兴趣！本项目是一个纯原生、零依赖的飞牛 fnOS Web 终端，欢迎各种形式的贡献。

## 开发环境

- **Python 3.8+**（仅用标准库，无需安装任何包）
- **飞牛 `fnpack`** 打包工具（打包 / 测试 `.fpk` 时需要）
- 一台飞牛 fnOS 设备（最终联调，可选）

本地无需飞牛环境即可开发后端：使用 TCP 调试模式（见 [README](README.md#本地开发与调试)）。

## 本地运行

```bash
FNTERM_TCP_PORT=8799 FNTERM_GATEWAY_PREFIX="" \
FNTERM_WEBROOT="$PWD/app/ui" FNTERM_REQUIRE_AUTH=0 \
python3 app/server/ptyserver.py
# 浏览器打开 http://localhost:8799/
```

## 代码风格

- **后端**：坚持「仅标准库」原则，不引入第三方依赖；保持单文件可读，关键逻辑写中文注释。
- **前端**：原生 JS，不引入框架；第三方库（xterm.js）放 `app/ui/vendor/` 并在 LICENSE 标注。
- **脚本**：`cmd/*` 用 POSIX-friendly bash；失败时把用户可见信息写入 `$TRIM_TEMP_LOGFILE`。
- 字符串 / 路径 / 配置使用 ASCII 直引号，避免全角符号导致解析问题。

## 提交流程

1. Fork 并新建分支：`git checkout -b feat/your-feature`
2. 修改后**本地冒烟测试**（见下）确保通过
3. 提交信息使用清晰的祈使句，例如 `fix: reject cross-origin websocket`
4. 发起 Pull Request，说明动机与改动点
5. 涉及行为变更时，请同步更新 `README.md` / `manifest` 的 `changelog`

## 冒烟测试

修改后端后，请至少验证以下链路（TCP 或 Unix socket 模式均可）：

- `GET /healthz` 返回 `200`
- `GET /`、`GET /vendor/xterm.js` 返回 `200`
- 无鉴权头时返回 `403`（`FNTERM_REQUIRE_AUTH=1`）
- WebSocket 握手成功并能执行 `echo` 回显
- 跨站 `Origin` 的 WS 升级被 `403` 拒绝

## 安全相关改动

涉及鉴权、socket 校验、Origin、文件服务路径的改动需格外谨慎：

- 不要削弱 `SO_PEERCRED` / Origin / 目录穿透防护；
- 新增对外接口默认走鉴权，最小授权；
- 如发现安全漏洞，请按 [SECURITY.md](SECURITY.md) 私下报告，**勿直接公开**。

## 版本与打包

- 每次发布请递增 `manifest` 的 `version`，并填写 `changelog`；
- 打包前清理：`rm -rf app/server/__pycache__ app.sock *.fpk && find . -name '.DS_Store' -delete`
- `fnpack build` 生成 `.fpk`，在设备上 `appcenter-cli install-fpk` 验证。

