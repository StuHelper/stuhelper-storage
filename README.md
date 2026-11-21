---
type: index
status: Accepted
updated: 2026-11-21
---

# StuHelper Storage

StuHelper 的通用存储库，负责实例和准入、容量账本、对象、副本、任务、审计与 outbox。默认保存三份完整副本，两份独立合规副本通过 SHA-256 校验后允许业务首次引用。

课程资料、文件元数据、贡献同意与奖励由对应模块管理。调用方经公开 Go 接口或 HTTP 契约操作存储。服务端按动作、对象和保护范围校验当前权限。运行身份只访问 `storage` schema，迁移由独立身份执行。

## 模块依赖

`module.json` 声明通用存储没有必需业务模块，`storage-bhpan` 是可选的供应商适配。宿主装配身份、凭据解析和存储驱动。未启用 BHpan 时，其他已装配驱动可独立提供存储能力。Go 构建仍按 `go.mod` 解析 BHpan 驱动的依赖。

`contracts/storage.openapi.json` 定义 HTTP 接口，`make generate` 生成 SDK。贡献模块经受限的 Go 接口读取本人云盘容量和控制实例，云盘原始读数与平台账本分开保存。详见[存储规格](docs/spec/storage.md#贡献扩展接口)。

## 开发与验证

使用工作区声明的 Go、Node.js 和 pnpm。执行 `make setup` 安装锁定工具，再运行 `bash scripts/check-with-postgres.sh` 启动独立 PostgreSQL 并执行 CI 使用的检查。已有专用测试服务器时，设置 `STUHELPER_STORAGE_TEST_DSN` 后运行 `make check`。

`module.json` 的 `scenario_tests` 按规格编号登记实际测试函数。单仓检查覆盖生成一致性、浏览器 SDK、独立数据库身份、文档与工作流。供应商回归使用协议夹具，宿主组合和真实账号验证见[存储实施状态](https://github.com/StuHelper/stuhelper/blob/develop/docs/development/storage-module.md)。
