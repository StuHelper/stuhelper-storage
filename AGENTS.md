---
type: guide
status: Accepted
updated: 2026-11-21
---

# 存储核心工程约定

遵循 [StuHelper 工作区工程约定](https://github.com/StuHelper/stuhelper/blob/develop/AGENTS.md)。本模块拥有实例、对象、副本、容量账本、任务、审计、outbox 和迁移。课程资料、文件元数据、贡献同意与奖励通过公开接口协作。

先维护 `contracts/storage.openapi.json`，再用 `make generate` 更新 SDK。Handler 处理请求解析，Service 校验授权和执行业务，Repository 负责事务与数据访问。供应商驱动、身份和凭据保管由宿主装配。

供应商原始容量与平台额度、预占和副本占用分开维护。原始容量仅通过当前所有者受限的 Go 接口提供给贡献模块。普通存储 HTTP 接口、审计、日志和事件省略贡献者的原始额度和凭据材料。

新增权限、冗余或故障路径时，在规格中声明场景，并用 `module.json` 的 `scenario_tests` 登记实际测试函数。使用独立 PostgreSQL 核验状态和副作用，供应商测试默认使用夹具。真实 BHpan 验收单独报告，读写限于获准的隔离目录。
