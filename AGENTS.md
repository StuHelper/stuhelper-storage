# 存储核心工程约定

遵循 Next 工作区 AGENTS.md。本模块拥有存储元数据、任务、审计、outbox 和迁移，不读写课程、文件元数据或贡献模块的数据。

API 先维护 contracts/storage.openapi.json，再生成 SDK。Handler 调用 Service，Service 通过 Repository 完成事务。供应商协议通过 Driver、Resolver 和 Verifier 接入，凭据保管由装配方负责。

新增权限、冗余和故障路径须用真实 PostgreSQL 集成测试核验实际状态及外部副作用。真实 BHpan 验收单独报告，只读写本任务隔离根。当前不实现受限加密或阅读器。
