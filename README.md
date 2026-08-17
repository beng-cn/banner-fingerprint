# banner-fingerprint — Banner 指纹识别系统

接收网络扫描原始数据（ip / port / banner），识别协议、软件（product）与版本信息。Go 自研规则引擎 + client/server 架构 + Docker Compose 一键启动。

## 快速开始

```bash
# Docker Compose 一键启动（server 常驻 + client 识别 data/sample.json 后退出）
docker compose up --build

# 或本机运行
go run ./cmd/server                              # 启动服务（默认 :8080）
go run ./cmd/client -file data/sample.json       # 另一终端：提交样例数据
```

## 接口

| 接口 | 方法 | 说明 |
|---|---|---|
| `/fingerprint` | POST | 批量识别：入参 `{"records":[{"ip":"...","port":80,"banner":"..."}]}` |
| `/health` | GET | 健康检查：服务状态 + 已加载规则数 |

结果字段：`ip`、`port`、`protocol`、`product`、`version`、`os_hint`、`confidence`（0~1）。认不出一律返回 `protocol:"unknown"`、confidence 0，任何输入都不会导致服务崩溃。

## 识别能力

| 协议 | 产品 | 版本 | 备注 |
|---|---|---|---|
| SSH | OpenSSH 等 | ✅ | 支持 os_hint 提取（如 Ubuntu） |
| HTTP | nginx / Apache / Jetty | ✅ | 解析响应头 Server 字段 |
| MySQL | MySQL | ✅ | 纯版本串 + 二进制握手包 |
| Redis | Redis | — | 被动 banner 拿不到版本，置信度 0.70 档 |
| FTP | ProFTPD / vsFTPd / Pure-FTPd / Microsoft FTP | ✅ | 220 欢迎语解析 |

置信度档位：完整命中 0.90、含端口先验+OS 提取 0.95、版本缺失 0.70、特殊版本格式（Jetty）0.85。

## 架构与设计

- **识别流程**：端口先验筛选候选 → 正则逐条匹配（按 priority 取最优）→ 捕获组提取 version/os → 置信度评分
- **规则解耦**：[rules/fingerprints.yaml](rules/fingerprints.yaml) 与代码零硬编码；容器内只读挂载，`SIGHUP` 热重载（`docker compose kill -s SIGHUP server`）
- **并发安全**：规则快照 `atomic.Pointer` 只读共享，并发识别零锁竞争（已过 `go test -race`）
- **分层**：`internal/model`（DTO）+ `internal/engine`（识别引擎）+ `internal/server`（HTTP 薄层），构造函数注入、接口依赖

## 生产级 Docker 交付

| 评估点 | 实现 |
|---|---|
| 容器间访问收敛 | 仅 server 发布 8080；client 经 Compose 内部 DNS 以服务名访问，零端口发布 |
| 真实健康检测 | healthcheck 调用 `GET /health` 业务端点；client `depends_on: condition: service_healthy` |
| 编译打包 | 多阶段构建：golang:1.25-alpine 编译（CGO_ENABLED=0）→ scratch 空镜像运行 |
| 权限收紧 | 非 root（65532）、只读根文件系统、`cap_drop: [ALL]`、`no-new-privileges` |
| 规则解耦 | rules/ 只读挂载 + SIGHUP 热重载，换规则无需重建镜像 |

## 目录结构

```
cmd/server/          服务入口（优雅关闭、SIGHUP 热重载）
cmd/client/          CLI 客户端（读文件 → 分批提交 → 表格展示）
internal/engine/     识别引擎（规则加载、匹配、置信度）
internal/server/     HTTP 薄层（参数绑定 + 统一响应）
internal/model/      共享 DTO
rules/               指纹规则库（YAML，与代码解耦）
data/sample.json     示例扫描数据
```
