# bannerfp — Banner 指纹识别系统

## 需求（2026-08-17 确认）

- **功能**：接收网络扫描原始数据（ip/port/banner），识别协议、软件（product）与版本
- **接口**：server 提供 `POST /fingerprint`（批量识别）+ `GET /health`（健康检查）；client 是独立 CLI 程序（读本地 JSON 文件 → 提交 server → 表格展示结果）
- **结果字段**：ip、port、protocol、product、version、os_hint、confidence（0~1）
- **兜底铁律**：认不出一律返回 `protocol:"unknown"`、confidence 0，任何输入（空 banner、乱码、畸形 JSON 单条）都不允许服务崩溃
- **必识别协议**：SSH、HTTP（nginx/Apache/Jetty）、MySQL、Redis、FTP
- **置信度基准**（示例响应对齐）：完整命中 0.90；含端口先验+OS 提取 0.95（SSH）；版本缺失 0.70（Redis）；Jetty 0.85（conf_bias -0.05）
- **交付**：Docker Compose 一键启动，生产级部署标准（容器间访问收敛、真实健康检测、多阶段构建、非 root 运行、规则与代码解耦）
- **验收方式**：本机 go run 验证功能；Compose 文件作为交付物（本机无 Docker）

## 已拍板的技术决策

- **指纹引擎**：自研规则引擎。`rules/fingerprints.yaml` 与代码完全解耦（零硬编码），server 收到 SIGHUP 信号热重载规则，运行期换规则不重启
- **识别流程**：端口先验筛选候选 → 正则逐条匹配（按 priority 取最优）→ 捕获组提取 version/os → 置信度评分
- **置信度算法**：base 0.42 + 端口先验命中 0.03 + product 确定 0.25 + version 提取 0.20 + os_hint 提取 0.05 + 规则级 conf_bias；结果四舍五入 2 位，钳制 [0,1]
- **并发模型**：规则库加载后只读，atomic.Pointer 快照共享，HTTP 并发识别零锁竞争
- **HTTP 层**：标准库 net/http（Go 1.22+ 方法路由），薄层只做参数绑定+调用引擎+统一响应；错误响应遵循 HTTP 200 + JSON code 字段规范
- **分层**：internal/model（DTO）+ internal/engine（识别引擎）+ internal/server（HTTP 薄层），构造函数注入、接口依赖

## 验收标准（测试清单已含）

1. `GET /health` 返回 ok + 已加载规则数
2. `POST /fingerprint` 对示例 7 条数据输出与示例响应同深度（协议/产品/版本/os_hint/置信度对齐）
3. 畸形输入（unknown banner、空 records）不崩溃，unknown 兜底
4. client 端到端：data/sample.json → 表格输出 + 统计
5. `go test -race`（并发安全）+ `go vet` 通过
6. Dockerfile 多阶段构建 + Compose 配置交付（本机无 Docker，文件层面评审）
