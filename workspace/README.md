# 芯片设计 ECO 与签核基线服务

面向芯片设计团队的工程变更（ECO）冻结、验证矩阵调度、双角色签核与不可变发布基线服务。
**零第三方依赖**：仅使用 Python 3.11 标准库（`http.server` + `sqlite3`）+ 原生 JS 前端。

## 要解决的问题

设计团队提交 ECO 时冻结 **网表 / 约束 / 受影响模块 / 验证矩阵**，系统按依赖图触发
**时序 STA、功耗、形式验证、版图 DRC**（及非必需 Lint）。只有满足：

1. 全部**必需检查针对同一条冻结基线**通过（每条结果带输入指纹）；
2. **双角色签核**（时序负责人 + 方法学负责人，且必须是两个不同的人；
   支持管理员配置**临时代理签核**，但代理未生效/已过期/已撤销一律在签核动作发生时拒绝，
   同一自然人即使经两条代理链也不得完成双签）；

才能形成一条新的**不可变发布基线**。

系统对四类高频异常给出确定性裁决，**任何情况下旧结果都不得跨基线拼接复用**：

| 场景 | 行为 |
|---|---|
| 验证结果迟到（基线已刷新/作废） | run 标记 `SUPERSEDED`，迟到提交以 `STALE_SUPERSEDED` 拒收并留痕 |
| 基础约束更新途中到来 | 在验 ECO → `REBASE_REQUIRED`，全部旧检查与签核作废；约束更新期间若有发布中 ECO 则直接拒绝，冻结世界 |
| 两个 ECO 修改重叠模块 | 模块锁互斥，后来单 `QUEUED` 明确排队；可由 CCB 裁决 `MERGE` 合并（逐模块 TARGET/SOURCE 赢家），合并使冻结纪元 +1 并整轮重跑 |
| 发布中断 | 两阶段发布：阶段1提交 `RELEASING`（可在其后崩溃），阶段2原子写入新基线；中断期间禁止中止 ECO / 更新约束，`resume` 幂等恢复 |

## 防串用的核心机制：冻结指纹 + 纪元

- **快照**：冻结时固化 `{网表, 约束, 受影响模块, 验证矩阵}`，整体 SHA-256 摘要（16hex）。
- **检查作用域指纹**：每条 check_run 绑定其输入作用域（netlist / sdc / modules + 固定矩阵）
  的指纹。Runner 从 `/inputs` 拉取冻结输入后**自行计算指纹**（不偷看期望值），随结果回传。
- **三重拒收**：`FINGERPRINT_MISMATCH`（输入被改/拿错基线）、`STALE_SUPERSEDED`
  （纪元已变，结果迟到）、`ALREADY_SUBMITTED`（重复提交）。所有拒收进 `rejected_result` 审计表。
- **冻结纪元 freeze_epoch**：rebase / 合并扩张均令纪元 +1，旧 run 整批 `SUPERSEDED`，
  旧签核因 `(epoch, overall_fp)` 不再匹配而失效。
- **依赖图**：`LAYOUT_DRC` 依赖 `TIMING_STA`+`POWER_ANALYSIS`，前置未 PASS 时保持
  `BLOCKED`，提前提交以 `DEPENDENCY_BLOCKED` 拒收；前置 FAIL 不会解锁下游。

## 快速开始

```bash
# 启动服务（默认 0.0.0.0:8080，SQLite 落盘 data/eco.db）
python3 -m app.api --db data/eco.db --port 8080 --lease-ttl 120

# 浏览器打开签核工作台
open http://localhost:8080

# 命令行跑完 A/B/C/D 四个异常场景演示（内存库）
python3 -m app.demo

# 全部测试（76 个：领域单测 + 租约协调不变量 + 真实 HTTP 端到端，含临时代理签核）
python3 -m unittest discover -s tests -v
```

## 目录结构

```
app/
  store.py    SQLite schema/连接/种子基线 R0/检查目录(依赖与作用域)/租约与审计表
  service.py  领域核心：冻结指纹、依赖调度、排队合并、双签门禁、临时代理签核授权、两阶段发布、差异包
  lease.py    验证执行租约协调：就绪任务领取(幂等/并发唯一)、续租、完成、释放、超时接管、代次+HMAC凭据门禁、重启恢复/回收
  runner.py   模拟验证 Runner（自行算指纹；可演示迟到/篡改）
  api.py      stdlib HTTP REST 路由（ECO + 租约协调独立 API）
  demo.py     四场景端到端演示
web/
  index.html  签核工作台（代理配置、ECO 队列、门禁矩阵、签核、差异包、拒收留痕、租约协调操作台）
  app.js      零依赖 JS；浏览器端用 WebCrypto 复算 Runner 指纹
tests/
  test_service.py     24 个领域不变量测试
  test_delegation.py  18 个临时代理签核测试
  test_lease.py       25 个租约协调不变量测试（幂等/并发/接管/代次凭据/重启恢复）
  test_api.py          9 个真实 socket HTTP 测试（6 ECO/签核 + 3 租约端到端）
```

## ECO 状态机

```
DRAFT ──freeze(无锁冲突)──▶ FROZEN ──双签+发布──▶ RELEASING ──阶段2──▶ RELEASED
  │                           │ ▲                                      
  │                           │ │ rebase(refreeze, epoch+1)            
  │      基础约束更新          ▼ │                                      
  │                    REBASE_REQUIRED                                  
  │ freeze(模块被占)                                                      
  ├──────────────────────▶ QUEUED ──合并裁决──▶ (源)MERGED / (目标留在 FROZEN, epoch+1)
  └──abort─▶ ABORTED        │                                           
        阻塞解除且未被合并 ──┴──▶ REBASE_REQUIRED（必须基于最新基线重冻结）
```

## REST API 摘要

详见 [API.md](API.md)。主要端点：

- `POST /api/ecos` · `POST /api/ecos/{id}/freeze|abort|signoff|release|release/resume`
- `GET  /api/ecos/{id}/checks/{type}/inputs`（Runner 拉冻结输入）
- `POST /api/ecos/{id}/checks/{type}/results|rerun`
- `POST /api/ecos/{src}/merge-into/{tgt}` · `POST /api/constraints`
- 临时代理签核（管理员）：`POST /api/admin/delegations` ·
  `POST /api/admin/delegations/{id}/revoke` · `GET /api/current-signers`
- 验证执行租约：`POST /api/leases/claim` ·
  `POST /api/leases/runs/{run}/renew|release|takeover|results` ·
  `GET  /api/leases/pool|/api/leases/runs/{run}|/api/leases/audit`
- `GET  /api/workbench` · `GET /api/baselines/diff?from=&to=` · `.../diff.zip`
- `POST /api/admin/reset`（演示数据重置）

所有错误形如 `{"error":"CODE","message":"...","detail":{...}}`，拒收原因码见 API.md。

## 临时代理签核

负责人休假/缺位时，管理员可为两种签核角色配置临时代理（工作台面板 ①，或
`POST /api/admin/delegations`）：

- 指定**代理人**、被代理负责人（可选，仅展示来源）、**生效/失效时间**（UTC ISO-8601）；
  可随时**撤销**。相同 `(角色, 代理人, 生效, 失效)` 重复提交**幂等**，不产生重复有效记录
  （部分唯一索引 + 应用层去重），时间窗重叠返回 409。
- 服务端**只在签核动作发生时**校验授权：拒绝未生效（`DELEGATION_NOT_STARTED`）、
  已过期（`DELEGATION_EXPIRED`）、已撤销（`DELEGATION_REVOKED`）、角色/人不符的代理；
  拒绝写 `audit_log(signoff.denied)`。
- **同一自然人禁止双角色签核**的禁令穿透代理：即使持有两个角色的有效代理，第二签仍被
  `DUAL_ROLE_CONFLICT` 拒绝。
- 已完成的代理签核在记录中固化**当时身份与代理链**（`signoff_kind=DELEGATE`、
  `delegation_id`、`auth_chain`：授权人/被代理人/有效期/校验时刻），长期保留供审计
  （差异包 `verification/signoffs.json` 同步包含）；ECO 重新冻结（rebase/合并/新基线发布）
  仍将旧签核标记失效（`voided_at`），新纪元必须重签。
- 工作台展示每角色**当前可签人员、代理来源与有效期**，并在 ECO 卡片提供"代理签核"按钮。

## 验证执行租约协调（`app/lease.py`）

配套的租约协调模块把验证矩阵中**已就绪**的检查原子分配给 Runner，并提供独立 API
与工作台面板 ⑥（待领任务 / 当前持有者 / 剩余时间 / 接管历史）。

- **就绪发现**：只暴露 `PENDING` 且 ECO=FROZEN 的活动 run；`BLOCKED`（依赖未满足）、
  已作废（`SUPERSEDED`）、已有结论的 run 不可领取。
- **领取幂等 + 并发唯一**：`claim(runner_id, idempotency_key)` 对同一键的重放/并发
  返回同一份分配（不重复发租约）；不同 Runner 抢同一 run 仅一个成功
  （`BEGIN IMMEDIATE` + `UNIQUE(run_id)` 串行化，落败方 `LEASE_HELD_BY_OTHER`）。
- **代次 + 不可伪造凭据**：每次领取/接管返回 `generation` 与 `lease_token`
  （持久密钥对 `(run_id, generation, nonce)` 的 HMAC-SHA256，密钥存 `lease_meta`，
  不落明文）。回传必须回带二者。旧持有者（被接管后拿旧代次）、错误 Runner、
  伪造凭据、过期租约、依赖未满足、**重跑后旧代次迟到结果**、无租约直交全部拒绝，
  拒绝写 `lease_audit`，可按 run/reason 查询。
- **续租 / 释放 / 超时接管**：续租刷新 `expires_at`（代次不变）；持有者可主动释放回池；
  接管**只允许在 TTL 过期后**，代次 +1、nonce/token 换新，旧持有者凭据即刻失效。
- **落盘与恢复**：租约、幂等键、审计、HMAC 密钥全部在 SQLite。进程重启恢复未过期
  租约（旧 token 仍验真），回收已过期/随纪元作废的租约并写 `reclaim` 审计。
- **不绕过既有门禁**：租约校验通过后，结果仍交给 `ECOService.submit_result`——
  接管回来的结果一样要过**基线指纹**与**依赖门禁**，重跑（旧 attempt SUPERSEDED、
  新 attempt 重新绑指纹）、双角色签核、两阶段发布的约束全部保持；租约置 COMPLETED
  与 check_run 落定在同一数据库事务内，要么一起成功要么一起回滚。

## 差异包
`GET /api/baselines/diff.zip?from=B-R1&to=B-R3` 产出：

```
manifest.json                 # 完整结构化差异
constraints/sdc.before|after.json
modules/<m>.before.v / .after.v / .diff   # 逐模块 unified diff
verification/matrix.json      # 目标基线的验证矩阵定义
verification/results.json     # 实际通过的检查结果（含 result_fp/expected_fp）
verification/signoffs.json    # 双角色签核记录
README.txt
```

差异包可独立审计：模块变更、约束 delta、每条检查是否针对目标基线指纹通过、双签是否齐备。
