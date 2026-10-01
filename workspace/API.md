# API 契约

基础路径 `http://<host>:8080`，全部 JSON。错误响应统一为：

```json
{ "error": "CODE", "message": "可读说明", "detail": { "reason": "..." } }
```

## 状态与原因码

- **ECO 状态**：`DRAFT / FROZEN / QUEUED / REBASE_REQUIRED / RELEASING / RELEASED / MERGED / ABORTED`
- **检查状态**：`PENDING / BLOCKED / PASS / FAIL / SUPERSEDED`（门洁面可能显示 `MISSING`）
- **拒收原因 reason**：
  - `FINGERPRINT_MISMATCH` 结果指纹与冻结输入不符（拿错基线/输入被改）
  - `STALE_SUPERSEDED` run 已因纪元变化作废，结果迟到
  - `ALREADY_SUBMITTED` 同一 run 重复提交
  - `DEPENDENCY_BLOCKED` 依赖前置尚未全部 PASS
  - `ECO_NOT_ACTIVE` ECO 不在 FROZEN 态
  - `BASE_CONSTRAINT_CHANGED` 基础约束更新导致在验单整体作废（系统事件留痕）

### 验证执行租约（Lease Coordinator）

Runner 对验证矩阵中**已经就绪**（`check_run=PENDING` 且 ECO=FROZEN）的检查执行
领取/续租/完成/超时接管。每次领取返回 **`generation`（租约代次）**与
**`lease_token`（不可伪造凭据）**：token 为服务端持久密钥对
`(run_id, generation, nonce)` 的 HMAC，不落明文、重启后仍可验真。

- 领取**幂等**：同一 `(runner_id, idempotency_key)` 的重放/并发请求至多成功一次，
  其余返回同一份分配（`claimed:false, idempotent:true`）；不同 Runner 并发领取同一
  run 仅一个成功（`409 LEASE_HELD_BY_OTHER`）。
- 回传结果必须携带正确的 `generation + lease_token`。被接管后的旧持有者（旧代次）、
  错误 Runner、伪造/缺失凭据、过期租约、依赖未满足、重跑后旧代次迟到结果、
  无租约直交结果一律拒绝；拒绝写 `lease_audit`（可按 run / reason 查询）。
- 租约/审计落盘：重启后**恢复未过期租约**（旧 token 仍有效）并**回收过期/随纪元
  失效租约**（写 `reclaim` 审计）。
- **接管不绕过门禁**：租约通过后，结果仍调用原 ECO 服务 `submit_result`，
  `FINGERPRINT_MISMATCH / DEPENDENCY_BLOCKED / STALE_SUPERSEDED / ALREADY_SUBMITTED`
  等拒收语义、重跑/签核/发布约束全部保持不变；租约完成与 check_run 落定在**同一事务**。

租约原因码：`LEASE_HELD_BY_OTHER`（并发竞争落败）、`LEASE_TASK_NOT_READY`
（依赖未满足/非 PENDING）、`LEASE_TASK_SUPERSEDED`（run 已因重跑/纪元作废）、
`LEASE_TASK_FINISHED`、`LEASE_NOT_FOUND`（无有效租约）、`LEASE_GENERATION_STALE`
（代次落后，典型为被接管后的旧持有者/重跑后旧代次迟到）、`LEASE_NOT_HOLDER`、
`LEASE_BAD_CREDENTIAL`(403)、`LEASE_EXPIRED`、`LEASE_NOT_ACTIVE`、
`LEASE_NOT_TIMED_OUT`（未过期不可接管）、`LEASE_NOT_TAKEOVERABLE`、
`LEASE_RUN_SUPERSEDED`、`LEASE_TASK_INVALIDATED`。租约状态：
`HELD / COMPLETED / RELEASED / EXPIRED / INVALIDATED`。


### 临时代理签核授权

管理员可为两种签核角色（`TIMING_LEAD / METHODOLOGY_LEAD`）配置**临时代理人**及其
生效/失效时间窗，并可随时撤销。服务端在**签核动作发生的那一刻**重新校验授权
（而不是配置时或冻结时）：

- 未生效（当前时刻 < `valid_from`）→ `403 DELEGATION_NOT_STARTED`
- 已过期（当前时刻 ≥ `valid_until`，半开区间）→ `403 DELEGATION_EXPIRED`
- 已撤销（`status=REVOKED`）→ `403 DELEGATION_REVOKED`
- 授权角色与签核角色不符 → `403 DELEGATION_ROLE_MISMATCH`
- 授权代理人与操作人不符 → `403 DELEGATION_USER_MISMATCH`
- 授权记录不存在 → `404 DELEGATION_NOT_FOUND`

所有拒绝写入 `audit_log`（`signoff.denied`）。**同一自然人仍不得完成两个角色签核**，
直签与代理签合并判定（`409 DUAL_ROLE_CONFLICT`）。

代理签核成功后，签核记录固化当时的身份与代理链快照
（`signoff_kind=DELEGATE`、`delegation_id`、`auth_chain`：授权人、被代理负责人、
有效期、动作校验时刻），记录长期保留供审计；ECO 重新冻结（rebase / 合并 / 新基线发布）
仍使旧签核失效（标记 `voided_at`），新纪元须重新签核。

## 端点

### 基线与目录
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/baselines` | 发布基线列表 |
| GET | `/api/baselines/{id}` | 基线完整不可变快照 |
| GET | `/api/baselines/diff?from=&to=` | 结构化差异包 |
| GET | `/api/baselines/diff.zip?from=&to=` | ZIP 差异包（before/after/diff/矩阵/结果/签核）|
| GET | `/api/catalog` | 验证矩阵目录（必需性、依赖、指纹作用域）|
| GET | `/api/constraints` | 当前发布基线与工作约束版本 |
| GET | `/api/workbench` | 工作台聚合视图（含代理配置与当前可签人员）|
| GET | `/api/current-signers` | 每种角色当前可签代理（来源、有效期）|
| GET | `/api/admin/delegations` | 全部代理配置（含待生效/已过期/已撤销及实时状态）|
| GET | `/api/rejected-results` | 全部拒收/作废留痕 |

### ECO
| 方法 | 路径 | Body / 说明 |
|---|---|---|
| POST | `/api/ecos` | `{title, owner, affected_modules[], edits:{m:{netlist}}}` → 201 |
| POST | `/api/ecos/{id}/edits` | `{edits, by}` 仅 DRAFT/REBASE_REQUIRED |
| POST | `/api/ecos/{id}/freeze` | `{by}` 冲突时转 QUEUED，否则冻结+触发矩阵 |
| POST | `/api/ecos/{id}/abort` | `{by}` 释放锁并推动排队单晋升 |
| GET | `/api/ecos` / `/api/ecos/{id}` | 列表（含门禁摘要）/ 详情（含 gate/queue/release）|

### 验证（Runner 协议）
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/ecos/{id}/checks/{type}/inputs` | 拉冻结输入包（含 expected_fingerprint 供核对）|
| POST | `/api/ecos/{id}/checks/{type}/results` | `{run_id, fingerprint, verdict:PASS|FAIL, result, runner_id}` |
| POST | `/api/ecos/{id}/checks/{type}/rerun` | `{by}` 仅 FAIL 可重跑；旧尝试 SUPERSEDED，新 run 绑当前指纹 |

Runner **必须**对 `inputs` 自行按作用域计算 SHA-256 摘要（紧凑规范 JSON：
键排序、无空白、`ensure_ascii`），服务端不接受缺失/不符指纹。

### 验证执行租约协调
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/leases/pool?eco_id=` | 待领任务（就绪 PENDING）+ 全部租约（持有者/状态/剩余秒） |
| POST | `/api/leases/claim` | `{runner_id, idempotency_key?, run_id?, ttl_seconds?}` 原子领取；幂等；不指定 run_id 则领取下一个就绪任务；无任务返回 `claimed:false` |
| POST | `/api/leases/runs/{run_id}/renew` | `{runner_id, generation, lease_token, ttl_seconds?}` 续租（心跳），代次不变、续期计数+1 |
| POST | `/api/leases/runs/{run_id}/release` | `{runner_id, generation, lease_token}` 持有者主动释放，任务回池，代次+1 后可再领 |
| POST | `/api/leases/runs/{run_id}/takeover` | `{by_runner, ttl_seconds?}` **仅超时后**可接管；代次+1、凭据换新，旧持有者即刻失效 |
| POST | `/api/leases/runs/{run_id}/results` | `{runner_id, generation, lease_token, fingerprint, verdict, result}` 租约门禁通过后仍走 ECO 基线指纹/依赖门禁 |
| GET | `/api/leases/runs/{run_id}` | 租约状态 + 剩余秒 + **接管/事件历史** |
| GET | `/api/leases?state=` | 全部租约（可按状态过滤） |
| GET | `/api/leases/audit?run_id=&reason=&limit=` | 租约事件与拒绝原因审计（claim/renew/complete/release/takeover/reclaim/deny） |

领取成功返回示例（后续续租/释放/回传均回带 `generation` 与 `lease_token`）：

```json
{ "claimed": true, "idempotent": false, "run_id": "ECO-001:TIMING_STA:e1:a1",
  "eco_id": "ECO-001", "check_type": "TIMING_STA", "generation": 1,
  "runner_id": "runner-0", "state": "HELD", "ttl_seconds": 120,
  "expires_at": "2026-10-01T12:02:00+00:00", "remaining_seconds": 120,
  "lease_token": "9f2c…(32hex)",
  "inputs_path": "/api/ecos/ECO-001/checks/TIMING_STA/inputs",
  "result_path": "/api/leases/runs/ECO-001:TIMING_STA:e1:a1/results" }
```


### 签核与发布
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/ecos/{id}/signoff` | `{role, user, delegation_id?}` 门禁红时 409；同一人双签 409；带 `delegation_id` 时代理未生效/过期/撤销/角色或人不符 403/404 |
| POST | `/api/ecos/{id}/release` | `{by, failpoint?}` 门禁/双签不满足 409 且状态不变；`failpoint=AFTER_PHASE1` 注入崩溃 |
| POST | `/api/ecos/{id}/release/resume` | 从中断点幂等恢复 |

### 临时代理签核（管理员）
| 方法 | 路径 | Body / 说明 |
|---|---|---|
| POST | `/api/admin/delegations` | `{role, delegate_user, valid_from, valid_until, granted_by, principal_user?, note?}`；时间为 UTC ISO-8601。**相同角色+代理人+完全相同时间窗重复提交幂等**：返回既有记录（200，`deduped:true`），不生成重复有效记录；与该代理人该角色另一有效记录时间窗重叠 → 409 `DELEGATION_OVERLAP` |
| POST | `/api/admin/delegations/{id}/revoke` | `{revoked_by?}`（或 `by`）立即撤销；重复撤销幂等 |

签核记录字段：`signoff_kind=DIRECT|DELEGATE`、`delegation_id`、`auth_chain`（代理链快照）、
`voided_at/voided_reason`（被重新冻结等原因失效，记录保留）。
`GET /api/workbench` 额外包含 `delegations`（含实时 `state: PENDING/ACTIVE/EXPIRED/REVOKED`）
与 `current_signers`；工作台页面据此展示**当前可签人员、代理来源与有效期**。

### 冲突与基础约束
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/ecos/{src}/merge-into/{tgt}` | `{by, module_winners:{m:TARGET_WINS|SOURCE_WINS}}`；src 须 QUEUED、tgt 须 FROZEN 且确有未决阻塞；合并后 tgt 纪元+1 整轮重跑 |
| POST | `/api/constraints` | `{delta:{...}, by, note}` 存在 RELEASING 单时 409；否则在验 FROZEN 单全部转 REBASE_REQUIRED |
| POST | `/api/admin/reset` | 重置为种子数据 |

## 典型时序（一次合规发布）

```
create → freeze → (Runner: inputs→自算指纹→results) ×依赖图
       → TIMING_LEAD signoff → METHODOLOGY_LEAD signoff(不同人)
       → release(阶段1锁状态 → 阶段2原子写 B-R{n}、推进 trunk)
```

## 典型时序（迟到结果）

```
ECO FROZEN 全绿 → POST /api/constraints 收紧时钟
  → ECO=REBASE_REQUIRED, 旧 run 全 SUPERSEDED, 旧签核失效
迟到 Runner 回传旧 run_id → 409 STALE_SUPERSEDED（rejected_result 留痕）
工程师 freeze(refreeze, epoch=2) → 矩阵重跑 → 双签 → 才能发布
```
