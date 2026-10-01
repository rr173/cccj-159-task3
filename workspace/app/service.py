"""核心领域服务：ECO 冻结、验证矩阵依赖调度、签核门禁、基线发布与差异包。

关键不变量：
1. 每条 check_run 绑定冻结时按作用域计算的指纹；迟到结果指纹不符一律拒收并留痕，
   绝不与其他基线的旧结果拼接。
2. 冻结纪元(freeze_epoch)变化（基础约束刷新 / 合并扩张 / rebase）即作废旧结果与签核。
3. 模块锁互斥；重叠 ECO 要么排队(QUEUED)，要么经裁决合并(MERGED)。
4. 发布是可恢复的两阶段事务；只有全部必需检查针对同一基线通过且双角色不同人签核，
   才能形成新发布基线。
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from difflib import unified_diff

from .store import CHECKS, Store, utcnow

ROLE_TIMING = "TIMING_LEAD"
ROLE_METHOD = "METHODOLOGY_LEAD"
SIGNOFF_ROLES = [ROLE_TIMING, ROLE_METHOD]
ROLE_LABELS = {ROLE_TIMING: "时序负责人", ROLE_METHOD: "方法学负责人"}


def parse_ts(s: str) -> datetime:
    """解析 UTC ISO-8601 时间串。无时区后缀按 UTC 处理，统一为感知 UTC。"""
    if not isinstance(s, str) or not s.strip():
        raise ValueError("时间为空")
    txt = s.strip()
    if txt.endswith("Z"):
        txt = txt[:-1] + "+00:00"
    dt = datetime.fromisoformat(txt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class ECOError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 409, extra=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.extra = extra or {}


# ---------------------------------------------------------------- 指纹与快照

def canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def fp_json(obj) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()[:16]


def matrix_catalog():
    return [
        {"type": t, "label": c["label"], "required": c["required"],
         "depends_on": list(c["depends_on"]), "scopes": list(c["scopes"])}
        for t, c in CHECKS.items()
    ]


def build_snapshot(modules: dict, constraints: dict, affected: list[str], note: str = ""):
    """构造不可变冻结快照：网表 + 约束 + 受影响模块 + 验证矩阵。"""
    return {
        "schema": "chip-eco-baseline/1",
        "note": note,
        "frozen_at": utcnow(),
        "affected_modules": sorted(affected),
        "constraints": constraints,
        "modules": copy.deepcopy(modules),
        "verification_matrix": matrix_catalog(),
    }


def snapshot_fingerprint(snap: dict) -> str:
    return fp_json({
        "affected_modules": snap["affected_modules"],
        "constraints": snap["constraints"],
        "modules": snap["modules"],
        "verification_matrix": snap["verification_matrix"],
    })


def scope_fingerprint(snap: dict, scopes: list[str]) -> str:
    """检查只对其作用域内的冻结输入负责；矩阵恒为输入的一部分。"""
    obj: dict = {"verification_matrix": snap["verification_matrix"]}
    if "netlist" in scopes:
        obj["modules"] = {
            m: {"netlist": d["netlist"], "version": d["version"]}
            for m, d in sorted(snap["modules"].items())
        }
    if "sdc" in scopes:
        obj["constraints"] = snap["constraints"]
    if "modules" in scopes:
        obj["affected_modules"] = snap["affected_modules"]
    return fp_json(obj)


# ---------------------------------------------------------------- 数据整形

def _baseline_dict(row):
    d = dict(row)
    d["snapshot"] = json.loads(d.pop("snapshot_json"))
    return d


def _eco_dict(row):
    d = dict(row)
    for k in ("affected_modules_json", "edits_json", "snapshot_json", "merge_of_json"):
        d[k.removesuffix("_json")] = json.loads(d.pop(k)) if d[k] is not None else None
    return d# ---------------------------------------------------------------- 服务

class ECOService:
    def __init__(self, store: Store, now_fn=utcnow):
        self.s = store
        # 可注入时钟（测试需精确控制生效/失效边界）；默认走系统 UTC 时钟
        self._now_fn = now_fn

    def _now(self) -> datetime:
        """当前时刻（感知 UTC datetime），签核授权一律以此刻为准。"""
        v = self._now_fn()
        return parse_ts(v) if isinstance(v, str) else v.astimezone(timezone.utc)

    def _now_str(self) -> str:
        return self._now().isoformat(timespec="seconds")

    # ===== 通用 =====
    def _audit(self, c, action: str, entity=None, actor=None, detail=None):
        c.execute("INSERT INTO audit_log(actor,action,entity,at,detail_json) VALUES(?,?,?,?,?)",
                  (actor, action, entity, utcnow(), json.dumps(detail or {}, ensure_ascii=False)))

    def _reject(self, reason, run=None, detail=None):
        self.s.conn.execute(
            "INSERT INTO rejected_result(run_id,eco_id,check_type,reason,detail_json,received_at)"
            " VALUES(?,?,?,?,?,?)",
            (run["id"] if run else None, run["eco_id"] if run else None,
             run["check_type"] if run else None, reason,
             json.dumps(detail or {}, ensure_ascii=False), utcnow()))

    def _signoff_dict(self, row):
        """签核记录整形：保留当时身份与代理链（DIRECT/DELEGATE）用于审计。"""
        d = dict(row)
        d["auth_chain"] = json.loads(d.pop("auth_chain_json") or "{}")
        return d

    def _get_eco(self, eco_id: str):
        row = self.s.q_one("SELECT * FROM eco WHERE id=?", (eco_id,))
        if not row:
            raise ECOError("ECO_NOT_FOUND", f"ECO {eco_id} 不存在", 404)
        return row

    def _get_baseline(self, bid: str):
        row = self.s.q_one("SELECT * FROM baseline WHERE id=?", (bid,))
        if not row:
            raise ECOError("BASELINE_NOT_FOUND", f"基线 {bid} 不存在", 404)
        return _baseline_dict(row)

    def _trunk(self, c):
        return c.execute("SELECT * FROM trunk WHERE id=1").fetchone()

    def _base_snapshot(self, c):
        t = self._trunk(c)
        return _baseline_dict(c.execute(
            "SELECT * FROM baseline WHERE id=?", (t["base_id"],)).fetchone())["snapshot"]

    # ===== 基线查询 =====
    def list_baselines(self):
        rows = self.s.q_all("SELECT * FROM baseline ORDER BY revision")
        out = []
        for r in rows:
            d = _baseline_dict(r)
            snap = d["snapshot"]
            out.append({
                "id": d["id"], "revision": d["revision"], "parent_id": d["parent_id"],
                "eco_id": d["eco_id"], "created_at": d["created_at"],
                "fingerprint": d["fingerprint"],
                "affected_modules": snap["affected_modules"],
                "constraints_version_note": snap.get("note", ""),
                "module_count": len(snap["modules"]),
            })
        return out

    def baseline_detail(self, bid):
        return self._get_baseline(bid)

    def check_catalog(self):
        return {"checks": matrix_catalog()}

    # ===== ECO 生命周期 =====
    def create_eco(self, title: str, owner: str, affected_modules: list[str],
                   edits: dict | None = None) -> dict:
        if not title or not owner:
            raise ECOError("BAD_REQUEST", "title/owner 必填", 400)
        with self.s.tx() as c:
            base = self._base_snapshot(c)
            unknown = [m for m in affected_modules if m not in base["modules"]]
            if unknown:
                raise ECOError("UNKNOWN_MODULE", f"模块不存在: {unknown}", 400)
            if not affected_modules:
                raise ECOError("EMPTY_SCOPE", "至少选择一个受影响模块", 400)
            edits = edits or {}
            bad = [m for m in edits if m not in affected_modules]
            if bad:
                raise ECOError("EDIT_OUT_OF_SCOPE", f"编辑了未声明受影响的模块: {bad}", 400)
            for m, e in edits.items():
                if not isinstance(e, dict) or not isinstance(e.get("netlist"), str):
                    raise ECOError("BAD_EDIT", f"模块 {m} 的编辑必须形如 {{'netlist': '...'}}", 400)
            n = c.execute("SELECT COUNT(*) k FROM eco").fetchone()["k"]
            eco_id = f"ECO-{n + 1:03d}"
            c.execute(
                "INSERT INTO eco(id,title,owner,status,affected_modules_json,edits_json,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (eco_id, title, owner, "DRAFT",
                 json.dumps(sorted(affected_modules)), json.dumps(edits, ensure_ascii=False),
                 utcnow()))
            self._audit(c, "eco.create", eco_id, owner, {"title": title})
            return self.eco_detail(eco_id, c)

    def update_edits(self, eco_id, edits: dict, by: str):
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            if eco["status"] not in ("DRAFT", "REBASE_REQUIRED"):
                raise ECOError("NOT_EDITABLE",
                               f"状态 {eco['status']} 下不可修改编辑（需先中止或刷新）", 409)
            modules = json.loads(eco["affected_modules_json"])
            bad = [m for m in edits if m not in modules]
            if bad:
                raise ECOError("EDIT_OUT_OF_SCOPE", f"模块超出受影响范围: {bad}", 400)
            merged = {**json.loads(eco["edits_json"]), **edits}
            c.execute("UPDATE eco SET edits_json=? WHERE id=?",
                      (json.dumps(merged, ensure_ascii=False), eco_id))
            self._audit(c, "eco.edit", eco_id, by, {"keys": sorted(edits)})
            return self.eco_detail(eco_id, c)

    def _effective_modules(self, base_modules: dict, affected, edits):
        mods = copy.deepcopy(base_modules)
        for m in affected:
            if m in edits:
                mods[m] = {"netlist": edits[m]["netlist"],
                           "version": base_modules[m]["version"] + 1}
        return mods

    def _dispatch(self, c, eco):
        """按依赖图创建新一轮检查：无依赖 PENDING，其余 BLOCKED 等待前置通过。

        run id 带冻结纪元：纪元变化后旧 run 全部 SUPERSEDED，新 run 重新绑定
        当前冻结输入的指纹，杜绝跨基线结果拼接。
        """
        snap = json.loads(eco["snapshot_json"])
        epoch = eco["freeze_epoch"]
        for t, spec in CHECKS.items():
            attempt = c.execute(
                "SELECT COALESCE(MAX(attempt),0)+1 a FROM check_run WHERE eco_id=? AND check_type=?",
                (eco["id"], t)).fetchone()["a"]
            c.execute(
                "INSERT INTO check_run(id,eco_id,check_type,attempt,status,required,"
                "depends_on_json,expected_fp) VALUES(?,?,?,?,?,?,?,?)",
                (f"{eco['id']}:{t}:e{epoch}:a{attempt}", eco["id"], t, attempt,
                 "PENDING" if not spec["depends_on"] else "BLOCKED",
                 int(spec["required"]), json.dumps(spec["depends_on"]),
                 scope_fingerprint(snap, spec["scopes"])))

    def _supersede_runs(self, c, eco_id, reason: str):
        """纪元变化：该 ECO 全部既有检查作废（含已 PASS），迟到提交将被拒收。"""
        cur = c.execute(
            "SELECT * FROM check_run WHERE eco_id=? AND status!='SUPERSEDED'", (eco_id,))
        rows = cur.fetchall()
        for r in rows:
            c.execute("UPDATE check_run SET status='SUPERSEDED' WHERE id=?", (r["id"],))
        return len(rows)

    def _void_signoffs(self, c, eco_id, reason="epoch/fingerprint changed"):
        """纪元/基线变化时作废旧签核（ECO 重新冻结同样使旧签核失效）。

        历史记录**保留**在 signoff 表（含当时身份与代理链）用于审计；将其标记 voided 后，
        门禁与发布不再认这些记录，同纪元同角色重签也不会与 UNIQUE(eco_id,role,epoch) 冲突。
        """
        c.execute(
            "UPDATE signoff SET voided_at=?, voided_reason=? "
            "WHERE eco_id=? AND voided_at IS NULL",
            (utcnow(), reason, eco_id))

    def _lock_conflicts(self, c, modules, exclude_eco=None):
        q = ("SELECT module, eco_id FROM module_lock WHERE module IN (%s)"
             % ",".join("?" * len(modules)))
        args = list(modules)
        rows = c.execute(q, args).fetchall()
        return [dict(r) for r in rows if r["eco_id"] != exclude_eco]

    def freeze_eco(self, eco_id: str, by: str) -> dict:
        """提交 ECO：冻结网表/约束/受影响模块/验证矩阵并触发检查。

        模块被占用时不冻结，转入 QUEUED 排队并登记阻塞关系。
        """
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            if eco["status"] not in ("DRAFT", "REBASE_REQUIRED"):
                raise ECOError("NOT_FREEZABLE",
                               f"状态 {eco['status']} 不可冻结", 409)
            modules = json.loads(eco["affected_modules_json"])
            edits = json.loads(eco["edits_json"])
            conflicts = self._lock_conflicts(c, modules, exclude_eco=eco_id)
            if conflicts:
                c.execute("UPDATE eco SET status='QUEUED' WHERE id=?", (eco_id,))
                for cf in conflicts:
                    exists = c.execute(
                        "SELECT 1 FROM queue_entry WHERE eco_id=? AND blocker_eco_id=? "
                        "AND module=? AND resolved_at IS NULL",
                        (eco_id, cf["eco_id"], cf["module"])).fetchone()
                    if not exists:
                        c.execute(
                            "INSERT INTO queue_entry(eco_id,blocker_eco_id,module,created_at)"
                            " VALUES(?,?,?,?)",
                            (eco_id, cf["eco_id"], cf["module"], utcnow()))
                self._audit(c, "eco.queue", eco_id, by, {"conflicts": conflicts})
                return self.eco_detail(eco_id, c)

            trunk = self._trunk(c)
            base_snap = self._base_snapshot(c)
            constraints = json.loads(trunk["working_constraints_json"])
            eff_mods = self._effective_modules(base_snap["modules"], modules, edits)
            snap = build_snapshot(eff_mods, constraints, modules,
                                 note=f"{eco_id} 冻结于 {trunk['base_id']}")
            fp = snapshot_fingerprint(snap)
            epoch = eco["freeze_epoch"] + 1
            c.execute(
                "UPDATE eco SET status='FROZEN',submitted_at=COALESCE(submitted_at,?),"
                "frozen_at=?,parent_baseline_id=?,base_revision_at_freeze=?,"
                "constraints_version_at_freeze=?,snapshot_json=?,fingerprint=?,freeze_epoch=?"
                " WHERE id=?",
                (utcnow(), utcnow(), trunk["base_id"], trunk["base_revision"],
                 trunk["constraints_version"], json.dumps(snap, ensure_ascii=False), fp,
                 epoch, eco_id))
            self._supersede_runs(c, eco_id, "refreeze")
            self._void_signoffs(c, eco_id, "ECO refrozen: epoch/fingerprint changed")
            for m in modules:
                # 重冻结（rebase/合并后）时锁可能仍属于本 ECO
                c.execute("INSERT OR IGNORE INTO module_lock(module,eco_id,acquired_at)"
                          " VALUES(?,?,?)", (m, eco_id, utcnow()))
            eco = self._get_eco(eco_id)
            self._dispatch(c, eco)
            self._audit(c, "eco.freeze", eco_id, by,
                        {"fingerprint": fp, "epoch": epoch, "modules": modules})
            return self.eco_detail(eco_id, c)

    def abort_eco(self, eco_id, by):
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            if eco["status"] in ("RELEASED", "MERGED", "RELEASING"):
                raise ECOError("NOT_ABORTABLE", f"状态 {eco['status']} 不可中止", 409)
            c.execute("UPDATE eco SET status='ABORTED' WHERE id=?", (eco_id,))
            c.execute("DELETE FROM module_lock WHERE eco_id=?", (eco_id,))
            c.execute("UPDATE queue_entry SET resolved_at=?, resolution='ABORT' "
                      "WHERE blocker_eco_id=? AND resolved_at IS NULL", (utcnow(), eco_id))
            c.execute("UPDATE queue_entry SET resolved_at=?, resolution='ABORT' "
                      "WHERE eco_id=? AND resolved_at IS NULL", (utcnow(), eco_id))
            self._audit(c, "eco.abort", eco_id, by)
            self._promote_waiting(c)
            return self.eco_detail(eco_id, c)

    # ===== 验证矩阵调度 =====
    def _active_runs(self, c, eco_id):
        return c.execute(
            "SELECT * FROM check_run WHERE eco_id=? AND status!='SUPERSEDED'",
            (eco_id,)).fetchall()

    def _advance(self, c, eco_id):
        """前置全部 PASS 后解除 BLOCKED；前置 FAIL 则继续阻塞（依赖图不调度）。"""
        runs = {r["check_type"]: r for r in self._active_runs(c, eco_id)}
        for t, r in runs.items():
            if r["status"] != "BLOCKED":
                continue
            deps = json.loads(r["depends_on_json"])
            if deps and all(runs.get(d) and runs[d]["status"] == "PASS" for d in deps):
                c.execute("UPDATE check_run SET status='PENDING' WHERE id=?", (r["id"],))

    def check_inputs(self, eco_id, check_type):
        """Runner 拉取冻结输入包，并据其内容自行计算/核对指纹。"""
        if check_type not in CHECKS:
            raise ECOError("UNKNOWN_CHECK", f"未知检查类型 {check_type}", 400)
        with self.s.lock:
            run = self.s.q_one(
                "SELECT * FROM check_run WHERE eco_id=? AND check_type=? AND status!='SUPERSEDED'",
                (eco_id, check_type))
            if not run:
                raise ECOError("RUN_NOT_FOUND", "检查不存在或已作废", 404)
            eco = self._get_eco(eco_id)
            snap = json.loads(eco["snapshot_json"])
            spec = CHECKS[check_type]
            inputs = {"verification_matrix": snap["verification_matrix"]}
            if "netlist" in spec["scopes"]:
                inputs["modules"] = snap["modules"]
            if "sdc" in spec["scopes"]:
                inputs["constraints"] = snap["constraints"]
            if "modules" in spec["scopes"]:
                inputs["affected_modules"] = snap["affected_modules"]
            return {
                "run_id": run["id"], "eco_id": eco_id, "check_type": check_type,
                "status": run["status"], "expected_fingerprint": run["expected_fp"],
                "scopes": spec["scopes"], "inputs": inputs,
            }

    def submit_result(self, run_id, fingerprint, verdict, result=None, runner_id="runner-0"):
        """提交验证结果。指纹不符 / 已作废 / 前置未过 / 重复提交一律拒收，绝不复用。

        拒收记录在独立事务中持久化：校验事务回滚不影响审计留痕。
        """
        result = result or {}
        try:
            with self.s.tx() as c:
                run = c.execute("SELECT * FROM check_run WHERE id=?", (run_id,)).fetchone()
                if not run:
                    raise ECOError("RUN_NOT_FOUND", f"运行 {run_id} 不存在", 404)
                eco = c.execute("SELECT * FROM eco WHERE id=?", (run["eco_id"],)).fetchone()

                def reject(reason, detail):
                    raise ECOError("RESULT_REJECTED",
                                   f"结果拒收: {reason}（旧结果不得拼接复用）", 409,
                                   {"reason": reason, **detail})

                if run["status"] == "SUPERSEDED":
                    reject("STALE_SUPERSEDED",
                           {"run_id": run_id, "eco_freeze_epoch": eco["freeze_epoch"]})
                if eco["status"] != "FROZEN":
                    reject("ECO_NOT_ACTIVE", {"eco_status": eco["status"]})
                if verdict not in ("PASS", "FAIL"):
                    reject("BAD_VERDICT", {"verdict": verdict})
                if not fingerprint:
                    reject("MISSING_FINGERPRINT", {})
                if fingerprint != run["expected_fp"]:
                    reject("FINGERPRINT_MISMATCH",
                           {"submitted_fp": fingerprint, "expected_fp": run["expected_fp"],
                            "check_type": run["check_type"]})
                if run["status"] == "BLOCKED":
                    reject("DEPENDENCY_BLOCKED",
                           {"depends_on": json.loads(run["depends_on_json"])})
                if run["status"] in ("PASS", "FAIL"):
                    reject("ALREADY_SUBMITTED", {"existing": run["status"]})

                c.execute(
                    "UPDATE check_run SET status=?,result_fp=?,result_json=?,submitted_at=?,"
                    "runner_id=? WHERE id=?",
                    (verdict, fingerprint, json.dumps(result, ensure_ascii=False), utcnow(),
                     runner_id, run_id))
                self._audit(c, "check.result", run_id, runner_id,
                            {"verdict": verdict, "check": run["check_type"]})
                self._advance(c, run["eco_id"])
                return self.eco_detail(run["eco_id"], c)
        except ECOError as e:
            if e.code == "RESULT_REJECTED":
                with self.s.tx() as c:
                    r = c.execute("SELECT * FROM check_run WHERE id=?", (run_id,)).fetchone()
                    self._reject(e.extra.get("reason", "REJECTED"), r,
                                 {k: v for k, v in e.extra.items() if k != "reason"})
            raise

    def rerun_check(self, eco_id, check_type, by):
        """FAIL 的检查可重跑：旧尝试标记 SUPERSEDED，新尝试重新绑定当前冻结指纹。"""
        if check_type not in CHECKS:
            raise ECOError("UNKNOWN_CHECK", f"未知检查类型 {check_type}", 400)
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            if eco["status"] != "FROZEN":
                raise ECOError("NOT_FROZEN", "仅 FROZEN 状态可重跑检查", 409)
            run = c.execute(
                "SELECT * FROM check_run WHERE eco_id=? AND check_type=? AND status!='SUPERSEDED'",
                (eco_id, check_type)).fetchone()
            if not run:
                raise ECOError("RUN_NOT_FOUND", "检查不存在", 404)
            if run["status"] != "FAIL":
                raise ECOError("NOT_RERUNNABLE",
                               f"当前状态 {run['status']}，仅 FAIL 可重跑", 409)
            attempt = run["attempt"] + 1
            c.execute("UPDATE check_run SET status='SUPERSEDED' WHERE id=?", (run["id"],))
            snap = json.loads(eco["snapshot_json"])
            spec = CHECKS[check_type]
            deps = json.loads(run["depends_on_json"])
            active = {r["check_type"]: r for r in self._active_runs(c, eco_id)}
            unblocked = all(active.get(d) and active[d]["status"] == "PASS" for d in deps) if deps else True
            c.execute(
                "INSERT INTO check_run(id,eco_id,check_type,attempt,status,required,"
                "depends_on_json,expected_fp) VALUES(?,?,?,?,?,?,?,?)",
                (f"{eco_id}:{check_type}:e{eco['freeze_epoch']}:a{attempt}", eco_id, check_type, attempt,
                 "PENDING" if unblocked else "BLOCKED", int(spec["required"]),
                 json.dumps(deps), scope_fingerprint(snap, spec["scopes"])))
            self._audit(c, "check.rerun", f"{eco_id}:{check_type}", by, {"attempt": attempt})
            return self.eco_detail(eco_id, c)

    # ===== 临时代理签核授权 =====
    def _delegation_state(self, row, now: datetime | None = None) -> str:
        """按当前时刻计算授权状态：PENDING / ACTIVE / EXPIRED / REVOKED。"""
        if row["status"] == "REVOKED":
            return "REVOKED"
        now = now or self._now()
        vf, vu = parse_ts(row["valid_from"]), parse_ts(row["valid_until"])
        if now < vf:
            return "PENDING"
        if now >= vu:
            return "EXPIRED"
        return "ACTIVE"

    def _delegation_dict(self, row, now: datetime | None = None):
        d = dict(row)
        d["state"] = self._delegation_state(row, now)
        d["role_label"] = ROLE_LABELS.get(d["role"], d["role"])
        d["active"] = d["state"] == "ACTIVE"
        return d

    def _active_delegation(self, c, role, user, now: datetime | None = None):
        """动作发生时的有效授权：角色/代理人匹配且当前时刻落在半开 [from, until) 内。"""
        now = now or self._now()
        rows = c.execute(
            "SELECT * FROM signoff_delegation WHERE role=? AND delegate_user=? AND status='ACTIVE'",
            (role, user)).fetchall()
        for r in rows:
            if parse_ts(r["valid_from"]) <= now < parse_ts(r["valid_until"]):
                return r
        return None

    def create_delegation(self, role, delegate_user, valid_from, valid_until,
                          granted_by, principal_user=None, note=""):
        """管理员配置一条临时代理签核授权。

        - 同一代理配置（角色+代理人+完全相同的时间窗）重复提交：幂等返回既有有效记录，
          不生成重复记录；
        - 与该代理人该角色另一条有效记录的时间窗重叠：409 DELEGATION_OVERLAP；
        - 时间窗非法（空、失效不晚于生效）：400。
        """
        if role not in SIGNOFF_ROLES:
            raise ECOError("BAD_ROLE", f"角色须为 {SIGNOFF_ROLES}", 400)
        if not delegate_user:
            raise ECOError("BAD_REQUEST", "delegate_user 必填", 400)
        if not granted_by:
            raise ECOError("BAD_REQUEST", "granted_by 必填（执行配置的管理员）", 400)
        try:
            vf, vu = parse_ts(valid_from), parse_ts(valid_until)
        except (ValueError, TypeError) as e:
            raise ECOError("BAD_TIME", f"生效/失效时间须为 ISO-8601: {e}", 400)
        vf_s, vu_s = vf.isoformat(timespec="seconds"), vu.isoformat(timespec="seconds")
        if vu <= vf:
            raise ECOError("BAD_TIME_WINDOW", "失效时间必须晚于生效时间", 400)
        with self.s.tx() as c:
            existing = c.execute(
                "SELECT * FROM signoff_delegation WHERE role=? AND delegate_user=? "
                "AND valid_from=? AND valid_until=? AND status='ACTIVE'",
                (role, delegate_user, vf_s, vu_s)).fetchone()
            if existing:
                d = self._delegation_dict(existing, vf)
                d["deduped"] = True
                return d
            overlaps = []
            for r in c.execute(
                    "SELECT * FROM signoff_delegation WHERE role=? AND delegate_user=? "
                    "AND status='ACTIVE'", (role, delegate_user)).fetchall():
                if vf < parse_ts(r["valid_until"]) and parse_ts(r["valid_from"]) < vu:
                    overlaps.append(self._delegation_dict(r, vf))
            if overlaps:
                raise ECOError("DELEGATION_OVERLAP",
                               "该代理人在此角色上已有时间窗重叠的有效代理授权", 409,
                               {"overlaps": [{"id": o["id"], "valid_from": o["valid_from"],
                                              "valid_until": o["valid_until"]}
                                             for o in overlaps]})
            cur = c.execute(
                "INSERT INTO signoff_delegation(role,delegate_user,principal_user,granted_by,"
                "granted_at,valid_from,valid_until,note) VALUES(?,?,?,?,?,?,?,?)",
                (role, delegate_user, principal_user, granted_by,
                 self._now_str(), vf_s, vu_s, note))
            row = c.execute("SELECT * FROM signoff_delegation WHERE id=?",
                            (cur.lastrowid,)).fetchone()
            self._audit(c, "delegation.grant", f"delegation:{row['id']}", granted_by,
                        {"role": role, "delegate_user": delegate_user,
                         "principal_user": principal_user,
                         "valid_from": vf_s, "valid_until": vu_s, "note": note})
            d = self._delegation_dict(row, self._now())
            d["deduped"] = False
            return d

    def list_delegations(self, include_revoked=True):
        with self.s.lock:
            sql = "SELECT * FROM signoff_delegation"
            if not include_revoked:
                sql += " WHERE status='ACTIVE'"
            sql += " ORDER BY id DESC"
            now = self._now()
            return [self._delegation_dict(r, now) for r in self.s.q_all(sql)]

    def get_delegation(self, delegation_id):
        row = self.s.q_one("SELECT * FROM signoff_delegation WHERE id=?", (delegation_id,))
        if not row:
            raise ECOError("DELEGATION_NOT_FOUND", f"代理授权 {delegation_id} 不存在", 404)
        return self._delegation_dict(row)

    def revoke_delegation(self, delegation_id, revoked_by):
        """撤销代理。撤销在签核动作发生时即时生效；对已撤销记录重复撤销幂等。"""
        if not revoked_by:
            raise ECOError("BAD_REQUEST", "revoked_by 必填", 400)
        with self.s.tx() as c:
            row = c.execute("SELECT * FROM signoff_delegation WHERE id=?",
                            (delegation_id,)).fetchone()
            if not row:
                raise ECOError("DELEGATION_NOT_FOUND",
                               f"代理授权 {delegation_id} 不存在", 404)
            if row["status"] == "REVOKED":
                d = self._delegation_dict(row)
                d["deduped"] = True
                return d
            c.execute("UPDATE signoff_delegation SET status='REVOKED',revoked_at=?,revoked_by=? "
                      "WHERE id=?", (self._now_str(), revoked_by, delegation_id))
            self._audit(c, "delegation.revoke", f"delegation:{delegation_id}", revoked_by,
                        {"role": row["role"], "delegate_user": row["delegate_user"],
                         "valid_from": row["valid_from"], "valid_until": row["valid_until"]})
            row = c.execute("SELECT * FROM signoff_delegation WHERE id=?",
                            (delegation_id,)).fetchone()
            d = self._delegation_dict(row)
            d["deduped"] = False
            return d

    def current_signers(self):
        """页面展示：每种角色当前可签的自然人（本人 + 有效代理）及其来源/有效期。"""
        with self.s.lock:
            now = self._now()
            delegates = [self._delegation_dict(r, now)
                         for r in self.s.q_all(
                             "SELECT * FROM signoff_delegation WHERE status='ACTIVE' ORDER BY id")]
            active = [d for d in delegates if d["state"] == "ACTIVE"]
            by_role = {}
            for role in SIGNOFF_ROLES:
                grants = [d for d in active if d["role"] == role]
                by_role[role] = {
                    "role": role, "role_label": ROLE_LABELS[role],
                    "delegates": [
                        {"user": d["delegate_user"], "principal_user": d["principal_user"],
                         "delegation_id": d["id"], "granted_by": d["granted_by"],
                         "valid_from": d["valid_from"], "valid_until": d["valid_until"],
                         "source": (f"代理 {d['principal_user']}" if d["principal_user"]
                                    else f"{ROLE_LABELS[role]}临时代理")}
                        for d in grants],
                    "delegate_users": sorted({d["delegate_user"] for d in grants}),
                }
            return {"at": now.isoformat(timespec="seconds"), "roles": by_role}

    # ===== 门禁与签核 =====
    def gate(self, eco_row, c):
        eco_id = eco_row["id"]
        runs = c.execute(
            "SELECT * FROM check_run r WHERE eco_id=? AND attempt=("
            "SELECT MAX(attempt) FROM check_run WHERE eco_id=r.eco_id AND check_type=r.check_type)"
            " ORDER BY check_type", (eco_id,)).fetchall()
        checks_out, required_pass = [], True
        for t, spec in CHECKS.items():
            r = next((x for x in runs if x["check_type"] == t), None)
            status = r["status"] if r else "MISSING"
            fp_ok = bool(r and r["result_fp"] and r["result_fp"] == r["expected_fp"])
            satisfied = status == "PASS" and fp_ok
            if spec["required"] and not satisfied:
                required_pass = False
            deps = json.loads(r["depends_on_json"]) if r else []
            dep_status = {d: next((x["status"] for x in runs if x["check_type"] == d), "MISSING")
                          for d in deps}
            checks_out.append({
                "type": t, "label": spec["label"], "required": spec["required"],
                "status": status, "fingerprint_ok": fp_ok, "satisfied": satisfied,
                "depends_on": deps, "dep_status": dep_status,
                "submitted_at": r["submitted_at"] if r else None,
                "runner_id": r["runner_id"] if r else None,
                "result": json.loads(r["result_json"]) if r and r["result_json"] else None,
            })
        signoffs = [self._signoff_dict(r) for r in c.execute(
            "SELECT * FROM signoff WHERE eco_id=? ORDER BY role", (eco_id,)).fetchall()]
        epoch = eco_row["freeze_epoch"]
        valid_sigs = [s for s in signoffs if s["voided_at"] is None and s["epoch"] == epoch
                      and s["overall_fp"] == eco_row["fingerprint"]]
        roles = {s["role"]: s["user"] for s in valid_sigs}
        dual = all(r in roles for r in SIGNOFF_ROLES) and len(set(roles.values())) == 2
        return {
            "checks": checks_out,
            "required_all_pass": required_pass,
            "signoffs": signoffs,
            "valid_signoffs": valid_sigs,
            "dual_role_complete": dual,
            "green": required_pass,
            "releasable": required_pass and dual,
        }

    def _deny_signoff_audit(self, eco_id, role, user, code, detail):
        """授权被拒也要留痕（独立事务，校验回滚不影响审计）。"""
        with self.s.tx() as c:
            self._audit(c, "signoff.denied", eco_id, user,
                        {"role": role, "reason": code, **(detail or {})})

    def signoff(self, eco_id, role, user, delegation_id=None):
        """双角色签核。授权一律以**动作发生时刻**校验：

        - 带 delegation_id：必须指向该角色、该代理人、当前未撤销且在有效期内的授权；
        - 不带 delegation_id：本人直签（DIRECT），或恰好持有该角色当前有效代理（DELEGATE）；
        - 代理未生效 / 已过期 / 已撤销 / 角色或代理人不符 → 拒绝签核；
        - 同一自然人不得完成两个角色签核（直签与代理签合并判定）。
        """
        if role not in SIGNOFF_ROLES:
            raise ECOError("BAD_ROLE", f"角色须为 {SIGNOFF_ROLES}", 400)
        if not user:
            raise ECOError("BAD_REQUEST", "user 必填", 400)
        try:
            with self.s.tx() as c:
                eco = self._get_eco(eco_id)
                if eco["status"] != "FROZEN":
                    raise ECOError("NOT_FROZEN", f"状态 {eco['status']} 不可签核", 409)
                g = self.gate(eco, c)
                if not g["green"]:
                    raise ECOError("GATE_RED", "必需检查未全部针对当前基线通过，禁止签核", 409,
                                   {"checks": [{"type": x["type"], "status": x["status"]}
                                               for x in g["checks"] if x["required"]
                                               and not x["satisfied"]]})
                # ---- 动作发生时的授权校验 ----
                now = self._now()
                now_s = now.isoformat(timespec="seconds")
                kind = "DIRECT"
                delegation = None
                if delegation_id is not None:
                    drow = c.execute("SELECT * FROM signoff_delegation WHERE id=?",
                                     (delegation_id,)).fetchone()
                    if not drow:
                        raise ECOError("DELEGATION_NOT_FOUND",
                                       f"代理授权 {delegation_id} 不存在", 404)
                    if drow["role"] != role:
                        raise ECOError("DELEGATION_ROLE_MISMATCH",
                                       "该代理授权的角色与本次签核角色不一致", 403,
                                       {"delegation_role": drow["role"], "requested_role": role})
                    if drow["delegate_user"] != user:
                        raise ECOError("DELEGATION_USER_MISMATCH",
                                       "该代理授权不属于当前操作人", 403,
                                       {"delegate_user": drow["delegate_user"], "user": user})
                    if drow["status"] == "REVOKED":
                        raise ECOError("DELEGATION_REVOKED",
                                       "代理授权已被撤销，禁止据此签核", 403,
                                       {"revoked_at": drow["revoked_at"],
                                        "revoked_by": drow["revoked_by"]})
                    if now < parse_ts(drow["valid_from"]):
                        raise ECOError("DELEGATION_NOT_STARTED",
                                       "代理授权尚未生效，禁止提前签核", 403,
                                       {"valid_from": drow["valid_from"], "at": now_s})
                    if now >= parse_ts(drow["valid_until"]):
                        raise ECOError("DELEGATION_EXPIRED",
                                       "代理授权已过期，禁止据此签核", 403,
                                       {"valid_until": drow["valid_until"], "at": now_s})
                    kind, delegation = "DELEGATE", drow
                else:
                    active = self._active_delegation(c, role, user, now)
                    if active:
                        kind, delegation = "DELEGATE", active

                # ---- 同一自然人禁止双角色签核（直签/代理一视同仁）----
                other = next((s for s in g["valid_signoffs"]
                              if s["role"] != role and s["user"] == user), None)
                if other:
                    raise ECOError("DUAL_ROLE_CONFLICT",
                                   "两个签核角色必须由不同人承担（禁止同一人双签，含代理签核）",
                                   409)

                if kind == "DELEGATE":
                    chain = {
                        "kind": "DELEGATE", "role": role, "actor": user,
                        "principal_user": delegation["principal_user"],
                        "delegation_id": delegation["id"],
                        "granted_by": delegation["granted_by"],
                        "granted_at": delegation["granted_at"],
                        "valid_from": delegation["valid_from"],
                        "valid_until": delegation["valid_until"],
                        "checked_at": now_s,
                    }
                else:
                    chain = {"kind": "DIRECT", "role": role, "actor": user,
                             "checked_at": now_s}

                c.execute("DELETE FROM signoff WHERE eco_id=? AND role=? AND epoch=?",
                          (eco_id, role, eco["freeze_epoch"]))
                c.execute(
                    "INSERT INTO signoff(eco_id,role,user,epoch,overall_fp,at,signoff_kind,"
                    "delegation_id,auth_chain_json) VALUES(?,?,?,?,?,?,?,?,?)",
                    (eco_id, role, user, eco["freeze_epoch"], eco["fingerprint"], now_s,
                     kind, delegation["id"] if delegation else None,
                     json.dumps(chain, ensure_ascii=False)))
                self._audit(c, "eco.signoff", eco_id, user,
                            {"role": role, "kind": kind,
                             "delegation_id": delegation["id"] if delegation else None})
                return self.eco_detail(eco_id, c)
        except ECOError as e:
            if e.code in ("DELEGATION_NOT_STARTED", "DELEGATION_EXPIRED", "DELEGATION_REVOKED",
                          "DELEGATION_ROLE_MISMATCH", "DELEGATION_USER_MISMATCH",
                          "DELEGATION_NOT_FOUND"):
                self._deny_signoff_audit(eco_id, role, user, e.code, e.extra)
            raise

    # ===== 基础约束刷新 =====
    def update_base_constraints(self, delta: dict, by: str, note: str = ""):
        if not delta:
            raise ECOError("BAD_REQUEST", "delta 为空", 400)
        with self.s.tx() as c:
            if c.execute("SELECT 1 FROM eco WHERE status='RELEASING'").fetchone():
                raise ECOError("RELEASE_IN_PROGRESS",
                               "存在发布中的 ECO，为保证原子性拒绝约束更新", 409)
            trunk = self._trunk(c)
            cur = json.loads(trunk["working_constraints_json"])
            new = {**cur, **delta}
            version = trunk["constraints_version"] + 1
            c.execute("UPDATE trunk SET working_constraints_json=?, constraints_version=?",
                      (json.dumps(new, ensure_ascii=False, sort_keys=True), version))
            c.execute(
                "INSERT INTO constraint_event(base_id,version,delta_json,by,at,note)"
                " VALUES(?,?,?,?,?,?)",
                (trunk["base_id"], version, json.dumps(delta, ensure_ascii=False), by,
                 utcnow(), note))
            affected_ecos = []
            for eco in c.execute("SELECT * FROM eco WHERE status='FROZEN'").fetchall():
                snap = json.loads(eco["snapshot_json"])
                if snap["constraints"] != new:
                    c.execute("UPDATE eco SET status='REBASE_REQUIRED' WHERE id=?", (eco["id"],))
                    c.execute(
                        "INSERT INTO rejected_result(run_id,eco_id,check_type,reason,detail_json,"
                        "received_at) VALUES(?,?,?,?,?,?)",
                        (None, eco["id"], None, "BASE_CONSTRAINT_CHANGED",
                         json.dumps({"old": snap["constraints"], "new": new,
                                     "constraints_version": version}, ensure_ascii=False),
                         utcnow()))
                    self._supersede_runs(c, eco["id"], "constraint-bump")
                    self._void_signoffs(c, eco["id"], "base constraints updated")
                    affected_ecos.append(eco["id"])
            self._audit(c, "constraint.update", trunk["base_id"], by,
                        {"delta": delta, "version": version, "rebased_ecos": affected_ecos})
            return {"constraints_version": version, "constraints": new,
                    "rebased_ecos": affected_ecos}

    # ===== 排队与合并裁决 =====
    def _promote_waiting(self, c):
        """阻塞全部解除的排队 ECO → REBASE_REQUIRED（必须基于新基线重新冻结，不得直接沿用）。"""
        promoted = []
        for eco in c.execute("SELECT id FROM eco WHERE status='QUEUED'").fetchall():
            eco_id = eco["id"]
            open_blockers = c.execute(
                "SELECT COUNT(*) k FROM queue_entry WHERE eco_id=? AND resolved_at IS NULL",
                (eco_id,)).fetchone()["k"]
            if open_blockers == 0:
                c.execute("UPDATE eco SET status='REBASE_REQUIRED' WHERE id=?", (eco_id,))
                self._audit(c, "eco.promote", eco_id, "system",
                            {"reason": "blockers cleared; rebasing onto newest base"})
                promoted.append(eco_id)
        return promoted

    def adjudicate_merge(self, source_eco_id, target_eco_id, by: str,
                         module_winners: dict | None = None):
        """合并裁决：将排队中的 source ECO 并入已冻结 target ECO。

        module_winners: {module: "TARGET_WINS"|"SOURCE_WINS"}，同模块双改默认 TARGET_WINS。
        合并使 target 冻结范围扩张 → 纪元 +1，旧结果与签核全部作废重跑。
        """
        module_winners = module_winners or {}
        with self.s.tx() as c:
            src = self._get_eco(source_eco_id)
            tgt = self._get_eco(target_eco_id)
            if src["status"] != "QUEUED":
                raise ECOError("SOURCE_NOT_QUEUED",
                               f"被合并方状态须为 QUEUED，实际 {src['status']}", 409)
            if tgt["status"] != "FROZEN":
                raise ECOError("TARGET_NOT_FROZEN",
                               f"并入方状态须为 FROZEN，实际 {tgt['status']}", 409)
            blocked = c.execute(
                "SELECT 1 FROM queue_entry WHERE eco_id=? AND blocker_eco_id=? "
                "AND resolved_at IS NULL",
                (source_eco_id, target_eco_id)).fetchone()
            if not blocked:
                raise ECOError("NOT_BLOCKING", "两个 ECO 不存在未决的模块阻塞关系", 409)

            src_mods = set(json.loads(src["affected_modules_json"]))
            tgt_mods = set(json.loads(tgt["affected_modules_json"]))
            added = src_mods - tgt_mods
            conflicts = self._lock_conflicts(c, list(added), exclude_eco=target_eco_id)
            if conflicts:
                raise ECOError("MERGE_STILL_BLOCKED",
                               "合并后仍与其他进行中 ECO 冲突，请先排队/裁决剩余冲突", 409,
                               {"conflicts": conflicts})

            src_edits = json.loads(src["edits_json"])
            tgt_edits = json.loads(tgt["edits_json"])
            merged_edits = dict(tgt_edits)
            overlap = src_mods & tgt_mods
            for m, e in src_edits.items():
                if m in overlap:
                    # 重叠模块由裁决决定：SOURCE_WINS 采用排队方编辑；TARGET_WINS（默认）
                    # 维持占用方对该模块的冻结内容（占用方未编辑即保留基线版本，丢弃源编辑）
                    if module_winners.get(m, "TARGET_WINS") == "SOURCE_WINS":
                        merged_edits[m] = e
                else:
                    merged_edits[m] = e
            merged_modules = sorted(tgt_mods | src_mods)

            # 在 target 的冻结基线之上重建快照（保持同一父基线与约束版本）
            parent = c.execute("SELECT * FROM baseline WHERE id=?",
                               (tgt["parent_baseline_id"],)).fetchone()
            base_snap = json.loads(parent["snapshot_json"])
            constraints = json.loads(tgt["snapshot_json"])["constraints"]
            eff = self._effective_modules(base_snap["modules"], merged_modules, merged_edits)
            snap = build_snapshot(eff, constraints, merged_modules,
                                 note=f"{target_eco_id} 合并 {source_eco_id} 后重新冻结")
            fp = snapshot_fingerprint(snap)
            epoch = tgt["freeze_epoch"] + 1
            c.execute(
                "UPDATE eco SET affected_modules_json=?,edits_json=?,snapshot_json=?,"
                "fingerprint=?,freeze_epoch=? WHERE id=?",
                (json.dumps(merged_modules), json.dumps(merged_edits, ensure_ascii=False),
                 json.dumps(snap, ensure_ascii=False), fp, epoch, target_eco_id))
            self._supersede_runs(c, target_eco_id, "merge")
            self._void_signoffs(c, target_eco_id, "merge adjudication: scope expanded")
            for m in added:
                c.execute("INSERT INTO module_lock(module,eco_id,acquired_at) VALUES(?,?,?)",
                          (m, target_eco_id, utcnow()))
            c.execute(
                "INSERT INTO adjudication(source_eco_id,target_eco_id,decision,"
                "merged_modules_json,merged_edits_json,by,at) VALUES(?,?,?,?,?,?,?)",
                (source_eco_id, target_eco_id, "MERGE", json.dumps(merged_modules),
                 json.dumps(merged_edits, ensure_ascii=False), by, utcnow()))
            c.execute("UPDATE eco SET status='MERGED', merge_of_json=? WHERE id=?",
                      (json.dumps({"into": target_eco_id, "at": utcnow()}), source_eco_id))
            c.execute("DELETE FROM module_lock WHERE eco_id=?", (source_eco_id,))
            c.execute("UPDATE queue_entry SET resolved_at=?, resolution='MERGED' "
                      "WHERE blocker_eco_id=? AND resolved_at IS NULL",
                      (utcnow(), source_eco_id))
            c.execute("UPDATE queue_entry SET resolved_at=?, resolution='MERGED' "
                      "WHERE eco_id=? AND resolved_at IS NULL",
                      (utcnow(), source_eco_id))
            tgt = self._get_eco(target_eco_id)
            self._dispatch(c, tgt)
            self._audit(c, "eco.merge", target_eco_id, by,
                        {"source": source_eco_id, "modules": merged_modules, "epoch": epoch})
            self._promote_waiting(c)
            return self.eco_detail(target_eco_id, c)

    # ===== 发布（两阶段、可恢复） =====
    def release_start(self, eco_id, by, failpoint=None):
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            existing = c.execute("SELECT * FROM release WHERE eco_id=?", (eco_id,)).fetchone()
            if existing and existing["state"] == "PUBLISHED":
                return {"status": "ALREADY_PUBLISHED",
                        "new_baseline_id": existing["new_baseline_id"]}
            if existing and existing["state"] == "RELEASING":
                raise ECOError("RELEASE_PENDING",
                               "发布处于中断态，请调用 resume 完成或恢复", 409)
            if eco["status"] != "FROZEN":
                raise ECOError("NOT_FROZEN", f"状态 {eco['status']} 不可发布", 409)
            g = self.gate(eco, c)
            if not g["releasable"]:
                raise ECOError("NOT_RELEASABLE",
                               "门禁未全绿或双角色签核不全，拒绝发布", 409,
                               {"green": g["green"], "dual": g["dual_role_complete"]})
            c.execute("UPDATE eco SET status='RELEASING' WHERE id=?", (eco_id,))
            c.execute(
                "INSERT INTO release(eco_id,state,started_at,failpoint) VALUES(?,?,?,?)",
                (eco_id, "RELEASING", utcnow(), failpoint))
            c.execute(
                "INSERT INTO release_journal(eco_id,event,at,detail_json) VALUES(?,?,?,?)",
                (eco_id, "PHASE1_LOCKED", utcnow(),
                 json.dumps({"fingerprint": eco["fingerprint"], "epoch": eco["freeze_epoch"],
                             "failpoint": failpoint}, ensure_ascii=False)))
            self._audit(c, "release.start", eco_id, by, {"failpoint": failpoint})
        # 阶段1已提交（RELEASING 持久化）。此处故障 = 真实崩溃：阶段2未执行，可 resume。
        if failpoint == "AFTER_PHASE1":
            raise ECOError("RELEASE_INTERRUPTED",
                           "模拟发布在阶段1提交后崩溃：RELEASING 已持久化，可 resume 恢复", 500,
                           {"eco_id": eco_id, "resume": f"/api/ecos/{eco_id}/release/resume"})
        return self.release_finish(eco_id, by)

    def release_finish(self, eco_id, by="system"):
        with self.s.tx() as c:
            rel = c.execute("SELECT * FROM release WHERE eco_id=?", (eco_id,)).fetchone()
            if not rel:
                raise ECOError("NO_RELEASE", "该 ECO 没有进行中的发布", 409)
            if rel["state"] == "PUBLISHED":
                return {"status": "ALREADY_PUBLISHED", "new_baseline_id": rel["new_baseline_id"]}
            eco = self._get_eco(eco_id)
            if eco["status"] != "RELEASING":
                raise ECOError("BAD_STATE", f"ECO 状态 {eco['status']} 异常", 409)
            # 恢复时重新验证：中断期间不允许任何变更（约束更新/中止均被拒绝），这里是纵深防御
            g = self.gate(eco, c)
            if not g["releasable"]:
                raise ECOError("NOT_RELEASABLE", "恢复时校验失败，基线不再满足发布条件", 409)

            snap = json.loads(eco["snapshot_json"])
            rev = c.execute("SELECT COALESCE(MAX(revision),0)+1 r FROM baseline").fetchone()["r"]
            new_id = f"B-R{rev}"
            c.execute(
                "INSERT INTO baseline(id,revision,parent_id,created_at,eco_id,snapshot_json,"
                "fingerprint,published_by) VALUES(?,?,?,?,?,?,?,?)",
                (new_id, rev, eco["parent_baseline_id"], utcnow(), eco_id,
                 json.dumps(snap, ensure_ascii=False), eco["fingerprint"], by))
            c.execute("UPDATE trunk SET base_id=?, base_revision=? WHERE id=1",
                      (new_id, rev))
            c.execute("UPDATE eco SET status='RELEASED' WHERE id=?", (eco_id,))
            c.execute("UPDATE release SET state='PUBLISHED',new_baseline_id=?,finished_at=? "
                      "WHERE eco_id=?", (new_id, utcnow(), eco_id))
            c.execute("DELETE FROM module_lock WHERE eco_id=?", (eco_id,))
            c.execute("UPDATE queue_entry SET resolved_at=?, resolution='AUTO_PROMOTE' "
                      "WHERE blocker_eco_id=? AND resolved_at IS NULL",
                      (utcnow(), eco_id))
            # 其他仍在验证的 FROZEN 单：其父基线已不是最新 trunk，冻结快照中含
            # 旧版模块（即使模块不重叠），必须 rebase 到新基线后重跑，绝不带旧内容发布。
            stale = c.execute("SELECT id FROM eco WHERE status='FROZEN'").fetchall()
            for r in stale:
                sid = r["id"]
                c.execute("UPDATE eco SET status='REBASE_REQUIRED' WHERE id=?", (sid,))
                c.execute(
                    "INSERT INTO rejected_result(run_id,eco_id,check_type,reason,detail_json,"
                    "received_at) VALUES(?,?,?,?,?,?)",
                    (None, sid, None, "BASELINE_PUBLISHED",
                     json.dumps({"published_baseline": new_id, "by_eco": eco_id},
                                ensure_ascii=False), utcnow()))
                self._supersede_runs(c, sid, "new-baseline-published")
                self._void_signoffs(c, sid, "newer baseline published")
                self._audit(c, "eco.rebase_required", sid, "system",
                            {"reason": "newer baseline published", "baseline": new_id})
            c.execute(
                "INSERT INTO release_journal(eco_id,event,at,detail_json) VALUES(?,?,?,?)",
                (eco_id, "PUBLISHED", utcnow(), json.dumps({"new_baseline_id": new_id})))
            self._audit(c, "release.publish", eco_id, by, {"baseline": new_id})
            self._promote_waiting(c)
            return {"status": "PUBLISHED", "new_baseline_id": new_id, "revision": rev}

    def resume_release(self, eco_id, by="system"):
        return self.release_finish(eco_id, by)

    # ===== 详情 / 工作台 =====
    def eco_detail(self, eco_id, c=None):
        def q(conn):
            eco = conn.execute("SELECT * FROM eco WHERE id=?", (eco_id,)).fetchone()
            if not eco:
                raise ECOError("ECO_NOT_FOUND", f"ECO {eco_id} 不存在", 404)
            d = _eco_dict(eco)
            d["gate"] = self.gate(eco, conn)
            d["queue"] = [dict(r) for r in conn.execute(
                "SELECT * FROM queue_entry WHERE eco_id=? AND resolved_at IS NULL",
                (eco_id,)).fetchall()]
            d["blocks"] = [dict(r) for r in conn.execute(
                "SELECT * FROM queue_entry WHERE blocker_eco_id=? AND resolved_at IS NULL",
                (eco_id,)).fetchall()]
            rel = conn.execute("SELECT * FROM release WHERE eco_id=?", (eco_id,)).fetchone()
            d["release"] = dict(rel) if rel else None
            return d
        if c is not None:
            return q(c)
        with self.s.lock:
            return q(self.s.conn)

    def list_ecos(self):
        with self.s.lock:
            rows = self.s.q_all("SELECT * FROM eco ORDER BY id")
            out = []
            for r in rows:
                d = _eco_dict(r)
                d.pop("snapshot", None)
                g = self.gate(r, self.s.conn)
                d["green"] = g["green"]
                d["releasable"] = g["releasable"]
                d["required_all_pass"] = g["required_all_pass"]
                d["dual_role_complete"] = g["dual_role_complete"]
                d["check_summary"] = {x["type"]: x["status"] for x in g["checks"]}
                out.append(d)
            return out

    def workbench(self):
        with self.s.lock:
            return {
                "baselines": self.list_baselines(),
                "ecos": self.list_ecos(),
                "catalog": matrix_catalog(),
                "roles": SIGNOFF_ROLES,
                "delegations": self.list_delegations(),
                "current_signers": self.current_signers(),
                "locks": [dict(r) for r in self.s.q_all("SELECT * FROM module_lock")],
                "rejected_results": [dict(r) for r in self.s.q_all(
                    "SELECT * FROM rejected_result ORDER BY seq DESC LIMIT 20")],
                "recent_audit": [dict(r) for r in self.s.q_all(
                    "SELECT seq,actor,action,entity,at FROM audit_log ORDER BY seq DESC LIMIT 30")],
                "constraints": self.current_constraints(),
            }

    def current_constraints(self):
        with self.s.lock:
            t = self.s.q_one("SELECT * FROM trunk WHERE id=1")
            return {"base_id": t["base_id"], "base_revision": t["base_revision"],
                    "constraints_version": t["constraints_version"],
                    "constraints": json.loads(t["working_constraints_json"])}

    # ===== 基线差异包 =====
    def _diff_constraints(self, old, new):
        keys = sorted(set(old) | set(new))
        items = []
        for k in keys:
            if k not in old:
                items.append({"key": k, "change": "ADDED", "new": new[k]})
            elif k not in new:
                items.append({"key": k, "change": "REMOVED", "old": old[k]})
            elif old[k] != new[k]:
                items.append({"key": k, "change": "CHANGED", "old": old[k], "new": new[k]})
        return items

    def _diff_modules(self, old, new):
        names = sorted(set(old) | set(new))
        items = []
        for m in names:
            if m not in old:
                items.append({"module": m, "change": "ADDED",
                              "after": new[m], "unified_diff": None})
            elif m not in new:
                items.append({"module": m, "change": "REMOVED",
                              "before": old[m], "unified_diff": None})
            elif old[m].get("netlist") != new[m].get("netlist") or \
                    old[m].get("version") != new[m].get("version"):
                before, after = old[m]["netlist"].splitlines(), new[m]["netlist"].splitlines()
                diff = "\n".join(unified_diff(
                    before, after, fromfile=f"{m}.v.before", tofile=f"{m}.v.after", lineterm=""))
                items.append({"module": m, "change": "CHANGED",
                              "before": old[m], "after": new[m], "unified_diff": diff})
        return items

    def diff_package(self, from_id, to_id):
        b_old, b_new = self._get_baseline(from_id), self._get_baseline(to_id)
        s_old, s_new = b_old["snapshot"], b_new["snapshot"]
        mod_diff = self._diff_modules(s_old["modules"], s_new["modules"])
        sdc_diff = self._diff_constraints(s_old["constraints"], s_new["constraints"])
        eco = None
        signoffs, check_results = [], []
        if b_new["eco_id"]:
            with self.s.lock:
                er = self.s.q_one("SELECT * FROM eco WHERE id=?", (b_new["eco_id"],))
                if er:
                    eco = {"id": er["id"], "title": er["title"], "owner": er["owner"]}
                    signoffs = [({k: v for k, v in dict(r).items()
                                  if k != "auth_chain_json"}
                                 | {"auth_chain": json.loads(r["auth_chain_json"] or "{}")})
                                for r in self.s.q_all(
                                    "SELECT id,eco_id,role,user,epoch,overall_fp,at,"
                                    "signoff_kind,delegation_id,auth_chain_json FROM signoff "
                                    "WHERE eco_id=? ORDER BY id", (b_new["eco_id"],))]
                    # 发布基线只认与目标基线指纹一致的签核；旧纪元签核保留在记录中供审计
                    valid_fp = b_new["fingerprint"]
                    valid_sigs = [s for s in signoffs if s["overall_fp"] == valid_fp]
                    check_results = [dict(r) for r in self.s.q_all(
                        "SELECT check_type,attempt,status,required,result_fp,expected_fp,"
                        "runner_id,submitted_at FROM check_run WHERE eco_id=? "
                        "AND status!='SUPERSEDED' ORDER BY check_type", (b_new["eco_id"],))]
        changed = [d["module"] for d in mod_diff if d["change"] == "CHANGED"]
        added = [d["module"] for d in mod_diff if d["change"] == "ADDED"]
        removed = [d["module"] for d in mod_diff if d["change"] == "REMOVED"]
        return {
            "format": "chip-eco-baseline-diff/1",
            "created_at": utcnow(),
            "from": {"id": b_old["id"], "revision": b_old["revision"],
                     "fingerprint": b_old["fingerprint"]},
            "to": {"id": b_new["id"], "revision": b_new["revision"],
                   "fingerprint": b_new["fingerprint"], "eco": eco},
            "summary": {"modules_changed": changed, "modules_added": added,
                        "modules_removed": removed,
                        "constraints_changed": [d["key"] for d in sdc_diff
                                                if d["change"] == "CHANGED"],
                        "affected_in_new": s_new["affected_modules"]},
            "modules": mod_diff,
            "constraints": sdc_diff,
            "verification": {
                "matrix": s_new["verification_matrix"],
                "results": check_results,
                "signoffs": signoffs,
                "valid_signoffs": [{k: v for k, v in s.items() if k != "auth_chain_json"}
                                   for s in valid_sigs],
                "dual_role_distinct_users":
                    len({s["role"] for s in valid_sigs}) == 2
                    and len({s["user"] for s in valid_sigs}) == 2,
            },
        }

    def diff_zip(self, from_id, to_id) -> bytes:
        pkg = self.diff_package(from_id, to_id)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(pkg, ensure_ascii=False, indent=2))
            z.writestr("constraints/sdc.before.json",
                       json.dumps(self._get_baseline(from_id)["snapshot"]["constraints"],
                                  ensure_ascii=False, indent=2, sort_keys=True))
            z.writestr("constraints/sdc.after.json",
                       json.dumps(self._get_baseline(to_id)["snapshot"]["constraints"],
                                  ensure_ascii=False, indent=2, sort_keys=True))
            for d in pkg["modules"]:
                if d["change"] == "CHANGED":
                    z.writestr(f"modules/{d['module']}.before.v", d["before"]["netlist"])
                    z.writestr(f"modules/{d['module']}.after.v", d["after"]["netlist"])
                    z.writestr(f"modules/{d['module']}.diff", d["unified_diff"] or "")
            z.writestr("verification/matrix.json",
                       json.dumps(pkg["verification"]["matrix"], ensure_ascii=False, indent=2))
            z.writestr("verification/results.json",
                       json.dumps(pkg["verification"]["results"], ensure_ascii=False, indent=2))
            z.writestr("verification/signoffs.json",
                       json.dumps(pkg["verification"]["signoffs"], ensure_ascii=False, indent=2))
            readme = (
                f"基线差异包 {pkg['from']['id']} -> {pkg['to']['id']}\n\n"
                f"变更模块: {pkg['summary']['modules_changed'] or '无'}\n"
                f"新增模块: {pkg['summary']['modules_added'] or '无'}\n"
                f"约束变更: {pkg['summary']['constraints_changed'] or '无'}\n"
                f"双角色签核: {'满足(不同人)' if pkg['verification']['dual_role_distinct_users'] else '不满足'}\n"
                f"目标基线指纹: {pkg['to']['fingerprint']}\n")
            z.writestr("README.txt", readme)
        return buf.getvalue()

    def rejected_results(self):
        with self.s.lock:
            return [dict(r) for r in self.s.q_all(
                "SELECT * FROM rejected_result ORDER BY seq DESC")]
