"""验证执行租约协调模块（Lease Coordinator）——与 ECO 服务配套。

职责：
- 从验证矩阵读取**已经就绪**的检查（check_run.status=PENDING 且 ECO=FROZEN），
  原子地分配给 Runner（领取），支持续租、完成（随结果回传）、主动释放与超时接管；
- 领取是**幂等**操作：同一 (runner_id, idempotency_key) 的并发/重放请求至多成功一次，
  其余返回同一份分配；不同 Runner 并发领取同一 run 只有一个成功（DB 唯一约束 +
  BEGIN IMMEDIATE 串行化）；
- 每次回传必须携带 **租约代次 generation** 与**不可伪造凭据 lease_token**
  （服务端持久密钥对 (run_id, generation, nonce) 的 HMAC，不落明文）：
  旧持有者、过期租约、凭据不符、代次落后（被接管后迟到）、依赖未满足、
  重跑后旧代次的迟到结果一律拒绝，拒绝原因写入可查询审计；
- 租约与审计全部落盘：进程重启后恢复未过期租约（凭据仍可验真），
  回收已过期租约（可被重新领取/接管）；
- **接管后的结果仍须经过原 ECO 服务的基线指纹与依赖门禁**
  （ECOService.submit_result），不能绕过现有重跑、签核与发布约束。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import timedelta, timezone

from .service import ECOError, ECOService, parse_ts
from .store import utcnow

DEFAULT_TTL_SECONDS = 120
MAX_TTL_SECONDS = 3600

LEASE_HELD = "HELD"
LEASE_COMPLETED = "COMPLETED"
LEASE_RELEASED = "RELEASED"
LEASE_EXPIRED = "EXPIRED"
LEASE_INVALIDATED = "INVALIDATED"
FINISHED_STATES = (LEASE_COMPLETED, LEASE_RELEASED, LEASE_EXPIRED, LEASE_INVALIDATED)


class LeaseError(ECOError):
    """租约协调器错误：沿用 ECOError 的 (code, message, http_status, detail) 形态。"""


class _Denial(Exception):
    """校验事务内部的拒绝信号：携带对外错误与持久化审计所需信息。

    事务因此回滚（绝不留下半截状态），由外层在**独立已提交事务**中写拒绝审计，
    再抛出对外 LeaseError —— 与 ECO 服务 rejected_result 留痕的处理同构。
    """
    def __init__(self, code, message, http_status, detail, audit):
        super().__init__(message)
        self.code, self.message = code, message
        self.http_status, self.detail, self.audit = http_status, detail, audit


class LeaseService:
    def __init__(self, svc: ECOService, ttl_seconds: int = DEFAULT_TTL_SECONDS,
                 now_fn=utcnow):
        self.svc = svc
        self.s = svc.s
        self.default_ttl = max(1, int(ttl_seconds))
        self._now_fn = now_fn
        self._secret = self._load_or_init_secret()
        # 进程启动恢复：未过期租约原样恢复，过期/因纪元变化失效的租约回收留痕
        self.recovery = self._recover_on_startup()

    # ---------------------------------------------------------------- 时钟
    def _now(self):
        v = self._now_fn()
        return parse_ts(v) if isinstance(v, str) else v.astimezone(timezone.utc)

    def _now_s(self) -> str:
        return self._now().isoformat(timespec="seconds")

    def _expiry(self, ttl: int) -> str:
        return (self._now().astimezone(timezone.utc) + timedelta(seconds=ttl)
                ).isoformat(timespec="seconds")

    def _parse_ttl(self, ttl_seconds, default):
        if ttl_seconds is None:
            return default
        try:
            ttl = int(ttl_seconds)
        except (TypeError, ValueError):
            raise LeaseError("BAD_REQUEST", "ttl_seconds 必须为整数秒", 400, {})
        if not 0 < ttl <= MAX_TTL_SECONDS:
            raise LeaseError("BAD_TTL",
                             f"ttl_seconds 须在 1..{MAX_TTL_SECONDS} 之间", 400, {})
        return ttl

    # ---------------------------------------------------------------- 凭据
    def _load_or_init_secret(self) -> bytes:
        row = self.s.q_one("SELECT value FROM lease_meta WHERE key='hmac_secret'")
        if row:
            return bytes.fromhex(row["value"])
        sec = secrets.token_bytes(32)
        with self.s.tx() as c:
            c.execute("INSERT OR IGNORE INTO lease_meta(key,value) VALUES('hmac_secret',?)",
                      (sec.hex(),))
        row = self.s.q_one("SELECT value FROM lease_meta WHERE key='hmac_secret'")
        return bytes.fromhex(row["value"])

    def _token(self, run_id: str, generation: int, nonce: str) -> str:
        msg = json.dumps([run_id, generation, nonce], separators=(",", ":"),
                         ensure_ascii=False).encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()[:32]

    def _lease_token(self, lease) -> str:
        return self._token(lease["run_id"], lease["generation"], lease["token_nonce"])

    # ---------------------------------------------------------------- 审计
    def _audit(self, c, event, lease=None, runner_id=None, reason=None, detail=None):
        c.execute(
            "INSERT INTO lease_audit(run_id,eco_id,check_type,lease_seq,generation,runner_id,"
            "event,reason,detail_json,at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (lease["run_id"] if lease else None, lease["eco_id"] if lease else None,
             lease["check_type"] if lease else None, lease["seq"] if lease else None,
             lease["generation"] if lease else None,
             runner_id or (lease["runner_id"] if lease else None),
             event, reason, json.dumps(detail or {}, ensure_ascii=False), self._now_s()))

    def _persist_denial(self, d: _Denial):
        """拒绝写独立审计事务：任何校验回滚都不影响留痕（与 rejected_result 同风格）。"""
        a = d.audit
        with self.s.tx() as c:
            c.execute(
                "INSERT INTO lease_audit(run_id,eco_id,check_type,lease_seq,generation,runner_id,"
                "event,reason,detail_json,at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (a.get("run_id"), a.get("eco_id"), a.get("check_type"), a.get("lease_seq"),
                 a.get("generation"), a.get("runner_id"), "deny", d.code,
                 json.dumps(d.detail or {}, ensure_ascii=False), self._now_s()))

    def _deny(self, code, message, *, http_status=409, detail=None,
              lease=None, runner_id=None, run_id=None, generation=None):
        """构造拒绝信号（在校验事务内调用），审计字段从 lease/显式参数填充。"""
        audit = {
            "run_id": run_id or (lease["run_id"] if lease else None),
            "eco_id": lease["eco_id"] if lease else None,
            "check_type": lease["check_type"] if lease else None,
            "lease_seq": lease["seq"] if lease else None,
            "generation": generation if generation is not None
                           else (lease["generation"] if lease else None),
            "runner_id": runner_id,
        }
        raise _Denial(code, message, http_status, detail or {}, audit)

    # ---------------------------------------------------------------- 整形
    def _lease_dict(self, lease, *, include_token=False):
        d = dict(lease)
        d.pop("token_nonce", None)
        now = self._now()
        exp = parse_ts(lease["expires_at"]) if lease["expires_at"] else None
        d["remaining_seconds"] = int((exp - now).total_seconds()) if exp else None
        d["alive"] = lease["state"] == LEASE_HELD and exp is not None and now < exp
        if include_token:
            d["lease_token"] = self._lease_token(lease)
        return d

    def _validate_credential(self, lease, runner_id, generation, token):
        """统一的代次/持有者/凭据/时效门禁，返回 (拒绝原因码, 说明, http, detail) 或 None。"""
        if lease["state"] in FINISHED_STATES:
            return ("LEASE_NOT_ACTIVE", f"租约已结束（{lease['state']}）", 409,
                    {"state": lease["state"]})
        # 代次先于持有者判定：被接管的旧持有者拿到的是旧代次 → GENERATION_STALE，
        # 明确告知其已被接管；代次正确但 runner 不符才是 NOT_HOLDER。
        try:
            gen_ok = generation is not None and int(generation) == lease["generation"]
        except (TypeError, ValueError):
            gen_ok = False
        if not gen_ok:
            return ("LEASE_GENERATION_STALE", "租约代次不匹配（可能已被接管/续租代次已变）",
                    409, {"expected_generation": lease["generation"],
                          "given_generation": generation})
        if runner_id != lease["runner_id"]:
            return ("LEASE_NOT_HOLDER", "当前 Runner 不是该租约持有者", 409,
                    {"holder": lease["runner_id"], "runner_id": runner_id})
        if not token or not hmac.compare_digest(str(token), self._lease_token(lease)):
            return ("LEASE_BAD_CREDENTIAL", "租约凭据无效或不可信", 403, {})
        if self._now() >= parse_ts(lease["expires_at"]):
            return ("LEASE_EXPIRED", "租约已过期，需重新领取或等待接管", 409,
                    {"expires_at": lease["expires_at"]})
        return None

    def _canonicalize(self, c, lease_row):
        """惰性规范化：把 HELD 但已过期/随 run 或 ECO 失效的租约落到终态。

        返回 (lease_row, events) —— events 为待写审计的 (reason, detail) 回收事件。
        """
        events = []
        lease = lease_row
        if lease["state"] == LEASE_HELD:
            run = c.execute("SELECT * FROM check_run WHERE id=?",
                            (lease["run_id"],)).fetchone()
            eco = c.execute("SELECT * FROM eco WHERE id=?", (lease["eco_id"],)).fetchone()
            if run and run["status"] == "SUPERSEDED":
                c.execute("UPDATE check_lease SET state=?, finished_reason=?, completed_at=? "
                          "WHERE seq=?",
                          (LEASE_INVALIDATED, "run_superseded", self._now_s(), lease["seq"]))
                events.append(("LEASE_RUN_SUPERSEDED",
                               {"reason": "重跑/纪元变化使旧 run 作废，旧代次租约失效"}))
            elif not eco or eco["status"] != "FROZEN":
                c.execute("UPDATE check_lease SET state=?, finished_reason=?, completed_at=? "
                          "WHERE seq=?",
                          (LEASE_INVALIDATED,
                           f"eco_{eco['status'] if eco else 'gone'}", self._now_s(),
                           lease["seq"]))
                events.append(("LEASE_TASK_INVALIDATED",
                               {"eco_status": eco["status"] if eco else None}))
            elif self._now() >= parse_ts(lease["expires_at"]):
                c.execute("UPDATE check_lease SET state=? WHERE seq=?",
                          (LEASE_EXPIRED, lease["seq"]))
                events.append(("LEASE_EXPIRED",
                               {"reason": "TTL 到期回收，等待接管/重新领取"}))
            lease = c.execute("SELECT * FROM check_lease WHERE seq=?",
                              (lease["seq"],)).fetchone()
        return lease, events

    def _settle(self, lease_seq):
        """在一个已提交事务内规范化某租约并落审计（供变更/查询前调用）。"""
        with self.s.tx() as c:
            row = c.execute("SELECT * FROM check_lease WHERE seq=?", (lease_seq,)).fetchone()
            if not row:
                return None
            lease, events = self._canonicalize(c, row)
            for reason, detail in events:
                self._audit(c, "reclaim", lease, reason=reason, detail=detail)
            return lease

    def _settle_all(self):
        """规范化全部 HELD 租约（启动恢复 / 池视图）。"""
        with self.s.tx() as c:
            for row in c.execute("SELECT * FROM check_lease").fetchall():
                lease, events = self._canonicalize(c, row)
                for reason, detail in events:
                    self._audit(c, "reclaim", lease, reason=reason, detail=detail)

    # ---------------------------------------------------------------- 启动恢复
    def _recover_on_startup(self):
        """进程重启恢复：未过期 HELD 租约继续有效（密钥持久，token 仍可验真）；
        已过期/已随纪元作废的租约回收并写可查询审计。"""
        recovered, reclaimed = [], []
        with self.s.tx() as c:
            for raw in c.execute("SELECT * FROM check_lease").fetchall():
                lease, events = self._canonicalize(c, raw)
                for reason, detail in events:
                    self._audit(c, "reclaim", lease, reason=reason, detail=detail)
                    reclaimed.append({"run_id": lease["run_id"], "reason": reason})
                if lease["state"] == LEASE_HELD:
                    recovered.append(lease["run_id"])
            c.execute("INSERT INTO lease_audit(event,detail_json,at) VALUES('recovery',?,?)",
                      (json.dumps({"recovered": recovered, "reclaimed": reclaimed},
                                  ensure_ascii=False), self._now_s()))
        return {"recovered_leases": recovered, "reclaimed_leases": reclaimed}

    # ---------------------------------------------------------------- 待领任务
    def _claimable_sql(self):
        # 已就绪 = 当前活动 run 处于 PENDING 且 ECO 仍 FROZEN；
        # 无 HELD/COMPLETED 租约（EXPIRED/RELEASED 的 run 可被再次领取）。
        return """
            SELECT r.* FROM check_run r JOIN eco e ON e.id=r.eco_id
            WHERE r.status='PENDING' AND e.status='FROZEN'
              AND NOT EXISTS (
                SELECT 1 FROM check_lease l
                WHERE l.run_id=r.id AND l.state IN ('HELD','COMPLETED'))
            ORDER BY r.eco_id,
                CASE r.check_type WHEN 'TIMING_STA' THEN 1 WHEN 'POWER_ANALYSIS' THEN 2
                     WHEN 'FORMAL_EQUIV' THEN 3 WHEN 'LAYOUT_DRC' THEN 4 ELSE 5 END,
                r.check_type
        """

    def pool(self, eco_id=None):
        """待领任务 + 持有者/剩余时间视图（操作页面）。列出时顺带惰性回收过期租约。"""
        self._settle_all()
        with self.s.lock:
            c = self.s.conn
            sql, args = self._claimable_sql(), []
            if eco_id:
                sql = sql.replace("WHERE r.status='PENDING'",
                                  "WHERE r.status='PENDING' AND r.eco_id=?", 1)
                args = [eco_id]
            avail = []
            for r in c.execute(sql, tuple(args)).fetchall():
                eco = c.execute("SELECT title,status,freeze_epoch FROM eco WHERE id=?",
                                (r["eco_id"],)).fetchone()
                avail.append({
                    "run_id": r["id"], "eco_id": r["eco_id"], "check_type": r["check_type"],
                    "required": bool(r["required"]),
                    "depends_on": json.loads(r["depends_on_json"]),
                    "expected_fingerprint": r["expected_fp"],
                    "eco_title": eco["title"], "freeze_epoch": eco["freeze_epoch"],
                })
            held_out = [self._lease_dict(r) for r in c.execute(
                "SELECT * FROM check_lease ORDER BY seq DESC").fetchall()]
            return {"at": self._now_s(), "default_ttl_seconds": self.default_ttl,
                    "claimable": avail, "leases": held_out}

    # ---------------------------------------------------------------- 领取
    def claim(self, runner_id, idempotency_key=None, run_id=None, ttl_seconds=None):
        """原子领取一个就绪检查。幂等：同 (runner, key) 重放返回同一份分配。"""
        if not runner_id:
            raise LeaseError("BAD_REQUEST", "runner_id 必填", 400, {})
        ttl = self._parse_ttl(ttl_seconds, self.default_ttl)
        key = idempotency_key or None
        try:
            return self._claim_tx(runner_id, key, run_id, ttl)
        except sqlite3.IntegrityError:
            # 与并发领取者竞争落败（UNIQUE(run_id)），或同幂等键的另一请求抢先提交：
            # 幂等键场景返回赢家的同一份分配；纯并发竞争报唯一成功者为对方。
            if key:
                with self.s.lock:
                    prior = self.s.q_one(
                        "SELECT * FROM lease_claim WHERE runner_id=? AND idempotency_key=?",
                        (runner_id, key))
                if prior:
                    lease = self._settle(self._lease_seq(prior["run_id"]))
                    d = self._lease_dict(lease, include_token=True)
                    d.update({"claimed": False, "idempotent": True,
                              "idempotency_key": key, "concurrent": True})
                    return d
            raise LeaseError("LEASE_HELD_BY_OTHER",
                             "该任务已被其他 Runner 并发领取，仅一个成功", 409, {})

    def _claim_tx(self, runner_id, key, run_id, ttl):
        try:
            with self.s.tx() as c:
                # 1) 幂等重放：该键已成功分配过 → 返回原分配（绝不第二次分配）
                if key:
                    prior = c.execute(
                        "SELECT * FROM lease_claim WHERE runner_id=? AND idempotency_key=?",
                        (runner_id, key)).fetchone()
                    if prior:
                        lease, _ = self._canonicalize(
                            c, c.execute("SELECT * FROM check_lease WHERE run_id=?",
                                         (prior["run_id"],)).fetchone())
                        d = self._lease_dict(lease, include_token=True)
                        d.update({"claimed": False, "idempotent": True,
                                  "idempotency_key": key})
                        return d
                # 2) 选定目标 run
                if run_id:
                    target = c.execute("SELECT * FROM check_run WHERE id=?",
                                       (run_id,)).fetchone()
                    if not target:
                        self._deny("RUN_NOT_FOUND", f"运行 {run_id} 不存在或已作废",
                                   http_status=404, runner_id=runner_id, run_id=run_id)
                    target, existing = self._check_claimable(c, target)
                else:
                    row = c.execute(self._claimable_sql() + " LIMIT 1").fetchone()
                    if not row:
                        return {"claimed": False, "reason": "NO_CLAIMABLE_TASK",
                                "message": "当前没有就绪且可领取的检查（可能依赖尚未满足）"}
                    target, existing = row, None
                # 3) 原子写入租约（并发的另一事务会被 UNIQUE(run_id) 拦截）
                now_s, nonce = self._now_s(), secrets.token_hex(8)
                if existing is not None:
                    prev = {"state": existing["state"], "holder": existing["runner_id"]}
                    gen = existing["generation"] + 1
                    c.execute(
                        "UPDATE check_lease SET generation=?,runner_id=?,state='HELD',"
                        "ttl_seconds=?,acquired_at=?,expires_at=?,last_heartbeat_at=?,"
                        "completed_at=NULL,finished_reason=NULL,renew_count=0,token_nonce=? "
                        "WHERE seq=?",
                        (gen, runner_id, ttl, now_s, self._expiry(ttl), now_s, nonce,
                         existing["seq"]))
                    lease = c.execute("SELECT * FROM check_lease WHERE seq=?",
                                      (existing["seq"],)).fetchone()
                    self._audit(c, "reclaim", lease, runner_id=runner_id,
                                reason="LEASE_REACQUIRED",
                                detail={"previous": prev, "ttl_seconds": ttl})
                else:
                    cur = c.execute(
                        "INSERT INTO check_lease(run_id,eco_id,check_type,generation,runner_id,"
                        "state,ttl_seconds,acquired_at,expires_at,last_heartbeat_at,token_nonce)"
                        " VALUES(?,?,?,1,?,'HELD',?,?,?,?,?)",
                        (target["id"], target["eco_id"], target["check_type"], runner_id,
                         ttl, now_s, self._expiry(ttl), now_s, nonce))
                    lease = c.execute("SELECT * FROM check_lease WHERE seq=?",
                                      (cur.lastrowid,)).fetchone()
                if key:
                    c.execute(
                        "INSERT INTO lease_claim(runner_id,idempotency_key,run_id,generation,"
                        "claimed_at) VALUES(?,?,?,?,?)",
                        (runner_id, key, lease["run_id"], lease["generation"], now_s))
                self._audit(c, "claim", lease, runner_id=runner_id,
                            detail={"ttl_seconds": ttl, "idempotency_key": key})
                d = self._lease_dict(lease, include_token=True)
                d.update({"claimed": True, "idempotent": False, "idempotency_key": key,
                          "inputs_path":
                          f"/api/ecos/{lease['eco_id']}/checks/{lease['check_type']}/inputs",
                          "result_path": f"/api/leases/runs/{lease['run_id']}/results"})
                return d
        except _Denial as d:
            self._persist_denial(d)
            raise LeaseError(d.code, d.message, d.http_status, d.detail)


    def _check_claimable(self, c, target):
        """指定 run 领取前的就绪性校验；返回 (规范化后的 run, 既有租约或 None)。"""
        if target["status"] == "SUPERSEDED":
            self._deny("LEASE_TASK_SUPERSEDED",
                       "该 run 已作废（重跑/纪元变化），不可领取",
                       detail={"run_id": target["id"]}, run_id=target["id"])
        if target["status"] == "BLOCKED":
            self._deny("LEASE_TASK_NOT_READY", "依赖尚未全部通过，检查仍 BLOCKED，不可领取",
                       detail={"depends_on": json.loads(target["depends_on_json"])},
                       run_id=target["id"])
        if target["status"] in ("PASS", "FAIL"):
            self._deny("LEASE_TASK_FINISHED",
                       f"检查已有结论 {target['status']}，不可领取",
                       detail={"check_status": target["status"]}, run_id=target["id"])
        if target["status"] != "PENDING":
            self._deny("LEASE_TASK_NOT_READY",
                       f"检查当前状态 {target['status']}，不可领取",
                       detail={"check_status": target["status"]}, run_id=target["id"])
        eco = c.execute("SELECT status FROM eco WHERE id=?", (target["eco_id"],)).fetchone()
        if not eco or eco["status"] != "FROZEN":
            self._deny("ECO_NOT_ACTIVE", "ECO 不在 FROZEN 态，任务不可领取",
                       detail={"eco_status": eco["status"] if eco else None},
                       run_id=target["id"])
        existing = c.execute("SELECT * FROM check_lease WHERE run_id=?",
                             (target["id"],)).fetchone()
        if existing is not None:
            existing, _ = self._canonicalize(c, existing)
            if existing["state"] == LEASE_HELD:
                self._deny("LEASE_HELD_BY_OTHER",
                           "该任务已被其他 Runner 持有，并发领取仅一个成功",
                           detail={"holder": existing["runner_id"],
                                   "generation": existing["generation"]},
                           lease=existing, runner_id=None, run_id=target["id"])
            if existing["state"] == LEASE_COMPLETED:
                self._deny("LEASE_TASK_FINISHED", "任务已完成", run_id=target["id"])
        return target, existing

    # ---------------------------------------------------------------- 续租
    def renew(self, run_id, runner_id, generation, token, ttl_seconds=None):
        lease = self._settle(self._lease_seq(run_id))
        if not lease:
            raise LeaseError("LEASE_NOT_FOUND", f"运行 {run_id} 没有租约", 404, {})
        ttl = self._parse_ttl(ttl_seconds, lease["ttl_seconds"])
        try:
            with self.s.tx() as c:
                cur = c.execute("SELECT * FROM check_lease WHERE seq=?",
                                (lease["seq"],)).fetchone()
                failure = self._validate_credential(cur, runner_id, generation, token)
                if failure:
                    code, msg, http, detail = failure
                    self._deny(code, msg, http_status=http, detail=detail, lease=cur,
                               runner_id=runner_id, generation=generation)
                c.execute("UPDATE check_lease SET expires_at=?,last_heartbeat_at=?,"
                          "ttl_seconds=?,renew_count=renew_count+1 WHERE seq=?",
                          (self._expiry(ttl), self._now_s(), ttl, cur["seq"]))
                cur = c.execute("SELECT * FROM check_lease WHERE seq=?",
                                (cur["seq"],)).fetchone()
                self._audit(c, "renew", cur, detail={"ttl_seconds": ttl})
                return self._lease_dict(cur, include_token=True)
        except _Denial as d:
            self._persist_denial(d)
            raise LeaseError(d.code, d.message, d.http_status, d.detail)

    # ---------------------------------------------------------------- 释放
    def release(self, run_id, runner_id, generation, token):
        """持有者提前主动释放：任务回到待领池（run 仍 PENDING，代次+1 后可被再领）。"""
        seq = self._lease_seq(run_id, required=True)
        lease = self._settle(seq)
        try:
            with self.s.tx() as c:
                cur = c.execute("SELECT * FROM check_lease WHERE seq=?", (seq,)).fetchone()
                failure = self._validate_credential(cur, runner_id, generation, token)
                if failure:
                    code, msg, http, detail = failure
                    self._deny(code, msg, http_status=http, detail=detail, lease=cur,
                               runner_id=runner_id, generation=generation)
                c.execute("UPDATE check_lease SET state='RELEASED',finished_reason='released',"
                          "completed_at=? WHERE seq=?", (self._now_s(), seq))
                cur = c.execute("SELECT * FROM check_lease WHERE seq=?", (seq,)).fetchone()
                self._audit(c, "release", cur, detail={})
                return self._lease_dict(cur)
        except _Denial as d:
            self._persist_denial(d)
            raise LeaseError(d.code, d.message, d.http_status, d.detail)

    def _lease_seq(self, run_id, required=False):
        row = self.s.q_one("SELECT seq FROM check_lease WHERE run_id=?", (run_id,))
        if not row and required:
            raise LeaseError("LEASE_NOT_FOUND", f"运行 {run_id} 没有租约", 404, {})
        return row["seq"] if row else None

    # ---------------------------------------------------------------- 结果回传（完成）
    def submit_result(self, run_id, runner_id, generation, token, fingerprint, verdict,
                      result=None):
        """携带租约代次+凭据回传结果。租约门禁通过后，结果**仍须通过 ECO 服务的
        基线指纹/依赖/纪元门禁**（FINGERPRINT_MISMATCH / DEPENDENCY_BLOCKED /
        STALE_SUPERSEDED / ALREADY_SUBMITTED 等），租约层不提供任何旁路。"""
        if not run_id:
            raise LeaseError("BAD_REQUEST", "run_id 必填", 400, {})
        seq = self._lease_seq(run_id)
        if seq is None:
            # 无租约提交：拒绝并审计（杜绝绕过协调器直接交结果的路径）
            self._persist_denial(_Denial(
                "LEASE_NOT_FOUND", "该 run 不存在有效租约，拒绝结果", 412,
                {"verdict": verdict},
                {"run_id": run_id, "runner_id": runner_id, "generation": generation}))
            raise LeaseError("LEASE_NOT_FOUND", "该 run 不存在有效租约，拒绝结果", 412,
                             {"verdict": verdict})
        lease = self._settle(seq)
        try:
            with self.s.tx() as c:
                cur = c.execute("SELECT * FROM check_lease WHERE seq=?", (seq,)).fetchone()
                run = c.execute("SELECT * FROM check_run WHERE id=?", (run_id,)).fetchone()
                # 重跑/纪元变化后的旧代次迟到结果（run 已作废，租约随之 INVALIDATED）
                if run and run["status"] == "SUPERSEDED":
                    self._deny("LEASE_RUN_SUPERSEDED",
                               "该 run 已被重跑/纪元变化作废，旧代次迟到结果拒收",
                               detail={"run_id": run_id}, lease=cur, runner_id=runner_id,
                               generation=generation)
                failure = self._validate_credential(cur, runner_id, generation, token)
                if failure:
                    code, msg, http, detail = failure
                    self._deny(code, msg, http_status=http, detail=detail, lease=cur,
                               runner_id=runner_id, generation=generation)
                if run["status"] == "BLOCKED":
                    self._deny("LEASE_TASK_NOT_READY", "依赖前置尚未全部 PASS，结果拒收",
                               detail={"depends_on": json.loads(run["depends_on_json"])},
                               lease=cur, runner_id=runner_id, generation=generation)
        except _Denial as d:
            self._persist_denial(d)
            raise LeaseError(d.code, d.message, d.http_status, d.detail)

        # 租约门禁已过：交给原 ECO 服务做基线指纹/依赖/纪元门禁（其拒收独立留痕）。
        # on_accept 在 ECO 接受结果的同一事务内把租约原子置为 COMPLETED：
        # 结果落定与租约完成要么一起成功，要么一起回滚。
        def on_accept(conn, accepted_run):
            conn.execute(
                "UPDATE check_lease SET state='COMPLETED',finished_reason='result_accepted',"
                "completed_at=? WHERE seq=?", (self.svc._now_str(), lease["seq"]))
            cur_lease = conn.execute("SELECT * FROM check_lease WHERE seq=?",
                                     (lease["seq"],)).fetchone()
            self._audit(conn, "complete", cur_lease,
                        detail={"verdict": verdict, "fingerprint_ok": True})

        try:
            detail = self.svc.submit_result(
                run_id, fingerprint, verdict, result or {}, runner_id, on_accept=on_accept)
        except ECOError as e:
            reason = e.extra.get("reason", e.code)
            self._persist_denial(_Denial(
                reason, e.message, e.http_status,
                {"ecoservice_code": e.code,
                 **{k: v for k, v in e.extra.items() if k != "reason"}},
                {"run_id": run_id, "eco_id": lease["eco_id"], "check_type": lease["check_type"],
                 "lease_seq": lease["seq"], "generation": lease["generation"],
                 "runner_id": runner_id}))
            # 对外仍用 ECO 的原因码与状态，保证现有拒收语义（FINGERPRINT_MISMATCH 等）不变
            raise
        return {"accepted": True, "lease": self.lease_status(run_id),
                "eco": {"id": detail["id"], "status": detail["status"],
                        "green": detail["gate"]["green"]}}

    # ---------------------------------------------------------------- 超时接管
    def takeover(self, run_id, by_runner, ttl_seconds=None):
        """超时接管：仅当租约已过 expires_at（HELD 过期或已 EXPIRED）才允许。
        代次 +1、凭据换新，旧持有者再交结果即 LEASE_GENERATION_STALE；历史写审计。"""
        if not by_runner:
            raise LeaseError("BAD_REQUEST", "by_runner 必填", 400, {})
        seq = self._lease_seq(run_id, required=True)
        lease = self._settle(seq)
        try:
            with self.s.tx() as c:
                cur = c.execute("SELECT * FROM check_lease WHERE seq=?", (seq,)).fetchone()
                run = c.execute("SELECT * FROM check_run WHERE id=?", (run_id,)).fetchone()
                if run and run["status"] == "SUPERSEDED":
                    self._deny("LEASE_TASK_SUPERSEDED",
                               "run 已作废（重跑/纪元变化），不可接管",
                               detail={"attempted": "takeover"}, lease=cur,
                               runner_id=by_runner)
                if cur["state"] in (LEASE_COMPLETED, LEASE_RELEASED, LEASE_INVALIDATED):
                    self._deny("LEASE_NOT_TAKEOVERABLE",
                               f"租约状态 {cur['state']}，不可接管；可重新领取",
                               detail={"state": cur["state"], "attempted": "takeover"},
                               lease=cur, runner_id=by_runner)
                now = self._now()
                if cur["state"] == LEASE_HELD and now < parse_ts(cur["expires_at"]):
                    self._deny("LEASE_NOT_TIMED_OUT",
                               "租约尚未过期，不允许接管（仅支持超时接管）",
                               detail={"expires_at": cur["expires_at"],
                                       "holder": cur["runner_id"]},
                               lease=cur, runner_id=by_runner)
                ttl = self._parse_ttl(ttl_seconds, cur["ttl_seconds"])
                previous = {"runner_id": cur["runner_id"], "generation": cur["generation"],
                            "acquired_at": cur["acquired_at"], "expires_at": cur["expires_at"],
                            "renew_count": cur["renew_count"], "state": cur["state"]}
                nonce = secrets.token_hex(8)
                c.execute(
                    "UPDATE check_lease SET generation=generation+1,runner_id=?,state='HELD',"
                    "ttl_seconds=?,acquired_at=?,expires_at=?,last_heartbeat_at=?,"
                    "completed_at=NULL,finished_reason=NULL,renew_count=0,token_nonce=? "
                    "WHERE seq=?",
                    (by_runner, ttl, self._now_s(), self._expiry(ttl), self._now_s(),
                     nonce, seq))
                cur = c.execute("SELECT * FROM check_lease WHERE seq=?", (seq,)).fetchone()
                self._audit(c, "takeover", cur, runner_id=by_runner,
                            detail={"previous": previous, "new_ttl_seconds": ttl})
                d = self._lease_dict(cur, include_token=True)
                d["previous"] = previous
                return d
        except _Denial as d:
            self._persist_denial(d)
            raise LeaseError(d.code, d.message, d.http_status, d.detail)

    # ---------------------------------------------------------------- 查询
    def lease_status(self, run_id):
        seq = self._lease_seq(run_id, required=True)
        with self.s.tx() as c:
            lease, events = self._canonicalize(
                c, c.execute("SELECT * FROM check_lease WHERE seq=?", (seq,)).fetchone())
            for reason, detail in events:
                self._audit(c, "reclaim", lease, reason=reason, detail=detail)
            d = self._lease_dict(lease)
            history = [dict(r) for r in c.execute(
                "SELECT seq,event,runner_id,generation,reason,detail_json,at FROM lease_audit "
                "WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()]
            for h in history:
                h["detail"] = json.loads(h.pop("detail_json") or "{}")
            d["history"] = history
            return d

    def list_leases(self, state=None):
        pool = self.pool()
        leases = pool["leases"]
        if state:
            leases = [l for l in leases if l["state"] == state]
        return {"at": pool["at"], "default_ttl_seconds": pool["default_ttl_seconds"],
                "leases": leases}

    def audit(self, run_id=None, reason=None, limit=100):
        sql = ("SELECT seq,run_id,eco_id,check_type,lease_seq,generation,runner_id,event,"
               "reason,detail_json,at FROM lease_audit WHERE 1=1")
        args = []
        if run_id:
            sql += " AND run_id=?"
            args.append(run_id)
        if reason:
            sql += " AND reason=?"
            args.append(reason)
        sql += " ORDER BY seq DESC LIMIT ?"
        args.append(int(limit))
        with self.s.lock:
            rows = self.s.q_all(sql, tuple(args))
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d.pop("detail_json") or "{}")
            out.append(d)
        return {"audit": out, "count": len(out)}
