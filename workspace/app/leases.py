"""验证执行租约协调服务（与 ECOService 配套的租约层）。

职责
----
1. 从验证矩阵读取**依赖已就绪**（PENDING）的检查，原子分配给 Runner；
2. 续租（heartbeat）、完成（携带租约代次 + 不可伪造凭据回传结果）、释放；
3. 租约超时后允许其他 Runner **接管**（租约代次 +1，旧持有者立即失效）；
4. 领取请求**幂等**：相同 idempotency_key 重放返回首次授权，并发领取只有一个成功；
5. 租约与审计全部落盘；进程重启后恢复未过期租约、回收已过期租约。

不可绕过的门禁
--------------
租约层只是“谁在什么代次可以提交”的协调层；真正的结果落库仍走 ECOService.submit_result：
冻结指纹（FINGERPRINT_MISMATCH）、纪元作废（STALE_SUPERSEDED）、依赖门禁
（DEPENDENCY_BLOCKED）、重跑/签核/发布约束全部由原 ECO 服务裁决，租约层无法绕过。

凭据模型
--------
- token = HMAC-SHA256(server_secret, f"{run_id}:{gen}:{runner_id}") 的 16hex，
  服务端在 CLAIM/TAKEOVER 响应中仅分发一次，库内只存 SHA-256(token)，因此不可伪造；
- 完成/续租必须同时携带 gen 与 token；gen 对不上即旧持有者（STALE_LEASE_GEN），
  token 对不上即 LEASE_BAD_CREDENTIAL；
- server_secret 落盘 lease_meta，进程重启后已发出的凭据继续有效。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone

from .service import ECOError, parse_ts
from .store import CHECKS, Store, utcnow

DEFAULT_TTL_SECONDS = 600
MIN_TTL_SECONDS = 30
MAX_TTL_SECONDS = 3600

# 租约状态
HELD, COMPLETED, RELEASED, EXPIRED, INVALIDATED = (
    "HELD", "COMPLETED", "RELEASED", "EXPIRED", "INVALIDATED")
ACTIVE_END_STATES = (COMPLETED, RELEASED, EXPIRED, INVALIDATED)

META_SECRET_KEY = "token_secret"


class LeaseError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 409, extra=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.extra = extra or {}


# ---------------------------------------------------------------- 凭据

def _derive_token(secret: str, run_id: str, gen: int, runner_id: str) -> str:
    msg = f"{run_id}:{gen}:{runner_id}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()[:16]


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class LeaseService:
    def __init__(self, store: Store, svc, now_fn=utcnow, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.s = store
        self.svc = svc                       # 原 ECO 服务：指纹/依赖/纪元门禁的唯一裁决者
        self._now_fn = now_fn
        self.default_ttl = int(ttl_seconds)
        self._secret = self._load_or_init_secret()

    # ---- 时钟 / 密钥 ----
    def _now(self) -> datetime:
        v = self._now_fn()
        return parse_ts(v) if isinstance(v, str) else v.astimezone(timezone.utc)

    def _now_str(self) -> str:
        return self._now().isoformat(timespec="seconds")

    def _load_or_init_secret(self) -> str:
        with self.s.lock:
            row = self.s.q_one("SELECT v FROM lease_meta WHERE k=?", (META_SECRET_KEY,))
            if row:
                return row["v"]
        secret = secrets.token_hex(32)
        with self.s.tx() as c:
            c.execute("INSERT OR IGNORE INTO lease_meta(k,v) VALUES(?,?)",
                      (META_SECRET_KEY, secret))
            row = c.execute("SELECT v FROM lease_meta WHERE k=?", (META_SECRET_KEY,)).fetchone()
            return row["v"]

    # ---- 审计 / 事件 ----
    def _event(self, c, event, *, run_id=None, eco_id=None, check_type=None, gen=None,
               actor=None, detail=None):
        c.execute(
            "INSERT INTO lease_event(run_id,eco_id,check_type,gen,event,actor,at,detail_json)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (run_id, eco_id, check_type, gen, event, actor, self._now_str(),
             json.dumps(detail or {}, ensure_ascii=False)))

    def _audit_out_of_band(self, event, **kw):
        """校验事务回滚后仍须留痕：在独立事务写一条 lease_event（与 rejected_result 同构）。"""
        with self.s.tx() as c:
            self._event(c, event, **kw)

    # ---- 租约整形 ----
    def _lease_dict(self, row, now: datetime | None = None):
        d = dict(row)
        d["detail"] = json.loads(d.pop("detail_json") or "{}")
        d.pop("token_hash", None)          # 凭据摘要绝不出现在任何响应里
        now = now or self._now()
        exp = parse_ts(d["expires_at"])
        d["remaining_seconds"] = max(0, int((exp - now).total_seconds()))
        d["expired"] = now >= exp
        return d

    def _grant(self, run, runner_id: str, gen: int, token: str, ttl: int, now: datetime, *,
               acquired: bool = True, **extra):
        return {
            "acquired": acquired,
            "run_id": run["id"], "eco_id": run["eco_id"], "check_type": run["check_type"],
            "gen": gen, "runner_id": runner_id,
            "lease_token": token,
            "token_type": "hmac-sha256-16",
            "acquired_at": now.isoformat(timespec="seconds"),
            "expires_at": (now + timedelta(seconds=ttl)).isoformat(timespec="seconds"),
            "ttl_seconds": ttl,
            "remaining_seconds": ttl,
            "run_status": run["status"],
            **extra,
        }

    # ---- 启动恢复 ----
    def recover(self) -> dict:
        """进程启动时调用：恢复未过期租约（保持 HELD），回收已过期租约（EXPIRED 可接管）。

        顺带对账：租约仍 HELD 但其 run 已在租约层之外结束（被直接提交/作废）的，
        收敛到 COMPLETED/INVALIDATED，避免页面长期挂死。
        """
        with self.s.tx() as c:
            now = self._now()
            expired, restored, reconciled = [], 0, 0
            for l in c.execute("SELECT * FROM check_lease").fetchall():
                if l["state"] in ACTIVE_END_STATES:
                    continue
                run = c.execute("SELECT * FROM check_run WHERE id=?", (l["run_id"],)).fetchone()
                if parse_ts(l["expires_at"]) <= now:
                    c.execute("UPDATE check_lease SET state='EXPIRED' WHERE run_id=?",
                              (l["run_id"],))
                    self._event(c, "EXPIRE", run_id=l["run_id"], eco_id=l["eco_id"],
                                check_type=l["check_type"], gen=l["gen"], actor="system",
                                detail={"reason": "expired at startup recovery",
                                        "expires_at": l["expires_at"]})
                    expired.append(l["run_id"])
                    continue
                restored += 1
                if run and run["status"] in ("PASS", "FAIL"):
                    c.execute("UPDATE check_lease SET state='COMPLETED',completed_at=?,"
                              "completion_verdict=? WHERE run_id=?",
                              (self._now_str(), run["status"], l["run_id"]))
                    self._event(c, "COMPLETE", run_id=l["run_id"], eco_id=l["eco_id"],
                                check_type=l["check_type"], gen=l["gen"], actor="system",
                                detail={"reason": "reconciled at startup"})
                    reconciled += 1
                elif not run or run["status"] == "SUPERSEDED":
                    c.execute("UPDATE check_lease SET state='INVALIDATED' WHERE run_id=?",
                              (l["run_id"],))
                    self._event(c, "INVALIDATE", run_id=l["run_id"], eco_id=l["eco_id"],
                                check_type=l["check_type"], gen=l["gen"], actor="system",
                                detail={"reason": "run superseded at startup recovery"})
                    reconciled += 1
            self._event(c, "RECOVER", actor="system",
                        detail={"restored_held": restored, "recovered_expired": len(expired),
                                "reconciled": reconciled, "at": now.isoformat(timespec="seconds")})
            return {"restored_held": restored, "recovered_expired": expired,
                    "reconciled": reconciled, "at": now.isoformat(timespec="seconds")}

    def _reconcile(self, c, now: datetime):
        """惰性回收：每次领取/接管事务内顺手收敛已过期租约与已结束的 run。

        与 recover() 同一套规则，保证即使没有后台线程，超时也会被确定性回收。
        """
        expired_ids, reconciled = [], 0
        for l in c.execute("SELECT * FROM check_lease WHERE state='HELD'").fetchall():
            run = c.execute("SELECT * FROM check_run WHERE id=?", (l["run_id"],)).fetchone()
            if parse_ts(l["expires_at"]) <= now:
                cur = c.execute("UPDATE check_lease SET state='EXPIRED' WHERE run_id=? AND state='HELD'",
                                (l["run_id"],))
                if cur.rowcount == 0:
                    continue
                self._event(c, "EXPIRE", run_id=l["run_id"], eco_id=l["eco_id"],
                            check_type=l["check_type"], gen=l["gen"], actor="system",
                            detail={"reason": "ttl expired", "expires_at": l["expires_at"]})
                expired_ids.append(l["run_id"])
            elif run and run["status"] in ("PASS", "FAIL"):
                c.execute("UPDATE check_lease SET state='COMPLETED',completed_at=?,"
                          "completion_verdict=? WHERE run_id=? AND state='HELD'",
                          (self._now_str(), run["status"], l["run_id"]))
                self._event(c, "COMPLETE", run_id=l["run_id"], eco_id=l["eco_id"],
                            check_type=l["check_type"], gen=l["gen"], actor="system",
                            detail={"reason": "run finished out-of-band"})
                reconciled += 1
            elif not run or run["status"] == "SUPERSEDED":
                c.execute("UPDATE check_lease SET state='INVALIDATED' WHERE run_id=? AND state='HELD'",
                          (l["run_id"],))
                self._event(c, "INVALIDATE", run_id=l["run_id"], eco_id=l["eco_id"],
                            check_type=l["check_type"], gen=l["gen"], actor="system",
                            detail={"reason": "run superseded (epoch/refreeze/rerun)"})
                reconciled += 1
        return expired_ids, reconciled

    # ---- 待领任务 ----
    def _claimable_run(self, c, run_id):
        """从验证矩阵读取一个当前可领取的 run：FROZEN ECO 上 PENDING（依赖已就绪）。"""
        run = c.execute("SELECT * FROM check_run WHERE id=?", (run_id,)).fetchone()
        if not run:
            raise LeaseError("RUN_NOT_FOUND", f"检查运行 {run_id} 不存在", 404)
        eco = c.execute("SELECT * FROM eco WHERE id=?", (run["eco_id"],)).fetchone()
        if run["status"] == "SUPERSEDED":
            raise LeaseError("RUN_SUPERSEDED", "该检查已随纪元/重跑作废，不能领取", 409,
                             {"run_id": run_id})
        if eco["status"] != "FROZEN":
            raise LeaseError("ECO_NOT_ACTIVE", f"ECO 状态 {eco['status']}，无可执行检查", 409,
                             {"eco_status": eco["status"]})
        if run["status"] in ("PASS", "FAIL"):
            raise LeaseError("RUN_NOT_CLAIMABLE", f"检查已完成（{run['status']}），无需领取",
                             409, {"run_status": run["status"]})
        if run["status"] == "BLOCKED":
            raise LeaseError("DEPENDENCY_NOT_READY",
                             "依赖前置尚未全部 PASS，任务未就绪，不能领取", 409,
                             {"depends_on": json.loads(run["depends_on_json"])})
        return run, eco

    def _pick_claimable(self, c):
        """原子挑选一个就绪任务：FROZEN ECO 上 status=PENDING、且当前没有 HELD 租约。

        排序确定（eco_id, check_type），便于并发下行为可预测。
        """
        row = c.execute(
            "SELECT cr.* FROM check_run cr JOIN eco e ON e.id=cr.eco_id "
            "WHERE e.status='FROZEN' AND cr.status='PENDING' "
            "AND NOT EXISTS (SELECT 1 FROM check_lease cl WHERE cl.run_id=cr.id "
            "                AND cl.state='HELD') "
            "ORDER BY cr.eco_id, cr.check_type LIMIT 1").fetchone()
        return row

    # ---- 领取（幂等；并发只有一个成功）----
    def claim(self, runner_id: str, *, run_id: str | None = None,
              idempotency_key: str | None = None, ttl_seconds: int | None = None) -> dict:
        if not runner_id:
            raise LeaseError("BAD_REQUEST", "runner_id 必填", 400)
        ttl = int(ttl_seconds or self.default_ttl)
        if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
            raise LeaseError("BAD_TTL",
                             f"ttl_seconds 须在 [{MIN_TTL_SECONDS},{MAX_TTL_SECONDS}] 内", 400)
        idem = (idempotency_key or "").strip() or None
        try:
            with self.s.tx() as c:
                now = self._now()
                self._reconcile(c, now)

                # ① 幂等重放：同 key 直接回放首次授权（不新代次、不新事件）
                if idem:
                    prev = c.execute("SELECT * FROM lease_claim WHERE idempotency_key=?",
                                     (idem,)).fetchone()
                    if prev:
                        grant = json.loads(prev["grant_json"])
                        if prev["runner_id"] != runner_id or prev["run_id"] != (run_id or prev["run_id"]):
                            raise LeaseError(
                                "IDEMPOTENCY_KEY_REUSED",
                                "幂等键已被另一 runner/任务的领取占用，不能复用", 409,
                                {"idempotency_key": idem,
                                 "original_runner": prev["runner_id"],
                                 "original_run_id": prev["run_id"]})
                        cur = c.execute("SELECT * FROM check_lease WHERE run_id=?",
                                        (prev["run_id"],)).fetchone()
                        grant["replayed"] = True
                        if cur:
                            exp = parse_ts(cur["expires_at"])
                            grant["state"] = cur["state"]
                            grant["gen"] = cur["gen"]
                            grant["remaining_seconds"] = max(0, int((exp - now).total_seconds()))
                            grant["expires_at"] = cur["expires_at"]
                            grant["expired"] = now >= exp
                        return grant

                # ② 确定目标 run（显式指定 或 原子挑一个就绪的）
                if run_id:
                    run, eco = self._claimable_run(c, run_id)
                else:
                    run = self._pick_claimable(c)
                    if not run:
                        raise LeaseError("NO_CLAIMABLE_TASK", "当前没有依赖就绪、可领取的检查",
                                         409)
                    eco = c.execute("SELECT * FROM eco WHERE id=?", (run["eco_id"],)).fetchone()

                # ③ 与既有租约裁决
                lease = c.execute("SELECT * FROM check_lease WHERE run_id=?",
                                  (run["id"],)).fetchone()
                taken_over = False
                if lease and lease["state"] == HELD and parse_ts(lease["expires_at"]) > now:
                    if lease["runner_id"] == runner_id:
                        # 同一持有者无幂等键重复领取：回放既有授权（不新增代次）
                        token = _derive_token(self._secret, run["id"], lease["gen"], runner_id)
                        grant = self._grant(run, runner_id, lease["gen"], token,
                                            max(0, int((parse_ts(lease["expires_at"]) - now)
                                                       .total_seconds())), now,
                                            state=HELD, replayed=True)
                        return grant
                    raise LeaseError(
                        "LEASE_HELD_BY_OTHER",
                        f"任务已被 {lease['runner_id']} 持有至 {lease['expires_at']}，"
                        "到期后才可接管", 409,
                        {"run_id": run["id"], "holder": lease["runner_id"],
                         "gen": lease["gen"], "expires_at": lease["expires_at"],
                         "remaining_seconds": max(0, int((parse_ts(lease["expires_at"]) - now)
                                                          .total_seconds()))})

                if lease:
                    # EXPIRED / INVALIDATED / COMPLETED / RELEASED 行：重新分配（代次 +1）
                    gen = lease["gen"] + 1
                    old_holder, old_gen, old_state = lease["runner_id"], lease["gen"], lease["state"]
                    if old_state in (COMPLETED, RELEASED) and run["status"] in ("PASS", "FAIL"):
                        raise LeaseError("RUN_NOT_CLAIMABLE",
                                         f"检查已完成（{run['status']}），不可再领取", 409,
                                         {"run_status": run["status"]})
                    # 事务开头的 _reconcile 已把超时 HELD 收敛为 EXPIRED；
                    # 主动释放(RELEASED)后重新领取记 CLAIM，超时/作废后领取记 TAKEOVER
                    is_takeover = old_state in (EXPIRED, INVALIDATED)
                    taken_over = is_takeover
                else:
                    gen, old_holder, old_gen, old_state = 1, None, None, None
                    is_takeover = False

                token = _derive_token(self._secret, run["id"], gen, runner_id)
                expires = now + timedelta(seconds=ttl)
                c.execute(
                    "INSERT INTO check_lease(run_id,eco_id,check_type,gen,runner_id,state,"
                    "token_hash,acquired_at,expires_at,renewed_count,detail_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(run_id) DO UPDATE SET gen=excluded.gen,runner_id=excluded.runner_id,"
                    "state='HELD',token_hash=excluded.token_hash,acquired_at=excluded.acquired_at,"
                    "expires_at=excluded.expires_at,renewed_count=0,completed_at=NULL,"
                    "completion_verdict=NULL,detail_json=excluded.detail_json",
                    (run["id"], run["eco_id"], run["check_type"], gen, runner_id, HELD,
                     _hash_token(token), now.isoformat(timespec="seconds"),
                     expires.isoformat(timespec="seconds"), 0,
                     json.dumps({"previous_holder": old_holder, "previous_gen": old_gen,
                                 "previous_state": old_state}, ensure_ascii=False)))
                ev_detail = {"ttl_seconds": ttl, "expires_at": expires.isoformat(timespec="seconds"),
                             "idempotency_key": idem}
                if taken_over:
                    ev_detail.update({"previous_holder": old_holder, "previous_gen": old_gen,
                                      "previous_state": old_state})
                    self._event(c, "TAKEOVER", run_id=run["id"], eco_id=run["eco_id"],
                                check_type=run["check_type"], gen=gen, actor=runner_id,
                                detail=ev_detail)
                else:
                    self._event(c, "CLAIM", run_id=run["id"], eco_id=run["eco_id"],
                                check_type=run["check_type"], gen=gen, actor=runner_id,
                                detail=ev_detail)

                grant = self._grant(run, runner_id, gen, token, ttl, now,
                                    state=HELD, taken_over=taken_over,
                                    previous_holder=old_holder if taken_over else None,
                                    previous_gen=old_gen if taken_over else None)
                if idem:
                    c.execute(
                        "INSERT INTO lease_claim(idempotency_key,run_id,runner_id,claimed_at,"
                        "grant_json) VALUES(?,?,?,?,?)",
                        (idem, run["id"], runner_id, now.isoformat(timespec="seconds"),
                         json.dumps(grant, ensure_ascii=False)))
                return grant
        except LeaseError as e:
            # 领取阶段的拒绝也进可查询审计（独立事务，回滚不影响留痕）
            if e.code not in ("BAD_REQUEST", "BAD_TTL"):
                self._audit_out_of_band(
                    "REJECT", run_id=run_id, actor=runner_id,
                    detail={"stage": "claim", "reason": e.code, **{
                        k: v for k, v in e.extra.items()
                        if k in ("gen", "holder", "run_status", "eco_status", "depends_on",
                                 "remaining_seconds")}})
            raise

    # ---- 凭据/代次校验（完成与续租共用）----
    def _authorize(self, c, run_id, gen, token, *, stage):
        if gen is None:
            raise LeaseError("MISSING_LEASE_GEN", "完成/续租必须携带租约代次 gen", 400)
        if not token:
            raise LeaseError("MISSING_LEASE_TOKEN", "完成/续租必须携带不可伪造凭据 lease_token",
                             400)
        lease = c.execute("SELECT * FROM check_lease WHERE run_id=?", (run_id,)).fetchone()
        if not lease:
            raise LeaseError("LEASE_NOT_FOUND", "该检查不存在有效租约，请先领取", 404,
                             {"run_id": run_id})
        now = self._now()
        # 先判代次：接管/重跑后旧持有者的迟到结果在这里被确定性拒绝
        if int(gen) != lease["gen"]:
            raise LeaseError("STALE_LEASE_GEN",
                             "租约代次不匹配：持有的是旧代次（已被接管/重领），结果拒收", 409,
                             {"submitted_gen": int(gen), "current_gen": lease["gen"],
                              "current_holder": lease["runner_id"]})
        if not hmac.compare_digest(_hash_token(token), lease["token_hash"]):
            raise LeaseError("LEASE_BAD_CREDENTIAL",
                             "租约凭据无效或已被接管，拒绝提交", 403,
                             {"run_id": run_id, "gen": int(gen)})
        if lease["state"] != HELD:
            # run 已随 rebase/合并/发布/重跑作废：无论租约之前是何终态，旧代次迟到结果
            # 一律按纪元作废拒收（与 ECO 的 STALE_SUPERSEDED 语义一致）
            run = c.execute("SELECT status FROM check_run WHERE id=?", (run_id,)).fetchone()
            if not run or run["status"] == "SUPERSEDED":
                raise LeaseError("STALE_SUPERSEDED",
                                 "租约对应的检查已随纪元/重跑作废，迟到结果拒收", 409,
                                 {"state": lease["state"], "current_gen": lease["gen"]})
            reason_map = {COMPLETED: "LEASE_ALREADY_COMPLETED", RELEASED: "LEASE_RELEASED",
                          EXPIRED: "LEASE_EXPIRED", INVALIDATED: "LEASE_INVALIDATED"}
            raise LeaseError(reason_map[lease["state"]],
                             f"租约已处于 {lease['state']} 终态，不能{stage}", 409,
                             {"state": lease["state"]})
        if parse_ts(lease["expires_at"]) <= now:
            raise LeaseError("LEASE_EXPIRED",
                             f"租约已于 {lease['expires_at']} 过期，请重新领取或被接管", 409,
                             {"expires_at": lease["expires_at"]})
        return lease

    # ---- 续租 ----
    def renew(self, run_id: str, gen: int, token: str, runner_id: str,
              ttl_seconds: int | None = None) -> dict:
        if not runner_id:
            raise LeaseError("BAD_REQUEST", "runner_id 必填", 400)
        ttl = int(ttl_seconds or self.default_ttl)
        if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
            raise LeaseError("BAD_TTL",
                             f"ttl_seconds 须在 [{MIN_TTL_SECONDS},{MAX_TTL_SECONDS}] 内", 400)
        with self.s.tx() as c:
            self._reconcile(c, self._now())
            lease = self._authorize(c, run_id, gen, token, stage="续租")
            if lease["runner_id"] != runner_id:
                raise LeaseError("LEASE_NOT_HELD_BY_RUNNER",
                                 "续租人不是当前持有者", 403,
                                 {"holder": lease["runner_id"], "runner_id": runner_id})
            now = self._now()
            expires = now + timedelta(seconds=ttl)
            c.execute("UPDATE check_lease SET expires_at=?,renewed_count=renewed_count+1 "
                      "WHERE run_id=?", (expires.isoformat(timespec="seconds"), run_id))
            self._event(c, "RENEW", run_id=run_id, eco_id=lease["eco_id"],
                        check_type=lease["check_type"], gen=lease["gen"], actor=runner_id,
                        detail={"new_expires_at": expires.isoformat(timespec="seconds"),
                                "renewed_count": lease["renewed_count"] + 1})
            d = self._lease_dict(
                c.execute("SELECT * FROM check_lease WHERE run_id=?", (run_id,)).fetchone(), now)
            d["acquired"] = True
            d["lease_token"] = token
            return d

    # ---- 完成：凭据校验通过后，结果仍必须穿过 ECO 服务的基线/依赖门禁 ----
    def complete(self, run_id: str, gen: int, token: str, fingerprint: str, verdict: str,
                 result: dict | None = None, runner_id: str | None = None) -> dict:
        result = result or {}
        denied = None
        try:
            with self.s.tx() as c:
                now = self._now()
                self._reconcile(c, now)
                lease = self._authorize(c, run_id, gen, token, stage="提交结果")
                runner_id = runner_id or lease["runner_id"]
                if lease["runner_id"] != runner_id:
                    raise LeaseError("LEASE_NOT_HELD_BY_RUNNER",
                                     "提交人不是当前代次持有者", 403,
                                     {"holder": lease["runner_id"], "runner_id": runner_id})
                if verdict not in ("PASS", "FAIL"):
                    raise LeaseError("BAD_VERDICT", "verdict 须为 PASS/FAIL", 400,
                                     {"verdict": verdict})
                if not fingerprint:
                    raise LeaseError("MISSING_FINGERPRINT", "必须携带 Runner 自算的输入指纹", 400)
                # 凭据与代次全部合法：落库交给原 ECO 服务裁决——指纹不符 / 依赖未满足 /
                # ECO 不活跃 / 已提交 / 纪元作废均在此被拒，租约层无法绕过。
                # 与凭据校验处于**同一个事务**：接管与完成并发时只有一方提交，
                # 旧持有者不可能在被接管的瞬间把结果塞进去。
                try:
                    eco_detail = self.svc._apply_result(
                        c, run_id, fingerprint, verdict, result, runner_id)
                except ECOError as ee:
                    reason = ee.extra.get("reason", ee.code)
                    # 与 ECO 侧 rejected_result 相同的留痕：在回滚前先于本事务插入，
                    # 随后用 LEASE REJECT 事件触发回滚——故改用独立审计事务（见 except）。
                    denied = {"reason": reason, "message": ee.message, "extra": ee.extra}
                    raise LeaseError("RESULT_REJECTED_BY_ECO", reason, 409,
                                     {"reason": reason, "eco_error": ee.code,
                                      "lease_gen": int(gen), **{
                                          k: v for k, v in ee.extra.items() if k != "reason"}})
                c.execute("UPDATE check_lease SET state='COMPLETED',completed_at=?,"
                          "completion_verdict=? WHERE run_id=? AND gen=? AND state='HELD'",
                          (self._now_str(), verdict, run_id, lease["gen"]))
                self._event(c, "COMPLETE", run_id=run_id, eco_id=lease["eco_id"],
                            check_type=lease["check_type"], gen=lease["gen"], actor=runner_id,
                            detail={"verdict": verdict, "fingerprint": fingerprint})
                final = c.execute("SELECT * FROM check_lease WHERE run_id=?", (run_id,)).fetchone()
                return {"accepted": True, "lease": self._lease_dict(final, now),
                        "eco": {"id": eco_detail["id"], "status": eco_detail["status"],
                                "freeze_epoch": eco_detail["freeze_epoch"]}}
        except LeaseError as e:
            # 所有完成拒绝进 lease_event 可查询审计（独立事务，主校验事务已回滚）
            self._audit_out_of_band(
                "REJECT", run_id=run_id, actor=runner_id,
                detail={"stage": "complete", "reason": denied["reason"] if denied else e.code,
                        "submitted_gen": gen if isinstance(gen, int) else None,
                        **{k: v for k, v in e.extra.items()
                           if k in ("current_gen", "current_holder", "state", "expires_at",
                                    "reason", "eco_error", "lease_gen")}})
            if denied:
                # ECO 侧 rejected_result 留痕 + 向调用方透传 ECO 原始原因码
                self.svc._record_result_rejection(run_id, ECOError(
                    "RESULT_REJECTED", denied["message"], 409, denied["extra"]))
                extra = dict(denied["extra"])
                extra.setdefault("lease_gen", gen)
                raise LeaseError(denied["reason"], denied["message"], 409, extra)
            raise

    # ---- 主动释放（持有者放弃，任务回到可领取池，不增加代次）----
    def release(self, run_id: str, gen: int, token: str, runner_id: str,
                note: str = "") -> dict:
        with self.s.tx() as c:
            lease = self._authorize(c, run_id, gen, token, stage="释放")
            if lease["runner_id"] != runner_id:
                raise LeaseError("LEASE_NOT_HELD_BY_RUNNER", "释放人不是当前持有者", 403,
                                 {"holder": lease["runner_id"], "runner_id": runner_id})
            c.execute("UPDATE check_lease SET state='RELEASED' WHERE run_id=?", (run_id,))
            self._event(c, "RELEASE", run_id=run_id, eco_id=lease["eco_id"],
                        check_type=lease["check_type"], gen=lease["gen"], actor=runner_id,
                        detail={"note": note})
            return self._lease_dict(
                c.execute("SELECT * FROM check_lease WHERE run_id=?", (run_id,)).fetchone())

    # ---- 显式接管已过期任务（无需旧持有者凭据；代次 +1 使其凭据立即失效）----
    def takeover(self, run_id: str, runner_id: str, ttl_seconds: int | None = None) -> dict:
        if not runner_id:
            raise LeaseError("BAD_REQUEST", "runner_id 必填", 400)
        ttl = int(ttl_seconds or self.default_ttl)
        if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
            raise LeaseError("BAD_TTL",
                             f"ttl_seconds 须在 [{MIN_TTL_SECONDS},{MAX_TTL_SECONDS}] 内", 400)
        with self.s.tx() as c:
            now = self._now()
            self._reconcile(c, now)
            run, eco = self._claimable_run(c, run_id)
            lease = c.execute("SELECT * FROM check_lease WHERE run_id=?", (run_id,)).fetchone()
            if not lease:
                raise LeaseError("LEASE_NOT_FOUND",
                                 "该检查尚未被领取过，应直接 claim 而非 takeover", 409)
            if lease["state"] == HELD and parse_ts(lease["expires_at"]) > now:
                if lease["runner_id"] == runner_id:
                    raise LeaseError("LEASE_HELD_BY_SELF",
                                     "你当前仍持有该任务的未过期租约，无需接管", 409,
                                     {"expires_at": lease["expires_at"]})
                raise LeaseError("LEASE_NOT_EXPIRED",
                                 "租约尚未过期，不能强制接管（等待 TTL 到期）", 409,
                                 {"holder": lease["runner_id"],
                                  "expires_at": lease["expires_at"],
                                  "remaining_seconds":
                                      max(0, int((parse_ts(lease["expires_at"]) - now)
                                                 .total_seconds()))})
            if lease["state"] != EXPIRED:
                raise LeaseError("LEASE_NOT_TAKEOVERABLE",
                                 f"租约状态为 {lease['state']}，非超时租约请用 claim 领取",
                                 409, {"state": lease["state"]})
            if lease["runner_id"] == runner_id:
                # 自己的过期租约“接管”等价于重新领取：仍 +1 代次，旧凭据作废
                pass
            gen = lease["gen"] + 1
            old_holder, old_gen = lease["runner_id"], lease["gen"]
            token = _derive_token(self._secret, run_id, gen, runner_id)
            expires = now + timedelta(seconds=ttl)
            c.execute(
                "UPDATE check_lease SET gen=?,runner_id=?,state='HELD',token_hash=?,"
                "acquired_at=?,expires_at=?,renewed_count=0,completed_at=NULL,"
                "completion_verdict=NULL,detail_json=? WHERE run_id=?",
                (gen, runner_id, _hash_token(token), now.isoformat(timespec="seconds"),
                 expires.isoformat(timespec="seconds"),
                 json.dumps({"previous_holder": old_holder, "previous_gen": old_gen,
                             "previous_state": lease["state"]}, ensure_ascii=False), run_id))
            self._event(c, "TAKEOVER", run_id=run_id, eco_id=run["eco_id"],
                        check_type=run["check_type"], gen=gen, actor=runner_id,
                        detail={"previous_holder": old_holder, "previous_gen": old_gen,
                                "previous_state": lease["state"], "ttl_seconds": ttl,
                                "expires_at": expires.isoformat(timespec="seconds")})
            return self._grant(run, runner_id, gen, token, ttl, now,
                               state=HELD, taken_over=True,
                               previous_holder=old_holder, previous_gen=old_gen)

    # ---- 查询：租约看板 / 接管历史 / 拒绝审计 ----
    def lease_board(self) -> dict:
        """操作页面聚合：待领任务、当前持有者与剩余时间、可接管任务、接管历史。"""
        with self.s.lock:
            now = self._now()
            with self.s.tx() as c:
                self._reconcile(c, now)

            # 待领：FROZEN ECO 上 PENDING 且无 HELD 租约
            pending = self.s.q_all(
                "SELECT cr.*, e.title eco_title FROM check_run cr JOIN eco e ON e.id=cr.eco_id "
                "WHERE e.status='FROZEN' AND cr.status='PENDING' "
                "AND NOT EXISTS (SELECT 1 FROM check_lease cl WHERE cl.run_id=cr.id "
                "                AND cl.state='HELD') ORDER BY cr.eco_id, cr.check_type")
            claimable = []
            for r in pending:
                deps = json.loads(r["depends_on_json"])
                claimable.append({
                    "run_id": r["id"], "eco_id": r["eco_id"], "eco_title": r["eco_title"],
                    "check_type": r["check_type"],
                    "label": CHECKS[r["check_type"]]["label"], "required": bool(r["required"]),
                    "depends_on": deps,
                    "dep_status": self._dep_status(r["eco_id"], deps)})

            held, takeoverable = [], []
            for l in self.s.q_all("SELECT * FROM check_lease ORDER BY acquired_at DESC, run_id"):
                d = self._lease_dict(l, now)
                d["label"] = CHECKS.get(l["check_type"], {}).get("label", l["check_type"])
                run = self.s.q_one("SELECT status FROM check_run WHERE id=?", (l["run_id"],))
                d["run_status"] = run["status"] if run else None
                if d["state"] == HELD and not d["expired"]:
                    held.append(d)
                elif d["state"] in (EXPIRED,) or (d["state"] == HELD and d["expired"]):
                    if run and run["status"] == "PENDING":
                        takeoverable.append(d)

            history = [self._event_dict(r) for r in self.s.q_all(
                "SELECT * FROM lease_event WHERE event IN ('TAKEOVER','EXPIRE','INVALIDATE') "
                "ORDER BY seq DESC LIMIT 50")]
            rejects = [self._event_dict(r) for r in self.s.q_all(
                "SELECT * FROM lease_event WHERE event='REJECT' ORDER BY seq DESC LIMIT 50")]
            return {
                "at": now.isoformat(timespec="seconds"),
                "default_ttl_seconds": self.default_ttl,
                "claimable": claimable,
                "held": held,
                "takeover_available": takeoverable,
                "takeover_history": history,
                "recent_rejects": rejects,
                "all_leases": [self._lease_dict(l, now) | {
                    "label": CHECKS.get(l["check_type"], {}).get("label", l["check_type"])}
                    for l in self.s.q_all(
                        "SELECT * FROM check_lease ORDER BY run_id")],
            }

    def _dep_status(self, eco_id, deps):
        if not deps:
            return {}
        rows = self.s.q_all(
            "SELECT check_type,status FROM check_run WHERE eco_id=? AND status!='SUPERSEDED'",
            (eco_id,))
        cur = {r["check_type"]: r["status"] for r in rows}
        return {d: cur.get(d, "MISSING") for d in deps}

    def _event_dict(self, row):
        d = dict(row)
        d["detail"] = json.loads(d.pop("detail_json") or "{}")
        return d

    def lease(self, run_id: str) -> dict:
        with self.s.lock:
            row = self.s.q_one("SELECT * FROM check_lease WHERE run_id=?", (run_id,))
            if not row:
                raise LeaseError("LEASE_NOT_FOUND", f"租约 {run_id} 不存在", 404)
            d = self._lease_dict(row)
            d["label"] = CHECKS.get(row["check_type"], {}).get("label", row["check_type"])
            d["events"] = [self._event_dict(r) for r in self.s.q_all(
                "SELECT * FROM lease_event WHERE run_id=? ORDER BY seq", (run_id,))]
            return d

    def audit_events(self, *, run_id: str | None = None, event: str | None = None,
                     reason: str | None = None, limit: int = 200):
        """可查询审计：支持按 run / 事件类型 / 拒绝原因过滤。"""
        limit = max(1, min(int(limit or 200), 1000))
        sql = "SELECT * FROM lease_event WHERE 1=1"
        args = []
        if run_id:
            sql += " AND run_id=?"
            args.append(run_id)
        if event:
            sql += " AND event=?"
            args.append(event)
        if reason:
            sql += " AND json_extract(detail_json,'$.reason')=?"
            args.append(reason)
        sql += " ORDER BY seq DESC LIMIT ?"
        args.append(limit)
        with self.s.lock:
            return {"events": [self._event_dict(r) for r in self.s.q_all(sql, tuple(args))]}
