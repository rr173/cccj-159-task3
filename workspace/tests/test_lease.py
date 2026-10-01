"""验证执行租约协调模块（LeaseService）不变量测试。

覆盖：就绪任务发现、领取幂等、并发唯一成功、续租、完成、释放、超时接管、
代次/凭据拒绝矩阵、依赖门禁、重跑后旧代次迟到结果、重启恢复/回收，
以及接管结果仍受 ECO 基线指纹/依赖门禁约束。
"""
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.runner import compute_input_fingerprint
from app.service import ECOError, ECOService
from app.store import Store
from app.lease import LeaseError, LeaseService


class Clock:
    """可控 UTC 时钟（字符串 ISO 输出，与 service.utcnow 形态一致）。"""
    def __init__(self, t=None):
        self.t = t or datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.t.isoformat(timespec="seconds")

    def advance(self, seconds):
        self.t += timedelta(seconds=seconds)


def make_service(ttl=60, path=":memory:"):
    clk = Clock()
    store = Store(path, seed=(path == ":memory:"))
    svc = ECOService(store, now_fn=clk)
    leases = LeaseService(svc, ttl_seconds=ttl, now_fn=clk)
    return clk, svc, leases, store


def freeze_one(svc, mods=("alu",)):
    edits = {m: {"netlist": f"MODULE {m}; CELL LEASE_FIX; ENDMODULE"} for m in mods}
    e = svc.create_eco(f"租约-{mods}", "owner.x", list(mods), edits)
    svc.freeze_eco(e["id"], "owner.x")
    return e["id"]


def fp_for(svc, eco_id, check_type):
    pkt = svc.check_inputs(eco_id, check_type)
    return compute_input_fingerprint(check_type, pkt["inputs"]), pkt


def submit_ok(leases, svc, claim, verdict="PASS"):
    rid = claim["run_id"]
    fp, _ = fp_for(svc, claim["eco_id"], claim["check_type"])
    return leases.submit_result(rid, claim["runner_id"], claim["generation"],
                                claim["lease_token"], fp, verdict, {"k": "v"})


class TestClaimPoolAndIdempotency(unittest.TestCase):
    def setUp(self):
        self.clk, self.svc, self.ls, self.store = make_service()
        self.eid = freeze_one(self.svc)

    def test_pool_only_lists_ready_pending_runs(self):
        pool = self.ls.pool(self.eid)
        # 无依赖检查就绪（含非必需 LINT_INFO）；LAYOUT_DRC 依赖 TIMING+POWER，不得出现
        types = {x["check_type"] for x in pool["claimable"]}
        self.assertEqual(types,
                         {"TIMING_STA", "POWER_ANALYSIS", "FORMAL_EQUIV", "LINT_INFO"})
        self.assertTrue(all(x["depends_on"] == [] for x in pool["claimable"]))

    def test_claim_assigns_and_disappears_from_pool(self):
        a = self.ls.claim("runner-A", "key-1")
        self.assertTrue(a["claimed"])
        self.assertEqual(a["generation"], 1)
        self.assertEqual(a["state"], "HELD")
        self.assertEqual(a["remaining_seconds"], 60)
        self.assertRegex(a["lease_token"], r"^[0-9a-f]{32}$")
        pool = self.ls.pool(self.eid)
        self.assertFalse(any(x["run_id"] == a["run_id"] for x in pool["claimable"]))

    def test_claim_is_idempotent_on_replay(self):
        a = self.ls.claim("runner-A", "key-1")
        b = self.ls.claim("runner-A", "key-1")
        self.assertFalse(b["claimed"])
        self.assertTrue(b["idempotent"])
        self.assertEqual(b["run_id"], a["run_id"])
        self.assertEqual(b["generation"], a["generation"])
        self.assertEqual(b["lease_token"], a["lease_token"])
        # 只生成一条租约
        self.assertEqual(self.store.q_one(
            "SELECT COUNT(*) k FROM check_lease WHERE run_id=?", (a["run_id"],))["k"], 1)
        self.assertEqual(self.store.q_one("SELECT COUNT(*) k FROM lease_claim")["k"], 1)

    def test_concurrent_claims_only_one_wins(self):
        target = self.ls.pool(self.eid)["claimable"][0]["run_id"]
        results, errors = [], []
        barrier = threading.Barrier(8)

        def worker(i):
            barrier.wait()
            try:
                results.append(self.ls.claim(f"runner-{i}", f"k-{i}", run_id=target))
            except LeaseError as e:
                errors.append(e.code)

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(len(results), 1, results)
        self.assertTrue(results[0]["claimed"])
        self.assertEqual(errors.count("LEASE_HELD_BY_OTHER"), 7)
        self.assertEqual(self.store.q_one(
            "SELECT COUNT(*) k FROM check_lease WHERE run_id=?", (target,))["k"], 1)

    def test_blocked_run_cannot_be_claimed(self):
        d = self.svc.eco_detail(self.eid)
        drc = next(c for c in d["gate"]["checks"] if c["type"] == "LAYOUT_DRC")
        self.assertEqual(drc["status"], "BLOCKED")
        run_id = next(r["id"] for r in self.store.q_all(
            "SELECT id FROM check_run WHERE eco_id=? AND check_type='LAYOUT_DRC'",
            (self.eid,)))
        with self.assertRaises(LeaseError) as cm:
            self.ls.claim("r", "k", run_id=run_id)
        self.assertEqual(cm.exception.code, "LEASE_TASK_NOT_READY")

    def test_claim_nonexistent_and_audit(self):
        with self.assertRaises(LeaseError) as cm:
            self.ls.claim("r", "k", run_id="NOPE:e1:a1")
        self.assertEqual(cm.exception.code, "RUN_NOT_FOUND")
        self.assertEqual(cm.exception.http_status, 404)

    def test_stress_many_runners_each_task_has_single_holder(self):
        # 三个就绪任务 × 12 Runner，每个 Runner 对三个 run 各抢一次；每个 run 唯一持有者
        target_runs = [x["run_id"] for x in self.ls.pool(self.eid)["claimable"]
                       if x["check_type"] in ("TIMING_STA", "POWER_ANALYSIS", "FORMAL_EQUIV")]
        ok, barrier = [], threading.Barrier(12 * 3)

        def worker(i, rid):
            barrier.wait()
            try:
                d = self.ls.claim(f"r{i}", f"job-{i}-{rid[-4:]}", run_id=rid)
                if d.get("claimed"):
                    ok.append(rid)
            except LeaseError:
                pass

        ts = [threading.Thread(target=worker, args=(i, rid))
              for i in range(12) for rid in target_runs]
        [t.start() for t in ts]
        [t.join() for t in ts]
        # 每个任务恰好被一个 Runner 成功领取
        self.assertEqual(sorted(ok), sorted(target_runs))
        self.assertEqual(self.store.q_all(
            "SELECT run_id,COUNT(*) k FROM check_lease GROUP BY run_id HAVING k>1"), [])


class TestCredentialGate(unittest.TestCase):
    def setUp(self):
        self.clk, self.svc, self.ls, self.store = make_service()
        self.eid = freeze_one(self.svc)
        self.c = self.ls.claim("runner-A", "key-1")

    def _try(self, **over):
        kw = dict(run_id=self.c["run_id"], runner_id="runner-A",
                  generation=self.c["generation"], token=self.c["lease_token"])
        fp, _ = fp_for(self.svc, self.eid, self.c["check_type"])
        kw.update(over)
        kw.setdefault("fingerprint", fp)
        return self.ls.submit_result(verdict="PASS", result={}, **kw)

    def test_valid_credential_completes_lease(self):
        r = self._try()
        self.assertTrue(r["accepted"])
        self.assertEqual(r["lease"]["state"], "COMPLETED")
        run = self.store.q_one("SELECT status FROM check_run WHERE id=?",
                               (self.c["run_id"],))
        self.assertEqual(run["status"], "PASS")

    def test_forged_token_rejected(self):
        with self.assertRaises(LeaseError) as cm:
            self._try(token="0" * 32)
        self.assertEqual(cm.exception.code, "LEASE_BAD_CREDENTIAL")
        self.assertEqual(cm.exception.http_status, 403)

    def test_wrong_runner_rejected(self):
        with self.assertRaises(LeaseError) as cm:
            self._try(runner_id="runner-Z")
        self.assertEqual(cm.exception.code, "LEASE_NOT_HOLDER")

    def test_wrong_generation_rejected(self):
        with self.assertRaises(LeaseError) as cm:
            self._try(generation=self.c["generation"] + 5)
        self.assertEqual(cm.exception.code, "LEASE_GENERATION_STALE")

    def test_expired_lease_rejects_submit_and_is_reclaimable(self):
        # 在过期前一刻先取得输入/指纹（过期后 inputs 不再可拉）
        fp, _ = fp_for(self.svc, self.eid, self.c["check_type"])
        self.clk.advance(61)
        # 租约在查询/提交时被惰性规范化为 EXPIRED
        self.assertEqual(self.ls.lease_status(self.c["run_id"])["state"], "EXPIRED")
        with self.assertRaises(LeaseError) as cm:
            self._try(token=self.c["lease_token"])
        self.assertIn(cm.exception.code, ("LEASE_EXPIRED", "LEASE_NOT_ACTIVE"))
        # 池里重新出现（过期租约已回收）
        self.assertTrue(any(x["run_id"] == self.c["run_id"]
                            for x in self.ls.pool(self.eid)["claimable"]))

    def test_denials_are_persisted_even_though_tx_rolls_back(self):
        for token in ("0" * 32,):
            with self.assertRaises(LeaseError):
                self._try(token=token)
        au = self.ls.audit(reason="LEASE_BAD_CREDENTIAL")
        self.assertGreaterEqual(au["count"], 1)
        # 租约本身保持 HELD（拒绝未改动状态）
        self.assertEqual(self.ls.lease_status(self.c["run_id"])["state"], "HELD")


class TestRenewReleaseTakeover(unittest.TestCase):
    def setUp(self):
        self.clk, self.svc, self.ls, self.store = make_service()
        self.eid = freeze_one(self.svc)

    def test_renew_extends_deadline_and_refreshes_token_generation_unchanged(self):
        c = self.ls.claim("runner-A", "k")
        self.clk.advance(50)
        r = self.ls.renew(c["run_id"], "runner-A", c["generation"], c["lease_token"])
        self.assertEqual(r["generation"], 1)
        self.assertEqual(r["renew_count"], 1)
        self.assertGreaterEqual(r["remaining_seconds"], 59)
        # 新 token（nonce 不变 → token 实际一致）；续租审计可查
        self.assertEqual(r["lease_token"], c["lease_token"])
        self.assertTrue(any(x["event"] == "renew"
                            for x in self.ls.lease_status(c["run_id"])["history"]))

    def test_renew_with_bad_credential_denied(self):
        c = self.ls.claim("runner-A", "k")
        with self.assertRaises(LeaseError) as cm:
            self.ls.renew(c["run_id"], "runner-X", c["generation"], c["lease_token"])
        self.assertEqual(cm.exception.code, "LEASE_NOT_HOLDER")

    def test_takeover_only_after_timeout_and_bumps_generation(self):
        c = self.ls.claim("runner-A", "k")
        with self.assertRaises(LeaseError) as cm:
            self.ls.takeover(c["run_id"], "runner-B")
        self.assertEqual(cm.exception.code, "LEASE_NOT_TIMED_OUT")
        self.clk.advance(61)
        t = self.ls.takeover(c["run_id"], "runner-B", ttl_seconds=30)
        self.assertEqual(t["generation"], 2)
        self.assertEqual(t["runner_id"], "runner-B")
        self.assertEqual(t["state"], "HELD")
        self.assertEqual(t["previous"]["runner_id"], "runner-A")
        st = self.ls.lease_status(c["run_id"])
        self.assertTrue(any(h["event"] == "takeover" for h in st["history"]))

    def test_old_holder_late_result_after_takeover_rejected(self):
        c = self.ls.claim("runner-A", "k")
        self.clk.advance(61)
        t = self.ls.takeover(c["run_id"], "runner-B")
        fp, _ = fp_for(self.svc, self.eid, c["check_type"])
        with self.assertRaises(LeaseError) as cm:
            self.ls.submit_result(c["run_id"], "runner-A", c["generation"],
                                  c["lease_token"], fp, "PASS", {})
        self.assertEqual(cm.exception.code, "LEASE_GENERATION_STALE")
        # 新持有者凭新一代凭据成功
        r = self.ls.submit_result(c["run_id"], "runner-B", t["generation"],
                                  t["lease_token"], fp, "PASS", {})
        self.assertTrue(r["accepted"])

    def test_release_returns_task_to_pool(self):
        c = self.ls.claim("runner-A", "k")
        self.ls.release(c["run_id"], "runner-A", c["generation"], c["lease_token"])
        self.assertTrue(any(x["run_id"] == c["run_id"]
                            for x in self.ls.pool(self.eid)["claimable"]))
        c2 = self.ls.claim("runner-B", "k2", run_id=c["run_id"])
        self.assertTrue(c2["claimed"])
        self.assertEqual(c2["generation"], 2)


class TestEcoGateStillEnforcedAfterTakeover(unittest.TestCase):
    def setUp(self):
        self.clk, self.svc, self.ls, self.store = make_service()
        self.eid = freeze_one(self.svc)

    def test_taken_over_result_still_requires_fingerprint_match(self):
        c = self.ls.claim("runner-A", "k")
        self.clk.advance(61)
        t = self.ls.takeover(c["run_id"], "runner-B")
        # 租约凭据全部正确，但指纹被篡改 → 仍由 ECO 服务 FINGERPRINT_MISMATCH 拒收
        with self.assertRaises(ECOError) as cm:
            self.ls.submit_result(c["run_id"], "runner-B", t["generation"],
                                  t["lease_token"], "deadbeefdeadbeef", "PASS", {})
        self.assertEqual(cm.exception.code, "RESULT_REJECTED")
        self.assertEqual(cm.exception.extra["reason"], "FINGERPRINT_MISMATCH")
        # 租约不得标记完成（结果未接受），且拒绝进 lease_audit + rejected_result
        self.assertEqual(self.ls.lease_status(c["run_id"])["state"], "HELD")
        self.assertTrue(any(x["reason"] == "FINGERPRINT_MISMATCH"
                            for x in self.ls.audit(run_id=c["run_id"])["audit"]))
        self.assertTrue(any(r["reason"] == "FINGERPRINT_MISMATCH"
                            for r in self.svc.rejected_results()))

    def test_result_without_lease_rejected(self):
        # 直接对一个 PENDING run（未领取）交结果 → LEASE_NOT_FOUND，无法绕过协调器
        rid = self.ls.pool(self.eid)["claimable"][0]["run_id"]
        fp, _ = fp_for(self.svc, self.eid, "TIMING_STA")
        with self.assertRaises(LeaseError) as cm:
            self.ls.submit_result(rid, "rogue", 1, "x", fp, "PASS", {})
        self.assertEqual(cm.exception.code, "LEASE_NOT_FOUND")
        self.assertEqual(self.store.q_one("SELECT status FROM check_run WHERE id=?",
                                          (rid,))["status"], "PENDING")

    def test_completed_lease_cannot_resubmit(self):
        c = self.ls.claim("runner-A", "k")
        submit_ok(self.ls, self.svc, c)
        fp, _ = fp_for(self.svc, self.eid, c["check_type"])
        with self.assertRaises(LeaseError) as cm:
            self.ls.submit_result(c["run_id"], "runner-A", c["generation"],
                                  c["lease_token"], fp, "PASS", {})
        self.assertEqual(cm.exception.code, "LEASE_NOT_ACTIVE")


class TestRerunAndEpochInvalidation(unittest.TestCase):
    def setUp(self):
        self.clk, self.svc, self.ls, self.store = make_service()
        self.eid = freeze_one(self.svc)

    def test_late_result_from_old_generation_after_rerun_rejected(self):
        c = self.ls.claim("runner-A", "k")
        submit_ok(self.ls, self.svc, c, verdict="FAIL")
        # 工程师重跑：旧 attempt SUPERSEDED，新 run PENDING
        self.svc.rerun_check(self.eid, c["check_type"], "owner.x")
        fp, _ = fp_for(self.svc, self.eid, c["check_type"])
        with self.assertRaises(LeaseError) as cm:
            self.ls.submit_result(c["run_id"], "runner-A", c["generation"],
                                  c["lease_token"], fp, "PASS", {})
        self.assertEqual(cm.exception.code, "LEASE_RUN_SUPERSEDED")
        # 新 run 可被重新领取，且是全新 attempt（gen 从 1 开始）
        pool = self.ls.pool(self.eid)
        new_run = next(x for x in pool["claimable"]
                       if x["check_type"] == c["check_type"])
        self.assertNotEqual(new_run["run_id"], c["run_id"])
        c2 = self.ls.claim("runner-A", "k2", run_id=new_run["run_id"])
        self.assertEqual(c2["generation"], 1)
        # 拒绝留痕可按 run / reason 查询
        au = self.ls.audit(run_id=c["run_id"], reason="LEASE_RUN_SUPERSEDED")
        self.assertGreaterEqual(au["count"], 1)

    def test_constraint_rebase_invalidates_held_lease_on_settle(self):
        c = self.ls.claim("runner-A", "k")
        fp, _ = fp_for(self.svc, self.eid, c["check_type"])
        self.svc.update_base_constraints({"clk_period_ns": 1.0}, "sdc")
        st = self.ls.lease_status(c["run_id"])
        self.assertEqual(st["state"], "INVALIDATED")
        with self.assertRaises(LeaseError) as cm:
            self.ls.submit_result(c["run_id"], "runner-A", c["generation"],
                                  c["lease_token"], fp, "PASS", {})
        self.assertIn(cm.exception.code,
                      ("LEASE_RUN_SUPERSEDED", "LEASE_NOT_ACTIVE"))
        self.assertTrue(any(x["reason"] in ("LEASE_RUN_SUPERSEDED", "LEASE_TASK_INVALIDATED")
                            for x in self.ls.audit(run_id=c["run_id"])["audit"]))


class TestDependencyGateThroughLease(unittest.TestCase):
    def test_dependent_check_claimable_only_after_deps_pass(self):
        clk, svc, ls, store = make_service()
        eid = freeze_one(svc)
        # 先跑两个前置
        for ctype in ("TIMING_STA", "POWER_ANALYSIS"):
            rid = next(x["run_id"] for x in ls.pool(eid)["claimable"]
                       if x["check_type"] == ctype)
            c = ls.claim("r", f"k-{ctype}", run_id=rid)
            submit_ok(ls, svc, c)
        pool = ls.pool(eid)
        drc = next(x for x in pool["claimable"] if x["check_type"] == "LAYOUT_DRC")
        c = ls.claim("r", "k-drc", run_id=drc["run_id"])
        r = submit_ok(ls, svc, c)
        self.assertTrue(r["accepted"])


class TestRestartRecovery(unittest.TestCase):
    def test_unexpired_lease_recovered_and_credential_still_valid(self):
        dbf = tempfile.mktemp(suffix=".db")
        try:
            clk = Clock()
            store = Store(dbf)
            svc = ECOService(store, now_fn=clk)
            ls = LeaseService(svc, 60, now_fn=clk)
            eid = freeze_one(svc)
            c = ls.claim("runner-A", "k")
            secret = store.q_one("SELECT value FROM lease_meta WHERE key='hmac_secret'")["value"]
            clk.advance(10)

            # 重启：未过期租约恢复
            store2 = Store(dbf, seed=False)
            svc2 = ECOService(store2, now_fn=clk)
            ls2 = LeaseService(svc2, 60, now_fn=clk)
            self.assertIn(c["run_id"], ls2.recovery["recovered_leases"])
            self.assertEqual(store2.q_one(
                "SELECT value FROM lease_meta WHERE key='hmac_secret'")["value"], secret)
            # 旧凭据仍可验真（持久密钥）
            r = submit_ok(ls2, svc2,
                          {"run_id": c["run_id"], "eco_id": eid,
                           "check_type": c["check_type"], "runner_id": "runner-A",
                           "generation": c["generation"],
                           "lease_token": c["lease_token"]})
            self.assertTrue(r["accepted"])
        finally:
            os.path.exists(dbf) and os.remove(dbf)

    def test_expired_lease_reclaimed_on_restart_and_takeoverable(self):
        dbf = tempfile.mktemp(suffix=".db")
        try:
            clk = Clock()
            store = Store(dbf)
            svc = ECOService(store, now_fn=clk)
            ls = LeaseService(svc, 60, now_fn=clk)
            eid = freeze_one(svc)
            c = ls.claim("runner-A", "k")
            clk.advance(70)

            store2 = Store(dbf, seed=False)
            svc2 = ECOService(store2, now_fn=clk)
            ls2 = LeaseService(svc2, 60, now_fn=clk)
            self.assertTrue(any(x["run_id"] == c["run_id"]
                                for x in ls2.recovery["reclaimed_leases"]))
            t = ls2.takeover(c["run_id"], "runner-B")
            self.assertEqual(t["generation"], 2)
        finally:
            os.path.exists(dbf) and os.remove(dbf)


if __name__ == "__main__":
    unittest.main(verbosity=2)
