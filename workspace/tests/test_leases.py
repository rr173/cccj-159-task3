"""验证执行租约协调模块的不变量测试（标准库 unittest，无第三方依赖）。

运行: python3 -m unittest tests.test_leases -v
"""
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.leases import LeaseError, LeaseService
from app.runner import compute_input_fingerprint
from app.service import ECOError, ECOService
from app.store import Store

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
SHORT_TTL = 30


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)
        return self.t


def fresh(ttl=SHORT_TTL):
    clk = Clock(T0)
    store = Store(":memory:", seed=True)
    svc = ECOService(store, now_fn=clk)
    leases = LeaseService(store, svc, now_fn=clk, ttl_seconds=ttl)
    return store, svc, leases, clk


def make_frozen(svc, mods=("alu",)):
    e = svc.create_eco("租约测试", "owner.x", list(mods),
                       {m: {"netlist": f"MODULE {m}; CELL LEASE_FIX; ENDMODULE"} for m in mods})
    svc.freeze_eco(e["id"], "owner.x")
    return e["id"]


def current_run_id(svc, eco_id, check_type):
    return svc.s.q_one(
        "SELECT id FROM check_run WHERE eco_id=? AND check_type=? AND status!='SUPERSEDED'",
        (eco_id, check_type))["id"]


class TestClaim(unittest.TestCase):
    def test_claim_specific_and_atomic_payload(self):
        _, svc, leases, clk = fresh()
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        g = leases.claim("runner-a", run_id=rid, idempotency_key="k1")
        self.assertEqual(g["acquired"], True)
        self.assertEqual(g["gen"], 1)
        self.assertEqual(g["runner_id"], "runner-a")
        self.assertEqual(g["ttl_seconds"], SHORT_TTL)
        self.assertEqual(g["remaining_seconds"], SHORT_TTL)
        self.assertEqual(len(g["lease_token"]), 16)
        self.assertNotIn("token_hash", g)

    def test_concurrent_claims_only_one_wins(self):
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        winners, losers = [], []

        def claim(runner):
            try:
                leases.claim(runner, run_id=rid)
                winners.append(runner)
            except LeaseError as e:
                losers.append((runner, e.code))
        threads = [threading.Thread(target=claim, args=(f"r{i}",)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 7)
        self.assertTrue(all(code == "LEASE_HELD_BY_OTHER" for _, code in losers))

    def test_idempotent_replay_returns_same_grant(self):
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        g1 = leases.claim("runner-a", run_id=rid, idempotency_key="idem-1")
        g2 = leases.claim("runner-a", run_id=rid, idempotency_key="idem-1")
        self.assertTrue(g2["replayed"])
        self.assertEqual(g1["lease_token"], g2["lease_token"])
        self.assertEqual(g1["gen"], g2["gen"])
        # 库里只有一条租约、一条领取事件
        self.assertEqual(leases.s.q_one(
            "SELECT COUNT(*) k FROM check_lease WHERE run_id=?", (rid,))["k"], 1)
        self.assertEqual(leases.s.q_one(
            "SELECT COUNT(*) k FROM lease_event WHERE run_id=? AND event='CLAIM'",
            (rid,))["k"], 1)

    def test_idempotency_key_cannot_be_reused_by_other_runner(self):
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        leases.claim("runner-a", run_id=rid, idempotency_key="idem-x")
        with self.assertRaises(LeaseError) as cm:
            leases.claim("runner-b", run_id=rid, idempotency_key="idem-x")
        self.assertEqual(cm.exception.code, "IDEMPOTENCY_KEY_REUSED")

    def test_auto_pick_skips_held_and_picks_ready_only(self):
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        g1 = leases.claim("runner-a")           # 自动挑选按 (eco,check) 字典序
        self.assertEqual(g1["check_type"], "FORMAL_EQUIV")
        g2 = leases.claim("runner-b")
        self.assertEqual(g2["check_type"], "LINT_INFO")
        g3 = leases.claim("runner-c")
        self.assertEqual(g3["check_type"], "POWER_ANALYSIS")
        g4 = leases.claim("runner-d")
        self.assertEqual(g4["check_type"], "TIMING_STA")
        with self.assertRaises(LeaseError) as cm:
            leases.claim("runner-e")            # LAYOUT_DRC 依赖未满足，不会被挑
        self.assertEqual(cm.exception.code, "NO_CLAIMABLE_TASK")
        drc = current_run_id(svc, eid, "LAYOUT_DRC")
        with self.assertRaises(LeaseError) as cm:
            leases.claim("runner-e", run_id=drc)
        self.assertEqual(cm.exception.code, "DEPENDENCY_NOT_READY")

    def test_second_runner_blocked_until_expiry(self):
        _, svc, leases, clk = fresh(ttl=60)
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        leases.claim("runner-a", run_id=rid)
        clk.advance(seconds=30)
        with self.assertRaises(LeaseError) as cm:
            leases.claim("runner-b", run_id=rid)
        self.assertEqual(cm.exception.code, "LEASE_HELD_BY_OTHER")
        self.assertEqual(cm.exception.extra["remaining_seconds"], 30)
        clk.advance(seconds=31)
        g = leases.claim("runner-b", run_id=rid)  # 过期 → 接管成功
        self.assertTrue(g["taken_over"])
        self.assertEqual(g["gen"], 2)
        self.assertEqual(g["previous_holder"], "runner-a")


class TestComplete(unittest.TestCase):
    def _claimed_with_fp(self, svc, leases, eid, check="TIMING_STA", runner="runner-a"):
        rid = current_run_id(svc, eid, check)
        g = leases.claim(runner, run_id=rid)
        pkt = svc.check_inputs(eid, check)
        fp = compute_input_fingerprint(check, pkt["inputs"])
        return rid, g, fp

    def test_complete_with_gen_and_token_accepts(self):
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        rid, g, fp = self._claimed_with_fp(svc, leases, eid)
        out = leases.complete(rid, g["gen"], g["lease_token"], fp, "PASS",
                              {"wns_ns": 0.1}, runner_id="runner-a")
        self.assertTrue(out["accepted"])
        self.assertEqual(out["lease"]["state"], "COMPLETED")
        self.assertEqual(svc.eco_detail(eid)["gate"]["checks"][0]["status"], "PASS")

    def test_old_holder_after_takeover_is_rejected(self):
        _, svc, leases, clk = fresh(ttl=60)
        eid = make_frozen(svc)
        rid, ga, fp = self._claimed_with_fp(svc, leases, eid, runner="runner-a")
        clk.advance(seconds=61)
        gb = leases.claim("runner-b", run_id=rid)
        self.assertEqual(gb["gen"], 2)
        # 旧持有者拿旧代次+旧凭据提交 → STALE_LEASE_GEN
        with self.assertRaises(LeaseError) as cm:
            leases.complete(rid, ga["gen"], ga["lease_token"], fp, "PASS",
                            runner_id="runner-a")
        self.assertEqual(cm.exception.code, "STALE_LEASE_GEN")
        # 新持有者成功，接管后的结果仍走 ECO 指纹门禁
        ok = leases.complete(rid, gb["gen"], gb["lease_token"], fp, "PASS",
                             runner_id="runner-b")
        self.assertTrue(ok["accepted"])

    def test_forged_token_rejected(self):
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        rid, g, fp = self._claimed_with_fp(svc, leases, eid)
        with self.assertRaises(LeaseError) as cm:
            leases.complete(rid, g["gen"], "0" * 16, fp, "PASS", runner_id="runner-a")
        self.assertEqual(cm.exception.code, "LEASE_BAD_CREDENTIAL")
        # 正确代次但别人伪造凭据同样拒绝
        with self.assertRaises(LeaseError) as cm:
            leases.complete(rid, g["gen"], g["lease_token"][::-1], fp, "PASS",
                            runner_id="runner-x")
        self.assertEqual(cm.exception.code, "LEASE_BAD_CREDENTIAL")

    def test_missing_gen_or_token_rejected(self):
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        rid, g, fp = self._claimed_with_fp(svc, leases, eid)
        with self.assertRaises(LeaseError) as cm:
            leases.complete(rid, None, g["lease_token"], fp, "PASS")
        self.assertEqual(cm.exception.code, "MISSING_LEASE_GEN")
        with self.assertRaises(LeaseError) as cm:
            leases.complete(rid, g["gen"], "", fp, "PASS")
        self.assertEqual(cm.exception.code, "MISSING_LEASE_TOKEN")

    def test_expired_lease_completion_rejected(self):
        _, svc, leases, clk = fresh(ttl=30)
        eid = make_frozen(svc)
        rid, g, fp = self._claimed_with_fp(svc, leases, eid)
        clk.advance(seconds=31)
        with self.assertRaises(LeaseError) as cm:
            leases.complete(rid, g["gen"], g["lease_token"], fp, "PASS",
                            runner_id="runner-a")
        self.assertEqual(cm.exception.code, "LEASE_EXPIRED")

    def test_fingerprint_mismatch_still_rejected_after_takeover(self):
        """接管不绕过原 ECO 服务的基线指纹门禁。"""
        _, svc, leases, clk = fresh(ttl=30)
        eid = make_frozen(svc)
        rid, ga, fp = self._claimed_with_fp(svc, leases, eid)
        clk.advance(seconds=31)
        gb = leases.claim("runner-b", run_id=rid)
        bad_fp = ("deadbeef" + fp)[:16]
        self.assertNotEqual(bad_fp, fp)
        with self.assertRaises(LeaseError) as cm:
            leases.complete(rid, gb["gen"], gb["lease_token"], bad_fp,
                            "PASS", runner_id="runner-b")
        self.assertEqual(cm.exception.code, "FINGERPRINT_MISMATCH")
        # ECO 侧 rejected_result 与租约侧 lease_event 双侧留痕
        rej = svc.rejected_results()
        self.assertTrue(any(r["reason"] == "FINGERPRINT_MISMATCH" and r["run_id"] == rid
                            for r in rej))
        audit = leases.audit_events(run_id=rid, reason="FINGERPRINT_MISMATCH")["events"]
        self.assertTrue(audit)

    def test_dependency_blocked_result_rejected_even_with_valid_lease(self):
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        drc = current_run_id(svc, eid, "LAYOUT_DRC")
        # 直接在租约表插一条对 BLOCKED run 的租约（绕过领取），
        # 完成时 ECO 依赖门禁仍应拒绝，证明租约层无法绕过 DEPENDENCY_BLOCKED
        import hashlib
        from app.leases import _derive_token, _hash_token
        tok = _derive_token(leases._secret, drc, 1, "runner-z")
        with leases.s.tx() as c:
            c.execute("INSERT INTO check_lease(run_id,eco_id,check_type,gen,runner_id,state,"
                      "token_hash,acquired_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
                      (drc, eid, "LAYOUT_DRC", 1, "runner-z", "HELD", _hash_token(tok),
                       "2026-10-01T12:00:00+00:00", "2026-10-01T13:00:00+00:00"))
        pkt = svc.check_inputs(eid, "LAYOUT_DRC")
        fp = compute_input_fingerprint("LAYOUT_DRC", pkt["inputs"])
        with self.assertRaises(LeaseError) as cm:
            leases.complete(drc, 1, tok, fp, "PASS", runner_id="runner-z")
        self.assertEqual(cm.exception.code, "DEPENDENCY_BLOCKED")

    def test_rerun_old_generation_late_result_rejected(self):
        """重跑产生新 run；旧持有者用旧租约代次回传迟到结果必须被拒。"""
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        rid, g, fp = self._claimed_with_fp(svc, leases, eid)
        leases.complete(rid, g["gen"], g["lease_token"], fp, "FAIL", runner_id="runner-a")
        svc.rerun_check(eid, "TIMING_STA", "owner.x")
        # 旧 run 已 SUPERSEDED、旧租约 INVALIDATED：旧凭据旧代次迟到 → STALE_SUPERSEDED
        with self.assertRaises(LeaseError) as cm:
            leases.complete(rid, g["gen"], g["lease_token"], fp, "PASS",
                            runner_id="runner-a")
        self.assertEqual(cm.exception.code, "STALE_SUPERSEDED")
        # 新 run 可被重新领取并通过
        new_rid = current_run_id(svc, eid, "TIMING_STA")
        g2 = leases.claim("runner-b", run_id=new_rid)
        self.assertEqual(g2["gen"], 1)
        ok = leases.complete(new_rid, 1, g2["lease_token"], fp, "PASS", runner_id="runner-b")
        self.assertTrue(ok["accepted"])

    def test_refreeze_invalidates_held_lease(self):
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        rid, g, fp = self._claimed_with_fp(svc, leases, eid)
        svc.update_base_constraints({"clk_period_ns": 1.0}, "sdc")
        svc.freeze_eco(eid, "owner.x")  # refreeze, epoch+1
        with self.assertRaises(LeaseError) as cm:
            leases.complete(rid, g["gen"], g["lease_token"], fp, "PASS",
                            runner_id="runner-a")
        self.assertEqual(cm.exception.code, "STALE_SUPERSEDED")


class TestRenewReleaseTakeover(unittest.TestCase):
    def test_renew_extends_ttl(self):
        _, svc, leases, clk = fresh(ttl=60)
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        g = leases.claim("runner-a", run_id=rid)
        clk.advance(seconds=50)
        r = leases.renew(rid, 1, g["lease_token"], "runner-a", ttl_seconds=120)
        self.assertEqual(r["remaining_seconds"], 120)
        clk.advance(seconds=100)
        # 未续租的话 110 秒已过期；续租后仍有效，可完成
        pkt = svc.check_inputs(eid, "TIMING_STA")
        fp = compute_input_fingerprint("TIMING_STA", pkt["inputs"])
        out = leases.complete(rid, 1, g["lease_token"], fp, "PASS", runner_id="runner-a")
        self.assertTrue(out["accepted"])

    def test_renew_with_old_gen_after_takeover_rejected(self):
        _, svc, leases, clk = fresh(ttl=30)
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        ga = leases.claim("runner-a", run_id=rid)
        clk.advance(seconds=31)
        gb = leases.claim("runner-b", run_id=rid)
        with self.assertRaises(LeaseError) as cm:
            leases.renew(rid, ga["gen"], ga["lease_token"], "runner-a")
        self.assertEqual(cm.exception.code, "STALE_LEASE_GEN")
        # 新持有者续租成功
        r = leases.renew(rid, gb["gen"], gb["lease_token"], "runner-b", ttl_seconds=60)
        self.assertEqual(r["gen"], 2)

    def test_release_returns_task_to_pool(self):
        _, svc, leases, _ = fresh()
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        g = leases.claim("runner-a", run_id=rid)
        leases.release(rid, 1, g["lease_token"], "runner-a", note="机器维护")
        # 无需等待过期，立即可被他人领取
        g2 = leases.claim("runner-b", run_id=rid)
        self.assertFalse(g2.get("taken_over"))
        self.assertEqual(g2["gen"], 2)
        self.assertEqual(g2["runner_id"], "runner-b")

    def test_explicit_takeover_requires_expiry(self):
        _, svc, leases, clk = fresh(ttl=60)
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        leases.claim("runner-a", run_id=rid)
        with self.assertRaises(LeaseError) as cm:
            leases.takeover(rid, "runner-b")
        self.assertEqual(cm.exception.code, "LEASE_NOT_EXPIRED")
        clk.advance(seconds=61)
        gb = leases.takeover(rid, "runner-b")
        self.assertEqual(gb["gen"], 2)
        self.assertEqual(gb["previous_holder"], "runner-a")


class TestRecovery(unittest.TestCase):
    def test_restart_restores_unexpired_and_reaps_expired(self):
        import tempfile
        tmpdir = tempfile.mkdtemp()
        path = str(Path(tmpdir) / "lease.db")
        clk = Clock(T0)
        store = Store(path)
        svc = ECOService(store, now_fn=clk)
        leases = LeaseService(store, svc, now_fn=clk, ttl_seconds=60)
        eid = make_frozen(svc)
        rid_a = current_run_id(svc, eid, "TIMING_STA")
        rid_b = current_run_id(svc, eid, "POWER_ANALYSIS")
        ga = leases.claim("runner-a", run_id=rid_a, ttl_seconds=30)   # 12:00:30 过期
        gb = leases.claim("runner-b", run_id=rid_b, ttl_seconds=120)  # 12:02:00 过期
        secret = leases._secret
        del leases, svc, store
        # 时钟前进 61 秒后“重启”：a 过期应回收，b 未过期应恢复（剩余 59 秒）
        clk2 = Clock(T0 + timedelta(seconds=61))
        store2 = Store(path)
        svc2 = ECOService(store2, now_fn=clk2)
        leases2 = LeaseService(store2, svc2, now_fn=clk2, ttl_seconds=60)
        rec = leases2.recover()
        self.assertIn(rid_a, rec["recovered_expired"])
        self.assertEqual(rec["restored_held"], 1)
        # 密钥落盘：未过期租约的旧凭据仍可校验并完成
        self.assertEqual(leases2._secret, secret)
        held = leases2.lease_board()["held"]
        self.assertEqual([h["run_id"] for h in held], [rid_b])
        self.assertEqual(held[0]["remaining_seconds"], 59)
        pkt = svc2.check_inputs(eid, "POWER_ANALYSIS")
        fp = compute_input_fingerprint("POWER_ANALYSIS", pkt["inputs"])
        out = leases2.complete(rid_b, gb["gen"], gb["lease_token"], fp, "PASS",
                               runner_id="runner-b")
        self.assertTrue(out["accepted"])
        # 过期租约可被接管，代次 +1
        gt = leases2.takeover(rid_a, "runner-c")
        self.assertEqual(gt["gen"], 2)

    def test_board_shows_pending_held_takeover_and_history(self):
        _, svc, leases, clk = fresh(ttl=30)
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        leases.claim("runner-a", run_id=rid)
        b = leases.lease_board()
        self.assertTrue(any(c["run_id"] != rid for c in b["claimable"]))
        held = next(h for h in b["held"] if h["run_id"] == rid)
        self.assertEqual(held["runner_id"], "runner-a")
        self.assertEqual(held["remaining_seconds"], SHORT_TTL)
        clk.advance(seconds=31)
        b2 = leases.lease_board()
        self.assertTrue(any(t["run_id"] == rid for t in b2["takeover_available"]))
        leases.takeover(rid, "runner-b")
        b3 = leases.lease_board()
        hist = [h for h in b3["takeover_history"] if h["run_id"] == rid]
        self.assertTrue(any(h["event"] == "TAKEOVER" for h in hist))

    def test_audit_query_filters_by_reason(self):
        _, svc, leases, clk = fresh(ttl=30)
        eid = make_frozen(svc)
        rid = current_run_id(svc, eid, "TIMING_STA")
        ga = leases.claim("runner-a", run_id=rid)
        clk.advance(seconds=31)
        with self.assertRaises(LeaseError):
            leases.complete(rid, ga["gen"], ga["lease_token"], "x" * 16, "PASS",
                            runner_id="runner-a")
        ev = leases.audit_events(reason="LEASE_EXPIRED")["events"]
        self.assertTrue(ev and all(e["detail"].get("reason") == "LEASE_EXPIRED" for e in ev))
        ev2 = leases.audit_events(run_id=rid)["events"]
        self.assertTrue(all(e["run_id"] == rid for e in ev2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
