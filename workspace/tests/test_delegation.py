"""临时代理签核不变量测试（标准库 unittest）。

运行: python3 -m unittest tests.test_delegation -v
"""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.runner import run_all_pending
from app.service import ECOError, ECOService, ROLE_METHOD, ROLE_TIMING
from app.store import Store

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)
        return self.t


def fresh():
    clk = Clock(T0)
    svc = ECOService(Store(":memory:"), now_fn=clk)
    return svc, clk


def frozen_green(svc):
    e = svc.create_eco("代理测试", "owner.x", ["alu"],
                       {"alu": {"netlist": "MODULE alu; CELL DELEG_FIX; ENDMODULE"}})
    svc.freeze_eco(e["id"], "owner.x")
    run_all_pending(svc, e["id"])
    return e["id"]


def iso(t):
    return t.isoformat(timespec="seconds")


class TestDelegationLifecycle(unittest.TestCase):
    def test_grant_pending_then_active_then_expired(self):
        svc, clk = fresh()
        d = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                  iso(clk.t + timedelta(hours=1)),
                                  iso(clk.t + timedelta(days=1)),
                                  "admin.chen", principal_user="timing.zhang",
                                  note="休假代理")
        self.assertEqual(d["state"], "PENDING")
        self.assertFalse(d["active"])
        self.assertEqual([x["id"] for x in svc.list_delegations()], [d["id"]])
        cs = svc.current_signers()["roles"][ROLE_TIMING]
        self.assertEqual(cs["delegate_users"], [])  # 未生效不可签
        clk.advance(hours=2)
        self.assertEqual(svc.get_delegation(d["id"])["state"], "ACTIVE")
        cs = svc.current_signers()["roles"][ROLE_TIMING]
        self.assertEqual(cs["delegate_users"], ["backup.wang"])
        self.assertEqual(cs["delegates"][0]["principal_user"], "timing.zhang")
        clk.advance(days=1)
        self.assertEqual(svc.get_delegation(d["id"])["state"], "EXPIRED")
        self.assertEqual(svc.current_signers()["roles"][ROLE_TIMING]["delegate_users"], [])

    def test_duplicate_submit_is_idempotent(self):
        svc, clk = fresh()
        kw = dict(valid_from=iso(clk.t - timedelta(hours=1)),
                  valid_until=iso(clk.t + timedelta(days=1)))
        d1 = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                   granted_by="admin.chen", **kw)
        self.assertFalse(d1["deduped"])
        d2 = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                   granted_by="admin.chen", **kw)
        self.assertTrue(d2["deduped"])
        self.assertEqual(d1["id"], d2["id"])
        active = [d for d in svc.list_delegations()]
        self.assertEqual(len(active), 1)

    def test_overlapping_window_rejected(self):
        svc, clk = fresh()
        svc.create_delegation(ROLE_TIMING, "backup.wang",
                              iso(clk.t - timedelta(hours=1)),
                              iso(clk.t + timedelta(days=1)), "admin")
        with self.assertRaises(ECOError) as cm:
            svc.create_delegation(ROLE_TIMING, "backup.wang",
                                  iso(clk.t + timedelta(hours=2)),
                                  iso(clk.t + timedelta(days=2)), "admin")
        self.assertEqual(cm.exception.code, "DELEGATION_OVERLAP")
        # 不重叠（首尾相接的半开区间）允许
        svc.create_delegation(ROLE_TIMING, "backup.wang",
                              iso(clk.t + timedelta(days=1)),
                              iso(clk.t + timedelta(days=2)), "admin")
        # 不同代理人不冲突
        svc.create_delegation(ROLE_TIMING, "other.zhao",
                              iso(clk.t - timedelta(hours=1)),
                              iso(clk.t + timedelta(days=1)), "admin")

    def test_bad_window_and_role_rejected(self):
        svc, clk = fresh()
        with self.assertRaises(ECOError) as cm:
            svc.create_delegation("BOSS", "x", iso(clk.t), iso(clk.t + timedelta(days=1)), "a")
        self.assertEqual(cm.exception.code, "BAD_ROLE")
        with self.assertRaises(ECOError):
            svc.create_delegation(ROLE_TIMING, "x", iso(clk.t + timedelta(days=1)),
                                  iso(clk.t), "a")

    def test_revoke_takes_effect_immediately_and_is_idempotent(self):
        svc, clk = fresh()
        d = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                  iso(clk.t - timedelta(hours=1)),
                                  iso(clk.t + timedelta(days=1)), "admin")
        r1 = svc.revoke_delegation(d["id"], "admin.chen")
        self.assertEqual(r1["state"], "REVOKED")
        self.assertFalse(r1.get("deduped"))
        r2 = svc.revoke_delegation(d["id"], "admin.chen")
        self.assertTrue(r2["deduped"])
        self.assertEqual(r2["id"], d["id"])
        with self.assertRaises(ECOError):
            svc.revoke_delegation(99999, "admin")
        self.assertEqual(svc.current_signers()["roles"][ROLE_TIMING]["delegate_users"], [])


class TestDelegatedSignoffAuthorization(unittest.TestCase):
    def test_delegate_can_sign_with_explicit_id_and_chain_is_kept(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        d = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                  iso(clk.t - timedelta(hours=1)),
                                  iso(clk.t + timedelta(days=1)), "admin.chen",
                                  principal_user="timing.zhang")
        detail = svc.signoff(eid, ROLE_TIMING, "backup.wang", delegation_id=d["id"])
        sig = next(s for s in detail["gate"]["valid_signoffs"] if s["role"] == ROLE_TIMING)
        self.assertEqual(sig["user"], "backup.wang")
        self.assertEqual(sig["signoff_kind"], "DELEGATE")
        self.assertEqual(sig["delegation_id"], d["id"])
        self.assertEqual(sig["auth_chain"]["principal_user"], "timing.zhang")
        self.assertEqual(sig["auth_chain"]["granted_by"], "admin.chen")
        self.assertEqual(sig["auth_chain"]["checked_at"], iso(clk.t))

    def test_signoff_before_valid_from_rejected(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        d = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                  iso(clk.t + timedelta(hours=1)),
                                  iso(clk.t + timedelta(days=1)), "admin")
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eid, ROLE_TIMING, "backup.wang", delegation_id=d["id"])
        self.assertEqual(cm.exception.code, "DELEGATION_NOT_STARTED")
        self.assertEqual(svc.eco_detail(eid)["gate"]["valid_signoffs"], [])

    def test_signoff_after_expiry_rejected(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        d = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                  iso(clk.t - timedelta(days=2)),
                                  iso(clk.t - timedelta(days=1)), "admin")
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eid, ROLE_TIMING, "backup.wang", delegation_id=d["id"])
        self.assertEqual(cm.exception.code, "DELEGATION_EXPIRED")
        # 恰好等于失效时刻也拒绝（半开区间）
        clk2 = Clock(datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc))
        svc2 = ECOService(Store(":memory:"), now_fn=clk2)
        e2 = frozen_green(svc2)
        d2 = svc2.create_delegation(ROLE_TIMING, "b",
                                    "2026-10-01T12:00:00+00:00",
                                    "2026-10-02T12:00:00+00:00", "admin")
        with self.assertRaises(ECOError) as cm:
            svc2.signoff(e2, ROLE_TIMING, "b", delegation_id=d2["id"])
        self.assertEqual(cm.exception.code, "DELEGATION_EXPIRED")

    def test_revoked_delegation_rejected(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        d = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                  iso(clk.t - timedelta(hours=1)),
                                  iso(clk.t + timedelta(days=1)), "admin")
        svc.revoke_delegation(d["id"], "admin")
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eid, ROLE_TIMING, "backup.wang", delegation_id=d["id"])
        self.assertEqual(cm.exception.code, "DELEGATION_REVOKED")
        self.assertEqual(svc.eco_detail(eid)["gate"]["valid_signoffs"], [])

    def test_role_and_user_mismatch_rejected(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        d = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                  iso(clk.t - timedelta(hours=1)),
                                  iso(clk.t + timedelta(days=1)), "admin")
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eid, ROLE_METHOD, "backup.wang", delegation_id=d["id"])
        self.assertEqual(cm.exception.code, "DELEGATION_ROLE_MISMATCH")
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eid, ROLE_TIMING, "someone.else", delegation_id=d["id"])
        self.assertEqual(cm.exception.code, "DELEGATION_USER_MISMATCH")
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eid, ROLE_TIMING, "backup.wang", delegation_id=99999)
        self.assertEqual(cm.exception.code, "DELEGATION_NOT_FOUND")

    def test_auto_detect_delegation_without_id(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        svc.create_delegation(ROLE_METHOD, "backup.wang",
                              iso(clk.t - timedelta(hours=1)),
                              iso(clk.t + timedelta(days=1)), "admin",
                              principal_user="method.li")
        detail = svc.signoff(eid, ROLE_METHOD, "backup.wang")  # 不带 delegation_id
        sig = next(s for s in detail["gate"]["valid_signoffs"] if s["role"] == ROLE_METHOD)
        self.assertEqual(sig["signoff_kind"], "DELEGATE")

    def test_direct_signoff_without_delegation(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        detail = svc.signoff(eid, ROLE_TIMING, "timing.zhang")
        sig = detail["gate"]["valid_signoffs"][0]
        self.assertEqual(sig["signoff_kind"], "DIRECT")
        self.assertIsNone(sig["delegation_id"])

    def test_same_natural_person_cannot_hold_both_roles_even_delegated(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        svc.create_delegation(ROLE_TIMING, "backup.wang",
                              iso(clk.t - timedelta(hours=1)),
                              iso(clk.t + timedelta(days=1)), "admin")
        svc.create_delegation(ROLE_METHOD, "backup.wang",
                              iso(clk.t - timedelta(hours=1)),
                              iso(clk.t + timedelta(days=1)), "admin")
        svc.signoff(eid, ROLE_TIMING, "backup.wang")
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eid, ROLE_METHOD, "backup.wang")
        self.assertEqual(cm.exception.code, "DUAL_ROLE_CONFLICT")
        # 代理与直签混合也禁止：先代理时序，本人直签方法学同一人
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eid, ROLE_METHOD, "backup.wang", delegation_id=None)
        self.assertEqual(cm.exception.code, "DUAL_ROLE_CONFLICT")

    def test_distinct_delegates_complete_dual_role_and_release(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        dt = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                   iso(clk.t - timedelta(hours=1)),
                                   iso(clk.t + timedelta(days=1)), "admin")
        dm = svc.create_delegation(ROLE_METHOD, "proxy.qian",
                                   iso(clk.t - timedelta(hours=1)),
                                   iso(clk.t + timedelta(days=1)), "admin")
        svc.signoff(eid, ROLE_TIMING, "backup.wang", delegation_id=dt["id"])
        svc.signoff(eid, ROLE_METHOD, "proxy.qian", delegation_id=dm["id"])
        rel = svc.release_start(eid, "owner.x")
        self.assertEqual(rel["new_baseline_id"], "B-R1")
        pkg = svc.diff_package("B-R0", "B-R1")
        kinds = {s["role"]: s["signoff_kind"] for s in pkg["verification"]["signoffs"]}
        self.assertEqual(kinds, {ROLE_TIMING: "DELEGATE", ROLE_METHOD: "DELEGATE"})
        self.assertTrue(pkg["verification"]["dual_role_distinct_users"])
        self.assertTrue(all(s["auth_chain"]["kind"] == "DELEGATE"
                            for s in pkg["verification"]["signoffs"]))

    def test_revocation_mid_flight_blocks_only_unsigned_role(self):
        """先完成一个角色，撤销另一角色的代理 → 第二签被拒；已完成签核保留。"""
        svc, clk = fresh()
        eid = frozen_green(svc)
        svc.signoff(eid, ROLE_TIMING, "timing.zhang")
        dm = svc.create_delegation(ROLE_METHOD, "backup.wang",
                                   iso(clk.t - timedelta(hours=1)),
                                   iso(clk.t + timedelta(days=1)), "admin")
        svc.revoke_delegation(dm["id"], "admin.chen")
        with self.assertRaises(ECOError):
            svc.signoff(eid, ROLE_METHOD, "backup.wang", delegation_id=dm["id"])
        with self.assertRaises(ECOError):
            svc.release_start(eid, "owner.x")
        self.assertEqual(svc.eco_detail(eid)["status"], "FROZEN")


class TestSignoffHistoryAndAudit(unittest.TestCase):
    def test_completed_signoffs_keep_chain_but_refreeze_invalidates(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        d = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                  iso(clk.t - timedelta(hours=1)),
                                  iso(clk.t + timedelta(days=30)), "admin",
                                  principal_user="timing.zhang")
        svc.signoff(eid, ROLE_TIMING, "backup.wang", delegation_id=d["id"])
        # 基础约束刷新 → REBASE_REQUIRED，旧签核失效但记录保留
        svc.update_base_constraints({"clk_period_ns": 1.05}, "sdc.owner")
        detail = svc.eco_detail(eid)
        self.assertEqual(detail["gate"]["valid_signoffs"], [])
        all_sigs = detail["gate"]["signoffs"]
        self.assertEqual(len(all_sigs), 1)
        old = all_sigs[0]
        self.assertIsNotNone(old["voided_at"])
        self.assertEqual(old["signoff_kind"], "DELEGATE")
        self.assertEqual(old["auth_chain"]["principal_user"], "timing.zhang")
        self.assertEqual(old["delegation_id"], d["id"])
        # 重新冻结后新纪元无旧签核，可由代理人重新签（授权仍有效）
        svc.freeze_eco(eid, "owner.x")
        run_all_pending(svc, eid)
        detail = svc.eco_detail(eid)
        self.assertEqual(detail["freeze_epoch"], 2)
        svc.signoff(eid, ROLE_TIMING, "backup.wang", delegation_id=d["id"])
        valid = svc.eco_detail(eid)["gate"]["valid_signoffs"]
        self.assertEqual(len(valid), 1)
        self.assertEqual(valid[0]["epoch"], 2)

    def test_denied_signoffs_are_audited(self):
        svc, clk = fresh()
        eid = frozen_green(svc)
        d = svc.create_delegation(ROLE_TIMING, "backup.wang",
                                  iso(clk.t + timedelta(hours=1)),
                                  iso(clk.t + timedelta(days=1)), "admin")
        for _ in range(1):
            with self.assertRaises(ECOError):
                svc.signoff(eid, ROLE_TIMING, "backup.wang", delegation_id=d["id"])
        svc.revoke_delegation(d["id"], "admin")
        with self.assertRaises(ECOError):
            svc.signoff(eid, ROLE_TIMING, "backup.wang", delegation_id=d["id"])
        wb = svc.workbench()
        actions = [a["action"] for a in wb["recent_audit"]]
        self.assertIn("signoff.denied", actions)
        self.assertIn("delegation.grant", actions)
        self.assertIn("delegation.revoke", actions)

    def test_workbench_exposes_delegations_and_current_signers(self):
        svc, clk = fresh()
        svc.create_delegation(ROLE_TIMING, "backup.wang",
                              iso(clk.t - timedelta(hours=1)),
                              iso(clk.t + timedelta(days=1)), "admin.chen",
                              principal_user="timing.zhang")
        wb = svc.workbench()
        self.assertEqual(len(wb["delegations"]), 1)
        cs = wb["current_signers"]
        self.assertEqual(set(cs["roles"]), {ROLE_TIMING, ROLE_METHOD})
        t = cs["roles"][ROLE_TIMING]
        self.assertEqual(t["delegates"][0]["user"], "backup.wang")
        self.assertIn("代理", t["delegates"][0]["source"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
