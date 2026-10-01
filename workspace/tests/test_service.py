"""核心不变量单元测试（标准库 unittest，无第三方依赖）。

运行: python3 -m unittest discover -s tests -v
"""
import sys
import unittest
import zipfile
import io
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.runner import compute_input_fingerprint, run_all_pending, submit
from app.service import (ECOError, ECOService, ROLE_METHOD, ROLE_TIMING,
                         snapshot_fingerprint, fp_json)
from app.store import Store, CHECKS


def fresh():
    return ECOService(Store(":memory:"))


def make_eco(svc, mods=("alu",), eco_id_n=0, edits=None):
    if edits is None:
        edits = {m: {"netlist": f"MODULE {m}; CELL ECO_NEW u_fix; ENDMODULE"} for m in mods}
    e = svc.create_eco(f"测试-{mods}", "owner.x", list(mods), edits)
    return e["id"]


def green_release(svc, eco_id, u1="timing.zhang", u2="method.li"):
    run_all_pending(svc, eco_id)
    svc.signoff(eco_id, ROLE_TIMING, u1)
    svc.signoff(eco_id, ROLE_METHOD, u2)
    return svc.release_start(eco_id, "owner.x")


class TestFreezeAndFingerprint(unittest.TestCase):
    def test_freeze_creates_immutable_snapshot(self):
        svc = fresh()
        eid = make_eco(svc)
        d1 = svc.freeze_eco(eid, "owner.x")
        fp1 = d1["fingerprint"]
        snap1 = d1["snapshot"]
        self.assertEqual(d1["status"], "FROZEN")
        self.assertEqual(snap1["affected_modules"], ["alu"])
        self.assertIn("verification_matrix", snap1)
        self.assertEqual(len(snap1["verification_matrix"]), len(CHECKS))
        # 锁已获取
        self.assertTrue(any(l["eco_id"] == eid for l in svc.workbench()["locks"]))

    def test_run_fingerprint_scoped(self):
        svc = fresh()
        eid = make_eco(svc)
        svc.freeze_eco(eid, "owner.x")
        pkt = svc.check_inputs(eid, "TIMING_STA")
        # Runner 端独立计算应一致
        self.assertEqual(compute_input_fingerprint("TIMING_STA", pkt["inputs"]),
                         pkt["expected_fingerprint"])
        # FORMAL 作用域不含 sdc：同样输入结构不同指纹（一般不相等，验证作用域隔离）
        pkt2 = svc.check_inputs(eid, "FORMAL_EQUIV")
        self.assertIn("constraints", pkt["inputs"])
        self.assertNotIn("constraints", pkt2["inputs"])

    def test_edit_out_of_scope_rejected(self):
        svc = fresh()
        with self.assertRaises(ECOError) as cm:
            svc.create_eco("越界", "o", ["alu"], {"core": {"netlist": "x"}})
        self.assertEqual(cm.exception.code, "EDIT_OUT_OF_SCOPE")


class TestDependencyGraph(unittest.TestCase):
    def test_blocked_until_deps_pass(self):
        svc = fresh()
        eid = make_eco(svc)
        svc.freeze_eco(eid, "owner.x")
        d = svc.eco_detail(eid)
        st = {c["type"]: c["status"] for c in d["gate"]["checks"]}
        self.assertEqual(st["LAYOUT_DRC"], "BLOCKED")
        # 前置失败 → 重跑通过后 DRC 才解锁
        run_all_pending(svc, eid, fail=("TIMING_STA",))
        d = svc.eco_detail(eid)
        st = {c["type"]: c["status"] for c in d["gate"]["checks"]}
        self.assertEqual(st["TIMING_STA"], "FAIL")
        self.assertEqual(st["LAYOUT_DRC"], "BLOCKED")
        svc.rerun_check(eid, "TIMING_STA", "owner.x")
        run_all_pending(svc, eid)
        d = svc.eco_detail(eid)
        st = {c["type"]: c["status"] for c in d["gate"]["checks"]}
        self.assertEqual(st["LAYOUT_DRC"], "PASS")

    def test_submit_blocked_rejected(self):
        svc = fresh()
        eid = make_eco(svc)
        svc.freeze_eco(eid, "owner.x")
        pkt = svc.check_inputs(eid, "LAYOUT_DRC")
        fp = compute_input_fingerprint("LAYOUT_DRC", pkt["inputs"])
        with self.assertRaises(ECOError) as cm:
            svc.submit_result(pkt["run_id"], fp, "PASS", {}, "r")
        self.assertEqual(cm.exception.extra["reason"], "DEPENDENCY_BLOCKED")

    def test_non_required_fail_does_not_block_gate(self):
        svc = fresh()
        eid = make_eco(svc)
        svc.freeze_eco(eid, "owner.x")
        run_all_pending(svc, eid)
        # LINT 非必需：直接构造 FAIL 不影响 green（其默认 PASS；手工置 FAIL）
        svc.s.conn.execute(
            "UPDATE check_run SET status='FAIL' WHERE eco_id=? AND check_type='LINT_INFO'",
            (eid,))
        d = svc.eco_detail(eid)
        self.assertTrue(d["gate"]["green"])


class TestStaleAndFingerprintGuard(unittest.TestCase):
    def test_late_result_after_supersede_rejected(self):
        svc = fresh()
        eid = make_eco(svc, mods=("l2c",))
        svc.freeze_eco(eid, "o")
        run_all_pending(svc, eid)
        pkt = svc.check_inputs(eid, "TIMING_STA")
        old_run, old_fp = pkt["run_id"], pkt["expected_fingerprint"]
        svc.update_base_constraints({"clk_period_ns": 1.10}, "sdc")
        with self.assertRaises(ECOError) as cm:
            svc.submit_result(old_run, old_fp, "PASS", {"late": True}, "late-runner")
        self.assertEqual(cm.exception.extra["reason"], "STALE_SUPERSEDED")
        # 留痕
        reasons = [r["reason"] for r in svc.rejected_results()]
        self.assertIn("STALE_SUPERSEDED", reasons)
        self.assertIn("BASE_CONSTRAINT_CHANGED", reasons)

    def test_wrong_fingerprint_rejected(self):
        svc = fresh()
        eid = make_eco(svc)
        svc.freeze_eco(eid, "o")
        pkt = svc.check_inputs(eid, "TIMING_STA")
        with self.assertRaises(ECOError) as cm:
            svc.submit_result(pkt["run_id"], "0" * 16, "PASS", {}, "evil")
        self.assertEqual(cm.exception.extra["reason"], "FINGERPRINT_MISMATCH")

    def test_double_submit_rejected(self):
        svc = fresh()
        eid = make_eco(svc)
        svc.freeze_eco(eid, "o")
        ok, _ = submit(svc, eid, "TIMING_STA")
        self.assertTrue(ok)
        ok, info = submit(svc, eid, "TIMING_STA")
        self.assertFalse(ok)
        self.assertEqual(info["reason"], "ALREADY_SUBMITTED")

    def test_constraint_bump_voids_signoffs_and_requires_rebase(self):
        svc = fresh()
        eid = make_eco(svc, mods=("l2c",))
        svc.freeze_eco(eid, "o")
        run_all_pending(svc, eid)
        svc.signoff(eid, ROLE_TIMING, "timing.zhang")
        svc.update_base_constraints({"clk_period_ns": 1.05}, "sdc")
        d = svc.eco_detail(eid)
        self.assertEqual(d["status"], "REBASE_REQUIRED")
        self.assertEqual(d["gate"]["valid_signoffs"], [])
        with self.assertRaises(ECOError):
            svc.signoff(eid, ROLE_METHOD, "method.li")
        # rebase 后旧结果不再满足
        svc.freeze_eco(eid, "o")
        d = svc.eco_detail(eid)
        self.assertFalse(d["gate"]["green"])
        self.assertEqual(d["freeze_epoch"], 2)
        for c in d["gate"]["checks"]:
            self.assertIn(c["status"], ("PENDING", "BLOCKED"))


class TestOverlapQueueAndMerge(unittest.TestCase):
    def test_overlapping_eco_queues(self):
        svc = fresh()
        a = make_eco(svc, mods=("noc", "core"))
        svc.freeze_eco(a, "a")
        b = make_eco(svc, mods=("noc",))
        bq = svc.freeze_eco(b, "b")
        self.assertEqual(bq["status"], "QUEUED")
        self.assertEqual([q["module"] for q in bq["queue"]], ["noc"])

    def test_non_overlapping_can_freeze_in_parallel(self):
        svc = fresh()
        a = make_eco(svc, mods=("alu",))
        svc.freeze_eco(a, "a")
        b = make_eco(svc, mods=("l2c",))
        d = svc.freeze_eco(b, "b")
        self.assertEqual(d["status"], "FROZEN")

    def test_merge_adjudication_expands_and_invalidates(self):
        svc = fresh()
        a = make_eco(svc, mods=("noc",))
        svc.freeze_eco(a, "a")
        run_all_pending(svc, a)
        svc.signoff(a, ROLE_TIMING, "timing.zhang")
        b = svc.create_eco("QoS", "b", ["noc", "l2c"],
                           {"noc": {"netlist": "MODULE noc; QOS; ENDMODULE"},
                            "l2c": {"netlist": "MODULE l2c; CELL RAMB u_tag(DEPTH=512); ENDMODULE"}})
        b = b["id"]
        svc.freeze_eco(b, "b")
        m = svc.adjudicate_merge(b, a, "ccb", {"noc": "TARGET_WINS"})
        self.assertEqual(m["affected_modules"], ["l2c", "noc"])
        self.assertEqual(m["freeze_epoch"], 2)
        # 原 noc 编辑保留 TARGET（占用方），新增 l2c 来自 source
        self.assertNotIn("QOS", m["edits"]["noc"]["netlist"])
        self.assertIn("512", m["edits"]["l2c"]["netlist"])
        # 旧结果与签核作废
        self.assertEqual(m["gate"]["valid_signoffs"], [])
        self.assertFalse(m["gate"]["green"])
        # 源单 MERGED，锁释放
        self.assertEqual(svc.eco_detail(b)["status"], "MERGED")
        locks = {l["module"]: l["eco_id"] for l in svc.workbench()["locks"]}
        self.assertEqual(locks.get("l2c"), a)

    def test_merge_without_block_relation_rejected(self):
        svc = fresh()
        a = make_eco(svc, mods=("alu",))
        svc.freeze_eco(a, "a")
        b = make_eco(svc, mods=("l2c",))
        svc.freeze_eco(b, "b")  # 不冲突，FROZEN
        with self.assertRaises(ECOError) as cm:
            svc.adjudicate_merge(b, a, "ccb")
        self.assertEqual(cm.exception.code, "SOURCE_NOT_QUEUED")

    def test_abort_releases_locks_and_promotes(self):
        svc = fresh()
        a = make_eco(svc, mods=("noc",))
        svc.freeze_eco(a, "a")
        b = make_eco(svc, mods=("noc",))
        self.assertEqual(svc.freeze_eco(b, "b")["status"], "QUEUED")
        svc.abort_eco(a, "a")
        d = svc.eco_detail(b)
        self.assertEqual(d["status"], "REBASE_REQUIRED")
        # 释放后可重新冻结
        self.assertEqual(svc.freeze_eco(b, "b")["status"], "FROZEN")


class TestSignoffAndRelease(unittest.TestCase):
    def test_no_release_without_green(self):
        svc = fresh()
        eid = make_eco(svc)
        svc.freeze_eco(eid, "o")
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eid, ROLE_TIMING, "t")
        self.assertEqual(cm.exception.code, "GATE_RED")

    def test_dual_role_distinct_users(self):
        svc = fresh()
        eid = make_eco(svc)
        svc.freeze_eco(eid, "o")
        run_all_pending(svc, eid)
        svc.signoff(eid, ROLE_TIMING, "same")
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eid, ROLE_METHOD, "same")
        self.assertEqual(cm.exception.code, "DUAL_ROLE_CONFLICT")

    def test_single_signoff_release_rejected_and_state_unchanged(self):
        svc = fresh()
        eid = make_eco(svc)
        svc.freeze_eco(eid, "o")
        run_all_pending(svc, eid)
        svc.signoff(eid, ROLE_TIMING, "t")
        with self.assertRaises(ECOError):
            svc.release_start(eid, "o")
        # 门禁失败不得把 ECO 留在 RELEASING
        self.assertEqual(svc.eco_detail(eid)["status"], "FROZEN")
        self.assertIsNone(svc.eco_detail(eid)["release"])

    def test_full_release_creates_baseline(self):
        svc = fresh()
        eid = make_eco(svc)
        svc.freeze_eco(eid, "o")
        rel = green_release(svc, eid)
        self.assertEqual(rel["new_baseline_id"], "B-R1")
        d = svc.eco_detail(eid)
        self.assertEqual(d["status"], "RELEASED")
        self.assertEqual(svc.current_constraints()["base_id"], "B-R1")

    def test_interrupted_release_resumes_atomically(self):
        svc = fresh()
        eid = make_eco(svc, mods=("core",))
        svc.freeze_eco(eid, "o")
        run_all_pending(svc, eid)
        svc.signoff(eid, ROLE_TIMING, "t")
        svc.signoff(eid, ROLE_METHOD, "m")
        with self.assertRaises(ECOError):
            svc.release_start(eid, "o", failpoint="AFTER_PHASE1")
        d = svc.eco_detail(eid)
        self.assertEqual(d["status"], "RELEASING")
        self.assertIsNone(d["release"]["new_baseline_id"])
        # 中断期间冻结世界
        with self.assertRaises(ECOError) as cm:
            svc.update_base_constraints({"clk_period_ns": 1.0}, "sdc")
        self.assertEqual(cm.exception.code, "RELEASE_IN_PROGRESS")
        with self.assertRaises(ECOError):
            svc.abort_eco(eid, "o")
        # 恢复且幂等
        r1 = svc.resume_release(eid, "o")
        r2 = svc.resume_release(eid, "o")
        self.assertEqual(r1["new_baseline_id"], "B-R1")
        self.assertEqual(r2["new_baseline_id"], "B-R1")
        self.assertEqual(len(svc.list_baselines()), 2)

    def test_post_release_eco_builds_on_new_base(self):
        svc = fresh()
        e1 = make_eco(svc, mods=("alu",))
        svc.freeze_eco(e1, "o"); green_release(svc, e1)
        e2 = make_eco(svc, mods=("l2c",))
        d = svc.freeze_eco(e2, "o")
        self.assertEqual(d["parent_baseline_id"], "B-R1")
        self.assertEqual(d["base_revision_at_freeze"], 1)

    def test_parallel_eco_invalidated_when_other_publishes(self):
        """两个模块不重叠的并行 ECO：先发布者推进基线后，在验单必须 rebase，
        不得携带旧基线模块内容直接发布。"""
        svc = fresh()
        a = make_eco(svc, mods=("alu",))
        b = make_eco(svc, mods=("l2c",))
        svc.freeze_eco(a, "o")
        svc.freeze_eco(b, "o")
        run_all_pending(svc, b)
        svc.signoff(b, ROLE_TIMING, "t"); svc.signoff(b, ROLE_METHOD, "m")
        # A 先发布
        run_all_pending(svc, a)
        svc.signoff(a, ROLE_TIMING, "t"); svc.signoff(a, ROLE_METHOD, "m")
        svc.release_start(a, "o")
        # B 虽模块不重叠、原本全绿双签，也被强制 rebase
        d = svc.eco_detail(b)
        self.assertEqual(d["status"], "REBASE_REQUIRED")
        self.assertFalse(d["gate"]["green"])
        self.assertEqual(d["gate"]["valid_signoffs"], [])
        with self.assertRaises(ECOError):
            svc.release_start(b, "o")  # REBASE_REQUIRED 态不可发布
        # 锁保留：新同模块 ECO 仍需排队
        c = make_eco(svc, mods=("l2c",))
        self.assertEqual(svc.freeze_eco(c, "o")["status"], "QUEUED")
        # B rebase 后父基线为新 B-R1，重跑可发布
        svc.abort_eco(c, "o")
        r = svc.freeze_eco(b, "o")
        self.assertEqual(r["parent_baseline_id"], "B-R1")
        rel = green_release(svc, b)
        self.assertEqual(rel["new_baseline_id"], "B-R2")


class TestDiffPackage(unittest.TestCase):
    def test_diff_contents(self):
        svc = fresh()
        eid = make_eco(svc, mods=("alu",))
        svc.freeze_eco(eid, "o")
        rel = green_release(svc, eid)
        pkg = svc.diff_package("B-R0", rel["new_baseline_id"])
        self.assertEqual(pkg["summary"]["modules_changed"], ["alu"])
        changed = next(m for m in pkg["modules"] if m["module"] == "alu")
        self.assertIn("ECO_NEW", changed["unified_diff"])
        self.assertTrue(pkg["verification"]["dual_role_distinct_users"])
        results = {r["check_type"]: r["status"] for r in pkg["verification"]["results"]}
        self.assertEqual(results["TIMING_STA"], "PASS")

    def test_diff_zip(self):
        svc = fresh()
        eid = make_eco(svc, mods=("alu",))
        svc.freeze_eco(eid, "o"); rel = green_release(svc, eid)
        data = svc.diff_zip("B-R0", rel["new_baseline_id"])
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
        self.assertIn("manifest.json", names)
        self.assertIn("modules/alu.diff", names)
        self.assertIn("verification/signoffs.json", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
