"""HTTP 端到端测试：真实启动 ThreadingHTTPServer，经 socket 调用 REST API。"""
import io
import json
import socket
import unittest
import zipfile
import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.api import _make_handler
from app.runner import compute_input_fingerprint
from app.service import ECOService
from app.store import Store


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc = ECOService(Store(":memory:"))
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", free_port()), _make_handler(cls.svc))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.t = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def call(self, path, method="GET", body=None, raw=False):
        data = json.dumps(body).encode() if body is not None else None
        req = Request(self.base + path, data=data, method=method,
                      headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5) as r:
                payload = r.read()
                if raw:
                    return r.status, payload, dict(r.headers)
                return r.status, json.loads(payload)
        except HTTPError as e:
            return e.code, json.loads(e.read())

    def test_full_flow_via_http(self):
        s, d = self.call("/api/ecos", "POST", {
            "title": "HTTP 流", "owner": "net.eng", "affected_modules": ["alu"],
            "edits": {"alu": {"netlist": "MODULE alu; CELL HTTP_FIX; ENDMODULE"}}})
        self.assertEqual(s, 201)
        eid = d["id"]

        s, d = self.call(f"/api/ecos/{eid}/freeze", "POST", {"by": "net.eng"})
        self.assertEqual(s, 200)
        self.assertEqual(d["status"], "FROZEN")

        # Runner：拉输入 → 自算指纹 → 提交；按依赖图循环直到无 PENDING
        for _ in range(20):
            s, d = self.call(f"/api/ecos/{eid}")
            pending = [c["type"] for c in d["gate"]["checks"] if c["status"] == "PENDING"]
            if not pending:
                break
            for t in pending:
                s, pkt = self.call(f"/api/ecos/{eid}/checks/{t}/inputs")
                fp = compute_input_fingerprint(t, pkt["inputs"])
                s, resp = self.call(f"/api/ecos/{eid}/checks/{t}/results", "POST",
                                    {"run_id": pkt["run_id"], "fingerprint": fp,
                                     "verdict": "PASS", "runner_id": "ci-runner"})
                self.assertEqual(s, 200, resp)

        s, _ = self.call(f"/api/ecos/{eid}/signoff", "POST",
                         {"role": "TIMING_LEAD", "user": "t.u"})
        self.assertEqual(s, 200)
        # 同一人第二签 → 409
        s, err = self.call(f"/api/ecos/{eid}/signoff", "POST",
                           {"role": "METHODOLOGY_LEAD", "user": "t.u"})
        self.assertEqual(s, 409)
        self.assertEqual(err["error"], "DUAL_ROLE_CONFLICT")
        s, _ = self.call(f"/api/ecos/{eid}/signoff", "POST",
                         {"role": "METHODOLOGY_LEAD", "user": "m.u"})
        self.assertEqual(s, 200)

        s, rel = self.call(f"/api/ecos/{eid}/release", "POST", {"by": "net.eng"})
        self.assertEqual(s, 200)
        new_b = rel["new_baseline_id"]

        s, pkg = self.call(f"/api/baselines/diff?from=B-R0&to={new_b}")
        self.assertEqual(s, 200)
        self.assertEqual(pkg["summary"]["modules_changed"], ["alu"])

        s, data, headers = self.call(f"/api/baselines/diff.zip?from=B-R0&to={new_b}", raw=True)
        self.assertEqual(s, 200)
        self.assertIn("zip", headers.get("Content-Type", ""))
        z = zipfile.ZipFile(io.BytesIO(data))
        self.assertIn("manifest.json", z.namelist())

    def test_stale_result_rejected_via_http(self):
        s, d = self.call("/api/ecos", "POST", {
            "title": "迟到流", "owner": "o", "affected_modules": ["l2c"],
            "edits": {"l2c": {"netlist": "MODULE l2c; CELL LATE_FIX; ENDMODULE"}}})
        eid = d["id"]
        self.call(f"/api/ecos/{eid}/freeze", "POST", {"by": "o"})
        s, pkt = self.call(f"/api/ecos/{eid}/checks/TIMING_STA/inputs")
        fp = compute_input_fingerprint("TIMING_STA", pkt["inputs"])
        old_run = pkt["run_id"]
        self.call("/api/constraints", "POST",
                  {"delta": {"clk_period_ns": 1.00}, "by": "sdc"})
        s, err = self.call(f"/api/ecos/{eid}/checks/TIMING_STA/results", "POST",
                           {"run_id": old_run, "fingerprint": fp, "verdict": "PASS"})
        self.assertEqual(s, 409)
        self.assertEqual(err["detail"]["reason"], "STALE_SUPERSEDED")
        s, rej = self.call("/api/rejected-results")
        self.assertTrue(any(r["reason"] == "STALE_SUPERSEDED" for r in rej["rejected"]))

    def test_overlap_queue_via_http(self):
        s, a = self.call("/api/ecos", "POST", {
            "title": "占用", "owner": "a", "affected_modules": ["noc"],
            "edits": {"noc": {"netlist": "MODULE noc; CELL A_FIX; ENDMODULE"}}})
        self.call(f"/api/ecos/{a['id']}/freeze", "POST", {"by": "a"})
        s, b = self.call("/api/ecos", "POST", {
            "title": "后来", "owner": "b", "affected_modules": ["noc"],
            "edits": {"noc": {"netlist": "MODULE noc; CELL B_FIX; ENDMODULE"}}})
        s, bq = self.call(f"/api/ecos/{b['id']}/freeze", "POST", {"by": "b"})
        self.assertEqual(bq["status"], "QUEUED")
        self.assertEqual(bq["queue"][0]["module"], "noc")
        s, m = self.call(f"/api/ecos/{b['id']}/merge-into/{a['id']}", "POST",
                         {"by": "ccb", "module_winners": {"noc": "SOURCE_WINS"}})
        self.assertEqual(s, 200)
        self.assertEqual(m["freeze_epoch"], 2)
        self.assertIn("B_FIX", m["edits"]["noc"]["netlist"])

    def test_static_index(self):
        s, data, _ = self.call("/", raw=True)
        self.assertEqual(s, 200)
        self.assertIn("ECO".encode(), data)

    def test_404(self):
        s, err = self.call("/api/nope")
        self.assertEqual(s, 404)

    def test_delegated_signoff_via_http(self):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        vf = (now - timedelta(hours=1)).isoformat(timespec="seconds")
        vu = (now + timedelta(days=1)).isoformat(timespec="seconds")

        s, d = self.call("/api/ecos", "POST", {
            "title": "代理签核流", "owner": "net.eng", "affected_modules": ["core"],
            "edits": {"core": {"netlist": "MODULE core; CELL DELEG_HTTP; ENDMODULE"}}})
        self.assertEqual(s, 201)
        eid = d["id"]
        self.call(f"/api/ecos/{eid}/freeze", "POST", {"by": "net.eng"})
        for _ in range(20):
            s, d = self.call(f"/api/ecos/{eid}")
            pending = [c["type"] for c in d["gate"]["checks"] if c["status"] == "PENDING"]
            if not pending:
                break
            for t in pending:
                s, pkt = self.call(f"/api/ecos/{eid}/checks/{t}/inputs")
                fp = compute_input_fingerprint(t, pkt["inputs"])
                s, resp = self.call(f"/api/ecos/{eid}/checks/{t}/results", "POST",
                                    {"run_id": pkt["run_id"], "fingerprint": fp,
                                     "verdict": "PASS", "runner_id": "ci-runner"})
                self.assertEqual(s, 200, resp)

        # 配置两条代理（不同自然人），重复提交第一次配置应幂等不重复
        body = {"role": "TIMING_LEAD", "delegate_user": "backup.wang",
                "principal_user": "timing.zhang", "granted_by": "admin.chen",
                "valid_from": vf, "valid_until": vu}
        s, d1 = self.call("/api/admin/delegations", "POST", body)
        self.assertEqual(s, 201)
        s, d1b = self.call("/api/admin/delegations", "POST", body)
        self.assertEqual(s, 200)
        self.assertTrue(d1b["deduped"])
        self.assertEqual(d1["id"], d1b["id"])

        s, d2 = self.call("/api/admin/delegations", "POST",
                          {"role": "METHODOLOGY_LEAD", "delegate_user": "proxy.qian",
                           "granted_by": "admin.chen", "valid_from": vf, "valid_until": vu})
        self.assertEqual(s, 201)

        s, cs = self.call("/api/current-signers")
        self.assertEqual(s, 200)
        self.assertIn("backup.wang", cs["roles"]["TIMING_LEAD"]["delegate_users"])

        # 代理人用 delegation_id 签核
        s, sd = self.call(f"/api/ecos/{eid}/signoff", "POST",
                          {"role": "TIMING_LEAD", "user": "backup.wang",
                           "delegation_id": d1["id"]})
        self.assertEqual(s, 200, sd)
        sig = next(x for x in sd["gate"]["valid_signoffs"] if x["role"] == "TIMING_LEAD")
        self.assertEqual(sig["signoff_kind"], "DELEGATE")
        self.assertEqual(sig["auth_chain"]["principal_user"], "timing.zhang")

        # 撤销方法学代理后，代理人签核 403，ECO 仍 FROZEN
        s, _ = self.call(f"/api/admin/delegations/{d2['id']}/revoke", "POST",
                         {"by": "admin.chen"})
        self.assertEqual(s, 200)
        s, err = self.call(f"/api/ecos/{eid}/signoff", "POST",
                           {"role": "METHODOLOGY_LEAD", "user": "proxy.qian",
                            "delegation_id": d2["id"]})
        self.assertEqual(s, 403)
        self.assertEqual(err["error"], "DELEGATION_REVOKED")
        s, ed = self.call(f"/api/ecos/{eid}")
        self.assertEqual(ed["status"], "FROZEN")

        # 未生效代理 → 403
        s, d3 = self.call("/api/admin/delegations", "POST",
                          {"role": "METHODOLOGY_LEAD", "delegate_user": "future.sun",
                           "granted_by": "admin",
                           "valid_from": (now + timedelta(days=2)).isoformat(timespec="seconds"),
                           "valid_until": (now + timedelta(days=3)).isoformat(timespec="seconds")})
        s, err = self.call(f"/api/ecos/{eid}/signoff", "POST",
                           {"role": "METHODOLOGY_LEAD", "user": "future.sun",
                            "delegation_id": d3["id"]})
        self.assertEqual(s, 403)
        self.assertEqual(err["error"], "DELEGATION_NOT_STARTED")


class LeaseApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.leases import LeaseService
        cls.svc = ECOService(Store(":memory:"))
        cls.leases = LeaseService(cls.svc.s, cls.svc, ttl_seconds=300)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", free_port()),
                                        _make_handler(cls.svc, cls.leases))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.t = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def call(self, path, method="GET", body=None, raw=False):
        data = json.dumps(body).encode() if body is not None else None
        req = Request(self.base + path, data=data, method=method,
                      headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5) as r:
                payload = r.read()
                if raw:
                    return r.status, payload
                return r.status, json.loads(payload)
        except HTTPError as e:
            return e.code, json.loads(e.read())

    def _frozen(self):
        s, d = self.call("/api/ecos", "POST", {
            "title": "租约 HTTP 流", "owner": "net.eng", "affected_modules": ["core"],
            "edits": {"core": {"netlist": "MODULE core; CELL LEASE_HTTP; ENDMODULE"}}})
        self.assertEqual(s, 201)
        eid = d["id"]
        self.call(f"/api/ecos/{eid}/freeze", "POST", {"by": "net.eng"})
        return eid

    def test_claim_complete_flow_via_http(self):
        eid = self._frozen()
        s, board = self.call("/api/leases/board")
        self.assertEqual(s, 200)
        self.assertIn("claimable", board)
        types = {c["check_type"] for c in board["claimable"]}
        self.assertIn("TIMING_STA", types)
        self.assertNotIn("LAYOUT_DRC", types)  # 依赖未满足，不进待领池

        # 自动领取一个任务
        s, g1 = self.call("/api/leases/claims", "POST",
                          {"runner_id": "ci-1", "idempotency_key": "http-1",
                           "ttl_seconds": 300})
        self.assertEqual(s, 201)
        rid = g1["run_id"]
        # 幂等重放：200 + 同 gen/token
        s, g1b = self.call("/api/leases/claims", "POST",
                           {"runner_id": "ci-1", "idempotency_key": "http-1"})
        self.assertEqual(s, 200)
        self.assertTrue(g1b["replayed"])
        self.assertEqual(g1b["lease_token"], g1["lease_token"])
        # 并发语义：另一 runner 领取同 run 被拒
        s, err = self.call("/api/leases/claims", "POST",
                           {"runner_id": "ci-2", "run_id": rid})
        self.assertEqual(s, 409)
        self.assertEqual(err["error"], "LEASE_HELD_BY_OTHER")
        # 缺凭据完成 → 400
        s, err = self.call(f"/api/leases/runs/{rid}/complete", "POST",
                           {"gen": 1, "fingerprint": "x", "verdict": "PASS",
                            "runner_id": "ci-1"})
        self.assertEqual(s, 400)
        self.assertEqual(err["error"], "MISSING_LEASE_TOKEN")
        # 错误代次 → 409 STALE_LEASE_GEN
        s, err = self.call(f"/api/leases/runs/{rid}/complete", "POST",
                           {"gen": 9, "lease_token": g1["lease_token"],
                            "fingerprint": "x", "verdict": "PASS", "runner_id": "ci-1"})
        self.assertEqual(s, 409)
        self.assertEqual(err["error"], "STALE_LEASE_GEN")

        # 拉输入、自算指纹、带租约代次+凭据完成
        s, pkt = self.call(f"/api/ecos/{eid}/checks/{g1['check_type']}/inputs")
        fp = compute_input_fingerprint(g1["check_type"], pkt["inputs"])
        s, done = self.call(f"/api/leases/runs/{rid}/complete", "POST",
                            {"gen": g1["gen"], "lease_token": g1["lease_token"],
                             "fingerprint": fp, "verdict": "PASS", "runner_id": "ci-1",
                             "result": {"note": "lease http ok"}})
        self.assertEqual(s, 200, done)
        self.assertTrue(done["accepted"])
        self.assertEqual(done["lease"]["state"], "COMPLETED")

        # 看板 + 审计可查
        s, board = self.call("/api/leases/board")
        self.assertTrue(all(h["run_id"] != rid for h in board["held"]))
        s, audit = self.call(f"/api/leases/audit?run_id={rid}")
        self.assertTrue(any(e["event"] == "CLAIM" for e in audit["events"]))
        self.assertTrue(any(e["event"] == "COMPLETE" for e in audit["events"]))

    def test_takeover_after_expiry_via_http(self):
        from datetime import datetime, timedelta, timezone
        # 用注入时钟的独立服务，精确控制过期
        from app.leases import LeaseService
        t0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)

        class Clk:
            def __init__(self):
                self.t = t0
            def __call__(self):
                return self.t

        clk = Clk()
        svc = ECOService(Store(":memory:"), now_fn=clk)
        leases = LeaseService(svc.s, svc, now_fn=clk, ttl_seconds=30)
        httpd = ThreadingHTTPServer(("127.0.0.1", free_port()), _make_handler(svc, leases))
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        def call(path, method="GET", body=None):
            data = json.dumps(body).encode() if body is not None else None
            req = Request(base + path, data=data, method=method,
                          headers={"Content-Type": "application/json"})
            try:
                with urlopen(req, timeout=5) as r:
                    return r.status, json.loads(r.read())
            except HTTPError as e:
                return e.code, json.loads(e.read())

        s, d = call("/api/ecos", "POST", {
            "title": "接管流", "owner": "o", "affected_modules": ["alu"],
            "edits": {"alu": {"netlist": "MODULE alu; CELL TAKEOVER; ENDMODULE"}}})
        eid = d["id"]
        call(f"/api/ecos/{eid}/freeze", "POST", {"by": "o"})
        s, g = call("/api/leases/claims", "POST",
                    {"runner_id": "old-runner", "ttl_seconds": 30})
        rid = g["run_id"]
        # 未过期不能接管
        s, err = call(f"/api/leases/runs/{rid}/takeover", "POST", {"runner_id": "new-runner"})
        self.assertEqual(s, 409)
        self.assertEqual(err["error"], "LEASE_NOT_EXPIRED")
        clk.t += timedelta(seconds=31)
        # 看板中该任务出现在可接管列表
        s, board = call("/api/leases/board")
        self.assertTrue(any(t["run_id"] == rid for t in board["takeover_available"]))
        s, g2 = call(f"/api/leases/runs/{rid}/takeover", "POST",
                     {"runner_id": "new-runner", "ttl_seconds": 60})
        self.assertEqual(s, 201)
        self.assertEqual(g2["gen"], 2)
        self.assertEqual(g2["previous_holder"], "old-runner")
        # 旧持有者旧凭据结果被拒
        s, pkt = call(f"/api/ecos/{eid}/checks/{g['check_type']}/inputs")
        fp = compute_input_fingerprint(g["check_type"], pkt["inputs"])
        s, err = call(f"/api/leases/runs/{rid}/complete", "POST",
                      {"gen": g["gen"], "lease_token": g["lease_token"],
                       "fingerprint": fp, "verdict": "PASS", "runner_id": "old-runner"})
        self.assertEqual(s, 409)
        self.assertEqual(err["error"], "STALE_LEASE_GEN")
        # 接管历史可查
        s, hist = call("/api/leases/audit?event=TAKEOVER")
        self.assertTrue(any(e["run_id"] == rid for e in hist["events"]))
        httpd.shutdown()

    def test_ops_page_served(self):
        s, data = self.call("/ops", raw=True)
        self.assertEqual(s, 200)
        self.assertIn("租约".encode(), data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
