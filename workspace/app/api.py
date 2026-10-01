"""HTTP API：基于标准库 http.server 的 REST 路由层。

启动: python3 -m app.api --db data/eco.db --port 8080
"""
from __future__ import annotations

import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .service import ECOError, ECOService
from .store import Store

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

_MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".json": "application/json"}


def _make_handler(svc: ECOService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ChipECO/1.0"

        def log_message(self, fmt, *args):
            pass

        # ---- 收发辅助 ----
        def _send(self, code, payload, ctype="application/json"):
            body = payload if isinstance(payload, bytes) else json.dumps(
                payload, ensure_ascii=False, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype if ctype.startswith("application/zip")
                             else ctype)
            self.send_header("Content-Length", str(len(body)))
            if ctype.startswith("application/zip"):
                self.send_header("Content-Disposition",
                                 'attachment; filename="baseline-diff.zip"')
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                return json.loads(raw or b"{}")
            except json.JSONDecodeError:
                raise ECOError("BAD_JSON", "请求体不是合法 JSON", 400)

        def _err(self, e: ECOError):
            self._send(e.http_status, {"error": e.code, "message": e.message,
                                       "detail": e.extra})

        def _q(self, name, default=None, cast=str):
            from urllib.parse import parse_qs
            qs = parse_qs(urlparse(self.path).query)
            return cast(qs[name][0]) if name in qs else default

        # ---- 静态资源 ----
        def _static(self, rel):
            p = (WEB_DIR / rel).resolve()
            if not str(p).startswith(str(WEB_DIR.resolve())) or not p.is_file():
                self._send(404, {"error": "NOT_FOUND", "message": str(rel)})
                return
            ctype = _MIME.get(p.suffix, "application/octet-stream")
            self._send(200, p.read_bytes(), ctype)

        # ---- 路由 ----
        def do_GET(self):
            path = urlparse(self.path).path.rstrip("/") or "/"
            try:
                if path == "/":
                    return self._static("index.html")
                if path.startswith("/static/"):
                    return self._static(path[len("/static/"):])
                # 更具体的字面路径先于参数化模式匹配
                m = re.fullmatch(r"/api/baselines/diff\.zip", path)
                if m:
                    f, t = self._q("from"), self._q("to")
                    if not f or not t:
                        raise ECOError("BAD_REQUEST", "需要 from/to 查询参数", 400)
                    return self._send(200, svc.diff_zip(f, t), "application/zip")
                m = re.fullmatch(r"/api/baselines/diff", path)
                if m:
                    f, t = self._q("from"), self._q("to")
                    if not f or not t:
                        raise ECOError("BAD_REQUEST", "需要 from/to 查询参数", 400)
                    return self._send(200, svc.diff_package(f, t))
                m = re.fullmatch(r"/api/baselines/([^/]+)", path)
                if m:
                    return self._send(200, svc.baseline_detail(m.group(1)))
                if path == "/api/baselines":
                    return self._send(200, {"baselines": svc.list_baselines()})
                m = re.fullmatch(r"/api/ecos/([^/]+)", path)
                if m:
                    return self._send(200, svc.eco_detail(m.group(1)))
                if path == "/api/ecos":
                    return self._send(200, {"ecos": svc.list_ecos()})
                m = re.fullmatch(r"/api/ecos/([^/]+)/checks/([^/]+)/inputs", path)
                if m:
                    return self._send(200, svc.check_inputs(m.group(1), m.group(2)))
                if path == "/api/workbench":
                    return self._send(200, svc.workbench())
                if path == "/api/catalog":
                    return self._send(200, svc.check_catalog())
                if path == "/api/constraints":
                    return self._send(200, svc.current_constraints())
                if path == "/api/rejected-results":
                    return self._send(200, {"rejected": svc.rejected_results()})
                if path == "/api/admin/delegations":
                    return self._send(200, {"delegations": svc.list_delegations()})
                m = re.fullmatch(r"/api/admin/delegations/(\d+)", path)
                if m:
                    return self._send(200, svc.get_delegation(int(m.group(1))))
                if path == "/api/current-signers":
                    return self._send(200, svc.current_signers())
                self._send(404, {"error": "NOT_FOUND", "message": path})
            except ECOError as e:
                self._err(e)

        def do_POST(self):
            path = urlparse(self.path).path.rstrip("/")
            try:
                b = self._body()
                if path == "/api/admin/reset":
                    svc.s.reset()
                    return self._send(200, {"ok": True, "seed": True})
                if path == "/api/ecos":
                    d = svc.create_eco(b["title"], b.get("owner", b.get("by", "?")),
                                       b["affected_modules"], b.get("edits"))
                    return self._send(201, d)
                m = re.fullmatch(r"/api/ecos/([^/]+)/edits", path)
                if m:
                    return self._send(200, svc.update_edits(
                        m.group(1), b["edits"], b.get("by", "?")))
                m = re.fullmatch(r"/api/ecos/([^/]+)/freeze", path)
                if m:
                    return self._send(200, svc.freeze_eco(m.group(1), b.get("by", "?")))
                m = re.fullmatch(r"/api/ecos/([^/]+)/abort", path)
                if m:
                    return self._send(200, svc.abort_eco(m.group(1), b.get("by", "?")))
                m = re.fullmatch(r"/api/ecos/([^/]+)/checks/([^/]+)/results", path)
                if m:
                    d = svc.submit_result(
                        b["run_id"], b["fingerprint"], b["verdict"],
                        b.get("result"), b.get("runner_id", "runner-0"))
                    return self._send(200, d)
                m = re.fullmatch(r"/api/ecos/([^/]+)/checks/([^/]+)/rerun", path)
                if m:
                    return self._send(200, svc.rerun_check(
                        m.group(1), m.group(2), b.get("by", "?")))
                m = re.fullmatch(r"/api/ecos/([^/]+)/signoff", path)
                if m:
                    return self._send(200, svc.signoff(
                        m.group(1), b["role"], b.get("user", b.get("by", "?")),
                        b.get("delegation_id")))
                # 临时代理签核：管理员配置 / 撤销
                if path == "/api/admin/delegations":
                    d = svc.create_delegation(
                        b["role"], b["delegate_user"], b["valid_from"], b["valid_until"],
                        b.get("granted_by", b.get("by", "admin")),
                        b.get("principal_user"), b.get("note", ""))
                    return self._send(201 if not d.get("deduped") else 200, d)
                m = re.fullmatch(r"/api/admin/delegations/(\d+)/revoke", path)
                if m:
                    return self._send(200, svc.revoke_delegation(
                        int(m.group(1)), b.get("revoked_by", b.get("by", "admin"))))
                # 更具体的路径必须排在同前缀通用模式之前（fullmatch 已锚定，
                # 但 merge-into 有两段，需先于通用段；resume 亦先于裸 release 防御）
                m = re.fullmatch(r"/api/ecos/([^/]+)/release/resume", path)
                if m:
                    return self._send(200, svc.resume_release(m.group(1), b.get("by", "?")))
                m = re.fullmatch(r"/api/ecos/([^/]+)/merge-into/([^/]+)", path)
                if m:
                    return self._send(200, svc.adjudicate_merge(
                        m.group(1), m.group(2), b.get("by", "?"),
                        b.get("module_winners")))
                m = re.fullmatch(r"/api/ecos/([^/]+)/release", path)
                if m:
                    d = svc.release_start(m.group(1), b.get("by", "?"),
                                          b.get("failpoint"))
                    return self._send(200, d)
                if path == "/api/constraints":
                    return self._send(200, svc.update_base_constraints(
                        b["delta"], b.get("by", "?"), b.get("note", "")))
                self._send(404, {"error": "NOT_FOUND", "message": path})
            except KeyError as e:
                self._err(ECOError("BAD_REQUEST", f"缺少字段: {e}", 400))
            except ECOError as e:
                self._err(e)

    return Handler


def serve(db_path=":memory:", port=8080):
    store = Store(db_path)
    svc = ECOService(store)
    httpd = ThreadingHTTPServer(("0.0.0.0", port), _make_handler(svc))
    print(f"ECO 基线服务已启动: http://localhost:{port}  (db={db_path})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/eco.db")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    serve(args.db, args.port)
