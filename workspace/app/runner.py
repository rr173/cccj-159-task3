"""模拟验证 Runner：真实 Runner 只信任冻结输入包，自行计算指纹后回传结果。

它不读取服务端 expected_fingerprint，从而可以真实演示：
- 针对同一冻结输入算出的指纹一致 → 结果接受
- 迟到结果（run 已 SUPERSEDED）→ 拒收
- 输入被改动/拿错基线算出的指纹不一致 → 拒收
"""
from __future__ import annotations

from .service import ECOError, fp_json
from .store import CHECKS


def compute_input_fingerprint(check_type: str, inputs: dict) -> str:
    spec = CHECKS[check_type]
    obj = {"verification_matrix": inputs["verification_matrix"]}
    if "netlist" in spec["scopes"]:
        obj["modules"] = {
            m: {"netlist": d["netlist"], "version": d["version"]}
            for m, d in sorted(inputs["modules"].items())}
    if "sdc" in spec["scopes"]:
        obj["constraints"] = inputs["constraints"]
    if "modules" in spec["scopes"]:
        obj["affected_modules"] = inputs["affected_modules"]
    return fp_json(obj)


def submit(svc, eco_id, check_type, *, verdict="PASS", result=None, tamper_fp=False,
           runner_id="runner-0", stale_run_id=None):
    """执行一次检查并提交。返回 (accepted: bool, payload/error)。"""
    pkt = svc.check_inputs(eco_id, check_type)
    run_id = stale_run_id or pkt["run_id"]
    fp = compute_input_fingerprint(check_type, pkt["inputs"])
    if tamper_fp:
        fp = (fp + "deadbeef")[:16]
    try:
        svc.submit_result(run_id, fp, verdict, result or {
            "wns_ns": 0.12, "tns_ns": 0.0, "power_mw": 421,
            "note": f"{check_type} 模拟通过"}, runner_id=runner_id)
        return True, {"run_id": run_id, "check": check_type, "verdict": verdict}
    except ECOError as e:
        return False, {"run_id": run_id, "check": check_type,
                       "reason": e.extra.get("reason", e.code), "message": e.message}


def run_all_pending(svc, eco_id, *, fail=()):
    """按依赖图把当前可提交的检查全部跑完（默认全 PASS）。"""
    log = []
    for _ in range(20):
        d = svc.eco_detail(eco_id)
        pending = [c["type"] for c in d["gate"]["checks"] if c["status"] == "PENDING"]
        if not pending:
            break
        for t in pending:
            ok, info = submit(svc, eco_id, t, verdict="FAIL" if t in fail else "PASS")
            log.append(info)
            if not ok:
                return log
    return log


def gate_status(svc, eco_id):
    d = svc.eco_detail(eco_id)
    return {c["type"]: c["status"] for c in d["gate"]["checks"]}
