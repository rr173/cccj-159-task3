"""端到端场景演示（内存库，无需起服务）：

  python3 -m app.demo

覆盖：
  A. 正常流：冻结 → 依赖图触发检查 → 全绿 → 双角色签核 → R1 发布 → 差异包
  B. 验证结果迟到 / 基础约束更新途中到来：拒收，ECO 须 rebase 重跑
  C. 两个 ECO 修改重叠模块：排队 + 合并裁决，旧结果作废
  D. 发布中断：RELEASING 持久化，resume 原子恢复；中断期间禁止任何变更
  E. 验证执行租约：幂等领取/并发单赢家、超时接管代次+1、旧持有者与伪造凭据结果拒收
  F. 临时代理签核：配置/撤销，动作时授权校验拒绝未生效/过期/撤销，同一人禁双签
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .runner import gate_status, run_all_pending, submit, compute_input_fingerprint
from .service import ECOError, ECOService, ROLE_METHOD, ROLE_TIMING
from .leases import LeaseError, LeaseService
from .store import Store

LINE = "=" * 78


class Clock:
    """演示用可控时钟：租约超时/接管需要确定性的时间推进。"""
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)
        return self.t


def hr(title):
    print(f"\n{LINE}\n  {title}\n{LINE}")


def show_gate(svc, eco_id):
    st = gate_status(svc, eco_id)
    print("   检查矩阵:", " | ".join(f"{k}={v}" for k, v in st.items()))


def expect_reject(fn, label):
    try:
        fn()
        print(f"   !! 异常：{label} 竟然被接受")
    except (ECOError, LeaseError) as e:
        reason = e.extra.get("reason", e.code) if getattr(e, "extra", None) else e.code
        print(f"   ✓ 按预期拒收 [{reason}]: {e.message}")


def main():
    # 演示钟锚定当前时刻：代理签核的“动作时校验”与租约 TTL 推进共用同一时钟
    clk = Clock(datetime.now(timezone.utc).replace(microsecond=0))
    store = Store(":memory:")
    svc = ECOService(store, now_fn=clk)
    leases = LeaseService(store, svc, now_fn=clk, ttl_seconds=300)
    # ---------------- A. 正常流 ----------------
    hr("A. 正常流：时序修复 ECO 冻结 → 依赖图检查 → 双签核 → 发布 R1")
    e1 = svc.create_eco(
        "ALU 关键路径插入 retimer", "wei.dong", ["alu"],
        {"alu": {"netlist": "MODULE alu; INPUT a b; CELL ADD u_add(a,b,s); "
                            "CELL RETIMER u_rt; CELL MUX u_mux; ENDMODULE"}})
    print(f"   1) 创建 {e1['id']}（草稿）")
    svc.freeze_eco(e1["id"], "wei.dong")
    print("   2) 提交冻结：网表/约束/受影响模块/验证矩阵固化，模块锁 [alu]")
    show_gate(svc, e1["id"])
    print("      (LAYOUT_DRC 依赖 TIMING/POWER，初始 BLOCKED)")
    log = run_all_pending(svc, e1["id"])
    print("   3) Runner 按依赖图回传结果:", {x["check"]: x["verdict"] for x in log if x.get("verdict")})
    show_gate(svc, e1["id"])
    # 检查未过时签核被拒：把某必需检查置失败验证红门禁
    e_probe = svc.create_eco("红门禁探针", "probe", ["noc"],
                             {"noc": {"netlist": "MODULE noc; CELL ROUTER r0/r1; LINK x; ENDMODULE"}})
    svc.freeze_eco(e_probe["id"], "probe"); run_all_pending(svc, e_probe["id"], fail=("TIMING_STA",))
    expect_reject(lambda: svc.signoff(e_probe["id"], ROLE_TIMING, "timing.zhang"),
                  "必需检查有 FAIL 时签核")
    svc.abort_eco(e_probe["id"], "probe")

    svc.signoff(e1["id"], ROLE_TIMING, "timing.zhang")
    print("   4) 时序负责人 timing.zhang 签核")
    expect_reject(lambda: svc.release_start(e1["id"], "wei.dong"), "只有单角色签核就发布")
    expect_reject(lambda: svc.signoff(e1["id"], ROLE_METHOD, "timing.zhang"), "同一人双签")
    svc.signoff(e1["id"], ROLE_METHOD, "method.li")
    print("   5) 方法学负责人 method.li 签核（必须不同人）")
    rel = svc.release_start(e1["id"], "wei.dong")
    print(f"   6) 全绿 + 双角色不同人 → 发布成功: {rel}")
    diff = svc.diff_package("B-R0", rel["new_baseline_id"])
    print("   7) 差异包摘要:", diff["summary"])

    # ---------------- B. 迟到结果 + 基础约束更新 ----------------
    hr("B. 验证结果迟到 & 基础约束更新途中到来：旧结果拒收，必须 rebase 重跑")
    e2 = svc.create_eco("L2 tag RAM 时序微调", "qiao.fang", ["l2c"],
                        {"l2c": {"netlist": "MODULE l2c; CELL RAMB u_tag(DEPTH=512); "
                                            "CELL RETIMER u_rt; NET hit=tag_cmp; ENDMODULE"}})
    svc.freeze_eco(e2["id"], "qiao.fang")
    run_all_pending(svc, e2["id"])
    svc.signoff(e2["id"], ROLE_TIMING, "timing.zhang")
    print(f"   1) {e2['id']} 已冻结、全绿并拿到一个签核")
    inputs = svc.check_inputs(e2["id"], "TIMING_STA")
    old_run_id, old_fp = inputs["run_id"], inputs["expected_fingerprint"]
    print(f"      旧 TIMING run={old_run_id} fp={old_fp}")
    upd = svc.update_base_constraints({"clk_period_ns": 1.10}, "sdc.owner",
                                      "工艺签核收紧时钟到 1.10ns")
    print(f"   2) 基础约束更新 clk_period_ns 1.20→1.10，约束 v{upd['constraints_version']}，"
          f"受影响 ECO={upd['rebased_ecos']} → REBASE_REQUIRED")
    show_gate(svc, e2["id"])
    print("      （全部旧检查 SUPERSEDED、旧签核作废）")
    # 迟到结果：用旧 run id + 旧指纹
    expect_reject(lambda: svc.submit_result(
        old_run_id, old_fp, "PASS", {"note": "迟到的时序结果"}, "runner-late"),
        "迟到结果（旧 run，旧基线指纹）")
    # 即使是针对当前输入重算的结果，run 也已作废
    expect_reject(lambda: submit(svc, e2["id"], "TIMING_STA"), "对作废 run 的新提交")
    expect_reject(lambda: svc.signoff(e2["id"], ROLE_METHOD, "method.li"), "rebase 前签核")
    svc.freeze_eco(e2["id"], "qiao.fang")
    print("   3) 工程师 rebase 重新冻结：新纪元、新指纹，验证矩阵重新触发")
    show_gate(svc, e2["id"])
    run_all_pending(svc, e2["id"])
    svc.signoff(e2["id"], ROLE_TIMING, "timing.zhang")
    svc.signoff(e2["id"], ROLE_METHOD, "method.li")
    rel2 = svc.release_start(e2["id"], "qiao.fang")
    print(f"   4) 全部检查针对同一新基线通过、双签 → 发布 {rel2['new_baseline_id']}")

    # ---------------- C. 重叠模块：排队 + 合并裁决 ----------------
    hr("C. 两个 ECO 修改重叠模块：排队或合并裁决，禁止并行覆盖")
    a = svc.create_eco("NoC 路由器加 buffer", "dev.a", ["noc", "core"],
                       {"noc": {"netlist": "MODULE noc; CELL ROUTER r0/r1(BUF=8); LINK; ENDMODULE"},
                        "core": {"netlist": "MODULE core; INPUT clk rst; CELL FF q0/q1/q2; ENDMODULE"}})
    svc.freeze_eco(a["id"], "dev.a")
    print(f"   1) {a['id']} 冻结，占用锁 [noc, core]，开始验证")
    run_all_pending(svc, a["id"])
    b = svc.create_eco("NoC QoS 仲裁改造", "dev.b", ["noc"],
                       {"noc": {"netlist": "MODULE noc; CELL ROUTER r0/r1(QOS=1); LINK; ENDMODULE"}})
    bq = svc.freeze_eco(b["id"], "dev.b")
    print(f"   2) {b['id']} 与 {a['id']} 在 [noc] 重叠 → 状态 {bq['status']}，"
          f"阻塞: {[(q['blocker_eco_id'],q['module']) for q in bq['queue']]}")
    print("   3) CCB 裁决：两单变更合并（重叠模块以占用方为准），冲突明确消除后并入")
    merged = svc.adjudicate_merge(b["id"], a["id"], "ccb.chair",
                                  module_winners={"noc": "TARGET_WINS"})
    print(f"      合并后 {a['id']} 模块={merged['affected_modules']}，"
          f"纪元 e{merged['freeze_epoch']}，源单状态=MERGED，检查矩阵整轮重跑")
    show_gate(svc, a["id"])
    expect_reject(lambda: svc.signoff(a["id"], ROLE_TIMING, "timing.zhang"),
                  "合并扩张后用旧门禁签核")
    run_all_pending(svc, a["id"])
    svc.signoff(a["id"], ROLE_TIMING, "timing.zhang")
    svc.signoff(a["id"], ROLE_METHOD, "method.li")
    rel3 = svc.release_start(a["id"], "dev.a")
    print(f"   4) 合并单重跑全绿、双签 → 发布 {rel3['new_baseline_id']}")

    # ---------------- D. 发布中断 ----------------
    hr("D. 发布中断：原子性与恢复（失败注入 AFTER_PHASE1）")
    e4 = svc.create_eco("Core 低功耗保持单元", "dev.c", ["core"],
                        {"core": {"netlist": "MODULE core; INPUT clk rst; CELL FF q0/q1; "
                                            "CELL ISOLATION u_iso; ENDMODULE"}})
    svc.freeze_eco(e4["id"], "dev.c"); run_all_pending(svc, e4["id"])
    svc.signoff(e4["id"], ROLE_TIMING, "timing.zhang")
    svc.signoff(e4["id"], ROLE_METHOD, "method.li")
    print(f"   1) {e4['id']} 全绿双签，发起发布并注入提交前崩溃")
    try:
        svc.release_start(e4["id"], "dev.c", failpoint="AFTER_PHASE1")
    except ECOError as e:
        print(f"   2) 发布中断（状态已持久化）: {e.message}")
    detail = svc.eco_detail(e4["id"])
    print(f"      ECO 状态={detail['status']}，release={detail['release']['state']}，"
          f"新基线尚未生成")
    expect_reject(lambda: svc.update_base_constraints({"clk_period_ns": 1.0}, "sdc.owner"),
                  "中断期间更新基础约束")
    expect_reject(lambda: svc.abort_eco(e4["id"], "dev.c"), "中断期间中止 ECO")
    resumed = svc.resume_release(e4["id"], "dev.c")
    print(f"   3) resume 重新校验同一冻结指纹 + 双签 → {resumed}")
    finals = svc.list_baselines()
    print("   4) 当前发布基线序列:", [(x["id"], x["eco_id"]) for x in finals])
    pkg = svc.diff_package("B-R0", resumed["new_baseline_id"])
    print(f"   5) 差异包 {pkg['from']['id']}→{pkg['to']['id']}: 模块变更 "
          f"{pkg['summary']['modules_changed']}，双角色={pkg['verification']['dual_role_distinct_users']}")

    # ---------------- E. 验证执行租约协调 ----------------
    hr("E. 验证执行租约：幂等领取/并发单赢家 → 超时接管 → 旧代次迟到拒收（不绕过指纹门禁）")
    f = svc.create_eco("ALU 租约调度演示", "dev.f", ["alu"],
                       {"alu": {"netlist": "MODULE alu; CELL LEASE_DEMO; ENDMODULE"}})
    svc.freeze_eco(f["id"], "dev.f")
    print(f"   1) {f['id']} 冻结，待领池:",
          [c["check_type"] for c in leases.lease_board()["claimable"]],
          "（LAYOUT_DRC 依赖未满足，不在池中）")
    sta_run = svc.s.q_one(
        "SELECT id FROM check_run WHERE eco_id=? AND check_type='TIMING_STA' AND status='PENDING'",
        (f["id"],))["id"]
    g1 = leases.claim("runner-A", run_id=sta_run, idempotency_key="f-sta-1", ttl_seconds=300)
    g1b = leases.claim("runner-A", run_id=sta_run, idempotency_key="f-sta-1", ttl_seconds=300)
    print(f"   2) runner-A 领取 {g1['check_type']} gen={g1['gen']}；同幂等键重放 "
          f"replayed={g1b['replayed']}，token/代次不变")
    expect_reject(lambda: leases.claim("runner-B", run_id=sta_run),
                  "runner-B 在租约未过期时并发领取同一任务")

    print("   3) TTL 推进 301 秒（模拟 runner-A 卡死）…")
    clk.advance(seconds=301)
    board = leases.lease_board()
    print("      可接管任务:", [t["run_id"] for t in board["takeover_available"]
                          if t["eco_id"] == f["id"]])
    g2 = leases.takeover(sta_run, "runner-B", ttl_seconds=300)
    print(f"   4) runner-B 超时接管成功：gen {g2['previous_gen']}→{g2['gen']}，"
          f"旧持有者 {g2['previous_holder']} 的凭据立即失效")
    pkt = svc.check_inputs(f["id"], "TIMING_STA")
    fp = compute_input_fingerprint("TIMING_STA", pkt["inputs"])
    expect_reject(lambda: leases.complete(sta_run, g1["gen"], g1["lease_token"], fp,
                                          "PASS", runner_id="runner-A"),
                  "runner-A 用旧代次+旧凭据迟到回传")
    expect_reject(lambda: leases.complete(sta_run, g2["gen"], "0" * 16, fp,
                                          "PASS", runner_id="runner-B"),
                  "伪造凭据的接管者提交")
    expect_reject(lambda: leases.complete(sta_run, g2["gen"], g2["lease_token"],
                                          "deadbeefdeadbeef", "PASS", runner_id="runner-B"),
                  "凭据有效但指纹不符（租约层不绕过基线指纹门禁）")
    ok = leases.complete(sta_run, g2["gen"], g2["lease_token"], fp, "PASS",
                         runner_id="runner-B")
    print(f"   5) runner-B 凭 gen={ok['lease']['gen']} 凭据 + 正确指纹完成 → "
          f"lease={ok['lease']['state']}，run 已由 ECO 服务落库")
    aud = leases.audit_events(run_id=sta_run)["events"]
    print("   6) 租约审计事件流:", [(e["event"], e["actor"], e["gen"]) for e in
          sorted(aud, key=lambda x: x["seq"]) if e["event"] != "REJECT"])
    print("      拒绝审计:", [(e["detail"]["reason"], e["actor"]) for e in aud
          if e["event"] == "REJECT"])
    print("      ECO 侧 rejected_result:", [r["reason"] for r in svc.rejected_results()
          if r["run_id"] == sta_run])

    # ---------------- F. 临时代理签核 ----------------
    hr("F. 临时代理签核：动作时授权校验 + 同一自然人禁双签 + 重新冻结失效")
    now = clk.t
    iso = lambda dt: dt.isoformat(timespec="seconds")
    e5 = svc.create_eco("L2C 功耗保持修复", "dev.e", ["l2c"],
                        {"l2c": {"netlist": "MODULE l2c; CELL RETENTION u_r; ENDMODULE"}})
    svc.freeze_eco(e5["id"], "dev.e"); run_all_pending(svc, e5["id"])
    print(f"   1) {e5['id']} 全绿待签；timing.zhang 休假，管理员配置 backup.wang 代理时序")
    dt = svc.create_delegation(
        ROLE_TIMING, "backup.wang", iso(now - timedelta(hours=1)), iso(now + timedelta(days=1)),
        "admin.chen", principal_user="timing.zhang", note="休假代理")
    dt2 = svc.create_delegation(
        ROLE_TIMING, "backup.wang", iso(now - timedelta(hours=1)), iso(now + timedelta(days=1)),
        "admin.chen", principal_user="timing.zhang", note="休假代理")
    print(f"      重复提交幂等: 同一 id={dt['id']}, deduped={dt2['deduped']}")
    svc.signoff(e5["id"], ROLE_TIMING, "backup.wang", delegation_id=dt["id"])
    print("   2) backup.wang 凭有效代理完成时序签（记录固化代理链）")
    # 未生效 / 已过期 / 已撤销 三类拒绝
    future = svc.create_delegation(
        ROLE_METHOD, "future.sun", iso(now + timedelta(days=1)), iso(now + timedelta(days=2)),
        "admin.chen")
    expect_reject(lambda: svc.signoff(e5["id"], ROLE_METHOD, "future.sun",
                                      delegation_id=future["id"]), "未生效代理签核")
    past = svc.create_delegation(
        ROLE_METHOD, "old.tan", iso(now - timedelta(days=2)), iso(now - timedelta(days=1)),
        "admin.chen")
    expect_reject(lambda: svc.signoff(e5["id"], ROLE_METHOD, "old.tan",
                                      delegation_id=past["id"]), "已过期代理签核")
    dm = svc.create_delegation(
        ROLE_METHOD, "proxy.qian", iso(now - timedelta(hours=1)), iso(now + timedelta(days=1)),
        "admin.chen")
    print("   3) backup.wang 又持有方法学代理 → 同一自然人双签仍被拒")
    both = svc.create_delegation(
        ROLE_METHOD, "backup.wang", iso(now - timedelta(hours=1)), iso(now + timedelta(days=1)),
        "admin.chen")
    expect_reject(lambda: svc.signoff(e5["id"], ROLE_METHOD, "backup.wang",
                                      delegation_id=both["id"]), "同一人经两条代理链双签")
    svc.revoke_delegation(dm["id"], "admin.chen")
    expect_reject(lambda: svc.signoff(e5["id"], ROLE_METHOD, "proxy.qian",
                                      delegation_id=dm["id"]), "撤销后代理签核")
    print("   4) 另一有效代理人 method.proxy 完成方法学签 → 发布；签核记录保留代理链")
    dm2 = svc.create_delegation(
        ROLE_METHOD, "method.proxy", iso(now - timedelta(hours=1)), iso(now + timedelta(days=7)),
        "admin.chen", principal_user="method.li")
    svc.signoff(e5["id"], ROLE_METHOD, "method.proxy", delegation_id=dm2["id"])
    rel5 = svc.release_start(e5["id"], "dev.e")
    print(f"      发布 {rel5['new_baseline_id']}；差异包签核:")
    pkg = svc.diff_package("B-R0", rel5["new_baseline_id"])
    for s in pkg["verification"]["signoffs"]:
        chain = s["auth_chain"]
        extra = f" 代 {chain['principal_user']}" if chain["kind"] == "DELEGATE" else "（本人）"
        print(f"        {s['role']}: {s['user']} [{s['signoff_kind']}]{extra}")

    # ---------------- F(租约) 已提前在 E 之前演示 ----------------

    hr("全部场景完成。拒收留痕(最近 5 条):")
    for r in svc.rejected_results()[:5]:
        print(f"   #{r['seq']} {r['eco_id'] or '-':8} {r['reason']}")


if __name__ == "__main__":
    main()
