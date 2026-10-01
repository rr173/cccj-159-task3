// 验证执行租约 Runner 操作页（零依赖原生 JS）
const $ = (id) => document.getElementById(id);
const CHECK_CN = {TIMING_STA: "时序STA", POWER_ANALYSIS: "功耗", FORMAL_EQUIV: "形式验证",
                  LAYOUT_DRC: "版图DRC", LINT_INFO: "Lint(非必需)"};
const STATE_CN = {HELD: "持有中", COMPLETED: "已完成", RELEASED: "已释放",
                  EXPIRED: "已过期", INVALIDATED: "已作废"};
const REASON_CN = {
  STALE_LEASE_GEN: "旧代次（已被接管/重领）", LEASE_BAD_CREDENTIAL: "凭据无效",
  LEASE_EXPIRED: "租约已过期", LEASE_NOT_FOUND: "无租约", LEASE_HELD_BY_OTHER: "他人持有中",
  LEASE_NOT_EXPIRED: "租约未到期不可接管", LEASE_ALREADY_COMPLETED: "租约已完成",
  LEASE_RELEASED: "租约已释放", STALE_SUPERSEDED: "纪元/重跑作废的迟到结果",
  FINGERPRINT_MISMATCH: "基线指纹不符", DEPENDENCY_BLOCKED: "依赖门禁未过",
  DEPENDENCY_NOT_READY: "依赖未就绪不可领取", NO_CLAIMABLE_TASK: "无待领任务",
  LEASE_NOT_HELD_BY_RUNNER: "非当前持有者", ALREADY_SUBMITTED: "结果已提交",
  ECO_NOT_ACTIVE: "ECO 不在验证态", IDEMPOTENCY_KEY_REUSED: "幂等键被他人占用",
  MISSING_LEASE_GEN: "缺少租约代次", MISSING_LEASE_TOKEN: "缺少凭据",
};

function toast(msg, kind="") {
  const t = document.createElement("div");
  t.className = "toast " + kind; t.innerHTML = msg;
  $("toast").appendChild(t);
  setTimeout(() => t.remove(), 7000);
}
async function api(path, method="GET", body) {
  const opt = {method, headers: {"Content-Type": "application/json"}};
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  const j = await r.json();
  if (!r.ok) throw Object.assign(new Error(j.message), {resp: j});
  return j;
}
function esc(s){return String(s??"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function fmtT(isoS){ return isoS ? new Date(isoS).toLocaleTimeString() : ""; }
function cnReason(r){ return REASON_CN[r] || r; }
function uuid(){ return (crypto.randomUUID && crypto.randomUUID()) ||
  "idem-" + Date.now() + "-" + Math.random().toString(16).slice(2, 10); }
function genIdem(){ $("idem").value = uuid(); }

// ---- Runner 自算指纹（与 Python canon 一致的紧凑规范序列化，不偷看 expected_fp）----
function canon(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}
async function sha16(obj) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon(obj)));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,"0")).join("").slice(0,16);
}
async function fingerprint(ecoId, checkType) {
  const cat = await api("/api/catalog");
  const spec = cat.checks.find(c => c.type === checkType);
  const pkt = await api(`/api/ecos/${ecoId}/checks/${checkType}/inputs`);
  const obj = {verification_matrix: pkt.inputs.verification_matrix};
  if (spec.scopes.includes("netlist")) obj.modules = Object.fromEntries(
    Object.entries(pkt.inputs.modules || {}).sort().map(([m,d])=>[m,{netlist:d.netlist,version:d.version}]));
  if (spec.scopes.includes("sdc")) obj.constraints = pkt.inputs.constraints;
  if (spec.scopes.includes("modules")) obj.affected_modules = pkt.inputs.affected_modules;
  return {fp: await sha16(obj), pkt};
}

// ---- 本机保存的领取授权（token 仅此处分发一次，存 localStorage 供刷新后续用）----
const VAULT_KEY = "lease_grants_v1";
const vault = {
  all() { try { return JSON.parse(localStorage.getItem(VAULT_KEY) || "{}"); } catch { return {}; } },
  get(runId) { return this.all()[runId]; },
  save(g) {
    const m = this.all();
    m[g.run_id] = {gen: g.gen, runner_id: g.runner_id, lease_token: g.lease_token,
                   eco_id: g.eco_id, check_type: g.check_type};
    localStorage.setItem(VAULT_KEY, JSON.stringify(m));
  },
  drop(runId) { const m = this.all(); delete m[runId]; localStorage.setItem(VAULT_KEY, JSON.stringify(m)); },
  mine(runId) { const v = this.get(runId); return v && v.runner_id === $("runner").value.trim() ? v : null; },
};

async function claimAny() {
  const idem = $("idem").value.trim() || uuid();
  $("idem").value = idem;
  try {
    const g = await api("/api/leases/claims", "POST",
      {runner_id: $("runner").value.trim(), idempotency_key: idem,
       ttl_seconds: Number($("ttl").value)});
    vault.save(g);
    toast(g.replayed ? `幂等重放：${g.check_type} 仍是你在 gen ${g.gen} 的租约`
                     : `✅ 已领取 ${g.check_type}（gen ${g.gen}，${g.remaining_seconds}s）`, "ok");
  } catch(e) { toast("⛔ " + (e.resp?.error ? cnReason(e.resp.error) : e.message), "err"); }
  await refresh();
}
async function claim(runId) {
  const idem = uuid();
  try {
    const g = await api("/api/leases/claims", "POST",
      {runner_id: $("runner").value.trim(), run_id: runId, idempotency_key: idem,
       ttl_seconds: Number($("ttl").value)});
    vault.save(g);
    toast(`✅ 已领取 ${g.check_type}（gen ${g.gen}）`, "ok");
  } catch(e) { toast("⛔ " + (e.resp?.error ? cnReason(e.resp.error) : e.message), "err"); }
  await refresh();
}
async function renew(runId) {
  const v = vault.mine(runId);
  if (!v) return toast("本机没有该任务的有效凭据（可能属于其他 runner）", "err");
  try {
    const r = await api(`/api/leases/runs/${encodeURIComponent(runId)}/renew`, "POST",
      {gen: v.gen, lease_token: v.lease_token, runner_id: v.runner_id,
       ttl_seconds: Number($("ttl").value)});
    toast(`已续租至 ${fmtT(r.expires_at)}（剩余 ${r.remaining_seconds}s）`, "ok");
  } catch(e) { toast("⛔ " + (e.resp?.error ? cnReason(e.resp.error) : e.message), "err"); }
  await refresh();
}
async function releaseLease(runId) {
  const v = vault.mine(runId);
  if (!v) return toast("本机没有该任务的有效凭据", "err");
  try {
    await api(`/api/leases/runs/${encodeURIComponent(runId)}/release`, "POST",
      {gen: v.gen, lease_token: v.lease_token, runner_id: v.runner, note: "页面主动释放"});
    vault.drop(runId);
    toast("已释放，任务回到待领池（代次不变）", "ok");
  } catch(e) { toast("⛔ " + (e.resp?.error ? cnReason(e.resp.error) : e.message), "err"); }
  await refresh();
}
async function complete(runId, verdict) {
  const v = vault.mine(runId);
  if (!v) return toast("本机没有该任务的有效凭据（接管后请到新持有者操作页提交）", "err");
  try {
    const {fp} = await fingerprint(v.eco_id, v.check_type);
    const d = await api(`/api/leases/runs/${encodeURIComponent(runId)}/complete`, "POST",
      {gen: v.gen, lease_token: v.lease_token, fingerprint: fp, verdict,
       runner_id: v.runner_id, result: {note: verdict === "PASS" ? "页面模拟通过" : "页面模拟违例"}});
    toast(`✅ 结果已接受（lease=COMPLETED，ECO 指纹/依赖门禁通过）`, "ok");
    vault.drop(runId);
  } catch(e) {
    const code = e.resp?.error || "";
    toast(`⛔ 结果拒收：<b>${esc(cnReason(code))}</b><div class="mut">${esc(e.message)}</div>`, "err");
  }
  await refresh();
}
async function tamperComplete(runId) {
  const v = vault.mine(runId);
  if (!v) return toast("本机没有该任务的有效凭据", "err");
  try {
    await api(`/api/leases/runs/${encodeURIComponent(runId)}/complete`, "POST",
      {gen: v.gen, lease_token: v.lease_token, fingerprint: "deadbeefdeadbeef",
       verdict: "PASS", runner_id: v.runner_id});
  } catch(e) {
    const code = e.resp?.error || "";
    toast(`⛔ 预期拒收：<b>${esc(cnReason(code))}</b>——接管/租约不绕过基线指纹门禁`, "err");
  }
  await refresh();
}
async function takeover(runId) {
  try {
    const g = await api(`/api/leases/runs/${encodeURIComponent(runId)}/takeover`, "POST",
      {runner_id: $("runner").value.trim(), ttl_seconds: Number($("ttl").value)});
    vault.save(g);
    toast(`🔁 已接管 ${g.check_type}：旧持有者 ${g.previous_holder} 的 gen ${g.previous_gen} 凭据作废，`
          + `当前 gen ${g.gen}`, "ok");
  } catch(e) { toast("⛔ " + (e.resp?.error ? cnReason(e.resp.error) : e.message), "err"); }
  await refresh();
}

// ---- 渲染 ----
function runCell(runId, ecoId, type, extra="") {
  return `<span class="mono">${esc(runId)}</span> <span class="mut">${ecoId} · ${CHECK_CN[type]||type}</span>${extra}`;
}
function renderClaimable(b) {
  $("claimable").innerHTML = b.claimable.length
    ? `<table><tr><th>任务</th><th>依赖</th><th></th></tr>` +
      b.claimable.map(c => `<tr>
        <td>${runCell(c.run_id, c.eco_id, c.check_type)}${c.required?"":' <span class="chip">非必需</span>'}</td>
        <td class="mut">${c.depends_on.length
            ? c.depends_on.map(d=>`${CHECK_CN[d]||d}:${c.dep_status[d]}`).join("，") : "—"}</td>
        <td><button onclick="claim('${esc(c.run_id)}')">领取</button></td></tr>`).join("") + "</table>"
    : '<div class="mut">（暂无就绪任务——把 ECO 冻结后，无依赖检查会出现在这里）</div>';
}
function tickClass(rem){ return rem > 60 ? "ok" : rem > 0 ? "warn ticker" : "bad"; }
function renderHeld(b) {
  $("held").innerHTML = b.held.length
    ? `<table><tr><th>持有者</th><th>任务</th><th>代次</th><th>剩余</th><th>到期</th><th>操作</th></tr>` +
      b.held.map(h => {
        const mine = h.runner_id === $("runner").value.trim();
        const v = vault.get(h.run_id);
        const mineBtns = mine && v
          ? `<button class="sec" onclick="renew('${esc(h.run_id)}')">续租</button>
             <button onclick="complete('${esc(h.run_id)}','PASS')">提交PASS</button>
             <button class="danger" onclick="complete('${esc(h.run_id)}','FAIL')">提交FAIL</button>
             <button class="warn" onclick="tamperComplete('${esc(h.run_id)}')">伪造指纹试提交</button>
             <button class="sec" onclick="releaseLease('${esc(h.run_id)}')">释放</button>`
          : '<span class="mut">（非本机 runner）</span>';
        return `<tr>
          <td><b>${esc(h.runner_id)}</b>${mine?' <span class="chip">我</span>':""}</td>
          <td>${runCell(h.run_id, h.eco_id, h.check_type)}</td>
          <td class="mono">g${h.gen}${h.renewed_count?` <span class="mut">续${h.renewed_count}</span>`:""}</td>
          <td class="${tickClass(h.remaining_seconds)}"><b>${h.remaining_seconds}s</b></td>
          <td class="mut">${fmtT(h.expires_at)}</td>
          <td>${mineBtns}</td></tr>`;
      }).join("") + "</table>"
    : '<div class="mut">（当前没有持有中的租约）</div>';
}
function renderTakeover(b) {
  $("takeover").innerHTML = b.takeover_available.length
    ? `<table><tr><th>任务</th><th>旧持有者</th><th>代次</th><th>到期时间</th><th></th></tr>` +
      b.takeover_available.map(t => `<tr>
        <td>${runCell(t.run_id, t.eco_id, t.check_type)}</td>
        <td><b>${esc(t.runner_id)}</b></td>
        <td class="mono">g${t.gen} → g${t.gen+1}</td>
        <td class="mut">${fmtT(t.expires_at)}</td>
        <td><button class="warn" onclick="takeover('${esc(t.run_id)}')">超时接管</button></td></tr>`
      ).join("") + "</table>"
    : '<div class="mut">（没有已过期待接管的任务）</div>';
}
function renderHistory(b) {
  $("history").innerHTML = b.takeover_history.length
    ? `<table><tr><th>时间</th><th>事件</th><th>任务</th><th>代次</th><th>操作者</th><th>详情</th></tr>` +
      b.takeover_history.map(e => `<tr>
        <td class="mut">${fmtT(e.at)}</td>
        <td class="${e.event==="TAKEOVER"?"ok":e.event==="INVALIDATE"?"bad":"warn"}">${e.event}</td>
        <td class="mono">${esc(e.run_id||"")}</td>
        <td>${e.gen??""}</td><td>${esc(e.actor||"")}</td>
        <td class="mut">${e.detail.previous_holder?`旧持有者 ${esc(e.detail.previous_holder)} (g${e.detail.previous_gen})`:esc(e.detail.reason||"")}</td>
      </tr>`).join("") + "</table>"
    : '<div class="mut">（暂无接管/超时记录）</div>';
}
function renderRejects(b) {
  $("rejects").innerHTML = b.recent_rejects.length
    ? `<table><tr><th>时间</th><th>任务</th><th>拒绝原因</th><th>操作者</th><th>细节</th></tr>` +
      b.recent_rejects.map(e => `<tr>
        <td class="mut">${fmtT(e.at)}</td>
        <td class="mono">${esc(e.run_id||"")}</td>
        <td class="bad">${esc(cnReason(e.detail.reason||""))}<div class="mut">${esc(e.detail.reason||"")}</div></td>
        <td>${esc(e.actor||"")}</td>
        <td class="mut">提交g${e.detail.submitted_gen??"?"}→当前g${e.detail.current_gen??"?"}
            ${e.detail.holder?`持有者 ${esc(e.detail.holder)}`:""}</td>
      </tr>`).join("") + "</table>"
    : '<div class="mut">（暂无拒绝记录）</div>';
}
function renderAll(b) {
  $("all").innerHTML = b.all_leases.length
    ? `<table><tr><th>run</th><th>状态</th><th>持有者</th><th>代次</th><th>剩余</th><th>结果</th></tr>` +
      b.all_leases.map(l => `<tr>
        <td>${runCell(l.run_id, l.eco_id, l.check_type)}</td>
        <td><span class="tag s-${l.state}">${STATE_CN[l.state]||l.state}</span></td>
        <td>${esc(l.runner_id)}</td>
        <td class="mono">g${l.gen}</td>
        <td class="${tickClass(l.remaining_seconds)}">${l.state==="HELD" && !l.expired ? l.remaining_seconds+"s" : "—"}</td>
        <td class="mut">${l.completion_verdict||""} ${l.run_status?`<span class="chip">run:${l.run_status}</span>`:""}</td>
      </tr>`).join("") + "</table>"
    : '<div class="mut">（暂无租约）</div>';
}

async function refresh() {
  const b = await api("/api/leases/board");
  window.__board = b;
  $("meta").textContent = `快照时刻 ${new Date(b.at).toLocaleTimeString()} · 默认 TTL ${b.default_ttl_seconds}s · 待领 ${b.claimable.length} · 持有 ${b.held.length} · 可接管 ${b.takeover_available.length}`;
  renderClaimable(b); renderHeld(b); renderTakeover(b);
  renderHistory(b); renderRejects(b); renderAll(b);
}

let timer = null;
function armTimer() {
  clearInterval(timer);
  timer = setInterval(async () => {
    if (!$("autoref").checked) return;
    try { await refresh(); } catch(e) {}
  }, 5000);
}
genIdem();
refresh().catch(e => toast(e.message, "err"));
armTimer();
