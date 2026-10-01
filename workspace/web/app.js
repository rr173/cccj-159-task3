// ECO 签核工作台前端（零依赖原生 JS）
const $ = (id) => document.getElementById(id);
const STATUS_CN = {
  DRAFT: "草稿", FROZEN: "已冻结/验证中", QUEUED: "排队等待",
  REBASE_REQUIRED: "需基于新基线刷新", RELEASING: "发布中断(待恢复)",
  RELEASED: "已发布", ABORTED: "已中止", MERGED: "已并入他单",
};
const CHECK_CN = {TIMING_STA: "时序STA", POWER_ANALYSIS: "功耗", FORMAL_EQUIV: "形式验证",
                  LAYOUT_DRC: "版图DRC", LINT_INFO: "Lint(非必需)"};
const ROLE_CN = {TIMING_LEAD: "时序负责人", METHODOLOGY_LEAD: "方法学负责人"};
const DLG_STATE_CN = {ACTIVE: "生效中", PENDING: "待生效", EXPIRED: "已过期", REVOKED: "已撤销"};

function toast(msg, kind="") {
  const t = document.createElement("div");
  t.className = "toast " + kind; t.innerHTML = msg;
  $("toast").appendChild(t);
  setTimeout(() => t.remove(), 6000);
}

async function api(path, method="GET", body) {
  const opt = {method, headers: {"Content-Type": "application/json"}};
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  const j = await r.json();
  if (!r.ok) throw Object.assign(new Error(j.message), {resp: j});
  return j;
}

// ---- Runner 侧自行计算指纹（与服务端 Python canon 完全一致的紧凑规范序列化）----
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
async function runnerFp(check) {
  // 不偷看服务端 expected_fingerprint：只凭冻结输入包自行哈希
  const spec = window.CATALOG.find(c => c.type === check);
  const obj = {verification_matrix: window.MATRIX};
  if (spec.scopes.includes("netlist")) obj.modules = Object.fromEntries(
    Object.entries(window.SNAP_MODULES).sort().map(([m,d])=>[m,{netlist:d.netlist,version:d.version}]));
  if (spec.scopes.includes("sdc")) obj.constraints = window.SNAP_CONS;
  if (spec.scopes.includes("modules")) obj.affected_modules = window.SNAP_AFFECTED;
  return sha16(obj);
}

async function runOne(ecoId, type, verdict="PASS", opts={}) {
  const pkt = await api(`/api/ecos/${ecoId}/checks/${type}/inputs`);
  window.MATRIX = pkt.inputs.verification_matrix;
  window.SNAP_MODULES = pkt.inputs.modules || {};
  window.SNAP_CONS = pkt.inputs.constraints || {};
  window.SNAP_AFFECTED = pkt.inputs.affected_modules || [];
  let fp = await runnerFp(type);
  if (opts.tamper) fp = (fp + "deadbeef").slice(0,16);
  const runId = opts.staleRunId || pkt.run_id;
  return api(`/api/ecos/${ecoId}/checks/${type}/results`, "POST",
             {run_id: runId, fingerprint: fp, verdict,
              result: {note: verdict==="PASS"?"模拟通过":"模拟违例"}, runner_id: "runner-0"});
}

// 依赖图顺序执行所有 PENDING
async function runAll(ecoId, failType=null) {
  for (let i=0;i<20;i++) {
    const d = await api(`/api/ecos/${ecoId}`);
    const pend = d.gate.checks.filter(c => c.status === "PENDING").map(c => c.type);
    if (!pend.length) break;
    for (const t of pend) {
      try { await runOne(ecoId, t, t === failType ? "FAIL":"PASS"); }
      catch(e) { toast("检查拒收: "+e.message, "err"); throw e; }
    }
  }
  await refresh();
}

// 模拟迟到结果：约束刷新后，用旧 run_id 回传
async function lateResult(ecoId) {
  const old = await api(`/api/ecos/${ecoId}`);
  const t = "TIMING_STA";
  try {
    // 先让一次通过拿到 run id 历史；迟到提交直接对当前已作废 run 尝试
    const pkt = await api(`/api/ecos/${ecoId}/checks/${t}/inputs`).catch(()=>null);
    if (!pkt) { toast("该 ECO 当前无活动检查（已被作废）——这正是防串用的体现", "err"); return; }
    await runOne(ecoId, t, "PASS", {staleRunId: pkt.run_id + ":OLD"});
  } catch(e) {
    toast("⛔ 迟到/串用结果被拒收：" + (e.resp?.detail?.reason || e.message), "err");
  }
  await refresh();
}

// ---- 临时代理签核 ----
function localToUTC(v) {
  // datetime-local 取值按浏览器本地时区解释，统一转 UTC ISO-8601 发送给服务端
  if (!v) return "";
  return new Date(v).toISOString();
}
function fmtShort(isoS) {
  // UTC ISO -> 紧凑的本地展示
  if (!isoS) return "";
  const d = new Date(isoS);
  return d.toLocaleString();
}
function setDefaultTimes() {
  if ($("dlg-from").value) return;
  const now = new Date(), end = new Date(Date.now() + 7 * 864e5);
  const pad = (x) => String(x).padStart(2, "0");
  const val = (d) => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  $("dlg-from").value = val(now); $("dlg-until").value = val(end);
}

async function createDelegation() {
  const body = {
    role: $("dlg-role").value,
    delegate_user: $("dlg-user").value.trim(),
    principal_user: $("dlg-principal").value.trim() || null,
    granted_by: $("dlg-admin").value.trim() || "admin",
    valid_from: localToUTC($("dlg-from").value),
    valid_until: localToUTC($("dlg-until").value),
    note: $("dlg-note").value.trim(),
  };
  if (!body.delegate_user) { toast("代理人账号必填", "err"); return; }
  try {
    const d = await api("/api/admin/delegations", "POST", body);
    toast(d.deduped ? `相同代理配置已存在 #${d.id}（幂等，未重复创建）`
                    : `代理已配置 #${d.id}（${DLG_STATE_CN[d.state]}）`, "ok");
  } catch(e) { toast("⛔ " + e.message, "err"); }
  await refresh();
}

async function revokeDelegation(id) {
  await act(`/api/admin/delegations/${id}/revoke`, {by: $("dlg-admin").value.trim() || "admin"},
            `代理 #${id} 已撤销，其后签核将立即被拒绝`);
}

function renderSigners(w) {
  const r = w.current_signers.roles;
  $("signers").innerHTML = Object.values(r).map(x => {
    const people = x.delegates.length
      ? x.delegates.map(d => `<span class="chip ok" title="来源:${esc(d.source)}&#10;${esc(fmtShort(d.valid_from))} ~ ${esc(fmtShort(d.valid_until))}">
          👤 ${esc(d.user)} <span class="mut">(${esc(d.source)})</span></span>`).join(" ")
      : '<span class="mut">（无有效代理）</span>';
    return `<div style="min-width:46%"><b>${x.role_label}</b> 当前可签代理：${people}</div>`;
  }).join("");
}

function renderDelegations(w) {
  $("delegations").innerHTML = w.delegations.length
    ? `<table style="margin-top:8px"><tr><th>#</th><th>角色</th><th>代理人</th><th>代理来源</th>
         <th>有效期(本地)</th><th>状态</th><th></th></tr>` +
      w.delegations.map(d => {
        const cls = d.state === "ACTIVE" ? "ok" : d.state === "PENDING" ? "warn" : "mut";
        const src = d.principal_user ? `代理 ${esc(d.principal_user)}`
                  : `<span class="mut">${ROLE_CN[d.role]}临时代理</span>`;
        const btn = d.state === "ACTIVE" || d.state === "PENDING"
          ? `<button class="danger" onclick="revokeDelegation(${d.id})">撤销</button>` : "";
        return `<tr>
          <td class="mono">${d.id}</td>
          <td>${ROLE_CN[d.role]||d.role}</td>
          <td><b>${esc(d.delegate_user)}</b></td>
          <td>${src}<div class="mut">由 ${esc(d.granted_by)} 配置</div></td>
          <td class="mut">${esc(fmtShort(d.valid_from))}<br/>~ ${esc(fmtShort(d.valid_until))}
            ${d.revoked_at?`<div class="bad">撤销于 ${esc(fmtShort(d.revoked_at))} (${esc(d.revoked_by)})</div>`:""}</td>
          <td class="${cls}"><b>${DLG_STATE_CN[d.state]||d.state}</b></td>
          <td>${btn}</td></tr>`;
      }).join("") + "</table>"
    : '<div class="mut" style="margin-top:8px">（暂无代理配置）</div>';
}

async function resetAll() {
  await api("/api/admin/reset", "POST", {});
  toast("演示数据已重置", "ok");
  await refresh();
}

// ---- 操作 ----
async function createEco() {
  const mods = $("f-mods").value.split(",").map(s=>s.trim()).filter(Boolean);
  let edits = {};
  try { edits = JSON.parse($("f-edits").value || "{}"); }
  catch { toast("编辑 JSON 不合法", "err"); return; }
  const d = await api("/api/ecos","POST",{title:$("f-title").value, owner:$("f-owner").value,
                                          affected_modules:mods, edits});
  toast(`已创建 ${d.id}（草稿）`); await refresh();
}
const act = async (p,b,msg) => { try { const d = await api(p,"POST",b||{}); toast(msg||"操作成功","ok"); await refresh(); return d; }
  catch(e){ toast("⛔ "+e.message+(e.resp?.detail?.reason?` [${e.resp.detail.reason}]`:""),"err"); await refresh(); } };

async function refresh() {
  const w = await api("/api/workbench"); window.WB = w;
  $("trunk").textContent = `当前发布基线 ${w.constraints.base_id}(rev ${w.constraints.base_revision}) · 约束版本 v${w.constraints.constraints_version}`;
  renderSigners(w); renderDelegations(w);
  renderEcos(w); renderBaselines(w); renderMisc(w);
}

function esc(s){return String(s??"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function jslit(v){return JSON.stringify(String(v??""));}

function checkTable(gate) {
  return `<table><tr><th>检查</th><th>状态</th><th>依赖</th><th>指纹</th><th>提交</th></tr>` +
    gate.checks.map(c => `<tr>
      <td>${CHECK_CN[c.type]||c.type}${c.required?"":' <span class="chip">非必需</span>'}</td>
      <td class="c-${c.status}"><b>${c.status}</b>${c.satisfied?' ✓':''}</td>
      <td class="mut">${c.depends_on.length?c.depends_on.map(d=>`${CHECK_CN[d]||d}:${c.dep_status[d]}`).join("，"):"—"}</td>
      <td>${c.fingerprint_ok?'<span class="ok">一致</span>':c.status==='PASS'?'<span class="bad">不符</span>':'<span class="mut">待提交</span>'}</td>
      <td class="mut">${esc(c.runner_id||"")}</td></tr>`).join("") + "</table>";
}

function renderEcos(w) {
  $("ecos").innerHTML = w.ecos.map(e => {
    const g = e.gate;
    let btns = "";
    if (["DRAFT","REBASE_REQUIRED"].includes(e.status))
      btns += `<button onclick="act('/api/ecos/${e.id}/freeze',{by:'${e.owner}'},'${e.id} 已冻结，验证矩阵已触发')">${e.status==="REBASE_REQUIRED"?"刷新冻结(rebase)":"提交并冻结"}</button>`;
    if (e.status==="FROZEN")
      btns += `<button onclick="runAll('${e.id}')">Runner 执行全部检查</button>
        <button class="sec" onclick="runAll('${e.id}','TIMING_STA')">模拟时序失败</button>`;
    if (e.status==="FROZEN" && g.checks.some(c=>c.status==="FAIL"))
      btns += `<button class="sec" onclick="act('/api/ecos/${e.id}/checks/TIMING_STA/rerun',{by:'${e.owner}'},'旧尝试已作废，已按当前基线重跑')">重跑时序</button>`;
    if (e.status==="FROZEN") {
      btns += `<span style="margin-left:6px"></span>`;
      for (const role of ["TIMING_LEAD","METHODOLOGY_LEAD"]) {
        const directUser = role==="TIMING_LEAD" ? "timing.zhang" : "method.li";
        const done = g.valid_signoffs.some(s=>s.role===role);
        btns += `<button ${g.green&&!done?"":"disabled"} onclick="act('/api/ecos/${e.id}/signoff',{role:'${role}',user:'${directUser}'},'${ROLE_CN[role]}本人已签核')">签核:${ROLE_CN[role]}本人</button>`;
        for (const d of w.delegations.filter(x=>x.role===role && x.state==="ACTIVE")) {
          btns += `<button class="sec" ${g.green&&!done?"":"disabled"} title="有效期至 ${esc(fmtShort(d.valid_until))}&#10;由 ${esc(d.granted_by)} 配置"
            onclick="act('/api/ecos/${e.id}/signoff',{role:${jslit(role)},user:${jslit(d.delegate_user)},delegation_id:${d.id}},'代理签核成功（动作时授权校验通过）')">
            代理签核:${esc(d.delegate_user)}${d.principal_user?`←${esc(d.principal_user)}`:""}</button>`;
        }
      }
      btns += `<button ${g.releasable?"":"disabled"} onclick="act('/api/ecos/${e.id}/release',{by:'${e.owner}'},'新基线已发布')">发布基线</button>
        <button class="danger" onclick="act('/api/ecos/${e.id}/release',{by:'${e.owner}',failpoint:'AFTER_PHASE1'}).then(()=>{}).catch(()=>{})">模拟发布中断</button>`;
    }
    if (e.status==="RELEASING")
      btns += `<button onclick="act('/api/ecos/${e.id}/release/resume',{by:'${e.owner}'},'已从中断恢复并完成发布')">恢复发布</button>`;
    if (e.status==="QUEUED") {
      const blockers = e.queue.map(q=>q.blocker_eco_id+":"+q.module).join("，");
      btns += `<span class="warn">阻塞于 ${esc(blockers)}</span>
        <button class="sec" onclick="mergeInto('${e.id}')">裁决：合并到占用方</button>
        <button class="danger" onclick="act('/api/ecos/${e.id}/abort',{by:'${e.owner}'},'已中止并让出排队')">中止</button>`;
    }
    if (["DRAFT","FROZEN","REBASE_REQUIRED"].includes(e.status))
      btns += `<button class="danger" onclick="act('/api/ecos/${e.id}/abort',{by:'${e.owner}'},'已中止，模块锁释放')">中止</button>`;
    if (e.status==="FROZEN")
      btns += `<button class="sec" onclick="lateResult('${e.id}')">模拟迟到结果</button>
        <button class="sec" onclick="tamperResult('${e.id}')">模拟串用他单指纹</button>`;
    const sigChip = s => {
      const kind = s.signoff_kind === "DELEGATE"
        ? `<span class="chip" style="border-color:var(--warn);color:var(--warn)"
             title="代理链: 授权#${s.delegation_id}&#10;由 ${esc(s.auth_chain?.granted_by||"")} 配置&#10;有效期 ${esc(fmtShort(s.auth_chain?.valid_from))} ~ ${esc(fmtShort(s.auth_chain?.valid_until))}&#10;动作时校验 ${esc(s.auth_chain?.checked_at||s.at)}">代理签</span>`
        : `<span class="chip">本人签</span>`;
      const who = s.signoff_kind === "DELEGATE" && s.auth_chain?.principal_user
        ? `${esc(s.user)}<span class="mut"> 代 ${esc(s.auth_chain.principal_user)}</span>`
        : esc(s.user);
      const voidMark = s.voided_at ? ` <span class="bad" title="${esc(s.voided_reason||"")} @ ${esc(fmtShort(s.voided_at))}">已失效</span>` : "";
      return `<span class="chip">${ROLE_CN[s.role]||s.role}: ${who} ${kind}${voidMark}</span>`;
    };
    const sigs = g.valid_signoffs.map(sigChip).join(" ");
    const voided = g.signoffs.filter(s=>s.voided_at).map(sigChip).join(" ");
    return `<div class="card">
      <div class="row"><b class="mono">${e.id}</b> ${esc(e.title)}
        <span class="tag s-${e.status}">${STATUS_CN[e.status]||e.status}</span>
        <span style="flex:1"></span><span class="mut">owner ${esc(e.owner)}</span></div>
      <div class="row mut">受影响模块: ${e.affected_modules.map(m=>`<span class="chip">${m}</span>`).join(" ")}
        &nbsp;|&nbsp; 冻结基线: ${e.parent_baseline_id||"—"}
        &nbsp;|&nbsp; 纪元 e${e.freeze_epoch}
        &nbsp;|&nbsp; 门禁: <b class="${g.green?'ok':'bad'}">${g.green?'必需检查全绿':'未全绿'}</b>
        &nbsp;|&nbsp; 双签: <b class="${g.dual_role_complete?'ok':'warn'}">${g.dual_role_complete?'完成':'待签'}</b></div>
      <div class="row">${sigs||'<span class="mut">（暂无有效签核）</span>'}</div>
      ${voided?`<div class="row mut">已失效旧签核（ECO 重新冻结，记录保留审计）：${voided}</div>`:""}
      ${e.fingerprint?`<div class="row mut mono">基线指纹 ${e.fingerprint} · 约束v${e.constraints_version_at_freeze}</div>`:""}
      ${e.queue?.length?`<div class="row warn">排队中，等待模块: ${e.queue.map(q=>q.module).join(", ")}</div>`:""}
      ${e.blocks?.length?`<div class="row mut">后续排队 ECO: ${e.blocks.map(q=>q.eco_id).join(", ")}</div>`:""}
      ${e.status==="FROZEN"||e.status==="RELEASING"?checkTable(g):""}
      <div class="row">${btns}</div></div>`;
  }).join("") || '<div class="mut">暂无 ECO</div>';
}

async function tamperResult(ecoId) {
  try { await runOne(ecoId, "TIMING_STA", "PASS", {tamper:true}); }
  catch(e) { toast("⛔ 指纹不符被拒收：" + (e.resp?.detail?.reason||e.message), "err"); }
  await refresh();
}

async function mergeInto(srcId) {
  const w = window.WB;
  const q = w.ecos.find(e=>e.id===srcId).queue[0];
  await act(`/api/ecos/${srcId}/merge-into/${q.blocker_eco_id}`, {by:"ccb.chair",
    module_winners:{[q.module]:"TARGET_WINS"}}, `已裁决合并：${srcId} → ${q.blocker_eco_id}，旧结果全部作废重跑`);
}

function renderBaselines(w) {
  $("baselines").innerHTML = w.baselines.map(b =>
    `<div class="row"><b class="mono">${b.id}</b> <span class="mut">rev ${b.revision}</span>
      <span class="chip">${b.affected_modules.join(",")||"全量"}</span>
      <span class="mono mut">${b.fingerprint.slice(0,10)}…</span>
      <span style="flex:1"></span><span class="mut">${b.eco_id?("来源 "+b.eco_id):"初始基线"}</span></div>`).join("");
  const ids = w.baselines.map(b=>b.id);
  for (const [sel,val] of [["d-from",ids[0]],["d-to",ids[ids.length-1]]]) {
    const cur = $(sel).value;
    $(sel).innerHTML = ids.map(i=>`<option ${i===(cur||val)?"selected":""}>${i}</option>`).join("");
  }
}

async function showDiff() {
  const d = await api(`/api/baselines/diff?from=${$("d-from").value}&to=${$("d-to").value}`);
  $("diff").textContent = JSON.stringify(d, null, 2);
}
async function downloadZip() {
  const r = await fetch(`/api/baselines/diff.zip?from=${$("d-from").value}&to=${$("d-to").value}`);
  const blob = await r.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = "baseline-diff.zip"; a.click();
}

function renderMisc(w) {
  $("locks").innerHTML = w.locks.length
    ? w.locks.map(l=>`<span class="chip">${l.module}→${l.eco_id}</span>`).join(" ")
    : '<span class="mut">（无模块锁）</span>';
  $("rejects").innerHTML = w.rejected_results.length
    ? `<table><tr><th>#</th><th>ECO/检查</th><th>拒收原因</th><th>时间</th></tr>` +
      w.rejected_results.map(r=>`<tr><td>${r.seq}</td><td class="mono">${r.eco_id||""} ${r.check_type||""}</td>
        <td class="bad">${r.reason}</td><td class="mut">${(r.received_at||"").slice(11)}</td></tr>`).join("")+"</table>"
    : '<div class="mut">（暂无拒收记录）</div>';
}

// ================= 验证执行租约协调操作台 =================
const LEASE_STATE_CN = {HELD:"持有中", COMPLETED:"已完成", RELEASED:"已释放",
                        EXPIRED:"已过期", INVALIDATED:"随纪元作废"};
function ttlV(){ return parseInt($("lz-ttl").value||"30", 10); }
function runnerV(){ return $("lz-runner").value.trim() || "runner-0"; }

async function leaseClaimNext() {
  try {
    const d = await api("/api/leases/claim","POST",
      {runner_id: runnerV(), idempotency_key: "ui-" + Date.now(), ttl_seconds: ttlV()});
    if (!d.claimed) { toast("当前没有可领取的就绪任务（依赖可能尚未满足）","err"); return; }
    toast(`已领取 ${d.check_type}（${d.run_id}）· 代次 g${d.generation}，TTL ${d.ttl_seconds}s`,"ok");
    await loadLeases();
  } catch(e){ toast("⛔ 领取被拒："+e.message+" "+(e.resp?.error?"["+e.resp.error+"]":""),"err"); await loadLeases(); }
}

async function leaseClaimRun(runId) {
  try {
    const d = await api("/api/leases/claim","POST",
      {runner_id: runnerV(), idempotency_key: "ui-" + Date.now(), run_id: runId,
       ttl_seconds: ttlV()});
    toast(d.idempotent ? "幂等返回既有分配（未重复领取）" : `已领取 ${runId}`, "ok");
  } catch(e){ toast("⛔ "+e.message+" ["+(e.resp?.error||"")+"]","err"); }
  await loadLeases();
}

// 凭租约拉输入、自算指纹并回传结果（携带 generation + lease_token）
async function leaseComplete(runId, checkType, ecoId, generation, token, verdict="PASS") {
  try {
    const pkt = await api(`/api/ecos/${ecoId}/checks/${checkType}/inputs`);
    window.MATRIX = pkt.inputs.verification_matrix;
    window.SNAP_MODULES = pkt.inputs.modules || {};
    window.SNAP_CONS = pkt.inputs.constraints || {};
    window.SNAP_AFFECTED = pkt.inputs.affected_modules || [];
    const fp = await runnerFp(checkType);
    const d = await api(`/api/leases/runs/${runId}/results`,"POST",
      {runner_id: runnerV(), generation, lease_token: token, fingerprint: fp,
       verdict, result: {note: verdict==="PASS"?"租约执行通过":"租约执行违例"}});
    toast(`结果已接受：${checkType} ${verictNote(verdict)}（租约 COMPLETED，仍通过基线指纹/依赖门禁）`,"ok");
  } catch(e){
    toast("⛔ 结果拒收："+(e.resp?.detail?.reason||e.resp?.error||e.message),"err");
  }
  await loadLeases(); await refresh();
}
function verictNote(v){ return v==="PASS"?"PASS":"FAIL"; }

async function leaseRenew(runId, generation, token) {
  try {
    const d = await api(`/api/leases/runs/${runId}/renew`,"POST",
      {runner_id: runnerV(), generation, lease_token: token, ttl_seconds: ttlV()});
    toast(`续租成功，剩余 ${d.remaining_seconds}s（心跳 ${d.renew_count} 次）`,"ok");
  } catch(e){ toast("⛔ 续租被拒："+(e.resp?.error||e.message),"err"); }
  await loadLeases();
}
async function leaseRelease(runId, generation, token) {
  try { await api(`/api/leases/runs/${runId}/release`,"POST",
    {runner_id: runnerV(), generation, lease_token: token});
    toast("租约已主动释放，任务回到待领池","ok");
  } catch(e){ toast("⛔ "+(e.resp?.error||e.message),"err"); }
  await loadLeases();
}
async function leaseTakeover(runId) {
  try {
    const d = await api(`/api/leases/runs/${runId}/takeover`,"POST",
      {by_runner: runnerV(), ttl_seconds: ttlV()});
    toast(`超时接管成功：代次 g${d.previous.generation}→g${d.generation}，旧持有者凭据即刻失效`,"ok");
  } catch(e){ toast("⛔ 接管被拒："+(e.resp?.error||e.message),"err"); }
  await loadLeases();
}
async function leaseHistory(runId) {
  try {
    const d = await api(`/api/leases/runs/${runId}`);
    const txt = d.history.map(h =>
      `${(h.at||"").slice(11)} ${h.event} ${h.runner_id||""} g${h.generation??""}` +
      (h.reason?` → ${h.reason}`:"")).join("\n");
    toast(`<b>${runId}</b> 接管/事件历史：<pre style="margin:6px 0 0;white-space:pre-wrap">${esc(txt)}</pre>`);
  } catch(e){ toast("⛔ "+e.message,"err"); }
}

async function loadLeases() {
  const [pool, au] = await Promise.all([
    api("/api/leases/pool"), api("/api/leases/audit?limit=15")]);
  // 待领任务
  $("lz-pool").innerHTML = pool.claimable.length
    ? `<table><tr><th>ECO</th><th>检查</th><th>必需</th><th>依赖</th><th></th></tr>` +
      pool.claimable.map(x=>`<tr>
        <td class="mono">${x.eco_id}<div class="mut">${esc(x.eco_title||"")} e${x.freeze_epoch}</div></td>
        <td>${CHECK_CN[x.check_type]||x.check_type}</td>
        <td>${x.required?"是":'<span class="mut">否</span>'}</td>
        <td class="mut">${x.depends_on.length?x.depends_on.map(d=>CHECK_CN[d]||d).join("，"):"—"}</td>
        <td><button onclick="leaseClaimRun('${x.run_id}')">领取</button></td></tr>`).join("")
      + "</table>"
    : '<div class="mut">（暂无就绪任务——可能全部已领取、已完成，或依赖尚未通过）</div>';
  // 当前租约
  $("lz-leases").innerHTML = pool.leases.length
    ? `<table><tr><th>run / 检查</th><th>状态</th><th>持有者</th><th>代次</th><th>剩余</th>
           <th>TTL</th><th>操作</th></tr>` +
      pool.leases.map(l=>{
        const rem = l.remaining_seconds;
        const remCls = l.state!=="HELD" ? "mut" : rem>15 ? "ok" : "bad";
        const remTxt = l.state==="HELD" ? `${rem}s` : "—";
        const acts = l.state==="HELD"
          ? `<button onclick='leaseComplete(${JSON.stringify(l.run_id)},${JSON.stringify(l.check_type)},${JSON.stringify(l.eco_id)},${l.generation},${JSON.stringify(l.lease_token)},"PASS")'>交结果PASS</button>
             <button class="danger" onclick='leaseComplete(${JSON.stringify(l.run_id)},${JSON.stringify(l.check_type)},${JSON.stringify(l.eco_id)},${l.generation},${JSON.stringify(l.lease_token)},"FAIL")'>FAIL</button>
             <button class="sec" onclick="leaseRenew('${l.run_id}',${l.generation},${JSON.stringify(l.lease_token)})">续租</button>
             <button class="sec" onclick="leaseRelease('${l.run_id}',${l.generation},${JSON.stringify(l.lease_token)})">释放</button>
             <button class="danger" onclick="leaseTakeover('${l.run_id}')">超时接管</button>`
          : (l.state==="EXPIRED"
             ? `<button class="sec" onclick="leaseClaimRun('${l.run_id}')">重新领取</button>
                <button class="danger" onclick="leaseTakeover('${l.run_id}')">接管</button>`
             : "");
        return `<tr>
          <td class="mono">${l.run_id}</td>
          <td><b>${LEASE_STATE_CN[l.state]||l.state}</b>${l.alive?"":""}</td>
          <td>${esc(l.runner_id||"")}</td>
          <td>g${l.generation}${l.renew_count?` <span class="mut">心跳${l.renew_count}</span>`:""}</td>
          <td class="${remCls}">${remTxt}</td>
          <td class="mut">${l.ttl_seconds}s</td>
          <td>${acts}
              <button class="sec" onclick="leaseHistory('${l.run_id}')">历史</button></td></tr>`;
      }).join("") + "</table>"
    : '<div class="mut">（暂无租约）</div>';
  // 审计
  $("lz-audit-count").textContent = `最近 ${au.count} 条`;
  $("lz-audit").innerHTML = au.audit.length
    ? `<table><tr><th>时间</th><th>事件</th><th>run</th><th>Runner</th><th>代次</th><th>拒绝原因</th></tr>` +
      au.audit.map(h=>`<tr>
        <td class="mut">${(h.at||"").slice(11)}</td>
        <td>${h.event==="deny"?'<span class="bad">拒绝</span>':h.event}</td>
        <td class="mono">${h.run_id?h.run_id.split(":").slice(1,3).join(":"):""}</td>
        <td>${esc(h.runner_id||"")}</td>
        <td>${h.generation??""}</td>
        <td class="bad">${h.reason||""}</td></tr>`).join("") + "</table>"
    : '<div class="mut">（暂无租约事件）</div>';
}

setDefaultTimes();
refresh().catch(e=>toast(e.message,"err"));
loadLeases().catch(e=>toast(e.message,"err"));
