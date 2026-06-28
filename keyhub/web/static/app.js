// KeyHub 前端：极简单页应用，通过 fetch 调用 /api/*。
const api = async (path, opts = {}) => {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail || msg; } catch {}
    throw new Error(msg);
  }
  if (res.status === 204) return null;
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
};

const el = (id) => document.getElementById(id);
const show = (id, on) => el(id)?.classList.toggle('hidden', !on);
const err = (id, msg) => { const e = el(id); if (e) e.textContent = msg || ''; };

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// ===== 通用 =====
async function postJSON(path, body) {
  return api(path, { method: 'POST', body: JSON.stringify(body) });
}
async function patchJSON(path, body) {
  return api(path, { method: 'PATCH', body: JSON.stringify(body) });
}

// ===== 初始化页 =====
window.initSubmit = async function () {
  const pw = el('pw').value;
  const pw2 = el('pw2').value;
  err('err', '');
  if (pw.length < 8) { err('err', '密码至少 8 位'); return; }
  if (pw !== pw2) { err('err', '两次密码不一致'); return; }
  try {
    await postJSON('/api/auth/init', { password: pw });
    location.reload();
  } catch (e) { err('err', e.message); }
};

// ===== 解锁页 =====
window.unlockSubmit = async function () {
  err('err', '');
  try {
    await postJSON('/api/auth/unlock', { password: el('pw').value });
    location.reload();
  } catch (e) { err('err', e.message); }
};

// ===== 控制台 =====
window.addEventListener('DOMContentLoaded', () => {
  if (!el('panel')) return;
  loadCreds();
  loadLLM();
  loadUsage();
  loadReminders();
  loadStats();
});

function switchTab(name) {
  ['creds', 'llm', 'usage', 'rotation'].forEach(n => {
    show('tab-' + n, n === name);
    el('t-' + n)?.classList.toggle('active', n === name);
  });
  if (name === 'rotation') loadReminders();
  if (name === 'usage') loadUsage();
  if (name === 'llm') loadLLM();
}
window.switchTab = switchTab;

async function loadCreds() {
  try {
    const list = await api('/api/credentials');
    const tbody = el('cred-tbody');
    if (!list.length) { tbody.innerHTML = '<tr><td colspan="6" class="muted">暂无凭证</td></tr>'; return; }
    // 使用 data-* 属性承载动态值，避免内联 onclick 的 XSS 风险
    tbody.innerHTML = list.map(c => `
      <tr>
        <td>${esc(c.name)}</td>
        <td><span class="tag">${esc(c.type)}</span></td>
        <td>${c.provider ? esc(c.provider) + '/' + esc(c.label) : '<span class="muted">-</span>'}</td>
        <td>${c.llm_status ? `<span class="tag ${c.llm_status === 'active' ? 'ok' : 'warn'}">${esc(c.llm_status)}</span>` : '<span class="muted">-</span>'}</td>
        <td>${c.expires_at ? esc(c.expires_at.slice(0, 10)) : '<span class="muted">-</span>'}</td>
        <td>
          <button class="small secondary" data-action="reveal" data-name="${esc(c.name)}">查看</button>
          <button class="small secondary" data-action="rotate" data-name="${esc(c.name)}">轮换</button>
          <button class="small danger" data-action="del" data-name="${esc(c.name)}">删</button>
        </td>
      </tr>`).join('');
    // 事件委托：避免内联 onclick 拼接 JS 字符串导致的 XSS
    tbody.querySelectorAll('button[data-action]').forEach(btn => {
      btn.addEventListener('click', () => {
        const action = btn.dataset.action;
        const name = btn.dataset.name;
        if (action === 'reveal') reveal(name);
        else if (action === 'rotate') rotate(name);
        else if (action === 'del') del(name);
      });
    });
  } catch (e) { console.error(e); }
}
window.loadCreds = loadCreds;

window.createCred = async function () {
  const body = {
    name: el('c-name').value,
    type: el('c-type').value,
    value: el('c-value').value,
    provider: el('c-provider').value || null,
    label: el('c-label').value || null,
    rotation_days: el('c-rot').value ? parseInt(el('c-rot').value) : null,
  };
  err('c-err', '');
  try {
    await postJSON('/api/credentials', body);
    ['c-name', 'c-value', 'c-provider', 'c-label', 'c-rot'].forEach(i => el(i).value = '');
    loadCreds(); loadStats();
  } catch (e) { err('c-err', e.message); }
};

window.reveal = async function (name) {
  try {
    const r = await api('/api/credentials/' + encodeURIComponent(name) + '/reveal');
    const box = el('secret-box');
    box.textContent = r.value;
    el('secret-name').textContent = name;
    show('secret-modal', true);
  } catch (e) { alert(e.message); }
};
window.closeSecret = () => { show('secret-modal', false); el('secret-box').textContent = ''; };

window.rotate = async function (name) {
  const nv = prompt('输入新值（明文）：');
  if (nv === null) return;
  try {
    await api(`/api/credentials/${encodeURIComponent(name)}/rotate?new_value=${encodeURIComponent(nv)}`, { method: 'POST' });
    loadCreds();
  } catch (e) { alert(e.message); }
};

window.del = async function (name) {
  if (!confirm(`删除 ${name}？`)) return;
  try {
    await api('/api/credentials/' + encodeURIComponent(name), { method: 'DELETE' });
    loadCreds(); loadStats();
  } catch (e) { alert(e.message); }
};

window.logout = async function () {
  await api('/api/auth/logout', { method: 'POST' });
  location.reload();
};

// ===== LLM =====
async function loadLLM() {
  try {
    const [keys, cost] = await Promise.all([api('/api/llm/keys'), api('/api/llm/cost')]);
    el('llm-keys').innerHTML = keys.length ? keys.map(k => `
      <tr>
        <td>${esc(k.provider)}</td>
        <td>${esc(k.label)} <span class="muted">(${esc(k.name)})</span></td>
        <td><span class="tag ${k.status === 'active' ? 'ok' : 'warn'}">${esc(k.status)}</span></td>
        <td>${k.total_requests}</td>
        <td>${k.estimated_cost_usd.toFixed(4)}</td>
        <td>
          <button class="small secondary" data-action="key-active" data-id="${esc(k.id)}">启用</button>
          <button class="small secondary" data-action="key-disabled" data-id="${esc(k.id)}">停用</button>
        </td>
      </tr>`).join('') : '<tr><td colspan="6" class="muted">暂无 LLM key</td></tr>';
    // 事件委托替代内联 onclick
    el('llm-keys').querySelectorAll('button[data-action]').forEach(btn => {
      btn.addEventListener('click', () => setKeyStatus(btn.dataset.id, btn.dataset.action === 'key-active' ? 'active' : 'disabled'));
    });
    let costHtml = '';
    for (const [p, v] of Object.entries(cost)) {
      costHtml += `<div class="stat"><div class="num">$${v.cost_usd.toFixed(4)}</div><div class="lbl">${esc(p)} · ${v.calls} 次调用</div></div>`;
    }
    el('llm-cost').innerHTML = costHtml || '<div class="muted">暂无用量</div>';
  } catch (e) { console.error(e); }
}
window.loadLLM = loadLLM;

window.setKeyStatus = async function (id, status) {
  try {
    await api(`/api/llm/keys/${id}/status?status=${status}`, { method: 'PATCH' });
    loadLLM();
  } catch (e) { alert(e.message); }
};

window.llmChat = async function () {
  err('llm-err', '');
  el('llm-out').textContent = '调用中...';
  try {
    const body = {
      provider: el('l-provider').value,
      model: el('l-model').value,
      messages: [{ role: 'user', content: el('l-input').value }],
    };
    const r = await postJSON('/api/llm/chat', body);
    const text = r.choices ? r.choices[0]?.message?.content
      : (r.content ? r.content[0]?.text : JSON.stringify(r, null, 2));
    el('llm-out').textContent = text || '(空响应)';
    loadLLM(); loadUsage(); loadStats();
  } catch (e) { err('llm-err', e.message); el('llm-out').textContent = ''; }
};

// ===== Usage =====
async function loadUsage() {
  try {
    const list = await api('/api/llm/usage?limit=50');
    el('usage-tbody').innerHTML = list.length ? list.map(u => `
      <tr>
        <td>${esc(u.created_at?.replace('T', ' ').slice(0, 19))}</td>
        <td>${esc(u.provider)}/${esc(u.label)}</td>
        <td>${esc(u.model)}</td>
        <td>${u.prompt_tokens}/${u.completion_tokens}</td>
        <td>$${u.cost_usd.toFixed(5)}</td>
        <td>${u.latency_ms}ms</td>
        <td>${u.success ? '<span class="tag ok">ok</span>' : '<span class="tag danger">fail</span>'}</td>
      </tr>`).join('') : '<tr><td colspan="7" class="muted">暂无调用记录</td></tr>';
  } catch (e) { console.error(e); }
}
window.loadUsage = loadUsage;

// ===== Rotation =====
async function loadReminders() {
  try {
    const list = await api('/api/rotation/reminders');
    el('rot-tbody').innerHTML = list.length ? list.map(r => {
      let badge = '<span class="tag">建议轮换</span>';
      if (r.days_until_expire !== null && r.days_until_expire < 0) badge = '<span class="tag danger">已过期</span>';
      else if (r.days_until_expire !== null && r.days_until_expire <= 7) badge = '<span class="tag warn">即将到期</span>';
      return `<tr>
        <td>${esc(r.name)}</td>
        <td><span class="tag">${esc(r.type)}</span></td>
        <td>${r.days_until_expire === null ? '-' : r.days_until_expire + ' 天'}</td>
        <td>${r.days_since_rotation === null ? '-' : r.days_since_rotation + ' 天前'}</td>
        <td>${badge}</td>
      </tr>`;
    }).join('') : '<tr><td colspan="5" class="muted">无需轮换的凭证 🎉</td></tr>';
  } catch (e) { console.error(e); }
}
window.loadReminders = loadReminders;

// ===== Stats =====
async function loadStats() {
  try {
    const [creds, keys] = await Promise.all([api('/api/credentials'), api('/api/llm/keys')]);
    el('stat-creds').textContent = creds.length;
    el('stat-llm').textContent = keys.length;
    el('stat-active').textContent = keys.filter(k => k.status === 'active').length;
    const totalCost = keys.reduce((s, k) => s + (k.estimated_cost_usd || 0), 0);
    el('stat-cost').textContent = '$' + totalCost.toFixed(4);
  } catch (e) { console.error(e); }
}
