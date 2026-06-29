// ============================================================
// KeyHub 前端：加密终端控制台
// ============================================================

// ===== API 封装（带 401 自动跳转、错误归一化）=====
// 标记是否正在处理 401 跳转，避免重复跳转与循环
let _handling401 = false;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (res.status === 401) {
    // session 过期 → 跳回解锁页（首页路由会渲染解锁页）
    if (!_handling401) {
      _handling401 = true;
      toast('会话已过期，请重新解锁', 'info', 2000);
      setTimeout(() => { location.href = '/'; }, 800);
    }
    throw new Error('会话已过期，请重新解锁');
  }
  if (!res.ok) {
    let msg = res.statusText || `HTTP ${res.status}`;
    try { msg = (await res.json()).detail || msg; } catch {}
    throw new Error(msg);
  }
  if (res.status === 204) return null;
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

const el = (id) => document.getElementById(id);
const show = (id, on) => el(id)?.classList.toggle('hidden', !on);
const err = (id, msg) => { const e = el(id); if (e) e.textContent = msg || ''; };

// HTML 转义（防 XSS）
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// ===== Toast 通知系统 =====
function toast(msg, type = 'info', duration = 3500) {
  const container = el('toast-container');
  if (!container) return;
  const icons = { success: '✓', error: '✕', info: 'ℹ' };
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span class="toast-icon">${icons[type] || ''}</span><span>${esc(msg)}</span>`;
  container.appendChild(t);
  setTimeout(() => {
    t.classList.add('fade-out');
    setTimeout(() => t.remove(), 300);
  }, duration);
}
window.toast = toast;

// ===== 按钮 loading 态 =====
function withLoading(btnId, fn) {
  const btn = el(btnId);
  if (!btn) return fn();
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="loading"></span> 处理中...';
  return fn().finally(() => {
    btn.disabled = false;
    btn.innerHTML = original;
  });
}

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
    await withLoading('submit-btn', () => postJSON('/api/auth/init', { password: pw }));
    toast('金库初始化成功', 'success');
    setTimeout(() => location.reload(), 600);
  } catch (e) { err('err', e.message); }
};

// ===== 解锁页 =====
window.unlockSubmit = async function () {
  err('err', '');
  try {
    await withLoading('submit-btn', () => postJSON('/api/auth/unlock', { password: el('pw').value }));
    toast('解锁成功', 'success');
    setTimeout(() => location.reload(), 400);
  } catch (e) { err('err', e.message); }
};

// ===== 控制台主入口 =====
window.addEventListener('DOMContentLoaded', () => {
  if (!el('panel')) return;
  // LLM 输入框聚焦时全选，避免外部注入值时拼接
  ['l-provider', 'l-model'].forEach(id => {
    const inp = el(id);
    if (inp) inp.addEventListener('focus', () => inp.select());
  });
  loadCreds();
  loadLLM();
  loadStats();
  // 审计/Token 懒加载（切 tab 时再加载）
});

function switchTab(name) {
  ['creds', 'llm', 'usage', 'rotation', 'audit', 'security'].forEach(n => {
    show('tab-' + n, n === name);
    el('t-' + n)?.classList.toggle('active', n === name);
  });
  if (name === 'rotation') loadReminders();
  if (name === 'usage') loadUsage();
  if (name === 'llm') loadLLM();
  if (name === 'audit') loadAudit();
  if (name === 'security') loadTokens();
}
window.switchTab = switchTab;

// ===== 凭证 =====
async function loadCreds() {
  const tbody = el('cred-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6"><div class="skeleton" style="height:14px;width:80%"></div></td></tr>';
  try {
    const list = await api('/api/credentials');
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted" style="text-align:center;padding:24px">暂无凭证，请在上方添加</td></tr>';
      return;
    }
    tbody.innerHTML = list.map(c => `
      <tr>
        <td><strong>${esc(c.name)}</strong></td>
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
    tbody.querySelectorAll('button[data-action]').forEach(btn => {
      btn.addEventListener('click', () => {
        const action = btn.dataset.action;
        const name = btn.dataset.name;
        if (action === 'reveal') reveal(name);
        else if (action === 'rotate') rotate(name);
        else if (action === 'del') del(name);
      });
    });
  } catch (e) { toast(e.message, 'error'); }
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
  if (!body.name || !body.value) { err('c-err', '名称和明文值必填'); return; }
  err('c-err', '');
  try {
    await postJSON('/api/credentials', body);
    toast(`凭证 ${body.name} 已创建`, 'success');
    ['c-name', 'c-value', 'c-provider', 'c-label', 'c-rot'].forEach(i => el(i).value = '');
    loadCreds(); loadStats();
  } catch (e) { err('c-err', e.message); }
};

window.reveal = async function (name) {
  try {
    const r = await api('/api/credentials/' + encodeURIComponent(name) + '/reveal');
    el('secret-box').textContent = r.value;
    el('secret-name').textContent = name;
    show('secret-modal', true);
  } catch (e) { toast(e.message, 'error'); }
};
window.closeSecret = () => { show('secret-modal', false); el('secret-box').textContent = ''; };
window.copySecret = async function () {
  const text = el('secret-box').textContent;
  try {
    await navigator.clipboard.writeText(text);
    toast('已复制到剪贴板', 'success', 2000);
  } catch { toast('复制失败，请手动选择', 'error'); }
};

window.rotate = async function (name) {
  const nv = prompt(`轮换 ${name}\n输入新明文值：`);
  if (nv === null) return;
  if (!nv) { toast('新值不能为空', 'error'); return; }
  try {
    await api(`/api/credentials/${encodeURIComponent(name)}/rotate?new_value=${encodeURIComponent(nv)}`, { method: 'POST' });
    toast(`${name} 已轮换`, 'success');
    loadCreds();
  } catch (e) { toast(e.message, 'error'); }
};

window.del = async function (name) {
  if (!confirm(`确认删除凭证 ${name}？此操作可恢复（软删除）。`)) return;
  try {
    await api('/api/credentials/' + encodeURIComponent(name), { method: 'DELETE' });
    toast(`${name} 已删除`, 'success');
    loadCreds(); loadStats();
  } catch (e) { toast(e.message, 'error'); }
};

window.logout = async function () {
  try {
    await api('/api/auth/logout', { method: 'POST' });
    toast('已锁定', 'info', 1500);
    setTimeout(() => location.reload(), 500);
  } catch { location.reload(); }
};

// ===== LLM =====
let chatAbortController = null;

async function loadLLM() {
  if (!el('llm-keys')) return;
  try {
    const [keys, cost] = await Promise.all([api('/api/llm/keys'), api('/api/llm/cost')]);
    el('llm-keys').innerHTML = keys.length ? keys.map(k => `
      <tr>
        <td><strong>${esc(k.provider)}</strong></td>
        <td>${esc(k.label)} <span class="muted">(${esc(k.name)})</span></td>
        <td><span class="tag ${k.status === 'active' ? 'ok' : 'warn'}">${esc(k.status)}</span></td>
        <td>${k.total_requests}</td>
        <td>$${k.estimated_cost_usd.toFixed(4)}</td>
        <td>
          <button class="small secondary" data-action="key-active" data-id="${esc(k.id)}">启用</button>
          <button class="small secondary" data-action="key-disabled" data-id="${esc(k.id)}">停用</button>
        </td>
      </tr>`).join('') : '<tr><td colspan="6" class="muted" style="text-align:center;padding:24px">暂无 LLM key</td></tr>';
    el('llm-keys').querySelectorAll('button[data-action]').forEach(btn => {
      btn.addEventListener('click', () => setKeyStatus(btn.dataset.id, btn.dataset.action === 'key-active' ? 'active' : 'disabled'));
    });
    let costHtml = '';
    for (const [p, v] of Object.entries(cost)) {
      costHtml += `<div class="stat"><div class="num accent">$${v.cost_usd.toFixed(4)}</div><div class="lbl">${esc(p)} · ${v.calls} 次调用</div></div>`;
    }
    el('llm-cost').innerHTML = costHtml || '<div class="muted">暂无用量</div>';
  } catch (e) { console.error(e); }
}
window.loadLLM = loadLLM;

window.setKeyStatus = async function (id, status) {
  try {
    await api(`/api/llm/keys/${id}/status?status=${status}`, { method: 'PATCH' });
    toast(`Key 已${status === 'active' ? '启用' : '停用'}`, 'success', 2000);
    loadLLM();
  } catch (e) { toast(e.message, 'error'); }
};

window.llmChat = async function () {
  err('llm-err', '');
  const out = el('llm-out');
  const stream = el('l-stream')?.checked;
  const body = {
    provider: el('l-provider').value.trim(),
    model: el('l-model').value.trim(),
    messages: [{ role: 'user', content: el('l-input').value }],
  };
  if (!body.provider || !body.model) {
    err('llm-err', '供应商和模型不能为空');
    return;
  }
  if (stream) body.stream = true;

  el('llm-send-btn').disabled = true;
  el('llm-stop-btn').disabled = false;
  out.classList.add('streaming');
  out.textContent = '';

  try {
    if (stream) {
      await streamChat(body, out);
    } else {
      const r = await postJSON('/api/llm/chat', body);
      const text = r.choices ? r.choices[0]?.message?.content
        : (r.content ? r.content[0]?.text : JSON.stringify(r, null, 2));
      out.textContent = text || '(空响应)';
    }
    loadLLM(); loadUsage(); loadStats();
  } catch (e) {
    if (e.name === 'AbortError') {
      out.textContent += '\n\n[已停止]';
    } else {
      err('llm-err', e.message);
    }
  } finally {
    out.classList.remove('streaming');
    el('llm-send-btn').disabled = false;
    el('llm-stop-btn').disabled = true;
    chatAbortController = null;
  }
};

async function streamChat(body, out) {
  chatAbortController = new AbortController();
  const res = await fetch('/api/llm/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: chatAbortController.signal,
  });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail || msg; } catch {}
    throw new Error(msg);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let fullText = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const data = line.slice(6);
      if (data === '[DONE]') continue;
      try {
        const obj = JSON.parse(data);
        if (obj.error) { throw new Error(obj.error); }
        // OpenAI 格式：choices[0].delta.content
        const delta = obj.choices?.[0]?.delta?.content;
        if (delta) { fullText += delta; out.textContent = fullText; }
        // Anthropic 格式：content_block_delta
        const anthDelta = obj.delta?.text;
        if (anthDelta) { fullText += anthDelta; out.textContent = fullText; }
      } catch { /* 非 JSON 行忽略 */ }
    }
  }
  if (!fullText) out.textContent = '(空响应)';
}

window.stopChat = function () {
  if (chatAbortController) chatAbortController.abort();
};

// ===== Usage =====
async function loadUsage() {
  if (!el('usage-tbody')) return;
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
      </tr>`).join('') : '<tr><td colspan="7" class="muted" style="text-align:center;padding:24px">暂无调用记录</td></tr>';
  } catch (e) { console.error(e); }
}
window.loadUsage = loadUsage;

// ===== Rotation =====
async function loadReminders() {
  if (!el('rot-tbody')) return;
  try {
    const list = await api('/api/rotation/reminders');
    el('rot-tbody').innerHTML = list.length ? list.map(r => {
      let badge = '<span class="tag info">建议轮换</span>';
      if (r.days_until_expire !== null && r.days_until_expire < 0) badge = '<span class="tag danger">已过期</span>';
      else if (r.days_until_expire !== null && r.days_until_expire <= 7) badge = '<span class="tag warn">即将到期</span>';
      return `<tr>
        <td><strong>${esc(r.name)}</strong></td>
        <td><span class="tag">${esc(r.type)}</span></td>
        <td>${r.days_until_expire === null ? '-' : r.days_until_expire + ' 天'}</td>
        <td>${r.days_since_rotation === null ? '-' : r.days_since_rotation + ' 天前'}</td>
        <td>${badge}</td>
      </tr>`;
    }).join('') : '<tr><td colspan="5" class="muted" style="text-align:center;padding:24px">无需轮换的凭证</td></tr>';
  } catch (e) { console.error(e); }
}
window.loadReminders = loadReminders;

// ===== Stats =====
async function loadStats() {
  if (!el('stat-creds')) return;
  try {
    const [creds, keys] = await Promise.all([api('/api/credentials'), api('/api/llm/keys')]);
    el('stat-creds').textContent = creds.length;
    el('stat-llm').textContent = keys.length;
    el('stat-active').textContent = keys.filter(k => k.status === 'active').length;
    const totalCost = keys.reduce((s, k) => s + (k.estimated_cost_usd || 0), 0);
    el('stat-cost').textContent = '$' + totalCost.toFixed(4);
  } catch (e) { console.error(e); }
}

// ===== 审计日志（新增）=====
async function loadAudit() {
  if (!el('audit-list')) return;
  const action = el('a-action')?.value || '';
  el('audit-list').innerHTML = '<div style="padding:20px;text-align:center"><span class="loading"></span> 加载中...</div>';
  try {
    const url = '/api/audit/logs?limit=100' + (action ? `&action=${action}` : '');
    const list = await api(url);
    if (!list.length) {
      el('audit-list').innerHTML = '<div class="muted" style="padding:24px;text-align:center">暂无审计记录</div>';
      return;
    }
    el('audit-list').innerHTML = list.map(x => {
      const time = x.created_at?.replace('T', ' ').slice(0, 19) || '-';
      const detailStr = x.detail ? Object.entries(x.detail).map(([k, v]) => `${k}=${esc(String(v))}`).join(' ') : '';
      return `<div class="audit-item">
        <span class="audit-time">${time}</span>
        <span class="audit-action ${x.success ? '' : 'failed'}">${esc(x.action)}</span>
        <span class="audit-detail">${esc(x.target || '')}${detailStr ? ' · ' + detailStr : ''}</span>
        <span class="audit-actor">${esc(x.actor)}</span>
      </div>`;
    }).join('');
  } catch (e) { toast(e.message, 'error'); }
}
window.loadAudit = loadAudit;

// ===== 安全：改密 / Token / 通知（新增）=====
window.changePassword = async function () {
  const oldPw = el('s-old').value;
  const newPw = el('s-new').value;
  const newPw2 = el('s-new2').value;
  err('s-err', '');
  if (!oldPw) { err('s-err', '请输入旧密码'); return; }
  if (newPw.length < 8) { err('s-err', '新密码至少 8 位'); return; }
  if (newPw !== newPw2) { err('s-err', '两次新密码不一致'); return; }
  try {
    const r = await postJSON('/api/auth/change-password', { old_password: oldPw, new_password: newPw });
    toast(r.message || '主密码已变更', 'success');
    el('s-old').value = ''; el('s-new').value = ''; el('s-new2').value = '';
    setTimeout(() => location.reload(), 1500);  // 改密后 session 仍有效但需重新解锁
  } catch (e) { err('s-err', e.message); }
};

async function loadTokens() {
  if (!el('token-tbody')) return;
  try {
    const list = await api('/api/auth/tokens');
    el('token-tbody').innerHTML = list.length ? list.map(t => `
      <tr>
        <td><strong>${esc(t.name)}</strong></td>
        <td>${(t.scopes || []).map(s => `<span class="tag info">${esc(s)}</span>`).join(' ')}</td>
        <td>${esc(t.created_at?.replace('T', ' ').slice(0, 19))}</td>
        <td>${t.last_used_at ? esc(t.last_used_at.replace('T', ' ').slice(0, 19)) : '<span class="muted">从未</span>'}</td>
        <td>${t.revoked ? '<span class="tag danger">已吊销</span>' : '<span class="tag ok">有效</span>'}</td>
        <td>${t.revoked ? '' : `<button class="small danger" data-action="revoke" data-id="${esc(t.id)}">吊销</button>`}</td>
      </tr>`).join('') : '<tr><td colspan="6" class="muted" style="text-align:center;padding:24px">暂无 Token</td></tr>';
    el('token-tbody').querySelectorAll('button[data-action="revoke"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('确认吊销此 Token？吊销后立即失效，不可恢复。')) return;
        try {
          await api('/api/auth/tokens/' + btn.dataset.id, { method: 'DELETE' });
          toast('Token 已吊销', 'success');
          loadTokens();
        } catch (e) { toast(e.message, 'error'); }
      });
    });
  } catch (e) { toast(e.message, 'error'); }
}
window.loadTokens = loadTokens;

window.createToken = async function () {
  const name = el('t-name').value;
  const scopesStr = el('t-scopes').value;
  if (!name) { toast('Token 名称必填', 'error'); return; }
  const scopes = scopesStr.split(',').map(s => s.trim()).filter(Boolean);
  try {
    const r = await postJSON('/api/auth/tokens', { name, scopes });
    el('token-plain').textContent = r.token;
    show('token-modal', true);
    el('t-name').value = '';
    loadTokens();
  } catch (e) { toast(e.message, 'error'); }
};

window.closeTokenModal = () => { show('token-modal', false); el('token-plain').textContent = ''; };
window.copyToken = async function () {
  const text = el('token-plain').textContent;
  try {
    await navigator.clipboard.writeText(text);
    toast('Token 已复制', 'success', 2000);
  } catch { toast('复制失败', 'error'); }
};

window.testNotify = async function () {
  try {
    const r = await postJSON('/api/notify/test', {});
    toast(r.message || '通知已发送', 'success');
  } catch (e) { toast(e.message, 'error'); }
};

// ===== 主题切换 =====
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('keyhub-theme', next);
  const btn = document.querySelector('.theme-toggle');
  if (btn) btn.textContent = next === 'dark' ? '🌙' : '☀️';
}
// 初始化主题
(function() {
  const saved = localStorage.getItem('keyhub-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  setTimeout(() => {
    const btn = document.querySelector('.theme-toggle');
    if (btn) btn.textContent = saved === 'dark' ? '🌙' : '☀️';
  }, 100);
})();

// ===== 密码生成器 =====
async function genPassword() {
  try {
    const data = await api('/api/credentials/utils/generate-password?length=20&symbols=true');
    const inp = el('c-value');
    if (inp) {
      inp.value = data.password;
      inp.type = 'text';
      toast(`已生成密码（强度: ${data.strength.label}）`, 'success');
    }
  } catch (e) { toast('生成失败: ' + e.message, 'error'); }
}
window.genPassword = genPassword;

// ===== 凭证搜索与标签过滤 =====
// 修改 loadCreds 函数支持搜索
const _origLoadCreds = window.loadCreds;
window.loadCreds = async function() {
  const search = el('c-search')?.value || '';
  const tagFilter = el('c-tag-filter')?.value || '';
  let url = '/api/credentials';
  const params = [];
  if (search) params.push('q=' + encodeURIComponent(search));
  if (tagFilter) params.push('tag=' + encodeURIComponent(tagFilter));
  if (params.length) url += '?' + params.join('&');
  try {
    const creds = await api(url);
    const tbody = el('cred-tbody');
    if (!tbody) return;
    if (!creds.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted)">暂无凭证</td></tr>';
      return;
    }
    tbody.innerHTML = creds.map(c => `
      <tr>
        <td>${esc(c.name)}</td>
        <td>${esc(c.type)}</td>
        <td>${c.provider ? esc(c.provider) + '/' + esc(c.label || '') : '-'}</td>
        <td>${c.llm_status ? `<span class="tag ${c.llm_status === 'active' ? 'ok' : 'warn'}">${esc(c.llm_status)}</span>` : '-'}</td>
        <td>${c.expires_at ? esc(c.expires_at.slice(0,10)) : '-'}</td>
        <td>${(c.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join(' ') || '-'}</td>
        <td>
          <button class="small secondary" onclick="reveal('${esc(c.name)}')">查看</button>
          <button class="small secondary" onclick="rotate('${esc(c.name)}')">轮换</button>
          <button class="small danger" onclick="del('${esc(c.name)}')">删</button>
        </td>
      </tr>
    `).join('');
  } catch (e) { toast('加载失败: ' + e.message, 'error'); }
};

// ===== 成本趋势图 =====
async function loadCostTrend() {
  try {
    const data = await api('/api/llm/cost/trend?days=7');
    const container = el('cost-trend-chart');
    if (!container) return;
    if (!data.length) {
      container.innerHTML = '<div style="margin:auto;color:var(--muted)">暂无数据</div>';
      return;
    }
    const maxCost = Math.max(...data.map(d => d.cost), 0.01);
    container.innerHTML = data.map(d => {
      const h = Math.max((d.cost / maxCost) * 100, 2);
      return `<div class="chart-bar" style="height:${h}%" data-label="${d.date.slice(5)}" data-value="$${d.cost.toFixed(4)}"></div>`;
    }).join('');
  } catch (e) { console.error('cost trend:', e); }
}
window.loadCostTrend = loadCostTrend;

// ===== 快捷键 =====
document.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
    if (e.key === 'Escape') e.target.blur();
    return;
  }
  if (e.key === '/') {
    e.preventDefault();
    const s = el('c-search');
    if (s) s.focus();
  } else if (e.key === 'Escape') {
    const modal = document.querySelector('.modal:not(.hidden)');
    if (modal) modal.classList.add('hidden');
  } else if (e.key >= '1' && e.key <= '6') {
    const tabs = ['creds', 'llm', 'usage', 'rotation', 'audit', 'security'];
    const idx = parseInt(e.key) - 1;
    if (tabs[idx] && typeof switchTab === 'function') switchTab(tabs[idx]);
  }
});

// 切换到用量 tab 时加载趋势图
const _origSwitchTab = window.switchTab;
window.switchTab = function(tab) {
  if (_origSwitchTab) _origSwitchTab(tab);
  if (tab === 'usage') setTimeout(loadCostTrend, 100);
};
