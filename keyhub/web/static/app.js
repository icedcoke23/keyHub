// ============================================================
// KeyHub 前端：加密终端控制台
// ============================================================

// ===== API 封装（带 401 自动跳转、错误归一化）=====
// 标记是否正在处理 401 跳转，避免重复跳转与循环
let _handling401 = false;
// sessionStorage 键：记录 401 重定向次数，跨页面重载防循环
const _REDIRECT_KEY = '_kh_401_redirects';
const _REDIRECT_MAX = 1; // 最多自动重定向 1 次，超过则停止

function _redirectCount() {
  try { return parseInt(sessionStorage.getItem(_REDIRECT_KEY) || '0', 10); } catch { return 0; }
}
function _bumpRedirect() {
  try { sessionStorage.setItem(_REDIRECT_KEY, String(_redirectCount() + 1)); } catch {}
}
function _clearRedirect() {
  try { sessionStorage.removeItem(_REDIRECT_KEY); } catch {}
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (res.status === 401) {
    // session 过期 → 先清除 cookie 再跳回解锁页
    // 调用 /api/auth/logout 确保浏览器删除 session cookie，
    // 避免后端仍认为 session 有效而渲染 panel 导致循环
    if (!_handling401) {
      _handling401 = true;
      const count = _redirectCount();
      if (count >= _REDIRECT_MAX) {
        // 已重定向过但仍 401：停止自动重定向，避免死循环
        _clearRedirect();
        toast('会话已过期，自动跳转失败。请手动刷新或重新解锁。', 'error', 8000);
        throw new Error('会话已过期，请手动刷新页面');
      }
      _bumpRedirect();
      toast('会话已过期，正在跳转解锁页…', 'info', 2000);
      // 先清除 session cookie，再跳转
      try { await fetch('/api/auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' } }); } catch {}
      setTimeout(() => { location.href = '/'; }, 800);
    }
    throw new Error('会话已过期，请重新解锁');
  }
  // 收到非 401 响应说明 session 有效，清除重定向计数
  _clearRedirect();
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
  t.style.setProperty('--toast-duration', duration + 'ms');
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
  // 初始化 tab ARIA 状态
  ['creds', 'llm', 'usage', 'rotation', 'audit', 'security'].forEach(n => {
    const panel = el('tab-' + n);
    const tab = el('t-' + n);
    const active = n === 'creds';
    if (panel) panel.setAttribute('aria-hidden', active ? 'false' : 'true');
    if (tab) {
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.setAttribute('tabindex', active ? '0' : '-1');
    }
  });
  loadCreds();
  loadLLM();
  loadStats();
  initChatInput();
  // 审计/Token 懒加载（切 tab 时再加载）
});

function switchTab(name) {
  const tabs = ['creds', 'llm', 'usage', 'rotation', 'audit', 'security'];
  tabs.forEach(n => {
    const panel = el('tab-' + n);
    const tab = el('t-' + n);
    const active = n === name;
    show('tab-' + n, active);
    if (tab) {
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.setAttribute('tabindex', active ? '0' : '-1');
    }
    if (panel) panel.setAttribute('aria-hidden', active ? 'false' : 'true');
  });
  if (name !== 'audit') {
    disconnectAuditSSE();
  }
  if (name === 'rotation') loadReminders();
  if (name === 'usage') { loadUsage(); setTimeout(loadCostTrend, 80); }
  if (name === 'llm') loadLLM();
  if (name === 'audit') loadAudit();
  if (name === 'security') loadTokens();
}
window.switchTab = switchTab;

// Tab 键盘导航
document.addEventListener('keydown', (e) => {
  const activeTab = document.querySelector('.tab.active');
  if (!activeTab || document.activeElement !== activeTab) return;
  const tabs = Array.from(document.querySelectorAll('.tab'));
  const idx = tabs.indexOf(activeTab);
  if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
    e.preventDefault();
    const next = tabs[(idx + 1) % tabs.length];
    next.click(); next.focus();
  } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
    e.preventDefault();
    const prev = tabs[(idx - 1 + tabs.length) % tabs.length];
    prev.click(); prev.focus();
  } else if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    activeTab.click();
  }
});

// ===== 凭证 =====
async function loadCreds() {
  const tbody = el('cred-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="7"><div class="skeleton" style="height:14px;width:80%"></div></td></tr>';
  try {
    const search = el('c-search')?.value?.trim() || '';
    const tagFilter = el('c-tag-filter')?.value?.trim() || '';
    let url = '/api/credentials';
    const params = [];
    if (search) params.push('q=' + encodeURIComponent(search));
    if (tagFilter) params.push('tag=' + encodeURIComponent(tagFilter));
    if (params.length) url += '?' + params.join('&');

    const creds = await api(url);
    if (!creds.length) {
      tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state"><div class="empty-state-icon">🗂️</div><div class="empty-state-text">${search || tagFilter ? '没有匹配的凭证' : '暂无凭证，请在上方添加'}</div></div></td></tr>`;
      return;
    }
    tbody.innerHTML = creds.map(c => `
      <tr style="animation:fadeInUp 0.4s var(--ease-out-expo) both">
        <td><strong>${esc(c.name)}</strong></td>
        <td><span class="tag">${esc(c.type)}</span></td>
        <td>${c.provider ? esc(c.provider) + '/' + esc(c.label || '') : '<span class="muted">-</span>'}</td>
        <td>${c.llm_status ? `<span class="tag ${c.llm_status === 'active' ? 'ok' : 'warn'}">${esc(c.llm_status)}</span>` : '<span class="muted">-</span>'}</td>
        <td>${c.expires_at ? esc(c.expires_at.slice(0, 10)) : '<span class="muted">-</span>'}</td>
        <td>${(c.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join(' ') || '<span class="muted">-</span>'}</td>
        <td>
          <button class="small secondary" data-action="reveal" data-name="${esc(c.name)}">查看</button>
          <button class="small secondary" data-action="rotate" data-name="${esc(c.name)}">轮换</button>
          <button class="small danger" data-action="del" data-name="${esc(c.name)}">删</button>
        </td>
      </tr>`).join('');
  } catch (e) { toast('加载失败: ' + e.message, 'error'); }
}
window.loadCreds = loadCreds;

// 凭证操作事件委托
document.addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn || !btn.closest('#cred-tbody')) return;
  const action = btn.dataset.action;
  const name = btn.dataset.name;
  if (action === 'reveal') reveal(name);
  else if (action === 'rotate') rotate(name);
  else if (action === 'del') del(name);
});

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
  if (!nv || !nv.trim()) { toast('新值不能为空', 'error'); return; }
  try {
    await api(`/api/credentials/${encodeURIComponent(name)}/rotate`, {
      method: 'POST',
      body: JSON.stringify({ new_value: nv }),
    });
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
let chatHistory = [];
let isGenerating = false;

async function loadLLM() {
  if (!el('llm-keys')) return;
  try {
    const [keys, cost] = await Promise.all([api('/api/llm/keys'), api('/api/llm/cost')]);
    el('llm-keys').innerHTML = keys.length ? keys.map(k => `
      <tr style="animation:fadeInUp 0.4s var(--ease-out-expo) both">
        <td><strong>${esc(k.provider)}</strong></td>
        <td>${esc(k.label)} <span class="muted">(${esc(k.name)})</span></td>
        <td><span class="tag ${k.status === 'active' ? 'ok' : 'warn'}">${esc(k.status)}</span></td>
        <td>${k.total_requests}</td>
        <td>$${k.estimated_cost_usd.toFixed(4)}</td>
        <td>
          <button class="small secondary" data-key-action="active" data-id="${esc(k.id)}">启用</button>
          <button class="small secondary" data-key-action="disabled" data-id="${esc(k.id)}">停用</button>
        </td>
      </tr>`).join('') : `<tr><td colspan="6"><div class="empty-state"><div class="empty-state-icon">🤖</div><div class="empty-state-text">暂无 LLM key</div></div></td></tr>`;
    let costHtml = '';
    for (const [p, v] of Object.entries(cost)) {
      costHtml += `<div class="stat" style="animation:fadeInUp 0.5s var(--ease-out-expo) both"><div class="num accent">$${v.cost_usd.toFixed(4)}</div><div class="lbl">${esc(p)} · ${v.calls} 次调用</div></div>`;
    }
    el('llm-cost').innerHTML = costHtml || '<div class="empty-state" style="padding:24px"><div class="empty-state-icon">📊</div><div class="empty-state-text">暂无用量</div></div>';
    loadChatModels();
  } catch (e) { console.error(e); }
}
window.loadLLM = loadLLM;

// LLM key 操作事件委托
document.addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-key-action]');
  if (!btn || !btn.closest('#llm-keys')) return;
  setKeyStatus(btn.dataset.id, btn.dataset.keyAction);
});

async function loadChatModels() {
  const sel = el('chat-model');
  if (!sel) return;
  try {
    const data = await api('/v1/models');
    const models = data.data || [];
    if (!models.length) {
      sel.innerHTML = '<option value="">无可用模型</option>';
      return;
    }
    const grouped = {};
    models.forEach(m => {
      const provider = m.owned_by || 'other';
      if (!grouped[provider]) grouped[provider] = [];
      grouped[provider].push(m);
    });
    let html = '';
    for (const [provider, ms] of Object.entries(grouped)) {
      html += `<optgroup label="${esc(provider)}">`;
      ms.forEach(m => {
        html += `<option value="${esc(m.id)}">${esc(m.id)}</option>`;
      });
      html += '</optgroup>';
    }
    sel.innerHTML = html;
    const preferred = ['gpt-4o-mini', 'gpt-3.5-turbo', 'claude-3-haiku', 'deepseek-chat'];
    for (const p of preferred) {
      const opt = Array.from(sel.options).find(o => o.value === p);
      if (opt) { sel.value = p; break; }
    }
  } catch (e) {
    sel.innerHTML = '<option value="">加载失败</option>';
    console.error('load models:', e);
  }
}

window.setKeyStatus = async function (id, status) {
  try {
    await api(`/api/llm/keys/${id}/status?status=${status}`, { method: 'PATCH' });
    toast(`Key 已${status === 'active' ? '启用' : '停用'}`, 'success', 2000);
    loadLLM();
  } catch (e) { toast(e.message, 'error'); }
};

// ===== Markdown 渲染（纯 JS 实现）=====
function renderMarkdown(text) {
  let html = esc(text);

  html = html.replace(/```([\s\S]*?)```/g, (match, code) => {
    return `<pre class="md-code-block"><code>${code.trim()}</code></pre>`;
  });

  html = html.replace(/`([^`]+)`/g, '<code class="md-code">$1</code>');

  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/__([^_]+)__/g, '<strong>$1</strong>');

  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  html = html.replace(/_([^_]+)_/g, '<em>$1</em>');

  const lines = html.split('\n');
  const result = [];
  let inList = false;
  let listType = null;

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    const ulMatch = line.match(/^\s*[-*+]\s+(.*)/);
    const olMatch = line.match(/^\s*\d+\.\s+(.*)/);

    if (ulMatch) {
      if (!inList || listType !== 'ul') {
        if (inList) result.push(listType === 'ul' ? '</ul>' : '</ol>');
        result.push('<ul class="md-list">');
        inList = true;
        listType = 'ul';
      }
      result.push(`<li>${ulMatch[1]}</li>`);
    } else if (olMatch) {
      if (!inList || listType !== 'ol') {
        if (inList) result.push(listType === 'ul' ? '</ul>' : '</ol>');
        result.push('<ol class="md-list">');
        inList = true;
        listType = 'ol';
      }
      result.push(`<li>${olMatch[1]}</li>`);
    } else {
      if (inList) {
        result.push(listType === 'ul' ? '</ul>' : '</ol>');
        inList = false;
        listType = null;
      }
      if (line.trim()) {
        result.push(`<p>${line}</p>`);
      }
    }
  }
  if (inList) {
    result.push(listType === 'ul' ? '</ul>' : '</ol>');
  }

  return result.join('\n');
}

// ===== Playground 聊天界面 =====
function scrollChatToBottom() {
  const container = el('chat-messages');
  if (container) {
    container.scrollTop = container.scrollHeight;
  }
}

function addMessage(role, content, streaming = false) {
  const container = el('chat-messages');
  if (!container) return;

  const welcome = container.querySelector('.chat-welcome');
  if (welcome) welcome.remove();

  const msgDiv = document.createElement('div');
  msgDiv.className = `chat-message ${role}`;
  msgDiv.dataset.role = role;

  const avatar = document.createElement('div');
  avatar.className = 'chat-avatar';
  avatar.textContent = role === 'user' ? '👤' : '🤖';

  const bubble = document.createElement('div');
  bubble.className = 'chat-bubble';
  if (streaming) {
    bubble.classList.add('streaming');
    bubble.innerHTML = '<span class="chat-cursor"></span>';
  } else {
    bubble.innerHTML = renderMarkdown(content);
  }

  msgDiv.appendChild(avatar);
  msgDiv.appendChild(bubble);
  container.appendChild(msgDiv);
  scrollChatToBottom();
  return bubble;
}

function updateStreamingMessage(bubble, content) {
  if (!bubble) return;
  bubble.innerHTML = renderMarkdown(content) + '<span class="chat-cursor"></span>';
  scrollChatToBottom();
}

function finishStreamingMessage(bubble, content) {
  if (!bubble) return;
  bubble.classList.remove('streaming');
  bubble.innerHTML = renderMarkdown(content);
  scrollChatToBottom();
}

function showChatError(msg) {
  const errEl = el('chat-err');
  if (errEl) {
    errEl.textContent = msg;
    errEl.style.display = 'block';
    setTimeout(() => { errEl.style.display = 'none'; }, 5000);
  }
}

function setGeneratingState(generating) {
  isGenerating = generating;
  const sendBtn = el('chat-send-btn');
  const stopBtn = el('chat-stop-btn');
  const input = el('chat-input');
  if (sendBtn) sendBtn.disabled = generating;
  if (stopBtn) stopBtn.disabled = !generating;
  if (input) input.disabled = generating;
}

window.clearChat = function() {
  chatHistory = [];
  const container = el('chat-messages');
  if (container) {
    container.innerHTML = `
      <div class="chat-welcome">
        <div class="chat-welcome-icon">💬</div>
        <div class="chat-welcome-text">选择模型，开始对话</div>
      </div>`;
  }
};

window.stopChatPlayground = function() {
  if (chatAbortController) {
    chatAbortController.abort();
  }
};

window.sendChatMessage = async function() {
  if (isGenerating) return;
  const input = el('chat-input');
  const modelSel = el('chat-model');
  if (!input || !modelSel) return;

  const content = input.value.trim();
  const model = modelSel.value;
  if (!content) return;
  if (!model) {
    showChatError('请先选择模型');
    return;
  }

  chatHistory.push({ role: 'user', content: content });
  addMessage('user', content);
  input.value = '';
  input.style.height = 'auto';

  setGeneratingState(true);
  const assistantBubble = addMessage('assistant', '', true);
  let assistantContent = '';

  try {
    chatAbortController = new AbortController();
    const res = await fetch('/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: model,
        messages: chatHistory,
        stream: true,
      }),
      signal: chatAbortController.signal,
    });

    if (!res.ok) {
      let msg = res.statusText;
      try {
        const errJson = await res.json();
        msg = errJson.error?.message || errJson.detail || msg;
      } catch {}
      throw new Error(msg);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6).trim();
        if (data === '[DONE]') continue;
        if (!data) continue;

        try {
          const obj = JSON.parse(data);
          if (obj.error) {
            const errMsg = typeof obj.error === 'string' ? obj.error : (obj.error.message || '流式响应错误');
            throw new Error(errMsg);
          }
          const delta = obj.choices?.[0]?.delta?.content;
          if (delta) {
            assistantContent += delta;
            updateStreamingMessage(assistantBubble, assistantContent);
          }
        } catch (e) {
          if (e instanceof SyntaxError) continue;
          throw e;
        }
      }
    }

    if (assistantContent) {
      chatHistory.push({ role: 'assistant', content: assistantContent });
      finishStreamingMessage(assistantBubble, assistantContent);
    } else {
      finishStreamingMessage(assistantBubble, '(空响应)');
    }
    loadLLM(); loadUsage(); loadStats();
  } catch (e) {
    if (e.name === 'AbortError') {
      finishStreamingMessage(assistantBubble, assistantContent + '\n\n[已停止]');
      if (assistantContent) {
        chatHistory.push({ role: 'assistant', content: assistantContent });
      }
    } else {
      showChatError(e.message);
      if (assistantBubble) assistantBubble.remove();
      // 请求失败：回滚已压入 chatHistory 的用户消息，避免下次发送时
      // 把失败消息再次发给上游导致上下文错乱
      chatHistory.pop();
    }
  } finally {
    setGeneratingState(false);
    chatAbortController = null;
    input.focus();
  }
};

function initChatInput() {
  const input = el('chat-input');
  if (!input) return;

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage();
    }
  });

  input.addEventListener('input', () => {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 200) + 'px';
  });
}

// 保留旧函数以兼容（但不再使用）
window.llmChat = async function () {};
window.stopChat = function() { stopChatPlayground(); };

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
        if (obj.error) { throw new Error(typeof obj.error === 'string' ? obj.error : obj.error.message || obj.error); }
        const delta = obj.choices?.[0]?.delta?.content;
        if (delta) { fullText += delta; out.textContent = fullText; }
        const anthDelta = obj.delta?.text;
        if (anthDelta) { fullText += anthDelta; out.textContent = fullText; }
      } catch { /* 非 JSON 行忽略 */ }
    }
  }
  if (!fullText) out.textContent = '(空响应)';
}

// ===== Usage =====
async function loadUsage() {
  if (!el('usage-tbody')) return;
  try {
    const list = await api('/api/llm/usage?limit=50');
    el('usage-tbody').innerHTML = list.length ? list.map(u => `
      <tr style="animation:fadeInUp 0.35s var(--ease-out-expo) both">
        <td>${esc(u.created_at?.replace('T', ' ').slice(0, 19))}</td>
        <td>${esc(u.provider)}/${esc(u.label)}</td>
        <td>${esc(u.model)}</td>
        <td>${u.prompt_tokens}/${u.completion_tokens}</td>
        <td>$${u.cost_usd.toFixed(5)}</td>
        <td>${u.latency_ms}ms</td>
        <td>${u.success ? '<span class="tag ok">ok</span>' : '<span class="tag danger">fail</span>'}</td>
      </tr>`).join('') : `<tr><td colspan="7"><div class="empty-state"><div class="empty-state-icon">📈</div><div class="empty-state-text">暂无调用记录</div></div></td></tr>`;
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
      return `<tr style="animation:fadeInUp 0.35s var(--ease-out-expo) both">
        <td><strong>${esc(r.name)}</strong></td>
        <td><span class="tag">${esc(r.type)}</span></td>
        <td>${r.days_until_expire === null ? '-' : r.days_until_expire + ' 天'}</td>
        <td>${r.days_since_rotation === null ? '-' : r.days_since_rotation + ' 天前'}</td>
        <td>${badge}</td>
      </tr>`;
    }).join('') : `<tr><td colspan="5"><div class="empty-state"><div class="empty-state-icon">🛡️</div><div class="empty-state-text">无需轮换的凭证</div></div></td></tr>`;
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
let auditEventSource = null;

function appendAuditEntry(x) {
  const list = el('audit-list');
  if (!list) return;
  const emptyMsg = list.querySelector('.empty-state');
  if (emptyMsg) {
    list.innerHTML = '';
  }
  const loading = list.querySelector('.loading');
  if (loading) return;
  const time = esc(x.created_at?.replace('T', ' ').slice(0, 19) || '-');
  const detailStr = x.detail ? Object.entries(x.detail).map(([k, v]) => `${esc(k)}=${esc(String(v))}`).join(' ') : '';
  const item = document.createElement('div');
  item.className = 'audit-item';
  item.style.animation = 'fadeInUp 0.3s ease';
  item.innerHTML = `
    <span class="audit-time">${time}</span>
    <span class="audit-action ${x.success ? '' : 'failed'}">${esc(x.action)}</span>
    <span class="audit-detail">${esc(x.target || '')}${detailStr ? ' · ' + detailStr : ''}</span>
    <span class="audit-actor">${esc(x.actor)}</span>
  `;
  list.insertBefore(item, list.firstChild);
  while (list.children.length > 200) {
    list.removeChild(list.lastChild);
  }
}

function connectAuditSSE() {
  disconnectAuditSSE();
  try {
    auditEventSource = new EventSource('/api/events/audit');
    auditEventSource.onmessage = (e) => {
      try {
        const entry = JSON.parse(e.data);
        appendAuditEntry(entry);
      } catch (err) {
        console.error('audit sse parse:', err);
      }
    };
    auditEventSource.onerror = () => {
      console.log('[audit sse] connection error, will retry');
    };
  } catch (e) {
    console.error('audit sse connect:', e);
  }
}

function disconnectAuditSSE() {
  if (auditEventSource) {
    auditEventSource.close();
    auditEventSource = null;
  }
}

async function loadAudit() {
  if (!el('audit-list')) return;
  const action = el('a-action')?.value || '';
  el('audit-list').innerHTML = '<div class="empty-state" style="padding:28px"><span class="loading"></span><div class="empty-state-text" style="margin-top:12px">加载中...</div></div>';
  try {
    const url = '/api/audit/logs?limit=100' + (action ? `&action=${action}` : '');
    const list = await api(url);
    if (!list.length) {
      el('audit-list').innerHTML = '<div class="empty-state" style="padding:28px"><div class="empty-state-icon">📋</div><div class="empty-state-text">暂无审计记录</div></div>';
    } else {
      el('audit-list').innerHTML = list.map(x => {
        const time = esc(x.created_at?.replace('T', ' ').slice(0, 19) || '-');
        const detailStr = x.detail ? Object.entries(x.detail).map(([k, v]) => `${esc(k)}=${esc(String(v))}`).join(' ') : '';
        return `<div class="audit-item">
          <span class="audit-time">${time}</span>
          <span class="audit-action ${x.success ? '' : 'failed'}">${esc(x.action)}</span>
          <span class="audit-detail">${esc(x.target || '')}${detailStr ? ' · ' + detailStr : ''}</span>
          <span class="audit-actor">${esc(x.actor)}</span>
        </div>`;
      }).join('');
    }
    connectAuditSSE();
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
      <tr style="animation:fadeInUp 0.35s var(--ease-out-expo) both">
        <td><strong>${esc(t.name)}</strong></td>
        <td>${(t.scopes || []).map(s => `<span class="tag info">${esc(s)}</span>`).join(' ')}</td>
        <td>${esc(t.created_at?.replace('T', ' ').slice(0, 19))}</td>
        <td>${t.last_used_at ? esc(t.last_used_at.replace('T', ' ').slice(0, 19)) : '<span class="muted">从未</span>'}</td>
        <td>${t.revoked ? '<span class="tag danger">已吊销</span>' : '<span class="tag ok">有效</span>'}</td>
        <td>${t.revoked ? '' : `<button class="small danger" data-token-action="revoke" data-id="${esc(t.id)}">吊销</button>`}</td>
      </tr>`).join('') : `<tr><td colspan="6"><div class="empty-state"><div class="empty-state-icon">🔖</div><div class="empty-state-text">暂无 Token</div></div></td></tr>`;
  } catch (e) { toast(e.message, 'error'); }
}
window.loadTokens = loadTokens;

// Token 操作事件委托
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-token-action="revoke"]');
  if (!btn || !btn.closest('#token-tbody')) return;
  if (!confirm('确认吊销此 Token？吊销后立即失效，不可恢复。')) return;
  try {
    await api('/api/auth/tokens/' + btn.dataset.id, { method: 'DELETE' });
    toast('Token 已吊销', 'success');
    loadTokens();
  } catch (e) { toast(e.message, 'error'); }
});

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

// 弹层交互：点击背景关闭 / ESC 关闭
document.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal-backdrop') && !e.target.classList.contains('hidden')) {
    const id = e.target.id;
    if (id === 'secret-modal') closeSecret();
    else if (id === 'token-modal') closeTokenModal();
  }
});
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (!el('secret-modal')?.classList.contains('hidden')) closeSecret();
  if (!el('token-modal')?.classList.contains('hidden')) closeTokenModal();
});

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

// ===== 成本趋势图 =====
async function loadCostTrend() {
  try {
    const data = await api('/api/llm/cost/trend?days=7');
    const container = el('cost-trend-chart');
    if (!container) return;
    if (!data.length) {
      container.innerHTML = '<div class="empty-state" style="margin:auto"><div class="empty-state-icon">📉</div><div class="empty-state-text">暂无数据</div></div>';
      return;
    }
    const maxCost = Math.max(...data.map(d => d.cost), 0.01);
    container.innerHTML = data.map((d, i) => {
      const h = Math.max((d.cost / maxCost) * 100, 2);
      return `<div class="chart-bar" style="height:${h}%;animation:fadeInUp 0.5s var(--ease-out-expo) ${i * 0.05}s both" data-label="${d.date.slice(5)}" data-value="$${d.cost.toFixed(4)}"></div>`;
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
    if (!el('secret-modal')?.classList.contains('hidden')) closeSecret();
    else if (!el('token-modal')?.classList.contains('hidden')) closeTokenModal();
  } else if (e.key >= '1' && e.key <= '6') {
    const tabs = ['creds', 'llm', 'usage', 'rotation', 'audit', 'security'];
    const idx = parseInt(e.key) - 1;
    if (tabs[idx] && typeof switchTab === 'function') switchTab(tabs[idx]);
  }
});


