const viewTitle = document.getElementById('view-title');
const viewSubtitle = document.getElementById('view-subtitle');
const navButtons = document.querySelectorAll('.nav-btn');
const viewPanels = document.querySelectorAll('[data-view-panel]');

const keyInput = document.getElementById('key-input');
const searchBtn = document.getElementById('search-btn');
const revokeBtn = document.getElementById('revoke-btn');
const unrevokeBtn = document.getElementById('unrevoke-btn');
const copyKeyBtn = document.getElementById('copy-key');

const keyDetails = document.getElementById('key-details');
const productsEl = document.getElementById('products');
const devicesEl = document.getElementById('devices');
const eventsEl = document.getElementById('events');
const keysTableBody = document.querySelector('#keys-table tbody');

const productInput = document.getElementById('product-input');
const daysInput = document.getElementById('days-input');
const assignBtn = document.getElementById('assign-btn');
const assignStatus = document.getElementById('assign-status');

const createModal = document.getElementById('create-modal');
const createOpen = document.getElementById('create-key-open');
const createClose = document.getElementById('create-close');
const createBtn = document.getElementById('create-btn');
const createStatus = document.getElementById('create-status');
const newKeyInput = document.getElementById('new-key-input');
const newDaysInput = document.getElementById('new-days-input');
const newProductsInput = document.getElementById('new-products-input');

const refreshAll = document.getElementById('refresh-all');
const eventFilter = document.getElementById('event-filter');
const eventLimit = document.getElementById('event-limit');
const eventsRefresh = document.getElementById('events-refresh');

const statLastKey = document.getElementById('stat-last-key');
const statLastEvent = document.getElementById('stat-last-event');
const statRevoked = document.getElementById('stat-revoked');

let currentKey = '';

function setEmpty(el, text) {
  el.classList.add('empty');
  el.textContent = text;
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttr(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/'/g, '&#39;')
    .replace(/\r?\n/g, ' ');
}

function truncateText(value, maxLen) {
  const text = String(value || '');
  if (text.length <= maxLen) {
    return text;
  }
  if (maxLen <= 3) {
    return text.slice(0, maxLen);
  }
  return text.slice(0, maxLen - 3) + '...';
}

function normalizeListResponse(data, key) {
  if (Array.isArray(data)) {
    return { ok: true, [key]: data };
  }
  if (data && Array.isArray(data[key])) {
    return data;
  }
  if (data && data.ok === false) {
    return data;
  }
  return { ok: false, error: 'invalid_response' };
}

function getKeyValue(row) {
  if (!row) {
    return '-';
  }
  return row.key_plain || row.key_hash || '-';
}

function formatDeviceNumber(value, unit) {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) {
    return '';
  }
  const fixed = num.toFixed(1);
  const text = fixed.endsWith('.0') ? fixed.slice(0, -2) : fixed;
  return unit ? `${text} ${unit}` : text;
}

function parseDeviceInfo(value) {
  if (!value) {
    return {};
  }
  if (typeof value === 'object') {
    return value;
  }
  try {
    const parsed = JSON.parse(value);
    if (typeof parsed === 'string') {
      return JSON.parse(parsed);
    }
    return parsed || {};
  } catch (_) {
    return {};
  }
}

function buildDeviceSummary(info) {
  if (!info || typeof info !== 'object') {
    return '<div class="device-meta">No device details.</div>';
  }
  const lines = [];
  const nameLine = [info.name, info.os, info.build].filter(Boolean).join(' | ');
  const hwLine = [info.cpu, info.gpu].filter(Boolean).join(' | ');
  const specParts = [];
  if (info.arch) specParts.push(String(info.arch));
  if (info.cores) specParts.push(`${info.cores} cores`);
  const ram = formatDeviceNumber(info.ram_gb, 'GB RAM');
  if (ram) specParts.push(ram);
  const disk = formatDeviceNumber(info.disk_gb, 'GB disk');
  if (disk) specParts.push(disk);
  const specLine = specParts.join(' | ');
  const localeLine = [info.locale, info.timezone].filter(Boolean).join(' | ');
  if (nameLine) lines.push(`<div class="device-title">${escapeHtml(nameLine)}</div>`);
  if (hwLine) lines.push(`<div class="device-meta">${escapeHtml(hwLine)}</div>`);
  if (specLine) lines.push(`<div class="device-meta">${escapeHtml(specLine)}</div>`);
  if (localeLine) lines.push(`<div class="device-meta">${escapeHtml(localeLine)}</div>`);
  if (!lines.length) {
    return '<div class="device-meta">No device details.</div>';
  }
  return lines.join('');
}

function buildDeviceTooltip(info) {
  if (!info || typeof info !== 'object') {
    return '';
  }
  const parts = [];
  const add = (label, value) => {
    if (value) {
      parts.push(`${label}=${value}`);
    }
  };
  add('name', info.name);
  add('os', info.os);
  add('build', info.build);
  add('arch', info.arch);
  add('cpu', info.cpu);
  add('gpu', info.gpu);
  if (info.cores) add('cores', info.cores);
  const ram = formatDeviceNumber(info.ram_gb, 'GB');
  if (ram) add('ram', ram);
  const disk = formatDeviceNumber(info.disk_gb, 'GB');
  if (disk) add('disk', disk);
  add('locale', info.locale);
  add('timezone', info.timezone);
  add('bios', info.bios);
  add('board', info.board);
  add('smbios', info.smbios);
  if (info.hwid_score) add('hwid_score', info.hwid_score);
  if (Array.isArray(info.hwid_flags) && info.hwid_flags.length) {
    add('hwid_flags', info.hwid_flags.join(','));
  }
  if (info.last_hwid_check) add('last_hwid_check', info.last_hwid_check);
  return parts.join(' | ');
}

function buildEventTooltip(event) {
  if (!event) {
    return '';
  }
  const parts = [];
  const type = String(event.event_type || '');
  const detail = event.detail || event.event_detail || '';
  const ip = event.ip || event.ip_address || '';
  const hwid = event.hwid_hash || '';
  const keyId = event.key_id || '';
  if (type) parts.push(`type=${type}`);
  if (detail) parts.push(`detail=${detail}`);
  if (keyId) parts.push(`key_id=${keyId}`);
  if (hwid) parts.push(`hwid=${hwid}`);
  if (ip) parts.push(`ip=${ip}`);
  return parts.join(' | ');
}

function showView(view) {
  navButtons.forEach((btn) => btn.classList.toggle('is-active', btn.dataset.view === view));
  viewPanels.forEach((panel) => {
    const show = panel.dataset.viewPanel === view || panel.dataset.viewPanel === undefined;
    panel.style.display = show ? '' : 'none';
  });
  if (view === 'keys') {
    viewTitle.textContent = 'Keys';
    viewSubtitle.textContent = 'Manage subscriptions, products and devices.';
  } else if (view === 'devices') {
    viewTitle.textContent = 'Devices';
    viewSubtitle.textContent = 'Inspect hardware fingerprints and sessions.';
  } else {
    viewTitle.textContent = 'Events';
    viewSubtitle.textContent = 'Review security and activity logs.';
  }
}

async function loadKeys() {
  const res = await fetch('/api/keys?limit=50');
  const data = normalizeListResponse(await res.json(), 'keys');
  keysTableBody.innerHTML = '';
  if (!data.ok) {
    const row = document.createElement('tr');
    row.innerHTML = `<td colspan="6">Failed to load keys: ${escapeHtml(data.error)}</td>`;
    keysTableBody.appendChild(row);
    return;
  }
  statRevoked.textContent = data.keys.filter((k) => k.is_revoked).length;
  if (data.keys.length) {
    statLastKey.textContent = getKeyValue(data.keys[0]) || '-';
  }
  data.keys.forEach((row) => {
    const keyHash = String(row.key_hash || '');
    const keyLabel = getKeyValue(row);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(keyLabel)}</td>
      <td>${escapeHtml(row.days)}</td>
      <td>${escapeHtml(row.created_at || '-')}</td>
      <td>${escapeHtml(row.activated_at || '-')}</td>
      <td>${escapeHtml(row.expires_at || '-')}</td>
      <td>${row.is_revoked ? 'Yes' : 'No'}</td>
    `;
    tr.addEventListener('click', () => {
      const lookup = row.key_plain || keyHash;
      keyInput.value = lookup;
      searchKey();
    });
    keysTableBody.appendChild(tr);
  });
}

function renderKeyDetails(data) {
  if (!data) {
    setEmpty(keyDetails, 'Select a key to view details.');
    setEmpty(productsEl, 'No products.');
    return;
  }
  keyDetails.classList.remove('empty');
  const keyHash = data.key.key_plain || data.key.key_hash || '-';
  keyDetails.innerHTML = `
    <div><strong>Key:</strong> ${escapeHtml(keyHash)}</div>
    <div><strong>Days:</strong> ${escapeHtml(data.key.days)}</div>
    <div><strong>Created:</strong> ${escapeHtml(data.key.created_at || '-')}</div>
    <div><strong>Activated:</strong> ${escapeHtml(data.key.activated_at || '-')}</div>
    <div><strong>Expires:</strong> ${escapeHtml(data.key.expires_at || '-')}</div>
    <div><strong>Revoked:</strong> ${data.key.is_revoked ? 'Yes' : 'No'}</div>
  `;
  if (data.products && data.products.length) {
    productsEl.classList.remove('empty');
    productsEl.innerHTML = data.products
      .map(
        (p) =>
          `<div class="badge">${escapeHtml(p.product_code)} - ${escapeHtml(p.days)} days</div>` +
          `<div>Activated: ${escapeHtml(p.activated_at || '-')} | Expires: ${escapeHtml(p.expires_at || '-')}</div>`
      )
      .join('<hr class="divider" />');
  } else {
    setEmpty(productsEl, 'No products.');
  }
}

async function searchKey() {
  const key = keyInput.value.trim();
  currentKey = key;
  if (!key) {
    renderKeyDetails(null);
    setEmpty(devicesEl, 'No devices.');
    setEmpty(eventsEl, 'No events.');
    return;
  }
  const res = await fetch(`/api/key?key=${encodeURIComponent(key)}`);
  const data = await res.json();
  if (!data.ok) {
    setEmpty(keyDetails, `Key error: ${data.error}`);
    return;
  }
  renderKeyDetails(data);
  loadDevices(key);
  loadEvents(key);
}

async function loadDevices(key) {
  const res = await fetch(`/api/devices?key=${encodeURIComponent(key)}`);
  const data = normalizeListResponse(await res.json(), 'devices');
  if (!data.ok || !data.devices || data.devices.length === 0) {
    setEmpty(devicesEl, 'No devices.');
    return;
  }
  devicesEl.classList.remove('empty');
  devicesEl.innerHTML = data.devices
    .map((d) => {
      const info = parseDeviceInfo(d.device_info);
      const summary = buildDeviceSummary(info);
      const tooltip = buildDeviceTooltip(info);
      const scoreLine = Number(info.hwid_score)
        ? `<div class="device-meta">HWID score: ${escapeHtml(info.hwid_score)}</div>`
        : '';
      const flagsLine =
        Array.isArray(info.hwid_flags) && info.hwid_flags.length
          ? `<div class="device-meta">HWID flags: ${escapeHtml(info.hwid_flags.join(', '))}</div>`
          : '';
      const titleAttr = tooltip ? ` title="${escapeAttr(tooltip)}"` : '';
      return `
        <div class="device-card"${titleAttr}>
          <div class="device-title">${escapeHtml(d.hwid_hash)}</div>
          <div class="device-meta">First: ${escapeHtml(d.first_seen_at)} | Last: ${escapeHtml(d.last_seen_at)} | Inject: ${escapeHtml(d.last_inject_at || '-')}</div>
          <div class="device-meta">Revoked: ${d.is_revoked ? 'Yes' : 'No'}</div>
          ${scoreLine}
          ${flagsLine}
          ${summary}
        </div>
      `;
    })
    .join('<hr class="divider" />');
}

async function loadEvents(key) {
  const limit = Number(eventLimit.value || '50') || 50;
  const res = await fetch(`/api/events?key=${encodeURIComponent(key)}&limit=${limit}`);
  const data = normalizeListResponse(await res.json(), 'events');
  if (!data.ok || !data.events || data.events.length === 0) {
    setEmpty(eventsEl, 'No events.');
    return;
  }
  const typeFilter = eventFilter.value;
  const filtered = typeFilter ? data.events.filter((e) => e.event_type === typeFilter) : data.events;
  if (!filtered.length) {
    setEmpty(eventsEl, 'No events for this filter.');
    return;
  }
  statLastEvent.textContent = filtered[0].event_type;
  eventsEl.classList.remove('empty');
  eventsEl.innerHTML = filtered
    .map(
      (e) => {
        const detail = e.detail || e.event_detail || '';
        const detailShort = detail ? truncateText(detail, 80) : '-';
        const tooltip = buildEventTooltip(e);
        const titleAttr = tooltip ? ` title="${escapeAttr(tooltip)}"` : '';
        const ip = e.ip || e.ip_address || '-';
        return `
          <div class="event-row"${titleAttr}>
            <div><span class="badge">${escapeHtml(e.event_type || '-')}</span> ${escapeHtml(e.created_at)}</div>
            <div class="event-meta">IP: ${escapeHtml(ip)} | ${escapeHtml(detailShort)}</div>
          </div>
        `;
      }
    )
    .join('<hr class="divider" />');
}

async function revokeKey(action) {
  const key = keyInput.value.trim();
  if (!key) return;
  const res = await fetch(`/api/${action}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  });
  const data = await res.json();
  if (!data.ok) {
    alert(`Failed: ${data.error}`);
    return;
  }
  await loadKeys();
  await searchKey();
}

async function assignProduct() {
  const key = keyInput.value.trim();
  const product = (productInput.value || '').trim();
  const daysValue = (daysInput.value || '').trim();
  if (!key || !product) {
    assignStatus.textContent = 'Enter key and product code.';
    return;
  }
  assignStatus.textContent = 'Assigning...';
  const res = await fetch('/api/assign-product', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      key,
      product_code: product,
      days: daysValue ? Number(daysValue) : undefined,
    }),
  });
  const data = await res.json();
  if (!data.ok) {
    assignStatus.textContent = `Failed: ${data.error}`;
    return;
  }
  assignStatus.textContent = 'Assigned.';
  await searchKey();
}

async function createKey() {
  createStatus.textContent = 'Creating...';
  const res = await fetch('/api/create-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      key: (newKeyInput.value || '').trim() || undefined,
      days: (newDaysInput.value || '').trim() ? Number(newDaysInput.value) : undefined,
      products: (newProductsInput.value || '').trim() || undefined,
    }),
  });
  const data = await res.json();
  if (!data.ok) {
    createStatus.textContent = `Failed: ${data.error}`;
    return;
  }
  createStatus.textContent = `Created: ${data.key}`;
  newKeyInput.value = data.key;
  await loadKeys();
}

function openModal(show) {
  createModal.classList.toggle('show', show);
}

navButtons.forEach((btn) => {
  btn.addEventListener('click', () => showView(btn.dataset.view));
});

searchBtn.addEventListener('click', searchKey);
revokeBtn.addEventListener('click', () => revokeKey('revoke'));
unrevokeBtn.addEventListener('click', () => revokeKey('unrevoke'));
assignBtn.addEventListener('click', assignProduct);
createBtn.addEventListener('click', createKey);
createOpen.addEventListener('click', () => openModal(true));
createClose.addEventListener('click', () => openModal(false));
refreshAll.addEventListener('click', async () => {
  await loadKeys();
  if (currentKey) {
    await searchKey();
  }
});
eventsRefresh.addEventListener('click', () => loadEvents(currentKey));
eventFilter.addEventListener('change', () => loadEvents(currentKey));

copyKeyBtn.addEventListener('click', async () => {
  if (!currentKey) return;
  try {
    await navigator.clipboard.writeText(currentKey);
  } catch (_) {
    alert('Copy failed');
  }
});

showView('keys');
loadKeys();




