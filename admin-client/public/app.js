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
      let info = '';
      if (d.device_info) {
        try {
          const parsed = JSON.parse(d.device_info);
          const deviceLine = [parsed.name, parsed.os, parsed.build].filter(Boolean).join(' - ');
          info = `<div>Device: ${escapeHtml(deviceLine)}</div>` +
                 `<div>CPU: ${escapeHtml(parsed.cpu || '-')} | GPU: ${escapeHtml(parsed.gpu || '-')}</div>`;
        } catch (_) {
          info = `<div>Device info: ${escapeHtml(d.device_info)}</div>`;
        }
      }
      return `<div><strong>${escapeHtml(d.hwid_hash)}</strong></div>` +
        `<div>First: ${escapeHtml(d.first_seen_at)} | Last: ${escapeHtml(d.last_seen_at)} | Inject: ${escapeHtml(d.last_inject_at || '-')}</div>` +
        `<div>Revoked: ${d.is_revoked ? 'Yes' : 'No'}</div>` +
        info;
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
      (e) =>
        `<div><strong>${escapeHtml(e.event_type)}</strong> - ${escapeHtml(e.created_at)}</div>` +
        `<div>IP: ${escapeHtml(e.ip || '-')} | ${escapeHtml(e.detail || '')}</div>`
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




