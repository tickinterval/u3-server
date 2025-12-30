// Global state
let adminToken = '';
let allKeys = [];
let visibleKeys = [];
let allDevices = [];
let allEvents = [];

// API Base URL
const API_URL = window.location.origin;

function initAdminUi() {
    const tokenInput = document.getElementById('adminToken');
    if (tokenInput) {
        tokenInput.value = '';
        tokenInput.addEventListener('keyup', (event) => {
            if (event.key === 'Enter') {
                login();
            }
        });
    }

    const loginBtn = document.getElementById('loginBtn');
    if (loginBtn) {
        loginBtn.addEventListener('click', login);
    }

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }

    const showCreateKeyBtn = document.getElementById('showCreateKeyBtn');
    if (showCreateKeyBtn) {
        showCreateKeyBtn.addEventListener('click', showCreateKeyModal);
    }

    const closeCreateKeyBtn = document.getElementById('closeCreateKeyBtn');
    if (closeCreateKeyBtn) {
        closeCreateKeyBtn.addEventListener('click', closeModal);
    }

    const createKeyBtn = document.getElementById('createKeyBtn');
    if (createKeyBtn) {
        createKeyBtn.addEventListener('click', createKey);
    }

    const closeAssignProductsBtn = document.getElementById('closeAssignProductsBtn');
    if (closeAssignProductsBtn) {
        closeAssignProductsBtn.addEventListener('click', closeAssignModal);
    }

    const assignProductsBtn = document.getElementById('assignProductsBtn');
    if (assignProductsBtn) {
        assignProductsBtn.addEventListener('click', assignProducts);
    }

    document.querySelectorAll('.tab').forEach((tab) => {
        tab.addEventListener('click', () => {
            const tabId = tab.dataset.tab || '';
            if (tabId) {
                switchTab(tabId, tab);
            }
        });
    });

    const keysSearch = document.getElementById('keysSearch');
    if (keysSearch) {
        keysSearch.addEventListener('keyup', filterKeys);
    }

    const devicesSearch = document.getElementById('devicesSearch');
    if (devicesSearch) {
        devicesSearch.addEventListener('input', filterDevices);
    }

    const eventsSearch = document.getElementById('eventsSearch');
    if (eventsSearch) {
        eventsSearch.addEventListener('input', filterEvents);
    }

    const keysList = document.getElementById('keysList');
    if (keysList) {
        keysList.addEventListener('click', onKeysListClick);
    }

    const devicesList = document.getElementById('devicesList');
    if (devicesList) {
        devicesList.addEventListener('click', onDevicesListClick);
    }
}

// Login
function login() {
    const token = document.getElementById('adminToken').value.trim();
    if (!token) {
        alert('Введите токен');
        return;
    }
    
    adminToken = token;
    
    // Test token
    fetchKeys().then(() => {
        document.getElementById('loginScreen').classList.add('hidden');
        document.getElementById('mainPanel').classList.remove('hidden');
        loadDashboard();
    }).catch(err => {
        alert('Неверный токен');
        adminToken = '';
    });
}

// Logout
function logout() {
    adminToken = '';
    document.getElementById('mainPanel').classList.add('hidden');
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('adminToken').value = '';
}

window.addEventListener('DOMContentLoaded', initAdminUi);

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function escapeAttr(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/'/g, '&#39;')
        .replace(/\r?\n/g, ' ');
}

function truncateText(value, maxLen) {
    const text = String(value ?? '');
    if (text.length <= maxLen) {
        return text;
    }
    if (maxLen <= 3) {
        return text.slice(0, maxLen);
    }
    return text.slice(0, maxLen - 3) + '...';
}

function getSelectedValues(selectId) {
    const select = document.getElementById(selectId);
    if (!select) {
        return [];
    }
    return Array.from(select.options)
        .filter(option => option.selected)
        .map(option => option.value);
}

// API Request wrapper
async function apiRequest(endpoint, options = {}) {
    if (!adminToken) {
        throw new Error('No admin token');
    }
    
    const headers = {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    const response = await fetch(`${API_URL}${endpoint}`, {
        ...options,
        headers
    });
    
    if (!response.ok) {
        const text = await response.text();
        console.error('API Error:', response.status, text);
        throw new Error(`HTTP ${response.status}: ${text}`);
    }
    
    return response.json();
}

// Switch tabs
function switchTab(tab, tabElement) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    const tabNode = tabElement || document.querySelector(`.tab[data-tab="${tab}"]`);
    if (tabNode) {
        tabNode.classList.add('active');
    }
    document.getElementById(`${tab}-tab`).classList.add('active');
    
    if (tab === 'dashboard') loadDashboard();
    if (tab === 'keys') loadKeys();
    if (tab === 'devices') loadDevices();
    if (tab === 'events') loadEvents();
    if (tab === 'products') loadProductStatuses();
}

// Load Dashboard
async function loadDashboard() {
    console.log('Loading dashboard, token:', adminToken ? 'present' : 'missing');
    try {
        const [keys, devices, events] = await Promise.all([
            fetchKeys(),
            fetchDevices(),
            fetchEvents(1000)
        ]);
        
        // Calculate stats
        const activeKeys = keys.filter(k => !k.is_revoked && 
            (!k.expires_at || new Date(k.expires_at) > new Date())).length;
        
        const suspiciousDevices = devices.filter(d => {
            const info = parseDeviceInfo(d.device_info);
            return Number(info.hwid_score) >= 50;
        }).length;
        
        document.getElementById('totalKeys').textContent = keys.length;
        document.getElementById('activeKeys').textContent = activeKeys;
        document.getElementById('totalDevices').textContent = devices.length;
        document.getElementById('suspiciousDevices').textContent = suspiciousDevices;
        
        // Recent events
        renderRecentEvents(events.slice(0, 10));
    } catch (err) {
        console.error('Failed to load dashboard:', err);
    }
}

async function loadProductStatuses() {
    const container = document.getElementById('productStatusList');
    if (!container) {
        return;
    }
    container.innerHTML = '<div class="loading">Loading...</div>';
    try {
        const response = await apiRequest('/admin/products');
        const products = (response && response.products) ? response.products : [];
        renderProductStatuses(products);
    } catch (err) {
        container.innerHTML = `<div class="loading">Failed to load products: ${escapeHtml(err.message)}</div>`;
    }
}

function renderProductStatuses(products) {
    const container = document.getElementById('productStatusList');
    if (!container) {
        return;
    }
    if (!products.length) {
        container.innerHTML = '<div class="loading">No products found</div>';
        return;
    }
    const rows = products.map((product) => {
        const code = escapeAttr(product.code || '');
        const name = escapeHtml(product.name || product.code || '');
        const statusEffective = escapeHtml(product.status_effective || '-');
        const statusOverride = product.status_override || '';
        const options = [
            { value: '', label: 'Default (disabled)' },
            { value: 'safe', label: 'Safe' },
            { value: 'risky', label: 'Risky' },
            { value: 'updating', label: 'Updating' },
            { value: 'ready', label: 'Ready' },
            { value: 'disabled', label: 'Disabled' },
        ];
        const select = options.map((opt) => {
            const selected = opt.value === statusOverride ? ' selected' : '';
            return `<option value="${opt.value}"${selected}>${opt.label}</option>`;
        }).join('');
        return `
            <tr>
                <td>${name} <span style="color:#718096;">(${code})</span></td>
                <td>${statusEffective}</td>
                <td>
                    <select data-code="${code}" class="product-status-select">
                        ${select}
                    </select>
                </td>
                <td>
                    <button class="btn btn-primary product-status-save" data-code="${code}">Save</button>
                </td>
            </tr>
        `;
    }).join('');

    container.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Product</th>
                    <th>Effective</th>
                    <th>Override</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                ${rows}
            </tbody>
        </table>
    `;

    container.querySelectorAll('.product-status-save').forEach((btn) => {
        btn.addEventListener('click', () => updateProductStatus(btn.dataset.code || ''));
    });
}

async function updateProductStatus(productCode) {
    if (!productCode) {
        return;
    }
    let select = null;
    document.querySelectorAll('.product-status-select').forEach((el) => {
        if (el.dataset.code === productCode) {
            select = el;
        }
    });
    if (!select) {
        return;
    }
    const status = String(select.value || '');
    try {
        await apiRequest('/admin/product/status', {
            method: 'POST',
            body: JSON.stringify({ product_code: productCode, status })
        });
        loadProductStatuses();
    } catch (err) {
        alert('Failed to update status: ' + err.message);
    }
}

// Render recent events
function renderRecentEvents(events) {
    const html = `
        <table>
            <thead>
                <tr>
                    <th>Время</th>
                    <th>Тип</th>
                    <th>IP</th>
                    <th>Детали</th>
                </tr>
            </thead>
            <tbody>
                ${events.map(e => {
                    const type = String(e.event_type || '');
                    const ip = e.ip_address ?? e.ip ?? '-';
                    const detail = e.event_detail ?? e.detail ?? '';
                    const detailShort = detail ? truncateText(detail, 60) : '-';
                    const tooltip = buildEventTooltip(e);
                    return `
                    <tr>
                        <td>${escapeHtml(formatDate(e.created_at))}</td>
                        <td><span class="badge ${getEventBadge(type)}" title="${escapeAttr(tooltip)}">${escapeHtml(type)}</span></td>
                        <td>${escapeHtml(ip)}</td>
                        <td title="${escapeAttr(detail || '')}">${escapeHtml(detailShort)}</td>
                    </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
    document.getElementById('recentEvents').innerHTML = html;
}

// Load Keys
async function loadKeys() {
    try {
        const keys = await fetchKeys();
        renderKeys(keys);
    } catch (err) {
        console.error('Failed to load keys:', err);
        document.getElementById('keysList').innerHTML = `<div class="loading">Ошибка загрузки: ${escapeHtml(err.message)}</div>`;
    }
}

// Render keys
function renderKeys(keys) {
    visibleKeys = Array.isArray(keys) ? keys : [];
    if (keys.length === 0) {
        document.getElementById('keysList').innerHTML = `
            <div class="empty-state">
                <p>Нет ключей</p>
            </div>
        `;
        return;
    }
    
    const html = `
        <table>
            <thead>
                <tr>
                    <th>Ключ</th>
                    <th>Статус</th>
                    <th>Создан</th>
                    <th>Активирован</th>
                    <th>Истекает</th>
                    <th>Действия</th>
                </tr>
            </thead>
            <tbody>
                ${keys.map(k => `
                    <tr>
                        <td><code>${escapeHtml(k.key_plain || k.key_hash || '-')}</code></td>
                        <td>${getKeyStatus(k)}</td>
                        <td>${escapeHtml(formatDate(k.created_at))}</td>
                        <td>${escapeHtml(k.activated_at ? formatDate(k.activated_at) : '-')}</td>
                        <td>${escapeHtml(k.expires_at ? formatDate(k.expires_at) : '-')}</td>
                        <td class="actions">
                            <button class="btn btn-sm btn-primary" data-action="assign-products" data-key="${escapeAttr(k.key_plain || k.key_hash || '')}">Products</button>
                            ${k.is_revoked ? 
                                `<button class="btn btn-sm btn-success" data-action="unrevoke-key" data-id="${k.id}">Разблокировать</button>` :
                                `<button class="btn btn-sm btn-danger" data-action="revoke-key" data-id="${k.id}">Заблокировать</button>`
                            }
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    document.getElementById('keysList').innerHTML = html;
}

// Load Devices
async function loadDevices() {
    try {
        const devices = await fetchDevices();
        renderDevices(devices);
    } catch (err) {
        console.error('Failed to load devices:', err);
        document.getElementById('devicesList').innerHTML = `<div class="loading">Ошибка загрузки: ${escapeHtml(err.message)}</div>`;
    }
}

// Render devices
function renderDevices(devices) {
    if (devices.length === 0) {
        document.getElementById('devicesList').innerHTML = `
            <div class="empty-state">
                <p>Нет устройств</p>
            </div>
        `;
        return;
    }
    
    const html = `
        <table>
            <thead>
                <tr>
                    <th>HWID Hash</th>
                    <th>Key ID</th>
                    <th>HWID Score</th>
                    <th>Device</th>
                    <th>Флаги</th>
                    <th>Первый вход</th>
                    <th>Последний вход</th>
                    <th>Действия</th>
                </tr>
            </thead>
            <tbody>
                ${devices.map(d => {
                    const info = parseDeviceInfo(d.device_info);
                    const deviceSummary = buildDeviceSummary(info);
                    const deviceTooltip = buildDeviceTooltip(info);
                    return `
                        <tr>
                            <td><code>${escapeHtml(d.hwid_hash.substring(0, 16) + '...')}</code></td>
                            <td>${escapeHtml(d.key_id)}</td>
                            <td>${getScoreBadge(info.hwid_score)}</td>
                            <td title="${escapeAttr(deviceTooltip)}">${deviceSummary}</td>
                            <td>
                                <div class="hwid-flags">
                                    ${(info.hwid_flags || []).map(f => `<span class="badge badge-warning">${escapeHtml(f)}</span>`).join('')}
                                    ${(info.hwid_flags || []).length === 0 ? '-' : ''}
                                </div>
                            </td>
                            <td>${escapeHtml(formatDate(d.first_seen_at))}</td>
                            <td>${escapeHtml(formatDate(d.last_seen_at))}</td>
                            <td class="actions">
                                ${d.is_revoked ?
                                    `<button class="btn btn-sm btn-success" data-action="allow-device" data-id="${d.id}">Разрешить</button>` :
                                    `<button class="btn btn-sm btn-danger" data-action="revoke-device" data-id="${d.id}">Заблокировать</button>`
                                }
                                <button class="btn btn-sm btn-primary" data-action="show-device" data-id="${d.id}">Инфо</button>
                            </td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
    document.getElementById('devicesList').innerHTML = html;
}

// Load Events
async function loadEvents() {
    try {
        const events = await fetchEvents(1000);
        renderEvents(events);
    } catch (err) {
        console.error('Failed to load events:', err);
        document.getElementById('eventsList').innerHTML = `<div class="loading">Ошибка загрузки: ${escapeHtml(err.message)}</div>`;
    }
}

// Render events
function renderEvents(events) {
    if (events.length === 0) {
        document.getElementById('eventsList').innerHTML = `
            <div class="empty-state">
                <p>Нет событий</p>
            </div>
        `;
        return;
    }
    
    const html = `
        <table>
            <thead>
                <tr>
                    <th>Время</th>
                    <th>Тип</th>
                    <th>Key ID</th>
                    <th>HWID Hash</th>
                    <th>IP</th>
                    <th>Детали</th>
                </tr>
            </thead>
            <tbody>
                ${events.map(e => {
                    const type = String(e.event_type || '');
                    const ip = e.ip_address ?? e.ip ?? '-';
                    const detail = e.event_detail ?? e.detail ?? '';
                    const detailShort = detail ? truncateText(detail, 80) : '-';
                    const tooltip = buildEventTooltip(e);
                    return `
                    <tr>
                        <td>${escapeHtml(formatDate(e.created_at))}</td>
                        <td><span class="badge ${getEventBadge(type)}" title="${escapeAttr(tooltip)}">${escapeHtml(type)}</span></td>
                        <td>${escapeHtml(e.key_id || '-')}</td>
                        <td>${escapeHtml(e.hwid_hash ? e.hwid_hash.substring(0, 12) + '...' : '-')}</td>
                        <td>${escapeHtml(ip)}</td>
                        <td title="${escapeAttr(detail || '')}">${escapeHtml(detailShort)}</td>
                    </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
    document.getElementById('eventsList').innerHTML = html;
}

// Fetch functions
async function fetchKeys() {
    allKeys = await apiRequest('/admin/keys');
    return allKeys;
}

async function fetchDevices() {
    allDevices = await apiRequest('/admin/devices');
    return allDevices;
}

async function fetchEvents(limit = 1000, offset = 0) {
    const query = `?limit=${encodeURIComponent(limit)}&offset=${encodeURIComponent(offset)}`;
    allEvents = await apiRequest(`/admin/events${query}`);
    return allEvents;
}

// Actions
async function revokeKey(id) {
    if (!confirm('Заблокировать этот ключ?')) return;
    
    try {
        const key = visibleKeys.find(k => k.id === id) || allKeys.find(k => k.id === id);
        if (!key) {
            alert('Key not found in list');
            return;
        }
        await apiRequest('/admin/revoke', {
            method: 'POST',
            body: JSON.stringify({ key: key.key_plain || key.key_hash })
        });
        alert('Ключ заблокирован');
        loadKeys();
    } catch (err) {
        alert('Ошибка: ' + err.message);
    }
}

async function unrevokeKey(id) {
    if (!confirm('Разблокировать этот ключ?')) return;
    
    try {
        const key = visibleKeys.find(k => k.id === id) || allKeys.find(k => k.id === id);
        if (!key) {
            alert('Key not found in list');
            return;
        }
        await apiRequest('/admin/unrevoke', {
            method: 'POST',
            body: JSON.stringify({ key: key.key_plain || key.key_hash })
        });
        alert('Ключ разблокирован');
        loadKeys();
    } catch (err) {
        alert('Ошибка: ' + err.message);
    }
}

async function revokeDevice(id) {
    if (!confirm('Заблокировать это устройство?')) return;
    
    try {
        await apiRequest('/admin/device/revoke', {
            method: 'POST',
            body: JSON.stringify({ device_id: id })
        });
        alert('Устройство заблокировано');
        loadDevices();
    } catch (err) {
        alert('Ошибка: ' + err.message);
    }
}

async function allowDevice(id) {
    if (!confirm('Разрешить это устройство?')) return;
    
    try {
        await apiRequest('/admin/device/allow', {
            method: 'POST',
            body: JSON.stringify({ device_id: id })
        });
        alert('Устройство разрешено');
        loadDevices();
    } catch (err) {
        alert('Ошибка: ' + err.message);
    }
}

function showDeviceInfo(id) {
    const device = allDevices.find(d => d.id === id);
    if (!device) return;
    
    const info = parseDeviceInfo(device.device_info);
    alert('Device Info:\n\n' + JSON.stringify(info, null, 2));
}

function onKeysListClick(event) {
    const button = event.target.closest('button');
    if (!button) {
        return;
    }
    const action = button.dataset.action || '';
    if (action === 'assign-products') {
        showAssignProductsModal(button.dataset.key || '');
        return;
    }
    if (action === 'revoke-key') {
        const id = Number(button.dataset.id);
        if (Number.isFinite(id)) {
            revokeKey(id);
        }
        return;
    }
    if (action === 'unrevoke-key') {
        const id = Number(button.dataset.id);
        if (Number.isFinite(id)) {
            unrevokeKey(id);
        }
    }
}

function onDevicesListClick(event) {
    const button = event.target.closest('button');
    if (!button) {
        return;
    }
    const action = button.dataset.action || '';
    const id = Number(button.dataset.id);
    if (!Number.isFinite(id)) {
        return;
    }
    if (action === 'allow-device') {
        allowDevice(id);
        return;
    }
    if (action === 'revoke-device') {
        revokeDevice(id);
        return;
    }
    if (action === 'show-device') {
        showDeviceInfo(id);
    }
}

// Create key modal
function showCreateKeyModal() {
    document.getElementById('createKeyModal').classList.add('active');
}

function closeModal() {
    document.getElementById('createKeyModal').classList.remove('active');
}

function showAssignProductsModal(key) {
    const keyInput = document.getElementById('assignKey');
    const daysInput = document.getElementById('assignDays');
    const select = document.getElementById('assignProducts');
    if (keyInput) {
        keyInput.value = key || '';
    }
    if (daysInput) {
        daysInput.value = '';
    }
    if (select) {
        Array.from(select.options).forEach(option => {
            option.selected = false;
        });
    }
    document.getElementById('assignProductsModal').classList.add('active');
}

function closeAssignModal() {
    document.getElementById('assignProductsModal').classList.remove('active');
}

async function assignProducts() {
    const key = String(document.getElementById('assignKey').value || '').trim();
    const products = getSelectedValues('assignProducts');
    const daysValue = Number(document.getElementById('assignDays').value);
    if (!key) {
        alert('Key is required');
        return;
    }
    if (!products.length) {
        alert('Select at least one product');
        return;
    }
    const assignDays = Number.isFinite(daysValue) && daysValue > 0 ? daysValue : null;

    try {
        for (const productCode of products) {
            const payload = { key, product_code: productCode };
            if (assignDays) {
                payload.days = assignDays;
            }
            await apiRequest('/admin/product/assign', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
        }
        alert('Products assigned');
        closeAssignModal();
        loadKeys();
    } catch (err) {
        alert('Dz¥^D,DñD§Dø: ' + err.message);
    }
}

async function createKey() {
    const days = parseInt(document.getElementById('keyDays').value);
    const products = getSelectedValues('keyProducts');
    if (!products.length) {
        alert('Select at least one product');
        return;
    }
    
    if (!days || days < 1) {
        alert('Укажите количество дней');
        return;
    }
    
    try {
        const result = await apiRequest('/admin/key/create', {
            method: 'POST',
            body: JSON.stringify({ days, products })
        });
        
        alert(`Ключ создан:\n\n${result.key}\n\nСкопируйте его сейчас!`);
        closeModal();
        loadKeys();
    } catch (err) {
        alert('Ошибка: ' + err.message);
    }
}

// Filter functions
async function searchKeyServer() {
    const search = document.getElementById('keysSearch').value.trim();
    if (!search) {
        renderKeys(allKeys);
        return;
    }
    document.getElementById('keysList').innerHTML = `<div class="loading">Searching...</div>`;
    try {
        const data = await apiRequest(`/admin/key?key=${encodeURIComponent(search)}`);
        if (!data || !data.key) {
            document.getElementById('keysList').innerHTML = `
                <div class="empty-state">
                    <p>Key not found</p>
                </div>
            `;
            return;
        }
        renderKeys([data.key]);
    } catch (err) {
        const message = String(err && err.message ? err.message : 'Search failed');
        document.getElementById('keysList').innerHTML = `
            <div class="empty-state">
                <p>${escapeHtml(message.includes('404') ? 'Key not found' : message)}</p>
            </div>
        `;
    }
}

async function filterKeys(event) {
    const input = document.getElementById('keysSearch');
    const search = input.value.toLowerCase();
    if (!search) {
        renderKeys(allKeys);
        return;
    }
    if (event && event.key === 'Enter') {
        await searchKeyServer();
        return;
    }
    const filtered = allKeys.filter(k =>
        (String(k.key_plain || k.key_hash || '')).toLowerCase().includes(search)
    );
    renderKeys(filtered);
}

function filterDevices() {
    const search = document.getElementById('devicesSearch').value.toLowerCase();
    const filtered = allDevices.filter(d => 
        d.hwid_hash.toLowerCase().includes(search) ||
        d.key_id.toString().includes(search)
    );
    renderDevices(filtered);
}

function filterEvents() {
    const search = document.getElementById('eventsSearch').value.toLowerCase();
    const filtered = allEvents.filter(e =>
        String(e.event_type || '').toLowerCase().includes(search) ||
        String(e.event_detail || e.detail || '').toLowerCase().includes(search) ||
        String(e.ip_address || e.ip || '').toLowerCase().includes(search) ||
        String(e.key_id || '').toLowerCase().includes(search) ||
        String(e.hwid_hash || '').toLowerCase().includes(search)
    );
    renderEvents(filtered);
}

// Helper functions
function formatDate(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleString('ru-RU');
}

function getKeyStatus(key) {
    if (key.is_revoked) {
        return '<span class="badge badge-danger">Заблокирован</span>';
    }
    if (!key.activated_at) {
        return '<span class="badge badge-info">Не активирован</span>';
    }
    if (key.expires_at && new Date(key.expires_at) < new Date()) {
        return '<span class="badge badge-warning">Истёк</span>';
    }
    return '<span class="badge badge-success">Активен</span>';
}

function getScoreBadge(score) {
    const value = Number(score);
    if (!Number.isFinite(value) || value === 0) return '-';

    let className = 'score-low';
    if (value >= 70) className = 'score-high';
    else if (value >= 50) className = 'score-medium';
    
    return `<span class="score-badge ${className}">${value}</span>`;
}

function getEventBadge(type) {
    const value = String(type || '');
    if (value.includes('fail') || value.includes('blocked') || value.includes('invalid')) {
        return 'badge-danger';
    }
    if (value.includes('suspicious') || value.includes('warning')) {
        return 'badge-warning';
    }
    if (value.includes('ok') || value.includes('success')) {
        return 'badge-success';
    }
    return 'badge-info';
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

function buildDeviceSummary(info) {
    if (!info || typeof info !== 'object') {
        return '-';
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
        return '-';
    }
    return `<div class="device-stack">${lines.join('')}</div>`;
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
    const detail = event.event_detail ?? event.detail ?? '';
    const keyId = event.key_id ? `key_id=${event.key_id}` : '';
    const hwid = event.hwid_hash ? `hwid=${event.hwid_hash}` : '';
    const ip = event.ip_address ?? event.ip ?? '';
    if (type) parts.push(`type=${type}`);
    if (detail) parts.push(`detail=${detail}`);
    if (keyId) parts.push(keyId);
    if (hwid) parts.push(hwid);
    if (ip) parts.push(`ip=${ip}`);
    return parts.join(' | ');
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
    } catch {
        return {};
    }
}
