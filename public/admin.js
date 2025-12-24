// Global state
let adminToken = '';
let allKeys = [];
let visibleKeys = [];
let allDevices = [];
let allEvents = [];

// API Base URL
const API_URL = window.location.origin;

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

window.onload = function() {
    document.getElementById('adminToken').value = '';
};

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
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
function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById(`${tab}-tab`).classList.add('active');
    
    if (tab === 'dashboard') loadDashboard();
    if (tab === 'keys') loadKeys();
    if (tab === 'devices') loadDevices();
    if (tab === 'events') loadEvents();
}

// Load Dashboard
async function loadDashboard() {
    console.log('Loading dashboard, token:', adminToken ? 'present' : 'missing');
    try {
        const [keys, devices, events] = await Promise.all([
            fetchKeys(),
            fetchDevices(),
            fetchEvents()
        ]);
        
        // Calculate stats
        const activeKeys = keys.filter(k => !k.is_revoked && 
            (!k.expires_at || new Date(k.expires_at) > new Date())).length;
        
        const suspiciousDevices = devices.filter(d => {
            try {
                const info = JSON.parse(d.device_info || '{}');
                return info.hwid_score >= 50;
            } catch {
                return false;
            }
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
                    const detail = e.event_detail ?? e.detail ?? '-';
                    return `
                    <tr>
                        <td>${escapeHtml(formatDate(e.created_at))}</td>
                        <td><span class="badge ${getEventBadge(type)}">${escapeHtml(type)}</span></td>
                        <td>${escapeHtml(ip)}</td>
                        <td>${escapeHtml(detail)}</td>
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
                            ${k.is_revoked ? 
                                `<button class="btn btn-sm btn-success" onclick="unrevokeKey(${k.id})">Разблокировать</button>` :
                                `<button class="btn btn-sm btn-danger" onclick="revokeKey(${k.id})">Заблокировать</button>`
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
                    <th>Флаги</th>
                    <th>Первый вход</th>
                    <th>Последний вход</th>
                    <th>Действия</th>
                </tr>
            </thead>
            <tbody>
                ${devices.map(d => {
                    const info = parseDeviceInfo(d.device_info);
                    return `
                        <tr>
                            <td><code>${escapeHtml(d.hwid_hash.substring(0, 16) + '...')}</code></td>
                            <td>${escapeHtml(d.key_id)}</td>
                            <td>${getScoreBadge(info.hwid_score)}</td>
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
                                    `<button class="btn btn-sm btn-success" onclick="allowDevice(${d.id})">Разрешить</button>` :
                                    `<button class="btn btn-sm btn-danger" onclick="revokeDevice(${d.id})">Заблокировать</button>`
                                }
                                <button class="btn btn-sm btn-primary" onclick="showDeviceInfo(${d.id})">Инфо</button>
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
        const events = await fetchEvents();
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
                    const detail = e.event_detail ?? e.detail ?? '-';
                    return `
                    <tr>
                        <td>${escapeHtml(formatDate(e.created_at))}</td>
                        <td><span class="badge ${getEventBadge(type)}">${escapeHtml(type)}</span></td>
                        <td>${escapeHtml(e.key_id || '-')}</td>
                        <td>${escapeHtml(e.hwid_hash ? e.hwid_hash.substring(0, 12) + '...' : '-')}</td>
                        <td>${escapeHtml(ip)}</td>
                        <td>${escapeHtml(detail)}</td>
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

async function fetchEvents() {
    allEvents = await apiRequest('/admin/events');
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

// Create key modal
function showCreateKeyModal() {
    document.getElementById('createKeyModal').classList.add('active');
}

function closeModal() {
    document.getElementById('createKeyModal').classList.remove('active');
}

async function createKey() {
    const days = parseInt(document.getElementById('keyDays').value);
    const product = document.getElementById('keyProduct').value;
    
    if (!days || days < 1) {
        alert('Укажите количество дней');
        return;
    }
    
    try {
        const result = await apiRequest('/admin/key/create', {
            method: 'POST',
            body: JSON.stringify({ days, product })
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
        e.event_type.toLowerCase().includes(search) ||
        (e.event_detail || '').toLowerCase().includes(search) ||
        (e.ip_address || '').toLowerCase().includes(search)
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

function parseDeviceInfo(json) {
    try {
        return JSON.parse(json || '{}');
    } catch {
        return {};
    }
}



