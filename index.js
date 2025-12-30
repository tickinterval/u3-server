const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');
const express = require('express');
const Database = require('better-sqlite3');

const configPath = path.join(__dirname, 'config.json');
if (!fs.existsSync(configPath)) {
  console.error('Missing config.json');
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
if (!config.pepper || config.pepper === 'change_me') {
  console.error('Set a strong pepper in config.json');
  process.exit(1);
}

const tcpPort = Number(config.tcp_port || config.tcpPort || 0);
const tcpMaxFrameBytes = Number(config.tcp_max_frame_bytes || 0) || 50 * 1024 * 1024;
const tcpTlsKeyPath = resolvePath(config.tcp_tls_key_path || config.tcp_tls_key);
const tcpTlsCertPath = resolvePath(config.tcp_tls_cert_path || config.tcp_tls_cert);
const tcpTlsCaPath = resolvePath(config.tcp_tls_ca_path || config.tcp_tls_ca);
const tcpTlsEnabled = config.tcp_tls_enabled === false
  ? false
  : (config.tcp_tls_enabled === true || (tcpTlsKeyPath && tcpTlsCertPath));
const payloadEncryptionEnabled =
  config.payload_encrypt_enabled !== false && config.payload_encryption_enabled !== false;

const storePlaintextKeys = config.store_plaintext_keys === true;
const exposePlaintextKeys = config.expose_plaintext_keys === true || storePlaintextKeys;

function normalizePepperList(value) {
  if (!value) {
    return [];
  }
  if (Array.isArray(value)) {
    return value.map((entry) => String(entry || '').trim()).filter(Boolean);
  }
  if (typeof value === 'string') {
    return value.split(',').map((entry) => entry.trim()).filter(Boolean);
  }
  return [];
}

const legacyPeppers = normalizePepperList(config.legacy_peppers);
const pepperCandidates = Array.from(
  new Set([String(config.pepper || '').trim(), ...legacyPeppers].filter(Boolean))
);

function resolvePath(value) {
  if (!value) {
    return '';
  }
  return path.isAbsolute(value) ? value : path.join(__dirname, value);
}

function hashFileHex(filePath) {
  if (!filePath) {
    return '';
  }
  try {
    const buffer = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buffer).digest('hex');
  } catch (err) {
    return '';
  }
}

function getPayloadHash(payloadPath) {
  const resolved = resolvePath(payloadPath);
  return hashFileHex(resolved);
}

function getPayloadBuffer(payloadPath) {
  const resolved = resolvePath(payloadPath);
  if (!resolved) {
    return null;
  }
  try {
    const stat = fs.statSync(resolved);
    const cached = payloadCache.get(resolved);
    if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
      return cached.buffer;
    }
    const buffer = fs.readFileSync(resolved);
    payloadCache.set(resolved, { buffer, mtimeMs: stat.mtimeMs, size: stat.size });
    return buffer;
  } catch (err) {
    return null;
  }
}

function buildWatermarkId({ keyHash, hwidHash, productCode }) {
  const product = productCode || 'default';
  return sha256Hex(`${keyHash}|${product}|${hwidHash}`).slice(0, 12);
}

function buildWatermarkOverlay({ watermark, productCode, tokenId }) {
  if (!watermarkEnabled) {
    return null;
  }
  const payload = {
    wm: String(watermark || ''),
    pc: String(productCode || ''),
    tid: String(tokenId || ''),
  };
  const json = JSON.stringify(payload);
  const data = Buffer.from(json, 'utf8');
  if (!data.length || data.length > watermarkMaxBytes) {
    return null;
  }
  const header = Buffer.alloc(10);
  header.write(WATERMARK_MAGIC, 0, 'ascii');
  header.writeUInt8(WATERMARK_VERSION, 5);
  header.writeUInt32LE(data.length, 6);
  return Buffer.concat([header, data]);
}

function computePayloadHashWithOverlay(payloadPath, overlay) {
  const buffer = getPayloadBuffer(payloadPath);
  if (!buffer) {
    return '';
  }
  const hash = crypto.createHash('sha256');
  hash.update(buffer);
  if (overlay) {
    hash.update(overlay);
  }
  return hash.digest('hex');
}

function buildPayloadBufferWithOverlay(payloadPath, overlay) {
  const buffer = getPayloadBuffer(payloadPath);
  if (!buffer) {
    return null;
  }
  if (!overlay) {
    return buffer;
  }
  return Buffer.concat([buffer, overlay]);
}

function loadKey(configKey, pathKey) {
  if (config[pathKey]) {
    const resolved = resolvePath(config[pathKey]);
    if (fs.existsSync(resolved)) {
      return fs.readFileSync(resolved, 'utf8');
    }
  }
  if (config[configKey]) {
    return String(config[configKey]);
  }
  return '';
}

const responseSigningKey = loadKey('response_signing_private_key', 'response_signing_private_key_path');
if (!responseSigningKey) {
  console.error('Missing response signing private key');
  process.exit(1);
}

const productList = Array.isArray(config.products) ? config.products : [];
const productMap = new Map();
for (const product of productList) {
  if (!product || !product.code) {
    continue;
  }
  const payloadPath = product.payload_path || config.payloadPath || './data/payload.dll';
  const payloadHash = getPayloadHash(payloadPath);
  const updatedAt = product.updated_at || new Date().toISOString();
  const status = product.status || 'ready';
  let avatarUrl = product.avatar_url || '';
  const avatarPath = product.avatar_path || '';
  if (!avatarUrl && avatarPath) {
    const trimmed = String(avatarPath).replace(/^\/+/, '');
    avatarUrl = `${config.baseUrl.replace(/\/$/, '')}/files/${trimmed}`;
  }
  productMap.set(product.code, {
    code: product.code,
    name: product.name || product.code,
    updated_at: updatedAt,
    payload_path: payloadPath,
    payload_hash: payloadHash,
    status,
    avatar_url: avatarUrl,
  });
}

const defaultPayloadPath = config.payloadPath || './data/payload.dll';
const staticFilesPath = resolvePath(config.static_files_path || './public');

const downloadTokenOneTime = config.download_token_one_time !== false;
const downloadTokenBindIp = config.download_token_bind_ip === true;
const downloadTokenBindUserAgent = config.download_token_bind_user_agent === true;
const downloadTokenRequireId = config.download_token_require_id !== false;
const downloadTokenMaxPerHour = Number(config.download_token_max_per_hour || 0);
const downloadTokenRateLimitMinutes = Number(config.download_token_rate_limit_minutes || 60);
const downloadTokenCleanupMinutes = Number(config.download_token_cleanup_minutes || 180);
const downloadTokenDefaultTtlSeconds = Number(config.download_token_ttl_seconds || 300);
const legacyDownloadEnabled = config.legacy_download_enabled === true;
const watermarkEnabled = config.watermark_enabled !== false;
const watermarkMaxBytes = Number(config.watermark_max_bytes || 256);
const WATERMARK_MAGIC = 'U3WM1';
const WATERMARK_VERSION = 1;
const PAYLOAD_MAGIC = 'U3E1';
const PAYLOAD_VERSION = 1;
const PROTECTION_MAGIC = 'U3PR1';
const PROTECTION_VERSION = 1;

const payloadCache = new Map();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 'loopback');
app.use(express.json({ limit: '1mb' }));

// Serve admin panel
const publicPath = path.join(__dirname, 'public');
if (fs.existsSync(publicPath)) {
  app.use('/admin', express.static(publicPath));
}

if (staticFilesPath) {
  app.use('/files', express.static(staticFilesPath));
}

const db = new Database(config.dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS license_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_plain TEXT,
    key_hash TEXT UNIQUE NOT NULL,
    days INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    activated_at TEXT,
    expires_at TEXT,
    hwid_hash TEXT,
    last_seen_at TEXT,
    is_revoked INTEGER NOT NULL DEFAULT 0
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS license_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER NOT NULL,
    product_code TEXT NOT NULL,
    days INTEGER NOT NULL,
    activated_at TEXT,
    expires_at TEXT,
    UNIQUE(key_id, product_code)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS product_overrides (
    product_code TEXT PRIMARY KEY,
    status TEXT,
    updated_at TEXT
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS license_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER NOT NULL,
    hwid_hash TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_inject_at TEXT,
    device_info TEXT,
    is_revoked INTEGER NOT NULL DEFAULT 0,
    UNIQUE(key_id, hwid_hash)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS license_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER,
    hwid_hash TEXT,
    ip TEXT,
    event_type TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS download_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT UNIQUE NOT NULL,
    key_hash TEXT NOT NULL,
    hwid_hash TEXT NOT NULL,
    product_code TEXT,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    issued_ip TEXT,
    issued_ua TEXT,
    used_at TEXT,
    used_ip TEXT,
    used_ua TEXT
  )
`);

function ensureColumn(table, column, type) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  const exists = columns.some((col) => col.name === column);
  if (!exists) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
  }
}

ensureColumn('license_keys', 'key_plain', 'TEXT');
ensureColumn('license_devices', 'last_inject_at', 'TEXT');
ensureColumn('license_devices', 'device_info', 'TEXT');
ensureColumn('license_products', 'status', 'TEXT');

const dropPlaintextKeys = config.drop_plaintext_keys !== false && !storePlaintextKeys;
if (dropPlaintextKeys) {
  db.exec('UPDATE license_keys SET key_plain = NULL');
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function hashKeyWithPepper(rawKey, pepper) {
  return sha256Hex(`${pepper}|key|${rawKey}`);
}

function hashKey(rawKey) {
  return hashKeyWithPepper(rawKey, config.pepper);
}

function hashHwid(rawHwid) {
  return sha256Hex(`${config.pepper}|hwid|${rawHwid}`);
}

function maybeRotateKeyHash(row, rawKey) {
  if (!row || !rawKey) {
    return;
  }
  const currentHash = hashKey(rawKey);
  if (!currentHash || row.key_hash === currentHash) {
    return;
  }
  try {
    db.prepare('UPDATE license_keys SET key_hash = ? WHERE id = ?').run(currentHash, row.id);
    row.key_hash = currentHash;
  } catch (err) {
    // Ignore rotation failures (likely duplicate hash or race).
  }
}

function randomKey() {
  const raw = crypto.randomBytes(20).toString('hex').toUpperCase();
  return `${raw.slice(0, 8)}-${raw.slice(8, 16)}-${raw.slice(16, 24)}-${raw.slice(24, 32)}-${raw.slice(32, 40)}`;
}

function nowIso() {
  return new Date().toISOString();
}

function sanitizeUserAgent(value) {
  return sanitizeLogField(value, 160);
}

function getRequestIp(req) {
  return sanitizeLogField(req.ip || '', 64);
}

function getRequestUserAgent(req) {
  return sanitizeUserAgent(req.get('user-agent') || '');
}

function normalizeKey(rawKey) {
  return String(rawKey || '').trim();
}

function normalizeProductStatus(value) {
  if (value === undefined || value === null) {
    return '';
  }
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized) {
    return '';
  }
  const disabled = new Set(['off', 'down', 'offline', 'disabled']);
  if (disabled.has(normalized)) {
    return 'disabled';
  }
  const allowed = new Set(['ready', 'updating', 'safe', 'risky', 'disabled']);
  return allowed.has(normalized) ? normalized : null;
}

const productOverrides = new Map();

function loadProductOverrides() {
  productOverrides.clear();
  const rows = db.prepare('SELECT product_code, status FROM product_overrides').all();
  for (const row of rows) {
    const normalized = normalizeProductStatus(row.status);
    if (normalized) {
      productOverrides.set(row.product_code, normalized);
    }
  }
}

function getProductOverrideStatus(productCode) {
  return productOverrides.get(productCode) || '';
}

function resolveProductStatus(_rowStatus, overrideStatus, _configStatus) {
  return normalizeProductStatus(overrideStatus) || 'disabled';
}

function isInjectableStatus(status) {
  const normalized = normalizeProductStatus(status);
  return normalized === 'safe' || normalized === 'risky';
}

loadProductOverrides();

function isSha256Hex(value) {
  return /^[a-f0-9]{64}$/i.test(String(value || ''));
}

function findKeyRow(rawKey) {
  const normalized = normalizeKey(rawKey);
  if (!normalized) {
    return null;
  }
  const isHash = isSha256Hex(normalized);
  if (isHash) {
    const direct = db.prepare('SELECT * FROM license_keys WHERE key_hash = ?').get(normalized);
    if (direct) {
      return direct;
    }
  }
  const row = db.prepare('SELECT * FROM license_keys WHERE key_plain = ?').get(normalized);
  if (row) {
    if (!isHash) {
      maybeRotateKeyHash(row, normalized);
    }
    return row;
  }
  for (const pepper of pepperCandidates) {
    const candidate = hashKeyWithPepper(normalized, pepper);
    const match = db.prepare('SELECT * FROM license_keys WHERE key_hash = ?').get(candidate);
    if (match) {
      if (!isHash) {
        maybeRotateKeyHash(match, normalized);
      }
      return match;
    }
  }
  return null;
}

function compareVersions(left, right) {
  const parse = (value) =>
    String(value || '')
      .split('.')
      .map((part) => {
        const match = part.match(/\d+/);
        return match ? parseInt(match[0], 10) : 0;
      });
  const a = parse(left);
  const b = parse(right);
  const size = Math.max(a.length, b.length);
  for (let i = 0; i < size; i += 1) {
    const av = a[i] || 0;
    const bv = b[i] || 0;
    if (av > bv) return 1;
    if (av < bv) return -1;
  }
  return 0;
}

function collectDeviceInfo(body) {
  if (body && body.device_info && typeof body.device_info === 'object' && !Array.isArray(body.device_info)) {
    return body.device_info;
  }
  return {
    cpu: (body && body.device_cpu) || '',
    gpu: (body && body.device_gpu) || '',
    build: (body && body.device_build) || '',
    os: (body && body.device_os) || '',
    name: (body && body.device_name) || '',
    arch: (body && body.device_arch) || '',
    cores: body && body.device_cores,
    ram_gb: body && body.device_ram_gb,
    disk_gb: body && body.device_disk_gb,
    locale: (body && body.device_locale) || '',
    timezone: (body && body.device_timezone) || '',
    bios: (body && body.device_bios) || '',
    board: (body && body.device_board) || '',
    smbios: (body && body.device_smbios) || '',
    hwid_score: body && body.hwid_score,
    hwid_flags: body && body.hwid_flags,
  };
}

function normalizeDeviceInfo(info) {
  if (!info || typeof info !== 'object') {
    return null;
  }
  const cleaned = {};
  const setText = (key, value, maxLen) => {
    const text = sanitizeLogField(value, maxLen);
    if (text) {
      cleaned[key] = text;
    }
  };
  const setNumber = (key, value, min, max) => {
    const num = Number(value);
    if (!Number.isFinite(num)) {
      return;
    }
    let out = num;
    if (Number.isFinite(min)) out = Math.max(min, out);
    if (Number.isFinite(max)) out = Math.min(max, out);
    cleaned[key] = out;
  };
  const setFlags = (key, value) => {
    if (!Array.isArray(value)) {
      return;
    }
    const flags = value
      .map((entry) => sanitizeLogField(entry, 64))
      .filter(Boolean)
      .slice(0, 12);
    if (flags.length > 0) {
      cleaned[key] = flags;
    }
  };

  setText('cpu', info.cpu, 200);
  setText('gpu', info.gpu, 200);
  setText('build', info.build, 120);
  setText('os', info.os, 120);
  setText('name', info.name, 120);
  setText('arch', info.arch, 32);
  setNumber('cores', info.cores, 1, 512);
  setNumber('ram_gb', info.ram_gb, 0, 4096);
  setNumber('disk_gb', info.disk_gb, 0, 32768);
  setText('locale', info.locale, 32);
  setText('timezone', info.timezone, 64);
  setText('bios', info.bios, 128);
  setText('board', info.board, 128);
  setText('smbios', info.smbios, 128);
  setNumber('hwid_score', info.hwid_score, 0, 1000);
  setFlags('hwid_flags', info.hwid_flags);
  if (info.last_hwid_check) {
    setText('last_hwid_check', info.last_hwid_check, 64);
  }

  return Object.keys(cleaned).length > 0 ? cleaned : null;
}

function escapeSigField(value) {
  return String(value || '')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

function buildSigPayload(payload) {
  const lines = [`ok=${payload.ok ? 1 : 0}`, `ts=${payload.ts}`, `nonce=${payload.nonce}`];
  if (payload.error) {
    lines.push(`error=${escapeSigField(payload.error)}`);
  }
  if (payload.min_version) {
    lines.push(`min_version=${escapeSigField(payload.min_version)}`);
  }
  if (payload.update_url) {
    lines.push(`update_url=${escapeSigField(payload.update_url)}`);
  }
  if (payload.expires_at) {
    lines.push(`expires_at=${escapeSigField(payload.expires_at)}`);
  }
  if (payload.dll_url) {
    lines.push(`dll_url=${escapeSigField(payload.dll_url)}`);
  }
  if (payload.dll_sha256) {
    lines.push(`dll_sha256=${escapeSigField(payload.dll_sha256)}`);
  }
  if (payload.event_token) {
    lines.push(`event_token=${escapeSigField(payload.event_token)}`);
  }
  if (Array.isArray(payload.programs)) {
    for (const program of payload.programs) {
      lines.push(
        `program=${escapeSigField(program.code)}|${escapeSigField(program.name)}|` +
        `${escapeSigField(program.updated_at)}|${escapeSigField(program.expires_at)}|` +
        `${escapeSigField(program.dll_url)}|${escapeSigField(program.status)}|` +
        `${escapeSigField(program.avatar_url || '')}|${escapeSigField(program.watermark)}|` +
        `${escapeSigField(program.payload_sha256)}`
      );
    }
  }
  return lines.join('\n');
}

function buildUpdateSigPayload(payload) {
  const lines = [`ok=${payload.ok ? 1 : 0}`, `ts=${payload.ts}`, `nonce=${payload.nonce}`];
  if (payload.error) {
    lines.push(`error=${escapeSigField(payload.error)}`);
  }
  if (payload.version) {
    lines.push(`version=${escapeSigField(payload.version)}`);
  }
  if (payload.url) {
    lines.push(`url=${escapeSigField(payload.url)}`);
  }
  if (payload.sha256) {
    lines.push(`sha256=${escapeSigField(payload.sha256)}`);
  }
  return lines.join('\n');
}

function sendSigned(res, payload) {
  const signed = {
    ...payload,
    ts: Date.now(),
    nonce: crypto.randomBytes(16).toString('hex'),
  };
  const sigPayload = buildSigPayload(signed);
  const signature = crypto.sign('sha256', Buffer.from(sigPayload, 'utf8'), responseSigningKey);
  signed.sig = signature.toString('base64');
  return res.json(signed);
}

function sendSignedUpdate(res, payload) {
  const signed = {
    ...payload,
    ts: Date.now(),
    nonce: crypto.randomBytes(16).toString('hex'),
  };
  const sigPayload = buildUpdateSigPayload(signed);
  const signature = crypto.sign('sha256', Buffer.from(sigPayload, 'utf8'), responseSigningKey);
  signed.sig = signature.toString('base64');
  return res.json(signed);
}

function logEvent(eventType, keyId, hwidHash, ip, detail) {
  db.prepare(
    'INSERT INTO license_events (key_id, hwid_hash, ip, event_type, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(keyId || null, hwidHash || null, ip || null, eventType, detail || null, nowIso());
}

function sanitizeLogField(value, maxLen) {
  if (!value) {
    return '';
  }
  const limit = Number.isFinite(maxLen) ? maxLen : 300;
  const text = String(value).replace(/[\r\n\t]/g, ' ').trim();
  return text.length > limit ? text.slice(0, limit) : text;
}

function countRecentEvents(keyId, eventType, minutes) {
  const since = new Date(Date.now() - minutes * 60000).toISOString();
  const row = db.prepare(
    'SELECT COUNT(1) AS count FROM license_events WHERE key_id = ? AND event_type = ? AND created_at >= ?'
  ).get(keyId, eventType, since);
  return row ? row.count : 0;
}

function revokeKey(keyId, reason) {
  db.prepare('UPDATE license_keys SET is_revoked = 1 WHERE id = ?').run(keyId);
  logEvent('revoked', keyId, null, null, reason);
}

function maybeRevokeForEvent(keyId, eventType) {
  if (!keyId) return;
  if (eventType === 'device_limit') {
    const maxCount = Number(config.revoke_on_device_limit_count || 0);
    const windowMinutes = Number(config.revoke_on_device_limit_window_minutes || 0);
    if (maxCount > 0 && windowMinutes > 0) {
      const count = countRecentEvents(keyId, eventType, windowMinutes);
      if (count >= maxCount) {
        revokeKey(keyId, `device_limit:${count}`);
      }
    }
  }
  if (eventType === 'download_hwid_mismatch') {
    const maxCount = Number(config.revoke_on_hwid_mismatch_count || 0);
    const windowMinutes = Number(config.revoke_on_hwid_mismatch_window_minutes || 0);
    if (maxCount > 0 && windowMinutes > 0) {
      const count = countRecentEvents(keyId, eventType, windowMinutes);
      if (count >= maxCount) {
        revokeKey(keyId, `hwid_mismatch:${count}`);
      }
    }
  }
  if (eventType === 'validate_ok') {
    const maxPerHour = Number(config.max_validations_per_hour || 0);
    if (maxPerHour > 0) {
      const count = countRecentEvents(keyId, eventType, 60);
      if (count > maxPerHour) {
        revokeKey(keyId, `validate_rate:${count}`);
      }
    }
  }
}

function addDays(date, days) {
  const next = new Date(date.getTime());
  next.setDate(next.getDate() + days);
  return next;
}

function makeDownloadToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', config.pepper).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function makeUpdateToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', config.pepper).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyDownloadToken(token) {
  if (!token || !token.includes('.')) {
    return null;
  }
  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }
  const [body, sig] = parts;
  const expected = crypto.createHmac('sha256', config.pepper).update(body).digest('base64url');
  if (sig.length !== expected.length) {
    return null;
  }
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return null;
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
  if (!payload.exp || Date.now() > payload.exp) {
    return null;
  }
  return payload;
}

function verifyUpdateToken(token) {
  if (!token || !token.includes('.')) {
    return null;
  }
  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }
  const [body, sig] = parts;
  const expected = crypto.createHmac('sha256', config.pepper).update(body).digest('base64url');
  if (sig.length !== expected.length) {
    return null;
  }
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return null;
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
  if (!payload.exp || Date.now() > payload.exp) {
    return null;
  }
  return payload;
}

let lastTokenCleanup = 0;
function cleanupDownloadTokens() {
  if (!Number.isFinite(downloadTokenCleanupMinutes) || downloadTokenCleanupMinutes <= 0) {
    return;
  }
  const now = Date.now();
  if (now - lastTokenCleanup < 10 * 60 * 1000) {
    return;
  }
  lastTokenCleanup = now;
  const cutoff = new Date(now - downloadTokenCleanupMinutes * 60000).toISOString();
  db.prepare('DELETE FROM download_tokens WHERE expires_at <= ? OR used_at <= ?').run(cutoff, cutoff);
}

function getDownloadTokenTtlSeconds() {
  if (Number.isFinite(downloadTokenDefaultTtlSeconds) && downloadTokenDefaultTtlSeconds > 0) {
    return downloadTokenDefaultTtlSeconds;
  }
  return 300;
}

function issueDownloadToken({ keyHash, hwidHash, productCode, ip, userAgent }) {
  cleanupDownloadTokens();
  const ttlSeconds = getDownloadTokenTtlSeconds();
  for (let i = 0; i < 3; i += 1) {
    const tokenId = crypto.randomBytes(16).toString('hex');
    const exp = Date.now() + ttlSeconds * 1000;
    const payload = {
      key_hash: keyHash,
      hwid_hash: hwidHash,
      exp,
      jti: tokenId,
    };
    if (productCode) {
      payload.product_code = productCode;
    }
    const token = makeDownloadToken(payload);
    try {
      db.prepare(
        'INSERT INTO download_tokens (token_id, key_hash, hwid_hash, product_code, issued_at, expires_at, issued_ip, issued_ua) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).run(tokenId, keyHash, hwidHash, productCode || null, nowIso(), new Date(exp).toISOString(), ip || null, userAgent || null);
      return { token, tokenId };
    } catch (_) {
      // Retry on token_id collision.
    }
  }
  return null;
}

function countRecentDownloads(keyHash, minutes) {
  if (!Number.isFinite(minutes) || minutes <= 0) {
    return 0;
  }
  const since = new Date(Date.now() - minutes * 60000).toISOString();
  const row = db.prepare(
    'SELECT COUNT(1) AS count FROM download_tokens WHERE key_hash = ? AND used_at IS NOT NULL AND used_at >= ?'
  ).get(keyHash, since);
  return row ? row.count : 0;
}

function handleValidate(req, res) {
  const key = (req.body && req.body.key) || '';
  const hwid = (req.body && req.body.hwid) || '';
  const loaderVersion = (req.body && req.body.version) || '';
  const hwidScore = Number(req.body.hwid_score) || 0;
  const hwidFlags = Array.isArray(req.body.hwid_flags) ? req.body.hwid_flags : [];
  const requestIp = getRequestIp(req);
  const requestUa = getRequestUserAgent(req);
  if (!key || !hwid) {
    logEvent('validate_missing', null, null, requestIp, 'missing_key_or_hwid');
    return sendSigned(res.status(400), { ok: false, error: 'missing_key_or_hwid' });
  }

  // HWID Spoof Detection - автоблокировка при высоком score
  if (hwidScore >= 70) {
    logEvent('hwid_spoof_blocked', null, null, requestIp,
      `score=${hwidScore},flags=${hwidFlags.join(',')}`);
    return sendSigned(res.status(403), { ok: false, error: 'hwid_invalid' });
  }

  // Логируем подозрительные HWID
  if (hwidScore >= 50) {
    logEvent('hwid_suspicious', null, null, requestIp,
      `score=${hwidScore},flags=${hwidFlags.join(',')}`);
  }

  const ip = requestIp;
  const normalizedKey = normalizeKey(key);
  const row = findKeyRow(normalizedKey);
  if (!row || row.is_revoked) {
    logEvent('validate_invalid', row ? row.id : null, null, requestIp, 'invalid_key');
    return sendSigned(res.status(403), { ok: false, error: 'invalid_key' });
  }
  const keyHash = row.key_hash || hashKey(normalizedKey);
  const hwidHash = hashHwid(hwid.trim());
  const eventTokenTtl = Number(config.event_token_ttl_seconds || 3600);
  const eventToken = makeUpdateToken({
    key_hash: keyHash,
    hwid_hash: hwidHash,
    exp: Date.now() + eventTokenTtl * 1000,
  });
  // Базовая информация об устройстве + HWID флаги
  let deviceInfo = normalizeDeviceInfo(collectDeviceInfo(req.body)) || {};
  if (hwidScore > 0) {
    deviceInfo.hwid_score = hwidScore;
  }
  if (hwidFlags.length > 0) {
    deviceInfo.hwid_flags = hwidFlags;
  }
  deviceInfo.last_hwid_check = nowIso();

  const now = new Date();
  let activatedAt = row.activated_at ? new Date(row.activated_at) : null;
  let expiresAt = row.expires_at ? new Date(row.expires_at) : null;

  if (!activatedAt) {
    activatedAt = now;
    expiresAt = addDays(now, row.days);
    db.prepare(
      'UPDATE license_keys SET activated_at = ?, expires_at = ?, hwid_hash = ?, last_seen_at = ? WHERE id = ?'
    ).run(activatedAt.toISOString(), expiresAt.toISOString(), hwidHash, nowIso(), row.id);
  } else {
    if (expiresAt && now > expiresAt) {
      logEvent('validate_expired', row.id, hwidHash, ip, 'expired');
      return sendSigned(res.status(403), { ok: false, error: 'expired' });
    }
    db.prepare('UPDATE license_keys SET last_seen_at = ?, hwid_hash = ? WHERE id = ?').run(nowIso(), hwidHash, row.id);
  }

  const minVersion = config.min_loader_version || '';
  const updateUrl = config.update_url || '';
  if (minVersion && compareVersions(loaderVersion, minVersion) < 0) {
    logEvent('update_required', row.id, hwidHash, ip, `version=${loaderVersion}`);
    return sendSigned(res.status(426), {
      ok: false,
      error: 'update_required',
      min_version: minVersion,
      update_url: updateUrl,
    });
  }

  if (row.hwid_hash) {
    const existing = db.prepare(
      'SELECT id FROM license_devices WHERE key_id = ? AND hwid_hash = ?'
    ).get(row.id, row.hwid_hash);
    if (!existing) {
      db.prepare(
        'INSERT OR IGNORE INTO license_devices (key_id, hwid_hash, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?)'
      ).run(row.id, row.hwid_hash, nowIso(), nowIso());
    }
  }

  const parsedMax = Number(config.max_devices_per_key);
  const maxDevices = Number.isFinite(parsedMax) ? parsedMax : 1;
  const deviceRow = db.prepare(
    'SELECT * FROM license_devices WHERE key_id = ? AND hwid_hash = ? AND is_revoked = 0'
  ).get(row.id, hwidHash);
  if (!deviceRow) {
    const countRow = db.prepare(
      'SELECT COUNT(1) AS count FROM license_devices WHERE key_id = ? AND is_revoked = 0'
    ).get(row.id);
    const deviceCount = countRow ? countRow.count : 0;
    if (maxDevices > 0 && deviceCount >= maxDevices) {
      logEvent('device_limit', row.id, hwidHash, ip, `limit=${maxDevices}`);
      maybeRevokeForEvent(row.id, 'device_limit');
      return sendSigned(res.status(403), { ok: false, error: 'device_limit' });
    }
    const deviceInfoJson = Object.keys(deviceInfo).length > 0 ? JSON.stringify(deviceInfo) : null;
    db.prepare(
      'INSERT INTO license_devices (key_id, hwid_hash, first_seen_at, last_seen_at, device_info) VALUES (?, ?, ?, ?, ?)'
    ).run(row.id, hwidHash, nowIso(), nowIso(), deviceInfoJson);
  } else {
    const deviceInfoJson = Object.keys(deviceInfo).length > 0 ? JSON.stringify(deviceInfo) : null;
    db.prepare(
      'UPDATE license_devices SET last_seen_at = ?, device_info = ? WHERE id = ?'
    ).run(nowIso(), deviceInfoJson, deviceRow.id);
  }

  let productRows = db.prepare('SELECT * FROM license_products WHERE key_id = ?').all(row.id);
  if (productRows.length === 0 && productMap.size > 0) {
    const insertProduct = db.prepare('INSERT INTO license_products (key_id, product_code, days) VALUES (?, ?, ?)');
    const insertAll = db.transaction(() => {
      for (const product of productMap.values()) {
        insertProduct.run(row.id, product.code, row.days);
      }
    });
    insertAll();
    productRows = db.prepare('SELECT * FROM license_products WHERE key_id = ?').all(row.id);
  }

  if (productRows.length === 0) {
    if (!legacyDownloadEnabled) {
      logEvent('download_disabled', row.id, hwidHash, requestIp, 'legacy_disabled');
      return sendSigned(res.status(403), { ok: false, error: 'no_products' });
    }
    const tokenInfo = issueDownloadToken({
      keyHash,
      hwidHash,
      productCode: null,
      ip: requestIp,
      userAgent: requestUa,
    });
    if (!tokenInfo) {
      logEvent('download_token_fail', row.id, hwidHash, requestIp, 'issue_failed');
      return sendSigned(res.status(500), { ok: false, error: 'download_token_failed' });
    }
    const watermarkId = buildWatermarkId({ keyHash, hwidHash, productCode: 'default' });
    const overlay = buildWatermarkOverlay({
      watermark: watermarkId,
      productCode: 'default',
      tokenId: tokenInfo.tokenId,
    });
    let dllHash = computePayloadHashWithOverlay(defaultPayloadPath, overlay);
    if (!dllHash) {
      dllHash = getPayloadHash(defaultPayloadPath);
    }
    const dllUrl = `${config.baseUrl.replace(/\/$/, '')}/download?token=${encodeURIComponent(tokenInfo.token)}`;
    return sendSigned(res, {
      ok: true,
      expires_at: (expiresAt || addDays(now, row.days)).toISOString(),
      dll_url: dllUrl,
      dll_sha256: dllHash,
      event_token: eventToken,
      programs: [],
    });
  }

  const programs = [];
  const updateProduct = db.prepare('UPDATE license_products SET activated_at = ?, expires_at = ? WHERE id = ?');

  for (const productRow of productRows) {
    let productActivated = productRow.activated_at ? new Date(productRow.activated_at) : null;
    let productExpires = productRow.expires_at ? new Date(productRow.expires_at) : null;
    if (!productActivated) {
      productActivated = activatedAt || now;
      productExpires = addDays(productActivated, productRow.days);
      updateProduct.run(productActivated.toISOString(), productExpires.toISOString(), productRow.id);
    }

    if (productExpires && now > productExpires) {
      continue;
    }

    const productConfig = productMap.get(productRow.product_code);
    if (!productConfig) {
      continue;
    }
    const overrideStatus = getProductOverrideStatus(productRow.product_code);
    const status = resolveProductStatus(productRow.status, overrideStatus, productConfig.status);
    const watermark = buildWatermarkId({
      keyHash,
      hwidHash,
      productCode: productRow.product_code,
    });
    let dllUrl = '';
    let payloadHash = productConfig.payload_hash || getPayloadHash(productConfig.payload_path);
    if (legacyDownloadEnabled) {
      const tokenInfo = issueDownloadToken({
        keyHash,
        hwidHash,
        productCode: productRow.product_code,
        ip: requestIp,
        userAgent: requestUa,
      });
      if (!tokenInfo) {
        logEvent('download_token_fail', row.id, hwidHash, requestIp, 'issue_failed');
        return sendSigned(res.status(500), { ok: false, error: 'download_token_failed' });
      }
      const overlay = buildWatermarkOverlay({
        watermark,
        productCode: productRow.product_code,
        tokenId: tokenInfo.tokenId,
      });
      payloadHash = computePayloadHashWithOverlay(productConfig.payload_path, overlay);
      if (!payloadHash) {
        payloadHash = productConfig.payload_hash || getPayloadHash(productConfig.payload_path);
      }
      dllUrl = `${config.baseUrl.replace(/\/$/, '')}/download?token=${encodeURIComponent(tokenInfo.token)}`;
    }

    programs.push({
      code: productConfig.code,
      name: productConfig.name,
      updated_at: productConfig.updated_at,
      expires_at: productExpires ? productExpires.toISOString() : '',
      dll_url: dllUrl,
      status,
      avatar_url: productConfig.avatar_url || '',
      watermark,
      payload_sha256: payloadHash,
    });
  }

  if (programs.length === 0) {
    logEvent('validate_expired', row.id, hwidHash, ip, 'expired_products');
    return sendSigned(res.status(403), { ok: false, error: 'expired' });
  }

  logEvent('validate_ok', row.id, hwidHash, ip, `version=${loaderVersion}`);
  maybeRevokeForEvent(row.id, 'validate_ok');
  return sendSigned(res, {
    ok: true,
    event_token: eventToken,
    programs,
  });
}

app.post('/validate', handleValidate);

function handleDownload(req, res) {
  if (!legacyDownloadEnabled) {
    logEvent('download_disabled', null, null, getRequestIp(req), 'legacy_disabled');
    return res.status(410).json({ ok: false, error: 'download_disabled' });
  }
  const token = req.query.token;
  const requestIp = getRequestIp(req);
  const requestUa = getRequestUserAgent(req);
  const payload = verifyDownloadToken(token);
  if (!payload) {
    logEvent('download_invalid', null, null, requestIp, 'invalid_token');
    return res.status(403).json({ ok: false, error: 'invalid_token' });
  }
  if (downloadTokenOneTime || downloadTokenBindIp || downloadTokenBindUserAgent || downloadTokenMaxPerHour > 0) {
    const tokenRow = db.prepare('SELECT * FROM download_tokens WHERE token_id = ?').get(payload.jti);
    if (!tokenRow) {
      logEvent('download_invalid', null, payload.hwid_hash || null, requestIp, 'token_unknown');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (tokenRow.expires_at && Date.now() > new Date(tokenRow.expires_at).getTime()) {
      logEvent('download_invalid', null, payload.hwid_hash || null, requestIp, 'token_expired');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (tokenRow.key_hash !== payload.key_hash || tokenRow.hwid_hash !== payload.hwid_hash) {
      logEvent('download_invalid', null, payload.hwid_hash || null, requestIp, 'token_mismatch');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    const expectedProduct = payload.product_code || null;
    if ((tokenRow.product_code || null) !== expectedProduct) {
      logEvent('download_invalid', null, payload.hwid_hash || null, requestIp, 'token_product_mismatch');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (downloadTokenOneTime && tokenRow.used_at) {
      logEvent('download_invalid', null, payload.hwid_hash || null, requestIp, 'token_reuse');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (downloadTokenBindIp && tokenRow.issued_ip && tokenRow.issued_ip !== requestIp) {
      logEvent('download_invalid', null, payload.hwid_hash || null, requestIp, 'token_ip_mismatch');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (downloadTokenBindUserAgent && tokenRow.issued_ua && tokenRow.issued_ua !== requestUa) {
      logEvent('download_invalid', null, payload.hwid_hash || null, requestIp, 'token_ua_mismatch');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (downloadTokenMaxPerHour > 0) {
      const count = countRecentDownloads(payload.key_hash, downloadTokenRateLimitMinutes);
      if (count >= downloadTokenMaxPerHour) {
        logEvent('download_rate_limit', null, payload.hwid_hash || null, requestIp, `limit=${downloadTokenMaxPerHour}`);
        return res.status(429).json({ ok: false, error: 'rate_limited' });
      }
    }
  }

  const row = db.prepare('SELECT * FROM license_keys WHERE key_hash = ?').get(payload.key_hash);
  if (!row || row.is_revoked) {
    logEvent('download_invalid', row ? row.id : null, payload.hwid_hash || null, requestIp, 'invalid_key');
    return res.status(403).json({ ok: false, error: 'invalid_key' });
  }
  const deviceRow = db.prepare(
    'SELECT id FROM license_devices WHERE key_id = ? AND hwid_hash = ? AND is_revoked = 0'
  ).get(row.id, payload.hwid_hash);
  if (!deviceRow) {
    logEvent('download_hwid_mismatch', row.id, payload.hwid_hash, requestIp, 'device_not_registered');
    maybeRevokeForEvent(row.id, 'download_hwid_mismatch');
    return res.status(403).json({ ok: false, error: 'hwid_mismatch' });
  }
  if (payload.product_code) {
    const productRow = db.prepare(
      'SELECT * FROM license_products WHERE key_id = ? AND product_code = ?'
    ).get(row.id, payload.product_code);
    if (!productRow) {
      logEvent('download_invalid', row.id, payload.hwid_hash, requestIp, 'invalid_product');
      return res.status(403).json({ ok: false, error: 'invalid_product' });
    }
    const productConfig = productMap.get(payload.product_code);
    const overrideStatus = getProductOverrideStatus(payload.product_code);
    const status = resolveProductStatus(productRow.status, overrideStatus, productConfig ? productConfig.status : '');
    if (!isInjectableStatus(status)) {
      logEvent('download_blocked', row.id, payload.hwid_hash, requestIp, `status=${status || 'unknown'}`);
      return res.status(403).json({ ok: false, error: 'status_blocked' });
    }
  }
  logEvent('download', row.id, payload.hwid_hash, requestIp, payload.product_code || 'default');

  let payloadPath = config.payloadPath;
  if (payload.product_code) {
    const productRow = db.prepare(
      'SELECT * FROM license_products WHERE key_id = ? AND product_code = ?'
    ).get(row.id, payload.product_code);
    if (!productRow) {
      logEvent('download_invalid', row.id, payload.hwid_hash, requestIp, 'invalid_product');
      return res.status(403).json({ ok: false, error: 'invalid_product' });
    }
    const expiresAt = productRow.expires_at ? new Date(productRow.expires_at) : null;
    if (expiresAt && Date.now() > expiresAt.getTime()) {
      logEvent('download_expired', row.id, payload.hwid_hash, requestIp, 'expired_product');
      return res.status(403).json({ ok: false, error: 'expired' });
    }
    const productConfig = productMap.get(payload.product_code);
    if (productConfig) {
      payloadPath = productConfig.payload_path;
    }
  } else {
    const expiresAt = row.expires_at ? new Date(row.expires_at) : null;
    if (expiresAt && Date.now() > expiresAt.getTime()) {
      logEvent('download_expired', row.id, payload.hwid_hash, requestIp, 'expired_key');
      return res.status(403).json({ ok: false, error: 'expired' });
    }
  }

  const resolvedPath = path.resolve(__dirname, payloadPath || './data/payload.dll');
  if (!fs.existsSync(resolvedPath)) {
    logEvent('download_missing', row.id, payload.hwid_hash, requestIp, 'missing_payload');
    return res.status(404).json({ ok: false, error: 'missing_payload' });
  }

  const watermarkId = buildWatermarkId({
    keyHash: payload.key_hash,
    hwidHash: payload.hwid_hash,
    productCode: payload.product_code || 'default',
  });
  const overlay = buildWatermarkOverlay({
    watermark: watermarkId,
    productCode: payload.product_code || 'default',
    tokenId: payload.jti,
  });
  const payloadBuffer = buildPayloadBufferWithOverlay(payloadPath || './data/payload.dll', overlay);
  if (!payloadBuffer) {
    logEvent('download_missing', row.id, payload.hwid_hash, requestIp, 'missing_payload');
    return res.status(404).json({ ok: false, error: 'missing_payload' });
  }

  if (downloadTokenOneTime || downloadTokenMaxPerHour > 0) {
    db.prepare(
      'UPDATE download_tokens SET used_at = ?, used_ip = ?, used_ua = ? WHERE token_id = ?'
    ).run(nowIso(), requestIp || null, requestUa || null, payload.jti);
  }

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Length', payloadBuffer.length);
  return res.send(payloadBuffer);
}

app.get('/download', handleDownload);

// Структура защиты для встраивания в DLL
function buildProtectionOverlay(processInfo) {
  if (!processInfo || typeof processInfo !== 'object') {
    console.error('[buildProtectionOverlay] Invalid processInfo:', typeof processInfo, processInfo);
    return null;
  }

  // Ограничиваем количество модулей и функций, чтобы не превысить лимит
  const maxModules = 50;
  const maxFunctions = 20;

  const protection = {
    cpuid: Number(processInfo.cpuid) || 0,
    timestamp: Number(processInfo.timestamp) || Date.now(),
    process_id: Number(processInfo.process_id) || 0,
    modules: (Array.isArray(processInfo.modules) ? processInfo.modules : [])
      .slice(0, maxModules)
      .map(mod => ({
        name: String(mod.name || '').substring(0, 128),
        base_address: String(mod.base_address || '0x0').substring(0, 32),
        size: Number(mod.size || 0),
      })),
    functions: (Array.isArray(processInfo.functions) ? processInfo.functions : [])
      .slice(0, maxFunctions)
      .map(func => ({
        module: String(func.module || '').substring(0, 64),
        function: String(func.function || '').substring(0, 64),
        address: String(func.address || '0x0').substring(0, 32),
      })),
  };

  const json = JSON.stringify(protection);
  const data = Buffer.from(json, 'utf8');

  if (data.length > 4096) {
    console.error('[buildProtectionOverlay] Data too large:', data.length, 'bytes');
    // Пытаемся уменьшить размер, убрав часть данных
    protection.modules = protection.modules.slice(0, Math.floor(protection.modules.length / 2));
    protection.functions = protection.functions.slice(0, Math.floor(protection.functions.length / 2));
    const json2 = JSON.stringify(protection);
    const data2 = Buffer.from(json2, 'utf8');
    if (data2.length > 4096) {
      console.error('[buildProtectionOverlay] Still too large after reduction:', data2.length, 'bytes');
      return null;
    }
    const header = Buffer.alloc(10);
    header.write(PROTECTION_MAGIC, 0, 'ascii');
    header.writeUInt8(PROTECTION_VERSION, 5);
    header.writeUInt32LE(data2.length, 6);
    return Buffer.concat([header, data2]);
  }

  // Формат: MAGIC (5 байт) + VERSION (1 байт) + LENGTH (4 байта LE) + DATA
  const header = Buffer.alloc(10);
  header.write(PROTECTION_MAGIC, 0, 'ascii');
  header.writeUInt8(PROTECTION_VERSION, 5);
  header.writeUInt32LE(data.length, 6);

  return Buffer.concat([header, data]);
}

// Генерация защищённой DLL с overlay
function buildProtectedPayload(payloadPath, protectionOverlay, watermarkOverlay) {
  const buffer = getPayloadBuffer(payloadPath);
  if (!buffer) {
    return null;
  }

  const overlays = [];
  if (watermarkOverlay) {
    overlays.push(watermarkOverlay);
  }
  if (protectionOverlay) {
    overlays.push(protectionOverlay);
  }

  if (overlays.length === 0) {
    return buffer;
  }

  return Buffer.concat([buffer, ...overlays]);
}

// Кэш для уникальных DLL (временное хранилище)
const protectedDllCache = new Map();
const PROTECTED_DLL_TTL_MS = 5 * 60 * 1000; // 5 минут

function cleanupProtectedDllCache() {
  const now = Date.now();
  for (const [key, entry] of protectedDllCache.entries()) {
    if (now - entry.timestamp > PROTECTED_DLL_TTL_MS) {
      protectedDllCache.delete(key);
    }
  }
}

// Endpoint для запроса защищённой DLL
function handleRequestDll(req, res) {
  const token = (req.body && req.body.token) || '';
  const productCode = sanitizeLogField((req.body && req.body.product_code) || '', 64);
  const processInfo = req.body && req.body.process_info;
  const requestIp = getRequestIp(req);
  const requestUa = getRequestUserAgent(req);

  // Логируем входящий запрос для отладки
  console.log('[request-dll] Received request:', {
    hasToken: !!token,
    tokenLength: token.length,
    productCode,
    hasProcessInfo: !!processInfo,
    processInfoType: typeof processInfo,
    processInfoKeys: processInfo ? Object.keys(processInfo) : [],
  });

  if (!token) {
    console.error('[request-dll] Missing token');
    return res.status(400).json({ ok: false, error: 'missing_token' });
  }

  // Обрабатываем случай, когда process_info может быть строкой (если Express не распарсил)
  let parsedProcessInfo = processInfo;
  if (typeof processInfo === 'string') {
    try {
      parsedProcessInfo = JSON.parse(processInfo);
    } catch (err) {
      console.error('[request-dll] Failed to parse processInfo string:', err);
      return res.status(400).json({ ok: false, error: 'invalid_process_info_format' });
    }
  }

  if (!parsedProcessInfo || typeof parsedProcessInfo !== 'object' || Array.isArray(parsedProcessInfo)) {
    console.error('[request-dll] Missing or invalid processInfo:', typeof parsedProcessInfo, parsedProcessInfo);
    return res.status(400).json({ ok: false, error: 'missing_process_info' });
  }

  // Проверяем event token
  const tokenPayload = verifyUpdateToken(token);
  if (!tokenPayload) {
    logEvent('request_dll_invalid', null, null, requestIp, 'invalid_token');
    return res.status(403).json({ ok: false, error: 'invalid_token' });
  }

  const keyHash = tokenPayload.key_hash;
  const hwidHash = tokenPayload.hwid_hash;

  // Проверяем ключ
  const row = db.prepare('SELECT * FROM license_keys WHERE key_hash = ?').get(keyHash);
  if (!row || row.is_revoked) {
    logEvent('request_dll_invalid', row ? row.id : null, hwidHash, requestIp, 'invalid_key');
    return res.status(403).json({ ok: false, error: 'invalid_key' });
  }

  // Проверяем устройство
  const deviceRow = db.prepare(
    'SELECT id FROM license_devices WHERE key_id = ? AND hwid_hash = ? AND is_revoked = 0'
  ).get(row.id, hwidHash);
  if (!deviceRow) {
    logEvent('request_dll_hwid_mismatch', row.id, hwidHash, requestIp, 'device_not_registered');
    return res.status(403).json({ ok: false, error: 'hwid_mismatch' });
  }

  // Определяем путь к payload
  let payloadPath = config.payloadPath;
  if (productCode) {
    const productRow = db.prepare(
      'SELECT * FROM license_products WHERE key_id = ? AND product_code = ?'
    ).get(row.id, productCode);
    if (!productRow) {
      logEvent('request_dll_invalid', row.id, hwidHash, requestIp, 'invalid_product');
      return res.status(403).json({ ok: false, error: 'invalid_product' });
    }
    const expiresAt = productRow.expires_at ? new Date(productRow.expires_at) : null;
    if (expiresAt && Date.now() > expiresAt.getTime()) {
      logEvent('request_dll_expired', row.id, hwidHash, requestIp, 'expired_product');
      return res.status(403).json({ ok: false, error: 'expired' });
    }
    const productConfig = productMap.get(productCode);
    if (productConfig) {
      payloadPath = productConfig.payload_path;
    }
    const overrideStatus = getProductOverrideStatus(productCode);
    const status = resolveProductStatus(productRow.status, overrideStatus, productConfig ? productConfig.status : '');
    if (!isInjectableStatus(status)) {
      logEvent('request_dll_blocked', row.id, hwidHash, requestIp, `status=${status || 'unknown'}`);
      return res.status(403).json({ ok: false, error: 'status_blocked' });
    }
  } else {
    const expiresAt = row.expires_at ? new Date(row.expires_at) : null;
    if (expiresAt && Date.now() > expiresAt.getTime()) {
      logEvent('request_dll_expired', row.id, hwidHash, requestIp, 'expired_key');
      return res.status(403).json({ ok: false, error: 'expired' });
    }
  }

  const resolvedPath = path.resolve(__dirname, payloadPath || './data/payload.dll');
  if (!fs.existsSync(resolvedPath)) {
    logEvent('request_dll_missing', row.id, hwidHash, requestIp, 'missing_payload');
    return res.status(404).json({ ok: false, error: 'missing_payload' });
  }

  // Генерируем уникальный ключ для кэша
  const cacheKey = crypto.createHash('sha256')
    .update(keyHash)
    .update(hwidHash)
    .update(productCode || 'default')
    .update(JSON.stringify(processInfo))
    .update(String(Date.now())) // Уникальность для каждого запроса
    .digest('hex')
    .slice(0, 32);

  // Очищаем старые записи
  cleanupProtectedDllCache();

  // Генерируем overlay с защитой
  const protectionOverlay = buildProtectionOverlay(parsedProcessInfo);
  if (!protectionOverlay) {
    console.error('[request-dll] Failed to build protection overlay for key:', keyHash, 'hwid:', hwidHash);
    logEvent('request_dll_fail', row.id, hwidHash, requestIp, 'protection_overlay_failed');
    return res.status(500).json({ ok: false, error: 'protection_failed' });
  }

  // Генерируем watermark overlay
  const watermarkId = buildWatermarkId({
    keyHash,
    hwidHash,
    productCode: productCode || 'default',
  });
  const tokenId = crypto.randomBytes(16).toString('hex');
  const watermarkOverlay = buildWatermarkOverlay({
    watermark: watermarkId,
    productCode: productCode || 'default',
    tokenId,
  });

  // Собираем защищённую DLL
  const protectedBuffer = buildProtectedPayload(resolvedPath, protectionOverlay, watermarkOverlay);
  if (!protectedBuffer) {
    logEvent('request_dll_fail', row.id, hwidHash, requestIp, 'build_failed');
    return res.status(500).json({ ok: false, error: 'build_failed' });
  }

  // Сохраняем в кэш
  let encKey = null;
  let encIv = null;
  let encAlg = null;
  if (payloadEncryptionEnabled) {
    encKey = crypto.randomBytes(32);
    encIv = crypto.randomBytes(16);
    encAlg = 'aes-256-cbc';
  }

  protectedDllCache.set(cacheKey, {
    buffer: protectedBuffer,
    timestamp: Date.now(),
    keyHash,
    hwidHash,
    encKey,
    encIv,
    encAlg,
  });

  // Вычисляем hash
  const dllHash = crypto.createHash('sha256').update(protectedBuffer).digest('hex');

  // Генерируем токен для скачивания
  const downloadTokenTtl = getDownloadTokenTtlSeconds();
  const downloadTokenPayload = {
    key_hash: keyHash,
    hwid_hash: hwidHash,
    exp: Date.now() + downloadTokenTtl * 1000,
    jti: tokenId,
    cache_key: cacheKey, // Уникальный ключ для кэша
  };
  if (productCode) {
    downloadTokenPayload.product_code = productCode;
  }
  const downloadToken = makeDownloadToken(downloadTokenPayload);

  // Сохраняем токен в БД
  try {
    db.prepare(
      'INSERT INTO download_tokens (token_id, key_hash, hwid_hash, product_code, issued_at, expires_at, issued_ip, issued_ua) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(tokenId, keyHash, hwidHash, productCode || null, nowIso(), new Date(Date.now() + downloadTokenTtl * 1000).toISOString(), requestIp || null, requestUa || null);
  } catch (err) {
    // Игнорируем ошибки (возможно дубликат)
  }

  logEvent('request_dll_ok', row.id, hwidHash, requestIp, productCode || 'default');

  const dllUrl = `${config.baseUrl.replace(/\/$/, '')}/download-protected?token=${encodeURIComponent(downloadToken)}`;

  // Возвращаем успешный ответ
  const responsePayload = {
    ok: true,
    dll_url: dllUrl,
    dll_sha256: dllHash,
  };
  if (encKey && encIv) {
    responsePayload.dll_key = encKey.toString('base64');
    responsePayload.dll_iv = encIv.toString('base64');
    responsePayload.dll_alg = encAlg;
  }
  return res.status(200).json(responsePayload);
}

app.post('/request-dll', handleRequestDll);

// Endpoint для скачивания защищённой DLL
function handleDownloadProtected(req, res) {
  const token = req.query.token;
  const requestIp = getRequestIp(req);
  const requestUa = getRequestUserAgent(req);
  const payload = verifyDownloadToken(token);

  if (!payload || !payload.cache_key) {
    logEvent('download_protected_invalid', null, null, requestIp, 'invalid_token');
    return res.status(403).json({ ok: false, error: 'invalid_token' });
  }

  if (downloadTokenRequireId && !payload.jti) {
    logEvent('download_protected_invalid', null, payload.hwid_hash || null, requestIp, 'missing_token_id');
    return res.status(403).json({ ok: false, error: 'invalid_token' });
  }

  if (downloadTokenRequireId || downloadTokenOneTime || downloadTokenBindIp || downloadTokenBindUserAgent || downloadTokenMaxPerHour > 0) {
    const tokenRow = db.prepare('SELECT * FROM download_tokens WHERE token_id = ?').get(payload.jti);
    if (!tokenRow) {
      logEvent('download_protected_invalid', null, payload.hwid_hash || null, requestIp, 'token_unknown');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (tokenRow.expires_at && Date.now() > new Date(tokenRow.expires_at).getTime()) {
      logEvent('download_protected_invalid', null, payload.hwid_hash || null, requestIp, 'token_expired');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (tokenRow.key_hash !== payload.key_hash || tokenRow.hwid_hash !== payload.hwid_hash) {
      logEvent('download_protected_invalid', null, payload.hwid_hash || null, requestIp, 'token_mismatch');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    const expectedProduct = payload.product_code || null;
    if ((tokenRow.product_code || null) !== expectedProduct) {
      logEvent('download_protected_invalid', null, payload.hwid_hash || null, requestIp, 'token_product_mismatch');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (downloadTokenOneTime && tokenRow.used_at) {
      logEvent('download_protected_invalid', null, payload.hwid_hash || null, requestIp, 'token_reuse');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (downloadTokenBindIp && tokenRow.issued_ip && tokenRow.issued_ip !== requestIp) {
      logEvent('download_protected_invalid', null, payload.hwid_hash || null, requestIp, 'token_ip_mismatch');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (downloadTokenBindUserAgent && tokenRow.issued_ua && tokenRow.issued_ua !== requestUa) {
      logEvent('download_protected_invalid', null, payload.hwid_hash || null, requestIp, 'token_ua_mismatch');
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    if (downloadTokenMaxPerHour > 0) {
      const count = countRecentDownloads(payload.key_hash, downloadTokenRateLimitMinutes);
      if (count >= downloadTokenMaxPerHour) {
        logEvent('download_rate_limit', null, payload.hwid_hash || null, requestIp, `limit=${downloadTokenMaxPerHour}`);
        return res.status(429).json({ ok: false, error: 'rate_limited' });
      }
    }
  }

  // Проверяем кэш
  const cached = protectedDllCache.get(payload.cache_key);
  if (!cached) {
    logEvent('download_protected_expired', null, payload.hwid_hash || null, requestIp, 'cache_expired');
    return res.status(403).json({ ok: false, error: 'expired' });
  }

  // Проверяем соответствие
  if (cached.keyHash !== payload.key_hash || cached.hwidHash !== payload.hwid_hash) {
    logEvent('download_protected_mismatch', null, payload.hwid_hash || null, requestIp, 'mismatch');
    return res.status(403).json({ ok: false, error: 'mismatch' });
  }

  if ((downloadTokenOneTime || downloadTokenMaxPerHour > 0) && payload.jti) {
    db.prepare(
      'UPDATE download_tokens SET used_at = ?, used_ip = ?, used_ua = ? WHERE token_id = ?'
    ).run(nowIso(), requestIp || null, requestUa || null, payload.jti);
  }

  // Удаляем из кэша (одноразовое использование)
  protectedDllCache.delete(payload.cache_key);

  logEvent('download_protected', null, payload.hwid_hash || null, requestIp, payload.product_code || 'default');

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  let payloadBuffer = cached.buffer;
  if (cached.encKey && cached.encIv && cached.encAlg === 'aes-256-cbc') {
    const cipher = crypto.createCipheriv(cached.encAlg, cached.encKey, cached.encIv);
    payloadBuffer = Buffer.concat([cipher.update(payloadBuffer), cipher.final()]);
  }

  res.setHeader('Content-Length', payloadBuffer.length);
  return res.send(payloadBuffer);
}

app.get('/download-protected', handleDownloadProtected);

function requireAdmin(req, res, next) {
  const adminToken = config.admin_token || '';
  if (!adminToken || adminToken === 'change_me') {
    return res.status(403).json({ ok: false, error: 'admin_disabled' });
  }
  const header = req.get('Authorization') || '';
  if (!header.toLowerCase().startsWith('bearer ')) {
    return res.status(403).json({ ok: false, error: 'unauthorized' });
  }
  const token = header.slice(7).trim();
  if (!token || token !== adminToken) {
    return res.status(403).json({ ok: false, error: 'unauthorized' });
  }
  return next();
}

app.post('/admin/revoke', requireAdmin, (req, res) => {
  const key = (req.body && req.body.key) || '';
  if (!key) {
    return res.status(400).json({ ok: false, error: 'missing_key' });
  }
  const row = findKeyRow(key);
  if (!row) {
    return res.status(404).json({ ok: false, error: 'not_found' });
  }
  db.prepare('UPDATE license_keys SET is_revoked = 1 WHERE id = ?').run(row.id);
  logEvent('admin_revoke', row.id, null, req.ip, null);
  return res.json({ ok: true });
});

app.post('/admin/unrevoke', requireAdmin, (req, res) => {
  const key = (req.body && req.body.key) || '';
  if (!key) {
    return res.status(400).json({ ok: false, error: 'missing_key' });
  }
  const row = findKeyRow(key);
  if (!row) {
    return res.status(404).json({ ok: false, error: 'not_found' });
  }
  db.prepare('UPDATE license_keys SET is_revoked = 0 WHERE id = ?').run(row.id);
  logEvent('admin_unrevoke', row.id, null, req.ip, null);
  return res.json({ ok: true });
});

app.get('/admin/products', requireAdmin, (req, res) => {
  const products = Array.from(productMap.values()).map((product) => {
    const overrideStatus = getProductOverrideStatus(product.code);
    const statusEffective = resolveProductStatus('', overrideStatus, product.status);
    return {
      code: product.code,
      name: product.name,
      status_override: overrideStatus,
      status_effective: statusEffective,
      updated_at: product.updated_at,
      avatar_url: product.avatar_url || '',
    };
  });
  return res.json({ ok: true, products });
});

app.post('/admin/product/status', requireAdmin, (req, res) => {
  const productCode = (req.body && req.body.product_code) || '';
  const statusRaw = req.body && Object.prototype.hasOwnProperty.call(req.body, 'status')
    ? req.body.status
    : undefined;
  if (!productCode) {
    return res.status(400).json({ ok: false, error: 'missing_product' });
  }
  if (statusRaw === undefined) {
    return res.status(400).json({ ok: false, error: 'missing_status' });
  }
  if (!productMap.has(productCode)) {
    return res.status(400).json({ ok: false, error: 'unknown_product' });
  }
  const normalizedStatus = normalizeProductStatus(statusRaw);
  if (normalizedStatus === null) {
    return res.status(400).json({ ok: false, error: 'invalid_status' });
  }
  if (!normalizedStatus) {
    db.prepare('DELETE FROM product_overrides WHERE product_code = ?').run(productCode);
    productOverrides.delete(productCode);
    logEvent('admin_product_status', null, null, req.ip, `product=${productCode},status=default`);
    return res.json({ ok: true });
  }
  db.prepare(
    'INSERT INTO product_overrides (product_code, status, updated_at) VALUES (?, ?, ?) ' +
    'ON CONFLICT(product_code) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at'
  ).run(productCode, normalizedStatus, nowIso());
  productOverrides.set(productCode, normalizedStatus);
  logEvent('admin_product_status', null, null, req.ip, `product=${productCode},status=${normalizedStatus}`);
  return res.json({ ok: true });
});

app.post('/admin/product/assign', requireAdmin, (req, res) => {
  const key = (req.body && req.body.key) || '';
  const productCode = (req.body && req.body.product_code) || '';
  const days = Number(req.body && req.body.days);
  if (!key || !productCode) {
    return res.status(400).json({ ok: false, error: 'missing_key_or_product' });
  }
  const row = findKeyRow(key);
  if (!row) {
    return res.status(404).json({ ok: false, error: 'not_found' });
  }
  if (!productMap.has(productCode)) {
    return res.status(400).json({ ok: false, error: 'unknown_product' });
  }
  const assignDays = Number.isFinite(days) && days > 0 ? days : row.days;
  const existing = db.prepare(
    'SELECT id FROM license_products WHERE key_id = ? AND product_code = ?'
  ).get(row.id, productCode);
  if (existing) {
    db.prepare('UPDATE license_products SET days = ? WHERE id = ?').run(assignDays, existing.id);
  } else {
    db.prepare(
      'INSERT INTO license_products (key_id, product_code, days) VALUES (?, ?, ?)'
    ).run(row.id, productCode, assignDays);
  }
  logEvent('admin_product_assign', row.id, null, req.ip, `product=${productCode},days=${assignDays}`);
  return res.json({ ok: true });
});

app.post('/admin/key/create', requireAdmin, (req, res) => {
  const providedKey = (req.body && req.body.key) || '';
  const days = Number(req.body && req.body.days) || 7;
  const requestedProduct = (req.body && req.body.product) || '';
  let products = (req.body && req.body.products) || [];
  const explicitProducts =
    Boolean(requestedProduct) ||
    (Array.isArray(req.body && req.body.products) && req.body.products.length > 0) ||
    (typeof (req.body && req.body.products) === 'string' && String(req.body.products).trim());
  if (
    (!Array.isArray(products) && typeof products !== 'string') ||
    (Array.isArray(products) && products.length === 0) ||
    (typeof products === 'string' && !products.trim())
  ) {
    if (requestedProduct) {
      products = requestedProduct;
    }
  }
  const key = providedKey.trim() || randomKey();

  const keyHash = hashKey(key);
  try {
    const insertKey = storePlaintextKeys
      ? 'INSERT INTO license_keys (key_hash, key_plain, days, created_at) VALUES (?, ?, ?, ?)'
      : 'INSERT INTO license_keys (key_hash, days, created_at) VALUES (?, ?, ?)';
    const info = storePlaintextKeys
      ? db.prepare(insertKey).run(keyHash, key, days, nowIso())
      : db.prepare(insertKey).run(keyHash, days, nowIso());

    const productCodes = Array.isArray(products)
      ? products.map((p) => String(p || '').trim()).filter(Boolean)
      : String(products || '').split(',').map((p) => p.trim()).filter(Boolean);
    if (explicitProducts && productCodes.length === 0) {
      return res.status(400).json({ ok: false, error: 'unknown_product' });
    }
    if (productCodes.length) {
      const insertProduct = db.prepare('INSERT OR IGNORE INTO license_products (key_id, product_code, days) VALUES (?, ?, ?)');
      const insertAll = db.transaction(() => {
        for (const code of productCodes) {
          if (productMap.has(code)) {
            insertProduct.run(info.lastInsertRowid, code, days);
          }
        }
      });
      insertAll();
    }

    logEvent('admin_key_create', info.lastInsertRowid, null, req.ip, `days=${days}`);
    return res.json({ ok: true, key });
  } catch (err) {
    return res.status(400).json({ ok: false, error: 'create_failed' });
  }
});

app.get('/admin/keys', requireAdmin, (req, res) => {
  const limit = Math.min(Number(req.query && req.query.limit) || 50, 500);
  const keyColumns = exposePlaintextKeys
    ? 'id, key_hash, key_plain, days, created_at, activated_at, expires_at, last_seen_at, is_revoked'
    : 'id, key_hash, days, created_at, activated_at, expires_at, last_seen_at, is_revoked';
  const keys = db.prepare(
    `SELECT ${keyColumns} FROM license_keys ORDER BY id DESC LIMIT ?`
  ).all(limit);
  return res.json(keys);
});

app.get('/admin/key', requireAdmin, (req, res) => {
  const key = (req.query && req.query.key) || '';
  if (!key) {
    return res.status(400).json({ ok: false, error: 'missing_key' });
  }
  const row = findKeyRow(key);
  if (!row) {
    return res.status(404).json({ ok: false, error: 'not_found' });
  }
  const products = db.prepare(
    'SELECT product_code, days, activated_at, expires_at FROM license_products WHERE key_id = ? ORDER BY product_code'
  ).all(row.id);
  if (!exposePlaintextKeys) {
    const safeRow = { ...row };
    delete safeRow.key_plain;
    return res.json({ ok: true, key: safeRow, products });
  }
  return res.json({ ok: true, key: row, products });
});

app.get('/admin/devices', requireAdmin, (req, res) => {
  const limit = Math.min(Number(req.query && req.query.limit) || 100, 500);
  const devices = db.prepare(
    'SELECT id, key_id, hwid_hash, first_seen_at, last_seen_at, last_inject_at, device_info, is_revoked FROM license_devices ORDER BY last_seen_at DESC LIMIT ?'
  ).all(limit);
  return res.json(devices);
});

app.post('/admin/device/revoke', requireAdmin, (req, res) => {
  const key = (req.body && req.body.key) || '';
  const hwid = (req.body && req.body.hwid) || '';
  if (!key || !hwid) {
    return res.status(400).json({ ok: false, error: 'missing_key_or_hwid' });
  }
  const row = findKeyRow(key);
  if (!row) {
    return res.status(404).json({ ok: false, error: 'not_found' });
  }
  const hwidHash = hashHwid(hwid.trim());
  db.prepare(
    'UPDATE license_devices SET is_revoked = 1 WHERE key_id = ? AND hwid_hash = ?'
  ).run(row.id, hwidHash);
  logEvent('admin_device_revoke', row.id, hwidHash, req.ip, null);
  return res.json({ ok: true });
});

app.post('/admin/device/allow', requireAdmin, (req, res) => {
  const key = (req.body && req.body.key) || '';
  const hwid = (req.body && req.body.hwid) || '';
  if (!key || !hwid) {
    return res.status(400).json({ ok: false, error: 'missing_key_or_hwid' });
  }
  const row = findKeyRow(key);
  if (!row) {
    return res.status(404).json({ ok: false, error: 'not_found' });
  }
  const hwidHash = hashHwid(hwid.trim());
  db.prepare(
    'INSERT OR IGNORE INTO license_devices (key_id, hwid_hash, first_seen_at, last_seen_at, is_revoked) VALUES (?, ?, ?, ?, 0)'
  ).run(row.id, hwidHash, nowIso(), nowIso());
  db.prepare(
    'UPDATE license_devices SET is_revoked = 0 WHERE key_id = ? AND hwid_hash = ?'
  ).run(row.id, hwidHash);
  logEvent('admin_device_allow', row.id, hwidHash, req.ip, null);
  return res.json({ ok: true });
});

app.get('/admin/events', requireAdmin, (req, res) => {
  const limit = Math.min(Number(req.query && req.query.limit) || 500, 1000);
  const offset = Math.max(Number(req.query && req.query.offset) || 0, 0);
  const key = (req.query && req.query.key) || '';
  if (key) {
    const keyRow = findKeyRow(key);
    if (!keyRow) {
      return res.json([]);
    }
    const events = db.prepare(
      'SELECT * FROM license_events WHERE key_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
    ).all(keyRow.id, limit, offset);
    return res.json(events);
  }
  const events = db.prepare(
    'SELECT * FROM license_events ORDER BY created_at DESC LIMIT ? OFFSET ?'
  ).all(limit, offset);
  return res.json(events);
});

function handleEvent(req, res) {
  const key = (req.body && req.body.key) || '';
  const hwid = (req.body && req.body.hwid) || '';
  const eventType = (req.body && req.body.type) || '';
  const token = (req.body && req.body.token) || '';
  const productCode = sanitizeLogField((req.body && req.body.product_code) || '', 64);
  const detail = sanitizeLogField((req.body && req.body.detail) || '', 512);
  if (!eventType) {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }
  const tokenPayload = verifyUpdateToken(token);
  if (!tokenPayload) {
    return res.status(403).json({ ok: false, error: 'invalid_token' });
  }
  let row = null;
  let hwidHash = '';
  if (key && hwid) {
    row = findKeyRow(key);
    if (!row || row.is_revoked) {
      return res.status(403).json({ ok: false, error: 'invalid_key' });
    }
    hwidHash = hashHwid(hwid.trim());
    const keyHash = row.key_hash || hashKey(key);
    if (tokenPayload.key_hash !== keyHash || tokenPayload.hwid_hash !== hwidHash) {
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
  } else {
    const tokenKeyHash = String(tokenPayload.key_hash || '');
    const tokenHwidHash = String(tokenPayload.hwid_hash || '');
    if (!isSha256Hex(tokenKeyHash) || !isSha256Hex(tokenHwidHash)) {
      return res.status(403).json({ ok: false, error: 'invalid_token' });
    }
    row = findKeyRow(tokenKeyHash);
    if (!row || row.is_revoked) {
      return res.status(403).json({ ok: false, error: 'invalid_key' });
    }
    hwidHash = tokenHwidHash;
  }
  const allowedTypes = new Set([
    'inject_ok',
    'inject_fail',
    'download_fail',
    'verify_fail',
    'heartbeat'
  ]);
  if (!allowedTypes.has(eventType)) {
    return res.status(400).json({ ok: false, error: 'invalid_event' });
  }
  const deviceRow = db.prepare(
    'SELECT id FROM license_devices WHERE key_id = ? AND hwid_hash = ? AND is_revoked = 0'
  ).get(row.id, hwidHash);
  if (!deviceRow) {
    return res.status(403).json({ ok: false, error: 'hwid_mismatch' });
  }

  const deviceInfo = normalizeDeviceInfo(collectDeviceInfo(req.body));
  const deviceInfoJson = deviceInfo && Object.keys(deviceInfo).length > 0 ? JSON.stringify(deviceInfo) : null;
  if (eventType === 'inject_ok' || eventType === 'heartbeat') {
    db.prepare(
      'UPDATE license_devices SET last_seen_at = ?, last_inject_at = COALESCE(?, last_inject_at), device_info = COALESCE(?, device_info) WHERE id = ?'
    ).run(nowIso(), eventType === 'inject_ok' ? nowIso() : null, deviceInfoJson, deviceRow.id);
  }

  const fullDetail = [detail, productCode ? `product=${productCode}` : ''].filter(Boolean).join(' | ');
  logEvent(eventType, row.id, hwidHash, req.ip, fullDetail || null);

  // Генерируем временный сессионный ключ для пейлоада
  const sessionKey = crypto.randomBytes(16).toString('hex');

  return res.json({ ok: true, session_key: sessionKey });
}

app.post('/event', handleEvent);

function handleHealth(_req, res) {
  res.json({ ok: true });
}

app.get('/health', handleHealth);

function handleUpdateLatest(_req, res) {
  const url = config.update_url || '';
  const version = config.update_version || config.min_loader_version || '';
  const updatePath = config.update_path || '';
  if (!url || !version || !updatePath) {
    return sendSignedUpdate(res, { ok: false, error: 'missing_update' });
  }
  const resolved = resolvePath(updatePath);
  const sha256 = hashFileHex(resolved);
  if (!sha256) {
    return sendSignedUpdate(res, { ok: false, error: 'missing_update' });
  }
  const ttlSeconds = Number(config.update_token_ttl_seconds || 300);
  const token = makeUpdateToken({
    exp: Date.now() + ttlSeconds * 1000,
    version,
  });
  const downloadUrl = `${config.baseUrl.replace(/\/$/, '')}/update/download?token=${encodeURIComponent(token)}`;
  return sendSignedUpdate(res, { ok: true, version, url: downloadUrl, sha256 });
}

app.get('/update/latest', handleUpdateLatest);

function handleUpdateDownload(req, res) {
  const token = req.query.token;
  const payload = verifyUpdateToken(token);
  if (!payload) {
    return res.status(403).json({ ok: false, error: 'invalid_token' });
  }
  const updatePath = config.update_path || '';
  const resolvedPath = path.resolve(__dirname, updatePath || './data/loader.exe');
  if (!fs.existsSync(resolvedPath)) {
    return res.status(404).json({ ok: false, error: 'missing_update' });
  }
  res.setHeader('Content-Type', 'application/octet-stream');
  return res.sendFile(resolvedPath);
}

app.get('/update/download', handleUpdateDownload);

function normalizeSocketIp(value) {
  const text = String(value || '');
  if (text.startsWith('::ffff:')) {
    return text.slice(7);
  }
  return text;
}

function parseTcpRequestPayload(buffer) {
  const text = buffer.toString('utf8');
  const headerEnd = text.indexOf('\n\n');
  const headerBlock = headerEnd >= 0 ? text.slice(0, headerEnd) : text;
  const body = headerEnd >= 0 ? text.slice(headerEnd + 2) : '';
  const lines = headerBlock.split('\n').map((line) => line.replace(/\r$/, ''));
  const requestLine = lines.shift() || '';
  const [methodRaw, pathRaw] = requestLine.trim().split(' ');
  const headers = {};
  for (const line of lines) {
    if (!line) {
      continue;
    }
    const idx = line.indexOf(':');
    if (idx < 0) {
      continue;
    }
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key) {
      headers[key] = value;
    }
  }
  return {
    method: String(methodRaw || 'GET').toUpperCase(),
    path: pathRaw || '/',
    headers,
    body,
  };
}

function createTcpResponse() {
  return {
    statusCode: 200,
    headers: {},
    body: Buffer.alloc(0),
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(name, value) {
      this.headers[String(name || '').toLowerCase()] = String(value);
      return this;
    },
    json(payload) {
      this.body = Buffer.from(JSON.stringify(payload));
      return this;
    },
    send(payload) {
      if (Buffer.isBuffer(payload)) {
        this.body = payload;
      } else if (payload === undefined || payload === null) {
        this.body = Buffer.alloc(0);
      } else {
        this.body = Buffer.from(String(payload), 'utf8');
      }
      return this;
    },
    sendFile(filePath) {
      this.body = fs.readFileSync(filePath);
      return this;
    },
  };
}

function handleTcpFiles(pathname, res) {
  if (!staticFilesPath) {
    return res.status(404).json({ ok: false, error: 'not_found' });
  }
  const base = path.resolve(staticFilesPath);
  const relative = decodeURIComponent(pathname.slice('/files/'.length));
  const resolved = path.resolve(base, relative);
  if (!resolved.startsWith(base + path.sep) && resolved !== base) {
    return res.status(403).json({ ok: false, error: 'invalid_path' });
  }
  if (!fs.existsSync(resolved)) {
    return res.status(404).json({ ok: false, error: 'not_found' });
  }
  const stat = fs.statSync(resolved);
  if (!stat.isFile()) {
    return res.status(404).json({ ok: false, error: 'not_found' });
  }
  res.setHeader('Content-Type', 'application/octet-stream');
  return res.send(fs.readFileSync(resolved));
}

function dispatchTcpRequest({ method, path, headers, body, ip }) {
  let pathname = '/';
  let query = {};
  try {
    const url = new URL(`tcp://localhost${path}`);
    pathname = url.pathname || '/';
    query = Object.fromEntries(url.searchParams.entries());
  } catch (_) {
    pathname = path || '/';
  }

  let parsedBody = {};
  if (body && body.trim()) {
    try {
      parsedBody = JSON.parse(body);
    } catch (_) {
      parsedBody = {};
    }
  }

  const req = {
    body: parsedBody,
    query,
    ip,
    get(name) {
      const key = String(name || '').toLowerCase();
      return headers[key] || '';
    },
  };
  const res = createTcpResponse();
  const routeKey = `${method} ${pathname}`;

  switch (routeKey) {
    case 'POST /validate':
      handleValidate(req, res);
      break;
    case 'POST /event':
      handleEvent(req, res);
      break;
    case 'POST /request-dll':
      handleRequestDll(req, res);
      break;
    case 'GET /download':
      handleDownload(req, res);
      break;
    case 'GET /download-protected':
      handleDownloadProtected(req, res);
      break;
    case 'GET /update/latest':
      handleUpdateLatest(req, res);
      break;
    case 'GET /update/download':
      handleUpdateDownload(req, res);
      break;
    case 'GET /health':
      handleHealth(req, res);
      break;
    default:
      if (pathname.startsWith('/files/')) {
        handleTcpFiles(pathname, res);
      } else {
        res.status(404).json({ ok: false, error: 'not_found' });
      }
      break;
  }

  return res.body || Buffer.alloc(0);
}

function sendTcpFrame(socket, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload || ''), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length, 0);
  socket.write(header);
  if (body.length > 0) {
    socket.write(body);
  }
}

function startTcpServer() {
  if (!Number.isFinite(tcpPort) || tcpPort <= 0) {
    console.log('TCP server disabled (tcp_port not set).');
    return;
  }

  let server;
  let label = 'TCP';
  if (tcpTlsEnabled) {
    if (!tcpTlsKeyPath || !tcpTlsCertPath) {
      console.error('TCP TLS enabled but key/cert path missing.');
      return;
    }
    let tlsOptions;
    try {
      tlsOptions = {
        key: fs.readFileSync(tcpTlsKeyPath),
        cert: fs.readFileSync(tcpTlsCertPath),
        minVersion: 'TLSv1.2',
      };
      if (tcpTlsCaPath) {
        tlsOptions.ca = fs.readFileSync(tcpTlsCaPath);
      }
    } catch (err) {
      console.error('Failed to load TCP TLS credentials:', err.message);
      return;
    }
    label = 'TCPS';
    server = tls.createServer(tlsOptions, (socket) => {
      handleTcpSocket(socket);
    });
    server.on('tlsClientError', () => { });
  } else {
    server = net.createServer((socket) => {
      handleTcpSocket(socket);
    });
  }

  function handleTcpSocket(socket) {
    let buffer = Buffer.alloc(0);
    let handled = false;
    socket.setNoDelay(true);

    socket.on('data', (chunk) => {
      if (handled) {
        return;
      }
      buffer = Buffer.concat([buffer, chunk]);
      while (!handled && buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (length > tcpMaxFrameBytes) {
          socket.destroy();
          return;
        }
        if (buffer.length < 4 + length) {
          return;
        }
        const payload = buffer.slice(4, 4 + length);
        buffer = buffer.slice(4 + length);
        handled = true;
        const request = parseTcpRequestPayload(payload);
        const requestIp = sanitizeLogField(normalizeSocketIp(socket.remoteAddress || ''), 64);
        const response = dispatchTcpRequest({
          method: request.method,
          path: request.path,
          headers: request.headers,
          body: request.body,
          ip: requestIp,
        });
        sendTcpFrame(socket, response);
        socket.end();
      }
    });

    socket.on('error', () => { });
  }

  server.listen(tcpPort, () => {
    console.log(`${label} server listening on ${tcpPort}`);
  });
}

app.listen(config.port, () => {
  console.log(`Loader server listening on ${config.port}`);
});

startTcpServer();
