const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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
const watermarkEnabled = config.watermark_enabled !== false;
const watermarkMaxBytes = Number(config.watermark_max_bytes || 256);
const payloadEncryptionEnabled = config.payload_encryption_enabled !== false;
const payloadEncryptionKeyBytes = Number(config.payload_encryption_key_bytes || 32);
const payloadEncryptionIvBytes = Number(config.payload_encryption_iv_bytes || 12);
const payloadEncryptionTagBytes = Number(config.payload_encryption_tag_bytes || 16);
const WATERMARK_MAGIC = 'U3WM1';
const WATERMARK_VERSION = 1;
const PAYLOAD_MAGIC = 'U3E1';
const PAYLOAD_VERSION = 1;

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
  if (body && body.device_info && typeof body.device_info === 'object') {
    return body.device_info;
  }
  return {
    cpu: (body && body.device_cpu) || '',
    gpu: (body && body.device_gpu) || '',
    build: (body && body.device_build) || '',
    os: (body && body.device_os) || '',
    name: (body && body.device_name) || '',
  };
}

function normalizeDeviceInfo(info) {
  if (!info || typeof info !== 'object') {
    return '';
  }
  const cleaned = {
    cpu: String(info.cpu || ''),
    gpu: String(info.gpu || ''),
    build: String(info.build || ''),
    os: String(info.os || ''),
    name: String(info.name || ''),
  };
  if (!cleaned.cpu && !cleaned.gpu && !cleaned.build && !cleaned.os && !cleaned.name) {
    return '';
  }
  return JSON.stringify(cleaned);
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
  if (!payload.key_hash || !payload.hwid_hash) {
    return null;
  }
  if (downloadTokenRequireId && !payload.jti) {
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

app.post('/validate', (req, res) => {
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
  const eventTokenTtl = Number(config.event_token_ttl_seconds || 300);
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
    const watermark = buildWatermarkId({
      keyHash,
      hwidHash,
      productCode: productRow.product_code,
    });
    const overlay = buildWatermarkOverlay({
      watermark,
      productCode: productRow.product_code,
      tokenId: tokenInfo.tokenId,
    });
    let payloadHash = computePayloadHashWithOverlay(productConfig.payload_path, overlay);
    if (!payloadHash) {
      payloadHash = productConfig.payload_hash || getPayloadHash(productConfig.payload_path);
    }
    const dllUrl = `${config.baseUrl.replace(/\/$/, '')}/download?token=${encodeURIComponent(tokenInfo.token)}`;

    programs.push({
      code: productConfig.code,
      name: productConfig.name,
      updated_at: productConfig.updated_at,
      expires_at: productExpires ? productExpires.toISOString() : '',
      dll_url: dllUrl,
      status: productConfig.status,
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
});

app.get('/download', (req, res) => {
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
});

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
  const limit = Math.min(Number(req.query && req.query.limit) || 100, 500);
  const events = db.prepare(
    'SELECT * FROM license_events ORDER BY created_at DESC LIMIT ?'
  ).all(limit);
  return res.json(events);
});

app.post('/event', (req, res) => {
  const key = (req.body && req.body.key) || '';
  const hwid = (req.body && req.body.hwid) || '';
  const eventType = (req.body && req.body.type) || '';
  const token = (req.body && req.body.token) || '';
  const productCode = sanitizeLogField((req.body && req.body.product_code) || '', 64);
  const detail = sanitizeLogField((req.body && req.body.detail) || '', 512);
  if (!key || !hwid || !eventType) {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }
  const row = findKeyRow(key);
  if (!row || row.is_revoked) {
    return res.status(403).json({ ok: false, error: 'invalid_key' });
  }
  const hwidHash = hashHwid(hwid.trim());
  const tokenPayload = verifyUpdateToken(token);
  if (!tokenPayload || tokenPayload.key_hash !== row.key_hash || tokenPayload.hwid_hash !== hwidHash) {
    return res.status(403).json({ ok: false, error: 'invalid_token' });
  }
  const allowedTypes = new Set([
    'inject_ok',
    'inject_fail',
    'download_fail',
    'verify_fail'
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
  if (eventType === 'inject_ok') {
    db.prepare(
      'UPDATE license_devices SET last_inject_at = ?, device_info = COALESCE(?, device_info) WHERE id = ?'
    ).run(nowIso(), deviceInfo || null, deviceRow.id);
  }
  const fullDetail = [detail, productCode ? `product=${productCode}` : ''].filter(Boolean).join(' | ');
  logEvent(eventType, row.id, hwidHash, req.ip, fullDetail || null);
  return res.json({ ok: true });
});

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/update/latest', (_req, res) => {
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
});

app.get('/update/download', (req, res) => {
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
});

app.listen(config.port, () => {
  console.log(`Loader server listening on ${config.port}`);
});
