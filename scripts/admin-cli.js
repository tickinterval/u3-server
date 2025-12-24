#!/usr/bin/env node
/* Simple admin CLI for keys/devices/events. */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const configPath = path.join(__dirname, '..', 'config.json');
if (!fs.existsSync(configPath)) {
  console.error('Missing config.json');
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
if (!config.dbPath) {
  console.error('Missing dbPath in config.json');
  process.exit(1);
}
if (!config.pepper) {
  console.error('Missing pepper in config.json');
  process.exit(1);
}

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

const db = new Database(path.isAbsolute(config.dbPath) ? config.dbPath : path.join(__dirname, '..', config.dbPath));

function usage() {
  console.log(`
Usage:
  node scripts/admin-cli.js list-keys [--limit N]
  node scripts/admin-cli.js key-info <KEY>
  node scripts/admin-cli.js revoke <KEY>
  node scripts/admin-cli.js unrevoke <KEY>
  node scripts/admin-cli.js devices <KEY>
  node scripts/admin-cli.js events [--limit N] [--key <KEY>]
`);
}

function getArg(flag) {
  const idx = process.argv.indexOf(flag);
  if (idx >= 0 && process.argv[idx + 1]) {
    return process.argv[idx + 1];
  }
  return null;
}

function isSha256Hex(value) {
  return /^[a-f0-9]{64}$/i.test(String(value || ''));
}

function hashKeyWithPepper(rawKey, pepper) {
  return crypto.createHash('sha256').update(`${pepper}|key|${rawKey}`).digest('hex');
}

function hashKey(rawKey) {
  return hashKeyWithPepper(rawKey, config.pepper);
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
    // Ignore rotation failures.
  }
}

function listKeys() {
  const limit = Number(getArg('--limit')) || 50;
  const rows = db.prepare(
    'SELECT id, key_hash, days, created_at, activated_at, expires_at, is_revoked FROM license_keys ORDER BY id DESC LIMIT ?'
  ).all(limit);
  console.table(rows);
}

function findKeyRow(key) {
  const normalized = String(key || '').trim();
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

function keyInfo(key) {
  const row = findKeyRow(key);
  if (!row) {
    console.error('Key not found');
    process.exit(1);
  }
  console.table([row]);
  const products = db.prepare(
    'SELECT product_code, days, activated_at, expires_at FROM license_products WHERE key_id = ? ORDER BY product_code'
  ).all(row.id);
  if (products.length) {
    console.log('\nProducts:');
    console.table(products);
  }
}

function revokeKey(key, revoke) {
  const row = findKeyRow(key);
  if (!row) {
    console.error('Key not found');
    process.exit(1);
  }
  db.prepare('UPDATE license_keys SET is_revoked = ? WHERE id = ?').run(revoke ? 1 : 0, row.id);
  console.log(revoke ? 'Revoked.' : 'Unrevoked.');
}

function listDevices(key) {
  const row = findKeyRow(key);
  if (!row) {
    console.error('Key not found');
    process.exit(1);
  }
  const devices = db.prepare(
    'SELECT hwid_hash, first_seen_at, last_seen_at, is_revoked FROM license_devices WHERE key_id = ? ORDER BY last_seen_at DESC'
  ).all(row.id);
  console.table(devices);
}

function listEvents() {
  const limit = Number(getArg('--limit')) || 100;
  const key = getArg('--key');
  if (key) {
    const row = findKeyRow(key);
    if (!row) {
      console.error('Key not found');
      process.exit(1);
    }
    const events = db.prepare(
      'SELECT created_at, event_type, ip, detail FROM license_events WHERE key_id = ? ORDER BY created_at DESC LIMIT ?'
    ).all(row.id, limit);
    console.table(events);
    return;
  }
  const events = db.prepare(
    'SELECT created_at, event_type, ip, detail FROM license_events ORDER BY created_at DESC LIMIT ?'
  ).all(limit);
  console.table(events);
}

const cmd = process.argv[2];
if (!cmd) {
  usage();
  process.exit(1);
}

if (cmd === 'list-keys') {
  listKeys();
} else if (cmd === 'key-info') {
  const key = process.argv[3];
  if (!key) {
    usage();
    process.exit(1);
  }
  keyInfo(key);
} else if (cmd === 'revoke') {
  const key = process.argv[3];
  if (!key) {
    usage();
    process.exit(1);
  }
  revokeKey(key, true);
} else if (cmd === 'unrevoke') {
  const key = process.argv[3];
  if (!key) {
    usage();
    process.exit(1);
  }
  revokeKey(key, false);
} else if (cmd === 'devices') {
  const key = process.argv[3];
  if (!key) {
    usage();
    process.exit(1);
  }
  listDevices(key);
} else if (cmd === 'events') {
  listEvents();
} else {
  usage();
  process.exit(1);
}
