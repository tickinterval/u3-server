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
if (!config.pepper || config.pepper === 'change_me') {
  console.error('Set a strong pepper in config.json');
  process.exit(1);
}
const storePlaintextKeys = config.store_plaintext_keys === true;

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

function ensureColumn(table, column, type) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  const exists = columns.some((col) => col.name === column);
  if (!exists) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
  }
}

ensureColumn('license_keys', 'key_plain', 'TEXT');

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function hashKey(rawKey) {
  return sha256Hex(`${config.pepper}|key|${rawKey}`);
}

function randomKey() {
  const raw = crypto.randomBytes(20).toString('hex').toUpperCase();
  return `${raw.slice(0, 8)}-${raw.slice(8, 16)}-${raw.slice(16, 24)}-${raw.slice(24, 32)}-${raw.slice(32, 40)}`;
}

function nowIso() {
  return new Date().toISOString();
}

function parseArgs() {
  const args = process.argv.slice(2);
  let days = 7;
  let count = 1;
  let products = null;
  for (let i = 0; i < args.length; i += 1) {
    const value = args[i];
    if (value === '--days' && args[i + 1]) {
      days = Number(args[i + 1]);
      i += 1;
    } else if (value === '--count' && args[i + 1]) {
      count = Number(args[i + 1]);
      i += 1;
    } else if (value === '--products' && args[i + 1]) {
      products = args[i + 1];
      i += 1;
    }
  }
  return { days, count, products };
}

const { days, count, products } = parseArgs();
const configProducts = Array.isArray(config.products) ? config.products.map((p) => p.code).filter(Boolean) : [];
const productCodes = (products ? products.split(',') : configProducts).map((p) => p.trim()).filter(Boolean);
if (productCodes.length === 0) {
  console.warn('No products specified; generated keys will have no programs.');
}
const insertKey = storePlaintextKeys
  ? db.prepare('INSERT INTO license_keys (key_hash, key_plain, days, created_at) VALUES (?, ?, ?, ?)')
  : db.prepare('INSERT INTO license_keys (key_hash, days, created_at) VALUES (?, ?, ?)');
const insertProduct = db.prepare('INSERT INTO license_products (key_id, product_code, days) VALUES (?, ?, ?)');
const insertAll = db.transaction((keyValue, keyHash) => {
  const info = storePlaintextKeys
    ? insertKey.run(keyHash, keyValue, days, nowIso())
    : insertKey.run(keyHash, days, nowIso());
  for (const code of productCodes) {
    insertProduct.run(info.lastInsertRowid, code, days);
  }
});

for (let i = 0; i < count; i += 1) {
  let key = randomKey();
  let keyHash = hashKey(key);
  let inserted = false;
  while (!inserted) {
    try {
      insertAll(key, keyHash);
      inserted = true;
    } catch (err) {
      key = randomKey();
      keyHash = hashKey(key);
    }
  }
  console.log(key);
}
