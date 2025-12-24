const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const keyDir = path.join(__dirname, '..', 'keys');
const privatePath = path.join(keyDir, 'response_private.pem');
const publicPath = path.join(keyDir, 'response_public.pem');
const force = process.argv.includes('--force');

if (!fs.existsSync(keyDir)) {
  fs.mkdirSync(keyDir, { recursive: true });
}

if (!force && (fs.existsSync(privatePath) || fs.existsSync(publicPath))) {
  console.log('Keys already exist. Use --force to overwrite.');
  process.exit(0);
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

fs.writeFileSync(privatePath, privateKey, { mode: 0o600 });
fs.writeFileSync(publicPath, publicKey, { mode: 0o644 });

console.log(`Generated response signing keys in ${keyDir}`);
