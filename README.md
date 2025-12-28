# u3-server

License validation and payload delivery service.

## What this repo contains
- TCP service for loader validation, updates, and payload download.
- SQLite database for keys/devices.
- Built-in admin panel at `/admin`.
- Optional admin client in `admin-client/` (local-only UI that proxies admin API).

## Requirements
- VPS (Linux recommended) or Windows Server.
- Node.js 18+ and npm.
- Build tools for `better-sqlite3` if prebuilds are not available.
- OpenSSL for response signing key generation.

## Configure
1) Copy the example config:
```
cp config.example.json config.json
```

2) Edit `config.json`:
- `baseUrl`: public TCP base (for example `tcps://example.com:4000`)
- `tcp_port`: TCP listen port for loader connections
- `tcp_tls_key_path` / `tcp_tls_cert_path` (enable TLS on the TCP port)
- `baseUrl` / `update_url` should use `tcps://` when TLS is enabled
- `payload_encrypt_enabled` (per-download payload encryption)
- `port`: HTTP listen port (admin panel + admin API)
- `pepper`: long random secret used to hash keys
- `admin_token`: long random secret for admin API
- `response_signing_private_key_path` / `response_signing_public_key_path`
- `payloadPath` or per-product `products[].payload_path`
- `update_path` and `update_version`
- `store_plaintext_keys` / `expose_plaintext_keys` (optional, lower security)

3) Create required directories:
```
mkdir -p data keys
```

4) Generate signing keys:
```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/response_private.pem
openssl rsa -in keys/response_private.pem -pubout -out keys/response_public.pem
```
Keep the private key only on the VPS. The public key is embedded into the loader.

## Install and run
```
npm install
npm start
```

Admin panel (HTTP): `http://your-domain:3000/admin/`
TCP server: `tcps://your-domain:4000`

## Create keys
```
npm run create-key -- --days 30 --products blitz
```
Keys are stored hashed by default. Enable `store_plaintext_keys` if you need to show full keys in the admin UI.

## Deploy on a VPS
1) Copy the repo to the VPS, for example `/opt/u3-server`.
2) Run with systemd:
```
[Unit]
Description=u3-server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/u3-server
ExecStart=/usr/bin/node /opt/u3-server/index.js
Restart=on-failure
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

Then:
```
sudo systemctl daemon-reload
sudo systemctl enable --now u3-server
```

3) Optional: put the HTTP admin panel behind a reverse proxy (nginx) for TLS.

### Nginx example (TLS reverse proxy for admin)
```
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
Expose the TCP port separately (no HTTP/HTTPS for loader traffic).

## Admin client (optional)
The admin client is included in `admin-client/` and binds to `127.0.0.1` only.
```
cd admin-client
cp config.example.json config.json
npm install
npm start
```

To access it remotely:
```
ssh -L 5175:127.0.0.1:5175 user@your-vps
```
Open `http://127.0.0.1:5175` locally.

## Files to upload from the build machine
- `data/payload.dll` (or per-product DLLs)
- `data/loader.exe` (for updates)

## Release checklist (VPS)
1) Pull latest changes and update `config.json` if needed.
2) Backup `data/keys.db`.
3) Upload new `data/loader.exe` and payload DLLs.
4) Update `update_version`, `update_url`, `min_loader_version`, and `products[].updated_at` in `config.json`.
5) Run `npm install` if dependencies changed.
6) Restart service: `sudo systemctl restart u3-server`.
