#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const express = require('express');

const configPath = path.join(__dirname, 'config.json');
if (!fs.existsSync(configPath)) {
  console.error('Missing config.json');
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
if (!config.apiBaseUrl || !config.adminToken) {
  console.error('Set apiBaseUrl and adminToken in config.json');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 'loopback');
app.use((req, res, next) => {
  const address = req.socket.remoteAddress || '';
  if (address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1') {
    return next();
  }
  return res.status(403).send('Forbidden');
});
app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, 'public')));

async function apiRequest(method, route, { query, body } = {}) {
  const url = new URL(route, config.apiBaseUrl);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    }
  }

  const options = {
    method,
    headers: {
      Authorization: `Bearer ${config.adminToken}`,
    },
  };

  if (body) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch (_) {
    payload = { ok: false, error: 'invalid_json', raw: text };
  }
  return { status: response.status, payload };
}

app.get('/api/keys', async (req, res) => {
  const { status, payload } = await apiRequest('GET', '/admin/keys', {
    query: { limit: req.query.limit },
  });
  return res.status(status).json(payload);
});

app.get('/api/key', async (req, res) => {
  const { status, payload } = await apiRequest('GET', '/admin/key', {
    query: { key: req.query.key },
  });
  return res.status(status).json(payload);
});

app.post('/api/revoke', async (req, res) => {
  const { status, payload } = await apiRequest('POST', '/admin/revoke', {
    body: { key: req.body.key },
  });
  return res.status(status).json(payload);
});

app.post('/api/unrevoke', async (req, res) => {
  const { status, payload } = await apiRequest('POST', '/admin/unrevoke', {
    body: { key: req.body.key },
  });
  return res.status(status).json(payload);
});

app.get('/api/devices', async (req, res) => {
  const { status, payload } = await apiRequest('GET', '/admin/devices', {
    query: { key: req.query.key },
  });
  return res.status(status).json(payload);
});

app.post('/api/assign-product', async (req, res) => {
  const { status, payload } = await apiRequest('POST', '/admin/product/assign', {
    body: {
      key: req.body.key,
      product_code: req.body.product_code,
      days: req.body.days,
    },
  });
  return res.status(status).json(payload);
});

app.post('/api/create-key', async (req, res) => {
  const { status, payload } = await apiRequest('POST', '/admin/key/create', {
    body: {
      key: req.body.key,
      days: req.body.days,
      products: req.body.products,
    },
  });
  return res.status(status).json(payload);
});

app.get('/api/events', async (req, res) => {
  const { status, payload } = await apiRequest('GET', '/admin/events', {
    query: { key: req.query.key, limit: req.query.limit },
  });
  return res.status(status).json(payload);
});

const listenPort = config.listenPort || 5175;
app.listen(listenPort, '127.0.0.1', () => {
  console.log(`Admin client running on http://127.0.0.1:${listenPort}`);
});
