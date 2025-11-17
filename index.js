require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { Pool } = require('pg');
const crypto = require('crypto');
const https = require('https');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { createRemoteJWKSet, jwtVerify } = require('jose');

var {
  PORT = 3002,
  KEYCLOAK_BASE_URL = 'http://localhost:18000/keycloak',
  KEYCLOAK_ADMIN_USER = 'admin',
  KEYCLOAK_ADMIN_PASSWORD = 'admin',
  KEYCLOAK_REALM = 'telesign',
} = process.env;

var {
  ADMIN_DB_HOST = 'admin-db',
  ADMIN_DB_PORT = '5432',
  ADMIN_DB_USER = 'admin',
  ADMIN_DB_PASSWORD = 'admin',
  ADMIN_DB_DATABASE = 'admin',
  KONG_ADMIN_URL = 'http://localhost:8001',
  NETAWARE_ENC_KEY
} = process.env;

// Optional OIDC audience/issuer for portal authentication
const { OIDC_AUDIENCE = undefined, OIDC_ISSUER = undefined } = process.env;

// Keycloak retry/queue configuration
const {
  KC_IMMEDIATE_RETRY_ATTEMPTS = '3',      // attempts per call before enqueue
  KC_IMMEDIATE_RETRY_BACKOFF_MS = '500',  // base backoff ms, exponential
  KC_QUEUE_WORKER_INTERVAL_MS = '30000',  // worker polling interval
  KC_QUEUE_MAX_ATTEMPTS = '12',           // max attempts in queue processor
  KC_QUEUE_BACKOFF_BASE_MS = '5000',      // base backoff for queue retries
  KC_QUEUE_BACKOFF_MAX_MS = '600000',     // cap backoff (10 min)
} = process.env;

// OIDC / JWKS for Keycloak access token validation
const ISSUER = OIDC_ISSUER || `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}`;
const JWKS = createRemoteJWKSet(new URL(`${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs`));

console.log('ENV ::: ', ADMIN_DB_HOST, ADMIN_DB_PORT, KEYCLOAK_BASE_URL, KONG_ADMIN_URL);
console.log('Railway ENV ::: ', process.env.ADMIN_DB_HOST ? 'Set' : 'Not set');

const app = express();
app.use(express.json()); // Parse application/json
app.use(express.urlencoded({ extended: true })); // Parse application/x-www-form-urlencoded

// Enforce application/json only for methods that are expected to have a body
// app.use((req, res, next) => {
//   const method = String(req.method || '').toUpperCase();
//   if (['POST', 'PUT', 'PATCH'].includes(method)) {
//     const ct = String(req.headers['content-type'] || '').toLowerCase();
//     if (!ct.includes('application/json')) {
//       return res.status(415).json({ error: 'Only application/json is supported for this endpoint' });
//     }
//   }
//   next();
// });

app.use(cors());

// Serve static assets for portal and OpenAPI specs from ./public
app.use('/static', express.static(path.join(__dirname, 'public')));

// Verify Bearer token from Authorization header using Keycloak JWKS
async function verifyAccessToken(authHeader) {
  if (!authHeader) throw new Error('missing Authorization header');
  const m = String(authHeader).match(/^Bearer\\s+(.+)$/i);
  if (!m) throw new Error('invalid Authorization header');
  const token = m[1];
  const verifyOpts = { clockTolerance: '5s' };
  if (OIDC_ISSUER) verifyOpts.issuer = OIDC_ISSUER;
  if (OIDC_AUDIENCE) verifyOpts.audience = OIDC_AUDIENCE;
  const { payload } = await jwtVerify(token, JWKS, verifyOpts);
  return payload;
}

function auth(req, res, next) {
  verifyAccessToken(req.headers['authorization'])
    .then((payload) => {
      req.user = payload;
      next();
    })
    .catch((e) => res.status(401).json({ error: 'unauthorized', detail: e.message }));
}

function subjectFromPayload(p) {
  return p?.preferred_username || p?.email || p?.sub || 'developer';
}

async function getAdminToken() {
  const url = `${KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token`;
  const params = new URLSearchParams();
  params.append('grant_type', 'password');
  params.append('client_id', 'admin-cli');
  params.append('username', KEYCLOAK_ADMIN_USER);
  params.append('password', KEYCLOAK_ADMIN_PASSWORD);

  const attempts = Number(KC_IMMEDIATE_RETRY_ATTEMPTS) || 3;
  const backoffMs = Number(KC_IMMEDIATE_RETRY_BACKOFF_MS) || 500;

  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await axios.post(url, params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 15000,
      });
      return res.data.access_token;
    } catch (e) {
      lastErr = e;
      const transient = (typeof isTransientKcError === 'function')
        ? isTransientKcError(e)
        : (!e.response || [429, 500, 502, 503, 504].includes(e.response?.status));
      if (i < attempts - 1 && transient) {
        const wait = backoffMs * Math.pow(2, i);
        await new Promise(r => setTimeout(r, wait));
        continue;
      }
      break;
    }
  }
  throw lastErr;
}

function isTransientKcError(err) {
  if (!err) return false;
  const code = err.code || (err.cause && err.cause.code);
  if (code && ['ECONNABORTED', 'ECONNREFUSED', 'ENOTFOUND', 'ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN'].includes(String(code))) {
    return true;
  }
  if (err.response) {
    const s = err.response.status;
    if (s === 429 || (s >= 500 && s <= 504)) return true;
  }
  if (err.request && !err.response) return true; // network/no response
  return false;
}

function methodIsMutating(m) {
  const mm = String(m || '').toLowerCase();
  return ['post', 'put', 'patch', 'delete'].includes(mm);
}

function delay(ms) {
  return new Promise((res) => setTimeout(res, ms));
}

function computeIdempotencyKey(method, path, body) {
  try {
    const h = crypto.createHash('sha256');
    h.update(String(method).toLowerCase());
    h.update('\n');
    h.update(String(path));
    h.update('\n');
    h.update(JSON.stringify(body == null ? null : body));
    return h.digest('hex');
  } catch (_) {
    return null;
  }
}

async function enqueueKcJob({ method, path, body, idempotencyKey, maxAttempts }) {
  const id = crypto.randomUUID();
  const idem = idempotencyKey || computeIdempotencyKey(method, path, body);
  const maxA = Number(KC_QUEUE_MAX_ATTEMPTS) || 12;
  const mA = Number.isFinite(maxAttempts) ? maxAttempts : maxA;

  await dbPool.query(
    `INSERT INTO kc_retry_jobs (id, method, path, body, attempt_count, max_attempts, next_attempt_at, idempotency_key, created_at, updated_at)
     VALUES ($1,$2,$3,$4,0,$5,NOW(),$6,NOW(),NOW())
     ON CONFLICT (idempotency_key) DO NOTHING`,
    [id, String(method).toUpperCase(), path, body != null ? JSON.stringify(body) : null, mA, idem || null]
  );
  return id;
}

async function processKcRetryQueue(limit = 20) {
  const sel = await dbPool.query(
    `SELECT id, method, path, body, attempt_count, max_attempts
     FROM kc_retry_jobs
     WHERE next_attempt_at <= NOW() AND attempt_count < max_attempts
     ORDER BY next_attempt_at ASC
     LIMIT $1`,
    [limit]
  );
  if (!sel.rowCount) return;

  // Acquire fresh admin token per batch
  const token = await getAdminToken();

  for (const job of sel.rows) {
    const id = job.id;
    const method = (job.method || 'GET').toLowerCase();
    const pathPart = job.path;
    const body = job.body ? (typeof job.body === 'string' ? JSON.parse(job.body) : job.body) : null;

    try {
      const url = `${KEYCLOAK_BASE_URL}${pathPart}`;
      const resp = await axios({
        method,
        url,
        data: body,
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        timeout: 15000,
      });

      // Success
      await dbPool.query(`DELETE FROM kc_retry_jobs WHERE id=$1`, [id]);
    } catch (e) {
      const status = e.response?.status;
      const methodUpper = String(method).toUpperCase();
      const acceptable = status === 409 || (methodUpper === 'DELETE' && status === 404);
      if (acceptable) {
        await dbPool.query(`DELETE FROM kc_retry_jobs WHERE id=$1`, [id]);
        continue;
      }

      const attempt = Number(job.attempt_count) + 1;
      const base = Number(KC_QUEUE_BACKOFF_BASE_MS) || 5000;
      const max = Number(KC_QUEUE_BACKOFF_MAX_MS) || 600000;
      const backoff = Math.min(max, base * Math.pow(2, attempt - 1));
      const jitter = Math.floor(backoff * (Math.random() * 0.25)); // up to +25%
      const nextAt = new Date(Date.now() + backoff + jitter);
      const lastErr = e.response?.data ? JSON.stringify(e.response.data).slice(0, 2000) : e.message;

      await dbPool.query(
        `UPDATE kc_retry_jobs
           SET attempt_count=$2, last_error=$3, next_attempt_at=$4, updated_at=NOW()
         WHERE id=$1`,
        [id, attempt, lastErr, nextAt]
      );
    }
  }
}

function startKcRetryWorker() {
  const interval = Number(KC_QUEUE_WORKER_INTERVAL_MS) || 30000;
  setInterval(() => {
    processKcRetryQueue().catch((e) => {
      console.error('KC retry worker tick failed:', e);
    });
  }, interval);

  // Kick once shortly after boot
  setTimeout(() => {
    processKcRetryQueue().catch((e) => {
      console.error('KC retry worker initial run failed:', e);
    });
  }, 2000);
}

async function kcRequest(method, path, data, token, opts = {}) {
  const url = `${KEYCLOAK_BASE_URL}${path}`;
  const attempts = Number(KC_IMMEDIATE_RETRY_ATTEMPTS) || 3;
  const backoffMs = Number(KC_IMMEDIATE_RETRY_BACKOFF_MS) || 500;

  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await axios({
        method,
        url,
        data,
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        timeout: 15000,
        ...opts,
      });
    } catch (e) {
      lastErr = e;
      const transient = isTransientKcError(e);
      if (i < attempts - 1 && transient) {
        const wait = backoffMs * Math.pow(2, i);
        await delay(wait);
        continue;
      }
      break;
    }
  }

  // Enqueue for later if this is a mutating request and queueing is enabled
  if (methodIsMutating(method) && opts.queue !== false) {
    try {
      const idem = opts.idempotencyKey || computeIdempotencyKey(method, path, data);
      await enqueueKcJob({
        method: String(method).toUpperCase(),
        path,
        body: data,
        idempotencyKey: idem,
        maxAttempts: Number(KC_QUEUE_MAX_ATTEMPTS) || 12,
      });
      console.warn('KC request failed; enqueued for retry', { method, path });
    } catch (qErr) {
      console.error('Failed to enqueue KC request for retry:', qErr);
    }
  }

  throw lastErr;
}

const dbPool = new Pool({
  host: ADMIN_DB_HOST,
  port: Number(ADMIN_DB_PORT),
  user: ADMIN_DB_USER,
  password: ADMIN_DB_PASSWORD,
  database: ADMIN_DB_DATABASE,
  max: 10,
});

function deriveKey() {
  if (!NETAWARE_ENC_KEY) return null;
  return crypto.createHash('sha256').update(NETAWARE_ENC_KEY).digest();
}

function encryptSecret(plain) {
  if (!plain) return null;
  const key = deriveKey();
  if (!key) return plain;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${enc.toString('base64')}`;
}

function decryptSecret(encStr) {
  if (!encStr) return null;
  const key = deriveKey();
  if (!key) return encStr;
  const parts = String(encStr).split(':');
  if (parts.length !== 4 || parts[0] !== 'v1') return null;
  const iv = Buffer.from(parts[1], 'base64');
  const tag = Buffer.from(parts[2], 'base64');
  const data = Buffer.from(parts[3], 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString('utf8');
}

async function ensureDb() {
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS netaware_instances (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      base_url TEXT NOT NULL,
      api_key_enc TEXT,
      timeout_ms INTEGER,
      retries INTEGER,
      enabled BOOLEAN DEFAULT TRUE,
      tags JSON,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_netaware_instances_name ON netaware_instances(name);
    ALTER TABLE netaware_instances ADD COLUMN IF NOT EXISTS prefix TEXT;
    ALTER TABLE netaware_instances ADD COLUMN IF NOT EXISTS insecure_tls BOOLEAN DEFAULT FALSE;

    -- Retry queue for Keycloak admin requests
    CREATE TABLE IF NOT EXISTS kc_retry_jobs (
      id UUID PRIMARY KEY,
      method TEXT NOT NULL,
      path TEXT NOT NULL,
      body JSON,
      attempt_count INTEGER DEFAULT 0,
      max_attempts INTEGER DEFAULT 10,
      next_attempt_at TIMESTAMP DEFAULT NOW(),
      last_error TEXT,
      idempotency_key TEXT UNIQUE,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_kc_retry_due ON kc_retry_jobs(next_attempt_at);
    CREATE INDEX IF NOT EXISTS idx_kc_retry_attempts ON kc_retry_jobs(attempt_count);
  `);
}

ensureDb()
  .then(() => {
    console.log('DB ready');
    startKcRetryWorker();
  })
  .catch(e => console.error('DB init failed:', e, ADMIN_DB_HOST));

async function kongRequest(method, path, data, opts = {}) {
  const url = `${KONG_ADMIN_URL}${path}`;
  return axios({
    method,
    url,
    data,
    headers: { 'Content-Type': 'application/json' },
    timeout: 15000,
    ...opts,
  });
}

async function ensureRealm(realm, token) {
  try {
    await kcRequest('get', `/admin/realms/${encodeURIComponent(realm)}`, null, token);
  } catch (err) {
    if (err.response && err.response.status === 404) {
      await kcRequest('post', `/admin/realms`, { realm, enabled: true }, token);
    } else {
      throw err;
    }
  }
}

async function createUserInRealm(realm, token, user) {
  const { username, email, firstName, lastName, password } = user;
  if (!username) throw new Error('username is required');

  const payload = {
    username,
    email,
    firstName,
    lastName,
    enabled: true,
  };

  const res = await kcRequest(
    'post',
    `/admin/realms/${encodeURIComponent(realm)}/users`,
    payload,
    token,
    { validateStatus: null }
  );

  let userId = null;
  let created = res.status === 201;
  if (res.status !== 201) {
    if (res.status === 409) {
      // User already exists (duplicate username/email) - try to find existing user id
      try {
        if (email) {
          const q2 = await kcRequest(
            'get',
            `/admin/realms/${encodeURIComponent(realm)}/users?email=${encodeURIComponent(email)}&exact=true`,
            null,
            token
          );
          if (Array.isArray(q2.data) && q2.data.length) {
            const nonSvc = q2.data.find(u => !(u.username || '').startsWith('service-account-'));
            if (nonSvc) userId = nonSvc.id;
          }
        }
        if (!userId) {
          const q1 = await kcRequest(
            'get',
            `/admin/realms/${encodeURIComponent(realm)}/users?username=${encodeURIComponent(username)}&exact=true`,
            null,
            token
          );
          if (Array.isArray(q1.data) && q1.data.length) {
            const exact = q1.data.find(u => u && u.username === username && !(u.username || '').startsWith('service-account-'));
            if (exact) userId = exact.id;
          }
        }
      } catch (_) {
        // ignore; will error below if userId is still not found
      }
      if (!userId) {
        throw new Error(
          `Failed to create user (409) and could not find existing user by username/email`
        );
      }
    } else {
      throw new Error(
        `Failed to create user: status=${res.status} body=${JSON.stringify(res.data)}`
      );
    }
  }

  // Extract userId from Location header or fallback to lookup by username
  const location = res.headers['location'] || res.headers['Location'];
  if (!userId && location) {
    const m = location.match(/\/users\/([^/]+)$/);
    if (m) userId = m[1];
  }
  if (!userId && email) {
    const qe = await kcRequest(
      'get',
      `/admin/realms/${encodeURIComponent(realm)}/users?email=${encodeURIComponent(email)}&exact=true`,
      null,
      token
    );
    if (Array.isArray(qe.data) && qe.data.length) {
      const nonSvc = qe.data.find(u => !(u.username || '').startsWith('service-account-'));
      if (nonSvc) userId = nonSvc.id;
    }
  }
  if (!userId) {
    const q = await kcRequest(
      'get',
      `/admin/realms/${encodeURIComponent(realm)}/users?username=${encodeURIComponent(username)}&exact=true`,
      null,
      token
    );
    if (Array.isArray(q.data) && q.data.length) {
      const exact = q.data.find(u => u && u.username === username && !(u.username || '').startsWith('service-account-'));
      if (exact) userId = exact.id;
    }
  }
  if (!userId) throw new Error('Created user but could not determine ID');

  if (password && created) {
    await kcRequest(
      'put',
      `/admin/realms/${encodeURIComponent(realm)}/users/${encodeURIComponent(userId)}/reset-password`,
      { type: 'password', value: password, temporary: false },
      token
    );
  }

  return { userId, created };
}

async function ensureClient(realm, token, clientId, name) {
  const list = await kcRequest(
    'get',
    `/admin/realms/${encodeURIComponent(realm)}/clients?clientId=${encodeURIComponent(clientId)}`,
    null,
    token
  );

  if (Array.isArray(list.data) && list.data.length) {
    return list.data[0]; // has id, clientId
  }

  await kcRequest(
    'post',
    `/admin/realms/${encodeURIComponent(realm)}/clients`,
    {
      clientId,
      name: name || clientId,
      publicClient: true,
      directAccessGrantsEnabled: true,
      standardFlowEnabled: true,
      serviceAccountsEnabled: false,
      redirectUris: ['*'],
      webOrigins: ['*'],
      protocol: 'openid-connect',
      enabled: true,
    },
    token
  );

  const list2 = await kcRequest(
    'get',
    `/admin/realms/${encodeURIComponent(realm)}/clients?clientId=${encodeURIComponent(clientId)}`,
    null,
    token
  );
  if (!Array.isArray(list2.data) || !list2.data.length) {
    throw new Error('Client creation failed');
  }
  return list2.data[0];
}

async function ensureConfidentialClientAndSecret(realm, token, clientId, name) {
  // Find or create the client
  const list = await kcRequest(
    'get',
    `/admin/realms/${encodeURIComponent(realm)}/clients?clientId=${encodeURIComponent(clientId)}`,
    null,
    token
  );

  let client;
  if (Array.isArray(list.data) && list.data.length) {
    client = list.data[0];
  } else {
    await kcRequest(
      'post',
      `/admin/realms/${encodeURIComponent(realm)}/clients`,
      {
        clientId,
        name: name || clientId,
        publicClient: false,
        directAccessGrantsEnabled: false,
        standardFlowEnabled: false,
        serviceAccountsEnabled: true,
        redirectUris: ['*'],
        webOrigins: ['*'],
        protocol: 'openid-connect',
        enabled: true,
      },
      token
    );
    const list2 = await kcRequest(
      'get',
      `/admin/realms/${encodeURIComponent(realm)}/clients?clientId=${encodeURIComponent(clientId)}`,
      null,
      token
    );
    if (!Array.isArray(list2.data) || !list2.data.length) {
      throw new Error('Client creation failed');
    }
    client = list2.data[0];
  }

  // Ensure it's confidential with service accounts enabled
  if (client.publicClient || !client.serviceAccountsEnabled) {
    await kcRequest(
      'put',
      `/admin/realms/${encodeURIComponent(realm)}/clients/${encodeURIComponent(client.id)}`,
      {
        ...client,
        publicClient: false,
        directAccessGrantsEnabled: false,
        standardFlowEnabled: false,
        serviceAccountsEnabled: true,
      },
      token
    );
  }

  // Helper to fetch secret
  async function fetchSecret() {
    try {
      const sec = await kcRequest(
        'get',
        `/admin/realms/${encodeURIComponent(realm)}/clients/${encodeURIComponent(client.id)}/client-secret`,
        null,
        token
      );
      return sec.data?.value;
    } catch (err) {
      if (err.response && err.response.status === 404) return null;
      throw err;
    }
  }

  // Get or regenerate secret if needed
  let secret = await fetchSecret();
  if (!secret) {
    await kcRequest(
      'post',
      `/admin/realms/${encodeURIComponent(realm)}/clients/${encodeURIComponent(client.id)}/client-secret`,
      null,
      token,
      { validateStatus: null }
    );
    secret = await fetchSecret();
  }
  if (!secret) throw new Error('Failed to retrieve client secret');

  return { client, secret };
}

async function ensureClientRole(realm, token, clientUuid, roleName) {
  const rolePath = (name) =>
    `/admin/realms/${encodeURIComponent(realm)}/clients/${encodeURIComponent(clientUuid)}/roles/${encodeURIComponent(name)}`;

  const getRole = async () => {
    const res = await kcRequest('get', rolePath(roleName), null, token);
    return res.data;
  };

  try {
    // Try to get role
    return await getRole();
  } catch (err) {
    if (err.response && err.response.status === 404) {
      // Create role, then fetch it to obtain id
      await kcRequest(
        'post',
        `/admin/realms/${encodeURIComponent(realm)}/clients/${encodeURIComponent(clientUuid)}/roles`,
        { name: roleName },
        token
      );
      const created = await getRole();
      return created;
    }
    throw err;
  }
}

async function assignClientRoleToUser(realm, token, userId, clientUuid, role) {
  await kcRequest(
    'post',
    `/admin/realms/${encodeURIComponent(realm)}/users/${encodeURIComponent(userId)}/role-mappings/clients/${encodeURIComponent(clientUuid)}`,
    [{ id: role.id, name: role.name }],
    token
  );
}

async function backgroundClientSetup(username, userId) {
  try {
    const token = await getAdminToken();
    await ensureRealm(KEYCLOAK_REALM, token);
    const clientId = `client-${username || userId}`;
    const client = await ensureClient(
      KEYCLOAK_REALM,
      token,
      clientId,
      `Client for ${username || userId}`
    );
    const role = await ensureClientRole(KEYCLOAK_REALM, token, client.id, 'owner');
    await assignClientRoleToUser(KEYCLOAK_REALM, token, userId, client.id, role);
    console.log(
      `Background: client ${client.clientId} created and role '${role.name}' assigned to user ${userId}`
    );
  } catch (e) {
    console.error('Background task failed:', e.response ? e.response.data : e);
  }
}

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/api/users', async (req, res) => {
  if (typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch (e) { /* ignore */ }
  }
  const { username, email, firstName, lastName, password } = req.body || {};
  console.log('POST /api/users headers:', req.headers);
  console.log('POST /api/users body:', req.body);
  if (!username) {
    return res.status(400).json({ error: 'username is required' });
  }

  try {
    const token = await getAdminToken();
    await ensureRealm(KEYCLOAK_REALM, token);
    const { userId, created } = await createUserInRealm(KEYCLOAK_REALM, token, {
      username,
      email,
      firstName,
      lastName,
      password,
    });

    // Fetch the persisted user to determine resolved username (handles 409 reuse by email)
    let userInfo = { id: userId, username, email, firstName, lastName };
    try {
      const ures = await kcRequest(
        'get',
        `/admin/realms/${encodeURIComponent(KEYCLOAK_REALM)}/users/${encodeURIComponent(userId)}`,
        null,
        token
      );
      if (ures && ures.data) {
        userInfo = {
          id: ures.data.id,
          username: ures.data.username,
          email: ures.data.email,
          firstName: ures.data.firstName,
          lastName: ures.data.lastName,
        };
      }
    } catch (_e) {
      // ignore and fallback to request data
    }

    // Prefer human user if service-account was selected due to fuzzy search
    let userIdVar = userId;
    if ((userInfo.username || '').startsWith('service-account-')) {
      try {
        if (email) {
          const qe = await kcRequest(
            'get',
            `/admin/realms/${encodeURIComponent(KEYCLOAK_REALM)}/users?email=${encodeURIComponent(email)}&exact=true`,
            null,
            token
          );
          const human = Array.isArray(qe.data) ? qe.data.find(u => !(u.username || '').startsWith('service-account-')) : null;
          if (human) {
            userIdVar = human.id;
            userInfo = {
              id: human.id,
              username: human.username,
              email: human.email,
              firstName: human.firstName,
              lastName: human.lastName,
            };
          }
        }
        if ((userInfo.username || '').startsWith('service-account-') && username) {
          const qx = await kcRequest(
            'get',
            `/admin/realms/${encodeURIComponent(KEYCLOAK_REALM)}/users?username=${encodeURIComponent(username)}&exact=true`,
            null,
            token
          );
          const exact = Array.isArray(qx.data) ? qx.data.find(u => u && u.username === username && !(u.username || '').startsWith('service-account-')) : null;
          if (exact) {
            userIdVar = exact.id;
            userInfo = {
              id: exact.id,
              username: exact.username,
              email: exact.email,
              firstName: exact.firstName,
              lastName: exact.lastName,
            };
          }
        }
      } catch (_) { /* ignore */ }
    }

    // Ensure confidential client (clientId derived from resolved username)
    const clientIdVal = `client-${userInfo.username || username || userId}`;
    const { client, secret } = await ensureConfidentialClientAndSecret(
      KEYCLOAK_REALM,
      token,
      clientIdVal,
      `Client for ${userInfo.username || username || userId}`
    );

    // Ensure client role and link to user synchronously
    const role = await ensureClientRole(KEYCLOAK_REALM, token, client.id, 'owner');
    await assignClientRoleToUser(KEYCLOAK_REALM, token, userIdVar, client.id, role);


    return res.status(201).json({
      message: 'User created and confidential client created + linked via client role',
      realm: KEYCLOAK_REALM,
      created: created,
      user: userInfo,
      clientId: client.clientId,
      clientSecret: secret,
      link: { role: role.name }
    });
  } catch (err) {
    const status = err.response?.status || 500;
    const data = err.response?.data || { error: err.message };
    return res.status(status).json(data);
  }
});

/**
 * Netaware Instances - CRUD
 */
app.post('/api/netaware/instances', async (req, res) => {
  if (typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch (_) {}
  }
  const { name, baseUrl, prefix, apiKey, timeoutMs, retries, enabled = true, tags, insecureTLS } = req.body || {};
  if (!name || !baseUrl) {
    return res.status(400).json({ error: 'name and baseUrl are required' });
  }
  try {
    const id = crypto.randomUUID();
    const apiKeyEnc = apiKey ? encryptSecret(apiKey) : null;
    const result = await dbPool.query(
      `INSERT INTO netaware_instances (id, name, base_url, prefix, api_key_enc, timeout_ms, retries, enabled, insecure_tls, tags)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (name) DO UPDATE SET
         base_url=EXCLUDED.base_url,
         prefix=COALESCE(EXCLUDED.prefix, netaware_instances.prefix),
         api_key_enc=COALESCE(EXCLUDED.api_key_enc, netaware_instances.api_key_enc),
         timeout_ms=EXCLUDED.timeout_ms,
         retries=EXCLUDED.retries,
         enabled=EXCLUDED.enabled,
         insecure_tls=COALESCE(EXCLUDED.insecure_tls, netaware_instances.insecure_tls),
         tags=EXCLUDED.tags,
         updated_at=NOW()
       RETURNING id,name,base_url,prefix,timeout_ms,retries,enabled,insecure_tls,tags,created_at,updated_at,(api_key_enc IS NOT NULL) AS has_api_key`,
      [
        id,
        name,
        baseUrl,
        prefix || null,
        apiKeyEnc,
        Number.isFinite(timeoutMs) ? timeoutMs : null,
        Number.isFinite(retries) ? retries : null,
        !!enabled,
        typeof insecureTLS === 'boolean' ? insecureTLS : null,
        tags ? JSON.stringify(tags) : null,
      ]
    );
    return res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error('POST /api/netaware/instances failed:', e.response ? e.response.data : e);
    return res.status(500).json({ error: 'failed to upsert instance' });
  }
});

app.get('/api/netaware/instances', async (_req, res) => {
  try {
    const r = await dbPool.query(
      `SELECT id,name,base_url,prefix,timeout_ms,retries,enabled,insecure_tls,tags,created_at,updated_at,(api_key_enc IS NOT NULL) AS has_api_key
       FROM netaware_instances ORDER BY name`
    );
    return res.json(r.rows);
  } catch (e) {
    console.error('GET /api/netaware/instances failed:', e);
    return res.status(500).json({ error: 'failed to list instances' });
  }
});

app.get('/api/netaware/instances/:name', async (req, res) => {
  try {
    const r = await dbPool.query(
      `SELECT id,name,base_url,prefix,timeout_ms,retries,enabled,insecure_tls,tags,created_at,updated_at,(api_key_enc IS NOT NULL) AS has_api_key
       FROM netaware_instances WHERE name=$1`,
      [req.params.name]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'not found' });
    return res.json(r.rows[0]);
  } catch (e) {
    console.error('GET /api/netaware/instances/:name failed:', e);
    return res.status(500).json({ error: 'failed to get instance' });
  }
});

app.put('/api/netaware/instances/:name', async (req, res) => {
  if (typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch (_) {}
  }
  const { baseUrl, prefix, apiKey, timeoutMs, retries, enabled, tags, insecureTLS } = req.body || {};
  try {
    const apiKeyEnc = apiKey ? encryptSecret(apiKey) : null;
    const r = await dbPool.query(
      `UPDATE netaware_instances SET
         base_url=COALESCE($2, base_url),
         prefix=COALESCE($3, prefix),
         api_key_enc=COALESCE($4, api_key_enc),
         timeout_ms=COALESCE($5, timeout_ms),
         retries=COALESCE($6, retries),
         enabled=COALESCE($7, enabled),
         insecure_tls=COALESCE($8, insecure_tls),
         tags=COALESCE($9, tags),
         updated_at=NOW()
       WHERE name=$1
       RETURNING id,name,base_url,prefix,timeout_ms,retries,enabled,insecure_tls,tags,created_at,updated_at,(api_key_enc IS NOT NULL) AS has_api_key`,
      [
        req.params.name,
        baseUrl || null,
        prefix || null,
        apiKeyEnc,
        Number.isFinite(timeoutMs) ? timeoutMs : null,
        Number.isFinite(retries) ? retries : null,
        typeof enabled === 'boolean' ? enabled : null,
        typeof insecureTLS === 'boolean' ? insecureTLS : null,
        tags ? JSON.stringify(tags) : null,
      ]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'not found' });
    return res.json(r.rows[0]);
  } catch (e) {
    console.error('PUT /api/netaware/instances/:name failed:', e);
    return res.status(500).json({ error: 'failed to update instance' });
  }
});

app.delete('/api/netaware/instances/:name', async (req, res) => {
  try {
    const r = await dbPool.query(`DELETE FROM netaware_instances WHERE name=$1`, [req.params.name]);
    if (!r.rowCount) return res.status(404).json({ error: 'not found' });
    return res.status(204).send();
  } catch (e) {
    console.error('DELETE /api/netaware/instances/:name failed:', e);
    return res.status(500).json({ error: 'failed to delete instance' });
  }
});

/**
 * Kong plugin management for netaware
 */
app.post('/api/netaware/kong/plugins', async (req, res) => {
  if (typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch (_) {}
  }
  const { scope = 'global', targetId, instanceName, configOverrides = {} } = req.body || {};
  if (!instanceName) return res.status(400).json({ error: 'instanceName is required' });
  if ((scope === 'service' || scope === 'route') && !targetId) {
    return res.status(400).json({ error: 'targetId is required for service/route scope' });
  }
  try {
    const r = await dbPool.query(
      `SELECT * FROM netaware_instances WHERE name=$1`,
      [instanceName]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'instance not found' });
    const inst = r.rows[0];
    const apiKey = inst.api_key_enc ? decryptSecret(inst.api_key_enc) : null;

    const config = {
      instance_name: inst.name,
      base_url: inst.base_url,
      api_key: apiKey,
      timeout_ms: inst.timeout_ms ?? undefined,
      retries: inst.retries ?? undefined,
      enabled: inst.enabled,
      ...(configOverrides || {}),
    };

    let path = '/plugins';
    if (scope === 'service') path = `/services/${encodeURIComponent(targetId)}/plugins`;
    if (scope === 'route') path = `/routes/${encodeURIComponent(targetId)}/plugins`;

    const resp = await kongRequest('post', path, { name: 'netaware', config });
    return res.status(201).json(resp.data);
  } catch (e) {
    console.error('POST /api/netaware/kong/plugins failed:', e.response ? e.response.data : e);
    const status = e.response?.status || 500;
    return res.status(status).json(e.response?.data || { error: 'failed to create plugin' });
  }
});

app.delete('/api/netaware/kong/plugins/:id', async (req, res) => {
  try {
    await kongRequest('delete', `/plugins/${encodeURIComponent(req.params.id)}`);
    return res.status(204).send();
  } catch (e) {
    const status = e.response?.status || 500;
    return res.status(status).json(e.response?.data || { error: 'failed to delete plugin' });
  }
});

/**
 * Provisioning by phoneNumber -> resolve netaware instance by prefix and optionally forward
 */
function normalizeNumber(s) {
  return String(s || '').replace(/[^\d]/g, '');
}

async function resolveNetawareInstanceForPhone(phoneNumber) {
  const norm = normalizeNumber(phoneNumber);
  const q = await dbPool.query(
    `SELECT id,name,base_url,prefix,api_key_enc,timeout_ms,retries,enabled,tags
     FROM netaware_instances
     WHERE enabled = TRUE AND prefix IS NOT NULL
     ORDER BY LENGTH(prefix) DESC, name ASC`
  );
  for (const row of q.rows || []) {
    const pfx = row.prefix || '';
    const pfxNorm = normalizeNumber(pfx);
    if (
      (String(phoneNumber).startsWith(pfx)) ||
      (pfxNorm && norm.startsWith(pfxNorm))
    ) {
      return row; // matched
    }
  }
  return null;
}

app.post('/api/netaware/provision', async (req, res) => {
  if (typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch (_) {}
  }
  const { phoneNumber, targetPath = '/provision', payload = null, forward = false, headers = {} } = req.body || {};
  if (!phoneNumber) return res.status(400).json({ error: 'phoneNumber is required' });

  try {
    const inst = await resolveNetawareInstanceForPhone(phoneNumber);
    if (!inst) return res.status(404).json({ error: 'no matching instance for phoneNumber prefix' });

    // Resolution response
    const resolved = {
      matched: { name: inst.name, baseUrl: inst.base_url, prefix: inst.prefix },
      route: { phoneNumber, normalized: normalizeNumber(phoneNumber), matchedBy: 'prefix' }
    };

    // Forward optionally
    if (forward === true || forward === 'true') {
      const url = `${inst.base_url}${String(targetPath).startsWith('/') ? '' : '/'}${targetPath}`;
      // Prepare headers; include apiKey if present as x-api-key
      const apiKey = inst.api_key_enc ? decryptSecret(inst.api_key_enc) : null;
      const fwdHeaders = {
        'Content-Type': 'application/json',
        ...(apiKey ? { 'x-api-key': apiKey } : {}),
        ...(headers || {}),
      };
      // const agent = /^https:/i.test(url) && inst.insecure_tls === true ? new https.Agent({ rejectUnauthorized: false }) : undefined;
      try {
        console.log(`Forwarding provisioning request to ${url} for phoneNumber ${phoneNumber}`);
        const resp = await axios.post(url, payload || {}, {
          headers: fwdHeaders,
          timeout: Number.isFinite(inst.timeout_ms) && inst.timeout_ms > 0 ? inst.timeout_ms : 15000,
          // ...(agent ? { httpsAgent: agent } : {}),
        });
        return res.status(200).json({
          ...resolved,
          forward: { targetUrl: url, status: resp.status, ok: true },
          data: resp.data
        });
      } catch (e) {
        const status = e.response?.status || 502;
        return res.status(status).json({
          ...resolved,
          forward: { targetUrl: url, status, ok: false },
          error: e.response?.data || { message: e.message }
        });
      }
    }

    return res.json(resolved);
  } catch (e) {
    console.error('POST /api/netaware/provision failed:', e);
    return res.status(500).json({ error: 'provisioning failed' });
  }
});

/**
 * Aggregator-compatible endpoint: transparently route by phoneNumber and forward
 * Accepts body shapes:
 *  - { phoneNumber: "..." , ... }
 *  - { device: { phoneNumber: "..." }, ... }
 * Always forwards to the matched instance at the same path (/location-retrieval/v0.4/retrieve)
 * Preserves Authorization header to upstream and also adds x-api-key if the instance has an apiKey.
 */
function extractPhoneNumber(body) {
  if (!body) return null;
  if (body.phoneNumber) return body.phoneNumber;
  if (body.device && body.device.phoneNumber) return body.device.phoneNumber;
  return null;
}

app.post('/location-retrieval/v0.4/retrieve', async (req, res) => {
  if (typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch (_) { /* ignore */ }
  }
  const phoneNumber = extractPhoneNumber(req.body);
  if (!phoneNumber) {
    return res.status(400).json({ error: 'phoneNumber is required (body.phoneNumber or body.device.phoneNumber)' });
  }

  try {
    const inst = await resolveNetawareInstanceForPhone(phoneNumber);
    if (!inst) return res.status(404).json({ error: 'no matching instance for phoneNumber prefix' });

    const url = `${inst.base_url}/location-retrieval/v0.4/retrieve`;
    const apiKey = inst.api_key_enc ? decryptSecret(inst.api_key_enc) : null;

    const upstreamHeaders = {
      'Content-Type': 'application/json',
      ...(req.headers && req.headers.authorization ? { Authorization: req.headers.authorization } : {}),
      ...(apiKey ? { 'x-api-key': apiKey } : {}),
    };

    const timeout = Number.isFinite(inst.timeout_ms) && inst.timeout_ms > 0 ? inst.timeout_ms : 15000;
    const agent = /^https:/i.test(url) && inst.insecure_tls === true ? new https.Agent({ rejectUnauthorized: false }) : undefined;

    try {
      console.log(`Forwarding aggregator request to ${url} for phoneNumber ${phoneNumber}`);
      const resp = await axios.post(url, req.body || {}, { headers: upstreamHeaders, timeout, ...(agent ? { httpsAgent: agent } : {}) });
      // Try to preserve upstream content-type if present
      const ct = resp.headers && (resp.headers['content-type'] || resp.headers['Content-Type']);
      if (ct) res.set('Content-Type', ct);
      res.set('X-Forwarded-Target', url).set('X-Forwarded-Phone', phoneNumber);
      return res.status(resp.status).send(resp.data);
    } catch (e) {
      const status = e.response?.status || 502;
      res.set('X-Forwarded-Target', url).set('X-Forwarded-Phone', phoneNumber);
      return res.status(status).json({
        message: `Forwarded to ${url} and upstream returned error`,
        phoneNumber,
        targetUrl: url,
        status,
        error: e.response?.data || { error: e.message }
      });
    }
  } catch (e) {
    console.error('POST /location-retrieval/v0.4/retrieve failed:', e);
    return res.status(500).json({ error: 'routing failed' });
  }
});

/**
 * Developer Portal endpoints (Keycloak-authenticated)
 */

// Who am I (from access token)
app.get('/api/portal/me', auth, (req, res) => {
  const p = req.user || {};
  res.json({
    sub: p.sub,
    username: p.preferred_username || null,
    email: p.email || null,
    name: p.name || null,
    realm: KEYCLOAK_REALM,
    issuer: ISSUER
  });
});

// Helper: get existing consumer by username
async function getConsumer(username) {
  try {
    const resp = await kongRequest('get', `/consumers/${encodeURIComponent(username)}`);
    return resp.data;
  } catch (e) {
    if (e.response && e.response.status === 404) return null;
    throw e;
  }
}

// Helper: create consumer
async function createConsumer(username, custom_id, tags = []) {
  const resp = await kongRequest('post', `/consumers`, { username, custom_id, tags });
  return resp.data;
}

// Ensure or return Consumer associated to Keycloak user
app.post('/api/portal/consumers', auth, async (req, res) => {
  try {
    const payload = req.user || {};
    const username = subjectFromPayload(payload);
    const existing = await getConsumer(username);
    if (existing) return res.json(existing);
    const consumer = await createConsumer(username, payload.sub, [
      'portal',
      `kc-realm:${KEYCLOAK_REALM}`
    ]);
    return res.status(201).json(consumer);
  } catch (e) {
    const status = e.response?.status || 500;
    return res.status(status).json(e.response?.data || { error: e.message });
  }
});

// Get current consumer (by token subject/username)
app.get('/api/portal/consumers/me', auth, async (req, res) => {
  try {
    const username = subjectFromPayload(req.user || {});
    const consumer = await getConsumer(username);
    if (!consumer) return res.status(404).json({ error: 'consumer not found' });
    return res.json(consumer);
  } catch (e) {
    const status = e.response?.status || 500;
    return res.status(status).json(e.response?.data || { error: e.message });
  }
});

// Issue a key-auth credential for current consumer
app.post('/api/portal/keys', auth, async (req, res) => {
  try {
    const username = subjectFromPayload(req.user || {});
    let consumer = await getConsumer(username);
    if (!consumer) {
      consumer = await createConsumer(username, (req.user || {}).sub, [
        'portal',
        `kc-realm:${KEYCLOAK_REALM}`
      ]);
    }
    const resp = await kongRequest('post', `/consumers/${encodeURIComponent(username)}/key-auth`, {});
    return res.status(201).json(resp.data);
  } catch (e) {
    const status = e.response?.status || 500;
    return res.status(status).json(e.response?.data || { error: e.message });
  }
});

// List key-auth credentials for current consumer
app.get('/api/portal/keys', auth, async (req, res) => {
  try {
    const username = subjectFromPayload(req.user || {});
    const existing = await getConsumer(username);
    if (!existing) return res.json([]);
    const resp = await kongRequest('get', `/consumers/${encodeURIComponent(username)}/key-auth`);
    // Kong may return { data: [...], next: null }
    const data = Array.isArray(resp.data) ? resp.data : (resp.data?.data || []);
    return res.json(data);
  } catch (e) {
    const status = e.response?.status || 500;
    return res.status(status).json(e.response?.data || { error: e.message });
  }
});

// Revoke a key-auth credential by ID
app.delete('/api/portal/keys/:id', auth, async (req, res) => {
  try {
    await kongRequest('delete', `/key-auth/${encodeURIComponent(req.params.id)}`);
    return res.status(204).send();
  } catch (e) {
    const status = e.response?.status || 500;
    return res.status(status).json(e.response?.data || { error: e.message });
  }
});

// API catalog for portal (linking to OpenAPI docs)
app.get('/api/portal/apis', (_req, res) => {
  const apis = [
    {
      name: 'Netaware Provision',
      method: 'POST',
      path: '/api/netaware/provision',
      security: 'key-auth',
      specUrl: '/static/openapi/provisioning.yaml'
    },
    {
      name: 'Aggregator Retrieve',
      method: 'POST',
      path: '/location-retrieval/v0.4/retrieve',
      security: 'key-auth',
      specUrl: '/static/openapi/aggregator.yaml'
    }
  ];
  res.json(apis);
});

// Serve the Portal UI
app.get('/portal', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'portal', 'index.html'));
});

/**
 * Bootstrap endpoint:
 * - Ensure Keycloak realm exists
 * - Ensure confidential client 'kong-portal' and retrieve its secret
 * - If Kong Enterprise license available, create workspace 'dev-portal' and enable portal
 * - If license is missing (403), skip workspace/portal steps but still return 200
 */
app.post('/api/bootstrap', async (_req, res) => {
  const result = {
    ok: true,
    realm: KEYCLOAK_REALM,
    workspace: null,
    portalEnabled: null,
    skippedDueToLicense: false,
  };

  try {
    // 1) Keycloak admin token and realm
    const token = await getAdminToken();
    await ensureRealm(KEYCLOAK_REALM, token);

    // 2) Ensure confidential client 'kong-portal'
    const { client, secret } = await ensureConfidentialClientAndSecret(
      KEYCLOAK_REALM,
      token,
      'kong-portal',
      'Kong Dev Portal'
    );

    // 3) Kong Enterprise-only steps (workspaces/portal)
    const workspace = 'dev-portal';

    // Ensure workspace exists if license permits
    try {
      await kongRequest('get', `/workspaces/${encodeURIComponent(workspace)}`);
    } catch (e) {
      if (e.response && e.response.status === 404) {
        try {
          await kongRequest('post', `/workspaces`, { name: workspace });
        } catch (eCreate) {
          if (eCreate.response && eCreate.response.status === 403) {
            result.skippedDueToLicense = true;
          } else {
            throw eCreate;
          }
        }
      } else if (e.response && e.response.status === 403) {
        result.skippedDueToLicense = true;
      } else {
        throw e;
      }
    }

    // Enable portal if not skipped
    if (!result.skippedDueToLicense) {
      try {
        await kongRequest('patch', `/workspaces/${encodeURIComponent(workspace)}`, {
          config: { portal: true, portal_auto_approve: true },
        });
        result.portalEnabled = true;
      } catch (e1) {
        if (e1.response && e1.response.status === 403) {
          result.skippedDueToLicense = true;
        } else {
          try {
            await kongRequest(
              'patch',
              `/workspaces/${encodeURIComponent(workspace)}/configuration`,
              { portal: true, portal_auto_approve: true }
            );
            result.portalEnabled = true;
          } catch (e2) {
            if (e2.response && e2.response.status === 403) {
              result.skippedDueToLicense = true;
            } else {
              throw e2;
            }
          }
        }
      }
      result.workspace = workspace;
    }

    return res.json({
      ...result,
      clientId: client.clientId,
      clientSecret: secret,
      kongAdmin: KONG_ADMIN_URL,
    });
  } catch (e) {
    const status = e.response?.status || 500;
    return res.status(status).json({
      error: 'bootstrap_failed',
      message: e.message,
      detail: e.response?.data || null,
    });
  }
});

app.listen(PORT, () => {
  console.log(`Admin service listening on :${PORT}`);
});
