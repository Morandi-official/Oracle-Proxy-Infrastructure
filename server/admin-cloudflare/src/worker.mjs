import { createRemoteJWKSet, jwtVerify } from 'jose';

const encoder = new TextEncoder();
const keysets = new Map();
const WINDOW = 300;
const MAX_BODY = 4096;
const headers = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
};
class HttpError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
const fail = (status, code) => { throw new HttpError(status, code); };
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8' }
});

function config(env) {
  if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(env.ACCESS_ISSUER || '') ||
      !env.ACCESS_AUD || !env.ADMIN_EMAILS || !/^[a-z0-9-]{1,64}$/.test(env.NODE_ID || ''))
    fail(503, 'IDENTITY_CONFIGURATION_REQUIRED');
  try {
    const url = new URL(env.PUBLIC_ORIGIN);
    if (url.protocol !== 'https:' || url.origin !== env.PUBLIC_ORIGIN) throw new Error();
  } catch { fail(503, 'PUBLIC_ORIGIN_REQUIRED'); }
}

export async function authenticate(request, env, resolveKeys) {
  const token = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!token || token.length > 16384) fail(401, 'ACCESS_LOGIN_REQUIRED');
  let payload;
  try {
    if (!resolveKeys) {
      if (!keysets.has(env.ACCESS_ISSUER)) keysets.set(env.ACCESS_ISSUER,
        createRemoteJWKSet(new URL(`${env.ACCESS_ISSUER}/cdn-cgi/access/certs`)));
      resolveKeys = keysets.get(env.ACCESS_ISSUER);
    }
    ({ payload } = await jwtVerify(token, resolveKeys, {
      issuer: env.ACCESS_ISSUER, audience: env.ACCESS_AUD, algorithms: ['RS256'],
      requiredClaims: ['exp', 'iat', 'sub', 'email', 'type'], clockTolerance: 5
    }));
  } catch { fail(401, 'ACCESS_TOKEN_INVALID'); }
  const email = typeof payload.email === 'string' ? payload.email.toLowerCase() : '';
  const allowed = env.ADMIN_EMAILS.split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
  if (payload.type !== 'app' || !payload.sub || !allowed.includes(email)) fail(403, 'ADMIN_REQUIRED');
  return email;
}

async function limitedBody(request) {
  if (!request.body) fail(400, 'BODY_REQUIRED');
  if (!/^application\/json(?:;.*)?$/i.test(request.headers.get('Content-Type') || ''))
    fail(415, 'JSON_REQUIRED');
  const reader = request.body.getReader();
  const chunks = []; let size = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY) { await reader.cancel(); fail(413, 'BODY_TOO_LARGE'); }
    chunks.push(value);
  }
  const body = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  try { return new TextDecoder('utf-8', { fatal: true }).decode(body); }
  catch { fail(400, 'INVALID_UTF8'); }
}

export function validateSnapshot(value, env, now) {
  const fields = ['schema', 'id', 'node_id', 'observed_at', 'source_revision', 'wg_service', 'wg_interface', 'udp_listener'];
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(k => !Object.hasOwn(value, k)) ||
      value.schema !== 1 || !/^[0-9a-f]{32}$/.test(value.id) || value.node_id !== env.NODE_ID ||
      !Number.isSafeInteger(value.observed_at) || Math.abs(now - value.observed_at) > WINDOW ||
      !/^[0-9a-f]{40}$/.test(value.source_revision) ||
      !['ACTIVE', 'INACTIVE'].includes(value.wg_service) ||
      !['PRESENT', 'ABSENT'].includes(value.wg_interface) ||
      !['LISTENING', 'NOT_LISTENING'].includes(value.udp_listener)) fail(400, 'INVALID_SNAPSHOT');
  return value;
}

async function ingest(request, env, now) {
  if (typeof env.INGEST_HMAC_KEY !== 'string' || !/^[0-9a-f]{64}$/.test(env.INGEST_HMAC_KEY))
    fail(503, 'INGEST_CONFIGURATION_REQUIRED');
  const timestamp = request.headers.get('X-Oracle-Timestamp') || '';
  const signature = request.headers.get('X-Oracle-Signature') || '';
  if (!/^\d{10}$/.test(timestamp) || Math.abs(now - Number(timestamp)) > WINDOW ||
      !/^[0-9a-f]{64}$/.test(signature)) fail(401, 'INGEST_SIGNATURE_INVALID');
  const raw = await limitedBody(request);
  const key = await crypto.subtle.importKey('raw', encoder.encode(env.INGEST_HMAC_KEY),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const bytes = Uint8Array.from(signature.match(/../g), x => parseInt(x, 16));
  if (!await crypto.subtle.verify('HMAC', key, bytes, encoder.encode(`${timestamp}\n${raw}`)))
    fail(401, 'INGEST_SIGNATURE_INVALID');
  let value;
  try { value = JSON.parse(raw); } catch { fail(400, 'INVALID_JSON'); }
  validateSnapshot(value, env, now);
  try {
    // D1 batch is atomic: duplicate receipt rolls back snapshot AND audit.
    await env.DB.batch([
      env.DB.prepare('INSERT INTO receipts VALUES (?, ?)').bind(value.id, now),
      env.DB.prepare('INSERT INTO snapshots VALUES (?, ?, ?, ?, ?, ?)').bind(
        value.id, value.node_id, value.observed_at, now, value.source_revision, JSON.stringify(value)),
      env.DB.prepare('INSERT INTO audit VALUES (?, ?, ?, ?, ?)').bind(
        crypto.randomUUID(), now, 'collector:github-actions', 'snapshot.received', env.NODE_ID)
    ]);
  } catch (error) {
    if (String(error).includes('UNIQUE constraint failed: receipts.id')) fail(409, 'REPLAY_REJECTED');
    throw error;
  }
  return json({ accepted: true }, 202);
}

export function createApp({ resolveKeys, now = () => Math.floor(Date.now() / 1000) } = {}) {
  return {
    async fetch(request, env) {
      try {
        config(env);
        const url = new URL(request.url);
        if (url.origin !== env.PUBLIC_ORIGIN) fail(403, 'ORIGIN_REJECTED');
        // Only this exact machine endpoint is excluded from browser identity.
        if (url.pathname === '/api/ingest' && request.method === 'POST')
          return await ingest(request, env, now());
        const actor = await authenticate(request, env, resolveKeys);
        if (request.method !== 'GET') fail(405, 'READ_ONLY_MANAGEMENT');
        if (url.pathname === '/api/status') {
          const row = await env.DB.prepare('SELECT payload, received_at FROM snapshots WHERE node_id = ? ORDER BY observed_at DESC, received_at DESC LIMIT 1')
            .bind(env.NODE_ID).first();
          await env.DB.prepare('INSERT INTO audit VALUES (?, ?, ?, ?, ?)').bind(
            crypto.randomUUID(), now(), actor, 'status.read', env.NODE_ID).run();
          const snapshot = row ? JSON.parse(row.payload) : null;
          const age = row ? Math.max(0, now() - snapshot.observed_at) : null;
          return json({ node_id: env.NODE_ID, actor, snapshot, age_seconds: age,
            freshness: row ? (age <= 180 ? 'fresh' : 'stale') : 'unknown',
            capabilities: { status: true, peers: false, usage: false, configuration: false },
            vpn_release: 'experimental-unverified' });
        }
        if (url.pathname === '/api/audit') {
          const result = await env.DB.prepare('SELECT occurred_at, actor, action, resource FROM audit ORDER BY occurred_at DESC, rowid DESC LIMIT 100').all();
          return json({ entries: result.results });
        }
        if (url.pathname.startsWith('/api/')) fail(404, 'NOT_IMPLEMENTED');
        // Explicit asset allowlist; all assets pass the same identity check.
        if (!['/', '/index.html', '/app.js', '/style.css'].includes(url.pathname)) fail(404, 'NOT_FOUND');
        const asset = await env.ASSETS.fetch(request);
        const response = new Response(asset.body, asset);
        for (const [key, value] of Object.entries(headers)) response.headers.set(key, value);
        return response;
      } catch (error) {
        return json({ error: error instanceof HttpError ? error.code : 'SERVICE_UNAVAILABLE' },
          error instanceof HttpError ? error.status : 503);
      }
    },
    async scheduled(_event, env) {
      const cutoff = now() - 30 * 86400;
      // Daily retention; replay receipts outlive the five-minute signature window.
      await env.DB.batch([
        env.DB.prepare('DELETE FROM snapshots WHERE received_at < ?').bind(cutoff),
        env.DB.prepare('DELETE FROM receipts WHERE received_at < ?').bind(cutoff),
        env.DB.prepare('DELETE FROM audit WHERE occurred_at < ?').bind(cutoff)
      ]);
    }
  };
}

export default createApp();
