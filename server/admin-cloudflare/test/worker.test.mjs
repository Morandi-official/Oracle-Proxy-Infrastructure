import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { generateKeyPair, exportJWK, SignJWT, createLocalJWKSet } from 'jose';
import { createApp } from '../src/worker.mjs';

const NOW = Math.floor(Date.now() / 1000);
const origin = 'https://admin.example.com';
const { privateKey, publicKey } = await generateKeyPair('RS256');
const jwk = { ...await exportJWK(publicKey), kid: 'test-key' };
const keys = createLocalJWKSet({ keys: [jwk] });
const app = createApp({ resolveKeys: keys, now: () => NOW });

// Execute real migration SQL and queries; emulate only D1's async interface.
class D1 {
  constructor() {
    this.sqlite = new DatabaseSync(':memory:');
    this.sqlite.exec(readFileSync(new URL('../migrations/0001_observability.sql', import.meta.url), 'utf8'));
  }
  prepare(sql) {
    const db = this.sqlite; let values = [];
    return {
      bind(...args) { values = args; return this; },
      async first() { return db.prepare(sql).get(...values) || null; },
      async all() { return { results: db.prepare(sql).all(...values) }; },
      async run() { return db.prepare(sql).run(...values); }
    };
  }
  async batch(statements) {
    this.sqlite.exec('BEGIN');
    try {
      const result = [];
      for (const statement of statements) result.push(await statement.run());
      this.sqlite.exec('COMMIT'); return result;
    } catch (error) { this.sqlite.exec('ROLLBACK'); throw error; }
  }
  count(table) { return this.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get().n; }
}
function env() {
  return { PUBLIC_ORIGIN: origin, ACCESS_ISSUER: 'https://example.cloudflareaccess.com',
    ACCESS_AUD: 'test-audience', ADMIN_EMAILS: 'admin@example.com', NODE_ID: 'oracle-primary',
    INGEST_HMAC_KEY: 'a'.repeat(64), DB: new D1(),
    ASSETS: { fetch: async () => new Response('<html>protected</html>') } };
}
async function token(extra = {}, options = {}) {
  return new SignJWT({ email: 'admin@example.com', type: 'app', ...extra })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setIssuer(options.issuer || 'https://example.cloudflareaccess.com')
    .setAudience(options.audience || 'test-audience').setSubject('admin-subject')
    .setIssuedAt(NOW).setExpirationTime(options.exp || NOW + 120).sign(privateKey);
}
async function adminRequest(path = '/api/status', options = {}, jwt = null) {
  return new Request(origin + path, { ...options, headers: {
    'Cf-Access-Jwt-Assertion': jwt || await token(), ...options.headers
  } });
}
function snapshot(extra = {}) {
  return { schema: 1, id: crypto.randomUUID().replaceAll('-', ''), node_id: 'oracle-primary',
    observed_at: NOW, source_revision: 'a'.repeat(40), wg_service: 'ACTIVE',
    wg_interface: 'PRESENT', udp_listener: 'LISTENING', ...extra };
}
async function signedRequest(value, e, timestamp = NOW, raw = JSON.stringify(value)) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(e.INGEST_HMAC_KEY),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}\n${raw}`));
  const hex = [...new Uint8Array(signature)].map(x => x.toString(16).padStart(2, '0')).join('');
  return new Request(origin + '/api/ingest', { method: 'POST', body: raw, headers: {
    'Content-Type': 'application/json', 'X-Oracle-Timestamp': String(timestamp), 'X-Oracle-Signature': hex
  } });
}

test('missing identity protects HTML, JavaScript, status, and audit', async () => {
  const e = env();
  for (const path of ['/', '/app.js', '/api/status', '/api/audit']) {
    const response = await app.fetch(new Request(origin + path), e);
    assert.equal(response.status, 401);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
  }
  assert.equal(e.DB.count('audit'), 0);
});
test('signed Access tokens require issuer, audience, expiration, app type and admin email', async () => {
  const e = env();
  for (const [jwt, status] of [
    [await token({}, { issuer: 'https://attacker.cloudflareaccess.com' }), 401],
    [await token({}, { audience: 'other-app' }), 401],
    [await token({}, { exp: NOW - 60 }), 401],
    [await token({ email: 'other@example.com' }), 403],
    [await token({ type: 'service' }), 403],
    ['eyJhbGciOiJub25lIn0.eyJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIn0.', 401]
  ]) assert.equal((await app.fetch(await adminRequest('/api/status', {}, jwt), e)).status, status);
});
test('signed payload tampering fails', async () => {
  const parts = (await token()).split('.');
  parts[1] = Buffer.from(JSON.stringify({ email: 'admin@example.com' })).toString('base64url');
  assert.equal((await app.fetch(await adminRequest('/', {}, parts.join('.')), env())).status, 401);
});
test('missing configuration and alternate origin fail closed', async () => {
  const e = env(); delete e.ACCESS_AUD;
  assert.equal((await app.fetch(await adminRequest(), e)).status, 503);
  assert.equal((await app.fetch(new Request('https://other.example.com/'), env())).status, 403);
});
test('empty database is unknown, never a healthy mock', async () => {
  const e = env(); const response = await app.fetch(await adminRequest(), e);
  assert.equal(response.status, 200); const data = await response.json();
  assert.equal(data.snapshot, null); assert.equal(data.freshness, 'unknown');
  assert.equal(data.capabilities.peers, false); assert.equal(data.capabilities.configuration, false);
  assert.equal(e.DB.count('audit'), 1);
});
test('assets carry CSP and reject unknown paths and mutations', async () => {
  const e = env();
  const html = await app.fetch(await adminRequest('/'), e);
  assert.equal(html.status, 200); assert.match(html.headers.get('Content-Security-Policy'), /frame-ancestors 'none'/);
  assert.equal((await app.fetch(await adminRequest('/api/peers', { method: 'POST', body: '{}' }), e)).status, 405);
  assert.equal((await app.fetch(await adminRequest('/api/configuration'), e)).status, 404);
  assert.equal((await app.fetch(await adminRequest('/secret.txt'), e)).status, 404);
  assert.equal((await app.fetch(await adminRequest('/api/ingest', { method: 'GET' }), e)).status, 404);
});
test('signed ingest persists real snapshot and audit; duplicate is atomic replay rejection', async () => {
  const e = env(); const value = snapshot();
  assert.equal((await app.fetch(await signedRequest(value, e), e)).status, 202);
  assert.equal((await app.fetch(await signedRequest(value, e), e)).status, 409);
  assert.equal(e.DB.count('snapshots'), 1); assert.equal(e.DB.count('receipts'), 1);
  assert.equal(e.DB.count('audit'), 1);
  const data = await (await app.fetch(await adminRequest(), e)).json();
  assert.deepEqual(data.snapshot, value); assert.equal(data.freshness, 'fresh');
});
test('out-of-order reports do not replace latest observation and old data becomes stale', async () => {
  const e = env(); const latest = snapshot({ observed_at: NOW - 190 });
  await app.fetch(await signedRequest(latest, e), e);
  await app.fetch(await signedRequest(snapshot({ observed_at: NOW - 210, wg_service: 'INACTIVE' }), e), e);
  const data = await (await app.fetch(await adminRequest(), e)).json();
  assert.equal(data.snapshot.id, latest.id); assert.equal(data.freshness, 'stale');
});
test('wrong HMAC, expired timestamp, future time, unknown fields and malformed snapshots cannot write', async () => {
  const e = env();
  const wrong = env(); wrong.INGEST_HMAC_KEY = 'b'.repeat(64);
  assert.equal((await app.fetch(await signedRequest(snapshot(), wrong), e)).status, 401);
  for (const timestamp of [NOW - 301, NOW + 301])
    assert.equal((await app.fetch(await signedRequest(snapshot(), e, timestamp), e)).status, 401);
  for (const value of [snapshot({ private_key: 'DO_NOT_ACCEPT' }), snapshot({ observed_at: NOW - 301 }),
    snapshot({ node_id: 'other-node' }), snapshot({ wg_service: 'MAYBE' }), snapshot({ schema: 2 }),
    snapshot({ source_revision: '../../shell' }), null])
    assert.equal((await app.fetch(await signedRequest(value, e), e)).status, 400);
  assert.equal((await app.fetch(await signedRequest({}, e, NOW, '{broken'), e)).status, 400);
  assert.equal(e.DB.count('receipts'), 0); assert.equal(e.DB.count('audit'), 0);
});
test('ingest enforces streaming size limit and content type', async () => {
  const e = env();
  assert.equal((await app.fetch(await signedRequest({}, e, NOW, ' '.repeat(4097)), e)).status, 413);
  const request = await signedRequest(snapshot(), e); request.headers.set('Content-Type', 'text/plain');
  assert.equal((await app.fetch(request, e)).status, 415);
});
test('database failure rolls back receipt and snapshot', async () => {
  const e = env(); e.DB.sqlite.exec('DROP TABLE audit');
  assert.equal((await app.fetch(await signedRequest(snapshot(), e), e)).status, 503);
  assert.equal(e.DB.count('receipts'), 0); assert.equal(e.DB.count('snapshots'), 0);
});
test('scheduled retention removes records older than thirty days only', async () => {
  const e = env(); await app.fetch(await signedRequest(snapshot(), e), e);
  const later = createApp({ now: () => NOW + 31 * 86400 });
  await later.scheduled({}, e);
  assert.equal(e.DB.count('snapshots'), 0); assert.equal(e.DB.count('receipts'), 0);
  assert.equal(e.DB.count('audit'), 0);
});
