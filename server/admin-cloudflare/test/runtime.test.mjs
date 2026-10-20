// Run after the Worker bundle is built. No Oracle/Cloudflare account access.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('bundled Worker on workerd: actual D1 migration, signed report, replay rollback and unauthenticated denial', async () => {
  const origin = 'https://admin.example.com';
  const secret = 'a'.repeat(64);
  const mf = new Miniflare(convertV4MiniflareOptions({
    modules: true, scriptPath: 'dist/worker.js', compatibilityDate: '2026-10-01',
    d1Databases: ['DB'], bindings: {
      PUBLIC_ORIGIN: origin, ACCESS_ISSUER: 'https://example.cloudflareaccess.com',
      ACCESS_AUD: 'test-audience', ADMIN_EMAILS: 'admin@example.com', NODE_ID: 'oracle-primary',
      INGEST_HMAC_KEY: secret
    }
  }));
  try {
    const db = await mf.getD1Database('DB');
    const sql = readFileSync('migrations/0001_observability.sql', 'utf8')
      .replace(/^--.*$/gm, '').split(';').map(x => x.trim()).filter(Boolean);
    for (const statement of sql) await db.prepare(statement).run();
    const now = Math.floor(Date.now() / 1000);
    const report = { schema: 1, id: crypto.randomUUID().replaceAll('-', ''),
      node_id: 'oracle-primary', observed_at: now, source_revision: 'a'.repeat(40),
      wg_service: 'ACTIVE', wg_interface: 'PRESENT', udp_listener: 'LISTENING' };
    const body = JSON.stringify(report);
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${now}\n${body}`));
    const headers = { 'Content-Type': 'application/json', 'X-Oracle-Timestamp': String(now),
      'X-Oracle-Signature': Buffer.from(signature).toString('hex') };
    const first = await mf.dispatchFetch(origin + '/api/ingest', { method: 'POST', body, headers });
    assert.equal(first.status, 202, await first.text());
    const replay = await mf.dispatchFetch(origin + '/api/ingest', { method: 'POST', body, headers });
    assert.equal(replay.status, 409, await replay.text());
    assert.equal((await db.prepare('SELECT count(*) AS n FROM snapshots').first()).n, 1);
    assert.equal((await db.prepare('SELECT count(*) AS n FROM audit').first()).n, 1);
    assert.equal((await mf.dispatchFetch(origin + '/api/status')).status, 401);
    assert.equal((await mf.dispatchFetch(origin + '/')).status, 401);
  } finally { await mf.dispose(); }
});
