'use strict';
/**
 * Example: Web2 backend using NullaAuthGate SDK
 *
 * Endpoints:
 *   GET  /apps           — list registered apps (public)
 *   POST /auth/nulla     — verify + consume access key → grant session
 *   GET  /dashboard      — protected page (requires valid session)
 *
 * Run:
 *   BACKEND_MNEMONIC="word1 ..." APP_ID="my-app-id" node example/server.js
 */

const http    = require('http');
const crypto  = require('crypto');
const { NullaAuthGate } = require('../index.js');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3000', 10);

// Funded AuthGate account that pays the fee for use_access_key (its address is on-chain, not the user's).
const BACKEND_MNEMONIC = process.env.BACKEND_MNEMONIC;
// The app id the Nulla team registered for you; keys for any other app are rejected.
const APP_ID = process.env.APP_ID;
if (!BACKEND_MNEMONIC || !APP_ID) throw new Error('Set BACKEND_MNEMONIC and APP_ID before starting');

// In-memory session store (replace with Redis/DB in production)
const sessions = new Map(); // token → { appId, grantedAt }

// ── SDK init (defaults to Nulla mainnet endpoints) ────────────────────────────
const ag = new NullaAuthGate({ authgateRpc: process.env.AUTHGATE_RPC || undefined });

// ── Simple HTTP server (no framework dependency) ──────────────────────────────
function json(res, code, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
  res.end(payload);
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 8192) reject(new Error('Body too large')); });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}

function getSession(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  return token ? sessions.get(token) : null;
}

async function router(req, res) {
  const url = req.url.split('?')[0];

  // ── GET /apps ──────────────────────────────────────────────────────────────
  if (req.method === 'GET' && url === '/apps') {
    try {
      const apps = await ag.admin.listApps();
      return json(res, 200, { apps });
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  }

  // ── POST /auth/nulla ───────────────────────────────────────────────────────
  // Body: { "txId": "<hex>", "blinding": "<hex>" }
  // Returns: { "token": "<session_token>", "appId": "<hex>", "expiresIn": 3600 }
  if (req.method === 'POST' && url === '/auth/nulla') {
    let body;
    try { body = await readBody(req); } catch (e) { return json(res, 400, { error: e.message }); }

    const { txId, blinding } = body;
    if (!txId || !blinding) return json(res, 400, { error: 'txId and blinding are required' });

    try {
      // Backend calls use_access_key — user identity never touches AuthGate
      const result = await ag.verifyAndConsume(txId, blinding, BACKEND_MNEMONIC, { expectedAppId: APP_ID });
      if (!result.ok) return json(res, 403, { error: result.reason });

      // Issue a session token
      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, { appId: result.appId, grantedAt: Date.now(), blockHash: result.blockHash });

      // Auto-expire after 1 hour
      setTimeout(() => sessions.delete(token), 3600 * 1000);

      console.log(`[auth] Key consumed for app ${result.appId.slice(0, 16)}... block ${result.blockHash}`);
      return json(res, 200, { token, appId: result.appId, expiresIn: 3600, blockHash: result.blockHash });
    } catch (e) {
      console.error('[auth] Error:', e.message);
      return json(res, 500, { error: e.message });
    }
  }

  // ── GET /dashboard ─────────────────────────────────────────────────────────
  // Protected: requires valid session token in Authorization header
  if (req.method === 'GET' && url === '/dashboard') {
    const session = getSession(req);
    if (!session) return json(res, 401, { error: 'Unauthorized. Post to /auth/nulla first.' });
    return json(res, 200, {
      message: 'Welcome! Access granted.',
      appId: session.appId,
      grantedAt: new Date(session.grantedAt).toISOString(),
      note: 'Your identity is unknown. Only proof of payment was verified.',
    });
  }

  return json(res, 404, { error: 'Not found' });
}

// ── Start ─────────────────────────────────────────────────────────────────────
(async () => {
  console.log('[NullaAuthGate] Connecting to chains...');
  await ag.connect();

  const server = http.createServer(async (req, res) => {
    try { await router(req, res); }
    catch (e) { json(res, 500, { error: 'Internal server error' }); }
  });

  server.listen(PORT, () => {
    console.log(`\n[NullaAuthGate] Server running on http://localhost:${PORT}`);
    console.log('\nEndpoints:');
    console.log('  GET  /apps                    — list registered apps');
    console.log('  POST /auth/nulla              — verify + consume key, get session');
    console.log('  GET  /dashboard               — protected page (needs Bearer token)');
    console.log('\nExample auth flow:');
    console.log('  1. User runs: nulla-wallet access buy --app-id <id> --note-id 0');
    console.log('  2. User POSTs txId + blinding to /auth/nulla');
    console.log('  3. Server calls use_access_key on-chain (backend address visible, not user)');
    console.log('  4. Server returns session token → user accesses /dashboard');
  });
})().catch(e => { console.error(e); process.exit(1); });
