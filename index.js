'use strict';
/**
 * @nulla/authgate-sdk
 *
 * Integrates Nulla Network's AuthGate parachain into any Web2 application.
 *
 *  - Backend : NullaAuthGate.verifyAndConsume() verifies and consumes a user's access key
 *  - Relay   : NullaRelay exposes POST /consume for frontend-only apps
 *  - Admin   : NullaAuthGate.admin.* (sudo; run by the Nulla team, not by providers)
 *
 * Providers MUST pin the app they serve via `expectedAppId`, otherwise a key bought
 * for a different app would be accepted.
 */

const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { decodeAddress } = require('@polkadot/util-crypto');
const { u8aToHex, hexToU8a } = require('@polkadot/util');
const { blake3 } = require('@noble/hashes/blake3');
const crypto = require('crypto');

// ── Constants ────────────────────────────────────────────────────────────────
const PLANCK_PER_NULLA = 1_000_000_000_000n;
const MAX_APP_NAME_LEN = 256; // mirrors pallet access-keys
const TX_TIMEOUT_MS = 60_000;

const DEFAULT_ENDPOINTS = Object.freeze({
  authgateRpc: 'wss://146.70.86.59.sslip.io/authgate/',
  proofhubRpc: 'wss://146.70.106.68.sslip.io/proofhub/',
});

// ── Helpers ──────────────────────────────────────────────────────────────────

const HEX64 = /^(0x)?[0-9a-fA-F]{64}$/;

/** Encode an app id (string <=32 chars, or 32-byte hex) into Array<u8> */
function encodeAppId(appIdInput) {
  if (typeof appIdInput !== 'string' || appIdInput.length === 0) {
    throw new Error('appId must be a non-empty string');
  }
  if (HEX64.test(appIdInput)) return Array.from(hexToU8a(appIdInput.startsWith('0x') ? appIdInput : `0x${appIdInput}`));
  if (appIdInput.startsWith('0x')) throw new Error('appId hex must be exactly 32 bytes');
  const bytes = Buffer.from(appIdInput, 'utf8');
  if (bytes.length > 32) throw new Error('appId string must be at most 32 bytes');
  const buf = Buffer.alloc(32, 0);
  bytes.copy(buf);
  return Array.from(buf);
}

/** Normalise appId to 64-char lowercase hex (no 0x) */
function normaliseAppId(appIdInput) {
  return Buffer.from(encodeAppId(appIdInput)).toString('hex');
}

/** Strip 0x and validate a fixed-length hex string; returns lowercase hex or null */
function cleanHex(value, bytes) {
  if (typeof value !== 'string') return null;
  const h = value.startsWith('0x') ? value.slice(2) : value;
  return new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(h) ? h.toLowerCase() : null;
}

/** BLAKE3("nulla_access_key_v1" || app_id || blinding) — mirrors the AuthGate pallet */
function accessKeyCommitment(appIdHex, blindingHex) {
  const input = Buffer.concat([
    Buffer.from('nulla_access_key_v1', 'utf8'),
    Buffer.from(appIdHex, 'hex'),
    Buffer.from(blindingHex, 'hex'),
  ]);
  return Buffer.from(blake3(input)).toString('hex');
}

/** Convert NULLA (human) to planck (bigint) */
function nullaToPlanck(nulla) {
  if (typeof nulla !== 'number' || !Number.isFinite(nulla) || nulla < 0) {
    throw new Error('priceNulla must be a non-negative finite number');
  }
  return BigInt(Math.round(nulla * 1e6)) * (PLANCK_PER_NULLA / 1_000_000n);
}

/** Wait for a tx to be in-block and check for dispatch errors */
function sendAndWait(api, signer, tx, nonce) {
  const metaError = (prefix, err) => {
    if (!err.isModule) return `${prefix}${err.toString()}`;
    const m = api.registry.findMetaError(err.asModule);
    return `${prefix}${m.section}.${m.name}`;
  };

  return new Promise((resolve, reject) => {
    let unsub = null;
    let done = false;
    const finish = (fn, v) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (unsub) unsub();
      fn(v);
    };
    const timer = setTimeout(() => finish(reject, new Error('Transaction timed out')), TX_TIMEOUT_MS);

    tx.signAndSend(signer, { nonce }, ({ status, events, dispatchError }) => {
      if (!status.isInBlock && !status.isFinalized) return;
      if (dispatchError) return finish(reject, new Error(metaError('', dispatchError)));
      for (const { event } of events) {
        if (event.section === 'sudo' && event.method === 'Sudid') {
          const r = event.data[0];
          if (r?.isErr) return finish(reject, new Error(metaError('sudo:', r.asErr)));
        }
      }
      finish(resolve, (status.isInBlock ? status.asInBlock : status.asFinalized).toHex());
    }).then((u) => {
      unsub = u;
      if (done) u();
    }).catch((e) => finish(reject, e));
  });
}

/** Read AccessGrants[txId] and return a plain object, or null when absent */
async function readGrant(api, txIdHex) {
  const opt = await api.query.accessKeys.accessGrants(hexToU8a(`0x${txIdHex}`));
  if (opt.isNone) return null;
  const g = opt.unwrap();
  return {
    appId: g.appId.toHex().slice(2),
    nullifier: g.nullifier.toHex().slice(2),
    commitment: g.accessKeyCommitment.toHex().slice(2),
    used: g.used.isTrue,
  };
}

/** Validate inputs and compare a grant to the user-supplied blinding / expected app */
async function checkKey(api, txId, blinding, expectedAppId) {
  const txIdHex = cleanHex(txId, 16);
  if (!txIdHex) return { ok: false, reason: 'txId must be 16 bytes (32 hex chars)' };
  const blindingHex = cleanHex(blinding, 32);
  if (!blindingHex) return { ok: false, reason: 'blinding must be 32 bytes (64 hex chars)' };

  let grant;
  try {
    grant = await readGrant(api, txIdHex);
  } catch {
    return { ok: false, reason: 'Failed to query chain' };
  }
  if (!grant) return { ok: false, reason: 'Access grant not found. XCM may not have arrived yet, or txId is wrong.' };
  if (grant.used) return { ok: false, reason: 'Access key already used' };

  if (expectedAppId !== undefined && expectedAppId !== null) {
    const allowed = (Array.isArray(expectedAppId) ? expectedAppId : [expectedAppId]).map(normaliseAppId);
    if (!allowed.includes(grant.appId)) return { ok: false, reason: 'Access key is for a different app' };
  }

  if (accessKeyCommitment(grant.appId, blindingHex) !== grant.commitment) {
    return { ok: false, reason: 'Blinding does not match stored commitment' };
  }
  return { ok: true, appId: grant.appId, commitment: grant.commitment, txIdHex, blindingHex };
}

// ── Session tokens (issued by NullaRelay, verifiable by the provider) ────────

const b64u = (buf) => Buffer.from(buf).toString('base64url');

/** Signed, expiring token: base64url(payload).base64url(HMAC-SHA256) */
function signSessionToken({ appId, txId }, secret, ttlSec = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const payload = b64u(JSON.stringify({ appId, txId, iat: now, exp: now + ttlSec }));
  const sig = crypto.createHmac('sha256', secret).update(payload).digest();
  return `${payload}.${b64u(sig)}`;
}

/** @returns {{appId,txId,iat,exp}|null} null when malformed, forged, expired or for another app */
function verifySessionToken(token, secret, { expectedAppId } = {}) {
  if (typeof token !== 'string') return null;
  const [payload, sig, extra] = token.split('.');
  if (!payload || !sig || extra !== undefined) return null;
  const want = crypto.createHmac('sha256', secret).update(payload).digest();
  const got = Buffer.from(sig, 'base64url');
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return null;
  let data;
  try { data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch { return null; }
  if (!data || typeof data.exp !== 'number' || data.exp < Math.floor(Date.now() / 1000)) return null;
  if (expectedAppId && data.appId !== normaliseAppId(expectedAppId)) return null;
  return data;
}

// ── NullaAuthGate ─────────────────────────────────────────────────────────────

class NullaAuthGate {
  /**
   * @param {object} [config]
   * @param {string} [config.authgateRpc]   - AuthGate WS RPC (defaults to Nulla mainnet)
   * @param {string} [config.proofhubRpc]   - ProofHub WS RPC; only needed for admin / payment balance (see DEFAULT_ENDPOINTS)
   * @param {string} [config.scanproofRpc]  - ScanProof WS RPC (optional)
   */
  constructor({ authgateRpc, proofhubRpc, scanproofRpc } = {}) {
    this.authgateRpc = authgateRpc || DEFAULT_ENDPOINTS.authgateRpc;
    this.proofhubRpc = proofhubRpc || null;
    this.scanproofRpc = scanproofRpc || null;
    this._ag = null;
    this._ph = null;
    this._sp = null;
    this.admin = new NullaAuthGateAdmin(this);
  }

  /** Connect to AuthGate and the configured privacy chains. */
  async connect() {
    this._ag = await ApiPromise.create({ provider: new WsProvider(this.authgateRpc), noInitWarn: true });
    const chainNames = [await this._ag.rpc.system.chain()];

    if (this.proofhubRpc) {
      this._ph = await ApiPromise.create({ provider: new WsProvider(this.proofhubRpc), noInitWarn: true });
      chainNames.push(`ProofHub: ${await this._ph.rpc.system.chain()}`);
    }
    if (this.scanproofRpc) {
      this._sp = await ApiPromise.create({ provider: new WsProvider(this.scanproofRpc), noInitWarn: true });
      chainNames.push(`ScanProof: ${await this._sp.rpc.system.chain()}`);
    }

    console.log(`[NullaAuthGate] Connected: ${chainNames.join(' | ')}`);
    return this;
  }

  async disconnect() {
    await Promise.all([this._ag?.disconnect(), this._ph?.disconnect(), this._sp?.disconnect()]);
  }

  /**
   * Check that an access grant exists, is unused, matches the blinding and
   * (when given) belongs to `expectedAppId`. Does NOT consume the key.
   *
   * @param {string} txId
   * @param {string} blinding
   * @param {{expectedAppId?: string|string[]}} [opts]
   * @returns {Promise<{ ok: boolean, appId?: string, commitment?: string, reason?: string }>}
   */
  async verifyKey(txId, blinding, { expectedAppId } = {}) {
    if (!this._ag) throw new Error('Call connect() first');
    const r = await checkKey(this._ag, txId, blinding, expectedAppId);
    return r.ok ? { ok: true, appId: r.appId, commitment: r.commitment } : r;
  }

  /**
   * Verify and consume an access key in one step. The backend account pays the
   * fee; the user's identity is never exposed.
   *
   * @param {string} txId             - From wallet `access buy` output
   * @param {string} blinding         - From wallet `access buy` output
   * @param {string} backendMnemonic  - Funded AuthGate account that signs use_access_key
   * @param {{expectedAppId: string|string[]}} opts - App(s) this provider serves (required)
   * @returns {Promise<{ ok: boolean, appId?: string, blockHash?: string, reason?: string }>}
   */
  async verifyAndConsume(txId, blinding, backendMnemonic, { expectedAppId } = {}) {
    if (!this._ag) throw new Error('Call connect() first');
    if (expectedAppId === undefined || expectedAppId === null || (Array.isArray(expectedAppId) && !expectedAppId.length)) {
      throw new Error('expectedAppId is required: pass the appId(s) this backend serves');
    }

    const check = await checkKey(this._ag, txId, blinding, expectedAppId);
    if (!check.ok) return { ok: false, reason: check.reason };

    const signer = new Keyring({ type: 'sr25519' }).addFromMnemonic(backendMnemonic);
    const nonce = (await this._ag.rpc.system.accountNextIndex(signer.address)).toNumber();
    const tx = this._ag.tx.accessKeys.useAccessKey(
      Array.from(hexToU8a(`0x${check.txIdHex}`)),
      Array.from(hexToU8a(`0x${check.blindingHex}`)),
    );
    const blockHash = await sendAndWait(this._ag, signer, tx, nonce);
    return { ok: true, appId: check.appId, blockHash };
  }
}

// ── NullaAuthGateAdmin ────────────────────────────────────────────────────────

class NullaAuthGateAdmin {
  constructor(sdk) { this._sdk = sdk; }

  /**
   * Register an app slot on AuthGate and set its price on ProofHub / ScanProof.
   * Requires sudo on the involved chains (Nulla team only).
   */
  async registerApp({
    appId,
    name,
    priceNulla,
    paymentAddress,
    authgateMnemonic,
    proofhubMnemonic,
    scanproofMnemonic,
  }) {
    const { _ag: ag, _ph: ph, _sp: sp } = this._sdk;
    if (!ag) throw new Error('Call connect() first (AuthGate connection required)');

    const appIdBytes  = encodeAppId(appId);
    const appIdHex    = normaliseAppId(appId);
    const nameBytes   = Array.from(Buffer.from(name, 'utf8'));
    if (nameBytes.length === 0 || nameBytes.length > MAX_APP_NAME_LEN) {
      throw new Error(`name must be 1-${MAX_APP_NAME_LEN} bytes`);
    }
    const pricePlanck = nullaToPlanck(priceNulla);
    const payBytes    = Array.from(decodeAddress(paymentAddress));

    const existing = await this.getApp(appIdHex);
    if (existing) throw new Error(`appId ${appIdHex} is already registered (use updateApp)`);

    const keyring = new Keyring({ type: 'sr25519' });
    const agSigner = keyring.addFromMnemonic(authgateMnemonic);
    const agNonce  = (await ag.rpc.system.accountNextIndex(agSigner.address)).toNumber();
    const agTx     = ag.tx.sudo.sudo(ag.tx.accessKeys.listAccessSlot(appIdBytes, nameBytes, pricePlanck, payBytes));

    console.log(`[NullaAuthGate] Registering app "${name}" (${appIdHex.slice(0, 16)}...) @ ${priceNulla} NULLA on AuthGate`);
    const agBlock = await sendAndWait(ag, agSigner, agTx, agNonce);
    console.log(`[NullaAuthGate] AuthGate block: ${agBlock}`);

    const setPrice = async (api, mnemonic, label) => {
      const signer = keyring.addFromMnemonic(mnemonic);
      const nonce  = (await api.rpc.system.accountNextIndex(signer.address)).toNumber();
      const tx     = api.tx.sudo.sudo(api.tx.proofs.setAccessConfig(appIdBytes, pricePlanck, payBytes));
      const block  = await sendAndWait(api, signer, tx, nonce);
      console.log(`[NullaAuthGate] ${label} block: ${block}`);
      return block;
    };

    const proofhubBlock  = ph && proofhubMnemonic  ? await setPrice(ph, proofhubMnemonic, 'ProofHub (para 2000)') : null;
    const scanproofBlock = sp && scanproofMnemonic ? await setPrice(sp, scanproofMnemonic, 'ScanProof (para 2002)') : null;

    return { appId: appIdHex, authgateBlock: agBlock, proofhubBlock, scanproofBlock };
  }

  /**
   * Update an existing slot on AuthGate (sudo). Omitted fields are left unchanged.
   * Price changes must also be applied on ProofHub via setAccessConfig.
   */
  async updateApp(appId, { name, priceNulla, paymentAddress, active } = {}, authgateMnemonic) {
    const ag = this._sdk._ag;
    if (!ag) throw new Error('Call connect() first');

    const nameBytes = name === undefined ? null : Array.from(Buffer.from(name, 'utf8'));
    if (nameBytes && (nameBytes.length === 0 || nameBytes.length > MAX_APP_NAME_LEN)) {
      throw new Error(`name must be 1-${MAX_APP_NAME_LEN} bytes`);
    }
    const price = priceNulla === undefined ? null : nullaToPlanck(priceNulla);
    const pay   = paymentAddress === undefined ? null : Array.from(decodeAddress(paymentAddress));
    const act   = active === undefined ? null : Boolean(active);

    const signer = new Keyring({ type: 'sr25519' }).addFromMnemonic(authgateMnemonic);
    const nonce  = (await ag.rpc.system.accountNextIndex(signer.address)).toNumber();
    const tx     = ag.tx.sudo.sudo(ag.tx.accessKeys.updateAccessSlot(encodeAppId(appId), nameBytes, price, pay, act));
    return { appId: normaliseAppId(appId), authgateBlock: await sendAndWait(ag, signer, tx, nonce) };
  }

  /** Read one registered app, or null. */
  async getApp(appId) {
    const ag = this._sdk._ag;
    if (!ag) throw new Error('Call connect() first');
    const opt = await ag.query.accessKeys.appRegistry(encodeAppId(appId));
    if (opt.isNone) return null;
    return slotToApp(normaliseAppId(appId), opt.unwrap().toJSON());
  }

  /** List all registered app slots on AuthGate. */
  async listApps() {
    const ag = this._sdk._ag;
    if (!ag) throw new Error('Call connect() first');
    const entries = await ag.query.accessKeys.appRegistry.entries();
    return entries.map(([key, val]) => {
      const slot = val.isSome === undefined ? val.toJSON() : val.unwrap().toJSON();
      return slotToApp(u8aToHex(key.args[0]).slice(2), slot);
    });
  }

  /** Free balance of an address on ProofHub (shows received payments). */
  async checkPaymentBalance(address) {
    const ph = this._sdk._ph;
    if (!ph) throw new Error('Call connect() first (ProofHub connection required)');
    const { data: { free } } = await ph.query.system.account(address);
    const freePlanck = BigInt(free.toString());
    return {
      address,
      freeNulla: Number(freePlanck) / 1e12,
      freePlanck: freePlanck.toString(),
    };
  }
}

function slotToApp(appId, slot) {
  return {
    appId,
    name: Buffer.from(slot.name.slice(2), 'hex').toString().replace(/\0+$/, ''),
    priceNulla: Number(BigInt(slot.price)) / Number(PLANCK_PER_NULLA),
    active: slot.active,
  };
}

// ── NullaAuthGateClient ───────────────────────────────────────────────────────
/**
 * Read-only client (no mnemonic, no signing). For apps without a backend:
 * verifyOnly() pre-checks a key, consumeViaRelay() hands it to a NullaRelay.
 */
class NullaAuthGateClient {
  /**
   * @param {object} config
   * @param {string}  [config.authgateRpc] - AuthGate WS RPC (defaults to Nulla mainnet)
   * @param {string}  [config.relayUrl]    - Provider's NullaRelay HTTP(S) base URL
   */
  constructor({ authgateRpc, relayUrl } = {}) {
    this.authgateRpc = authgateRpc || DEFAULT_ENDPOINTS.authgateRpc;
    this.relayUrl    = relayUrl ? relayUrl.replace(/\/+$/, '') : null;
    this._ag         = null;
  }

  async connect() {
    this._ag = await ApiPromise.create({ provider: new WsProvider(this.authgateRpc), noInitWarn: true });
    return this;
  }

  async disconnect() { await this._ag?.disconnect(); }

  /** @returns {Promise<{ valid: boolean, appId?: string, reason?: string }>} */
  async verifyOnly(txId, blinding, { expectedAppId } = {}) {
    if (!this._ag) throw new Error('Call connect() first');
    const r = await checkKey(this._ag, txId, blinding, expectedAppId);
    return r.ok ? { valid: true, appId: r.appId } : { valid: false, reason: r.reason };
  }

  /** @returns {Promise<{ ok: boolean, token?: string, appId?: string, blockHash?: string, reason?: string }>} */
  async consumeViaRelay(txId, blinding) {
    if (!this.relayUrl) throw new Error('relayUrl not configured');

    const check = await this.verifyOnly(txId, blinding);
    if (!check.valid) return { ok: false, reason: check.reason };

    const res = await fetch(`${this.relayUrl}/consume`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ txId, blinding }),
      signal: AbortSignal.timeout(TX_TIMEOUT_MS + 5_000),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, reason: data.error || 'Relay error' };
    return { ok: true, ...data };
  }
}

// ── NullaRelay ────────────────────────────────────────────────────────────────
/**
 * HTTP relay so frontend-only apps can consume keys without holding a mnemonic.
 *
 * Exposes POST /consume { txId, blinding } and GET /health. It only consumes keys
 * of `allowedAppIds` and answers with a signed session token that the provider
 * checks with verifySessionToken(token, sessionSecret).
 */
class NullaRelay {
  /**
   * @param {object}   config
   * @param {string}  [config.authgateRpc]
   * @param {string}   config.relayMnemonic     - Funded AuthGate account that pays fees
   * @param {string[]} config.allowedAppIds     - Apps this relay serves (required)
   * @param {string}   config.sessionSecret     - HMAC secret for session tokens (>=32 chars)
   * @param {string[]} [config.allowedOrigins]  - Browser origins allowed via CORS (default: none)
   * @param {number}  [config.port=4000]
   * @param {number}  [config.sessionTtlSec=3600]
   * @param {number}  [config.maxBodyBytes=4096]
   * @param {{windowMs:number,max:number}} [config.rateLimit] - per client IP (default 20 / minute)
   * @param {boolean} [config.trustProxy=false] - read client IP from X-Forwarded-For
   */
  constructor({
    authgateRpc,
    relayMnemonic,
    allowedAppIds,
    sessionSecret,
    allowedOrigins = [],
    port = 4000,
    sessionTtlSec = 3600,
    maxBodyBytes = 4096,
    rateLimit = { windowMs: 60_000, max: 20 },
    trustProxy = false,
  }) {
    if (!relayMnemonic) throw new Error('relayMnemonic is required');
    if (!Array.isArray(allowedAppIds) || allowedAppIds.length === 0) {
      throw new Error('allowedAppIds is required: list the app(s) this relay serves');
    }
    if (typeof sessionSecret !== 'string' || sessionSecret.length < 32) {
      throw new Error('sessionSecret is required (at least 32 characters)');
    }
    this.port = port;
    this.allowedAppIds = allowedAppIds.map(normaliseAppId);
    this.allowedOrigins = allowedOrigins;
    this.sessionSecret = sessionSecret;
    this.sessionTtlSec = sessionTtlSec;
    this.maxBodyBytes = maxBodyBytes;
    this.rateLimit = rateLimit;
    this.trustProxy = trustProxy;
    this._sdk = new NullaAuthGate({ authgateRpc, proofhubRpc: null });
    this._mnemonic = relayMnemonic;
    this._hits = new Map();
    this._inflight = new Set();
    this._server = null;
  }

  _rateLimited(ip) {
    const now = Date.now();
    const rec = this._hits.get(ip);
    if (!rec || now - rec.start > this.rateLimit.windowMs) {
      this._hits.set(ip, { start: now, n: 1 });
      return false;
    }
    rec.n += 1;
    return rec.n > this.rateLimit.max;
  }

  async start() {
    await this._sdk.connect();
    const http = require('http');

    const sweep = setInterval(() => {
      const now = Date.now();
      for (const [ip, rec] of this._hits) if (now - rec.start > this.rateLimit.windowMs) this._hits.delete(ip);
    }, this.rateLimit.windowMs);
    sweep.unref();

    this._server = http.createServer(async (req, res) => {
      const origin = req.headers.origin;
      if (origin && this.allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      }

      const send = (code, body) => {
        const p = JSON.stringify(body);
        res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(p) });
        res.end(p);
      };

      const url = (req.url || '').split('?')[0];
      if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
      if (req.method === 'GET' && url === '/health') return send(200, { ok: true });
      if (req.method !== 'POST' || url !== '/consume') return send(404, { error: 'POST /consume only' });

      const fwd = this.trustProxy ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() : '';
      const ip = fwd || req.socket.remoteAddress || 'unknown';
      if (this._rateLimited(ip)) return send(429, { error: 'Too many requests' });

      let body;
      try {
        body = await new Promise((resolve, reject) => {
          let d = '';
          req.on('data', (c) => {
            d += c;
            if (d.length > this.maxBodyBytes) reject(new Error('Body too large'));
          });
          req.on('end', () => { try { resolve(JSON.parse(d)); } catch { reject(new Error('Invalid JSON')); } });
          req.on('error', reject);
        });
      } catch (e) {
        if (e.message !== 'Body too large') return send(400, { error: e.message });
        res.setHeader('Connection', 'close');
        res.on('finish', () => req.destroy());
        return send(413, { error: e.message });
      }

      const { txId, blinding } = body || {};
      const txIdHex = cleanHex(txId, 16);
      if (!txIdHex || !cleanHex(blinding, 32)) return send(400, { error: 'txId (16 bytes hex) and blinding (32 bytes hex) required' });

      if (this._inflight.has(txIdHex)) return send(409, { error: 'This key is already being processed' });
      this._inflight.add(txIdHex);
      try {
        const result = await this._sdk.verifyAndConsume(txId, blinding, this._mnemonic, { expectedAppId: this.allowedAppIds });
        if (!result.ok) return send(403, { error: result.reason });

        const token = signSessionToken({ appId: result.appId, txId: txIdHex }, this.sessionSecret, this.sessionTtlSec);
        console.log(`[relay] Key consumed for app ${result.appId.slice(0, 16)}... block ${result.blockHash}`);
        return send(200, { ok: true, token, appId: result.appId, blockHash: result.blockHash, expiresIn: this.sessionTtlSec });
      } catch (e) {
        console.error('[relay] Error:', e.message);
        // Only chain-level reasons are safe to show to the client
        return send(500, { error: /^accessKeys\./.test(e.message) ? e.message : 'Internal error' });
      } finally {
        this._inflight.delete(txIdHex);
      }
    });

    await new Promise((resolve) => this._server.listen(this.port, resolve));
    console.log(`[NullaRelay] Running on port ${this.port}`);
    return this._server;
  }

  async stop() {
    if (this._server) await new Promise((resolve) => this._server.close(resolve));
    await this._sdk.disconnect();
  }
}

module.exports = {
  NullaAuthGate,
  NullaAuthGateClient,
  NullaRelay,
  DEFAULT_ENDPOINTS,
  normaliseAppId,
  nullaToPlanck,
  accessKeyCommitment,
  signSessionToken,
  verifySessionToken,
};
