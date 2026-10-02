'use strict';
/**
 * Example: frontend-only app using NullaRelay.
 *
 *   RELAY_MNEMONIC="word1 ..." \
 *   ALLOWED_APP_IDS="my-app-id,<64-hex>" \
 *   SESSION_SECRET="$(openssl rand -hex 32)" \
 *   ALLOWED_ORIGINS="https://my-site.example" \
 *   node example/relay.js
 *
 * Browser: POST <relay>/consume { txId, blinding } -> { ok, token, appId, blockHash }
 * Your backend validates the token with verifySessionToken(token, SESSION_SECRET).
 */

const { NullaRelay } = require('../index.js');

const required = (name) => {
  if (!process.env[name]) throw new Error(`Set ${name} before starting`);
  return process.env[name];
};
const list = (v) => (v || '').split(',').map((s) => s.trim()).filter(Boolean);

const relay = new NullaRelay({
  authgateRpc:    process.env.AUTHGATE_RPC || undefined,
  relayMnemonic:  required('RELAY_MNEMONIC'),
  allowedAppIds:  list(required('ALLOWED_APP_IDS')),
  sessionSecret:  required('SESSION_SECRET'),
  allowedOrigins: list(process.env.ALLOWED_ORIGINS),
  port:           parseInt(process.env.PORT || '4000', 10),
  trustProxy:     process.env.TRUST_PROXY === '1',
});

relay.start().catch((e) => { console.error(e); process.exit(1); });

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => relay.stop().finally(() => process.exit(0)));
}
