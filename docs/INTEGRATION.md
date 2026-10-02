# Integration guide

Audience: developers adding "pay anonymously with Nulla" to a Web2 application.

## 0. Prerequisites

1. **An app ID.** Request one through the provider form (see [Provider onboarding](PROVIDER_ONBOARDING.md)). The Nulla team registers your `appId`, price and payment address on-chain.
2. **A fee account.** A dedicated AuthGate account that pays the small fee for consuming keys. Fund it with a small balance and keep its mnemonic in an environment variable.
3. **Node.js 18 or newer** for the backend or relay.

```bash
npm install @nulla/authgate-sdk
```

Endpoints default to Nulla mainnet (`DEFAULT_ENDPOINTS`). Override with `authgateRpc` if needed.

## 1. Choose a mode

| | Mode A: backend | Mode B: relay |
| --- | --- | --- |
| You have a server | yes | no (static site or SPA) |
| Who holds the fee mnemonic | your backend | the relay process you run |
| Session | your own (cookie, JWT) | signed token issued by the relay |

Both modes verify and consume the key the same way. Pick A if you already run a backend.

## 2. Mode A: backend

```js
const { NullaAuthGate } = require('@nulla/authgate-sdk');

const ag = new NullaAuthGate();
await ag.connect();

app.post('/auth/nulla', async (req, res) => {
  const { txId, blinding } = req.body;
  const r = await ag.verifyAndConsume(txId, blinding, process.env.BACKEND_MNEMONIC, {
    expectedAppId: process.env.APP_ID,
  });
  if (!r.ok) return res.status(403).json({ error: r.reason });
  res.json({ token: issueYourSession(r.appId) });
});
```

- `expectedAppId` is required. It can be a string, a 64-character hex, or an array of ids.
- `verifyAndConsume` returns `{ ok: true, appId, blockHash }` or `{ ok: false, reason }`. It throws only on infrastructure errors (connection, signing, on-chain failure).
- Use `ag.verifyKey(...)` for a read-only check that does not consume the key.
- A full example is in `example/server.js`.

## 3. Mode B: relay for frontend-only apps

Run the relay on a machine you control:

```bash
RELAY_MNEMONIC="..." \
ALLOWED_APP_IDS="my-app-id" \
SESSION_SECRET="$(openssl rand -hex 32)" \
ALLOWED_ORIGINS="https://my-site.example" \
node example/relay.js
```

In the browser:

```js
import { NullaAuthGateClient } from '@nulla/authgate-sdk/browser';

const client = new NullaAuthGateClient({ relayUrl: 'https://relay.my-site.example' });
await client.connect();
const r = await client.consumeViaRelay(txId, blinding, { expectedAppId: 'my-app-id' });
if (r.ok) sessionStorage.setItem('nullaToken', r.token);
```

On every protected request, your server checks the token:

```js
const { verifySessionToken } = require('@nulla/authgate-sdk');

const session = verifySessionToken(token, process.env.SESSION_SECRET, { expectedAppId: 'my-app-id' });
if (!session) return res.status(401).end();   // forged, expired, or for another app
```

Never trust a token that is only checked in the browser. The check must run where `SESSION_SECRET` lives.

The relay accepts only `POST /consume` and `GET /health`:

| Status | Meaning |
| --- | --- |
| 200 | `{ ok, token, appId, blockHash, expiresIn }` |
| 400 | Invalid JSON or malformed `txId` / `blinding` |
| 403 | Key rejected (`reason` explains: used, wrong app, wrong blinding, not found) |
| 409 | The same key is already being processed |
| 413 | Body too large |
| 429 | Rate limit (default 20 requests per minute per IP) |
| 500 | `accessKeys.<Error>` from the chain, or `Internal error` |

## 4. The user side

Your UI needs to tell users how to get a key. They run, in the Nulla wallet:

```bash
nulla-wallet access buy --app-id <your-appId-as-64-hex> --note-id <n>
```

The wallet prints `tx-id` (32 hex characters) and `blinding` (64 hex characters). The user pastes both into your form. The `authgate-demo-app` shipped with this SDK contains a complete working UI for this step.

Use `normaliseAppId('my-app-id')` to show your app ID in the 64-character hex form that the wallet expects.

## 5. Going live checklist

1. App ID approved and registered; payment address confirmed.
2. Fee account funded; mnemonic and `SESSION_SECRET` in environment variables, not in source control.
3. `expectedAppId` or `ALLOWED_APP_IDS` set to your own app ID.
4. HTTPS in front of your backend or relay. `TRUST_PROXY=1` only when behind a proxy that sets `X-Forwarded-For`.
5. `ALLOWED_ORIGINS` limited to your site's origin.
6. Request logs do not contain `blinding`.
7. A real test: buy a key, consume it once (success), submit it again (`Access key already used`).
8. Monitoring on the fee account's balance.

## 6. Troubleshooting

| Message | Cause and fix |
| --- | --- |
| `Access grant not found` | Wrong `tx-id`, or the XCM message has not arrived yet. Wait a few blocks and retry. |
| `Access key already used` | The key was consumed (possibly by an earlier attempt of yours). |
| `Blinding does not match stored commitment` | Typo in the blinding, or it belongs to another purchase. |
| `Access key is for a different app` | The user bought a key for a different `appId`. |
| `Transaction timed out` | The transaction was not included within 60 seconds. Check the fee account balance and the RPC endpoint. |
| `1010: Inability to pay some fees` | The fee account has no balance on AuthGate. |
| `expectedAppId is required` | Pass the app ID(s) your backend serves. |
