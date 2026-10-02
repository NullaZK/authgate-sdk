# API reference

All exports come from `@nulla/authgate-sdk` (Node, CommonJS). The browser client is imported from `@nulla/authgate-sdk/browser` (ES module).

## `NullaAuthGate`

```js
const ag = new NullaAuthGate({ authgateRpc?, proofhubRpc?, scanproofRpc? });
await ag.connect();
await ag.disconnect();
```

| Option | Default |
| --- | --- |
| `authgateRpc` | `DEFAULT_ENDPOINTS.authgateRpc` (mainnet) |
| `proofhubRpc` | not connected. Only needed for `admin.registerApp` and `admin.checkPaymentBalance` |
| `scanproofRpc` | not connected |

### `verifyKey(txId, blinding, { expectedAppId? })`

Read-only. Does not consume the key.

Returns `{ ok: true, appId, commitment }` or `{ ok: false, reason }`.

Rejection reasons: `txId must be 16 bytes (32 hex chars)`, `blinding must be 32 bytes (64 hex chars)`, `Failed to query chain`, `Access grant not found...`, `Access key already used`, `Access key is for a different app`, `Blinding does not match stored commitment`.

### `verifyAndConsume(txId, blinding, mnemonic, { expectedAppId })`

Runs the same checks, then signs and submits `use_access_key` with the account derived from `mnemonic` (sr25519), and waits for inclusion in a block (60 s timeout).

Returns `{ ok: true, appId, blockHash }` or `{ ok: false, reason }` for rejected keys. Throws if `expectedAppId` is missing, or on signing, network or on-chain failures (message is `section.Name`, for example `accessKeys.InvalidBlinding`).

`expectedAppId`: a string (up to 32 characters, or 64-character hex), or an array of them.

### `admin` (Nulla team only, requires sudo)

| Method | Purpose |
| --- | --- |
| `listApps()` | `[{ appId, name, priceNulla, active }]` |
| `getApp(appId)` | One app or `null` |
| `registerApp({ appId, name, priceNulla, paymentAddress, authgateMnemonic, proofhubMnemonic?, scanproofMnemonic? })` | Creates the slot on AuthGate and sets price and payment address on ProofHub/ScanProof. Fails if the app already exists |
| `updateApp(appId, { name?, priceNulla?, paymentAddress?, active? }, authgateMnemonic)` | Updates the AuthGate slot. Price changes must also be applied on ProofHub |
| `checkPaymentBalance(address)` | Free balance on ProofHub: `{ address, freeNulla, freePlanck }` |

## `NullaRelay`

```js
const relay = new NullaRelay({
  relayMnemonic,            // required, funded AuthGate account
  allowedAppIds,            // required, non-empty array
  sessionSecret,            // required, at least 32 characters
  authgateRpc,              // default mainnet
  allowedOrigins: [],       // browser origins allowed by CORS (default: none)
  port: 4000,
  sessionTtlSec: 3600,
  maxBodyBytes: 4096,
  rateLimit: { windowMs: 60000, max: 20 },   // per client IP
  trustProxy: false,        // read the client IP from X-Forwarded-For
});
await relay.start();        // resolves with the http.Server
await relay.stop();
```

Endpoints: `POST /consume` with `{ txId, blinding }`, and `GET /health`. See the [integration guide](INTEGRATION.md#3-mode-b-relay-for-frontend-only-apps) for status codes.

## Session tokens

```js
signSessionToken({ appId, txId }, secret, ttlSec = 3600)  // -> string
verifySessionToken(token, secret, { expectedAppId? })      // -> { appId, txId, iat, exp } | null
```

Format: `base64url(JSON payload) . base64url(HMAC-SHA256)`. `verifySessionToken` returns `null` for malformed, forged or expired tokens, and for tokens issued for a different app.

## `NullaAuthGateClient` (browser or Node, read-only)

```js
const client = new NullaAuthGateClient({ authgateRpc?, relayUrl? });
await client.connect();
await client.verifyOnly(txId, blinding, { expectedAppId? });         // { valid, appId } | { valid: false, reason }
await client.consumeViaRelay(txId, blinding, { expectedAppId? });    // { ok, token, appId, blockHash } | { ok: false, reason }
await client.disconnect();
```

The browser build (`/browser`) also has `getStats()`: `{ appsRegistered, apps, totalGrants, totalRedeemed, totalPending }`, read directly from AuthGate storage.

## Helpers

| Function | Purpose |
| --- | --- |
| `DEFAULT_ENDPOINTS` | `{ authgateRpc, proofhubRpc }` for Nulla mainnet |
| `normaliseAppId(id)` | Any accepted app ID form to 64-character lowercase hex (the form the wallet expects) |
| `accessKeyCommitment(appIdHex, blindingHex)` | `BLAKE3("nulla_access_key_v1" ‖ app_id ‖ blinding)` as hex |
| `nullaToPlanck(n)` | NULLA to planck (`bigint`); 1 NULLA = 10^12 planck |

## App ID forms

An app ID is 32 bytes. You can write it as a string of up to 32 UTF-8 bytes (padded with zeros) or as 64 hex characters, with or without `0x`. For example `nulla-demo-app-001` and `6e756c6c612d64656d6f2d6170702d3030310000000000000000000000000000` are the same ID.

## On-chain errors (`accessKeys` pallet)

`AppNotFound`, `AppNotActive`, `NotProofHubSovereign`, `GrantAlreadyRecorded`, `GrantNotFound`, `KeyAlreadyUsed`, `InvalidBlinding`, `AppIdMismatch`.
