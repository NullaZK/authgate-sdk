# Provider onboarding

A provider needs an **app ID** registered on-chain by the Nulla team before users can buy keys for it. This page describes the process for both sides.

## For providers

1. Open the provider request form (`/apply` on the Nulla provider portal) and submit:
   - service name
   - desired app ID (unique, up to 32 characters, for example `my-gpu-service`)
   - price per access key in NULLA
   - payment address (SS58): where the payments are received
   - contact (email or handle), and optionally your website and a description
2. The Nulla team reviews the request. You are contacted at the address you provided, and told the final app ID if it was changed.
3. After approval, the team registers your app on-chain (AuthGate slot, plus price and payment address on ProofHub).
4. Follow the [integration guide](INTEGRATION.md). Users buy keys for your app with:

   ```bash
   nulla-wallet access buy --app-id <app-id-as-64-hex> --note-id <n>
   ```

   Print the 64-character hex form of your ID with `normaliseAppId('my-app-id')`.

To change price or payment address later, contact the team (they use `updateApp`).

## For the Nulla team

The portal lives in `portal/` of the SDK repository. It has three parts and never holds sudo keys.

| Part | File | Purpose |
| --- | --- | --- |
| Request form | `portal/public/apply.html` | Public, rate limited, validates SS58 address, price and app ID; rejects duplicates |
| Review page | `portal/public/review.html` | Protected by `ADMIN_TOKEN`; Approve or Reject with a note |
| Registration tool | `portal/register-approved.js` | Run on a trusted machine; registers approved requests on-chain |

### Run the portal

```bash
cd authgate-sdk
ADMIN_TOKEN="$(openssl rand -hex 32)" \
DATA_FILE=/var/lib/authgate-portal/requests.json \
PORT=4100 node portal/server.js
```

- Put it behind HTTPS. Set `TRUST_PROXY=1` only behind a proxy that sets `X-Forwarded-For`.
- Keep `DATA_FILE` outside the repository: it holds provider contact details.
- Share `ADMIN_TOKEN` only with the team. The review page asks for it and keeps it in the browser session only.

### Review and register

1. Open `/review`, enter the admin token, and approve or reject pending requests.
2. On a trusted machine (not the portal server), register the approved ones:

   ```bash
   PORTAL_URL=https://portal.example.com \
   ADMIN_TOKEN=... \
   AUTHGATE_SUDO_MNEMONIC="..." \
   PROOFHUB_SUDO_MNEMONIC="..." \
   node portal/register-approved.js [--dry-run] [--yes]
   ```

   For each approved request the tool prints the details, skips apps already on-chain, asks for confirmation (unless `--yes`), calls `registerApp`, and marks the request `registered` with the block hash. `--dry-run` lists what would be registered and needs no mnemonics.
3. Tell the provider their app ID and point them to the integration guide.

### Request states

`pending` -> `approved` or `rejected` -> `registered`.

### API (admin token required, except `apply`)

| Method and path | Purpose |
| --- | --- |
| `POST /api/apply` | Submit a request (public) |
| `GET /api/requests` | List all requests |
| `POST /api/requests/:id/decision` | `{ decision: "approved" \| "rejected", note }` |
| `POST /api/requests/:id/registered` | `{ blockHash }`; only for approved requests |

### Notes

- The form has a honeypot field and a limit of 5 submissions per hour per IP (in memory, resets on restart).
- Notifications to providers are manual for now.
- Registration needs sudo on AuthGate and ProofHub. Treat those mnemonics as the most sensitive secrets of the network.
