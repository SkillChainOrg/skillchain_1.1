# SkillChain — Vault Key Management Setup

This guide covers two deployment paths:

| Path | Use case | Persistence |
|------|----------|-------------|
| **HCP Vault** (recommended) | Production / Railway | Always-unsealed managed service |
| **Dev Mode** (`VAULT_DEV_MODE`) | Local dev / hackathon | In-memory, resets on restart |

---

## Option A: HCP Vault (Production — Railway)

HCP Vault is HashiCorp's managed Vault service. It stays unsealed permanently,
which eliminates the "sealed after Railway deploy" crash that self-hosted Vault causes.

### 1. Create a free HCP Vault cluster

1. Sign in or create an account at <https://portal.cloud.hashicorp.com>
2. Click **Create organization** if prompted.
3. Navigate to **Vault** → **Create cluster**.
4. Choose:
   - **Cluster type**: `HCP Vault Dedicated` (2-week free trial) **or**
     `HCP Vault Secrets` (always free, but uses a different REST API — not compatible
      with the hvac KV v2 calls used here; choose Dedicated).
   - **Provider / Region**: any region close to your Railway deployment.
   - **Cluster name**: `skillchain` (or anything).
5. Wait ~5 minutes for provisioning.
6. Note your **Public cluster URL** — it looks like:
   `https://<cluster-id>.vault.hashicorp.cloud:8200`
   This is your `VAULT_ADDR`.

### 2. Enable the KV v2 secrets engine

In the HCP Vault UI, open a **Vault CLI shell** or use the built-in terminal:

```sh
vault secrets enable -path=secret kv-v2
```

Or via API (replace `$VAULT_ADDR` and `$VAULT_TOKEN`):

```sh
curl -s -X POST "$VAULT_ADDR/v1/sys/mounts/secret" \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -H "X-Vault-Namespace: admin" \
  -d '{"type":"kv","options":{"version":"2"}}'
```

### 3. Create a policy granting read/write on `secret/skillchain/*`

Save the following as `skillchain-policy.hcl`:

```hcl
path "secret/data/skillchain/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/skillchain/*" {
  capabilities = ["list", "delete"]
}
```

Apply it:

```sh
vault policy write skillchain skillchain-policy.hcl
```

### 4. Create a token with that policy

```sh
vault token create \
  -policy=skillchain \
  -ttl=8760h \
  -display-name="skillchain-backend"
```

Copy the `token` value — this is your `VAULT_TOKEN`.

> **Security**: Rotate this token at least every 90 days. Set a calendar reminder.

### 5. Store the system key on first run

Run this locally (with your `.env` populated) or as a one-off Railway run command:

```sh
python -c "
from vault_client import store_key
from algosdk import mnemonic as mn
import os
store_key('system', mn.to_private_key(os.getenv('MNEMONIC')))
print('System key stored in Vault.')
"
```

> The system wallet is used **only** for funding new institution wallets (PaymentTxn).
> Each approved institution gets its own keypair and key path in Vault.

### 6. Set Railway environment variables

In your Railway project → **Variables**, add:

```
VAULT_ADDR=https://<cluster-id>.vault.hashicorp.cloud:8200
VAULT_TOKEN=<token from step 4>
VAULT_NAMESPACE=admin
VAULT_ENABLED=true
KEY_ENCRYPTION_KEY=  # leave blank when using Vault; required only for dev mode
```

---

## Option B: Dev Mode (Local / Hackathon — NOT for production)

When `VAULT_ENABLED=false`, SkillChain uses:
- The system wallet from `MNEMONIC` env var.
- AES-256-GCM encrypted per-institution keys stored in the `did_registry` SQLite table.

### Required env vars for dev mode

```env
VAULT_ENABLED=false
MNEMONIC=<25-word Algorand mnemonic for system wallet>
KEY_ENCRYPTION_KEY=<64 hex chars>
```

Generate `KEY_ENCRYPTION_KEY`:

```sh
python -c "import secrets; print(secrets.token_hex(32))"
```

> **WARNING**: Dev mode keys are tied to the local `skillchain.db` file.
> If the database is deleted, all per-institution keys are permanently lost.
> This mode is **not** suitable for production.

---

## `.env.example` additions

Add these to your `.env.example` (never commit actual values):

```env
# --- Vault (production) ---
VAULT_ADDR=https://<cluster-id>.vault.hashicorp.cloud:8200
VAULT_TOKEN=
VAULT_NAMESPACE=admin
VAULT_ENABLED=true

# --- Dev mode fallback (VAULT_ENABLED=false only) ---
KEY_ENCRYPTION_KEY=   # python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Verifying Vault connectivity

```sh
curl -s "$VAULT_ADDR/v1/sys/health" \
  -H "X-Vault-Namespace: admin" | python -m json.tool
```

Expected response when healthy:
```json
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  ...
}
```

The `GET /health` endpoint on the SkillChain API also reports Vault status:

```sh
curl https://your-railway-app.railway.app/health
# {"status": "ok", "vault": "connected"}
```
