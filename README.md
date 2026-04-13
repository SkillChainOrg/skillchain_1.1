# SkillChain

A blockchain-anchored credential verification system built on Algorand, IPFS, and W3C Decentralised Identifiers (DIDs), with government-backed identity binding via DigiLocker.

---

## What It Solves

Academic and professional credentials are trivially forgeable. Existing verification systems are centralised, opaque, and dependent on the continued operation of the issuing institution. If a college shuts down, its issued certificates become unverifiable.

SkillChain addresses this by anchoring a cryptographic fingerprint of every certificate directly on the Algorand blockchain at issuance time. Verification does not depend on contacting the issuing institution — it requires only the original certificate file and public blockchain state. The identity layer adds a second guarantee: not just that a certificate is authentic, but that the person presenting it is the person it was issued to, confirmed via DigiLocker's Aadhaar-backed identity.


---

## System Architecture

### Component Map

```
                          ┌──────────────────────────────────────────┐
                          │               Flask API (app.py)          │
                          │  Rate-limited, CORS-enabled, admin-gated  │
                          └──────┬──────────────┬────────────┬────────┘
                                 │              │            │
               ┌─────────────────▼──┐   ┌──────▼──────┐  ┌─▼──────────────┐
               │  algorand_service  │   │ did_service  │  │identity_service│
               │  anchor_hash()     │   │ register_did │  │ bind_identity  │
               │  verify_hash()     │   │ validate_key │  │ verify_owns    │
               │  trust_score()     │   │ sign_cred    │  └────────────────┘
               └────────┬───────────┘   └──────┬───────┘
                        │                      │
           ┌────────────▼──────┐   ┌───────────▼────────────────┐
           │   Algorand Node   │   │      signing_service        │
           │  (testnet via     │   │  Vault → fetch key → sign   │
           │   Algonode.cloud) │   │  → del key (scope-limited)  │
           └────────┬──────────┘   └──────┬─────────────────────┘
                    │                     │
           ┌────────▼──────────┐   ┌──────▼───────────────────┐
           │   ipfs_service    │   │   vault_client / key_vault│
           │  Pinata + 3-GW    │   │   HashiCorp Vault (prod)  │
           │  fallback chain   │   │   AES-256-GCM DB (dev)    │
           └────────┬──────────┘   └──────────────────────────┘
                    │
           ┌────────▼──────────┐
           │   PostgreSQL      │
           │  certificates     │
           │  did_registry     │
           │  pending_reg.     │
           │  identity_anchors │
           └───────────────────┘
```

### Backend Structure

The application is a Flask API with eight Python service modules, each with a single responsibility:

- `algorand_service.py` — certificate hashing, Algorand anchoring, trust scoring, and verification
- `did_service.py` — institution DID registration, API key lifecycle, Ed25519 credential signing, email verification
- `digilocker_service.py` — DigiLocker session management (mock with production-swap points)
- `identity_service.py` — DigiLocker-to-DID binding, identity ownership verification
- `signing_service.py` — secure private-key operations (fetch → sign → delete pattern)
- `vault_client.py` — HashiCorp Vault KV v2 integration for key storage
- `ipfs_service.py` — Pinata pinning with three-gateway retry fallback
- `queue_service.py` — in-memory batch anchoring queue with background thread
- `validation_service.py` — multi-layer credential validation pipeline inspired by Decouchant et al., combining                                       cryptographic verification, issuer trust evaluation, and identity binding checks

### Database Design

Four PostgreSQL tables:

**`certificates`** — one row per anchored certificate. Stores `cert_hash` (SHA-256), `tx_id`, `doc_type`, `issued_at`, `ipfs_cid`, `cert_number`, and `issued_to` (now an `identity_did`, not a name hash — this changed in the April 10–11 refactor). The HMAC value is intentionally absent from this table; it lives only in IPFS metadata to prevent a known-plaintext corpus from sitting next to the data it protects.

**`did_registry`** — one row per approved institution. Stores the W3C DID, institution name, Algorand wallet address, Ed25519 public key, API key (SHA-256 hashed), encrypted private key for dev mode, Vault key version indicator (`wallet_version`), and revocation fields.

**`pending_registrations`** — institutions awaiting admin approval. Has an email verification token column and a double-guard (`verified` + `approved`) to prevent premature activation.

**`identity_anchors`** — one row per DigiLocker-verified person. Stores `identity_did` (derived deterministically from `digilocker_id` + `name_hash`), `name_hash` (SHA-256 of normalised name — raw PII never stored), and `bound_at` timestamp.

Schema migrations are idempotent — `run_migrations()` uses `pg_advisory_lock` to prevent race conditions during multi-worker startup on Railway, adds columns with `IF NOT EXISTS` guards, and never drops data.

### Blockchain Interaction

Every certificate issuance creates a zero-value `PaymentTxn` (self-send) on Algorand testnet. The transaction note field carries a compact JSON payload:

```json
{"sc": "1", "cid": "<ipfs_cid>", "wv": <wallet_version>}
```

This note links the on-chain transaction to the IPFS metadata object that contains the full certificate record. The `wait_for_confirmation(client, tx_id, 4)` call makes issuance synchronous — the API does not return until the transaction is confirmed in a block.

Verification has two paths:
1. Fast path: DB lookup by `cert_hash` → direct indexer fetch by `tx_id`
2. Fallback: Algorand indexer search across all institution transactions, scanning IPFS metadata for hash match

Both paths include a primary/fallback indexer pattern (Algonode → Algoexplorer) with retry and exponential backoff.

### IPFS Usage

Certificate metadata is pinned to IPFS via Pinata on issuance. The metadata object includes `cert_hash`, `doc_type`, `issued_by`, `issuer_did`, `issued_at`, Ed25519 `signature`, `hmac_value`, `cert_number`, and `issued_to`. Raw PII is never included — names are hashed before reaching this layer.

Retrieval falls through three gateways in order: Pinata (authenticated), Cloudflare IPFS, and ipfs.io. If all three fail, verification returns a structured error rather than a false negative.

### Identity Layer

The DigiLocker flow produces a government-backed identity binding:

```
User completes DigiLocker consent
        ↓
digilocker_service extracts: {digilocker_id, name}
        ↓
identity_service.bind_identity()
    name_hash     = SHA-256(name.strip().lower())
    identity_did  = did:skillchain:identity:<SHA-256(digilocker_id:name_hash)[:16]>
        ↓
Row written to identity_anchors (idempotent)
        ↓
identity_did stored in certificates.issued_to at issuance
        ↓
At verification: hmac_lib.compare_digest(claimant_did, cert_issued_to_did)
```

The DID derivation is deterministic — the same DigiLocker user always gets the same identity DID, making the system resilient to session loss. The constant-time comparison in `verify_identity_owns_cert` prevents timing-oracle attacks.

### DID Resolution

Institution DIDs follow the pattern `did:skillchain:<sha256_prefix>` and comply with W3C DID Core 1.0. The `/did/<path:did>` endpoint constructs the DID Document directly from `did_registry` at request time — it does not depend on a pre-generated cache. The document includes Ed25519 verification methods, authentication/assertionMethod arrays, a `SkillChainIssuer` service endpoint, and a `LinkedDomains` entry. Content-Type is set to `application/did+ld+json`.

An on-chain ARC4 smart contract (`DIDRegistry` in `smart_contracts/did_contract.py`) exists and stores DID documents in Algorand Box Storage, with per-institution write access controlled by transaction sender identity. This contract is not yet integrated into the main application flow — it operates as a parallel proof-of-concept.

### Validation Layer (Decouchant Model Alignment)

SkillChain’s verification pipeline follows a multi-layer validation approach inspired by Decouchant’s research on decentralised trust systems. Rather than relying on a single signal, verification is composed of independent layers:

- **Cryptographic integrity** — SHA-256 hash matching and HMAC recomputation ensure the certificate has not been altered.
- **Provenance verification** — Ed25519 signatures confirm issuance by a valid institution DID.
- **Anchoring layer** — Algorand transaction inclusion guarantees temporal integrity and immutability.
- **Identity binding** — DigiLocker-derived identity DIDs confirm ownership of the credential.
- **Issuer state validation** — revocation status and registry presence are checked at verification time.

These layers are evaluated independently and aggregated into the trust score, preventing any single point of failure from compromising verification correctness.

---


---

## Feature Inventory

### Certificate Issuance (`/issue`)

**What it does:** Accepts a certificate file, normalises it, computes its SHA-256 hash, signs it with the institution's Ed25519 key, anchors the hash on Algorand, and pins metadata to IPFS.

**Implementation:** PIL opens the image, clears EXIF metadata (`img.getexif().clear()`), converts to RGB, serialises to PNG in-memory, then SHA-256 hashes the bytes. EXIF clearing ensures the hash is stable across re-saves. The file bytes are deleted from memory after hashing.

**Location:** `app.py → issue()`, `algorand_service.py → anchor_hash()`

**Constraints:** Requires the institution wallet to hold at least 200,000 microAlgos (`is_wallet_ready` check). Rate-limited to 10 requests per minute. Only processes files named in the request — empty filenames are rejected.

---

### Certificate Verification (`/verify`)

**What it does:** Accepts a certificate file, re-derives its hash, looks it up in the DB and on-chain, checks IPFS metadata integrity, recomputes the HMAC, checks issuer revocation, verifies the Ed25519 signature, and returns a composite trust score.

**Implementation:** Trust score is a weighted sum across four signals — chain confirmation (35 points), HMAC validity (25), Ed25519 signature (25), issuer not revoked (15) — with a +5 bonus for wallet version 2 (per-institution key). HMAC is recomputed from the env secret on every verification call; the stored IPFS value is compared with `hmac.compare_digest` (timing-safe).

**Location:** `algorand_service.py → verify_hash(), _verify_full(), compute_trust_score()`

**Constraints:** IPFS metadata fetch can fail if all three gateways are unavailable. Falls back to indexer scan if cert is not in local DB, which is slower and depends on Algorand indexer availability.

---

### Batch Issuance (`/issue/batch`)

**What it does:** Accepts a ZIP file of up to 500 certificates, hashes all of them synchronously, then queues Algorand anchoring as a background job. Returns immediately with a `batch_id` and a status polling URL.

**Implementation:** A module-level `threading.Thread` drains a `collections.deque` in a 2-second polling loop. Results accumulate in a dict keyed by `batch_id`. A `metadata.json` file inside the ZIP can pre-assign cert numbers and holder names. Files prefixed with `__MACOSX` are skipped.

**Location:** `app.py → issue_batch()`, `queue_service.py`

**Constraints:** Queue state is in-memory — a worker restart loses all queued and in-progress jobs. Not safe for multi-worker deployments (the Flask process must be single-worker for queue continuity). Max 500 files per batch is enforced before queuing.

---

### Institution Registration and DID Onboarding

**What it does:** Three-stage flow — institution submits name/email/domain → email token verification → admin approval → DID registration and wallet provisioning.

**Implementation:** Registration tokens are `secrets.token_hex(16)`. API keys are `secrets.token_hex(32)`, SHA-256 hashed before DB storage; the plaintext key is returned once and never re-stored. Institution names are normalised (`strip().lower()` + whitespace collapse) before all DB operations to prevent duplicate registrations under different capitalisation. On approval, a fresh Algorand keypair is generated and either stored in Vault (production) or AES-256-GCM encrypted in `did_registry` (dev mode).
### Intelligent Institution Approval (ML Decision Layer)

**What it does:** Augments the manual admin approval process with a machine learning–assisted decision layer to evaluate institution legitimacy.

**Implementation:** The current system uses manual approval gated by email/domain verification. A planned ML layer operates on institution metadata (domain reputation, historical issuance patterns, registry consistency, and anomaly signals) to assign a risk score and recommend approval or rejection.

**Design intent:** The ML layer does not replace admin control — it acts as a decision-support system, reducing human bias and scaling onboarding without weakening trust guarantees.

**Status:** Not yet active in production; designed as an extension point over the existing `pending_registrations` workflow.

**Location:** `app.py`, `did_service.py → request_registration(), approve_registration()`

**Constraints:** `DEMO_MODE` must be explicitly set — the application refuses to start with an unset value. Admin operations are gated by `X-Admin-Key` header comparison against an env-provided `ADMIN_KEY` (not hashed — this is an admin-only channel, not a user-facing secret).

---

### DigiLocker Identity Binding (`/digilocker/*`)

**What it does:** Initiates a DigiLocker consent session, receives the authenticated user identity, and creates or retrieves a deterministic identity DID.

**Implementation:** Currently operates in mock mode — real Setu API calls are replaced by two private helper functions (`_mock_create_request`, `_mock_get_status`) with clearly marked swap points. The session store (`_FAKE_DIGILOCKER_DB`) is module-level in-memory. The `/digilocker/start` endpoint accepts a user-provided `name` field and stores it against the `request_id`; no hardcoded identity values exist in the codebase.

**Location:** `digilocker_service.py`, `app.py → digilocker_start(), digilocker_verify(), digilocker_bind()`

**Constraints:** In-memory session store does not survive server restarts. `ensure_mock_session` is a demo-only fallback that re-creates sessions with an empty name on restart — this causes `verify_with_identity` to return 422 with an informative error rather than silently binding a phantom identity.

---

### Key Management and Signing (`signing_service.py`, `vault_client.py`)

**What it does:** Abstracts all private key operations so keys never exist outside the innermost signing scope.

**Implementation:** `sign_transaction()` and `sign_credential_hash()` follow a fetch → use → `del` pattern with `try/finally` guaranteeing deletion even on exceptions. When `VAULT_ENABLED=true`, keys are fetched from HashiCorp Vault KV v2 at `secret/skillchain/{institution_id}` with no fallback. When `VAULT_ENABLED=false`, per-institution keys are AES-256-GCM decrypted from `did_registry` (key encrypted at approval time using `KEY_ENCRYPTION_KEY` env var).Vault usage is strict and non-optional in production mode. When enabled, private keys never exist in application memory outside the immediate signing scope and are never persisted in the database. Each institution is assigned a unique key path, enabling isolation, revocation, and future key rotation without cross-tenant risk.


**Location:** `signing_service.py`, `vault_client.py`, `key_vault.py`

**Constraints:** Python does not guarantee memory zeroing on `del` — the fetch-sign-delete pattern minimises the exposure window but does not provide cryptographic memory erasure. Vault integration includes authentication validation at client construction time, failing hard rather than discovering authentication failure at sign time.

---

### W3C DID Document Resolution (`/did/<path:did>`)

**What it does:** Resolves a SkillChain DID to a W3C-compliant DID Document with verification methods, authentication arrays, and service endpoints.

**Implementation:** Document is constructed at request time directly from `did_registry` — no pre-generation cache required. Revoked DIDs return HTTP 410. Invalid DID format returns 400 (regex-validated). Content-Type is `application/did+ld+json`.

**Location:** `app.py → resolve_did_endpoint()`, `w3c_did_service.py` (pre-generation cache, non-critical)

---

### Trust Score Engine

**What it does:** Produces a 0–100 composite score and A–F grade for every verified credential.

**Implementation:** Four weighted signals with a per-institution key bonus. Score is computed inline in `_verify_full()` and returned alongside all verification fields.

| Signal | Weight |
|---|---|
| Chain confirmed | 35 |
| HMAC valid | 25 |
| Ed25519 signature valid | 25 |
| Issuer not revoked | 15 |
| Per-institution key (v2) | +5 bonus |

**Location:** `algorand_service.py → compute_trust_score()`

---

### Issuer Revocation (`/admin/revoke-issuer/<institution_id>`)

**What it does:** Sets `revoked=1` on a `did_registry` row, with timestamp and reason. All subsequent verifications for certificates issued by that institution return invalid.

**Implementation:** Revocation is checked during `_verify_full()` by querying `did_registry` on the transaction sender address. DID resolution returns HTTP 410 for revoked DIDs.

---

## Development Evolution

### March 17 — MVP

Initial commit. Flask + Algorand SDK, SHA-256 normalisation pipeline, frontend UI, SQLite as the database. The normalisation test (`test_normalization.py`) was included from day one — image normalisation correctness was treated as foundational, not an afterthought.

### March 18–19 — Institution Layer and DigiLocker

DID-gated issuance introduced — institutions must register and be approved before issuing certificates. DigiLocker integration via Setu API added, initially as a live sandbox flow. This commit introduced the first form of the identity verification pipeline.

### March 23–24 — Hardening

Byte note safety guard added to the Algorand transaction note (length assertion before submission). HMAC implementation added to tamper-evidence chain. Batch issuance with the in-memory queue introduced. This period represents the jump from single-cert MVP to institution-scale operation.

### March 28 — IPFS CID Fix

The IPFS CID was not being correctly embedded in transaction notes. Fixed to use the actual Pinata response CID rather than a placeholder.

### April 2 — Vault and Signing Isolation

Major security refactor: `signing_service.py` introduced as the sole authority for private-key operations. Private keys extracted from `algorand_service.py` and `did_service.py`. HashiCorp Vault KV v2 integration added via `hvac`. This commit eliminated private key exposure from core services — before this, keys were accessible from multiple callsites.

### April 3 — Deployment Fixes

Idempotent PostgreSQL migrations with `pg_advisory_lock`. Dependency declarations stabilised. W3C DID document structure formalised in `w3c_did_service.py`. Vault integration made deployment-safe (partial integration without breaking non-Vault deployments).

### April 10 — PostgreSQL Migration and Identity Layer

SQLite removed entirely. All DB access migrated to `psycopg2` via a single `db.py` connection helper. `identity_service.py` introduced with the full DigiLocker-to-DID binding architecture. Two security fixes landed simultaneously: HMAC vulnerability removed (HMAC value no longer stored in DB), and admin authentication hardened. Multi-worker race condition in migrations fixed using Postgres advisory locks. Private key decoding bug in `signing_service.py` corrected. DigiLocker moved from live Setu calls to a mock implementation with explicit production swap points.

### April 11 — HMAC and Identity Refactor

HMAC strengthened with a mandatory `HMAC_SECRET` env var checked at module import time (raises `RuntimeError` if missing — no silent defaults). Identity binding refactored: `issued_to` column semantics changed from `name_hash` to `identity_did`. The old `verify_identity_against_cert` (name-hash comparison, susceptible to same-name collisions) replaced by `verify_identity_owns_cert` (constant-time DID string comparison, no collision risk).

### April 12–13 — W3C Compliance and Security Hardening

DID registry updated to W3C DID Core 1.0 structure. API key storage hardened — keys are now SHA-256 hashed before DB insertion; plaintext is returned once at registration. DigiLocker identity flow made dynamic — hardcoded `_DEMO_USER_NAME` removed, user-provided name attached to session at creation time. DID resolution endpoint made self-contained (no longer dependent on `w3c_did_service` for resolution).

---

## Production Analysis

### Authentication and API Key Management

API keys are SHA-256 hashed at storage — the DB contains no retrievable plaintext keys. Rate limiting (Flask-Limiter) is applied per remote address. The `ADMIN_KEY` is compared directly (not hashed) — acceptable for an admin-only channel, but a compromised environment variable fully compromises admin access. There is no API key rotation mechanism; revocation requires direct DB manipulation.

### Blockchain Anchoring

The Algorand testnet dependency is the most significant production risk. `wait_for_confirmation(client, tx_id, 4)` blocks the HTTP response for 4 block rounds (~16 seconds worst case) on each `/issue` call. Under load, this makes the endpoint unsuitable as a synchronous API without upstream timeouts. The batch endpoint correctly decouples this by queuing, but its in-memory queue is lost on restart — jobs in progress at restart time are silently dropped.

The fallback indexer pattern handles transient Algonode outages, but if both primary and fallback indexers are down, verification fails with a structured error rather than a false positive. This is the correct failure mode.

### IPFS Dependency

Verification depends on IPFS metadata retrieval. A certificate whose CID has been unpinned from Pinata and evicted from both Cloudflare and ipfs.io caches is unverifiable even if the on-chain transaction is valid. Long-term metadata persistence requires either a dedicated IPFS node or Pinata's paid pinning guarantees.

### Identity Layer

The mock DigiLocker implementation is not a placeholder — it is a correctly architected swap point. The real Setu integration requires only replacing `_mock_create_request` and `_mock_get_status`. All downstream code (session retrieval, name normalisation, identity binding, DID derivation) is production-ready and does not need modification when the swap is made.

### Batch Queue

The `queue_service` threading model is incompatible with multi-process deployment (gunicorn with multiple workers). The queue lives in one process's memory. If Railway scales to multiple workers, each handles its own queue in isolation, meaning batch status queries can return "not found" when routed to a worker that did not create the batch. This requires replacement with a durable task queue (Celery + Redis or similar) before scaling.

### Key Management

The Vault integration is architecturally sound — fail-hard on unavailability, no silent fallbacks in production mode. The dev-mode AES-256-GCM encryption of keys in `did_registry` is a reasonable local substitute. The `KEY_ENCRYPTION_KEY` env var for dev mode must be rotated manually; there is no key rotation workflow implemented.

---

## Security Evaluation

### Implemented Protections

- **HMAC tamper-evidence:** HMAC-SHA256 computed server-side from `HMAC_SECRET` and stored only in IPFS metadata — not in the DB alongside the hash it protects. Verification recomputes and compares with `hmac.compare_digest` (timing-safe). The April 10 commit removed an earlier vulnerability where HMAC was stored in the DB.

- **Ed25519 provenance signatures:** Every certificate hash is signed with the issuing institution's Ed25519 private key at issuance. Signature is stored in IPFS metadata and verified during the `_verify_full` path using the institution's public key from `did_registry`.

- **API key hashing:** Plaintext API keys never persisted. SHA-256 hash stored; DB compromise does not yield usable keys.

- **Private key scoping:** `signing_service.py` fetch-sign-`del` pattern. Keys exist only within the signing function scope. `try/finally` guarantees deletion on exception paths.

- **No PII storage:** Names stored as SHA-256 hashes. Raw DigiLocker names exist only in the in-memory session store (and transiently in the Flask request context). `identity_anchors` stores `name_hash`, not `name`.

- **Constant-time identity comparison:** `hmac_lib.compare_digest` used for identity DID comparison, preventing timing oracle attacks.

- **Rate limiting:** Flask-Limiter on `/issue` (10/min), `/verify` (30/min), DigiLocker endpoints (20/min), and identity lookup (30/min).

- **Startup-time env validation:** `HMAC_SECRET`, `ADMIN_KEY`, `DEMO_MODE`, and `DATABASE_URL` are all checked at import/startup time with `RuntimeError` on absence — no deferred failure at runtime.

- **Transaction ID validation:** `is_valid_txid()` rejects demo/placeholder IDs before indexer queries, preventing false verification against non-existent transactions.

### Potential Vulnerabilities

- `ADMIN_KEY` is compared with `==` (not `compare_digest`) — susceptible to timing oracle in theory, though in practice HTTP network jitter dominates. Low severity.

- The `ensure_mock_session` function re-creates sessions with an empty name on server restart. This correctly causes downstream 422 errors rather than silent incorrect bindings, but the function should be removed entirely when moving to real Setu.

- In `_verify_full`, the revocation lookup uses an `OR` condition (`institution_address = %s OR (institution_address IS NULL AND address = %s)`). This is a legacy compatibility pattern from the SQLite→PostgreSQL migration period and could theoretically match unexpected rows if address values overlap between the two columns. Harmless in practice given unique address constraints, but worth cleaning up.

- The ARC4 smart contract's `revoke` function has a tautological authorization check (`sender == sender`) that was present in one version — the updated contract in the AlgoKit project corrects this to `sender == self.admin.value`.

---

## Limitations

**DigiLocker is not live.** The current `digilocker_service.py` uses a mock implementation. Production deployment requires Setu sandbox credentials and replacement of two private helper functions. The rest of the identity pipeline is production-ready.

**Batch queue is not restart-safe.** Jobs queued but not yet anchored are lost if the Flask process restarts. There is no job persistence, retry mechanism, or dead-letter queue.

### Smart Contract (On-Chain DID Registry)

An Algorand ARC4 smart contract (`smart_contracts/did_contract.py`), along with the AlgoKit project under `skill_contracts/`, implements a decentralised DID registry using Algorand Box Storage.

The current system uses a PostgreSQL-backed `did_registry` for DID resolution and management. This choice is deliberate: database-backed reads provide low-latency access and simplify integration with the verification pipeline during early-stage development.

The smart contract represents the decentralised evolution of this layer. Integrating it would require replacing database operations with on-chain state access and transaction-driven updates, introducing additional latency, cost, and failure modes that were intentionally avoided in the current iteration.

By separating the contract implementation from the active system, the architecture remains production-stable while still demonstrating a complete pathway to a fully decentralised registry.

**`issued_to` semantic change is not backward-compatible.** Certificates issued before the April 11 refactor stored a `name_hash` in `issued_to`; certificates issued after store an `identity_did`. The `verify_identity_owns_cert` function does not handle the legacy case — certificates issued in the early period will fail identity verification.

**No HMAC key rotation.** Rotating `HMAC_SECRET` invalidates all existing HMAC checks. There is no versioned HMAC scheme, so rotation requires re-pinning all IPFS metadata objects.

**Testnet only.** All Algorand addresses, transactions, and explorer URLs reference the Algorand testnet. Mainnet migration requires funded institution wallets and a Pinata account with production SLA.

**Single-process constraint for batch.** Gunicorn multi-worker deployments break the batch queue. Production batch issuance requires a durable queue backend.

---

## Tech Stack

| Layer | Technology |
|---|---|
| API framework | Flask, flask-cors, Flask-Limiter |
| Blockchain | Algorand (algosdk), Algonode testnet |
| Smart contracts | AlgoKit, algopy (ARC4, Box Storage) |
| IPFS | Pinata (pinning), multi-gateway fetch |
| Database | PostgreSQL (psycopg2, RealDictCursor) |
| Key management | HashiCorp Vault KV v2 (hvac), AES-256-GCM (dev) |
| Cryptography | Ed25519 (PyNaCl / nacl.signing), HMAC-SHA256, SHA-256 |
| Image processing | Pillow (PIL) |
| Identity | DigiLocker via Setu (mock; production swap-ready) |
| Deployment | Docker, Railway (PostgreSQL managed service) |
| Language | Python 3.11+ |

---

## API Surface

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| POST | `/issue` | X-API-Key | Issue a single certificate |
| POST | `/verify` | None | Verify a certificate file |
| POST | `/issue/batch` | X-API-Key | Queue up to 500 certificates |
| GET | `/batch/status/<batch_id>` | X-API-Key | Poll batch anchoring progress |
| POST | `/request-registration` | None | Submit institution for review |
| GET | `/verify-email` | Token (query param) | Confirm institution email |
| GET | `/admin/pending` | X-Admin-Key | List pending registrations |
| POST | `/admin/approve/<id>` | X-Admin-Key | Approve and provision institution |
| POST | `/admin/revoke-issuer/<id>` | X-Admin-Key | Revoke an institution |
| POST | `/digilocker/start` | None | Start DigiLocker consent session |
| GET | `/digilocker/callback` | None | Process DigiLocker callback |
| POST | `/digilocker/verify` | None | Bind DigiLocker identity to DID |
| POST | `/digilocker/bind` | None | Directly bind a DigiLocker identity |
| GET | `/digilocker/identity/<id>` | X-API-Key | Look up identity anchor |
| GET | `/did/<path:did>` | None | Resolve DID to W3C DID Document |
| GET | `/did/view/<path:did>` | None | Human-readable DID viewer |
| GET | `/institution/<path:did>` | None | Institution dashboard |
| GET | `/health` | None | Service health (Vault status) |

---

## Key Strengths

**HMAC architecture.** Storing the HMAC only in IPFS metadata and recomputing it server-side on every verification is a non-obvious design choice that eliminates the known-plaintext risk of keeping HMAC values adjacent to the data they protect. This was identified and corrected during development rather than being present from the start.

**Identity binding is collision-free.** The shift from name-hash comparison (April 10) to identity-DID comparison (April 11) is significant. Name hashing is susceptible to same-name collisions — two people named "Ravi Kumar" produce identical issued_to values. DID binding eliminates this by using the DigiLocker user ID as part of the derivation seed, producing unique DIDs per person regardless of name.

**Production swap architecture.** The DigiLocker mock is not a shortcut — it is a carefully designed interface boundary. The two private helper functions are the only code that changes for production. Route handlers, verification logic, identity binding, and the DID derivation chain are all real production code running against mock data.

**Signing isolation.** Eliminating private key access from all modules except `signing_service.py` means a vulnerability in `algorand_service.py` or `did_service.py` cannot leak key material. The fetch-sign-delete pattern, with `del` in `finally`, minimises the in-memory window.

**Deterministic identity DIDs.** `_derive_identity_did` is a pure function of `digilocker_id` and `name_hash`. The same user always gets the same DID across sessions, servers, and time. This enables stateless identity verification without requiring session persistence.

**Self-contained DID resolution.** The `/did/<path:did>` endpoint constructs DID Documents directly from the PostgreSQL registry without depending on a pre-generation service. This means DID resolution continues working even if `w3c_did_service.py` is unavailable — an explicit architectural decision visible in the April 13 commit.

---

## Future Work

**Replace batch queue with Celery + Redis.** The in-memory queue is the single largest operational risk. A durable queue with job persistence, retry logic, and multi-worker support is the direct next step.

**Integrate the ARC4 DID Registry contract.** The on-chain DID registry exists and is written against the current AlgoKit/algopy API. Wiring it into the institution approval flow would make DID registration fully on-chain and auditable without relying on the PostgreSQL registry.

**Activate real Setu DigiLocker.** Replace `_mock_create_request` and `_mock_get_status` with live Setu sandbox calls. No other changes required.

**Versioned HMAC.** Store an `hmac_version` field in IPFS metadata alongside the HMAC value to enable key rotation without invalidating existing certificates.

**Backfill `issued_to` semantics.** Certificates issued before April 11 have a `name_hash` in `issued_to` rather than an `identity_did`. A one-time migration that marks pre-refactor certificates and handles them in the identity verification path would restore coverage for the early-issued cohort.

**Mainnet deployment.** Replace testnet Algonode URLs with mainnet equivalents, fund institution wallets with real ALGO, and update explorer URLs.
