# SkillChain — Backend

Backend API for [SkillChain](https://frontend-rho-eight-42.vercel.app/), a blockchain-backed provenance infrastructure platform for artisan and cultural assets.

This service handles x402 payment challenge flows, Algorand smart contract interactions, provenance event recording, DID-linked ownership management, and artwork acquisition orchestration.

---

## Live Deployments

| Service | URL |
|---|---|
| **Frontend** | https://frontend-rho-eight-42.vercel.app/ |
| **Backend API** | https://skillchain-dcyr.onrender.com |
| **Frontend Repo** | https://github.com/SkillChainOrg/frontend |
| **Vault Repo** | https://github.com/SkillChainOrg/skillchain-vault |

---

## Architecture

```
Frontend (React + Vite)          → Vercel
        ↓
Backend API (Flask)              → Render
        ↓
x402 Challenge Layer             → Payment-gated acquisition
        ↓
Vault Service                    → Key management + signing
        ↓
Algorand Smart Contracts         → On-chain state transitions
        ↓
Provenance Event Store           → Explorer-verifiable ownership history
```

The backend is intentionally stateless between acquisition requests. All persistent ownership state lives on-chain via Algorand application state and box storage.

---

## What This Backend Does

- **x402 Payment Flow** — Implements the HTTP 402 challenge-response cycle. Incoming requests are challenged, payment is verified against the Algorand marketplace contract, and acquisition is unlocked only after grouped transaction settlement.
- **Provenance Verification** — Records and verifies the full ownership chain for each registered artwork. Each provenance event is submitted as an on-chain transaction, making the history independently verifiable via any Algorand explorer.
- **Algorand Smart Contract Interaction** — Communicates with an ARC4-compliant marketplace contract. Handles grouped transaction construction, ABI method calls, box storage encoding (keyed by artwork ID), and application state reads.
- **DID-Linked Ownership** — Artisans and collectors are identified via Decentralized Identifiers (DIDs). Ownership assertions are linked to DID documents, allowing verification without relying on a central identity store.
- **Artwork Registration Orchestration** — Coordinates artwork registration across the database layer and on-chain contract. Bootstraps contract state and links on-chain records to off-chain artisan metadata.
- **Vault Integration** — Delegates signing operations to a separate vault microservice. The backend never holds raw private keys in memory during request handling.
- **Acquisition Pipeline** — Manages the full wallet-authorized acquisition flow: payment challenge → transaction group construction → vault-signed submission → provenance record creation.

### Prototype Integrations (Mocked)
- **Razorpay** — Payment order architecture is wired in; currently returns mock responses. Designed to be swapped for live keys without structural changes.
- **DigiLocker** — Identity document verification architecture exists. Currently returns stubbed responses for demo purposes.

---

## Repository Structure

```
skillchain-backend/
├── app.py                   # Flask app entry point, route registration
├── routes/
│   ├── acquisition.py       # x402 acquisition flow endpoints
│   ├── provenance.py        # Provenance recording and verification
│   ├── artwork.py           # Artwork registration and metadata
│   ├── artisan.py           # Artisan registration and DID management
│   └── verification.py      # Ownership and approval verification
├── services/
│   ├── algorand.py          # Algorand SDK wrapper, grouped tx construction
│   ├── vault.py             # Vault service client (signing delegation)
│   ├── x402.py              # x402 challenge-response logic
│   └── payment.py           # Razorpay integration (prototype)
├── models/                  # SQLAlchemy models
├── contracts/               # ABI JSON and contract constants
├── requirements.txt
├── .env.example
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- An Algorand node or API key (Nodely / AlgoNode recommended)
- A running instance of [skillchain-vault](https://github.com/SkillChainOrg/skillchain-vault)
- PostgreSQL (or SQLite for local development)

---

### 1. Clone the Repository

```bash
git clone https://github.com/SkillChainOrg/backend.git
cd backend
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

#### Environment Variable Reference

```env
# --- Flask ---
FLASK_ENV=development
SECRET_KEY=your-flask-secret-key

# --- Database ---
DATABASE_URL=postgresql://user:password@localhost:5432/skillchain
# For local SQLite: sqlite:///skillchain.db

# --- Algorand ---
ALGOD_TOKEN=your-algod-api-token
ALGOD_SERVER=https://testnet-api.algonode.cloud
ALGOD_PORT=443

INDEXER_SERVER=https://testnet-idx.algonode.cloud
INDEXER_PORT=443

# App ID of the deployed marketplace smart contract
MARKETPLACE_APP_ID=762870187

# --- Vault Service ---
# Base URL of the running skillchain-vault instance
VAULT_URL=http://localhost:5001

# Admin key used by the backend to authenticate with the vault
VAULT_ADMIN_KEY=your-vault-admin-key

# --- CORS ---
# Comma-separated list of allowed frontend origins
FRONTEND_ORIGIN=http://localhost:5173,https://frontend-rho-eight-42.vercel.app

# --- Razorpay (Prototype) ---
RAZORPAY_KEY_ID=rzp_test_xxxxx
RAZORPAY_KEY_SECRET=your-razorpay-secret
```

**Key variables explained:**

| Variable | Purpose |
|---|---|
| `MARKETPLACE_APP_ID` | Algorand application ID of the deployed ARC4 marketplace contract. All smart contract calls target this app. |
| `VAULT_URL` | The vault microservice handles all signing. The backend constructs transactions but never signs them directly. |
| `VAULT_ADMIN_KEY` | Short-lived admin credential used to authorize signing requests to the vault. |
| `ALGOD_SERVER` | Algorand node endpoint. Testnet uses AlgoNode by default; swap for Mainnet when ready. |
| `FRONTEND_ORIGIN` | Drives CORS policy. Add any origin that needs to call the API. |

---

### 5. Initialize the Database

```bash
flask db upgrade
```

To bootstrap sample artwork and artisan data for local testing:

```bash
python scripts/bootstrap_artworks.py
```

---

### 6. Run the Backend

```bash
flask run --port 5000
```

The API will be available at `http://localhost:5000`.

---

### 7. Connect the Frontend

Clone the frontend repository and point it at your local backend:

```bash
# In the frontend repo
VITE_API_URL=http://localhost:5000
```

The frontend expects the backend to expose `/api/v1/*` routes. CORS is configured via `FRONTEND_ORIGIN` in the backend `.env`.

---

### 8. Connect the Vault Service

Clone and run [skillchain-vault](https://github.com/SkillChainOrg/skillchain-vault) separately:

```bash
# In the vault repo
flask run --port 5001
```

Ensure `VAULT_URL` in the backend `.env` matches the vault's running address.

---

## x402 Payment Flow

The x402 flow implements the HTTP 402 Payment Required specification for gating content or actions behind cryptographic payment proof.

```
Client                    Backend                    Algorand
  |                          |                           |
  |── POST /acquire ─────────>|                           |
  |                          |── Return 402 Challenge ──>|
  |<── 402 + challenge ───────|                           |
  |                          |                           |
  |  (client constructs grouped tx: payment + acquire)   |
  |                          |                           |
  |── POST /acquire ─────────>|                           |
  |   + signed tx group      |── Submit grouped tx ─────>|
  |                          |<── Confirmed txn ID ───────|
  |                          |                           |
  |                          |── Record provenance event |
  |<── 200 + proof ───────────|                           |
```

The payment and acquisition calls are bundled as an atomic grouped transaction. If either fails, neither settles. Box references in the grouped transaction are encoded using the ARC4 artwork key derived from the registered artwork contract ID.

---

## Algorand Smart Contract Integration

- **Contract Standard**: ARC4 (ABI-compliant)
- **Application ID (Testnet)**: `762870187`
- **Box Storage**: Ownership and provenance state is stored in Algorand box storage, keyed by artwork ID
- **Grouped Transactions**: Acquisition requires a two-transaction group (payment + method call) submitted atomically
- **DID Ownership**: Creator and owner fields in box state are DID strings, enabling off-chain identity resolution
- **Indexer Queries**: The backend uses the Algorand Indexer to read confirmed transaction history for provenance reconstruction

---

## Provenance Flow

```
Artwork Registration
      ↓
On-chain box storage initialized (creator DID, artwork ID, metadata hash)
      ↓
Acquisition (x402 + grouped tx)
      ↓
Box state updated (new owner DID, acquisition txn ID)
      ↓
Provenance event recorded (txn ID → backend provenance store)
      ↓
Verifiable via /api/v1/provenance/<artwork_id> or Algorand explorer
```

Each provenance record links to a confirmed Algorand transaction, making the ownership chain independently auditable without trusting the backend.

---

## Blockchain Verification

The smart contract is live on Algorand Testnet and has processed real acquisition transactions.

**Marketplace Smart Contract (Testnet)**
https://testnet.explorer.perawallet.app/application/762870187/

Inspect application state, box storage, and ABI method history directly on the explorer.

**Verified x402 Acquisition Transaction**
https://testnet.explorer.perawallet.app/tx/Q6LAKG4U3FQWIPQM6Q42HETXOT3VK3AQ6OWBVZODCUHOGIVXZESQ/

This confirms:
- Grouped transaction settlement executed correctly
- x402 payment and acquisition method call settled atomically
- Ownership transfer is recorded in on-chain box state
- Provenance event is independently verifiable without backend involvement

---

## Deployment

The backend is deployed on [Render](https://render.com) as a web service.

Key deployment notes:
- Environment variables are set via the Render dashboard (not committed to the repository)
- `gunicorn` is used as the WSGI server in production
- The vault service is deployed as a separate Render service, and `VAULT_URL` points to its live URL
- Database migrations run automatically on deploy via the Render start command

**Render start command:**
```bash
gunicorn app:app
```

---

## Related Repositories

| Repo | Purpose |
|---|---|
| [SkillChainOrg/frontend](https://github.com/SkillChainOrg/frontend) | React + Vite frontend, deployed on Vercel |
| [SkillChainOrg/skillchain-vault](https://github.com/SkillChainOrg/skillchain-vault) | Key management and transaction signing microservice |

---

## License

MIT
