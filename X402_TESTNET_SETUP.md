# SkillChain x402 Testnet Setup

## What changed

- New ARC4 contract: `ArtworkMarketplace`
- `/acquire-artwork` now implements a real two-step `402 -> grouped tx -> verify` flow
- Ownership settlement is persisted into:
  - `acquisitions`
  - `artwork_ownership`
  - `artwork_provenance_events`
  - `x402_payment_challenges`

## Required environment variables

Backend / frontend:

```env
ALGOD_URL=https://testnet-api.algonode.cloud
INDEXER_URL=https://testnet-idx.algonode.cloud
ARTWORK_MARKETPLACE_APP_ID=<deployed app id>
ARTWORK_MARKETPLACE_RECEIVER=<treasury wallet address>
DEFAULT_ARTWORK_PRICE_MICROALGOS=1000000
ARTWORK_PRICE_MICROALGOS_MAP={"1":1000000,"2":1500000}
X402_CHALLENGE_TTL_SECONDS=900
X402_NETWORK=algorand-testnet
ARTWORK_MARKETPLACE_OWNER_BOX_PREFIX=owner:
ARTWORK_MARKETPLACE_PRICE_BOX_PREFIX=price:
VITE_ALGOD_URL=https://testnet-api.algonode.cloud
```

Contract deployment:

```env
DEPLOYER_MNEMONIC=<testnet deployer mnemonic>
ARTWORK_BOOTSTRAP_ID=1
ARTWORK_BOOTSTRAP_CREATOR_DID=did:skillchain:testnet:artisan001
ARTWORK_BOOTSTRAP_INITIAL_OWNER=<initial algorand address>
ARTWORK_BOOTSTRAP_PRICE_MICROALGOS=1000000
```

## Deploy the contract

From `skill_contracts/projects/skill_contracts/smart_contracts/__main__.py`:

```powershell
cd skill_contracts\projects\skill_contracts
algokit project run build -- artwork_marketplace
python -m smart_contracts.__main__ build artwork_marketplace
python -m smart_contracts.__main__ deploy artwork_marketplace
```

The deploy script prints:

- `APP_ID=<new app id>`
- `TREASURY_ADDRESS=<deployer / treasury address>`

Copy those into:

- `ARTWORK_MARKETPLACE_APP_ID`
- `ARTWORK_MARKETPLACE_RECEIVER`

## Register an artwork on-chain

```powershell
cd skill_contracts\projects\skill_contracts
python smart_contracts\artwork_marketplace\register_artwork.py
```

This registers the three required boxes for a specific artwork:

- `owner:<artwork_id>`
- `price:<artwork_id>`
- `creator:<artwork_id>`

## Local testing flow

1. Start Flask so migrations create the new challenge table and acquisition columns.
2. Start the React frontend.
3. Open an artwork details page backed by the existing `artworks` table.
4. Click `Acquire Artwork`.
5. The first backend call returns HTTP `402` with:
   - amount
   - app id
   - receiver
   - challenge nonce
   - artwork id
   - required box names
6. Pera Wallet signs a grouped Testnet transaction:
   - payment txn
   - `acquire(string)` app call
7. The frontend resubmits the proof to `/acquire-artwork`.
8. The backend verifies:
   - app call exists on Testnet
   - group payment exists and pays the treasury
   - method selector matches `acquire(string)bool`
   - challenged artwork id matches
   - owner box now equals the buyer wallet
   - challenge nonce has not already been used
9. PostgreSQL is updated with the final provenance event and ownership row.

## Notes

- This flow is Testnet-only and intentionally minimal.
- No NFT, escrow, auction, or bidding logic was added.
- The existing DID registry, DID resolution, QR verification, and provenance verification endpoints were left alone.
- I verified Python syntax locally with `python -m py_compile`, but I did not run a frontend build or install new npm packages in this session.
