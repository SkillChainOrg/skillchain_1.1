#!/bin/bash

set -euo pipefail

BASE="http://localhost:5000"
ADMIN_KEY=fbc30b81a99c2bd15cb2a51bd5898a64728f3b512e26413b1eb0f50a2f6fe12b


# ---------- Helpers ----------
print_step() {
  echo -e "\n----------------------------------------"
  echo "$1"
  echo "----------------------------------------"
}

fail_if_empty() {
  local value="$1"
  local message="$2"
  if [ -z "$value" ] || [ "$value" == "null" ]; then
    echo "❌ $message"
    exit 1
  fi
}

# ---------- Checks ----------
command -v jq >/dev/null 2>&1 || { echo "❌ jq is required but not installed."; exit 1; }

if [ ! -f "test.jpg" ]; then
  echo "❌ test.jpg not found!"
  exit 1
fi

# ---------- 1. Register Artisan ----------
print_step "1. Register Artisan"

ARTISAN_NAME="Test Artisan $(date +%s)"

REGISTER_RESPONSE=$(jq -n \
  --arg name "$ARTISAN_NAME" \
  '{
    name: $name,
    craft_type: "Pottery",
    cluster: "Jaipur",
    location: "Rajasthan"
  }' | curl -s -X POST "$BASE/register-artisan" \
      -H "Content-Type: application/json" \
      -d @-)
echo "$REGISTER_RESPONSE" | jq

ARTISAN_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.id')
fail_if_empty "$ARTISAN_ID" "Failed to register artisan"

echo "Artisan ID: $ARTISAN_ID"

# ---------- 2. Approve Artisan ----------
print_step "2. Approve Artisan"

APPROVE_RESPONSE=$(curl -s -X POST "$BASE/admin/approve-artisan/$ARTISAN_ID" \
  -H "X-Admin-Key: $ADMIN_KEY")

echo "$APPROVE_RESPONSE" | jq

ARTISAN_DID=$(echo "$APPROVE_RESPONSE" | jq -r '.did')
fail_if_empty "$ARTISAN_DID" "Failed to approve artisan"

echo "Artisan DID: $ARTISAN_DID"

# ---------- 3. Add Artwork ----------
print_step "3. Add Artwork"

ADD_RESPONSE=$(curl -s -X POST "$BASE/add-artwork" \
  -F "artwork=@test.jpg" \
  -F "artisan_did=$ARTISAN_DID" \
  -F "title=Test Pot" \
  -F "materials=Clay")

echo "$ADD_RESPONSE" | jq

TX_ID=$(echo "$ADD_RESPONSE" | jq -r '.tx_id')
CERT_HASH=$(echo "$ADD_RESPONSE" | jq -r '.cert_hash')

fail_if_empty "$TX_ID" "Transaction failed"
fail_if_empty "$CERT_HASH" "Certificate hash missing"

echo "TX_ID: $TX_ID"
echo "CERT_HASH: $CERT_HASH"

# ---------- 4. Verify Artwork ----------
print_step "4. Verify Artwork"

VERIFY_RESPONSE=$(curl -s -X POST "$BASE/verify" \
  -F "certificate=@test.jpg")

echo "$VERIFY_RESPONSE" | jq



# ---------- 5. Negative Test ----------
print_step "5. Negative Test (Tampered Image)"

cp test.jpg tampered.jpg
dd if=/dev/zero bs=10 count=1 >> tampered.jpg 2>/dev/null

TAMPER_RESPONSE=$(curl -s -X POST "$BASE/verify" \
  -F "certificate=@tampered.jpg")

echo "$TAMPER_RESPONSE" | jq

# ---------- 6. x402 Acquisition Challenge ----------
print_step "6. x402 Acquisition Challenge"

X402_CHALLENGE_RESPONSE=$(curl -s -i -X POST "$BASE/acquire-artwork" \
  -H "Content-Type: application/json" \
  -d '{
    "artwork_id": "art_001"
  }')

echo "$X402_CHALLENGE_RESPONSE"

STATUS_CODE=$(echo "$X402_CHALLENGE_RESPONSE" | head -n 1 | awk '{print $2}')

if [ "$STATUS_CODE" != "402" ]; then
  echo "❌ Expected HTTP 402 Payment Required"
  exit 1
fi

echo "✅ x402 challenge returned successfully"

# ---------- 7. x402 Payment + Ownership Transfer ----------
print_step "7. x402 Payment + Ownership Transfer"

COLLECTOR_WALLET="ALGORAND_TEST_WALLET_001"

X402_PAYMENT_RESPONSE=$(curl -s -X POST "$BASE/acquire-artwork" \
  -H "Content-Type: application/json" \
  -H "X-X402-Payment: paid-demo-proof" \
  -H "X-X402-Wallet: $COLLECTOR_WALLET" \
  -d '{
    "artwork_id": "art_001"
  }')

echo "$X402_PAYMENT_RESPONSE" | jq

ACQUISITION_STATUS=$(echo "$X402_PAYMENT_RESPONSE" | jq -r '.status')
NEW_OWNER=$(echo "$X402_PAYMENT_RESPONSE" | jq -r '.owner')

fail_if_empty "$ACQUISITION_STATUS" "x402 acquisition failed"
fail_if_empty "$NEW_OWNER" "Ownership transfer failed"

echo "✅ Ownership transferred to: $NEW_OWNER"

# ---------- 8. Verify Persistent Provenance ----------
print_step "8. Verify Persistent Provenance"

PROVENANCE_RESPONSE=$(curl -s "$BASE/artwork/art_001")

echo "$PROVENANCE_RESPONSE" | jq

CURRENT_OWNER=$(echo "$PROVENANCE_RESPONSE" | jq -r '.current_owner')

if [ "$CURRENT_OWNER" != "$COLLECTOR_WALLET" ]; then
  echo "❌ Current owner mismatch"
  exit 1
fi

PROVENANCE_COUNT=$(echo "$PROVENANCE_RESPONSE" | jq '.provenance_history | length')

if [ "$PROVENANCE_COUNT" -lt 1 ]; then
  echo "❌ Provenance history missing"
  exit 1
fi

echo "✅ Provenance persisted successfully"

# ---------- Done ----------
print_step "TEST COMPLETE"

echo "✅ ALL TESTS COMPLETED SUCCESSFULLY"
