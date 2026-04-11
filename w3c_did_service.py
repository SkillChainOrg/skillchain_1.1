"""
w3c_did_service.py — W3C-compliant DID Document generation and resolution for SkillChain.

DID Method Spec: did:algo
─────────────────────────
Method:   algo
Network:  testnet | mainnet
Format:   did:algo:<network>:<algorand_address>:<institution_id_hex>

Example:  did:algo:testnet:ABC123...XYZ:8f3a1c9d24b07e5f

Creation:
  1. An Algorand Ed25519 keypair is generated at institution approval time.
  2. The institution_id is derived: sha256(institution_name.lower())[:16]
  3. The DID string is assembled and the DID Document is generated + stored.

Resolution:
  GET /did/<did_string>  →  returns the DID Document JSON

Verification:
  The Ed25519 public key in verificationMethod is derived from the Algorand address.
  An Algorand address IS the public key: decode_address(address) → 32-byte Ed25519 pubkey.
  Signatures made via signing_service.sign_credential_hash() are verifiable against this key.

Key format: Ed25519VerificationKey2020 (W3C standard)
  publicKeyMultibase: 'z' prefix + base58btc(32-byte-public-key)
  — Multibase z = base58btc per https://w3c-ccg.github.io/multibase/

Security:
  - Only the PUBLIC key is ever included in the DID Document.
  - Private keys stay in Vault / AES-GCM encrypted storage.
  - This module never calls _load_private_key or any signing function.
"""

import base64
import hashlib
import json
import logging
import os
import re
import time

from algosdk import encoding

from db import get_db_connection, dict_cursor

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

# DID format:  did:algo:testnet:<58-char-base32-address>:<16-char-hex>
# Algorand addresses are 58 characters, base32-encoded (A-Z + 2-7).
_DID_RE = re.compile(
    r"^did:algo:(testnet|mainnet):"
    r"([A-Z2-7]{58}):"  # Algorand address (exactly 58 chars, uppercase base32)
    r"([0-9a-f]{16})$"  # institution_id hex (16 chars)
)

# DID contexts
_DID_CONTEXT = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
]

# VC contexts
_VC_CONTEXT = [
    "https://www.w3.org/2018/credentials/v1",
    "https://skillchain.io/credentials/v1",
]

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
ALGO_NETWORK = os.getenv("ALGO_NETWORK", "testnet")


# ── Base58btc encoder (multibase 'z' prefix) ──────────────────────────────────
# Used for publicKeyMultibase in Ed25519VerificationKey2020.
# Implements https://datatracker.ietf.org/doc/html/draft-multiformats-multibase

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_encode(data: bytes) -> str:
    """Encode bytes to base58btc string (no multibase prefix)."""
    count = 0
    for byte in data:
        if byte == 0:
            count += 1
        else:
            break

    num = int.from_bytes(data, "big")
    encoded = []
    while num:
        num, remainder = divmod(num, 58)
        encoded.append(_B58_ALPHABET[remainder])
    encoded.reverse()

    result = bytes([_B58_ALPHABET[0]] * count) + bytes(encoded)
    return result.decode("ascii")


def _multibase_base58btc(data: bytes) -> str:
    """Return multibase base58btc string with 'z' prefix per W3C multibase spec."""
    return "z" + _base58btc_encode(data)


# ── DID validation ────────────────────────────────────────────────────────────

def parse_did(did: str) -> dict | None:
    """
    Validate and parse a SkillChain DID string.

    Returns:
        dict with keys: network, address, institution_id_hex
        None if the DID does not match the did:algo method format.
    """
    m = _DID_RE.match(did)
    if not m:
        return None
    return {
        "network":           m.group(1),
        "address":           m.group(2),
        "institution_id_hex": m.group(3),
    }


def is_valid_did(did: str) -> bool:
    return parse_did(did) is not None


# ── Public key derivation ─────────────────────────────────────────────────────

def _address_to_public_key_bytes(algorand_address: str) -> bytes:
    """
    Derive the raw 32-byte Ed25519 public key from an Algorand address.

    An Algorand address is base32(ed25519_pubkey + checksum[:4]).
    encoding.decode_address() strips the checksum and returns the 32-byte pubkey.
    """
    return encoding.decode_address(algorand_address)


def _public_key_multibase(algorand_address: str) -> str:
    """Return the W3C publicKeyMultibase value for this Algorand address."""
    pubkey_bytes = _address_to_public_key_bytes(algorand_address)
    return _multibase_base58btc(pubkey_bytes)


# ── DID Document generation ───────────────────────────────────────────────────

def generate_did_document(
    did: str,
    institution_name: str,
    domain: str,
    algorand_address: str,
    registered_at: str | None = None,
    revoked: bool = False,
) -> dict:
    """
    Generate a W3C-compliant DID Document for a SkillChain institution.

    The document conforms to:
      - https://www.w3.org/TR/did-core/
      - Ed25519VerificationKey2020 (https://w3c-ccg.github.io/lds-ed25519-2020/)

    Args:
        did:               Full DID string (did:algo:testnet:<address>:<hex>)
        institution_name:  Human-readable institution name.
        domain:            Official institution domain (e.g. "iitb.ac.in").
        algorand_address:  Base32 Algorand public address (source of the public key).
        registered_at:     ISO date string of DID creation.
        revoked:           If True, the document includes a revocation notice.

    Returns:
        dict — fully-formed W3C DID Document, JSON-serialisable.

    Security note:
        Only the public key is included. This function is safe to call from
        any endpoint because it never touches Vault or signing_service.
    """
    key_id = f"{did}#key-1"
    now    = registered_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    pubkey_multibase = _public_key_multibase(algorand_address)

    doc: dict = {
        "@context": _DID_CONTEXT,
        "id": did,

        # ── Verification methods ─────────────────────────────────────────────
        "verificationMethod": [
            {
                "id":                 key_id,
                "type":               "Ed25519VerificationKey2020",
                "controller":         did,
                # publicKeyMultibase: multibase 'z' (base58btc) per W3C Ed25519-2020 spec
                "publicKeyMultibase": pubkey_multibase,
            }
        ],

        # ── Verification relationships ───────────────────────────────────────
        # authentication: key can be used to authenticate as the DID subject
        # assertionMethod: key can be used to make assertions (sign credentials)
        "authentication":   [key_id],
        "assertionMethod":  [key_id],

        # ── Service endpoints ────────────────────────────────────────────────
        # Binds institution metadata and resolution endpoint to the DID Document
        "service": [
            {
                "id":              f"{did}#skillchain-resolver",
                "type":            "SkillChainResolver",
                "serviceEndpoint": f"{BASE_URL}/did/{did}",
            },
            {
                "id":   f"{did}#institution-profile",
                "type": "InstitutionProfile",
                "serviceEndpoint": {
                    "name":       institution_name,
                    "domain":     domain,
                    "network":    ALGO_NETWORK,
                    "address":    algorand_address,
                    "registered": now,
                    "verified":   True,
                },
            },
            {
                "id":              f"{did}#certificate-verification",
                "type":            "CertificateVerificationService",
                "serviceEndpoint": f"{BASE_URL}/verify",
            },
        ],

        # ── DID Document metadata ────────────────────────────────────────────
        "created": now,
        "updated": now,
    }

    # Revocation notice (does not remove keys — resolvers must check this field)
    if revoked:
        doc["deactivated"] = True

    return doc


# ── DB storage and retrieval ──────────────────────────────────────────────────

def store_did_document(did: str, document: dict) -> None:
    """
    Persist a serialised DID Document to the did_documents cache table.

    The cache table allows instant resolution without recomputing from did_registry.
    The canonical source of truth remains did_registry; this is a read-through cache.
    """
    document_json = json.dumps(document, separators=(",", ":"))

    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO did_documents (did, document, created_at, updated_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (did) DO UPDATE SET
                document   = EXCLUDED.document,
                updated_at = EXCLUDED.updated_at
            """,
            (did, document_json, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        conn.commit()
        log.info("DID Document stored: %s", did)
    except Exception as exc:
        conn.rollback()
        log.error("Failed to store DID Document for %s: %s", did, exc)
        raise
    finally:
        cur.close()
        conn.close()


def _fetch_from_cache(did: str) -> dict | None:
    """Return the cached DID Document dict, or None if not cached."""
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            "SELECT document FROM did_documents WHERE did = %s",
            (did,),
        )
        row = cur.fetchone()
        return json.loads(row["document"]) if row else None
    finally:
        cur.close()
        conn.close()


def _fetch_from_registry(did: str) -> dict | None:
    """
    Build a DID Document on-the-fly from did_registry if the cache misses.

    Falls back to live recomputation — regenerates the document, stores it,
    and returns it. This handles DIDs registered before the cache table existed.
    """
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT institution, domain, address, institution_address,
                   registered_at, revoked, public_key
            FROM did_registry
            WHERE did = %s
            """,
            (did,),
        )
        row = cur.fetchone()
        if not row:
            return None

        # Prefer institution_address (per-institution wallet); fall back to address
        algo_address = row["institution_address"] or row["address"]

        document = generate_did_document(
            did=did,
            institution_name=row["institution"],
            domain=row["domain"] or "",
            algorand_address=algo_address,
            registered_at=row["registered_at"],
            revoked=bool(row["revoked"]),
        )
        # Backfill the cache
        try:
            store_did_document(did, document)
        except Exception as exc:
            log.warning("Cache backfill failed for %s: %s", did, exc)

        return document
    finally:
        cur.close()
        conn.close()


def resolve_did(did: str) -> dict | None:
    """
    Resolve a DID to its W3C DID Document.

    Resolution order:
      1. Validate DID format.
      2. Check did_documents cache.
      3. Fall back to live recomputation from did_registry.
      4. Return None if the DID is unknown.

    Args:
        did: Full DID string.

    Returns:
        DID Document dict, or None if not found / invalid.
    """
    if not is_valid_did(did):
        return None

    document = _fetch_from_cache(did)
    if document is not None:
        return document

    return _fetch_from_registry(did)


# ── Verifiable Credential builder ─────────────────────────────────────────────

def build_verifiable_credential(
    issuer_did: str,
    holder_identity_did: str | None,
    holder_name: str | None,
    cert_hash: str,
    tx_id: str,
    doc_type: str,
    issued_at: str,
    institution_name: str,
    signature: str | None = None,
    cert_number: str | None = None,
) -> dict:
    """
    Construct a W3C Verifiable Credential for a SkillChain certificate.

    Conforms to:
      - https://www.w3.org/TR/vc-data-model/
      - Type: SkillCertificate (custom SkillChain credential type)

    The `proof` section uses Ed25519Signature2020 format.
    The `proofValue` is the base64-encoded Ed25519 signature returned by
    signing_service.sign_credential_hash() — the VC proof IS the on-chain
    signature, so no additional signing step is required.

    Args:
        issuer_did:          DID of the issuing institution.
        holder_identity_did: DID of the credential holder (from DigiLocker KYC), or None.
        holder_name:         Plain-text name of the holder (for display only).
        cert_hash:           SHA-256 hex digest of the normalised certificate image.
        tx_id:               Algorand transaction ID anchoring the hash.
        doc_type:            Certificate type string ("academic", "employment", etc.).
        issued_at:           ISO timestamp of issuance.
        institution_name:    Human-readable issuer name.
        signature:           Base64 Ed25519 signature string (from sign_credential_hash).
        cert_number:         Optional certificate serial number.

    Returns:
        dict — W3C Verifiable Credential, JSON-serialisable.
    """
    vc_id = f"{BASE_URL}/credentials/{cert_hash[:16]}"

    # credentialSubject: what is being asserted about the holder
    credential_subject: dict = {
        "certificate": {
            "type":       doc_type,
            "hash":       f"sha256:{cert_hash}",
            "txId":       tx_id,
            "issuedBy":   institution_name,
            "issuedAt":   issued_at,
            "anchoredOn": "Algorand Testnet",
        }
    }
    if holder_identity_did:
        credential_subject["id"] = holder_identity_did
    if holder_name:
        credential_subject["name"] = holder_name
    if cert_number:
        credential_subject["certificate"]["certificateNumber"] = cert_number

    vc: dict = {
        "@context": _VC_CONTEXT,
        "id":   vc_id,
        "type": ["VerifiableCredential", "SkillCertificate"],

        # issuer: the institution's W3C DID
        "issuer": {
            "id":   issuer_did,
            "name": institution_name,
        },

        "issuanceDate": issued_at,
        "credentialSubject": credential_subject,
    }

    # ── Proof section (Ed25519Signature2020) ─────────────────────────────────
    # The proof value is the Ed25519 signature already generated by
    # signing_service.sign_credential_hash(). We reuse it here — the VC
    # proof IS the same signature that was anchored on-chain.
    if signature:
        vc["proof"] = {
            "type":               "Ed25519Signature2020",
            "created":            issued_at,
            "verificationMethod": f"{issuer_did}#key-1",
            "proofPurpose":       "assertionMethod",
            # proofValue: multibase base64url per Ed25519Signature2020 spec
            # (we store as base64; prefix 'z' would indicate base58btc — use 'u' for base64url)
            "proofValue":         "u" + base64.urlsafe_b64encode(
                base64.b64decode(signature)
            ).rstrip(b"=").decode(),
        }

    # ── Algorand anchoring metadata (extension property) ─────────────────────
    # Non-standard but valuable for verifiers who want on-chain proof.
    vc["skillchainEvidence"] = {
        "type":        "AlgorandAnchor",
        "network":     ALGO_NETWORK,
        "txId":        tx_id,
        "explorerUrl": f"https://testnet.explorer.perawallet.app/tx/{tx_id}",
        "certHash":    cert_hash,
    }

    return vc


# ── Integration helper: generate + store at registration time ─────────────────

def generate_and_store_did_document(
    did: str,
    institution_name: str,
    domain: str,
    algorand_address: str,
    registered_at: str | None = None,
) -> dict:
    """
    Convenience wrapper called by did_service.register_did() after a DID is created.

    Generates the W3C DID Document and writes it to the did_documents cache table
    so that GET /did/<did> resolves instantly without recomputing.

    Args:
        did:               The newly-created DID string.
        institution_name:  Institution name.
        domain:            Official domain.
        algorand_address:  The institution's Algorand wallet address.
        registered_at:     ISO date of registration (defaults to now).

    Returns:
        The generated DID Document dict.
    """
    document = generate_did_document(
        did=did,
        institution_name=institution_name,
        domain=domain,
        algorand_address=algorand_address,
        registered_at=registered_at,
    )
    store_did_document(did, document)
    log.info("W3C DID Document generated and stored for: %s", did)
    return document


# ── CLI test harness ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Quick offline test — no DB required
    import sys

    # Deterministic test address (Algorand testnet example)
    TEST_ADDRESS = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    TEST_DID = f"did:algo:testnet:{TEST_ADDRESS}:8f3a1c9d24b07e5f"

    print("=== DID Validation ===")
    print(f"valid DID: {is_valid_did(TEST_DID)}")
    print(f"bad DID:   {is_valid_did('did:algo:testnet:tooshort:x')}")

    print("\n=== DID Document ===")
    doc = generate_did_document(
        did=TEST_DID,
        institution_name="IIT Bombay",
        domain="iitb.ac.in",
        algorand_address=TEST_ADDRESS,
        registered_at="2024-01-01T00:00:00Z",
    )
    print(json.dumps(doc, indent=2))

    print("\n=== Verifiable Credential ===")
    vc = build_verifiable_credential(
        issuer_did=TEST_DID,
        holder_identity_did="did:skillchain:identity:abc123def456",
        holder_name="Arjun Sharma",
        cert_hash="a" * 64,
        tx_id="ALGORAND_TX_ID_EXAMPLE",
        doc_type="academic",
        issued_at="2024-06-15T10:30:00Z",
        institution_name="IIT Bombay",
        signature=None,
        cert_number="CS2024-001",
    )
    print(json.dumps(vc, indent=2))