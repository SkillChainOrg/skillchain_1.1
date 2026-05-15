import hashlib
import io
import json
import os
import sys
import types

from PIL import Image


_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_TESTS_DIR)
sys.path.insert(0, _PROJECT_DIR)

os.environ.setdefault("DATABASE_URL", "postgresql://fake/fake")
os.environ.setdefault("HMAC_SECRET", "test-hmac-secret")
os.environ.setdefault("KEY_ENCRYPTION_KEY", "a" * 64)
os.environ.setdefault("VAULT_ENABLED", "false")
os.environ.setdefault("DEMO_MODE", "true")

import algorand_service


def _make_jpeg_bytes() -> bytes:
    image = Image.new("RGB", (12, 12), color=(180, 120, 45))
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG")
    return buffer.getvalue()


def _normalize_and_hash(file_bytes: bytes) -> str:
    image = Image.open(io.BytesIO(file_bytes))
    exif = image.getexif()
    exif.clear()
    image = image.convert("RGB")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return hashlib.sha256(buffer.getvalue()).hexdigest()


class _FakeCursor:
    def __init__(self, row):
        self._row = row

    def execute(self, *_args, **_kwargs):
        return None

    def fetchone(self):
        return self._row

    def close(self):
        return None


class _FakeConnection:
    def close(self):
        return None


def _patch_verification_dependencies(monkeypatch, *, cert_hash: str, integrity_hash: str, signature_verified: bool):
    monkeypatch.setattr(
        algorand_service,
        "lookup_hash",
        lambda _cert_hash: {"tx_id": "T" * 52, "ipfs_cid": "cid123"},
    )
    monkeypatch.setattr(algorand_service, "is_valid_txid", lambda _tx_id: True)
    monkeypatch.setattr(
        algorand_service,
        "_txn_from_indexer",
        lambda _tx_id: {
            "id": "T" * 52,
            "note": json.dumps({"cid": "cid123", "wv": 2}),
            "sender": "ADDR123",
            "confirmed-round": 77,
        },
    )
    monkeypatch.setattr(
        algorand_service,
        "fetch_certificate_metadata",
        lambda _cid: {
            "cert_hash": cert_hash,
            "integrity_hash": integrity_hash,
            "signature": "sig",
            "hmac_value": "expected-hmac",
            "doc_type": "artwork",
            "issued_at": "2026-05-15",
            "artisan_did": "did:algo:testnet:ADDR123:artisan",
            "artisan": "Test Artisan",
        },
    )
    monkeypatch.setattr(algorand_service, "generate_hmac", lambda _cert_hash: "expected-hmac")
    monkeypatch.setattr(algorand_service, "get_db_connection", lambda: _FakeConnection())
    monkeypatch.setattr(
        algorand_service,
        "dict_cursor",
        lambda _conn: _FakeCursor({"wallet_version": 2, "revoked": 0, "institution_id": "inst-1"}),
    )
    monkeypatch.setitem(
        sys.modules,
        "did_service",
        types.SimpleNamespace(
            verify_provenance=lambda *_args, **_kwargs: {"verified": signature_verified}
        ),
    )


def test_appended_bytes_fail_integrity_verification(monkeypatch):
    original_bytes = _make_jpeg_bytes()
    tampered_bytes = original_bytes + (b"\x00" * 10)

    original_cert_hash = _normalize_and_hash(original_bytes)
    tampered_cert_hash = _normalize_and_hash(tampered_bytes)

    assert tampered_cert_hash == original_cert_hash

    original_integrity_hash = hashlib.sha256(original_bytes).hexdigest()
    tampered_integrity_hash = hashlib.sha256(tampered_bytes).hexdigest()

    _patch_verification_dependencies(
        monkeypatch,
        cert_hash=original_cert_hash,
        integrity_hash=original_integrity_hash,
        signature_verified=True,
    )

    result = algorand_service.verify_hash(
        tampered_cert_hash,
        uploaded_integrity_hash=tampered_integrity_hash,
    )

    assert result["valid"] is False
    assert result["integrity_hash_match"] is False
    assert result["tampered_detected"] is True
    assert result["signature_valid"] is True
    assert result["provenance_valid"] is True


def test_verification_succeeds_only_when_integrity_and_signature_match(monkeypatch):
    original_bytes = _make_jpeg_bytes()
    cert_hash = _normalize_and_hash(original_bytes)
    integrity_hash = hashlib.sha256(original_bytes).hexdigest()

    _patch_verification_dependencies(
        monkeypatch,
        cert_hash=cert_hash,
        integrity_hash=integrity_hash,
        signature_verified=True,
    )

    result = algorand_service.verify_hash(
        cert_hash,
        uploaded_integrity_hash=integrity_hash,
    )

    assert result["valid"] is True
    assert result["verified"] is True
    assert result["integrity_hash_match"] is True
    assert result["tampered_detected"] is False
    assert result["signature_valid"] is True


def test_signature_failure_keeps_verification_invalid_even_when_integrity_matches(monkeypatch):
    original_bytes = _make_jpeg_bytes()
    cert_hash = _normalize_and_hash(original_bytes)
    integrity_hash = hashlib.sha256(original_bytes).hexdigest()

    _patch_verification_dependencies(
        monkeypatch,
        cert_hash=cert_hash,
        integrity_hash=integrity_hash,
        signature_verified=False,
    )

    result = algorand_service.verify_hash(
        cert_hash,
        uploaded_integrity_hash=integrity_hash,
    )

    assert result["integrity_hash_match"] is True
    assert result["signature_valid"] is False
    assert result["provenance_valid"] is False
    assert result["valid"] is False
