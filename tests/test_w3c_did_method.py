"""Focused coverage for the SkillChain DID method namespace."""

from algosdk import encoding

import did_service
import w3c_did_service as dids


ADDRESS = encoding.encode_address(bytes(range(32)))
IDENTIFIER = "550e8400-e29b-41d4-a716-446655440000"
SKILLCHAIN_DID = dids.build_skillchain_did("testnet", ADDRESS, IDENTIFIER)
# Historical resolver-compatibility fixture; never accepted as a new DID.
LEGACY_DID = f"did:algo:testnet:{ADDRESS}:{IDENTIFIER}"


def test_skillchain_did_validates_and_legacy_did_is_rejected_for_new_validation():
    parsed = dids.parse_did(SKILLCHAIN_DID)

    assert parsed == {
        "network": "testnet",
        "address": ADDRESS,
        "identifier": IDENTIFIER,
    }
    assert dids.is_valid_did(SKILLCHAIN_DID) is True
    assert dids.is_valid_did(LEGACY_DID) is False
    assert dids.is_legacy_did(LEGACY_DID) is True


def test_did_document_references_the_new_did_and_keeps_public_key_behavior():
    document = dids.generate_did_document(
        did=SKILLCHAIN_DID,
        institution_name="SkillChain Test",
        domain="example.test",
        algorand_address=ADDRESS,
        registered_at="2026-08-26T00:00:00Z",
    )
    key_id = f"{SKILLCHAIN_DID}#key-1"

    assert document["id"] == SKILLCHAIN_DID
    assert document["controller"] == SKILLCHAIN_DID
    assert document["verificationMethod"][0]["id"] == key_id
    assert document["verificationMethod"][0]["controller"] == SKILLCHAIN_DID
    assert document["authentication"] == [key_id]
    assert document["assertionMethod"] == [key_id]
    assert document["verificationMethod"][0]["publicKeyMultibase"] == dids._public_key_multibase(ADDRESS)
    assert document["service"][0]["id"].startswith(f"{SKILLCHAIN_DID}#")


def test_historical_did_is_resolvable_without_being_rewritten(monkeypatch):
    cached = {"id": LEGACY_DID, "controller": LEGACY_DID}
    monkeypatch.setattr(dids, "_fetch_from_cache", lambda did: cached if did == LEGACY_DID else None)

    assert dids.resolve_did(LEGACY_DID) == cached


def test_institution_registration_constructs_a_skillchain_did(monkeypatch):
    class Cursor:
        rowcount = 1

        def execute(self, *_args, **_kwargs):
            pass

        def close(self):
            pass

    class Connection:
        def cursor(self):
            return Cursor()

        def commit(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(did_service, "get_db_connection", Connection)
    monkeypatch.setattr(did_service, "generate_api_key", lambda: "test-api-key")
    monkeypatch.setattr(did_service, "_W3C_DID_ENABLED", False)

    result = did_service.register_did(
        "Example Institute",
        institution_address=ADDRESS,
        institution_id="institution-1",
    )

    assert result["did"].startswith(f"did:skillchain:testnet:{ADDRESS}:")
    assert not result["did"].startswith("did:algo:")
