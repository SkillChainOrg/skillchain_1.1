from dotenv import load_dotenv
from pathlib import Path

# go to project root where .env exists
env_path = Path(__file__).resolve().parents[5] / ".env"
load_dotenv(env_path)

import os
print("MNEMONIC FOUND:", os.getenv("DEPLOYER_MNEMONIC") is not None)

import logging
import algokit_utils
from algokit_utils import AlgorandClient
from algosdk import mnemonic

logger = logging.getLogger(__name__)


def deploy() -> None:
    from smart_contracts.artifacts.did_registry.did_registry_client import (
        DidRegistryFactory,
    )

    # ✅ Explicitly connect to testnet — bypasses is_localnet() localhost check
    algorand = AlgorandClient.testnet()

    # ✅ Load deployer from mnemonic in .env instead of from_environment()
    deployer_mnemonic = os.environ.get("DEPLOYER_MNEMONIC")
    if not deployer_mnemonic:
        raise ValueError("DEPLOYER_MNEMONIC not set in .env")

    from algosdk import account, mnemonic

    private_key = mnemonic.to_private_key(deployer_mnemonic)
    address = account.address_from_private_key(private_key)

    from algokit_utils import SigningAccount

    deployer_ = SigningAccount(private_key=private_key)
    algorand.account.set_default_signer(deployer_)

    factory = algorand.client.get_typed_app_factory(
        DidRegistryFactory,
        default_sender=deployer_.address
    )

    app_client, result = factory.deploy(
        on_update=algokit_utils.OnUpdate.AppendApp,
        on_schema_break=algokit_utils.OnSchemaBreak.AppendApp,
    )

    print(f"✅ APP_ID: {app_client.app_id}")
    print(f"✅ Deployer address: {deployer_.address}")


if __name__ == "__main__":
    deploy()