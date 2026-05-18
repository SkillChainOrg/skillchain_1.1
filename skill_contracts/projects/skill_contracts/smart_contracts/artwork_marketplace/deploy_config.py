from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parents[5] / ".env"
load_dotenv(env_path)

import os
import logging
import algokit_utils
from algokit_utils import AlgorandClient, SigningAccount
from algosdk import account, mnemonic

logger = logging.getLogger(__name__)


def deploy() -> None:
    from smart_contracts.artifacts.artwork_marketplace.artwork_marketplace_client import (
        ArtworkMarketplaceFactory,
    )

    algorand = AlgorandClient.testnet()

    deployer_mnemonic = os.environ.get("DEPLOYER_MNEMONIC")
    if not deployer_mnemonic:
        raise ValueError("DEPLOYER_MNEMONIC not set in .env")

    private_key = mnemonic.to_private_key(deployer_mnemonic)
    address = account.address_from_private_key(private_key)

    deployer = SigningAccount(private_key=private_key)
    algorand.account.set_default_signer(deployer)

    factory = algorand.client.get_typed_app_factory(
        ArtworkMarketplaceFactory,
        default_sender=deployer.address,
    )

    app_client, _ = factory.deploy(
        on_update=algokit_utils.OnUpdate.AppendApp,
        on_schema_break=algokit_utils.OnSchemaBreak.AppendApp,
    )

    print(f"APP_ID={app_client.app_id}")
    print(f"TREASURY_ADDRESS={address}")


if __name__ == "__main__":
    deploy()
