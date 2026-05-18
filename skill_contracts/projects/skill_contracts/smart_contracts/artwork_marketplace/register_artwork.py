from pathlib import Path
import os

from dotenv import load_dotenv
from algosdk import abi, account, mnemonic
from algosdk.atomic_transaction_composer import (
    AccountTransactionSigner,
    AtomicTransactionComposer,
)
from algosdk.v2client import algod


env_path = Path(__file__).resolve().parents[5] / ".env"
load_dotenv(env_path)


def main() -> None:
    app_id = int(os.environ["ARTWORK_MARKETPLACE_APP_ID"])
    algod_url = os.getenv("ALGOD_URL", "https://testnet-api.algonode.cloud")
    artwork_id = os.environ["ARTWORK_BOOTSTRAP_ID"]
    creator_did = os.environ["ARTWORK_BOOTSTRAP_CREATOR_DID"]
    initial_owner = os.environ["ARTWORK_BOOTSTRAP_INITIAL_OWNER"]
    price_microalgos = int(os.environ["ARTWORK_BOOTSTRAP_PRICE_MICROALGOS"])

    deployer_mnemonic = os.environ["DEPLOYER_MNEMONIC"]
    private_key = mnemonic.to_private_key(deployer_mnemonic)
    sender = account.address_from_private_key(private_key)
    signer = AccountTransactionSigner(private_key)

    client = algod.AlgodClient("", algod_url)
    method = abi.Method.from_signature(
        "register_artwork(string,string,address,uint64)bool"
    )

    atc = AtomicTransactionComposer()
    atc.add_method_call(
        app_id=app_id,
        method=method,
        sender=sender,
        sp=client.suggested_params(),
        signer=signer,
        method_args=[artwork_id, creator_did, initial_owner, price_microalgos],
        boxes=[
            (0, f"owner:{artwork_id}".encode("utf-8")),
            (0, f"price:{artwork_id}".encode("utf-8")),
            (0, f"creator:{artwork_id}".encode("utf-8")),
        ],
    )
    result = atc.execute(client, 4)
    print(f"REGISTER_TX_ID={result.tx_ids[0]}")


if __name__ == "__main__":
    main()
