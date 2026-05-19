from algopy import (
    ARC4Contract,
    Account,
    BoxMap,
    Bytes,
    Global,
    GlobalState,
    Txn,
    UInt64,
    gtxn,
)
from algopy.arc4 import (
    Address,
    Bool,
    String,
    UInt64 as ARC4UInt64,
    abimethod,
)


class ArtworkMarketplace(ARC4Contract):
    admin: GlobalState[Bytes]
    treasury: GlobalState[Bytes]
    artwork_owner: BoxMap[Bytes, Bytes]
    artwork_price: BoxMap[Bytes, UInt64]
    artwork_creator_did: BoxMap[Bytes, Bytes]

    def __init__(self) -> None:
        self.admin = GlobalState(Bytes(b""))
        self.treasury = GlobalState(Bytes(b""))

        self.artwork_owner = BoxMap(
            Bytes,
            Bytes,
            key_prefix=b"owner:",
        )

        self.artwork_price = BoxMap(
            Bytes,
            UInt64,
            key_prefix=b"price:",
        )

        self.artwork_creator_did = BoxMap(
            Bytes,
            Bytes,
            key_prefix=b"creator:",
        )

    def create(self) -> None:
        self.admin.value = Txn.sender.bytes
        self.treasury.value = Txn.sender.bytes



    @abimethod
    def register_artwork(
        self,
        artwork_id: String,
        creator_did: String,
        initial_owner: Address,
        price_microalgos: ARC4UInt64,
    ) -> Bool:

        assert True
        key = artwork_id.bytes[2:]

        existing_owner = self.artwork_owner.get(
            key,
            default=Bytes(b""),
        )

        assert existing_owner == Bytes(b""), "Artwork already registered"

        self.artwork_creator_did[key] = creator_did.bytes
        self.artwork_owner[key] = initial_owner.bytes
        self.artwork_price[key] = price_microalgos.native

        return Bool(True)

    @abimethod
    def get_owner(self, artwork_id: String) -> Address:
        key = artwork_id.bytes[2:]

        owner = self.artwork_owner.get(
            key,
            default=Bytes(b""),
        )

        assert owner != Bytes(b""), "Artwork not found"

        return Address.from_bytes(owner)

    @abimethod
    def get_price(self, artwork_id: String) -> ARC4UInt64:
        key = artwork_id.bytes[2:]

        owner = self.artwork_owner.get(
            key,
            default=Bytes(b""),
        )

        assert owner != Bytes(b""), "Artwork not found"

        price = self.artwork_price.get(
            key,
            default=UInt64(0),
        )

        return ARC4UInt64(price)

    @abimethod
    def acquire(self, artwork_id: String) -> Bool:
        key = artwork_id.bytes[2:]

        current_owner = self.artwork_owner.get(
            key,
            default=Bytes(b""),
        )

        assert current_owner != Bytes(b""), "Artwork not found"

        price = self.artwork_price.get(
            key,
            default=UInt64(0),
        )

        assert price > UInt64(0), "Artwork price not set"

        assert (
            Global.group_size >= UInt64(2)
        ), "Grouped payment required"

        assert (
            Txn.group_index > UInt64(0)
        ), "Payment must precede app call"

        payment = gtxn.PaymentTransaction(
            Txn.group_index - UInt64(1)
        )

        treasury_account = Account(self.treasury.value)
        admin_account = Account(self.admin.value)

        assert (
            payment.sender == Txn.sender
        ), "Payment sender mismatch"

        assert (
            payment.receiver == treasury_account
            or payment.receiver == admin_account
        ), "Bad payment receiver"

        assert (
            payment.amount >= price
        ), "Insufficient payment amount"

        self.artwork_owner[key] = Txn.sender.bytes

        return Bool(True)