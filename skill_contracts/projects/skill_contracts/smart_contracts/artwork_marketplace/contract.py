# Change this import line:
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
    baremethod,
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

    # -------------------------------------------------------
    # FIX 1: Must be decorated so algopy exposes it as the
    # creation entry point. Without this, admin and treasury
    # are never written → acquire() payment check always fails.
    # -------------------------------------------------------
    # Change this decorator:
    @baremethod(create='require')   # WAS: @abimethod(create='require')
    def create(self) -> None:
        self.admin.value = Txn.sender.bytes
        self.treasury.value = Txn.sender.bytes

    def _artwork_key(self, artwork_id: String) -> Bytes:
        """
        Strip the 2-byte ARC4 length prefix from an ARC4 String.

        ARC4 encodes "art_001" (7 chars) as:
            b'\\x00\\x07art_001'

        This returns:
            b'art_001'

        So BoxMap keys resolve to:
            owner:art_001
            price:art_001
            creator:art_001
        """
        return artwork_id.bytes[2:]

    @abimethod
    def register_artwork(
        self,
        artwork_id: String,
        creator_did: String,
        initial_owner: Address,
        price_microalgos: ARC4UInt64,
    ) -> Bool:
        key = self._artwork_key(artwork_id)

        existing_owner = self.artwork_owner.get(
            key,
            default=Bytes(b""),
        )
        assert existing_owner == Bytes(b""), "Artwork already registered"

        # FIX 2: strip ARC4 prefix so creator_did is stored as raw UTF-8,
        # consistent with how artwork_id keys are derived.
        self.artwork_creator_did[key] = creator_did.bytes[2:]
        self.artwork_owner[key] = initial_owner.bytes
        self.artwork_price[key] = price_microalgos.native

        return Bool(True)

    @abimethod
    def get_owner(self, artwork_id: String) -> Address:
        key = self._artwork_key(artwork_id)

        owner = self.artwork_owner.get(
            key,
            default=Bytes(b""),
        )
        assert owner != Bytes(b""), "Artwork not found"

        return Address.from_bytes(owner)

    @abimethod
    def get_price(self, artwork_id: String) -> ARC4UInt64:
        key = self._artwork_key(artwork_id)

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
        key = self._artwork_key(artwork_id)

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

        assert Global.group_size >= UInt64(2), "Grouped payment required"

        assert Txn.group_index > UInt64(0), "Payment must precede app call"

        payment = gtxn.PaymentTransaction(Txn.group_index - UInt64(1))

        treasury_account = Account(self.treasury.value)
        admin_account = Account(self.admin.value)

        assert payment.sender == Txn.sender, "Payment sender mismatch"

        assert (
            payment.receiver == treasury_account
            or payment.receiver == admin_account
        ), "Bad payment receiver"

        assert payment.amount >= price, "Insufficient payment amount"

        self.artwork_owner[key] = Txn.sender.bytes

        return Bool(True)