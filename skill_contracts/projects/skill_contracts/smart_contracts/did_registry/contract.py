from algopy import ARC4Contract, BoxMap, Bytes, GlobalState, Txn
from algopy.arc4 import abimethod, String, Bool, Address


class DIDRegistry(ARC4Contract):

    admin: GlobalState[Bytes]
    registry: BoxMap[Bytes, Bytes]

    def __init__(self) -> None:
        self.admin = GlobalState(Bytes(b""))
        self.registry = BoxMap(Bytes, Bytes, key_prefix=b"did:")

    def create(self) -> None:
     self.admin.value = Txn.sender.bytes 
    
    @abimethod
    def register(
        self,
        institution_name: String,
        domain: String,
        public_key: String,
    ) -> Bool:

        sender = Txn.sender.bytes  # ✅ FIX

        existing = self.registry.get(sender, default=Bytes(b""))
        assert existing == Bytes(b""), "Already registered"

        did_doc = (
            b'{"v":1,"name":"'
            + institution_name.bytes
            + b'","domain":"'
            + domain.bytes
            + b'","key":"'
            + public_key.bytes
            + b'","status":"active"}'
        )

        self.registry[sender] = did_doc
        return Bool(True)

    @abimethod
    def resolve(self, address: Address) -> String:
        value = self.registry.get(address.bytes, default=Bytes(b""))
        assert value != Bytes(b""), "DID not found"
        return String.from_bytes(value)

    @abimethod
    def revoke(self) -> Bool:
        sender = Txn.sender.bytes  # ✅ FIX

        value = self.registry.get(sender, default=Bytes(b""))
        assert value != Bytes(b""), "DID not found"

        assert sender == self.admin.value, "Not authorized"

        del self.registry[sender]
        return Bool(True)

    @abimethod
    def is_registered(self, address: Address) -> Bool:
        value = self.registry.get(address.bytes, default=Bytes(b""))
        return Bool(value != Bytes(b""))