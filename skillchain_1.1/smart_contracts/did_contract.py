from algopy import (
    ARC4Contract, BoxMap, Bytes, GlobalState,
    Transaction, arc4, op, subroutine
)
from algopy.arc4 import abimethod, String, Bool


class DIDRegistry(ARC4Contract):
    """
    SkillChain DID Registry — stores institution DID documents
    in Algorand Box Storage. Each institution owns its own box.
    Only the institution's wallet can write to its box.
    """

    admin: GlobalState[Bytes]
    registry: BoxMap[Bytes, Bytes]

    def __init__(self) -> None:
        self.admin = GlobalState(Bytes(b""))
        self.registry = BoxMap(Bytes, Bytes, key_prefix=b"did:")

    @abimethod(create="require")
    def create(self) -> None:
        self.admin.value = Transaction.sender().bytes

    @abimethod
    def register(
        self,
        institution_name: String,
        domain: String,
        public_key: String,
    ) -> Bool:
        sender = Transaction.sender().bytes
        assert not self.registry[sender].exists(), "Already registered"

        did_doc = (
            b'{"v":1,"name":"'
            + institution_name.bytes
            + b'","domain":"'
            + domain.bytes
            + b'","key":"'
            + public_key.bytes
            + b'","status":"active"}'
        )
        self.registry[sender] = Bytes(did_doc)
        return Bool(True)

    @abimethod
    def resolve(self, address: arc4.Address) -> String:
        assert self.registry[address.bytes].exists(), "DID not found"
        return String.from_bytes(self.registry[address.bytes].value)

    @abimethod
    def revoke(self) -> Bool:
        sender = Transaction.sender().bytes
        assert self.registry[sender].exists(), "DID not found"
        assert (
            sender == self.admin.value
            or sender == sender
        ), "Not authorized"
        del self.registry[sender]
        return Bool(True)

    @abimethod
    def is_registered(self, address: arc4.Address) -> Bool:
        return Bool(self.registry[address.bytes].exists())