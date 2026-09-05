"""Canonical ``debitChannel`` calldata: derive, decode strictly, re-encode, compare.

Every selector is computed from its signature string at import time, never written down as
a literal — the same discipline (and the same reason) as the hub's
``escrow_bridge.chain.selector``: a hand-copied selector is how the lottery relayer ended
up encoding a function that no longer existed.

The decoder is deliberately unforgiving. A permissive ABI decoder makes every downstream
content check decorative, because two decoders that disagree about the same bytes let an
attacker satisfy the checker with one reading and the chain with another. So: fixed total
length, fixed offset word, fixed length word, zero padding, no trailing bytes — and then
:func:`decode_debit` re-encodes what it read and requires byte equality with the input.
"""

from __future__ import annotations

from dataclasses import dataclass

from eth_utils import keccak

DEBIT_SIG = "debitChannel(bytes32,uint256,bytes32,uint256,bytes)"
SETTLE_SIG = "settleChannel(bytes32)"
GET_CHANNEL_SIG = "getChannel(bytes32)"
USED_RECEIPTS_SIG = "usedReceipts(bytes32)"
AUTHORIZED_HUBS_SIG = "authorizedHubs(address)"
DOMAIN_SEPARATOR_SIG = "domainSeparator()"
DECIMALS_SIG = "decimals()"


def selector(signature: str) -> bytes:
    """First four bytes of keccak(signature). Computed, never hardcoded."""
    return keccak(signature.encode())[:4]


# R8 — the allowed selectors, derived rather than transcribed.
DEBIT_SELECTOR = selector(DEBIT_SIG)

# R27 — `expireChannel(bytes32)`, allowed for one specific reason: it is **permissionless**
# on chain. Anyone may call it after a channel's expiry, and the contract fixes who gets
# paid — `usedAmount` to the bound hub, the remainder to the depositor, with no caller-
# supplied recipient and no amount argument anywhere in the call. So letting this key sign
# it grants no power that an attacker holding any other funded wallet does not already
# have; the only resource at risk is our own gas. That is what makes it a bounded
# extension rather than a second way to move money.
EXPIRE_SIG = "expireChannel(bytes32)"
EXPIRE_SELECTOR = selector(EXPIRE_SIG)
EXPIRE_LEN = 4 + 32

# 4 selector + 5 head words + 1 length word + 65 signature bytes + 31 zero pad.
SIG_LEN = 65
CANONICAL_LEN = 4 + 5 * 32 + 32 + 96
_OFFSET_WORD = 160  # where the dynamic `bytes` tail starts, measured from the head

# secp256k1 group order, and the low-s boundary OpenZeppelin's ECDSA.recover enforces.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_N = SECP256K1_N // 2


class CalldataError(ValueError):
    """Refusal with a stable reason code. Never carries the calldata itself."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        super().__init__(reason_code if not detail else f"{reason_code}: {detail}")
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True)
class DebitCall:
    channel_id: bytes      # 32
    amount: int            # uint256, USDC base units (6 dp)
    receipt_id: bytes      # 32
    deadline: int          # uint256, unix seconds
    signature: bytes       # exactly 65 bytes, the depositor's EIP-712 signature

    @property
    def r(self) -> int:
        return int.from_bytes(self.signature[0:32], "big")

    @property
    def s(self) -> int:
        return int.from_bytes(self.signature[32:64], "big")

    @property
    def v(self) -> int:
        return self.signature[64]

    def redacted(self) -> dict:
        """Everything an operator needs and nothing that is the buyer's signature."""
        return {
            "channel_id": "0x" + self.channel_id.hex(),
            "receipt_id": "0x" + self.receipt_id.hex(),
            "amount_units": self.amount,
            "deadline": self.deadline,
            "signature": f"<{len(self.signature)} bytes>",
        }


def _word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def encode_debit(call: DebitCall) -> bytes:
    """The one encoding this service considers canonical."""
    if len(call.signature) != SIG_LEN:
        raise CalldataError("calldata_length", "signature must be 65 bytes")
    head = (
        call.channel_id
        + _word(call.amount)
        + call.receipt_id
        + _word(call.deadline)
        + _word(_OFFSET_WORD)
    )
    tail = _word(SIG_LEN) + call.signature + bytes(31)
    return DEBIT_SELECTOR + head + tail


def parse_hex_bytes(value: object, *, reason: str) -> bytes:
    """A JSON string that is 0x-prefixed, even-length, lowercase-or-upper hex. Nothing else."""
    if not isinstance(value, str):
        raise CalldataError(reason, "not a string")
    if not value.startswith("0x") or len(value) % 2 != 0:
        raise CalldataError(reason, "not 0x-prefixed even-length hex")
    try:
        return bytes.fromhex(value[2:])
    except ValueError:
        raise CalldataError(reason, "not hex") from None


def decode_debit(data: bytes) -> DebitCall:
    """R7/R8/R9/R10 — strict decode + re-encode-and-compare. Raises :class:`CalldataError` on anything else.

    Order matters: length before selector, because a wrong-length body with the right
    selector is the more interesting attack and we want its reason code to say so.
    """
    if len(data) != CANONICAL_LEN:
        raise CalldataError("calldata_length", f"{len(data)} bytes, expected {CANONICAL_LEN}")
    if data[0:4] != DEBIT_SELECTOR:
        raise CalldataError("selector_not_allowed", "0x" + data[0:4].hex())

    channel_id = data[4:36]
    amount = int.from_bytes(data[36:68], "big")
    receipt_id = data[68:100]
    deadline = int.from_bytes(data[100:132], "big")
    offset = int.from_bytes(data[132:164], "big")
    length = int.from_bytes(data[164:196], "big")
    signature = data[196:261]
    pad = data[261:292]

    if offset != _OFFSET_WORD:
        raise CalldataError("calldata_noncanonical", f"offset word {offset}")
    if length != SIG_LEN:
        raise CalldataError("calldata_length", f"length word {length}")
    if pad != bytes(31):
        raise CalldataError("calldata_noncanonical", "non-zero padding")

    call = DebitCall(channel_id, amount, receipt_id, deadline, signature)
    if encode_debit(call) != data:
        # Unreachable through the checks above, which is the point: it is the assertion
        # that makes every field check above sound rather than parser-dependent.
        raise CalldataError("calldata_noncanonical", "re-encode mismatch")
    return call


class ExpireCall:
    """One channel id. Deliberately not a dataclass shared with DebitCall: an expire has no
    amount, no receipt and no signature, and code that can confuse the two is code that
    could apply the debit rules to a call that has none of the fields they read."""

    __slots__ = ("channel_id",)

    def __init__(self, channel_id: bytes) -> None:
        self.channel_id = channel_id


def encode_expire(call: ExpireCall) -> bytes:
    return EXPIRE_SELECTOR + call.channel_id


def decode_expire(data: bytes) -> ExpireCall:
    """R27 — strict decode + re-encode-and-compare, exactly as the debit path does.

    Length before selector, same as `decode_debit`: a right-selector body of the wrong
    length is the more interesting attack, and its reason code should say so.
    """
    if len(data) != EXPIRE_LEN:
        raise CalldataError("calldata_length", f"{len(data)} bytes, expected {EXPIRE_LEN}")
    if data[0:4] != EXPIRE_SELECTOR:
        raise CalldataError("selector_not_allowed", "0x" + data[0:4].hex())
    call = ExpireCall(data[4:36])
    if encode_expire(call) != data:
        raise CalldataError("calldata_noncanonical", "re-encode mismatch")
    return call


def check_signature_shape(call: DebitCall) -> None:
    """R12 — refuse signatures the contract's ECDSA.recover would revert on.

    OpenZeppelin 5.x reverts ``ECDSAInvalidSignatureS`` above the low-s boundary and
    rejects any ``v`` outside {27, 28}. Refusing here costs nothing; broadcasting instead
    burns gas on a guaranteed revert, and a reverted debit pins the hub's row in SUBMITTED
    forever, which blocks every later nonce on that channel.
    """
    r, s, v = call.r, call.s, call.v
    if not (1 <= r < SECP256K1_N):
        raise CalldataError("signature_malformed", "r out of range")
    if not (1 <= s < SECP256K1_N):
        raise CalldataError("signature_malformed", "s out of range")
    if s > SECP256K1_HALF_N:
        raise CalldataError("signature_malformed", "high-s")
    if v not in (27, 28):
        raise CalldataError("signature_malformed", f"v={v}")
