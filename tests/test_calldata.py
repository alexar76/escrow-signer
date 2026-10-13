"""Calldata: the canonical shape, and every deviation we refuse."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from escrow_signer import calldata as cd

CHANNEL = b"\x02" * 32
RECEIPT = b"\x01" * 32
SIG = bytes(31) + b"\x11" + bytes(31) + b"\x22" + bytes([27])


def canonical(**kw):
    call = cd.DebitCall(kw.get("channel", CHANNEL), kw.get("amount", 10_000),
                        kw.get("receipt", RECEIPT), kw.get("deadline", 1_800_003_600),
                        kw.get("signature", SIG))
    return call, cd.encode_debit(call)


def test_selector_is_derived_not_written_down():
    assert cd.DEBIT_SELECTOR == keccak(cd.DEBIT_SIG.encode())[:4]
    assert cd.DEBIT_SELECTOR.hex() == "f7becd80"


def test_canonical_length_is_292():
    _, data = canonical()
    assert len(data) == cd.CANONICAL_LEN == 292


def test_roundtrip():
    call, data = canonical()
    assert cd.decode_debit(data) == call


def test_trailing_byte_is_refused():
    _, data = canonical()
    with pytest.raises(cd.CalldataError) as exc:
        cd.decode_debit(data + b"\x00")
    assert exc.value.reason_code == "calldata_length"


def test_non_zero_padding_is_refused():
    _, data = canonical()
    tampered = data[:291] + b"\x01"
    with pytest.raises(cd.CalldataError) as exc:
        cd.decode_debit(tampered)
    assert exc.value.reason_code == "calldata_noncanonical"


def test_offset_word_must_be_160():
    _, data = canonical()
    tampered = data[:132] + (192).to_bytes(32, "big") + data[164:]
    with pytest.raises(cd.CalldataError) as exc:
        cd.decode_debit(tampered)
    assert exc.value.reason_code == "calldata_noncanonical"


def test_length_word_must_be_65():
    _, data = canonical()
    tampered = data[:164] + (64).to_bytes(32, "big") + data[196:]
    with pytest.raises(cd.CalldataError) as exc:
        cd.decode_debit(tampered)
    assert exc.value.reason_code == "calldata_length"


def test_compact_64_byte_signature_is_refused():
    """A 260-byte body (pad == 0) is what the hub's own builder would emit for a compact
    signature — and OZ 5.x ECDSA.recover reverts ECDSAInvalidSignatureLength on it. Refusing
    here keeps us from being the instrument of a guaranteed-revert broadcast."""
    call = cd.DebitCall(CHANNEL, 10_000, RECEIPT, 1_800_003_600, SIG)
    head = (call.channel_id + (call.amount).to_bytes(32, "big") + call.receipt_id
            + (call.deadline).to_bytes(32, "big") + (160).to_bytes(32, "big"))
    body = cd.DEBIT_SELECTOR + head + (64).to_bytes(32, "big") + SIG[:64]
    assert len(body) == 260
    with pytest.raises(cd.CalldataError) as exc:
        cd.decode_debit(body)
    assert exc.value.reason_code == "calldata_length"


def test_settle_channel_selector_is_refused():
    body = cd.selector(cd.SETTLE_SIG) + CHANNEL
    with pytest.raises(cd.CalldataError):
        cd.decode_debit(body)


def test_right_selector_wrong_length_reports_length():
    body = cd.DEBIT_SELECTOR + bytes(32)
    with pytest.raises(cd.CalldataError) as exc:
        cd.decode_debit(body)
    assert exc.value.reason_code == "calldata_length"


def test_wrong_selector_at_canonical_length_reports_selector():
    _, data = canonical()
    body = cd.selector("transfer(address,uint256)") + data[4:]
    with pytest.raises(cd.CalldataError) as exc:
        cd.decode_debit(body)
    assert exc.value.reason_code == "selector_not_allowed"


@pytest.mark.parametrize("bad_v", [0, 26, 29, 255])
def test_v_outside_27_28_is_refused(bad_v):
    call = cd.DebitCall(CHANNEL, 10_000, RECEIPT, 1_800_003_600, SIG[:64] + bytes([bad_v]))
    with pytest.raises(cd.CalldataError) as exc:
        cd.check_signature_shape(call)
    assert exc.value.reason_code == "signature_malformed"


def test_high_s_is_refused():
    high_s = (cd.SECP256K1_HALF_N + 1).to_bytes(32, "big")
    call = cd.DebitCall(CHANNEL, 10_000, RECEIPT, 1_800_003_600,
                        SIG[:32] + high_s + bytes([27]))
    with pytest.raises(cd.CalldataError) as exc:
        cd.check_signature_shape(call)
    assert "high-s" in exc.value.detail


def test_zero_r_or_s_is_refused():
    for sig in (bytes(32) + SIG[32:64] + bytes([27]), SIG[:32] + bytes(32) + bytes([27])):
        call = cd.DebitCall(CHANNEL, 10_000, RECEIPT, 1_800_003_600, sig)
        with pytest.raises(cd.CalldataError):
            cd.check_signature_shape(call)


def test_redacted_never_shows_the_signature():
    call, _ = canonical()
    rendered = str(call.redacted())
    assert "65 bytes" in rendered
    assert call.signature.hex()[:16] not in rendered
