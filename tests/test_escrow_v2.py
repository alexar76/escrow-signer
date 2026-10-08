"""AIMarketEscrowV2 changes three facts this service reads from chain, and the signer must
read all three right before the pinned escrow can move to V2 — while still serving V1.

* ``getChannel`` returns ten words: ``closableAt`` sits before ``status``.
* Receipts are keyed per channel. ``usedReceipts(receiptId)`` on V2 is a lookup under the
  wrong key and answers "unused" for every receipt — the answer that signs a second
  collection. The question is ``isReceiptUsed(channelId, receiptId)``; V1 lacks it and
  reverts, which is the one case that falls back. An outage never does.
* The hub keeps ``SETTLE_WINDOW`` past ``expiresAt`` to land what it earned, and
  ``expireChannel`` reverts until that window is over.
"""

from __future__ import annotations

import pytest

from conftest import DEPOSITOR, envelope, sign_debit
from escrow_signer import calldata as cd
from escrow_signer import config as cfg
from escrow_signer.chainio import Channel, Reverted, RpcPool, RpcUnavailable
from test_expire_policy import collectable_channel, expire_body

CHANNEL = b"\x02" * 32
RECEIPT = b"\x01" * 32


def _word(value) -> bytes:
    if isinstance(value, str):
        return bytes(12) + bytes.fromhex(value[2:])
    return int(value).to_bytes(32, "big")


class ScriptedPool(RpcPool):
    """An RpcPool whose eth_call answers from a table keyed by selector."""

    def __init__(self, answers):
        super().__init__(("http://stub",))
        self.answers = answers
        self.calls = []

    def eth_call(self, to, data, *, sender=""):
        sel = data[:4]
        self.calls.append((sel, data[4:]))
        answer = self.answers.get(sel)
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise Reverted("unknown_revert")      # a selector the contract does not have
        return answer


def _channel_words(*, v2: bool, closable_at: int = 0, status: int = 0) -> bytes:
    head = [_word(DEPOSITOR.address), _word("0x" + "44" * 20), _word(cfg.TOKEN),
            _word(1_000_000), _word(990_000), _word(10_000), _word(1_800_000_000), _word(3)]
    tail = [_word(closable_at), _word(status)] if v2 else [_word(status)]
    return b"".join(head + tail)


GET_CHANNEL = cd.selector(cd.GET_CHANNEL_SIG)
IS_RECEIPT_USED = cd.selector(cd.IS_RECEIPT_USED_SIG)
USED_RECEIPTS = cd.selector(cd.USED_RECEIPTS_SIG)
SETTLE_WINDOW = cd.selector(cd.SETTLE_WINDOW_SIG)


# ── decoding ─────────────────────────────────────────────────────────────────────────────

def test_a_v2_channel_decodes_closable_at_and_status():
    pool = ScriptedPool({GET_CHANNEL: _channel_words(v2=True, closable_at=1_799_000_000, status=0)})
    ch = pool.get_channel(cfg.ESCROW, CHANNEL)
    assert ch.v2 is True
    assert ch.closable_at == 1_799_000_000
    assert ch.status == 0 and ch.is_open
    assert ch.nonce == 3 and ch.expires_at == 1_800_000_000


def test_a_v1_channel_is_marked_v1():
    pool = ScriptedPool({GET_CHANNEL: _channel_words(v2=False, status=1)})
    ch = pool.get_channel(cfg.ESCROW, CHANNEL)
    assert (ch.v2, ch.closable_at, ch.status) == (False, 0, 1)


# ── receipts ─────────────────────────────────────────────────────────────────────────────

def test_v2_receipts_are_asked_per_channel():
    pool = ScriptedPool({IS_RECEIPT_USED: _word(1), USED_RECEIPTS: _word(0)})
    assert pool.receipt_used(cfg.ESCROW, RECEIPT, channel_id=CHANNEL) is True
    sel, args = pool.calls[0]
    assert sel == IS_RECEIPT_USED and args == CHANNEL + RECEIPT


def test_v1_falls_back_to_used_receipts_when_the_selector_reverts():
    pool = ScriptedPool({USED_RECEIPTS: _word(1)})
    assert pool.receipt_used(cfg.ESCROW, RECEIPT, channel_id=CHANNEL) is True
    assert [sel for sel, _ in pool.calls] == [IS_RECEIPT_USED, SETTLE_WINDOW, USED_RECEIPTS]


def test_a_spurious_revert_on_v2_never_falls_back():
    pool = ScriptedPool({IS_RECEIPT_USED: Reverted("unknown_revert"), SETTLE_WINDOW: _word(3600),
                         USED_RECEIPTS: _word(0)})
    with pytest.raises(RpcUnavailable):
        pool.receipt_used(cfg.ESCROW, RECEIPT, channel_id=CHANNEL)
    assert USED_RECEIPTS not in [sel for sel, _ in pool.calls]
    # Not remembered as V1: the next read asks the V2 question again.
    pool.answers[IS_RECEIPT_USED] = _word(1)
    assert pool.receipt_used(cfg.ESCROW, RECEIPT, channel_id=CHANNEL) is True


def test_v1_is_learned_once_per_escrow():
    pool = ScriptedPool({USED_RECEIPTS: _word(0)})
    for _ in range(3):
        pool.receipt_used(cfg.ESCROW, RECEIPT, channel_id=CHANNEL)
    assert [sel for sel, _ in pool.calls].count(IS_RECEIPT_USED) == 1


def test_an_outage_never_falls_back_to_the_v1_question():
    """On V2 `usedReceipts(receiptId)` answers "unused" for everything."""
    pool = ScriptedPool({IS_RECEIPT_USED: RpcUnavailable("timeout"), USED_RECEIPTS: _word(0)})
    with pytest.raises(RpcUnavailable):
        pool.receipt_used(cfg.ESCROW, RECEIPT, channel_id=CHANNEL)
    assert USED_RECEIPTS not in [sel for sel, _ in pool.calls]


def test_without_a_channel_the_v1_question_is_asked():
    pool = ScriptedPool({USED_RECEIPTS: _word(0)})
    assert pool.receipt_used(cfg.ESCROW, RECEIPT) is False
    assert [sel for sel, _ in pool.calls] == [USED_RECEIPTS]


# ── the policy passes the channel ────────────────────────────────────────────────────────

def test_the_debit_path_asks_about_the_receipt_on_its_channel(signer):
    call = sign_debit(signer, channel=CHANNEL, receipt=RECEIPT)
    assert signer.handle(envelope(call)).status == 200
    assert ("0x" + RECEIPT.hex(), CHANNEL) in signer.rpc.receipt_checks


def test_reconcile_asks_about_each_row_on_its_channel(signer):
    call = sign_debit(signer, channel=CHANNEL, receipt=RECEIPT)
    assert signer.handle(envelope(call)).status == 200
    signer.rpc.receipt_checks.clear()
    signer.boot()
    assert ("0x" + RECEIPT.hex(), CHANNEL) in signer.rpc.receipt_checks


# ── the settle window ────────────────────────────────────────────────────────────────────

def _v2(channel: Channel, **changes) -> Channel:
    values = dict(channel.__dict__)
    values.update(changes, v2=True)
    return Channel(**values)


def test_v2_debits_land_inside_the_window_after_expiry(signer, clock):
    signer.rpc.channel = _v2(signer.rpc.channel, expires_at=int(clock()) - 600)
    d = signer.handle(envelope(sign_debit(signer)))
    assert d.status == 200, d.reason_code


def test_v2_debits_stop_before_the_window_closes(signer, clock):
    end = int(clock()) + cfg.CHANNEL_MIN_REMAINING_S - 1
    signer.rpc.channel = _v2(signer.rpc.channel, expires_at=end - cfg.ESCROW_V2_SETTLE_WINDOW_S)
    d = signer.handle(envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (422, "channel_expiring")


def test_v1_debits_still_stop_at_expiry(signer, clock):
    c = signer.rpc.channel
    signer.rpc.channel = Channel(**{**c.__dict__, "expires_at": int(clock()) - 600})
    d = signer.handle(envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (422, "channel_expiring")


def test_v2_expiry_waits_out_the_window(signer, clock):
    signer.rpc.channel = _v2(collectable_channel(signer, clock),
                             expires_at=int(clock()) - cfg.ESCROW_V2_SETTLE_WINDOW_S)
    d = signer.handle(expire_body(signer))
    assert (d.status, d.reason_code) == (422, "channel_not_expired")
    assert signer.rpc.sent == []


def test_v2_expiry_is_signed_once_the_window_is_over(signer, clock):
    signer.rpc.channel = _v2(collectable_channel(signer, clock),
                             expires_at=int(clock()) - cfg.ESCROW_V2_SETTLE_WINDOW_S - 1)
    d = signer.handle(expire_body(signer))
    assert d.status == 200, d.reason_code
