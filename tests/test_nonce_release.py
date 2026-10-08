"""An account nonce that was never signed goes back to the allocator.

The allocator hands out the hot key's account nonce at RESERVATION, and the simulation runs
after it. When the simulation reverted (or the RPC was down) the row was released `dead`, but
the allocator had already moved past its nonce. Nothing was ever signed at that nonce, so the
chain still expected it, and the next debit was signed one higher: it sat queued in the
mempool, and every debit after it queued behind it. A restart did not help: boot puts the
allocator above every live row, and the queued debits stay live until their deadlines pass.

A row can also be left `reserved` with nobody to release it: the process stops between the
reservation and the signature, or the simulation raises something no handler names. Boot
and every reconcile now release such a row; the request path releases it on the spot.

The opposite mistake is the expensive one: a nonce that ANY signed attempt carried is never
handed out again. A node may know that transaction, and a second one at the same nonce would
replace it or be replaced by it.
"""

from __future__ import annotations

import pytest
from eth_utils import keccak

from conftest import FakeClock, envelope, make_caps, sign_debit
from escrow_signer import config as cfg
from escrow_signer.chainio import RpcUnavailable
from escrow_signer.ledger import Ledger
from test_expire_policy import CHANNEL, collectable_channel, expire_body

FROM = "0x" + "44" * 20
TOKEN = "0x" + "33" * 20


def chain_next(signer) -> int:
    """The nonce the chain expects next: its pending count at boot, plus what we broadcast."""
    return signer.rpc.nonce + len(signer.rpc.sent)


def row_for(signer, decision):
    return signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, decision.receipt_id)


def good_debit(signer, receipt: bytes):
    d = signer.handle(envelope(sign_debit(signer, receipt=receipt)))
    assert d.status == 200, d.reason_code
    return row_for(signer, d)


# ── the gap: a release that never signed ────────────────────────────────────────────────


def test_a_reverted_simulation_gives_its_nonce_back(signer):
    expected = chain_next(signer)
    signer.rpc.simulate_error = "InsufficientBalance"
    refused = signer.handle(envelope(sign_debit(signer, receipt=b"\x0a" * 32)))
    assert refused.reason_code == "simulation_reverted:InsufficientBalance"
    assert row_for(signer, refused).state == "dead"

    signer.rpc.simulate_error = None
    assert good_debit(signer, b"\x0b" * 32).account_nonce == expected, (
        "the next debit skipped the nonce a never-signed reservation was holding")
    # and the sequence stays contiguous after it
    assert good_debit(signer, b"\x0c" * 32).account_nonce == expected + 1


def test_an_unreachable_simulation_gives_its_nonce_back(signer, monkeypatch):
    expected = chain_next(signer)

    def down(*_args):
        raise RpcUnavailable("stub")

    monkeypatch.setattr(signer.rpc, "simulate", down)
    refused = signer.handle(envelope(sign_debit(signer, receipt=b"\x0a" * 32)))
    assert (refused.status, refused.reason_code) == (503, "rpc_unavailable")
    monkeypatch.undo()

    assert good_debit(signer, b"\x0b" * 32).account_nonce == expected


def test_a_failed_signature_gives_its_nonce_back(signer):
    expected = chain_next(signer)
    real = signer.account

    class Broken:
        def sign_transaction(self, _tx):
            raise ValueError("stub")

    signer.account = Broken()
    refused = signer.handle(envelope(sign_debit(signer, receipt=b"\x0a" * 32)))
    assert (refused.status, refused.reason_code) == (500, "signing_failed")
    signer.account = real

    assert good_debit(signer, b"\x0b" * 32).account_nonce == expected


def test_a_reverted_expire_simulation_gives_its_nonce_back(signer, clock):
    """The gas-only door shares the allocator, so it shares the gap."""
    expected = chain_next(signer)
    debit_channel = signer.rpc.channel
    signer.rpc.channel = collectable_channel(signer, clock)
    signer.rpc.simulate_error = "ChannelNotExpired"
    refused = signer.handle(expire_body(signer))
    assert refused.reason_code == "simulation_reverted:ChannelNotExpired"
    pseudo = "0x" + keccak(b"expireChannel|" + CHANNEL).hex()
    assert signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, pseudo).state == "dead"

    signer.rpc.simulate_error = None
    signer.rpc.channel = debit_channel
    assert good_debit(signer, b"\x0b" * 32).account_nonce == expected


def test_a_revived_debit_takes_the_nonce_its_released_attempt_gave_back(signer):
    """The retry of the same receipt is just the next debit: it signs at the chain's nonce."""
    call = sign_debit(signer)
    expected = chain_next(signer)
    signer.rpc.simulate_error = "ChannelExpired"
    signer.handle(envelope(call))
    signer.rpc.simulate_error = None
    d = signer.handle(envelope(call))
    assert d.status == 200, d.reason_code
    assert row_for(signer, d).account_nonce == expected


# ── a reservation nobody released ────────────────────────────────────────────────────────


class Crash(BaseException):
    """The process stopping mid-request: no handler below `BaseException` runs."""


def crash_in_simulation(signer, monkeypatch, error=Crash):
    def boom(*_args):
        raise error("stub")

    monkeypatch.setattr(signer.rpc, "simulate", boom)


def test_a_reservation_orphaned_by_a_crash_is_released_at_boot(signer, monkeypatch):
    expected = chain_next(signer)
    call = sign_debit(signer, receipt=b"\x0a" * 32)
    crash_in_simulation(signer, monkeypatch)
    with pytest.raises(Crash):
        signer.handle(envelope(call))
    monkeypatch.undo()
    orphan = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, "0x" + call.receipt_id.hex())
    assert orphan.state == "reserved"

    signer.boot()
    assert signer.ready
    released = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, orphan.receipt_id)
    assert (released.state, released.dead_reason) == ("dead", "never signed")
    assert good_debit(signer, b"\x0b" * 32).account_nonce == expected, (
        "boot put the allocator above a reservation nothing will ever sign")


def test_the_retry_of_an_orphaned_reservation_is_signed(signer, monkeypatch):
    """No restart: the hub retries the same debit, and the replay path reconciles."""
    expected = chain_next(signer)
    call = sign_debit(signer, receipt=b"\x0a" * 32)
    crash_in_simulation(signer, monkeypatch)
    with pytest.raises(Crash):
        signer.handle(envelope(call))
    monkeypatch.undo()

    retry = signer.handle(envelope(call))
    assert retry.status == 200, f"the orphan kept its receipt hostage: {retry.reason_code}"
    assert row_for(signer, retry).account_nonce == expected


def test_a_revived_reservation_orphaned_by_a_crash_is_released(signer, monkeypatch):
    """The row keeps the attempt record of its first, signed incarnation at nonce 0; the
    orphaned second one, at nonce 1, was never signed and must still be released."""
    call = sign_debit(signer, receipt=b"\x0a" * 32)
    signer.rpc.send_error = "ReplacementUnderpriced"
    first = signer.handle(envelope(call))
    assert row_for(signer, first).state == "dead"
    signer.rpc.send_error = None
    crash_in_simulation(signer, monkeypatch)
    with pytest.raises(Crash):
        signer.handle(envelope(call))
    monkeypatch.undo()
    orphan = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, first.receipt_id)
    assert (orphan.state, orphan.account_nonce) == ("reserved", 1)

    retry = signer.handle(envelope(call))
    assert retry.status == 200, retry.reason_code
    assert row_for(signer, retry).account_nonce == 1


def test_a_row_half_way_through_mark_signed_is_kept(signer, monkeypatch):
    """`signed` without its attempt record: the state write landed, the insert did not. Not
    provably unsigned, so reconcile leaves it to its deadline."""
    call = sign_debit(signer, receipt=b"\x0a" * 32)
    crash_in_simulation(signer, monkeypatch)
    with pytest.raises(Crash):
        signer.handle(envelope(call))
    monkeypatch.undo()
    orphan = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, "0x" + call.receipt_id.hex())
    signer.ledger._set_state(orphan, "signed", tx_hash="0x" + "ab" * 32)
    signer.boot()
    assert signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, orphan.receipt_id).state == "signed"


def test_an_unnamed_simulation_error_releases_the_row_and_its_nonce(signer, monkeypatch):
    expected = chain_next(signer)
    crash_in_simulation(signer, monkeypatch, error=ValueError)
    call = sign_debit(signer, receipt=b"\x0a" * 32)
    with pytest.raises(ValueError):
        signer.handle(envelope(call))
    monkeypatch.undo()
    row = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, "0x" + call.receipt_id.hex())
    assert (row.state, row.dead_reason) == ("dead", "simulation failed: ValueError")
    assert good_debit(signer, b"\x0b" * 32).account_nonce == expected


def test_an_unnamed_expire_simulation_error_releases_the_row_and_its_nonce(
        signer, clock, monkeypatch):
    expected = chain_next(signer)
    debit_channel = signer.rpc.channel
    signer.rpc.channel = collectable_channel(signer, clock)
    crash_in_simulation(signer, monkeypatch, error=ValueError)
    with pytest.raises(ValueError):
        signer.handle(expire_body(signer))
    monkeypatch.undo()
    pseudo = "0x" + keccak(b"expireChannel|" + CHANNEL).hex()
    row = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, pseudo)
    assert (row.state, row.dead_reason) == ("dead", "simulation failed: ValueError")

    signer.rpc.channel = debit_channel
    assert good_debit(signer, b"\x0b" * 32).account_nonce == expected


def test_a_signed_row_is_not_released_as_never_signed(signer):
    """Boot leaves a broadcast-failed row alone: a node may still hold its transaction."""
    signer.rpc.send_error = "unavailable"
    refused = signer.handle(envelope(sign_debit(signer, receipt=b"\x0a" * 32)))
    assert refused.reason_code == "broadcast_failed"
    signer.rpc.send_error = None
    signer.boot()
    assert row_for(signer, refused).state == "signed"


# ── never reuse a signed nonce ───────────────────────────────────────────────────────────


def test_a_rejected_broadcast_keeps_its_nonce_spent(signer):
    """The node said no, but the transaction was signed and handed to it: another node of the
    pool may hold it. The row is released, and its nonce stays consumed."""
    signer.rpc.send_error = "ReplacementUnderpriced"
    refused = signer.handle(envelope(sign_debit(signer, receipt=b"\x0a" * 32)))
    assert refused.reason_code == "simulation_reverted:ReplacementUnderpriced"
    dead = row_for(signer, refused)
    assert dead.state == "dead"
    assert signer.ledger.attempts_for(cfg.CHAIN_ID, cfg.ESCROW, dead.receipt_id)

    signer.rpc.send_error = None
    assert good_debit(signer, b"\x0b" * 32).account_nonce == dead.account_nonce + 1


# ── the ledger's own guards, one at a time ───────────────────────────────────────────────


def _ledger(tmp_path) -> Ledger:
    return Ledger(str(tmp_path / "signer.db"), clock=FakeClock())


def _reserve(ledger: Ledger, i: int):
    return ledger.reserve(
        caps=make_caps(), chain_id=cfg.CHAIN_ID, escrow=cfg.ESCROW,
        receipt_id="0x" + f"{i:064x}", channel_id="0x" + f"{i:064x}",
        depositor=FROM, token=TOKEN, amount_units=10_000, deadline=2_000_000_000,
        channel_nonce=0, calldata_keccak="0x" + "55" * 32, to_addr=cfg.ESCROW,
        gas_limit=200_000, hub_gas_hint=200_000, max_fee_wei=10, from_addr=FROM)


def test_only_the_most_recently_allocated_nonce_is_given_back(tmp_path):
    """A has 0, B holds 1. Rewinding to 0 on A's release would hand 1 out a second time."""
    ledger = _ledger(tmp_path)
    a, b = _reserve(ledger, 1), _reserve(ledger, 2)
    assert (a.account_nonce, b.account_nonce) == (0, 1)
    ledger.mark_dead(a, "simulation reverted: X")
    assert _reserve(ledger, 3).account_nonce == 2


def test_a_row_already_signed_is_not_rewound_from_a_stale_snapshot(tmp_path):
    """The debit path releases a rejected broadcast with the row object `reserve` returned,
    whose `state` still reads 'reserved'. The ledger must read the state it actually holds."""
    ledger = _ledger(tmp_path)
    snapshot = _reserve(ledger, 1)
    ledger._set_state(snapshot, "signed", tx_hash="0x" + "ab" * 32)  # no attempt row yet
    assert snapshot.state == "reserved"
    ledger.mark_dead(snapshot, "broadcast rejected: X")
    assert _reserve(ledger, 2).account_nonce == snapshot.account_nonce + 1


def test_a_nonce_any_signed_attempt_carried_is_never_given_back(tmp_path):
    """Whatever the row's state says, an attempt record at this nonce means the key signed it."""
    ledger = _ledger(tmp_path)
    row = _reserve(ledger, 1)
    seq, ts = ledger.tick()
    ledger.db.execute(
        "INSERT INTO tx_attempt(tx_hash, chain_id, escrow, receipt_id, account_nonce,"
        " raw_keccak, max_fee_wei, sent_at, seq) VALUES (?,?,?,?,?,?,?,?,?)",
        ("0x" + "cd" * 32, cfg.CHAIN_ID, cfg.ESCROW, "0x" + "ee" * 32, row.account_nonce,
         "0x" + "cd" * 32, 10, ts, seq))
    ledger.mark_dead(row, "simulation reverted: X")
    assert _reserve(ledger, 2).account_nonce == row.account_nonce + 1


def test_the_books_still_verify_after_a_rewind(tmp_path):
    ledger = _ledger(tmp_path)
    row = _reserve(ledger, 1)
    ledger.mark_dead(row, "simulation reverted: X")
    again = _reserve(ledger, 2)
    assert again.account_nonce == row.account_nonce
    ledger.verify_chains()
