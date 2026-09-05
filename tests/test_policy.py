"""The refusal table. Each case asserts the status, the reason code, and — the part that
actually matters — that nothing was signed and nothing was broadcast."""

from __future__ import annotations

import json

import pytest
from eth_account import Account

from conftest import (DEPOSITOR, HOT, OUTSIDER, ZERO, envelope, sign_debit)
from escrow_signer import calldata as cd
from escrow_signer import config as cfg
from escrow_signer.chainio import Channel

# ── helpers ───────────────────────────────────────────────────────────────────────


def post(signer, body):
    return signer.handle(body)


def assert_nothing_sent(signer):
    assert signer.rpc.sent == [], f"a transaction was broadcast: {signer.rpc.sent}"


def assert_no_budget_moved(signer):
    assert signer.ledger.window_units(cfg.CHAIN_ID, cfg.ESCROW, cfg.TOKEN.lower(), 0) == 0


# ── envelope ──────────────────────────────────────────────────────────────────────


def test_value_not_zero(signer):
    call = sign_debit(signer)
    d = post(signer, envelope(call, value=1))
    assert (d.status, d.reason_code) == (422, "value_not_zero")
    assert d.alarm
    assert_nothing_sent(signer)


@pytest.mark.parametrize("chain_id", [84532, 1, 0])
def test_wrong_chain(signer, chain_id):
    d = post(signer, envelope(sign_debit(signer), chain_id=chain_id))
    assert (d.status, d.reason_code) == (422, "wrong_chain")
    assert_nothing_sent(signer)


def test_to_is_usdc_with_a_transfer(signer):
    """The drain attempt: right shape, wrong destination."""
    data = "0x" + (cd.selector("transfer(address,uint256)")
                   + bytes(12) + bytes.fromhex(OUTSIDER.address[2:])
                   + (5_000_000_000).to_bytes(32, "big")).hex()
    d = post(signer, envelope(sign_debit(signer), to=cfg.TOKEN, data=data))
    assert (d.status, d.reason_code) == (422, "to_not_escrow")
    assert d.alarm
    assert_nothing_sent(signer)


@pytest.mark.parametrize("to", ["", "0x", "0xdeadbeef", "0x" + "11" * 21])
def test_absent_short_or_long_to(signer, to):
    d = post(signer, envelope(sign_debit(signer), to=to))
    assert (d.status, d.reason_code) == (422, "to_not_escrow")
    assert_nothing_sent(signer)


def test_escrow_admin_call_is_refused(signer):
    """setHubAuthorization to the pinned escrow — the escalation this service exists to stop."""
    data = "0x" + (cd.selector("setHubAuthorization(address,bool)")
                   + bytes(12) + bytes.fromhex(OUTSIDER.address[2:])
                   + (1).to_bytes(32, "big")).hex()
    d = post(signer, envelope(sign_debit(signer), data=data))
    assert d.status == 422
    assert d.reason_code in ("selector_not_allowed", "calldata_length")
    assert_nothing_sent(signer)


def test_settle_channel_is_refused(signer):
    data = "0x" + (cd.selector(cd.SETTLE_SIG) + b"\x02" * 32).hex()
    d = post(signer, envelope(sign_debit(signer), data=data))
    assert d.status == 422
    assert_nothing_sent(signer)


@pytest.mark.parametrize("body", [
    b"[]", b"{}", b'{"transaction": {}}', b'{"transaction": 1}', b"not json",
    b'{"transaction": {"to":"0x00","data":"0x00","chainId":8453,"gas":1,"value":0,"from":"0x1"}}',
    b'{"transaction": {"to":"0x00","data":"0x00","chainId":8453,"gas":1,"value":0,"nonce":7}}',
    b'{"transaction": {"to":"0x00","data":"0x00","chainId":"0x2105","gas":1,"value":0}}',
    b'{"transaction": {"to":"0x00","data":"0x00","chainId":8453,"gas":true,"value":0}}',
    b'{"transaction": {"to":"0x00","data":"0x00","chainId":8453,"value":0}}',
])
def test_envelope_violations(signer, body):
    d = post(signer, body)
    assert d.status == 400, (body, d.reason_code)
    assert_nothing_sent(signer)


def test_float_gas_is_refused(signer):
    call = sign_debit(signer)
    body = json.loads(envelope(call))
    body["transaction"]["gas"] = 312500.0
    d = post(signer, json.dumps(body).encode())
    assert d.status == 400
    assert_nothing_sent(signer)


# ── calldata content ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("amount,expected", [
    (0, "amount_out_of_band"),
    (10_001, "amount_out_of_band"),
    (160, "amount_out_of_band"),
    (65, "amount_out_of_band"),
    (10_000_000_001, "amount_out_of_band"),
])
def test_amount_band(signer, amount, expected):
    call = sign_debit(signer, amount=max(amount, 0))
    call = cd.DebitCall(call.channel_id, amount, call.receipt_id, call.deadline, call.signature)
    d = post(signer, envelope(call))
    assert (d.status, d.reason_code) == (422, expected), amount
    assert_nothing_sent(signer)


def test_zero_receipt_and_channel(signer):
    call = sign_debit(signer, receipt=bytes(32))
    d = post(signer, envelope(call))
    assert (d.status, d.reason_code) == (422, "receipt_id_zero")
    call = sign_debit(signer, channel=bytes(32))
    d = post(signer, envelope(call))
    assert (d.status, d.reason_code) == (422, "channel_id_zero")
    assert_nothing_sent(signer)


@pytest.mark.parametrize("delta", [-1, -3600, 30, 86_401, 200_000])
def test_deadline_band(signer, clock, delta):
    call = sign_debit(signer, deadline=int(clock()) + delta)
    d = post(signer, envelope(call))
    assert (d.status, d.reason_code) == (422, "deadline_out_of_band"), delta
    assert_nothing_sent(signer)


def test_hub_gas_hint_above_the_cap_is_a_tamper_signal(signer):
    d = post(signer, envelope(sign_debit(signer), gas=30_000_000))
    assert (d.status, d.reason_code) == (422, "hub_gas_anomalous")
    assert d.alarm
    assert_nothing_sent(signer)


# ── chain state ───────────────────────────────────────────────────────────────────


def test_channel_not_found(signer):
    signer.rpc.channel = Channel(ZERO, ZERO, cfg.TOKEN, 0, 0, 0, 0, 0, 0)
    d = post(signer, envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (422, "channel_not_found")
    assert_nothing_sent(signer)


def test_channel_not_open(signer, clock):
    c = signer.rpc.channel
    signer.rpc.channel = Channel(c.depositor, c.hub, c.token, c.deposit_amount, c.balance,
                                 c.used_amount, c.expires_at, c.nonce, 1)
    d = post(signer, envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (422, "channel_not_open")


def test_channel_expiring(signer, clock):
    c = signer.rpc.channel
    signer.rpc.channel = Channel(c.depositor, c.hub, c.token, c.deposit_amount, c.balance,
                                 c.used_amount, int(clock()) + 10, c.nonce, 0)
    d = post(signer, envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (422, "channel_expiring")


def test_insufficient_balance(signer):
    c = signer.rpc.channel
    signer.rpc.channel = Channel(c.depositor, c.hub, c.token, c.deposit_amount, 5_000,
                                 c.used_amount, c.expires_at, c.nonce, 0)
    d = post(signer, envelope(sign_debit(signer, amount=10_000)))
    assert (d.status, d.reason_code) == (422, "insufficient_balance")


def test_token_not_allowed(signer):
    """A whitelisted 6-decimal impostor: the contract's gate checks decimals, not worth."""
    c = signer.rpc.channel
    impostor = "0x" + "ab" * 20
    signer.rpc.channel = Channel(c.depositor, c.hub, impostor, c.deposit_amount, c.balance,
                                 c.used_amount, c.expires_at, c.nonce, 0)
    d = post(signer, envelope(sign_debit(signer, token=impostor)))
    assert (d.status, d.reason_code) == (422, "token_not_allowed")
    assert_nothing_sent(signer)


def test_channel_bound_to_another_hub(signer):
    c = signer.rpc.channel
    signer.rpc.channel = Channel(c.depositor, OUTSIDER.address, c.token, c.deposit_amount,
                                 c.balance, c.used_amount, c.expires_at, c.nonce, 0)
    d = post(signer, envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (422, "channel_bound_elsewhere")


def test_receipt_already_used_by_someone_else(signer):
    call = sign_debit(signer)
    signer.rpc.receipt_flags["0x" + call.receipt_id.hex()] = True
    d = post(signer, envelope(call))
    assert (d.status, d.reason_code) == (422, "receipt_already_used")
    assert_nothing_sent(signer)


def test_not_an_authorized_hub_refuses_everything(signer):
    signer.rpc.authorized = False
    signer._chain_ok_until = 0
    d = post(signer, envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (503, "chain_unverified")
    assert_nothing_sent(signer)


def test_rpc_reports_a_different_chain(signer):
    signer.rpc.chain = 84532
    signer._chain_ok_until = 0
    d = post(signer, envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (503, "chain_unverified")


def test_domain_separator_mismatch(signer):
    signer.rpc.separator = bytes(32)
    signer._chain_ok_until = 0
    d = post(signer, envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (503, "chain_unverified")


# ── the signature is the authority ────────────────────────────────────────────────


def test_signature_from_someone_who_is_not_the_depositor(signer):
    call = sign_debit(signer, depositor=OUTSIDER)
    d = post(signer, envelope(call))
    assert (d.status, d.reason_code) == (422, "signature_not_depositor")
    assert_nothing_sent(signer)


def test_signature_minted_for_a_different_hub(signer):
    """R16 substitutes OUR address for `hub`, so a signature for hub A cannot be used here."""
    call = sign_debit(signer, hub=OUTSIDER.address)
    d = post(signer, envelope(call))
    assert (d.status, d.reason_code) == (422, "signature_not_depositor")
    assert_nothing_sent(signer)


def test_signature_at_a_stale_channel_nonce(signer):
    call = sign_debit(signer, nonce=7)  # chain says nonce 0
    d = post(signer, envelope(call))
    assert (d.status, d.reason_code) == (422, "signature_not_depositor")


def test_amount_changed_after_signing(signer):
    """The hub asks for more than the buyer signed for."""
    call = sign_debit(signer, amount=10_000)
    tampered = cd.DebitCall(call.channel_id, 1_000_000, call.receipt_id, call.deadline,
                            call.signature)
    d = post(signer, envelope(tampered))
    assert (d.status, d.reason_code) == (422, "signature_not_depositor")
    assert_nothing_sent(signer)


# ── gas, fees, simulation ─────────────────────────────────────────────────────────


def test_own_estimate_over_the_cap(signer):
    signer.rpc.estimate_value = 500_000
    d = post(signer, envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (422, "gas_estimate_over_cap")
    assert_nothing_sent(signer)


def test_fee_ceiling(signer):
    signer.rpc.base_fee = 10 ** 12
    d = post(signer, envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (503, "fee_ceiling")
    assert_nothing_sent(signer)


def test_simulation_revert_releases_the_reservation(signer):
    signer.rpc.simulate_error = "InsufficientBalance"
    d = post(signer, envelope(sign_debit(signer)))
    assert d.status == 422 and d.reason_code == "simulation_reverted:InsufficientBalance"
    assert_nothing_sent(signer)
    row = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, d.receipt_id)
    assert row.state == "dead"
    assert_no_budget_moved(signer)


def test_the_hub_gas_hint_is_never_used_for_signing(signer):
    signer.rpc.estimate_value = 120_000
    d = post(signer, envelope(sign_debit(signer), gas=399_999))
    assert d.status == 200
    row = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, d.receipt_id)
    assert row.gas_limit == 120_000 * 5 // 4
    assert row.hub_gas_hint == 399_999


# ── the happy path, idempotency, caps ─────────────────────────────────────────────


def test_signs_once_and_records_one_row(signer):
    call = sign_debit(signer)
    d = post(signer, envelope(call))
    assert d.status == 200 and d.body["replayed"] is False
    assert d.body["tx_hash"].startswith("0x") and len(d.body["tx_hash"]) == 66
    assert signer.rpc.sent == [d.body["tx_hash"]]
    row = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, "0x" + call.receipt_id.hex())
    assert (row.state, row.amount_units) == ("broadcast", 10_000)
    assert signer.ledger.window_units(cfg.CHAIN_ID, cfg.ESCROW, cfg.TOKEN.lower(), 0) == 10_000


def test_replay_with_a_different_gas_hint_is_the_same_request(signer):
    """The real retry shape: the hub re-estimates gas every pass."""
    call = sign_debit(signer)
    first = post(signer, envelope(call, gas=250_000))
    second = post(signer, envelope(call, gas=312_501))
    assert first.status == second.status == 200
    assert second.body == {"tx_hash": first.body["tx_hash"], "replayed": True}
    assert len(signer.rpc.sent) == 1, "a second transaction was broadcast"
    assert signer.ledger.window_units(cfg.CHAIN_ID, cfg.ESCROW, cfg.TOKEN.lower(), 0) == 10_000


def test_same_receipt_different_amount_is_a_conflict(signer):
    call = sign_debit(signer)
    assert post(signer, envelope(call)).status == 200
    topup = sign_debit(signer, amount=1_000_000, receipt=call.receipt_id)
    d = post(signer, envelope(topup))
    assert (d.status, d.reason_code) == (422, "receipt_id_tuple_conflict")
    assert d.alarm
    assert len(signer.rpc.sent) == 1
    assert signer.ledger.window_units(cfg.CHAIN_ID, cfg.ESCROW, cfg.TOKEN.lower(), 0) == 10_000


def test_twenty_identical_requests_broadcast_once(signer):
    call = sign_debit(signer)
    results = [post(signer, envelope(call, gas=250_000 + i)) for i in range(20)]
    assert all(r.status == 200 for r in results)
    assert sum(1 for r in results if r.body["replayed"]) == 19
    assert len(signer.rpc.sent) == 1


def test_cap_is_exact_at_the_boundary(signer):
    """Three $0.01 debits fit a 30 000-unit day exactly; the fourth is refused.

    Only the 24h window is tightened: the checks run cheapest-window-first, so leaving 10m
    at the same value would report `cap_units_10m` and the test would be asserting the
    order of the checks rather than the boundary.
    """
    from conftest import make_caps, make_settings
    from escrow_signer.policy import PolicySigner
    caps = make_caps(units_24h=30_000, units_10m=10 ** 12, units_1h=10 ** 12,
                     units_per_tx=10_000, units_channel_24h=10 ** 12)
    settings = make_settings(signer.s.db_path, caps=caps)
    ps = PolicySigner(settings, signer.ledger, signer.rpc, clock=signer._clock)
    ps.boot()
    for i in range(3):
        d = ps.handle(envelope(sign_debit(ps, receipt=bytes([i + 1]) * 32)))
        assert d.status == 200, (i, d.reason_code)
    d = ps.handle(envelope(sign_debit(ps, receipt=b"\x09" * 32)))
    assert (d.status, d.reason_code) == (429, "cap_units_24h")
    assert d.body["retry_after_s"] > 0
    assert len(ps.rpc.sent) == 3


def test_per_tx_cap(signer):
    """Over the per-transaction ceiling but WITHIN the channel balance.

    The balance has to be raised first: the chain checks run before the caps, so with the
    default fixture balance this would refuse `insufficient_balance` and never reach the
    cap at all — a green test that proves nothing about the cap.
    """
    c = signer.rpc.channel
    signer.rpc.channel = Channel(c.depositor, c.hub, c.token, 10_000_000, 10_000_000,
                                 0, c.expires_at, c.nonce, 0)
    d = post(signer, envelope(sign_debit(signer, amount=1_010_000)))
    assert (d.status, d.reason_code) == (429, "cap_units_per_tx")
    assert_nothing_sent(signer)


def test_broadcast_failure_keeps_the_row_signed(signer):
    signer.rpc.send_error = "unavailable"
    call = sign_debit(signer)
    d = post(signer, envelope(call))
    assert (d.status, d.reason_code) == (503, "broadcast_failed")
    row = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, "0x" + call.receipt_id.hex())
    assert row.state == "signed" and row.tx_hash
    # The budget stays charged: the transaction may still be known to a node.
    assert signer.ledger.window_units(cfg.CHAIN_ID, cfg.ESCROW, cfg.TOKEN.lower(), 0) == 10_000


def test_ten_thousand_dollar_debit_meters_as_integers(signer):
    from conftest import make_caps, make_settings
    from escrow_signer.policy import PolicySigner
    c = signer.rpc.channel
    signer.rpc.channel = Channel(c.depositor, c.hub, c.token, 10_000_000_000,
                                 10_000_000_000, 0, c.expires_at, c.nonce, 0)
    caps = make_caps(units_per_tx=10_000_000_000, units_10m=10_000_000_000,
                     units_1h=10_000_000_000, units_24h=10_000_000_000,
                     units_channel_24h=10_000_000_000)
    ps = PolicySigner(make_settings(signer.s.db_path, caps=caps), signer.ledger, signer.rpc,
                      clock=signer._clock)
    ps.boot()
    d = ps.handle(envelope(sign_debit(ps, amount=10_000_000_000)))
    assert d.status == 200, d.reason_code
    row = ps.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, d.receipt_id)
    assert row.amount_units == 10_000_000_000
    assert isinstance(row.amount_units, int)


def test_halted_ledger_refuses(signer):
    signer.ledger.halt("operator test")
    d = post(signer, envelope(sign_debit(signer)))
    assert (d.status, d.reason_code) == (503, "clock_regression")
    assert_nothing_sent(signer)


def test_clock_regression_halts_and_keeps_the_window(signer, clock):
    call = sign_debit(signer)
    assert post(signer, envelope(call)).status == 200
    before = signer.ledger.window_units(cfg.CHAIN_ID, cfg.ESCROW, cfg.TOKEN.lower(), 0)
    clock.now -= 90_000  # step back a day
    d = post(signer, envelope(sign_debit(signer, receipt=b"\x08" * 32)))
    assert d.status == 503
    assert signer.ledger.halted
    assert signer.ledger.window_units(cfg.CHAIN_ID, cfg.ESCROW, cfg.TOKEN.lower(), 0) == before


def test_boot_refuses_when_the_books_are_broken(signer):
    signer.ledger.db.execute("UPDATE spend SET amount_units = amount_units")  # no-op
    call = sign_debit(signer)
    assert post(signer, envelope(call)).status == 200
    signer.ledger.db.execute("UPDATE spend SET amount_units = 1")
    signer.boot()
    assert not signer.ready
    assert signer.not_ready_reason == "ledger_chain_mismatch"
    d = post(signer, envelope(sign_debit(signer, receipt=b"\x07" * 32)))
    assert (d.status, d.reason_code) == (503, "ledger_chain_mismatch")


# ── a released reservation must be retryable ──────────────────────────────────────
# R21 releases a reservation whose simulation failed so the work can be attempted again.
# The primary key is the receipt, so the retry's INSERT hit it and raised — turning one
# transient RPC failure into a debit that could never be submitted, ever. Found in production
# on 2026-08-24 with a real $0.01 debit: the audit chain showed `dead: simulation unavailable`
# followed by `ledger_unavailable` on every retry after that.

def test_a_debit_released_by_a_failed_simulation_can_be_retried(signer):
    call = sign_debit(signer)
    signer.rpc.simulate_error = "InsufficientBalance"
    first = post(signer, envelope(call))
    assert first.status == 422 and first.reason_code.startswith("simulation_reverted")
    row = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, first.receipt_id)
    assert row.state == "dead"
    assert_nothing_sent(signer)

    # The condition clears; the same debit must now be signable.
    signer.rpc.simulate_error = None
    second = post(signer, envelope(call))
    assert second.status == 200, f"a released debit stayed unsubmittable: {second.reason_code}"
    assert second.body["replayed"] is False
    assert signer.rpc.sent == [second.body["tx_hash"]]
    revived = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, first.receipt_id)
    assert revived.state == "broadcast"
    # One row, one receipt — the revive updates in place rather than duplicating.
    assert signer.ledger.stats()["rows"] == 1
    # And the budget is charged exactly once.
    assert signer.ledger.window_units(cfg.CHAIN_ID, cfg.ESCROW, cfg.TOKEN.lower(), 0) == 10_000


def test_a_revived_row_gets_a_fresh_account_nonce(signer):
    call = sign_debit(signer)
    signer.rpc.simulate_error = "ChannelExpired"
    post(signer, envelope(call))
    dead = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, "0x" + call.receipt_id.hex())
    signer.rpc.simulate_error = None
    post(signer, envelope(call))
    revived = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, "0x" + call.receipt_id.hex())
    assert revived.account_nonce > dead.account_nonce, (
        "the retry reused a nonce that the dead attempt had already allocated")


def test_a_live_row_is_never_revived(signer):
    """Only a dead row may be retried. A reserved/signed one must not be rewritten."""
    call = sign_debit(signer)
    signer.rpc.send_error = "unavailable"
    first = post(signer, envelope(call))
    assert first.status == 503 and first.reason_code == "broadcast_failed"
    assert signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, first.receipt_id).state == "signed"
    signer.rpc.send_error = None
    # R17 reconciles a signed row rather than starting a second attempt.
    second = post(signer, envelope(call))
    assert second.status in (200, 409), second.reason_code
    assert second.reason_code in ("", "reserved_unresolved"), second.reason_code


def test_the_chain_still_verifies_after_a_revive(signer):
    call = sign_debit(signer)
    signer.rpc.simulate_error = "InvalidSignature"
    post(signer, envelope(call))
    signer.rpc.simulate_error = None
    post(signer, envelope(call))
    signer.ledger.verify_chains()   # raises if the revive broke either chain
