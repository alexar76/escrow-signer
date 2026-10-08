"""The proceeds sweep — this key's own USDC to the operator's treasury.

The escrow pays `usedAmount` to the channel's bound hub, and the bound hub is this key, so
revenue piles up on a hot address whose only job is to pay gas (1.64 USDC on 2026-10-06).
The sweep is the one token transfer this key may sign, and every test here keeps it narrow:
off unless configured, recipient fixed by configuration, amount = the key's own balance read
from chain, no request can trigger it, and it shares the nonce allocator with the debit path
(a second sender on the key outside the ledger left the next debit one nonce behind).
"""
from __future__ import annotations

import dataclasses
import json
import threading

import pytest
from eth_account import Account
from eth_utils import keccak

from escrow_signer import calldata as cd
from escrow_signer import config as cfg
from escrow_signer.ledger import Ledger
from escrow_signer.policy import SWEEP_CHANNEL, SWEEP_GIVE_UP_S, PolicySigner, run_sweeps

from conftest import FakeRpc, ZERO, envelope, make_settings, sign_debit

TREASURY = "0x1218ff36C5d2e3B6A565CdB1A8B1AcCFc606Ad0a"


@pytest.fixture
def sweeper(clock, tmp_path):
    db = str(tmp_path / "signer.db")
    ledger = Ledger(db, clock=clock)
    rpc = FakeRpc(clock=clock, hot_address=ZERO)
    settings = dataclasses.replace(make_settings(db), sweep_to=TREASURY)
    ps = PolicySigner(settings, ledger, rpc, clock=clock)
    ps.boot()
    assert ps.ready, ps.not_ready_reason
    return ps


def _all_rows(signer):
    db = signer.ledger.db
    keys = db.execute("SELECT chain_id, escrow, receipt_id FROM spend").fetchall()
    return [signer.ledger.get(k["chain_id"], k["escrow"], k["receipt_id"]) for k in keys]


def _sweep_rows(signer):
    return [r for r in _all_rows(signer) if r.channel_id == SWEEP_CHANNEL]


# ── off, and below the threshold ─────────────────────────────────────────────────────────

def test_off_unless_a_recipient_is_configured(signer):
    signer.rpc.token_units = 5_000_000
    assert signer.sweep_proceeds() is None
    assert signer.rpc.sent == [] and signer.rpc.balance_reads == []


def test_below_the_threshold_nothing_is_signed(sweeper):
    sweeper.rpc.token_units = 999_999
    assert sweeper.sweep_proceeds() is None
    assert sweeper.rpc.sent == []
    assert _sweep_rows(sweeper) == []


def test_a_refusing_signer_does_not_sweep(sweeper):
    sweeper.ready = False
    sweeper.rpc.token_units = 5_000_000
    assert sweeper.sweep_proceeds() is None
    assert sweeper.rpc.sent == []


def test_its_own_address_is_never_a_recipient(clock, tmp_path):
    db = str(tmp_path / "s.db")
    rpc = FakeRpc(clock=clock, hot_address=ZERO)
    own = Account.from_key("0x" + "22" * 32).address
    ps = PolicySigner(dataclasses.replace(make_settings(db), sweep_to=own),
                      Ledger(db, clock=clock), rpc, clock=clock)
    ps.boot()
    rpc.token_units = 5_000_000
    assert ps.sweep_proceeds() is None
    assert rpc.sent == []


# ── the sweep itself ─────────────────────────────────────────────────────────────────────

def test_the_whole_balance_goes_to_the_configured_treasury(sweeper):
    sweeper.rpc.token_units = 1_640_000
    decision = sweeper.sweep_proceeds()
    assert decision is not None and decision.status == 200, decision
    assert decision.body == {"tx_hash": decision.tx_hash, "amount_units": 1_640_000, "to": TREASURY}
    assert sweeper.rpc.sent == [decision.tx_hash]
    (row,) = _sweep_rows(sweeper)
    assert row.state == "broadcast"
    assert row.to_addr == cfg.TOKEN.lower(), "the transaction goes to the pinned token"
    assert row.calldata_keccak == "0x" + keccak(cd.encode_transfer(TREASURY, 1_640_000)).hex()
    assert row.amount_units == 0, "a sweep spends no debit budget"
    assert sweeper.rpc.balance_reads == [(cfg.TOKEN, sweeper.address)]


def test_the_transfer_calldata_names_only_the_recipient_and_the_amount():
    data = cd.encode_transfer(TREASURY, 1_640_000)
    assert data[:4] == keccak(b"transfer(address,uint256)")[:4]
    assert data[4:36] == bytes(12) + bytes.fromhex(TREASURY[2:])
    assert int.from_bytes(data[36:68], "big") == 1_640_000
    assert len(data) == 68
    with pytest.raises(ValueError):
        cd.encode_transfer(TREASURY, 0)


def test_the_sweep_is_audited_with_its_amount(sweeper):
    sweeper.rpc.token_units = 2_000_000
    decision = sweeper.sweep_proceeds()
    row = sweeper.ledger.db.execute(
        "SELECT * FROM audit WHERE kind = 'sweep' ORDER BY seq DESC LIMIT 1").fetchone()
    assert row["decision"] == "signed" and row["amount_units"] == 2_000_000
    assert row["tx_hash"] == decision.tx_hash
    sweeper.ledger.verify_chains()   # the audit chain still verifies


# ── one key, one nonce sequence ──────────────────────────────────────────────────────────

def test_a_sweep_and_a_debit_never_share_a_nonce(sweeper, clock):
    sweeper.rpc.channel = dataclasses.replace(sweeper.rpc.channel, hub=sweeper.address)
    sweeper.rpc.token_units = 1_500_000
    sweeper.sweep_proceeds()
    (sweep_row,) = _sweep_rows(sweeper)
    call = sign_debit(sweeper)
    decision = sweeper.handle(envelope(call))
    assert decision.status == 200, decision.body
    debit_row = sweeper.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, "0x" + call.receipt_id.hex())
    assert debit_row.account_nonce == sweep_row.account_nonce + 1


def test_a_refused_estimate_reserves_no_nonce(sweeper):
    """The allocator never gives a nonce back, so nothing may be reserved before the
    transfer is known to execute; a released reservation would leave a gap."""
    sweeper.rpc.token_units = 1_500_000
    sweeper.rpc.estimate_error = "ERC20InsufficientBalance"
    before = sweeper.ledger.db.execute("SELECT next_nonce FROM nonce_alloc").fetchone()[0]
    decision = sweeper.sweep_proceeds()
    assert decision.status == 422
    assert sweeper.rpc.sent == [] and _sweep_rows(sweeper) == []
    assert sweeper.ledger.db.execute("SELECT next_nonce FROM nonce_alloc").fetchone()[0] == before


def test_one_sweep_in_flight_at_a_time(sweeper):
    sweeper.rpc.token_units = 1_500_000
    first = sweeper.sweep_proceeds()
    assert first.status == 200
    # Not mined yet: the next cycle waits instead of sending a second transfer.
    assert sweeper.sweep_proceeds() is None
    assert len(sweeper.rpc.sent) == 1
    # Mined: the row settles and the next cycle may sweep again.
    sweeper.rpc.receipts[first.tx_hash] = {"status": "0x1", "gasUsed": "0x9d43", "effectiveGasPrice": "0x5f5e100"}
    sweeper.rpc.token_units = 1_200_000
    second = sweeper.sweep_proceeds()
    assert second is not None and second.status == 200
    states = sorted(r.state for r in _sweep_rows(sweeper))
    assert states == ["broadcast", "mined"]


def test_a_sweep_that_never_lands_is_released_after_a_day(sweeper, clock):
    sweeper.rpc.token_units = 1_500_000
    sweeper.sweep_proceeds()
    clock.now += SWEEP_GIVE_UP_S + 1
    sweeper.rpc.token_units = 0
    assert sweeper.sweep_proceeds() is None
    (row,) = _sweep_rows(sweeper)
    assert row.state == "dead" and row.dead_reason == "sweep never landed"


def test_the_gas_only_daily_limit_applies(clock, tmp_path):
    db = str(tmp_path / "g.db")
    rpc = FakeRpc(clock=clock, hot_address=ZERO)
    ps = PolicySigner(dataclasses.replace(make_settings(db), sweep_to=TREASURY, max_gas_only_per_24h=0),
                      Ledger(db, clock=clock), rpc, clock=clock)
    ps.boot()
    rpc.token_units = 5_000_000
    decision = ps.sweep_proceeds()
    assert decision.status == 429 and decision.reason_code == "cap_gas_only_24h"
    assert rpc.sent == []


def test_an_unreadable_balance_skips_the_cycle(sweeper):
    sweeper.rpc.balance_error = True
    assert sweeper.sweep_proceeds() is None
    assert sweeper.rpc.sent == []


# ── no request can trigger it ────────────────────────────────────────────────────────────

def test_a_request_to_the_token_is_still_refused(sweeper):
    """The HTTP door keeps R6: a transfer addressed to USDC is refused whatever it says."""
    data = cd.encode_transfer(TREASURY, 1_000_000)
    body = json.dumps({"transaction": {"to": cfg.TOKEN, "data": "0x" + data.hex(),
                                       "chainId": cfg.CHAIN_ID, "gas": 80_000, "value": 0}}).encode()
    decision = sweeper.handle(body)
    assert decision.status != 200 and decision.reason_code == "to_not_escrow"
    assert sweeper.rpc.sent == []


def test_the_loop_runs_under_the_signing_lock_and_survives_a_bad_cycle(sweeper):
    calls = []
    lock = threading.RLock()
    stop = threading.Event()

    def boom():
        assert lock._is_owned(), "the sweep must hold the request path's signing lock"
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("one bad cycle")
        stop.set()

    sweeper.sweep_proceeds = boom
    run_sweeps(sweeper, lock, interval_s=1, first_delay_s=0, stop=stop, sleep=lambda s: None)
    assert len(calls) == 2


# ── configuration ────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value, ok", [
    ("", True), (TREASURY, True), ("0x" + "00" * 20, False), ("0x1234", False), ("treasury", False),
])
def test_the_recipient_must_be_a_real_address(monkeypatch, value, ok):
    for name, v in {"SIGNER_PRIVATE_KEY": "0x" + "22" * 32, "SIGNER_TOKEN": "t",
                    "SIGNER_RPC_URLS": "http://stub", "SIGNER_SWEEP_TO": value}.items():
        monkeypatch.setenv(name, v)
    for cap in ("UNITS_10M", "UNITS_1H", "UNITS_24H", "UNITS_PER_TX", "UNITS_CHANNEL_24H", "TX_1H",
                "TX_24H", "TX_PER_CHANNEL_24H", "DISTINCT_CHANNELS_24H", "FEE_WEI_24H"):
        monkeypatch.setenv(f"SIGNER_CAP_{cap}", "1")
    monkeypatch.setenv("SIGNER_PRIORITY_FEE_WEI", "1")
    monkeypatch.setenv("SIGNER_MAX_FEE_WEI_CEILING", "1")
    if ok:
        assert cfg.load().sweep_to == value
    else:
        with pytest.raises(cfg.ConfigError):
            cfg.load()
