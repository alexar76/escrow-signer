"""`expireChannel` — the one call this key may sign that is not a debit.

The reason it is allowed is narrow and worth restating, because every test here defends it:
the function is **permissionless on chain**. Any funded wallet may call it after a channel
expires, and the contract fixes the split — `usedAmount` to the bound hub, the remainder to
the depositor — with no recipient and no amount anywhere in the calldata. So signing it
grants no authority an attacker with any other wallet lacks; the only resource at stake is
our own gas. These tests exist to keep it that narrow: gas goes on our own revenue, once
per channel, under a limit of its own, and the debit path is untouched.
"""
from __future__ import annotations

import json

import pytest
from eth_utils import keccak

from escrow_signer import calldata as cd
from escrow_signer import config as cfg
from escrow_signer.chainio import Channel

from conftest import DEPOSITOR, ZERO, envelope, sign_debit


CHANNEL = b"\x33" * 32


def expire_body(signer_obj, *, channel: bytes = CHANNEL, gas: int = 120_000,
                to: str = cfg.ESCROW, chain_id: int = cfg.CHAIN_ID) -> bytes:
    data = cd.encode_expire(cd.ExpireCall(channel))
    return _wrap("0x" + data.hex(), to=to, chain_id=chain_id, gas=gas)


def _wrap(data_hex: str, *, to: str = cfg.ESCROW, chain_id: int = cfg.CHAIN_ID,
          gas: int = 120_000, value: int = 0) -> bytes:
    return json.dumps({"transaction": {"to": to, "data": data_hex, "chainId": chain_id,
                                       "gas": gas, "value": value}}).encode()


def collectable_channel(signer_obj, clock, **overrides) -> Channel:
    """An expired channel that owes us money — the only shape that should be signed."""
    base = dict(depositor=DEPOSITOR.address, hub=signer_obj.address, token=cfg.TOKEN,
                deposit_amount=1_000_000, balance=990_000, used_amount=10_000,
                expires_at=int(clock()) - 3600, nonce=1, status=0)
    base.update(overrides)
    return Channel(**base)


# ── the happy path ───────────────────────────────────────────────────────────────────────

def test_an_expired_channel_of_ours_is_signed_and_broadcast(signer, clock):
    signer.rpc.channel = collectable_channel(signer, clock)
    decision = signer.handle(expire_body(signer))
    assert decision.status == 200, decision.body
    assert decision.decision == "signed"
    assert decision.body["tx_hash"] in signer.rpc.sent
    assert decision.amount_units == 0          # no tokens are named in this call


def test_the_ledger_row_records_no_amount(signer, clock):
    """It must not consume the money windows: nothing was spent but gas."""
    signer.rpc.channel = collectable_channel(signer, clock)
    signer.handle(expire_body(signer))
    pseudo = "0x" + keccak(b"expireChannel|" + CHANNEL).hex()
    row = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, pseudo)
    assert row is not None
    assert row.amount_units == 0
    assert row.state == "broadcast"


def test_a_second_call_replays_instead_of_paying_gas_twice(signer, clock):
    signer.rpc.channel = collectable_channel(signer, clock)
    first = signer.handle(expire_body(signer))
    again = signer.handle(expire_body(signer))
    assert again.status == 200
    assert again.body == {"tx_hash": first.body["tx_hash"], "replayed": True}
    assert len(signer.rpc.sent) == 1


# ── whose money, and when ────────────────────────────────────────────────────────────────

def test_a_channel_bound_to_another_hub_is_refused(signer, clock):
    """It would succeed on chain and pay somebody else. Not our gas."""
    signer.rpc.channel = collectable_channel(signer, clock, hub="0x" + "ab" * 20)
    decision = signer.handle(expire_body(signer))
    assert decision.status == 422
    assert decision.reason_code == "channel_not_ours"
    assert signer.rpc.sent == []


def test_a_channel_that_owes_nothing_is_refused(signer, clock):
    signer.rpc.channel = collectable_channel(signer, clock, used_amount=0)
    decision = signer.handle(expire_body(signer))
    assert decision.reason_code == "channel_owes_nothing"
    assert signer.rpc.sent == []


def test_a_channel_before_its_expiry_is_refused(signer, clock):
    """The contract reverts ChannelNotExpired; refusing here saves a wasted simulation."""
    signer.rpc.channel = collectable_channel(signer, clock, expires_at=int(clock()) + 3600)
    decision = signer.handle(expire_body(signer))
    assert decision.reason_code == "channel_not_expired"
    assert signer.rpc.sent == []


@pytest.mark.parametrize("status,label", [(1, "settled"), (2, "refunded"), (3, "expired")])
def test_an_already_closed_channel_is_refused(signer, clock, status, label):
    signer.rpc.channel = collectable_channel(signer, clock, status=status)
    decision = signer.handle(expire_body(signer))
    assert decision.reason_code == "channel_not_open", label
    assert signer.rpc.sent == []


# ── the calldata is as strictly decoded as a debit ───────────────────────────────────────

def test_a_short_body_with_the_right_selector_is_refused(signer, clock):
    signer.rpc.channel = collectable_channel(signer, clock)
    data = cd.EXPIRE_SELECTOR + b"\x33" * 31
    body = _wrap("0x" + data.hex())
    decision = signer.handle(body)
    assert decision.reason_code == "calldata_length"


def test_trailing_bytes_are_refused(signer, clock):
    signer.rpc.channel = collectable_channel(signer, clock)
    data = cd.encode_expire(cd.ExpireCall(CHANNEL)) + b"\x00"
    body = _wrap("0x" + data.hex())
    assert signer.handle(body).reason_code == "calldata_length"


def test_an_unknown_selector_is_still_refused(signer, clock):
    """`settleChannel` is deliberately NOT allowed: it works before expiry and only for the
    depositor or the bound hub, so allowing it would widen the authority this key holds."""
    settle = cd.selector("settleChannel(bytes32)") + CHANNEL
    body = _wrap("0x" + settle.hex())
    decision = signer.handle(body)
    assert decision.status == 422
    assert decision.reason_code == "selector_not_allowed"
    assert decision.alarm is True          # a wrong selector is a tamper signal


def test_the_envelope_guards_still_apply(signer, clock):
    signer.rpc.channel = collectable_channel(signer, clock)
    assert signer.handle(expire_body(signer, to="0x" + "cd" * 20)).reason_code == "to_not_escrow"
    assert signer.handle(expire_body(signer, chain_id=1)).reason_code == "wrong_chain"
    assert signer.handle(expire_body(signer, gas=10 ** 9)).reason_code == "hub_gas_anomalous"


# ── the gas-only limit ───────────────────────────────────────────────────────────────────

def test_the_daily_gas_only_limit_refuses_a_runaway_sweep(signer, clock):
    """No token window bites a zero-amount call, so this limit is the only thing between a
    looping sweep and an empty gas balance."""
    object.__setattr__(signer.s, "max_gas_only_per_24h", 2)
    signed = 0
    for i in range(4):
        signer.rpc.channel = collectable_channel(signer, clock)
        decision = signer.handle(expire_body(signer, channel=bytes([i + 1]) * 32))
        if decision.status == 200:
            signed += 1
        else:
            assert decision.status == 429
            assert decision.reason_code == "cap_gas_only_24h"
    assert signed == 2


def test_zero_turns_the_feature_off_without_a_deploy(signer, clock):
    object.__setattr__(signer.s, "max_gas_only_per_24h", 0)
    signer.rpc.channel = collectable_channel(signer, clock)
    decision = signer.handle(expire_body(signer))
    assert decision.status == 429 and signer.rpc.sent == []


def test_gas_still_counts_against_the_fee_window(signer, clock):
    """Gas comes out of the same balance as everything else, so the fee cap must apply."""
    object.__setattr__(signer.s, "caps", type(signer.s.caps)(
        **{**signer.s.caps.__dict__, "fee_wei_24h": 1}))
    signer.rpc.channel = collectable_channel(signer, clock)
    decision = signer.handle(expire_body(signer))
    assert decision.status == 429
    assert decision.reason_code == "cap_fee_wei_24h"


# ── the money path is untouched ──────────────────────────────────────────────────────────

def test_a_debit_still_goes_through_its_own_rules(signer, clock):
    """The dispatch must not have changed anything for the call this service exists for."""
    signer.rpc.channel = Channel(
        depositor=DEPOSITOR.address, hub=ZERO, token=cfg.TOKEN, deposit_amount=1_000_000,
        balance=1_000_000, used_amount=0, expires_at=int(clock()) + 86_400, nonce=0, status=0)
    call = sign_debit(signer)
    decision = signer.handle(envelope(call))
    assert decision.status == 200, decision.body
    assert decision.amount_units == 10_000        # the debit's own amount, not zero


def test_both_paths_draw_nonces_from_one_allocator(signer, clock):
    """Two doors handing out the same account nonce would replace each other's
    transactions — the debit would silently vanish."""
    signer.rpc.channel = collectable_channel(signer, clock)
    signer.handle(expire_body(signer))
    signer.rpc.channel = Channel(
        depositor=DEPOSITOR.address, hub=ZERO, token=cfg.TOKEN, deposit_amount=1_000_000,
        balance=1_000_000, used_amount=0, expires_at=int(clock()) + 86_400, nonce=0, status=0)
    signer.handle(envelope(sign_debit(signer)))

    nonces = sorted(r.account_nonce for r in signer.ledger.unresolved())
    assert nonces == list(range(nonces[0], nonces[0] + len(nonces))), nonces
    assert len(set(nonces)) == len(nonces), "a nonce was handed out twice"
