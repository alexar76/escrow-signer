"""Test doubles. The fake chain records everything, so a test can assert what did NOT happen."""

from __future__ import annotations

import os
import sys
import tempfile
import time

import pytest
from eth_account import Account
from eth_utils import keccak

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from escrow_signer import calldata as cd            # noqa: E402
from escrow_signer import config as cfg             # noqa: E402
from escrow_signer import eip712                    # noqa: E402
from escrow_signer.chainio import Channel, Reverted, RpcUnavailable  # noqa: E402
from escrow_signer.ledger import Ledger             # noqa: E402
from escrow_signer.policy import PolicySigner       # noqa: E402

ZERO = "0x" + "00" * 20
DEPOSITOR = Account.from_key("0x" + "11" * 32)
HOT = Account.from_key("0x" + "22" * 32)
OUTSIDER = Account.from_key("0x" + "33" * 32)


class FakeClock:
    def __init__(self, now: float = 1_800_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeRpc:
    """Same surface as RpcPool. Every mutating call is recorded, never performed."""

    def __init__(self, *, clock, channel: Channel = None, hot_address: str = ""):
        self.clock = clock
        self.sent = []
        self.estimates = []
        self.receipt_flags = {}
        self.authorized = True
        self.chain = cfg.CHAIN_ID
        self.decimals = cfg.TOKEN_DECIMALS
        self.estimate_value = 150_000
        self.base_fee = 10_000_000
        self.nonce = 0
        self.simulate_error = None
        self.send_error = None
        self.receipts = {}
        self.separator = eip712.domain_separator(cfg.CHAIN_ID, cfg.ESCROW)
        self.channel = channel or Channel(
            depositor=DEPOSITOR.address, hub=hot_address or ZERO, token=cfg.TOKEN,
            deposit_amount=1_000_000, balance=1_000_000, used_amount=0,
            expires_at=int(clock()) + 86_400, nonce=0, status=0)

    # reads
    def chain_id(self):
        return self.chain

    def domain_separator(self, escrow):
        return self.separator

    def hub_authorized(self, escrow, address):
        return self.authorized

    def token_decimals(self, token):
        return self.decimals

    def get_channel(self, escrow, channel_id):
        return self.channel

    def receipt_used(self, escrow, receipt_id):
        return bool(self.receipt_flags.get("0x" + receipt_id.hex(), False))

    def estimate_gas(self, to, data, sender):
        self.estimates.append(len(data))
        return self.estimate_value

    def base_fee_wei(self):
        return self.base_fee

    def transaction_count(self, address, block="pending"):
        return self.nonce

    def receipt(self, tx_hash):
        return self.receipts.get(tx_hash)

    def simulate(self, escrow, data, sender):
        if self.simulate_error:
            raise Reverted(self.simulate_error)

    # writes
    def send_raw(self, raw):
        if self.send_error == "unavailable":
            raise RpcUnavailable("stub")
        if self.send_error:
            raise Reverted(self.send_error)
        tx_hash = "0x" + keccak(raw).hex()
        self.sent.append(tx_hash)
        return tx_hash


def make_caps(**overrides):
    base = dict(units_10m=2_000_000, units_1h=5_000_000, units_24h=25_000_000,
                units_per_tx=1_000_000, units_channel_24h=5_000_000, tx_1h=100, tx_24h=500,
                tx_per_channel_24h=50, distinct_channels_24h=20, fee_wei_24h=10 ** 18)
    base.update(overrides)
    return cfg.Caps(**base)


def make_settings(db_path: str, **overrides):
    values = dict(
        bind_host="127.0.0.1", bind_port=0, sign_path="/sign", token="test-token",
        private_key="0x" + "22" * 32, db_path=db_path,
        rpc_urls=("http://stub",), rpc_timeout_s=1.0, priority_fee_wei=1_000_000,
        max_fee_wei_ceiling=10 ** 12, caps=make_caps(), audit_witness_path="",
    )
    values.update(overrides)
    return cfg.Settings(**values)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def signer(clock, tmp_path):
    db = str(tmp_path / "signer.db")
    ledger = Ledger(db, clock=clock)
    rpc = FakeRpc(clock=clock, hot_address=ZERO)
    settings = make_settings(db)
    ps = PolicySigner(settings, ledger, rpc, clock=clock)
    ps.boot()
    assert ps.ready, ps.not_ready_reason
    return ps


def sign_debit(signer_obj, *, amount=10_000, receipt=b"\x01" * 32, channel=b"\x02" * 32,
               deadline=None, depositor=DEPOSITOR, hub=None, nonce=None, token=None):
    """A genuine depositor signature over the digest the contract will rebuild."""
    rpc = signer_obj.rpc
    deadline = deadline if deadline is not None else int(rpc.clock()) + 3_600
    digest = eip712.debit_digest(
        separator=signer_obj._separator, channel_id=channel,
        hub=hub or signer_obj.address, token=token or rpc.channel.token, amount=amount,
        receipt_id=receipt, nonce=rpc.channel.nonce if nonce is None else nonce,
        deadline=deadline)
    signed = Account._sign_hash(digest, depositor.key)
    return cd.DebitCall(channel, amount, receipt, deadline, bytes(signed.signature))


def envelope(call: cd.DebitCall, *, gas=250_000, chain_id=cfg.CHAIN_ID, to=cfg.ESCROW,
             value=0, data=None):
    import json
    return json.dumps({"transaction": {
        "to": to,
        "data": data if data is not None else "0x" + cd.encode_debit(call).hex(),
        "chainId": chain_id, "gas": gas, "value": value,
    }}).encode()
