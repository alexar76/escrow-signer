"""The decision. Ordered, single-purpose, and hostile to its own caller by construction.

Every rule below can only refuse. The service signs exactly one shape of transaction — a
canonical ``debitChannel`` on one pinned escrow on one pinned chain — and the authority for
the *amount* is the depositor's EIP-712 signature, re-verified here against channel state
this process read itself.

One deliberate departure from the written spec, with its reason: the idempotency lookup runs
BEFORE the chain reads rather than after them. The spec's phase order would meet a
legitimate replay (our own transaction, already mined) at the ``usedReceipts`` check and
refuse it ``receipt_already_used``, which is precisely the answer that leaves the hub's row
unresolved and invites another pass. A replay must be answered with the hash we actually
broadcast, so the lookup comes first.
"""

from __future__ import annotations

import hmac
import json
import logging
import time
from dataclasses import dataclass, field

from eth_account import Account
from eth_utils import keccak

from escrow_signer import calldata as cd
from escrow_signer import config as cfg
from escrow_signer import eip712
from escrow_signer.chainio import Channel, Reverted, RpcPool, RpcUnavailable
from escrow_signer.ledger import CapBreach, ClockRegression, Ledger, LedgerUnavailable

log = logging.getLogger("escrow_signer")

ALARM_CODES = frozenset({
    "selector_not_allowed", "to_not_escrow", "value_not_zero", "wrong_chain",
    "receipt_id_tuple_conflict", "hub_gas_anomalous", "clock_regression",
    "ledger_chain_mismatch",
})


@dataclass
class Decision:
    status: int
    body: dict
    reason_code: str = ""
    receipt_id: str = ""
    channel_id: str = ""
    amount_units: int = 0
    digest16: str = ""
    tx_hash: str = ""
    decision: str = "refused"

    @property
    def alarm(self) -> bool:
        return self.reason_code in ALARM_CODES


def _refuse(status: int, reason: str, **extra) -> Decision:
    body = {"error": reason}
    body.update({k: v for k, v in extra.items() if k in ("retry_after_s", "detail")})
    return Decision(status=status, body=body, reason_code=reason,
                    receipt_id=extra.get("receipt_id", ""), channel_id=extra.get("channel_id", ""),
                    amount_units=extra.get("amount_units", 0),
                    digest16=extra.get("digest16", ""))


class PolicySigner:
    """Holds the key, the ledger and its own chain view. One in-flight signature at a time."""

    ENVELOPE_KEYS = frozenset({"to", "data", "chainId", "gas", "value"})

    def __init__(self, settings: cfg.Settings, ledger: Ledger, rpc: RpcPool, *, clock=time.time):
        self.s = settings
        self.ledger = ledger
        self.rpc = rpc
        self._clock = clock
        self.account = Account.from_key(settings.private_key)
        self.address = self.account.address
        self.ready = False
        self.not_ready_reason = "boot_reconciliation"
        self._chain_ok_until = 0.0
        self._separator = eip712.domain_separator(cfg.CHAIN_ID, cfg.ESCROW)

    # ── boot ──────────────────────────────────────────────────────────────────────

    def boot(self) -> None:
        """R26 — refuse everything until the books verify, chain agrees and rows are classified."""
        self.ready = False
        try:
            self.ledger.verify_chains()
        except LedgerUnavailable as exc:
            self.not_ready_reason = "ledger_chain_mismatch"
            log.error("REFUSING TO SERVE: %s", exc)
            return
        if self.ledger.halted:
            self.not_ready_reason = "clock_regression"
            log.error("REFUSING TO SERVE: ledger halted: %s", self.ledger.halted)
            return
        try:
            self._verify_chain_identity(force=True)
            reconciled = self._reconcile()
            chain_nonce = self.rpc.transaction_count(self.address, "pending")
        except (RpcUnavailable, Reverted) as exc:
            self.not_ready_reason = "boot_reconciliation"
            log.error("REFUSING TO SERVE: chain unreachable at boot (%s)", type(exc).__name__)
            return
        live = self.ledger.unresolved()
        highest = max((r.account_nonce for r in live), default=-1)
        self.ledger.set_next_nonce(cfg.CHAIN_ID, self.address, max(chain_nonce, highest + 1))
        self.ledger.record_boot(self.address, cfg.CHAIN_ID, cfg.ESCROW,
                                json.dumps(self.s.caps.as_json()), reconciled)
        self.ledger.audit(kind="boot", decision="ready", http_status=200,
                          chain_id=cfg.CHAIN_ID, escrow=cfg.ESCROW)
        self.ready = True
        self.not_ready_reason = ""
        log.info("boot ok | address=%s next_nonce=%s live_rows=%d caps=%s unlimited=%s",
                 self.address, max(chain_nonce, highest + 1), len(live),
                 json.dumps(self.s.caps.as_json()), self.s.caps.unlimited_windows or "none")

    def _verify_chain_identity(self, *, force: bool = False) -> None:
        """R13. Cached briefly; a failure refuses every request until it passes again."""
        if not force and self._clock() < self._chain_ok_until:
            return
        chain_id = self.rpc.chain_id()
        if chain_id != cfg.CHAIN_ID:
            raise ChainUnverified(f"rpc chain_id={chain_id}")
        separator = self.rpc.domain_separator(cfg.ESCROW)
        if separator != self._separator:
            raise ChainUnverified("domain separator mismatch")
        if not self.rpc.hub_authorized(cfg.ESCROW, self.address):
            raise ChainUnverified("this key is not an authorized hub")
        if self.rpc.token_decimals(cfg.TOKEN) != cfg.TOKEN_DECIMALS:
            raise ChainUnverified("token decimals changed")
        self._chain_ok_until = self._clock() + cfg.CHAIN_CACHE_TTL_S

    def _reconcile(self) -> bool:
        """Classify every live row from chain evidence. Never releases on an RPC error (R24)."""
        now = int(self._clock())
        for row in self.ledger.unresolved():
            receipt_id = bytes.fromhex(row.receipt_id[2:])
            used = self.rpc.receipt_used(cfg.ESCROW, receipt_id)
            if used:
                self.ledger.mark_mined(row)
                log.info("reconcile: receipt %s collected on chain", row.receipt_id)
                continue
            landed = False
            for attempt in self.ledger.attempts_for(row.chain_id, row.escrow, row.receipt_id):
                receipt = self.rpc.receipt(attempt["tx_hash"])
                if not receipt:
                    self.ledger.record_attempt_status(attempt["tx_hash"], "absent")
                    continue
                status = str(receipt.get("status", ""))
                self.ledger.record_attempt_status(attempt["tx_hash"], status)
                if status == "0x1":
                    fee = int(str(receipt.get("gasUsed", "0x0")), 16) * int(
                        str(receipt.get("effectiveGasPrice", "0x0")), 16)
                    self.ledger.mark_mined(row, tx_hash=attempt["tx_hash"], fee_wei=fee)
                    landed = True
                    break
                if status == "0x0":
                    self.ledger.mark_dead(row, "transaction reverted on chain")
                    landed = True
                    break
            if landed:
                continue
            if now > row.deadline:
                # Past the deadline the contract reverts ChannelExpired, so this debit can
                # never land: the budget it holds is free to release. Only here, and only
                # with a successful `usedReceipts` read behind it.
                self.ledger.mark_dead(row, "deadline passed before it landed")
                log.warning("reconcile: row %s released, deadline passed", row.receipt_id)
        return True

    # ── the request path ──────────────────────────────────────────────────────────

    def authorized(self, header: str) -> bool:
        """R1. Constant-time, and never logs any part of either token."""
        prefix = "Bearer "
        if not header.startswith(prefix):
            return False
        return hmac.compare_digest(header[len(prefix):].strip(), self.s.token)

    def handle(self, raw_body: bytes) -> Decision:
        """Everything after auth and the size cap, which the server enforces first."""
        if self.ledger.halted:
            return _refuse(503, "clock_regression")
        if not self.ready:
            return _refuse(503, self.not_ready_reason or "boot_reconciliation")

        envelope = self._parse_envelope(raw_body)
        if isinstance(envelope, Decision):
            return envelope
        to_addr, data, chain_id, gas_hint, _value = envelope
        digest16 = keccak(data).hex()[:16]

        # R27 — dispatch on the selector, and do it BEFORE any length check.
        #
        # `expireChannel` has no amount, no receipt and no depositor signature, so every
        # rule in the debit path would be reading absent fields; it takes its own road.
        # But the ordering matters for a second reason. With one allowed selector, the
        # debit decoder could check length first — deliberately, since a right-selector
        # body of the wrong length is the more interesting attack. With two allowed shapes
        # of different lengths, length-first misclassifies: a 36-byte `settleChannel`
        # attempt came back `calldata_length`, which is not in ALARM_CODES, so a deliberate
        # probe for a forbidden selector passed without raising an alarm. Its own test
        # caught that. Unknown selectors are now named as such, and the debit path keeps
        # length-first for bodies that do carry its selector.
        selector = data[0:4]
        if selector == cd.EXPIRE_SELECTOR:
            return self._handle_expire(to_addr, data, gas_hint, digest16)
        if selector != cd.DEBIT_SELECTOR:
            return _refuse(422, "selector_not_allowed", digest16=digest16)

        # R7-R12 — the calldata must be canonical before anything reads chain.
        try:
            call = cd.decode_debit(data)
            cd.check_signature_shape(call)
        except cd.CalldataError as exc:
            return _refuse(422, exc.reason_code, digest16=digest16)

        sanity = self._field_sanity(call)
        if sanity is not None:
            return _refuse(422, sanity, digest16=digest16,
                           receipt_id="0x" + call.receipt_id.hex(),
                           channel_id="0x" + call.channel_id.hex(),
                           amount_units=call.amount)

        receipt_id = "0x" + call.receipt_id.hex()
        channel_id = "0x" + call.channel_id.hex()
        common = dict(digest16=digest16, receipt_id=receipt_id, channel_id=channel_id,
                      amount_units=call.amount)

        # R18a — the hub's gas is advisory, but an absurd hint is a tamper signal, not noise.
        if gas_hint > cfg.GAS_HARD_CAP:
            return _refuse(422, "hub_gas_anomalous", **common)

        calldata_keccak = "0x" + keccak(data).hex()

        # R17 (moved ahead of the chain reads — see the module docstring).
        existing = self.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, receipt_id)
        if existing is not None:
            replay = self._replay(existing, to_addr, channel_id, call, calldata_keccak, common)
            if replay is not None:
                return replay

        try:
            self._verify_chain_identity()
            channel = self.rpc.get_channel(cfg.ESCROW, call.channel_id)
            state = self._channel_state(channel, call)
            if state is not None:
                return _refuse(422, state, **common)
            if self.rpc.receipt_used(cfg.ESCROW, call.receipt_id):
                # Somebody collected this receipt. Not us — R17 already answered that case.
                return _refuse(422, "receipt_already_used", **common)
        except ChainUnverified as exc:
            log.error("chain unverified: %s", exc)
            return _refuse(503, "chain_unverified", **common)
        except Reverted as exc:
            return _refuse(422, f"simulation_reverted:{exc.name}", **common)
        except RpcUnavailable:
            return _refuse(503, "rpc_unavailable", **common)

        # R16 — the depositor's signature is the authority, and `hub` is OUR address.
        digest = eip712.debit_digest(
            separator=self._separator, channel_id=call.channel_id, hub=self.address,
            token=channel.token, amount=call.amount, receipt_id=call.receipt_id,
            nonce=channel.nonce, deadline=call.deadline)
        try:
            recovered = eip712.recover(digest, call.signature)
        except Exception:  # type only: a recovery error can carry the signature
            return _refuse(422, "signature_malformed", **common)
        if recovered.lower() != channel.depositor.lower():
            return _refuse(422, "signature_not_depositor", **common)

        # R18/R19 — our own gas estimate and our own fee, never the caller's.
        try:
            estimate = self.rpc.estimate_gas(cfg.ESCROW, data, self.address)
            base_fee = self.rpc.base_fee_wei()
        except Reverted as exc:
            return _refuse(422, f"simulation_reverted:{exc.name}", **common)
        except RpcUnavailable:
            return _refuse(503, "rpc_unavailable", **common)
        if estimate > cfg.GAS_HARD_CAP:
            return _refuse(422, "gas_estimate_over_cap", **common)
        gas_limit = min(estimate * cfg.GAS_MULTIPLIER_NUM // cfg.GAS_MULTIPLIER_DEN,
                        cfg.GAS_HARD_CAP)
        max_fee = 2 * base_fee + self.s.priority_fee_wei
        if max_fee > self.s.max_fee_wei_ceiling:
            return _refuse(503, "fee_ceiling", **common)

        # R20 — reserve before the key is touched.
        try:
            row = self.ledger.reserve(
                caps=self.s.caps, chain_id=cfg.CHAIN_ID, escrow=cfg.ESCROW,
                receipt_id=receipt_id, channel_id=channel_id, depositor=channel.depositor,
                token=channel.token.lower(), amount_units=call.amount, deadline=call.deadline,
                channel_nonce=channel.nonce, calldata_keccak=calldata_keccak,
                to_addr=to_addr.lower(), gas_limit=gas_limit, hub_gas_hint=gas_hint,
                max_fee_wei=max_fee, from_addr=self.address)
        except CapBreach as exc:
            return _refuse(429, exc.cap_name, retry_after_s=exc.retry_after_s, **common)
        except ClockRegression:
            return _refuse(503, "clock_regression", **common)
        except LedgerUnavailable as exc:
            # Name what failed. `ledger_unavailable` alone is unactionable — it is the same
            # answer for a full disk, a schema mismatch and a bug in the reserve statement,
            # and an operator cannot tell them apart from the outside. The message carries an
            # exception TYPE, never a payload, so it is safe to log.
            log.error("ledger refused the reservation: %s", exc)
            return _refuse(503, "ledger_unavailable", **common)

        # R21 — simulate the exact call from our address; a revert releases the reservation.
        try:
            self.rpc.simulate(cfg.ESCROW, data, self.address)
        except Reverted as exc:
            self.ledger.mark_dead(row, f"simulation reverted: {exc.name}")
            return _refuse(422, f"simulation_reverted:{exc.name}", **common)
        except RpcUnavailable:
            self.ledger.mark_dead(row, "simulation unavailable")
            return _refuse(503, "rpc_unavailable", **common)

        # R22/R23 — sign, record, then broadcast. The hash is knowable before the send.
        try:
            signed = self.account.sign_transaction({
                "to": cfg.ESCROW,
                "value": cfg.TX_VALUE,
                "data": "0x" + data.hex(),
                "gas": gas_limit,
                "maxFeePerGas": max_fee,
                "maxPriorityFeePerGas": self.s.priority_fee_wei,
                "nonce": row.account_nonce,
                "chainId": cfg.CHAIN_ID,
                "type": 2,
            })
        except Exception as exc:  # type only — never the payload
            self.ledger.mark_dead(row, f"signing failed: {type(exc).__name__}")
            log.error("signing failed (%s)", type(exc).__name__)
            return _refuse(500, "signing_failed", **common)
        raw = bytes(getattr(signed, "raw_transaction", None) or signed.rawTransaction)
        tx_hash = "0x" + keccak(raw).hex()
        self.ledger.mark_signed(row, tx_hash, "0x" + keccak(raw).hex())

        try:
            broadcast_hash = self.rpc.send_raw(raw)
        except Reverted as exc:
            self.ledger.mark_dead(row, f"broadcast rejected: {exc.name}")
            return _refuse(422, f"simulation_reverted:{exc.name}", **common)
        except RpcUnavailable as exc:
            # The row stays `signed`: the transaction may yet be known to a node. R17 will
            # return this hash if it landed, and R24 releases it only past the deadline.
            log.warning("broadcast failed, row kept signed: %s", str(exc)[:200])
            return _refuse(503, "broadcast_failed", **common)
        if broadcast_hash.lower() != tx_hash.lower():
            log.warning("node returned a different hash than we computed; trusting ours")
        self.ledger.mark_broadcast(row, tx_hash)
        return Decision(status=200, body={"tx_hash": tx_hash, "replayed": False},
                        decision="signed", tx_hash=tx_hash, **common)

    # ── R27-R33: expireChannel, the one gas-only call ─────────────────────────────

    def _handle_expire(self, to_addr: str, data: bytes, gas_hint: int,
                       digest16: str) -> Decision:
        """Collect a channel the chain already owes us, past its expiry.

        Why this key is allowed to sign it at all: `expireChannel` is **permissionless** on
        chain — any funded wallet may call it — and the contract fixes the split
        (`usedAmount` to the bound hub, the remainder to the depositor) with no recipient
        and no amount anywhere in the call. The authority granted here is therefore not
        "move money"; it is "spend our own gas to trigger a transfer the contract has
        already decided". Everything below exists to make sure the gas goes on our own
        revenue and nobody else's.
        """
        try:
            call = cd.decode_expire(data)
        except cd.CalldataError as exc:
            return _refuse(422, exc.reason_code, digest16=digest16)

        channel_id = "0x" + call.channel_id.hex()
        common = dict(digest16=digest16, channel_id=channel_id, amount_units=0)

        if gas_hint > cfg.GAS_HARD_CAP:
            return _refuse(422, "hub_gas_anomalous", **common)

        calldata_keccak = "0x" + keccak(data).hex()
        # R30 — one durable key per channel, domain-separated so it can never collide with
        # a receipt id a buyer chooses. Without a key the ledger's primary key has nothing
        # to hold, and two sweeps could be handed the same account nonce.
        pseudo_receipt = "0x" + keccak(b"expireChannel|" + call.channel_id).hex()

        existing = self.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, pseudo_receipt)
        if existing is not None and existing.state in ("signed", "broadcast", "mined"):
            # Already done, or in flight: answer with the hash instead of paying gas twice.
            return Decision(status=200, body={"tx_hash": existing.tx_hash, "replayed": True},
                            decision="replayed", tx_hash=existing.tx_hash,
                            receipt_id=pseudo_receipt, **common)

        try:
            self._verify_chain_identity()
            channel = self.rpc.get_channel(cfg.ESCROW, call.channel_id)
        except ChainUnverified as exc:
            log.error("chain unverified: %s", exc)
            return _refuse(503, "chain_unverified", **common)
        except Reverted as exc:
            return _refuse(422, f"simulation_reverted:{exc.name}", **common)
        except RpcUnavailable:
            return _refuse(503, "rpc_unavailable", **common)

        # R31 — spend gas only where the contract will actually pay us.
        if channel.status != 0:
            return _refuse(422, "channel_not_open", **common)
        if int(getattr(channel, "used_amount", 0) or 0) <= 0:
            # The call would succeed and pay us nothing.
            return _refuse(422, "channel_owes_nothing", **common)
        if (channel.hub or "").lower() != self.address.lower():
            # A channel bound to another hub pays THAT hub. Legal, and none of our gas.
            return _refuse(422, "channel_not_ours", **common)
        expires_at = int(getattr(channel, "expires_at", 0) or 0)
        if expires_at and self.ledger.now() <= expires_at:
            # Before expiry this selector reverts — only settleChannel works, and only for
            # the depositor or the bound hub. Refusing here saves a wasted simulation.
            return _refuse(422, "channel_not_expired", **common)

        try:
            estimate = self.rpc.estimate_gas(cfg.ESCROW, data, self.address)
            base_fee = self.rpc.base_fee_wei()
        except Reverted as exc:
            return _refuse(422, f"simulation_reverted:{exc.name}", **common)
        except RpcUnavailable:
            return _refuse(503, "rpc_unavailable", **common)
        if estimate > cfg.GAS_HARD_CAP:
            return _refuse(422, "gas_estimate_over_cap", **common)
        gas_limit = min(estimate * cfg.GAS_MULTIPLIER_NUM // cfg.GAS_MULTIPLIER_DEN,
                        cfg.GAS_HARD_CAP)
        max_fee = 2 * base_fee + self.s.priority_fee_wei
        if max_fee > self.s.max_fee_wei_ceiling:
            return _refuse(503, "fee_ceiling", **common)

        # R32 — reserve before the key is touched, through the gas-only door: `reserve`
        # refuses a zero amount, and rightly so, since every window it guards is in tokens.
        try:
            row = self.ledger.reserve_gas_only(
                caps=self.s.caps, chain_id=cfg.CHAIN_ID, escrow=cfg.ESCROW,
                receipt_id=pseudo_receipt, channel_id=channel_id,
                calldata_keccak=calldata_keccak, to_addr=to_addr.lower(),
                gas_limit=gas_limit, max_fee_wei=max_fee, from_addr=self.address,
                max_per_24h=self.s.max_gas_only_per_24h)
        except CapBreach as exc:
            return _refuse(429, exc.cap_name, retry_after_s=exc.retry_after_s, **common)
        except ClockRegression:
            return _refuse(503, "clock_regression", **common)
        except LedgerUnavailable as exc:
            log.error("ledger refused the gas-only reservation: %s", exc)
            return _refuse(503, "ledger_unavailable", **common)

        try:
            self.rpc.simulate(cfg.ESCROW, data, self.address)
        except Reverted as exc:
            self.ledger.mark_dead(row, f"simulation reverted: {exc.name}")
            return _refuse(422, f"simulation_reverted:{exc.name}", **common)
        except RpcUnavailable:
            self.ledger.mark_dead(row, "simulation unavailable")
            return _refuse(503, "rpc_unavailable", **common)

        # R33 — sign, record, then broadcast, exactly as the money path does.
        try:
            signed = self.account.sign_transaction({
                "to": cfg.ESCROW,
                "value": cfg.TX_VALUE,
                "data": "0x" + data.hex(),
                "gas": gas_limit,
                "maxFeePerGas": max_fee,
                "maxPriorityFeePerGas": self.s.priority_fee_wei,
                "nonce": row.account_nonce,
                "chainId": cfg.CHAIN_ID,
                "type": 2,
            })
        except Exception as exc:  # type only — never the payload
            self.ledger.mark_dead(row, f"signing failed: {type(exc).__name__}")
            log.error("signing failed (%s)", type(exc).__name__)
            return _refuse(500, "signing_failed", **common)
        raw = bytes(getattr(signed, "raw_transaction", None) or signed.rawTransaction)
        tx_hash = "0x" + keccak(raw).hex()
        self.ledger.mark_signed(row, tx_hash, tx_hash)

        try:
            self.rpc.send_raw(raw)
        except Reverted as exc:
            self.ledger.mark_dead(row, f"broadcast rejected: {exc.name}")
            return _refuse(422, f"simulation_reverted:{exc.name}", **common)
        except RpcUnavailable as exc:
            # The row stays `signed`: a node may yet know this transaction, and the replay
            # branch above will answer with its hash.
            log.warning("broadcast failed, row kept signed: %s", str(exc)[:200])
            return _refuse(503, "broadcast_failed", **common)
        self.ledger.mark_broadcast(row, tx_hash)
        return Decision(status=200, body={"tx_hash": tx_hash, "replayed": False},
                        decision="signed", tx_hash=tx_hash, receipt_id=pseudo_receipt,
                        **common)

    # ── helpers ───────────────────────────────────────────────────────────────────

    def _parse_envelope(self, raw_body: bytes):
        """R3 (shape), R4 (value == 0), R5 (chain id), R6 (to == escrow).

        Returns the parsed tuple, or a Decision that refuses. R4 is the rule that removes
        "sign a plain ETH transfer" from the surface entirely, and R6 rejects an absent or
        empty `to` explicitly because several signing libraries serialise that as a contract
        creation.
        """
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            return _refuse(400, "malformed_json")
        if not isinstance(payload, dict) or set(payload) != {"transaction"}:
            return _refuse(400, "envelope_invalid")
        tx = payload["transaction"]
        if not isinstance(tx, dict) or set(tx) != self.ENVELOPE_KEYS:
            return _refuse(400, "envelope_invalid")
        # bool is a subclass of int in Python; a JSON `true` must not pass as 1.
        for key in ("chainId", "gas", "value"):
            if not isinstance(tx[key], int) or isinstance(tx[key], bool):
                return _refuse(400, "envelope_invalid")
        if tx["value"] != cfg.TX_VALUE:
            return _refuse(422, "value_not_zero")
        if tx["chainId"] != cfg.CHAIN_ID:
            return _refuse(422, "wrong_chain")
        to_addr = tx["to"]
        if not isinstance(to_addr, str) or len(to_addr) != 42 or not to_addr.startswith("0x"):
            return _refuse(422, "to_not_escrow")
        try:
            raw_to = bytes.fromhex(to_addr[2:])
        except ValueError:
            return _refuse(422, "to_not_escrow")
        if len(raw_to) != 20 or raw_to != bytes.fromhex(cfg.ESCROW[2:]):
            return _refuse(422, "to_not_escrow")
        try:
            data = cd.parse_hex_bytes(tx["data"], reason="calldata_length")
        except cd.CalldataError as exc:
            return _refuse(422, exc.reason_code)
        if tx["gas"] <= 0:
            return _refuse(400, "envelope_invalid")
        return to_addr, data, tx["chainId"], tx["gas"], tx["value"]

    def _field_sanity(self, call: cd.DebitCall):
        """R11. The bands the contract does not have, and the ones it does."""
        now = int(self._clock())
        if call.amount < cfg.MIN_AMOUNT_UNITS or call.amount > cfg.MAX_AMOUNT_UNITS:
            return "amount_out_of_band"
        if call.amount % cfg.CENT_UNITS != 0:
            return "amount_out_of_band"
        if call.receipt_id == bytes(32):
            return "receipt_id_zero"
        if call.channel_id == bytes(32):
            return "channel_id_zero"
        if call.deadline < now + cfg.MIN_DEADLINE_SKEW_S:
            return "deadline_out_of_band"
        if call.deadline > now + cfg.MAX_DEADLINE_TTL_S:
            return "deadline_out_of_band"
        return None

    def _channel_state(self, channel: Channel, call: cd.DebitCall):
        """R14. Everything about the channel, read from chain."""
        now = int(self._clock())
        if not channel.exists:
            return "channel_not_found"
        if not channel.is_open:
            return "channel_not_open"
        if channel.expires_at <= now + cfg.CHANNEL_MIN_REMAINING_S:
            return "channel_expiring"
        if channel.balance < call.amount:
            return "insufficient_balance"
        if channel.token.lower() != cfg.TOKEN.lower():
            return "token_not_allowed"
        if int(channel.hub, 16) != 0 and channel.hub.lower() != self.address.lower():
            return "channel_bound_elsewhere"
        return None

    def _replay(self, row, to_addr: str, channel_id: str, call: cd.DebitCall,
                calldata_keccak: str, common: dict):
        """R17. The same receipt id means the same debit — or a conflict, never a top-up."""
        same = row.semantic_tuple() == (
            to_addr.lower(), channel_id, call.amount, "0x" + call.receipt_id.hex(),
            calldata_keccak)
        if not same:
            log.error("ALARM receipt_id_tuple_conflict receipt=%s stored_amount=%s asked=%s",
                      row.receipt_id, row.amount_units, call.amount)
            return _refuse(422, "receipt_id_tuple_conflict", **common)
        if row.state == "superseded":
            return _refuse(422, "superseded", **common)
        if row.state in ("broadcast", "mined") and row.tx_hash:
            return Decision(status=200, body={"tx_hash": row.tx_hash, "replayed": True},
                            decision="replayed", tx_hash=row.tx_hash, **common)
        if row.state in ("reserved", "signed"):
            try:
                self._reconcile()
            except (RpcUnavailable, Reverted):
                return _refuse(409, "reserved_unresolved", **common)
            fresh = self.ledger.get(row.chain_id, row.escrow, row.receipt_id)
            if fresh and fresh.state == "mined" and fresh.tx_hash:
                return Decision(status=200, body={"tx_hash": fresh.tx_hash, "replayed": True},
                                decision="replayed", tx_hash=fresh.tx_hash, **common)
            if fresh and fresh.state == "dead":
                return None  # released and provably unlandable — treat as new work
            return _refuse(409, "reserved_unresolved", **common)
        return None  # dead → new work


class ChainUnverified(RuntimeError):
    """The chain does not look like the one this service was pinned to."""
