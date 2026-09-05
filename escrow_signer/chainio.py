"""This service's own view of chain. Never the hub's.

The point of a separate RPC client is not tidiness: every fact this service checks — the
channel's depositor, its token, its nonce, whether the receipt was already collected,
whether we are still an authorized hub — is a fact the caller would love to supply. Reading
them here, over endpoints the caller does not configure, is what makes the policy real.

Failures are unavailability, never "false". A read that cannot be performed must refuse the
request (503); answering "receipt not used" because the RPC timed out is how a double
collection gets signed.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from eth_utils import keccak

from escrow_signer import calldata as cd

# Custom errors declared by AIMarketEscrow. Selectors are derived, not copied; an error we
# have not listed degrades to its raw selector rather than being mislabelled.
ESCROW_ERRORS = (
    "ChannelNotFound()", "ChannelNotOpen()", "ChannelExists()", "ChannelNotExpired()",
    "InsufficientBalance(uint256,uint256)", "InvalidSignature()", "ChannelExpired()",
    "Unauthorized()", "DepositOutOfRange()", "TokenNotSupported()",
    "ReceiptAlreadyUsed(bytes32)", "RefundAfterDebit()", "UnsupportedTokenDecimals()",
    "ReasonTooLong()",
)
_ERROR_NAMES = {"0x" + cd.selector(sig).hex(): sig.split("(", 1)[0] for sig in ESCROW_ERRORS}

_CREDENTIALS = re.compile(r"//[^/@\s]*:[^/@\s]*@")


class RpcUnavailable(RuntimeError):
    """No endpoint could answer. Always a 503 — never interpreted as a value."""


class Reverted(RuntimeError):
    """An eth_call reverted. Carries the decoded error name, which is safe to log."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


def scrub(text: str) -> str:
    """Strip embedded credentials from anything about to be logged."""
    return _CREDENTIALS.sub("//<redacted>@", text)


def _decode_revert(data: str) -> str:
    raw = (data or "").strip()
    if not raw.startswith("0x") or len(raw) < 10:
        return "unknown_revert"
    sel = raw[:10].lower()
    if sel in _ERROR_NAMES:
        return _ERROR_NAMES[sel]
    if sel == "0x08c379a0":  # Error(string)
        try:
            body = bytes.fromhex(raw[10:])
            length = int.from_bytes(body[32:64], "big")
            return "Error:" + body[64:64 + length].decode("utf-8", "replace")[:64]
        except Exception:
            return "Error(string)"
    return "revert" + sel


@dataclass(frozen=True)
class Channel:
    depositor: str
    hub: str
    token: str
    deposit_amount: int
    balance: int
    used_amount: int
    expires_at: int
    nonce: int
    status: int

    @property
    def is_open(self) -> bool:
        return self.status == 0

    @property
    def exists(self) -> bool:
        return int(self.depositor, 16) != 0


class RpcPool:
    """Round-robin over endpoints, first answer wins, every failure recorded.

    A User-Agent is set explicitly: Base's public endpoint answers 403 to urllib's default,
    which would otherwise look exactly like an outage on a healthy network.
    """

    def __init__(self, urls, timeout_s: float = 10.0, user_agent: str = "escrow-policy-signer/0.1"):
        if not urls:
            raise ValueError("at least one RPC URL is required")
        self._urls = tuple(urls)
        self._timeout = timeout_s
        self._ua = user_agent
        self.last_errors = []

    def _post(self, url: str, payload: dict) -> dict:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            method="POST",
            headers={"content-type": "application/json", "user-agent": self._ua},
        )
        with urllib.request.urlopen(request, timeout=self._timeout) as response:
            return json.loads(response.read().decode() or "{}")

    def call_method(self, method: str, params):
        """One JSON-RPC call, trying every endpoint. Reverts propagate; outages rotate."""
        self.last_errors = []
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        for url in self._urls:
            try:
                body = self._post(url, payload)
            except urllib.error.HTTPError as exc:
                self.last_errors.append(f"{scrub(url)}: HTTP {exc.code}")
                continue
            except Exception as exc:  # timeouts, DNS, TLS — type only, never the message
                self.last_errors.append(f"{scrub(url)}: {type(exc).__name__}")
                continue
            error = body.get("error")
            if error:
                data = error.get("data") if isinstance(error, dict) else None
                if isinstance(data, dict):
                    data = data.get("data")
                message = (error.get("message") or "") if isinstance(error, dict) else ""
                if isinstance(data, str) and data.startswith("0x") and len(data) >= 10:
                    raise Reverted(_decode_revert(data))
                if "revert" in message.lower():
                    raise Reverted("unknown_revert")
                # A method-level error (bad params, archive gating) is this endpoint's
                # problem, not an answer: try the next one.
                self.last_errors.append(f"{scrub(url)}: rpc {message[:60]}")
                continue
            if "result" in body:
                return body["result"]
            self.last_errors.append(f"{scrub(url)}: no result")
        raise RpcUnavailable("; ".join(self.last_errors) or "no endpoints tried")

    # ── typed helpers ─────────────────────────────────────────────────────────────

    def chain_id(self) -> int:
        return int(str(self.call_method("eth_chainId", [])), 16)

    def eth_call(self, to: str, data: bytes, *, sender: str = "") -> bytes:
        tx = {"to": to, "data": "0x" + data.hex()}
        if sender:
            tx["from"] = sender
        return bytes.fromhex(str(self.call_method("eth_call", [tx, "latest"]))[2:])

    def estimate_gas(self, to: str, data: bytes, sender: str) -> int:
        result = self.call_method(
            "eth_estimateGas", [{"to": to, "from": sender, "data": "0x" + data.hex(), "value": "0x0"}]
        )
        return int(str(result), 16)

    def base_fee_wei(self) -> int:
        block = self.call_method("eth_getBlockByNumber", ["latest", False])
        return int(str(block.get("baseFeePerGas") or "0x0"), 16)

    def transaction_count(self, address: str, block: str = "pending") -> int:
        return int(str(self.call_method("eth_getTransactionCount", [address, block])), 16)

    def send_raw(self, raw: bytes) -> str:
        return str(self.call_method("eth_sendRawTransaction", ["0x" + raw.hex()]))

    def receipt(self, tx_hash: str):
        return self.call_method("eth_getTransactionReceipt", [tx_hash])

    def balance_wei(self, address: str) -> int:
        return int(str(self.call_method("eth_getBalance", [address, "latest"])), 16)

    # ── escrow reads ──────────────────────────────────────────────────────────────

    def get_channel(self, escrow: str, channel_id: bytes) -> Channel:
        out = self.eth_call(escrow, cd.selector(cd.GET_CHANNEL_SIG) + channel_id)
        if len(out) < 9 * 32:
            raise RpcUnavailable(f"getChannel returned {len(out)} bytes")
        words = [out[i * 32:(i + 1) * 32] for i in range(9)]
        addr = lambda w: "0x" + w[12:].hex()
        num = lambda w: int.from_bytes(w, "big")
        return Channel(
            depositor=addr(words[0]), hub=addr(words[1]), token=addr(words[2]),
            deposit_amount=num(words[3]), balance=num(words[4]), used_amount=num(words[5]),
            expires_at=num(words[6]), nonce=num(words[7]), status=num(words[8]),
        )

    def receipt_used(self, escrow: str, receipt_id: bytes) -> bool:
        out = self.eth_call(escrow, cd.selector(cd.USED_RECEIPTS_SIG) + receipt_id)
        return int.from_bytes(out[-32:], "big") != 0 if out else False

    def hub_authorized(self, escrow: str, address: str) -> bool:
        word = bytes(12) + bytes.fromhex(address[2:])
        out = self.eth_call(escrow, cd.selector(cd.AUTHORIZED_HUBS_SIG) + word)
        return int.from_bytes(out[-32:], "big") != 0 if out else False

    def domain_separator(self, escrow: str) -> bytes:
        return self.eth_call(escrow, cd.selector(cd.DOMAIN_SEPARATOR_SIG))[-32:]

    def token_decimals(self, token: str) -> int:
        return int.from_bytes(self.eth_call(token, cd.selector(cd.DECIMALS_SIG))[-32:], "big")

    def simulate(self, escrow: str, data: bytes, sender: str) -> None:
        """eth_call a state-changing function to learn whether it WOULD be accepted."""
        self.eth_call(escrow, data, sender=sender)


def keccak_hex(data: bytes) -> str:
    return "0x" + keccak(data).hex()
