"""The HTTP surface. Deliberately stdlib, deliberately tiny, deliberately serial.

A framework was considered and rejected for one concrete reason: the hub's client posts to
the configured URL verbatim and follows redirects with the ``Authorization`` header
attached. Starlette/FastAPI turn on ``redirect_slashes`` by default, so a single trailing
slash would hand the bearer token to whatever the redirect points at. This server has no
redirect code path at all, no docs routes, no debug echo and no access log that could
capture a body containing the buyer's signature.

Serial by construction: one request at a time, one signature at a time, one account nonce at
a time. The hub submits strictly in nonce order anyway, and concurrency here would buy
nothing except a second way to double-allocate a nonce.
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

from escrow_signer import config as cfg
from escrow_signer.policy import Decision, PolicySigner

log = logging.getLogger("escrow_signer")


class Handler(BaseHTTPRequestHandler):
    server_version = "escrow-policy-signer"
    sys_version = ""          # do not advertise the Python version
    protocol_version = "HTTP/1.1"

    signer: PolicySigner = None  # set by make_server

    # ── plumbing ──────────────────────────────────────────────────────────────────

    def log_message(self, fmt, *args):
        """Silence the default access log: it would record request lines verbatim."""
        return

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    # ── routes ────────────────────────────────────────────────────────────────────

    def do_GET(self):
        signer = self.signer
        if self.path == "/health":
            # No ledger write, no signing, no chain call: a health probe must not be able
            # to move the sequence counter or spend an RPC budget.
            self._send(200, {
                "ok": bool(signer.ready),
                "service": "escrow-policy-signer",
                "address": signer.address,
                "chain_id": cfg.CHAIN_ID,
                "escrow": cfg.ESCROW,
                "ready": bool(signer.ready),
                "not_ready_reason": signer.not_ready_reason,
                "halted": signer.ledger.halted,
            })
            return
        if self.path == "/status":
            stats = signer.ledger.stats()
            self._send(200, {
                "address": signer.address,
                "ready": bool(signer.ready),
                "caps": signer.s.caps.as_json(),
                "unlimited_windows": signer.s.caps.unlimited_windows,
                "ledger": stats,
            })
            return
        if self.path.startswith("/receipt/"):
            # The authoritative view of what THIS service broadcast — the hub's `confirm()`
            # must not treat a returned hash as proof, and this is where it can check.
            parts = self.path.strip("/").split("/")
            if len(parts) != 2:
                self._send(400, {"error": "usage: /receipt/<receipt_id>"})
                return
            row = signer.ledger.get(cfg.CHAIN_ID, cfg.ESCROW, parts[1].lower())
            if row is None:
                self._send(404, {"error": "unknown_receipt"})
                return
            self._send(200, {
                "receipt_id": row.receipt_id, "channel_id": row.channel_id,
                "amount_units": row.amount_units, "state": row.state,
                "tx_hash": row.tx_hash, "account_nonce": row.account_nonce,
            })
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self):
        signer = self.signer
        if self.path != signer.s.sign_path:
            # Never a redirect, not even for a trailing slash: urllib would follow it with
            # the bearer token attached, which turns a typo into a token disclosure.
            self._send(404, {"error": "not_found"})
            return

        if not signer.authorized(self.headers.get("Authorization", "") or ""):
            self._decide(Decision(status=401, body={"error": "unauthorized"},
                                  reason_code="unauthorized"))
            return

        # R2 — trust the socket, not the header: read one byte past the cap and refuse if it
        # arrives, so a lying Content-Length cannot smuggle a larger body through.
        try:
            declared = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            self._send(400, {"error": "malformed_length"})
            return
        if declared > cfg.MAX_BODY_BYTES:
            self._decide(Decision(status=413, body={"error": "body_too_large"},
                                  reason_code="body_too_large"))
            return
        raw = self.rfile.read(min(declared, cfg.MAX_BODY_BYTES + 1))
        if len(raw) > cfg.MAX_BODY_BYTES:
            self._decide(Decision(status=413, body={"error": "body_too_large"},
                                  reason_code="body_too_large"))
            return

        try:
            decision = signer.handle(raw)
        except Exception as exc:  # never leak a payload-adjacent exception
            log.error("unhandled error in decision path (%s)", type(exc).__name__)
            decision = Decision(status=500, body={"error": "internal_error"},
                                reason_code="internal_error")
        self._decide(decision)

    def _decide(self, decision: Decision) -> None:
        signer = self.signer
        try:
            signer.ledger.audit(
                kind="request", decision=decision.decision, http_status=decision.status,
                reason_code=decision.reason_code, chain_id=cfg.CHAIN_ID, escrow=cfg.ESCROW,
                receipt_id=decision.receipt_id or None, channel_id=decision.channel_id or None,
                amount_units=decision.amount_units or None, digest16=decision.digest16,
                tx_hash=decision.tx_hash)
        except Exception as exc:
            # The audit row is the system of record for refusals — the hub keeps none. If it
            # cannot be written, say so rather than answering as if it had been.
            log.error("audit write failed (%s)", type(exc).__name__)
            if decision.status < 400:
                decision = Decision(status=503, body={"error": "ledger_unavailable"},
                                    reason_code="ledger_unavailable")
        level = logging.ERROR if decision.alarm else logging.INFO
        log.log(level, "%s decision=%s status=%d reason=%s receipt=%s channel=%s units=%s "
                       "digest16=%s tx=%s%s",
                "ALARM" if decision.alarm else "sign",
                decision.decision, decision.status, decision.reason_code or "-",
                decision.receipt_id or "-", decision.channel_id or "-",
                decision.amount_units or "-", decision.digest16 or "-",
                decision.tx_hash or "-", " ALARM" if decision.alarm else "")
        self._send(decision.status, decision.body)


def make_server(signer: PolicySigner, host: str, port: int) -> HTTPServer:
    handler = type("BoundHandler", (Handler,), {"signer": signer})
    server = HTTPServer((host, port), handler)
    return server
