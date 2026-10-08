"""Entry point. Boots into a refusing state and only then binds."""

from __future__ import annotations

import logging
import sys
import threading

from escrow_signer import config as cfg
from escrow_signer.chainio import RpcPool
from escrow_signer.ledger import Ledger, LedgerUnavailable
from escrow_signer.policy import PolicySigner, run_sweeps
from escrow_signer.server import make_server

log = logging.getLogger("escrow_signer")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, stream=sys.stdout,
        format="%(asctime)sZ %(levelname)s %(message)s",
    )
    logging.Formatter.converter = __import__("time").gmtime
    try:
        settings = cfg.load()
    except cfg.ConfigError as exc:
        log.error("configuration refused: %s", exc)
        return 2

    log.info("starting | %s", settings.redacted())
    if settings.caps.unlimited_windows:
        log.warning("UNLIMITED windows in force: %s — this is a deliberate choice, "
                    "announced at every boot", settings.caps.unlimited_windows)

    try:
        ledger = Ledger(settings.db_path, witness_path=settings.audit_witness_path)
    except LedgerUnavailable as exc:
        log.error("ledger unavailable (%s) — refusing to start", exc)
        return 3

    rpc = RpcPool(settings.rpc_urls, timeout_s=settings.rpc_timeout_s,
                  user_agent=settings.user_agent)
    signer = PolicySigner(settings, ledger, rpc)
    log.info("signing address %s", signer.address)
    signer.boot()
    if not signer.ready:
        log.warning("serving in REFUSING state (%s) — it will not sign until this clears",
                    signer.not_ready_reason)

    server = make_server(signer, settings.bind_host, settings.bind_port)
    log.info("listening on %s:%d path=%s", settings.bind_host, settings.bind_port,
             settings.sign_path)
    if settings.sweep_to:
        # Same lock as the request path: a sweep and a debit are never signed at once.
        threading.Thread(target=run_sweeps, name="proceeds-sweep", daemon=True,
                         args=(signer, server.signing_lock),
                         kwargs={"interval_s": settings.sweep_interval_s}).start()
        log.info("proceeds sweep on: to %s every %ds, from %d units", settings.sweep_to,
                 settings.sweep_interval_s, settings.sweep_min_units)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.server_close()
        ledger.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
