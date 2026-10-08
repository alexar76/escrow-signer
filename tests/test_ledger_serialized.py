"""The ledger is one sqlite connection shared by a threaded server.

`/health`, `/status` and `/receipt` are served from their own threads while a debit is
being reserved. Before every method took the ledger mutex, those reads ran inside another
thread's ``BEGIN IMMEDIATE`` on the same connection; and `reserve` took the mutex by hand,
so an exception type it did not name left the mutex held and the transaction open.
"""

from __future__ import annotations

import threading
import time

import pytest

import escrow_signer.ledger as ledger_mod
from escrow_signer import config as cfg
from escrow_signer.ledger import Ledger
from tests.conftest import FakeClock, make_caps

TOKEN = "0x" + "33" * 20
FROM = "0x" + "44" * 20


def _reserve(ledger: Ledger, i: int):
    return ledger.reserve(
        caps=make_caps(), chain_id=cfg.CHAIN_ID, escrow=cfg.ESCROW,
        receipt_id="0x" + f"{i:064x}", channel_id="0x" + f"{i % 7:064x}",
        depositor=FROM, token=TOKEN, amount_units=100, deadline=2_000_000_000,
        channel_nonce=i, calldata_keccak="0x" + "55" * 32, to_addr=cfg.ESCROW,
        gas_limit=200_000, hub_gas_hint=200_000, max_fee_wei=10, from_addr=FROM)


class _WatchedConnection:
    """Wraps the ledger's sqlite connection and records every statement a thread runs
    while ANOTHER thread's transaction is open on it — the interleaving the mutex forbids."""

    def __init__(self, real):
        self._real = real
        self._owner = None
        self.violations = []
        self._guard = threading.Lock()

    def execute(self, sql, *args):
        me = threading.get_ident()
        head = sql.strip().split()[0].upper()
        with self._guard:
            if self._owner is not None and self._owner != me:
                self.violations.append(sql.strip()[:60])
            if head == "BEGIN":
                self._owner = me
        try:
            return self._real.execute(sql, *args)
        finally:
            if head in ("COMMIT", "ROLLBACK"):
                with self._guard:
                    self._owner = None

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_reads_from_other_threads_never_land_inside_a_reservation(tmp_path, monkeypatch):
    ledger = Ledger(str(tmp_path / "l.db"), clock=FakeClock())
    watched = _WatchedConnection(ledger.db)
    ledger.db = watched
    real_hash = ledger_mod._row_hash

    def slow_hash(*args, **kwargs):
        time.sleep(0.002)  # hold the reservation's transaction open
        return real_hash(*args, **kwargs)

    monkeypatch.setattr(ledger_mod, "_row_hash", slow_hash)
    stop = threading.Event()
    errors: list[BaseException] = []

    def reader():
        # What the threaded server does for /health, /status and /receipt.
        while not stop.is_set():
            try:
                ledger.stats()
                _ = ledger.halted
                ledger.get(cfg.CHAIN_ID, cfg.ESCROW, "0x" + "00" * 32)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(6)]
    for t in threads:
        t.start()
    try:
        for i in range(60):
            _reserve(ledger, i)
    finally:
        stop.set()
        for t in threads:
            t.join()
    assert errors == []
    assert watched.violations == [], f"{len(watched.violations)} statement(s) ran inside another thread's transaction"
    assert ledger.stats()["rows"] == 60
    ledger.verify_chains()  # the hash chain is intact


def test_an_unexpected_error_inside_reserve_releases_the_ledger(tmp_path, monkeypatch):
    ledger = Ledger(str(tmp_path / "l.db"), clock=FakeClock())
    real_hash = ledger_mod._row_hash
    monkeypatch.setattr(ledger_mod, "_row_hash", lambda *a, **k: (_ for _ in ()).throw(TypeError("boom")))
    with pytest.raises(TypeError):
        _reserve(ledger, 1)
    assert not ledger.db.in_transaction
    got = []

    def probe():
        ok = ledger._lock.acquire(timeout=1)
        got.append(ok)
        if ok:
            ledger._lock.release()

    t = threading.Thread(target=probe)
    t.start()
    t.join()
    assert got == [True], "the ledger mutex was left held"
    monkeypatch.setattr(ledger_mod, "_row_hash", real_hash)
    assert _reserve(ledger, 2).state == "reserved"  # the ledger is usable again
