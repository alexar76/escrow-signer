"""The migration may only re-tag rows that were honest under the rule that wrote them.

Re-tagging is an operator writing to the integrity chain, which is precisely the act the
chain exists to detect. So the property under test is not "it converts rows" — it is
"it refuses to convert a row it cannot first prove authentic", and "it leaves a record of
itself in the audit chain".
"""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

from escrow_signer.ledger import Ledger, _CHAINED_FIELDS, _row_hash

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "migration001", ROOT / "migrations" / "001_narrow_chain_rebaseline.py")
migration = importlib.util.module_from_spec(_spec)
sys.modules["migration001"] = migration
_spec.loader.exec_module(migration)


def wide_db(tmp_path, *, tamper: bool = False, rows: int = 1) -> str:
    """A ledger holding rows tagged the way production tagged them until 2026-08-25."""
    path = str(tmp_path / "signer.db")
    ledger = Ledger(path)            # creates the schema
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    head = "0x00"
    for i in range(rows):
        payload = {
            "chain_id": 8453, "escrow": "0xESCROW", "receipt_id": f"0x{i:02x}" + "aa" * 31,
            "seq": i + 1, "ts": 1_787_000_000 + i, "channel_id": "0x" + "bb" * 32,
            "depositor": "0x" + "cc" * 20, "token": "0x" + "dd" * 20,
            "amount_units": 10_000, "deadline": 1_787_100_000, "channel_nonce": i,
            "calldata_keccak": "0x" + "ee" * 32, "to_addr": "0xescrow",
            "gas_limit": 150_000, "hub_gas_hint": 250_000, "max_fee_wei": 21_000_000,
            "account_nonce": i, "from_addr": "0x" + "ff" * 20, "state": "reserved",
        }
        row_hash = _row_hash(head, payload)
        if tamper:
            row_hash = "0x" + "99" * 32
        insert = dict(payload, prev=head, row_hash=row_hash)
        db.execute(
            "INSERT INTO spend (chain_id, escrow, receipt_id, seq, ts, channel_id, depositor,"
            " token, amount_units, deadline, channel_nonce, calldata_keccak, to_addr,"
            " gas_limit, hub_gas_hint, max_fee_wei, account_nonce, from_addr, state,"
            " prev_row_hash, row_hash) VALUES (:chain_id,:escrow,:receipt_id,:seq,:ts,"
            ":channel_id,:depositor,:token,:amount_units,:deadline,:channel_nonce,"
            ":calldata_keccak,:to_addr,:gas_limit,:hub_gas_hint,:max_fee_wei,:account_nonce,"
            ":from_addr,'broadcast',:prev,:row_hash)", insert)
        head = row_hash
    db.execute("UPDATE chain_head SET head = ? WHERE name='spend'", (head,))
    db.commit()
    db.close()
    del ledger
    return path


def test_a_wide_row_is_unverifiable_before_the_migration(tmp_path):
    """The state that took production down: new code, old rows."""
    path = wide_db(tmp_path)
    with pytest.raises(Exception) as exc:
        Ledger(path).verify_chains()
    assert "spend chain broken" in str(exc.value)


def test_the_migration_makes_it_verify(tmp_path):
    path = wide_db(tmp_path)
    assert migration.main([path, "--apply"]) == 0
    Ledger(path).verify_chains()          # raises if it did not work


def test_a_dry_run_changes_nothing(tmp_path):
    path = wide_db(tmp_path)
    before = sqlite3.connect(path).execute(
        "SELECT row_hash FROM spend").fetchone()[0]
    assert migration.main([path]) == 0
    after = sqlite3.connect(path).execute("SELECT row_hash FROM spend").fetchone()[0]
    assert after == before


def test_a_tampered_row_is_refused(tmp_path):
    """Authentic under neither rule. The migration must fail rather than legitimise it."""
    path = wide_db(tmp_path, tamper=True)
    assert migration.main([path, "--apply"]) == 2
    row = sqlite3.connect(path).execute("SELECT row_hash FROM spend").fetchone()[0]
    assert row == "0x" + "99" * 32, "a refused row must be left exactly as found"


def test_a_multi_row_chain_is_relinked_in_order(tmp_path):
    path = wide_db(tmp_path, rows=3)
    assert migration.main([path, "--apply"]) == 0
    Ledger(path).verify_chains()
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    head = "0x00"
    for row in db.execute("SELECT * FROM spend ORDER BY seq"):
        assert row["prev_row_hash"] == head
        head = row["row_hash"]
    assert db.execute("SELECT head FROM chain_head WHERE name='spend'").fetchone()[0] == head


def test_the_migration_records_itself_in_the_audit_chain(tmp_path):
    path = wide_db(tmp_path)
    before = sqlite3.connect(path).execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    assert migration.main([path, "--apply"]) == 0
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    assert db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == before + 1
    entry = db.execute("SELECT * FROM audit ORDER BY seq DESC").fetchone()
    assert entry["kind"] == "migration"
    assert "narrow_chain_rebaseline" in entry["reason_code"]
    Ledger(path).verify_chains()          # the audit chain must still verify too


def test_running_it_twice_is_a_no_op(tmp_path):
    path = wide_db(tmp_path)
    assert migration.main([path, "--apply"]) == 0
    first = sqlite3.connect(path).execute("SELECT row_hash FROM spend").fetchone()[0]
    assert migration.main([path, "--apply"]) == 0
    assert sqlite3.connect(path).execute(
        "SELECT row_hash FROM spend").fetchone()[0] == first


def test_the_narrow_payload_is_exactly_the_declared_field_set():
    """If `_CHAINED_FIELDS` changes again, this migration's idea of 'narrow' must not
    silently drift away from the service's."""
    row = {k: i for i, k in enumerate(_CHAINED_FIELDS)}
    row.update({k: 0 for k in migration.WIDE_EXTRA})
    row["state"] = "broadcast"
    assert set(migration.narrow_payload(row)) == set(_CHAINED_FIELDS)
    assert set(migration.wide_payload(row)) == set(_CHAINED_FIELDS) | set(
        migration.WIDE_EXTRA) | {"state"}
