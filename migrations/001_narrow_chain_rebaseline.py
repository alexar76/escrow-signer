#!/usr/bin/env python3
"""Re-tag spend rows written under the WIDE chain rule so the NARROW rule accepts them.

The integrity tag on a spend row is `keccak(prev_head || canonical_json(payload))`. Which
fields go into `payload` is the chain *rule*, and it changed:

* **wide** (what production ran until 2026-08-25): every immutable field **plus**
  `gas_limit`, `hub_gas_hint`, `max_fee_wei`, `account_nonce`, and a hardcoded
  `state="reserved"`.
* **narrow** (`_CHAINED_FIELDS`, what the code does now): the immutable fields only.

The wide rule had a real defect, which is why it changed. `reserve`'s revive path — the one
that lets a debit be retried after a released simulation — rewrites `account_nonce`,
`gas_limit` and `max_fee_wei` by design. Under the wide rule that rewrite silently
invalidated the row's own tag, so the next boot refused to serve. A rule that a legitimate
retry breaks is not an integrity check; it is a time bomb.

Changing the rule leaves existing rows unverifiable, and a signer that cannot verify its
books refuses to sign — which is exactly what happened on the oracle host when the new code
met a row written by the old.

**The safety property of this migration:** a row is re-tagged only if its stored tag is
correct under the rule that wrote it. Verification comes first, and it uses the *insert-time*
values for the mutable fields the wide rule included — `state="reserved"`, which is what the
wide rule hardcoded in both its writer and its verifier. A row that verifies under neither
rule is left alone and the migration fails: that is the tampering case the chain exists to
catch, and this script must never paper over it.

    python3 migrations/001_narrow_chain_rebaseline.py /var/lib/escrow-signer/signer.db --dry-run
    python3 migrations/001_narrow_chain_rebaseline.py /var/lib/escrow-signer/signer.db --apply

Stop the signer first. It holds the database open and boots by verifying it.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys

from eth_utils import keccak

# The rule as the code has it now. Imported rather than copied so this script cannot
# disagree with the service it is migrating for.
sys.path.insert(0, __file__.rsplit("/migrations/", 1)[0])
from escrow_signer.ledger import _CHAINED_FIELDS, _row_hash  # noqa: E402

WIDE_EXTRA = ("gas_limit", "hub_gas_hint", "max_fee_wei", "account_nonce")


def wide_payload(row: sqlite3.Row) -> dict:
    """What the retired rule hashed, with the values it used at insert time."""
    payload = {k: row[k] for k in _CHAINED_FIELDS if k != "from_addr"}
    payload["from_addr"] = row["from_addr"]
    for key in WIDE_EXTRA:
        payload[key] = row[key]
    payload["state"] = "reserved"      # hardcoded by the old writer AND its verifier
    return payload


def narrow_payload(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in _CHAINED_FIELDS}


def audit_tail(db: sqlite3.Connection) -> tuple:
    row = db.execute("SELECT head FROM chain_head WHERE name='audit'").fetchone()
    seq = db.execute("SELECT COALESCE(MAX(seq), 0) AS s FROM audit").fetchone()["s"]
    return (row["head"] if row else "0x00"), int(seq)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument("db_path")
    parser.add_argument("--apply", action="store_true",
                        help="write the new tags (default: report only)")
    args = parser.parse_args(argv)

    db = sqlite3.connect(args.db_path)
    db.row_factory = sqlite3.Row
    rows = list(db.execute("SELECT * FROM spend ORDER BY seq"))
    print(f"{len(rows)} spend row(s) in {args.db_path}")

    head, plan = "0x00", []
    for row in rows:
        narrow = _row_hash(head, narrow_payload(row))
        if row["row_hash"] == narrow:
            print(f"  seq {row['seq']}: already narrow — nothing to do")
            head = narrow
            continue
        # Verify under the OLD rule using the OLD link — the row's own stored
        # `prev_row_hash`, which is what its writer hashed against. Using the running
        # narrow head here made every row after the first fail its authenticity check and
        # the whole migration refuse; its own multi-row test caught that.
        wide = _row_hash(row["prev_row_hash"] or "0x00", wide_payload(row))
        if row["row_hash"] != wide:
            print(f"  seq {row['seq']}: FAILS under BOTH rules — refusing to re-tag.\n"
                  f"    stored   {row['row_hash']}\n"
                  f"    wide     {wide}\n"
                  f"    narrow   {narrow}\n"
                  f"  This is the tampering case. Do not run with --apply; investigate.",
                  file=sys.stderr)
            return 2
        print(f"  seq {row['seq']}: authentic under the wide rule → re-tag to narrow")
        print(f"    {row['row_hash'][:20]}… -> {narrow[:20]}…")
        plan.append((row["seq"], row["chain_id"], row["escrow"], row["receipt_id"],
                     row["channel_id"], row["amount_units"], head, narrow))
        head = narrow

    if not plan:
        print("nothing to migrate")
        return 0
    if not args.apply:
        print(f"\ndry run: {len(plan)} row(s) would be re-tagged, chain head would become "
              f"{head[:20]}…\nrerun with --apply")
        return 0

    try:
        db.execute("BEGIN IMMEDIATE")
        for seq, chain_id, escrow, receipt_id, channel_id, amount, prev, new in plan:
            db.execute("UPDATE spend SET row_hash = ?, prev_row_hash = ? WHERE seq = ?",
                       (new, prev, seq))
        db.execute("UPDATE chain_head SET head = ? WHERE name='spend'", (head,))
        # The migration writes itself into the audit chain: an operator touching the books
        # has to be visible in them, or the next unexplained mismatch has no history.
        a_head, a_seq = audit_tail(db)
        payload = {
            "ts": int(rows[-1]["ts"]), "kind": "migration",
            "decision": "rebaseline", "http_status": 0,
            "reason_code": "001_narrow_chain_rebaseline: re-tagged "
                           f"{len(plan)} row(s) verified under the wide rule",
            "chain_id": rows[-1]["chain_id"], "escrow": rows[-1]["escrow"],
            "receipt_id": "", "channel_id": "", "amount_units": 0,
            "digest16": "", "tx_hash": "",
        }
        a_hash = _row_hash(a_head, payload)
        db.execute(
            "INSERT INTO audit (seq, ts, kind, decision, http_status, reason_code, chain_id,"
            " escrow, receipt_id, channel_id, amount_units, digest16, tx_hash,"
            # The audit table calls it `prev_hash`; only `spend` uses `prev_row_hash`.
            " prev_hash, row_hash) VALUES (:seq,:ts,:kind,:decision,:http_status,"
            ":reason_code,:chain_id,:escrow,:receipt_id,:channel_id,:amount_units,"
            ":digest16,:tx_hash,:prev,:row_hash)",
            dict(payload, seq=a_seq + 1, prev=a_head, row_hash=a_hash))
        db.execute("UPDATE chain_head SET head = ? WHERE name='audit'", (a_hash,))
        db.execute("COMMIT")
    except Exception as exc:
        db.execute("ROLLBACK")
        print(f"migration failed, nothing written: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1

    print(f"\napplied: {len(plan)} row(s) re-tagged, spend head {head[:20]}…, "
          f"audit entry {a_seq + 1} recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
