"""The signer's own books. The only writer is this process.

Three properties this module exists to guarantee, in order of how badly their absence bites:

1. **A reservation is committed before the key is touched.** The cap check, the ledger
   insert and the account-nonce allocation are one transaction. Never SELECT-then-INSERT:
   twenty concurrent $2 requests against a $25 window must produce twelve signatures, not
   twenty. Budget is counted from the moment of reservation, so a crash between signing and
   confirming cannot leak it.
2. **Idempotency on the contract's own once-only key** ``(chain_id, escrow, receipt_id)``.
   Not the body hash — the hub re-estimates gas every pass, so the same debit legitimately
   arrives with different ``gas`` bytes. Not the tx hash — unknown before signing. The
   contract's ``usedReceipts`` mapping guarantees at most one of two requests sharing this
   key can ever succeed on chain, which is what makes counting it once ground truth.
3. **Totals are SUMs over immutable rows.** ``amount_units`` is never UPDATEd; a correction
   is a new row. An incremented counter can be corrupted once and stay wrong forever, and
   every window would inherit the error silently.

The hash chain and the monotone clock are what make the first three auditable rather than
merely intended: a row edited by hand breaks the chain, and a clock stepped backwards to
"empty" the 24h window halts signing instead of opening the gate.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass

from eth_utils import keccak

STATES = ("reserved", "signed", "broadcast", "mined", "dead", "superseded")
_COUNTED = ("reserved", "signed", "broadcast", "mined")  # states that hold budget
_LIVE = ("reserved", "signed", "broadcast")              # not yet terminal


def _in_list(values) -> str:
    """Render a SQL IN list. Not str(tuple): a single-element tuple renders ('x',)."""
    return "(" + ", ".join("'%s'" % v for v in values) + ")"


COUNTED = _in_list(_COUNTED)
LIVE = _in_list(_LIVE)

# Tolerance for a clock that merely jitters, versus one that was stepped back.
CLOCK_TOLERANCE_S = 5

SCHEMA = """
CREATE TABLE IF NOT EXISTS spend (
    chain_id        INTEGER NOT NULL,
    escrow          TEXT    NOT NULL,
    receipt_id      TEXT    NOT NULL,
    seq             INTEGER NOT NULL UNIQUE,
    ts              INTEGER NOT NULL,
    channel_id      TEXT    NOT NULL,
    depositor       TEXT    NOT NULL,
    token           TEXT    NOT NULL,
    amount_units    INTEGER NOT NULL,
    deadline        INTEGER NOT NULL,
    channel_nonce   INTEGER NOT NULL,
    calldata_keccak TEXT    NOT NULL,
    to_addr         TEXT    NOT NULL,
    gas_limit       INTEGER NOT NULL,
    hub_gas_hint    INTEGER NOT NULL,
    max_fee_wei     INTEGER NOT NULL,
    account_nonce   INTEGER,
    from_addr       TEXT    NOT NULL,
    state           TEXT    NOT NULL CHECK (state IN
                      ('reserved','signed','broadcast','mined','dead','superseded')),
    tx_hash         TEXT    NOT NULL DEFAULT '',
    fee_wei_spent   INTEGER NOT NULL DEFAULT 0,
    dead_reason     TEXT    NOT NULL DEFAULT '',
    prev_row_hash   TEXT    NOT NULL,
    row_hash        TEXT    NOT NULL,
    PRIMARY KEY (chain_id, escrow, receipt_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_spend_window  ON spend(chain_id, escrow, token, state, ts);
CREATE INDEX IF NOT EXISTS idx_spend_channel ON spend(chain_id, escrow, channel_id, ts);
CREATE UNIQUE INDEX IF NOT EXISTS idx_spend_nonce ON spend(chain_id, from_addr, account_nonce)
    WHERE account_nonce IS NOT NULL AND state <> 'dead';
CREATE INDEX IF NOT EXISTS idx_spend_unresolved ON spend(state)
    WHERE state IN ('reserved','signed','broadcast');

CREATE TABLE IF NOT EXISTS tx_attempt (
    tx_hash        TEXT PRIMARY KEY,
    chain_id       INTEGER NOT NULL,
    escrow         TEXT NOT NULL,
    receipt_id     TEXT NOT NULL,
    account_nonce  INTEGER NOT NULL,
    raw_keccak     TEXT NOT NULL,
    max_fee_wei    INTEGER NOT NULL,
    sent_at        INTEGER NOT NULL,
    receipt_status TEXT NOT NULL DEFAULT '',
    seq            INTEGER NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_attempt_receipt ON tx_attempt(chain_id, escrow, receipt_id);

CREATE TABLE IF NOT EXISTS audit (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    kind         TEXT NOT NULL,
    decision     TEXT NOT NULL,
    http_status  INTEGER NOT NULL,
    reason_code  TEXT NOT NULL DEFAULT '',
    chain_id     INTEGER,
    escrow       TEXT,
    receipt_id   TEXT,
    channel_id   TEXT,
    amount_units INTEGER,
    digest16     TEXT NOT NULL DEFAULT '',
    tx_hash      TEXT NOT NULL DEFAULT '',
    prev_hash    TEXT NOT NULL,
    row_hash     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clock_guard (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    max_ts      INTEGER NOT NULL,
    max_seq     INTEGER NOT NULL,
    halted      INTEGER NOT NULL DEFAULT 0,
    halt_reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS nonce_alloc (
    chain_id    INTEGER NOT NULL,
    from_addr   TEXT    NOT NULL,
    next_nonce  INTEGER NOT NULL,
    updated_seq INTEGER NOT NULL,
    PRIMARY KEY (chain_id, from_addr)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS boot (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    address    TEXT NOT NULL,
    chain_id   INTEGER NOT NULL,
    escrow     TEXT NOT NULL,
    caps_json  TEXT NOT NULL,
    audit_head TEXT NOT NULL,
    reconciled INTEGER NOT NULL DEFAULT 0
);

-- Chain heads live in their own table rather than being re-derived by scanning: the spend
-- table is keyed by receipt, so "the last row written" is not expressible as an ORDER BY on
-- the primary key. `seq` gives the order; this caches the head so every write is O(1).
CREATE TABLE IF NOT EXISTS chain_head (
    name TEXT PRIMARY KEY,
    head TEXT NOT NULL
);
"""


class LedgerUnavailable(RuntimeError):
    """The books cannot be written. Never sign while this is true."""


class ClockRegression(RuntimeError):
    """Wall clock moved backwards past tolerance. Halts signing until an operator clears it."""


class CapBreach(RuntimeError):
    def __init__(self, cap_name: str, retry_after_s: int = 60) -> None:
        super().__init__(cap_name)
        self.cap_name = cap_name
        self.retry_after_s = retry_after_s


@dataclass(frozen=True)
class SpendRow:
    chain_id: int
    escrow: str
    receipt_id: str
    seq: int
    ts: int
    channel_id: str
    depositor: str
    token: str
    amount_units: int
    deadline: int
    channel_nonce: int
    calldata_keccak: str
    to_addr: str
    gas_limit: int
    hub_gas_hint: int
    max_fee_wei: int
    account_nonce: int
    from_addr: str
    state: str
    tx_hash: str
    fee_wei_spent: int
    dead_reason: str

    def semantic_tuple(self) -> tuple:
        """What "the same request" means: never gas, never the body, never the fee."""
        return (self.to_addr, self.channel_id, self.amount_units, self.receipt_id,
                self.calldata_keccak)


def _row_hash(prev: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "0x" + keccak(prev.encode() + canonical).hex()


# Fields the spend chain protects: the ones that must never change for a given receipt —
# who, how much, on what channel, under whose signature. Deliberately NOT the per-attempt
# parameters (state, account_nonce, gas, fee, tx_hash): a released attempt is legitimately
# retried with a fresh nonce and a fresh gas estimate, and hashing those made a lawful retry
# indistinguishable from tampering. Every attempt is recorded in `tx_attempt` and every
# transition in the audit chain, which IS linear and IS verified.
_CHAINED_FIELDS = (
    "chain_id", "escrow", "receipt_id", "seq", "ts", "channel_id", "depositor", "token",
    "amount_units", "deadline", "channel_nonce", "calldata_keccak", "to_addr", "from_addr",
)


def _spend_payload(row) -> dict:
    """The chained subset, from a dict or a sqlite3.Row."""
    return {k: row[k] for k in _CHAINED_FIELDS}


class Ledger:
    def __init__(self, path: str, *, clock=time.time, witness_path: str = ""):
        self.path = path
        self._clock = clock
        self.witness_path = witness_path
        # check_same_thread=False + one mutex, rather than a connection per thread: the
        # service is serial by design (one signature, one nonce, one in-flight transaction),
        # so the honest model is a single connection that only one caller may touch at a
        # time. Without the flag the connection is bound to the thread that opened it, which
        # breaks the moment the HTTP server serves from anywhere but main — found by the
        # wire test, where the server runs in a background thread.
        self._lock = threading.RLock()
        try:
            self.db = sqlite3.connect(path, timeout=5.0, isolation_level=None,
                                      check_same_thread=False)
        except sqlite3.Error as exc:
            raise LedgerUnavailable(type(exc).__name__) from None
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA journal_mode = WAL")
            self.db.execute("PRAGMA synchronous = FULL")
            self.db.execute("PRAGMA busy_timeout = 5000")
            self.db.executescript(SCHEMA)
            self.db.execute(
                "INSERT OR IGNORE INTO clock_guard(id, max_ts, max_seq) VALUES (1, 0, 0)")
            for name in ("spend", "audit"):
                self.db.execute(
                    "INSERT OR IGNORE INTO chain_head(name, head) VALUES (?, '0x00')", (name,))
        except sqlite3.Error as exc:
            raise LedgerUnavailable(type(exc).__name__) from None

    # ── clock + sequence ──────────────────────────────────────────────────────────

    def _guard(self) -> sqlite3.Row:
        return self.db.execute("SELECT * FROM clock_guard WHERE id = 1").fetchone()

    @property
    def halted(self) -> str:
        row = self._guard()
        return row["halt_reason"] if row["halted"] else ""

    def halt(self, reason: str) -> None:
        self.db.execute(
            "UPDATE clock_guard SET halted = 1, halt_reason = ? WHERE id = 1", (reason,))

    def clear_halt(self) -> None:
        """Operator action only — never called on a request path."""
        self.db.execute("UPDATE clock_guard SET halted = 0, halt_reason = '' WHERE id = 1")

    def now(self) -> int:
        """The signer's own clock, the same one the monotonicity guard watches. Read
        through here rather than `time.time()` so a test can pin it and a caller cannot
        accidentally compare a chain timestamp against an unguarded wall clock."""
        return int(self._clock())

    def assert_clock_sane(self) -> None:
        """R25 — halt on a backwards clock BEFORE any transaction is open.

        ``tick`` also detects it, but ``tick`` runs inside the reservation's
        ``BEGIN IMMEDIATE`` — so the halt it wrote was rolled back by the very handler that
        caught the exception, leaving one request refused and the service still armed. The
        halt has to be committed outside that transaction to mean anything.
        """
        with self._lock:
            row = self._guard()
            wall = int(self._clock())
            if wall < row["max_ts"] - CLOCK_TOLERANCE_S:
                self.halt(f"clock regression: wall={wall} max_ts={row['max_ts']}")
                raise ClockRegression(
                    f"wall clock is {row['max_ts'] - wall}s behind the ledger")

    def tick(self) -> tuple:
        """Allocate ``(seq, ts)``. ``ts`` never moves backwards; a big step back halts.

        A frozen or slow clock is tolerated (rows share a timestamp, ``seq`` still orders
        them) because the alternative — trusting the wall clock — lets 24h windows be
        emptied on demand.
        """
        with self._lock:
            row = self._guard()
            wall = int(self._clock())
            if wall < row["max_ts"] - CLOCK_TOLERANCE_S:
                self.halt(f"clock regression: wall={wall} max_ts={row['max_ts']}")
                raise ClockRegression(f"wall clock is {row['max_ts'] - wall}s behind the ledger")
            ts = max(wall, row["max_ts"])
            seq = row["max_seq"] + 1
            self.db.execute("UPDATE clock_guard SET max_ts = ?, max_seq = ? WHERE id = 1", (ts, seq))
            return seq, ts

        # ── audit (every request, accepted or refused) ─────────────────────────────────

    def audit(self, **fields) -> None:
        """Append one row to the decision log. Every request, accepted or refused.

        The hash is computed over the values that are actually stored, not over the caller's
        kwargs: coercing on the way in and hashing on the way out is how a chain ends up
        unverifiable one row after the first defaulted field.
        """
        with self._lock:
            seq, ts = self.tick()
            head = self.db.execute("SELECT head FROM chain_head WHERE name='audit'").fetchone()["head"]
            record = {
                "ts": ts,
                "kind": str(fields.get("kind") or "request"),
                "decision": str(fields.get("decision") or "refused"),
                "http_status": int(fields.get("http_status") or 0),
                "reason_code": str(fields.get("reason_code") or ""),
                "chain_id": fields.get("chain_id"),
                "escrow": fields.get("escrow"),
                "receipt_id": fields.get("receipt_id"),
                "channel_id": fields.get("channel_id"),
                "amount_units": fields.get("amount_units"),
                "digest16": str(fields.get("digest16") or ""),
                "tx_hash": str(fields.get("tx_hash") or ""),
            }
            row_hash = _row_hash(head, record)
            self.db.execute(
                "INSERT INTO audit(ts, kind, decision, http_status, reason_code, chain_id, escrow,"
                " receipt_id, channel_id, amount_units, digest16, tx_hash, prev_hash, row_hash)"
                " VALUES (:ts,:kind,:decision,:http_status,:reason_code,:chain_id,:escrow,"
                " :receipt_id,:channel_id,:amount_units,:digest16,:tx_hash,:prev,:row_hash)",
                dict(record, prev=head, row_hash=row_hash))
            self.db.execute("UPDATE chain_head SET head = ? WHERE name='audit'", (row_hash,))
            self._witness("audit", row_hash)

    def _witness(self, name: str, head: str) -> None:
        """Append the chain head where a compromise of this host cannot rewrite history.

        Best-effort by design: a witness that can block signing becomes an availability
        weapon. A missing witness is a logged degradation, not a refusal.
        """
        path = self.witness_path
        if not path:
            return
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({"chain": name, "head": head, "ts": int(self._clock())}) + "\n")
        except OSError:
            pass

    # ── window totals ─────────────────────────────────────────────────────────────

    def window_units(self, chain_id: int, escrow: str, token: str, since_ts: int) -> int:
        row = self.db.execute(
            "SELECT COALESCE(SUM(amount_units), 0) AS total FROM spend"
            " WHERE chain_id=? AND escrow=? AND token=? AND ts > ?"
            f" AND state IN {COUNTED}",
            (chain_id, escrow, token, since_ts)).fetchone()
        return int(row["total"])

    def window_count(self, chain_id: int, escrow: str, since_ts: int) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) AS n FROM spend WHERE chain_id=? AND escrow=? AND ts > ?"
            f" AND state IN {COUNTED}", (chain_id, escrow, since_ts)).fetchone()
        return int(row["n"])

    def channel_units(self, chain_id: int, escrow: str, channel_id: str, since_ts: int) -> int:
        row = self.db.execute(
            "SELECT COALESCE(SUM(amount_units), 0) AS total FROM spend"
            " WHERE chain_id=? AND escrow=? AND channel_id=? AND ts > ?"
            f" AND state IN {COUNTED}",
            (chain_id, escrow, channel_id, since_ts)).fetchone()
        return int(row["total"])

    def channel_count(self, chain_id: int, escrow: str, channel_id: str, since_ts: int) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) AS n FROM spend WHERE chain_id=? AND escrow=? AND channel_id=?"
            f" AND ts > ? AND state IN {COUNTED}",
            (chain_id, escrow, channel_id, since_ts)).fetchone()
        return int(row["n"])

    def distinct_channels(self, chain_id: int, escrow: str, since_ts: int) -> int:
        row = self.db.execute(
            "SELECT COUNT(DISTINCT channel_id) AS n FROM spend WHERE chain_id=? AND escrow=?"
            f" AND ts > ? AND state IN {COUNTED}", (chain_id, escrow, since_ts)).fetchone()
        return int(row["n"])

    def fee_wei_window(self, chain_id: int, escrow: str, since_ts: int) -> int:
        """Committed fee exposure: spent where known, otherwise the ceiling we authorised.

        Counting only ``fee_wei_spent`` would let an attacker reserve unbounded gas cost as
        long as nothing had mined yet — the ETH float is a separate drain from the USDC.
        """
        row = self.db.execute(
            "SELECT COALESCE(SUM(CASE WHEN fee_wei_spent > 0 THEN fee_wei_spent"
            "  ELSE max_fee_wei * gas_limit END), 0) AS total FROM spend"
            f" WHERE chain_id=? AND escrow=? AND ts > ? AND state IN {COUNTED}",
            (chain_id, escrow, since_ts)).fetchone()
        return int(row["total"])

    # ── rows ──────────────────────────────────────────────────────────────────────

    def get(self, chain_id: int, escrow: str, receipt_id: str):
        row = self.db.execute(
            "SELECT * FROM spend WHERE chain_id=? AND escrow=? AND receipt_id=?",
            (chain_id, escrow, receipt_id)).fetchone()
        return self._to_row(row) if row else None

    @staticmethod
    def _to_row(row: sqlite3.Row) -> SpendRow:
        return SpendRow(
            chain_id=row["chain_id"], escrow=row["escrow"], receipt_id=row["receipt_id"],
            seq=row["seq"], ts=row["ts"], channel_id=row["channel_id"],
            depositor=row["depositor"], token=row["token"], amount_units=row["amount_units"],
            deadline=row["deadline"], channel_nonce=row["channel_nonce"],
            calldata_keccak=row["calldata_keccak"], to_addr=row["to_addr"],
            gas_limit=row["gas_limit"], hub_gas_hint=row["hub_gas_hint"],
            max_fee_wei=row["max_fee_wei"],
            account_nonce=row["account_nonce"] if row["account_nonce"] is not None else -1,
            from_addr=row["from_addr"], state=row["state"], tx_hash=row["tx_hash"],
            fee_wei_spent=row["fee_wei_spent"], dead_reason=row["dead_reason"],
        )

    def unresolved(self) -> list:
        rows = self.db.execute(
            f"SELECT * FROM spend WHERE state IN {LIVE} ORDER BY seq").fetchall()
        return [self._to_row(r) for r in rows]

    def attempts_for(self, chain_id: int, escrow: str, receipt_id: str) -> list:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM tx_attempt WHERE chain_id=? AND escrow=? AND receipt_id=? ORDER BY seq",
            (chain_id, escrow, receipt_id)).fetchall()]

    # ── the atomic reserve ────────────────────────────────────────────────────────

    def reserve(self, *, caps, chain_id: int, escrow: str, receipt_id: str, channel_id: str,
                depositor: str, token: str, amount_units: int, deadline: int,
                channel_nonce: int, calldata_keccak: str, to_addr: str, gas_limit: int,
                hub_gas_hint: int, max_fee_wei: int, from_addr: str) -> SpendRow:
        """R20 — check every window, insert the row and allocate the nonce in one transaction.

        Raises :class:`CapBreach` naming the first window that would be exceeded, or
        ``CapBreach('cap_race')`` when the guarded INSERT loses to a concurrent writer —
        the read below is advisory, the INSERT's WHERE clause is authoritative.
        """
        if amount_units <= 0:
            raise ValueError("amount_units must be positive")
        # The mutex makes the advisory read below and the guarded INSERT one critical section
        # in-process; the INSERT's WHERE clause still guards against any other writer.
        self._lock.acquire()
        try:
            self.assert_clock_sane()
        except ClockRegression:
            self._lock.release()
            raise
        now = int(self._clock())
        cut_10m, cut_1h, cut_24h = now - 600, now - 3600, now - 86_400

        checks = (
            ("cap_units_per_tx", caps.units_per_tx, amount_units, 0),
            ("cap_units_10m", caps.units_10m, amount_units,
             self.window_units(chain_id, escrow, token, cut_10m)),
            ("cap_units_1h", caps.units_1h, amount_units,
             self.window_units(chain_id, escrow, token, cut_1h)),
            ("cap_units_24h", caps.units_24h, amount_units,
             self.window_units(chain_id, escrow, token, cut_24h)),
            ("cap_units_channel_24h", caps.units_channel_24h, amount_units,
             self.channel_units(chain_id, escrow, channel_id, cut_24h)),
            ("cap_tx_1h", caps.tx_1h, 1, self.window_count(chain_id, escrow, cut_1h)),
            ("cap_tx_24h", caps.tx_24h, 1, self.window_count(chain_id, escrow, cut_24h)),
            ("cap_tx_per_channel_24h", caps.tx_per_channel_24h, 1,
             self.channel_count(chain_id, escrow, channel_id, cut_24h)),
            ("cap_fee_wei_24h", caps.fee_wei_24h, max_fee_wei * gas_limit,
             self.fee_wei_window(chain_id, escrow, cut_24h)),
        )
        for name, limit, adding, existing in checks:
            if limit != -1 and existing + adding > limit:
                self._lock.release()
                raise CapBreach(name)

        if caps.distinct_channels_24h != -1:
            seen = self.distinct_channels(chain_id, escrow, cut_24h)
            fresh = self.channel_count(chain_id, escrow, channel_id, cut_24h) == 0
            if fresh and seen + 1 > caps.distinct_channels_24h:
                self._lock.release()
                raise CapBreach("cap_distinct_channels_24h")

        # A previous attempt that provably never landed leaves a `dead` row, and the primary
        # key is the receipt — so a plain INSERT hits it and the debit can never be retried.
        # That is a permanent jam of my own making: R21 releases a reservation whose simulation
        # failed precisely so the work can be attempted again. A matching dead row is therefore
        # REVIVED in place (same receipt, same amount, fresh nonce) rather than duplicated.
        # Found on 2026-08-24, when a transient RPC failure during simulate made a real $0.01
        # debit unsubmittable forever.
        existing = self.get(chain_id, escrow, receipt_id)
        revive = existing is not None and existing.state == "dead"
        if existing is not None and not revive:
            self._lock.release()
            raise LedgerUnavailable(
                f"a row for this receipt already exists in state {existing.state!r}; "
                f"only a dead row may be retried")

        try:
            self.db.execute("BEGIN IMMEDIATE")
            seq, ts = self.tick()
            self.db.execute(
                "INSERT OR IGNORE INTO nonce_alloc(chain_id, from_addr, next_nonce, updated_seq)"
                " VALUES (?,?,?,?)", (chain_id, from_addr, 0, seq))
            nonce_row = self.db.execute(
                "SELECT next_nonce FROM nonce_alloc WHERE chain_id=? AND from_addr=?",
                (chain_id, from_addr)).fetchone()
            account_nonce = int(nonce_row["next_nonce"])
            head = self.db.execute(
                "SELECT head FROM chain_head WHERE name='spend'").fetchone()["head"]
            payload = {
                "chain_id": chain_id, "escrow": escrow, "receipt_id": receipt_id, "seq": seq,
                "ts": ts, "channel_id": channel_id, "depositor": depositor, "token": token,
                "amount_units": amount_units, "deadline": deadline,
                "channel_nonce": channel_nonce, "calldata_keccak": calldata_keccak,
                "to_addr": to_addr, "gas_limit": gas_limit, "hub_gas_hint": hub_gas_hint,
                "max_fee_wei": max_fee_wei, "account_nonce": account_nonce,
                "from_addr": from_addr, "state": "reserved",
            }
            row_hash = _row_hash(head, _spend_payload(payload))
            if revive:
                # Same receipt, same amount: only the attempt is new. `amount_units` is still
                # never rewritten, so the immutability the window sums depend on holds.
                cursor = self.db.execute(
                    # seq and ts stay as first written: they are what the chain walks, and a
                    # retry is a new attempt on the same row, not a new row.
                    "UPDATE spend SET state = 'reserved',"
                    " account_nonce = :account_nonce, gas_limit = :gas_limit,"
                    " hub_gas_hint = :hub_gas_hint, max_fee_wei = :max_fee_wei,"
                    " tx_hash = '', dead_reason = ''"
                    " WHERE chain_id = :chain_id AND escrow = :escrow"
                    "   AND receipt_id = :receipt_id AND state = 'dead'"
                    "   AND amount_units = :amount_units",
                    dict(payload))
                if cursor.rowcount != 1:
                    self.db.execute("ROLLBACK")
                    self._lock.release()
                    raise LedgerUnavailable(
                        "the dead row changed under us, or its amount does not match")
                self.db.execute(
                    "UPDATE nonce_alloc SET next_nonce = next_nonce + 1, updated_seq = ?"
                    " WHERE chain_id=? AND from_addr=?", (seq, chain_id, from_addr))
                self.db.execute("COMMIT")
                revived = self.get(chain_id, escrow, receipt_id)
                self._lock.release()
                if revived is None:  # pragma: no cover
                    raise LedgerUnavailable("row vanished after revive")
                self.audit(kind="transition", decision="reserved", http_status=0,
                           reason_code="revived after a released attempt", chain_id=chain_id,
                           escrow=escrow, receipt_id=receipt_id, channel_id=channel_id,
                           amount_units=amount_units)
                return revived
            # The WHERE clause re-checks the money windows inside the transaction, so a
            # racing writer cannot slip a second reservation past a total we read earlier.
            cursor = self.db.execute(
                "INSERT INTO spend (chain_id, escrow, receipt_id, seq, ts, channel_id,"
                " depositor, token, amount_units, deadline, channel_nonce, calldata_keccak,"
                " to_addr, gas_limit, hub_gas_hint, max_fee_wei, account_nonce, from_addr,"
                " state, prev_row_hash, row_hash)"
                " SELECT :chain_id, :escrow, :receipt_id, :seq, :ts, :channel_id, :depositor,"
                " :token, :amount_units, :deadline, :channel_nonce, :calldata_keccak,"
                " :to_addr, :gas_limit, :hub_gas_hint, :max_fee_wei, :account_nonce,"
                " :from_addr, 'reserved', :prev, :row_hash"
                " WHERE (:cap_24h = -1 OR (SELECT COALESCE(SUM(amount_units),0) FROM spend"
                "        WHERE chain_id=:chain_id AND escrow=:escrow AND token=:token"
                f"       AND state IN {COUNTED} AND ts > :cut_24h) + :amount_units <= :cap_24h)"
                "   AND (:cap_1h = -1 OR (SELECT COALESCE(SUM(amount_units),0) FROM spend"
                "        WHERE chain_id=:chain_id AND escrow=:escrow AND token=:token"
                f"       AND state IN {COUNTED} AND ts > :cut_1h) + :amount_units <= :cap_1h)"
                "   AND (:cap_10m = -1 OR (SELECT COALESCE(SUM(amount_units),0) FROM spend"
                "        WHERE chain_id=:chain_id AND escrow=:escrow AND token=:token"
                f"       AND state IN {COUNTED} AND ts > :cut_10m) + :amount_units <= :cap_10m)"
                "   AND (:cap_chan = -1 OR (SELECT COALESCE(SUM(amount_units),0) FROM spend"
                "        WHERE chain_id=:chain_id AND escrow=:escrow AND channel_id=:channel_id"
                f"       AND state IN {COUNTED} AND ts > :cut_24h) + :amount_units <= :cap_chan)"
                "   AND (:cap_tx_1h = -1 OR (SELECT COUNT(*) FROM spend"
                "        WHERE chain_id=:chain_id AND escrow=:escrow"
                f"       AND state IN {COUNTED} AND ts > :cut_1h) + 1 <= :cap_tx_1h)"
                "   AND (:cap_tx_24h = -1 OR (SELECT COUNT(*) FROM spend"
                "        WHERE chain_id=:chain_id AND escrow=:escrow"
                f"       AND state IN {COUNTED} AND ts > :cut_24h) + 1 <= :cap_tx_24h)",
                dict(payload, prev=head, row_hash=row_hash,
                     cap_24h=caps.units_24h, cap_1h=caps.units_1h, cap_10m=caps.units_10m,
                     cap_chan=caps.units_channel_24h, cap_tx_1h=caps.tx_1h,
                     cap_tx_24h=caps.tx_24h, cut_10m=cut_10m, cut_1h=cut_1h, cut_24h=cut_24h),
            )
            if cursor.rowcount != 1:
                self.db.execute("ROLLBACK")
                raise CapBreach("cap_race")
            self.db.execute(
                "UPDATE nonce_alloc SET next_nonce = next_nonce + 1, updated_seq = ?"
                " WHERE chain_id=? AND from_addr=?", (seq, chain_id, from_addr))
            self.db.execute("UPDATE chain_head SET head = ? WHERE name='spend'", (row_hash,))
            self.db.execute("COMMIT")
        except CapBreach:
            self._lock.release()
            raise
        except (sqlite3.Error, ClockRegression) as exc:
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._lock.release()
            if isinstance(exc, ClockRegression):
                raise
            # sqlite's own message names the constraint or the malformed statement, and it
            # contains no request data — the values are bound parameters, not text. Dropping it
            # in favour of the class name made a reservation failure undiagnosable.
            raise LedgerUnavailable(f"{type(exc).__name__}: {exc}") from None
        finally_row = self.get(chain_id, escrow, receipt_id)
        self._lock.release()
        if finally_row is None:  # pragma: no cover - the INSERT above committed
            raise LedgerUnavailable("row vanished after commit")
        return finally_row

    def gas_only_count(self, chain_id: int, escrow: str, since_ts: int) -> int:
        """How many gas-only calls this key has made in a window.

        Gas-only rows are exactly the ones with `amount_units = 0`: nothing else in this
        ledger writes a zero amount, because `reserve` refuses one.
        """
        row = self.db.execute(
            "SELECT COUNT(*) AS n FROM spend WHERE chain_id=? AND escrow=?"
            f" AND amount_units = 0 AND state IN {COUNTED} AND ts > ?",
            (chain_id, escrow, since_ts)).fetchone()
        return int(row["n"] or 0)

    def reserve_gas_only(self, *, caps, chain_id: int, escrow: str, receipt_id: str,
                         channel_id: str, calldata_keccak: str, to_addr: str,
                         gas_limit: int, max_fee_wei: int, from_addr: str,
                         max_per_24h: int) -> SpendRow:
        """R28 — a reservation for a call that moves no tokens, only gas.

        `reserve` refuses `amount_units <= 0` on purpose: every window it guards is
        denominated in token units, and a zero-amount row would consume none of them while
        still holding a nonce. `expireChannel` is exactly that shape — no amount argument
        exists in the call — so it gets its own door with its own limit.

        What is deliberately shared with the money path: the nonce allocator (two doors
        handing out the same account nonce would replace each other's transactions), the
        clock guard, the hash chain, and the fee window — gas is spent from the same
        balance, so a runaway sweep must hit `cap_fee_wei_24h` like anything else.
        """
        self._lock.acquire()
        try:
            self.assert_clock_sane()
        except ClockRegression:
            self._lock.release()
            raise
        now = int(self._clock())
        cut_24h = now - 86_400

        if max_per_24h != -1:
            used = self.gas_only_count(chain_id, escrow, cut_24h)
            if used + 1 > max_per_24h:
                self._lock.release()
                raise CapBreach("cap_gas_only_24h")
        if caps.fee_wei_24h != -1:
            spent = self.fee_wei_window(chain_id, escrow, cut_24h)
            if spent + max_fee_wei * gas_limit > caps.fee_wei_24h:
                self._lock.release()
                raise CapBreach("cap_fee_wei_24h")

        existing = self.get(chain_id, escrow, receipt_id)
        revive = existing is not None and existing.state == "dead"
        if existing is not None and not revive:
            self._lock.release()
            raise LedgerUnavailable(
                f"a row for this key already exists in state {existing.state!r}; "
                f"only a dead row may be retried")

        try:
            self.db.execute("BEGIN IMMEDIATE")
            seq, ts = self.tick()
            self.db.execute(
                "INSERT OR IGNORE INTO nonce_alloc(chain_id, from_addr, next_nonce, updated_seq)"
                " VALUES (?,?,?,?)", (chain_id, from_addr, 0, seq))
            nonce_row = self.db.execute(
                "SELECT next_nonce FROM nonce_alloc WHERE chain_id=? AND from_addr=?",
                (chain_id, from_addr)).fetchone()
            account_nonce = int(nonce_row["next_nonce"])
            head = self.db.execute(
                "SELECT head FROM chain_head WHERE name='spend'").fetchone()["head"]
            payload = {
                "chain_id": chain_id, "escrow": escrow, "receipt_id": receipt_id, "seq": seq,
                "ts": ts, "channel_id": channel_id, "depositor": "", "token": "",
                "amount_units": 0, "deadline": 0, "channel_nonce": 0,
                "calldata_keccak": calldata_keccak, "to_addr": to_addr,
                "gas_limit": gas_limit, "hub_gas_hint": 0, "max_fee_wei": max_fee_wei,
                "account_nonce": account_nonce, "from_addr": from_addr, "state": "reserved",
            }
            row_hash = _row_hash(head, _spend_payload(payload))
            if revive:
                cursor = self.db.execute(
                    "UPDATE spend SET state = 'reserved',"
                    " account_nonce = :account_nonce, gas_limit = :gas_limit,"
                    " max_fee_wei = :max_fee_wei, tx_hash = '', dead_reason = ''"
                    " WHERE chain_id = :chain_id AND escrow = :escrow"
                    "   AND receipt_id = :receipt_id AND state = 'dead'"
                    "   AND amount_units = 0",
                    dict(payload))
                if cursor.rowcount != 1:
                    self.db.execute("ROLLBACK")
                    self._lock.release()
                    raise LedgerUnavailable("the dead row changed under us")
            else:
                # The count cap is re-checked inside the transaction, so a racing writer
                # cannot slip a second gas-only call past a total read a moment ago.
                cursor = self.db.execute(
                    "INSERT INTO spend (chain_id, escrow, receipt_id, seq, ts, channel_id,"
                    " depositor, token, amount_units, deadline, channel_nonce,"
                    " calldata_keccak, to_addr, gas_limit, hub_gas_hint, max_fee_wei,"
                    " account_nonce, from_addr, state, prev_row_hash, row_hash)"
                    " SELECT :chain_id, :escrow, :receipt_id, :seq, :ts, :channel_id,"
                    " :depositor, :token, 0, :deadline, :channel_nonce, :calldata_keccak,"
                    " :to_addr, :gas_limit, :hub_gas_hint, :max_fee_wei, :account_nonce,"
                    " :from_addr, 'reserved', :prev, :row_hash"
                    " WHERE (:cap = -1 OR (SELECT COUNT(*) FROM spend"
                    "        WHERE chain_id=:chain_id AND escrow=:escrow"
                    f"       AND amount_units = 0 AND state IN {COUNTED}"
                    "        AND ts > :cut_24h) + 1 <= :cap)",
                    dict(payload, prev=head, row_hash=row_hash, cap=max_per_24h,
                         cut_24h=cut_24h))
                if cursor.rowcount != 1:
                    self.db.execute("ROLLBACK")
                    self._lock.release()
                    raise CapBreach("cap_race")
                self.db.execute("UPDATE chain_head SET head = ? WHERE name='spend'",
                                (row_hash,))
            self.db.execute(
                "UPDATE nonce_alloc SET next_nonce = next_nonce + 1, updated_seq = ?"
                " WHERE chain_id=? AND from_addr=?", (seq, chain_id, from_addr))
            self.db.execute("COMMIT")
        except (CapBreach, LedgerUnavailable):
            self._lock.release()
            raise
        except (sqlite3.Error, ClockRegression) as exc:
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._lock.release()
            if isinstance(exc, ClockRegression):
                raise
            raise LedgerUnavailable(f"{type(exc).__name__}: {exc}") from None
        row = self.get(chain_id, escrow, receipt_id)
        self._lock.release()
        if row is None:  # pragma: no cover
            raise LedgerUnavailable("row vanished after commit")
        self.audit(kind="transition", decision="reserved", http_status=0,
                   reason_code="gas-only call reserved", chain_id=chain_id, escrow=escrow,
                   receipt_id=receipt_id, channel_id=channel_id, amount_units=0)
        return row

    # ── state transitions (amount_units is never touched) ─────────────────────────

    def _set_state(self, row: SpendRow, state: str, **updates) -> None:
        assignments = ", ".join(f"{k} = :{k}" for k in updates)
        sql = "UPDATE spend SET state = :state"
        if assignments:
            sql += ", " + assignments
        sql += " WHERE chain_id=:chain_id AND escrow=:escrow AND receipt_id=:receipt_id"
        params = dict(updates, state=state, chain_id=row.chain_id, escrow=row.escrow,
                      receipt_id=row.receipt_id)
        self.db.execute(sql, params)
        # The spend row's hash covers the fields that were immutable when it was written
        # (amount, receipt, channel, token, seq, ts) — deliberately not `state`, because a
        # linear chain cannot be re-derived from rows that mutate. Transitions are therefore
        # written into the AUDIT chain, which is linear and verified: a state flipped by hand
        # to free budget leaves no matching transition row, and the two disagree.
        self.audit(kind="transition", decision=state, http_status=0,
                   reason_code=updates.get("dead_reason", ""), chain_id=row.chain_id,
                   escrow=row.escrow, receipt_id=row.receipt_id, channel_id=row.channel_id,
                   amount_units=row.amount_units, tx_hash=updates.get("tx_hash", row.tx_hash))

    def mark_signed(self, row: SpendRow, tx_hash: str, raw_keccak: str) -> None:
        self._set_state(row, "signed", tx_hash=tx_hash)
        seq, ts = self.tick()
        self.db.execute(
            "INSERT OR REPLACE INTO tx_attempt(tx_hash, chain_id, escrow, receipt_id,"
            " account_nonce, raw_keccak, max_fee_wei, sent_at, seq) VALUES (?,?,?,?,?,?,?,?,?)",
            (tx_hash, row.chain_id, row.escrow, row.receipt_id, row.account_nonce,
             raw_keccak, row.max_fee_wei, ts, seq))

    def mark_broadcast(self, row: SpendRow, tx_hash: str) -> None:
        self._set_state(row, "broadcast", tx_hash=tx_hash)

    def mark_mined(self, row: SpendRow, tx_hash: str = "", fee_wei: int = 0) -> None:
        updates = {}
        if tx_hash:
            updates["tx_hash"] = tx_hash
        if fee_wei:
            updates["fee_wei_spent"] = fee_wei
        self._set_state(row, "mined", **updates)

    # R24 — the only path out of a live row that did not mine. The caller must have proved
    # the deadline passed AND the receipt is unused AND no recorded hash has a receipt.
    def mark_dead(self, row: SpendRow, reason: str) -> None:
        self._set_state(row, "dead", dead_reason=reason)

    def record_attempt_status(self, tx_hash: str, status: str) -> None:
        self.db.execute("UPDATE tx_attempt SET receipt_status = ? WHERE tx_hash = ?",
                        (status, tx_hash))

    def set_next_nonce(self, chain_id: int, from_addr: str, nonce: int) -> None:
        seq, _ = self.tick()
        self.db.execute(
            "INSERT INTO nonce_alloc(chain_id, from_addr, next_nonce, updated_seq)"
            " VALUES (?,?,?,?) ON CONFLICT(chain_id, from_addr) DO UPDATE SET"
            " next_nonce = excluded.next_nonce, updated_seq = excluded.updated_seq",
            (chain_id, from_addr, nonce, seq))

    # ── integrity ─────────────────────────────────────────────────────────────────

    def verify_chains(self) -> None:
        """Recompute both hash chains. A mismatch is a startup refusal, not a warning."""
        head = "0x00"
        for row in self.db.execute("SELECT * FROM spend ORDER BY seq"):
            expected = _row_hash(head, _spend_payload(row))
            if expected != row["row_hash"]:
                raise LedgerUnavailable(
                    f"spend chain broken at seq {row['seq']}: the row was edited after it "
                    f"was written, or a row was removed")
            head = expected
        audit_head = "0x00"
        for row in self.db.execute("SELECT * FROM audit ORDER BY seq"):
            payload = {
                "ts": row["ts"], "kind": row["kind"], "decision": row["decision"],
                "http_status": row["http_status"], "reason_code": row["reason_code"],
                "chain_id": row["chain_id"], "escrow": row["escrow"],
                "receipt_id": row["receipt_id"], "channel_id": row["channel_id"],
                "amount_units": row["amount_units"], "digest16": row["digest16"],
                "tx_hash": row["tx_hash"],
            }
            expected = _row_hash(audit_head, payload)
            if expected != row["row_hash"]:
                raise LedgerUnavailable(f"audit chain broken at seq {row['seq']}")
            audit_head = expected

    def record_boot(self, address: str, chain_id: int, escrow: str, caps_json: str,
                    reconciled: bool) -> None:
        seq, ts = self.tick()
        head = self.db.execute("SELECT head FROM chain_head WHERE name='audit'").fetchone()["head"]
        self.db.execute(
            "INSERT INTO boot(ts, address, chain_id, escrow, caps_json, audit_head, reconciled)"
            " VALUES (?,?,?,?,?,?,?)",
            (ts, address, chain_id, escrow, caps_json, head, 1 if reconciled else 0))

    def stats(self) -> dict:
        now = int(self._clock())
        return {
            "rows": int(self.db.execute("SELECT COUNT(*) AS n FROM spend").fetchone()["n"]),
            "live": len(self.unresolved()),
            "audit_rows": int(self.db.execute("SELECT COUNT(*) AS n FROM audit").fetchone()["n"]),
            "audit_head": self.db.execute(
                "SELECT head FROM chain_head WHERE name='audit'").fetchone()["head"],
            "halted": self.halted,
            "max_ts": int(self._guard()["max_ts"]),
            "now": now,
        }

    def close(self) -> None:
        try:
            self.db.close()
        except sqlite3.Error:
            pass
