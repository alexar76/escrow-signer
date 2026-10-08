"""Configuration. Pinned where it must not vary, required where a default would be a hole.

Two rules run through this module:

1. **Compiled-in, not configurable**, for everything whose variation is an attack: the
   chain id, the escrow address, the token, ``value == 0``, the allowed selector. A
   deployment that needs a different escrow gets a different service instance with its own
   key and its own caps — not an environment variable.
2. **Required, not defaulted**, for every cap. A missing, zero, negative or unparseable cap
   is a startup failure. The hub's own ``config._usd_cap`` treats ``0`` as "no limit" and
   swallows a ``ValueError`` into the default; both behaviours turn a typo into an
   unmetered signer, so neither is repeated here. "No limit" must be spelled ``unlimited``
   and is announced at every boot.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# ── Pinned deployment (Base mainnet, docs/onchain-journal.md §2c) ──────────────────
#
# ESCROW moved on 2026-10-08 to AIMarketEscrowV2 (contracts/evm/ESCROW-V2.md: depositor exit
# through requestClose + SETTLE_WINDOW, receipts keyed per channel). Superseded:
# 0x12Db8FAC81E5999D2f2087B79e38951571562CF2 (V1, 2026-09-04 audit redeploy) and before it
# 0x0606983cbEc6D0C12a0B750f72Ceb6032c72C25D (credited the GROSS deposit, not the measured delta).
#
# This address is PINNED here on purpose, not read from the deployment registry: HORKOS is
# the one process holding a key in AIMarketEscrow.authorizedHubs, and `_verify_chain_identity`
# fails CLOSED if the chain id, the domain separator, the hub authorisation or the token
# decimals disagree with these constants. The separator binds the CONTRACT ADDRESS, so a
# mismatch here is not a warning — it stops the signer.
#
# Consequence for a switchover: the hub reads the escrow from
# config/deployments/base-mainnet.json (via generated package data) while HORKOS reads this
# line, so the two must be deployed TOGETHER. Either one alone leaves the hub recording
# channels on one escrow and the signer debiting the other.
CHAIN_ID = 8453
ESCROW = "0xa4cb6ef73B982B847fB06Ec75540d05D0311B2Eb"
TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # Circle USDC on Base
TOKEN_DECIMALS = 6
TX_VALUE = 0

# ── Pinned policy bands ───────────────────────────────────────────────────────────
MAX_BODY_BYTES = 8192
GAS_HARD_CAP = 400_000          # canonical debitChannel measures ~120-160k
GAS_MULTIPLIER_NUM, GAS_MULTIPLIER_DEN = 5, 4  # estimate * 1.25, in integers
MIN_AMOUNT_UNITS = 10_000       # $0.01 — the hub bills in whole cents
MAX_AMOUNT_UNITS = 10_000_000_000  # $10 000 — the escrow's own MAX_DEPOSIT
CENT_UNITS = 10_000
MIN_DEADLINE_SKEW_S = 60
MAX_DEADLINE_TTL_S = 86_400
CHANNEL_MIN_REMAINING_S = 60
# AIMarketEscrowV2.SETTLE_WINDOW (a contract constant): on V2 the hub may still debit for
# this long past expiresAt, and expireChannel reverts until it is over. V1 has no window.
ESCROW_V2_SETTLE_WINDOW_S = 3600
CHAIN_CACHE_TTL_S = 30
CLOCK_REGRESSION_TOLERANCE_S = 5

UNLIMITED = "unlimited"


class ConfigError(RuntimeError):
    """Refuse to start. Never falls back to a permissive default."""


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name, default) or "").strip()


def _required(name: str) -> str:
    value = _env(name)
    if not value:
        raise ConfigError(f"{name} is required and must be non-empty")
    return value


def _cap(name: str) -> int:
    """A cap is required. ``unlimited`` is the only way to switch one off."""
    raw = _env(name)
    if not raw:
        raise ConfigError(
            f"{name} is required. A cap that defaults to something is a cap nobody chose; "
            f"set an integer, or the literal '{UNLIMITED}' to disable this window (it is "
            f"logged at every boot)."
        )
    if raw.lower() == UNLIMITED:
        return -1
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name}={raw!r} is not an integer (or '{UNLIMITED}')") from None
    if value <= 0:
        raise ConfigError(
            f"{name}={value} — zero and negative are not 'no limit' here; use '{UNLIMITED}'"
        )
    return value


@dataclass(frozen=True)
class Caps:
    units_10m: int
    units_1h: int
    units_24h: int
    units_per_tx: int
    units_channel_24h: int
    tx_1h: int
    tx_24h: int
    tx_per_channel_24h: int
    distinct_channels_24h: int
    fee_wei_24h: int

    def as_json(self) -> dict:
        return {
            k: (UNLIMITED if v == -1 else v) for k, v in self.__dict__.items()
        }

    @property
    def unlimited_windows(self) -> list:
        return sorted(k for k, v in self.__dict__.items() if v == -1)


@dataclass(frozen=True)
class Settings:
    bind_host: str
    bind_port: int
    sign_path: str
    token: str
    private_key: str
    db_path: str
    rpc_urls: tuple
    rpc_timeout_s: float
    priority_fee_wei: int
    max_fee_wei_ceiling: int
    caps: Caps
    user_agent: str = "escrow-policy-signer/0.1"
    audit_witness_path: str = ""
    # R32 — how many gas-only calls (`expireChannel`) this key may make per day. Those move
    # no tokens, so none of the `Caps` windows above bite; without a limit of their own a
    # looping sweep could burn the balance on gas alone. -1 disables the limit, 0 refuses
    # every gas-only call, which is how an operator turns the feature off without a deploy.
    max_gas_only_per_24h: int = 24
    # The proceeds sweep (policy.PolicySigner.sweep_proceeds): the escrow pays `usedAmount` to
    # this key's address, which only needs ETH for gas. Empty `sweep_to` = off. The recipient is
    # the operator's decision, fixed here; nothing a caller sends can name another.
    sweep_to: str = ""
    sweep_min_units: int = 1_000_000          # 1.00 USDC: below it the gas is not worth it
    sweep_interval_s: int = 86_400

    def redacted(self) -> dict:
        """For the boot log. No key, no token — not even a prefix of either."""
        return {
            "bind": f"{self.bind_host}:{self.bind_port}",
            "sign_path": self.sign_path,
            "db_path": self.db_path,
            "rpc_endpoints": len(self.rpc_urls),
            "chain_id": CHAIN_ID,
            "escrow": ESCROW,
            "token": TOKEN,
            "gas_hard_cap": GAS_HARD_CAP,
            "priority_fee_wei": self.priority_fee_wei,
            "max_fee_wei_ceiling": self.max_fee_wei_ceiling,
            "caps": self.caps.as_json(),
            "max_gas_only_per_24h": self.max_gas_only_per_24h,
            "sweep_to": self.sweep_to or "off",
            "sweep_min_units": self.sweep_min_units,
            "sweep_interval_s": self.sweep_interval_s,
        }


def load() -> Settings:
    key = _required("SIGNER_PRIVATE_KEY")
    if not key.startswith("0x") or len(key) != 66:
        raise ConfigError("SIGNER_PRIVATE_KEY must be 0x + 64 hex characters")
    path = _env("SIGNER_SIGN_PATH", "/sign")
    if not path.startswith("/") or path.endswith("/") and path != "/":
        raise ConfigError(
            "SIGNER_SIGN_PATH must start with '/' and must not end with one: the hub's "
            "ExternalSigner posts to the configured URL verbatim and this service never "
            "redirects, because urllib would follow a redirect with the bearer token attached"
        )
    urls = tuple(u.strip() for u in _env("SIGNER_RPC_URLS").split(",") if u.strip())
    if not urls:
        raise ConfigError("SIGNER_RPC_URLS is required — this service reads chain itself")
    for url in urls:
        if not url.startswith(("http://", "https://")):
            raise ConfigError(f"SIGNER_RPC_URLS entry {url!r} is not an http(s) URL")
    sweep_to = _env("SIGNER_SWEEP_TO")
    if sweep_to and not re.fullmatch(r"0x[0-9a-fA-F]{40}", sweep_to):
        raise ConfigError("SIGNER_SWEEP_TO must be a 0x address, or empty to keep the sweep off")
    if sweep_to and int(sweep_to, 16) == 0:
        raise ConfigError("SIGNER_SWEEP_TO must not be the zero address")
    sweep_interval_s = int(_env("SIGNER_SWEEP_INTERVAL_S", "86400"))
    if sweep_interval_s < 600:
        raise ConfigError("SIGNER_SWEEP_INTERVAL_S must be at least 600 seconds")
    sweep_min_units = int(_env("SIGNER_SWEEP_MIN_UNITS", "1000000"))
    if sweep_min_units <= 0:
        raise ConfigError("SIGNER_SWEEP_MIN_UNITS must be positive")
    return Settings(
        bind_host=_env("SIGNER_BIND_HOST", "127.0.0.1"),
        bind_port=int(_env("SIGNER_BIND_PORT", "9500")),
        sign_path=path,
        token=_required("SIGNER_TOKEN"),
        private_key=key,
        db_path=_env("SIGNER_DB_PATH", "/var/lib/escrow-signer/signer.db"),
        rpc_urls=urls,
        rpc_timeout_s=float(_env("SIGNER_RPC_TIMEOUT_S", "10")),
        priority_fee_wei=_cap("SIGNER_PRIORITY_FEE_WEI"),
        max_fee_wei_ceiling=_cap("SIGNER_MAX_FEE_WEI_CEILING"),
        audit_witness_path=_env("SIGNER_AUDIT_WITNESS_PATH"),
        max_gas_only_per_24h=int(_env("SIGNER_MAX_GAS_ONLY_PER_24H", "24")),
        sweep_to=sweep_to,
        sweep_min_units=sweep_min_units,
        sweep_interval_s=sweep_interval_s,
        caps=Caps(
            units_10m=_cap("SIGNER_CAP_UNITS_10M"),
            units_1h=_cap("SIGNER_CAP_UNITS_1H"),
            units_24h=_cap("SIGNER_CAP_UNITS_24H"),
            units_per_tx=_cap("SIGNER_CAP_UNITS_PER_TX"),
            units_channel_24h=_cap("SIGNER_CAP_UNITS_CHANNEL_24H"),
            tx_1h=_cap("SIGNER_CAP_TX_1H"),
            tx_24h=_cap("SIGNER_CAP_TX_24H"),
            tx_per_channel_24h=_cap("SIGNER_CAP_TX_PER_CHANNEL_24H"),
            distinct_channels_24h=_cap("SIGNER_CAP_DISTINCT_CHANNELS_24H"),
            fee_wei_24h=_cap("SIGNER_CAP_FEE_WEI_24H"),
        ),
    )
