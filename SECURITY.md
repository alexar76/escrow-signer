# Security model

This service holds a private key that is authorized in `AIMarketEscrow.authorizedHubs` on
Base mainnet. Everything below is written so that a reader can check the claims against the
code rather than trust them.

## What the key can do, at most

`debitChannel` moves nothing on its own: it decrements a channel's balance and marks a
receipt used. Value leaves the escrow only in `settleChannel`, which pays `ch.hub` — this
key — and refunds the remainder to the depositor. Every amount is bounded by an EIP-712
signature the **depositor** produced, and the contract binds `msg.sender` into that digest,
so a signature minted for another hub cannot be used here.

The ceiling, therefore, is: *the sum of amounts buyers have already validly signed for, up to
each channel's balance*, minus whatever the velocity caps refuse. It is not the treasury, and
it is not ownership of any contract — those live on a different key that never reaches this
host.

## What the service refuses

One selector, `0xf7becd80`, derived at boot from
`debitChannel(bytes32,uint256,bytes32,uint256,bytes)` and never written down as a literal.
One escrow address, one chain id, `value == 0`, a fixed 292-byte canonical calldata layout
that is decoded strictly and then re-encoded and compared byte for byte. The depositor's
signature is re-verified here, against channel state this process read from its own RPC
endpoints, with **its own address** substituted for the `hub` field.

Refusals are enumerated as R1–R26 in `escrow_signer/policy.py`, `ledger.py` and
`calldata.py`, and every one is exercised by a test that asserts nothing was signed and
nothing was broadcast.

## What it is not protected against

Stated plainly, because a security document that only lists strengths is marketing:

- **A compromised hub can still collect for work it did not do**, up to the caps, using
  signatures buyers really produced. Every field the contract checks is inside the
  depositor's digest, so such a request is indistinguishable from a legitimate one. This
  shrinks with smaller caps, a shorter authorization TTL, and buyers signing per invocation
  instead of in advance. It cannot be closed inside a signer.
- **Receipt burning and nonce grinding cost no USDC** and are therefore invisible to the
  dollar caps. They are bounded only by the count caps (`SIGNER_CAP_TX_*`,
  `SIGNER_CAP_DISTINCT_CHANNELS_24H`).
- **The key is also the payee.** `settleChannel` pays `ch.hub`, so revenue accumulates on
  this address rather than in the treasury. Sweeping it is a separate operator action.
- **A malicious RPC that lies consistently** about channel state. Mitigated only by using
  several endpoints, never the caller's.

## Handling secrets

The bearer token, the private key, the raw calldata and the buyer's signature bytes are
never logged, never returned in a response body, and never placed in a metrics label. Signing
and RPC errors are logged by exception **type** only — an exception can carry the payload, and
the payload is adjacent to the key. There is an executable test for this
(`tests/test_wire.py::test_logs_never_contain_the_signature_the_token_or_the_key`) rather
than a promise.

The service never redirects. `urllib` — which is what the Hub's client uses — follows a
redirect with the `Authorization` header attached, so a 3xx on any route would be a
token-disclosure primitive. A test asserts that no path, with or without a trailing slash,
can answer 301/302/303/307/308.

## Reporting

Open a private security advisory on the repository, or contact the operator directly. Please
include the `digest16` from any log line involved: it identifies a request without revealing
the signature.
