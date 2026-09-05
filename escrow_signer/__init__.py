"""escrow-policy-signer — the only process in the ecosystem that holds a key which is
authorized in ``AIMarketEscrow.authorizedHubs``.

It exists so that the hub does not. The hub proposes a transaction; this service decides
whether that proposal is one of the very few transactions it is willing to put its name on,
and the buyer's own EIP-712 signature — re-verified here against state read from chain, not
from the request — is the actual authority for the amount.

Design rule that outranks every other: a fully compromised hub with a valid bearer token
must not be able to obtain a signature for anything except a canonical ``debitChannel``
call, on one pinned escrow, on one pinned chain, within this service's own spend windows.
"""

__version__ = "0.1.0"
