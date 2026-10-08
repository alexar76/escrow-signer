"""Compatibility with the client that will actually call us.

These tests import the hub's own ``ExternalSigner`` and drive it against a real socket. A
hand-rolled request would prove that our server matches our idea of the contract; this
proves it matches the code on the other side — including the parts that are easy to get
wrong from the docs, like the client refusing anything that is not a 66-character hash and
raising on any non-2xx.
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
import threading
import urllib.error
import urllib.request

import pytest

HUB = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "aimarket-hub")
HAS_HUB = os.path.isdir(HUB)
if HAS_HUB:
    if HUB not in sys.path:
        sys.path.insert(0, HUB)
    from aimarket_hub.escrow_bridge.errors import SubmissionRefused   # noqa: E402
    from aimarket_hub.escrow_bridge.signer import (                   # noqa: E402
        ExternalSigner, UnsignedTx, _looks_like_tx_hash)
else:
    SubmissionRefused = ExternalSigner = UnsignedTx = None  # type: ignore[misc, assignment]

    def _looks_like_tx_hash(_: str) -> bool:
        return False

pytestmark = pytest.mark.skipif(
    not HAS_HUB,
    reason="aimarket-hub sibling checkout required for wire compatibility tests",
)

from conftest import envelope, sign_debit                          # noqa: E402
from escrow_signer import calldata as cd                           # noqa: E402
from escrow_signer import config as cfg                            # noqa: E402
from escrow_signer.server import make_server                       # noqa: E402


@pytest.fixture
def live(signer):
    """Our service on a real ephemeral port, serving in a background thread."""
    server = make_server(signer, "127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield signer, f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def _client(url: str, token: str = "test-token") -> ExternalSigner:
    return ExternalSigner(url=url + "/sign", token=token, timeout_s=10)


def _tx(signer, call, gas: int = 250_000) -> UnsignedTx:
    return UnsignedTx(to=cfg.ESCROW, data="0x" + cd.encode_debit(call).hex(),
                      chain_id=cfg.CHAIN_ID, gas=gas)


def test_the_real_client_gets_the_hash_we_broadcast(live):
    signer, url = live
    call = sign_debit(signer)
    tx_hash = _client(url).submit(_tx(signer, call))
    assert _looks_like_tx_hash(tx_hash)
    assert signer.rpc.sent == [tx_hash]


def test_a_retry_with_a_different_gas_returns_the_same_hash(live):
    signer, url = live
    call = sign_debit(signer)
    client = _client(url)
    first = client.submit(_tx(signer, call, gas=250_000))
    second = client.submit(_tx(signer, call, gas=318_113))
    assert first == second
    assert len(signer.rpc.sent) == 1


def test_the_client_refuses_when_we_refuse(live):
    signer, url = live
    call = sign_debit(signer, amount=10_001)   # not a whole cent
    with pytest.raises(SubmissionRefused) as exc:
        _client(url).submit(_tx(signer, call))
    # The client reports the status and never invents a hash.
    assert "422" in str(exc.value)
    assert signer.rpc.sent == []


def test_no_token_is_401_and_never_reaches_signing(live):
    signer, url = live
    call = sign_debit(signer)
    with pytest.raises(SubmissionRefused) as exc:
        ExternalSigner(url=url + "/sign", token="", timeout_s=10).submit(_tx(signer, call))
    assert "401" in str(exc.value)
    assert signer.rpc.sent == []


def test_a_wrong_token_is_401(live):
    signer, url = live
    with pytest.raises(SubmissionRefused):
        _client(url, token="not-the-token").submit(_tx(signer, sign_debit(signer)))
    assert signer.rpc.sent == []


@pytest.mark.parametrize("path", ["/sign/", "/Sign", "/sign/extra", "/", "/invoke"])
def test_no_route_ever_redirects(live, path):
    """urllib follows redirects WITH the Authorization header attached, so a 3xx here is a
    token-disclosure primitive. There must be no redirect on any path, slash or not."""
    signer, url = live
    request = urllib.request.Request(
        url + path, data=b'{"transaction":{}}', method="POST",
        headers={"content-type": "application/json", "authorization": "Bearer test-token"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status not in (301, 302, 303, 307, 308), f"{path} redirected"
    assert status in (400, 404), f"{path} answered {status}"


def test_body_over_the_cap_is_refused_even_with_a_lying_length(live):
    signer, url = live
    payload = b'{"transaction":{"to":"0x0","data":"0x' + b"00" * 6000 + b'","chainId":8453,' \
              b'"gas":1,"value":0}}'
    assert len(payload) > cfg.MAX_BODY_BYTES
    request = urllib.request.Request(
        url + "/sign", data=payload, method="POST",
        headers={"content-type": "application/json", "authorization": "Bearer test-token",
                 "content-length": "120"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read()
    # Either the size cap fires, or the truncated read fails to parse — never a signature.
    assert status in (400, 413), (status, body[:100])
    assert signer.rpc.sent == []


def test_health_needs_no_auth_writes_nothing_and_names_the_address(live):
    signer, url = live
    before = signer.ledger.stats()
    with urllib.request.urlopen(url + "/health", timeout=10) as response:
        body = json.loads(response.read())
    assert body["address"] == signer.address
    assert body["chain_id"] == cfg.CHAIN_ID and body["escrow"] == cfg.ESCROW
    after = signer.ledger.stats()
    assert (after["audit_rows"], after["max_ts"]) == (before["audit_rows"], before["max_ts"])


def test_receipt_route_is_the_authoritative_view(live):
    signer, url = live
    call = sign_debit(signer)
    tx_hash = _client(url).submit(_tx(signer, call))
    receipt_id = "0x" + call.receipt_id.hex()
    with urllib.request.urlopen(url + "/receipt/" + receipt_id, timeout=10) as response:
        body = json.loads(response.read())
    assert body["tx_hash"] == tx_hash and body["state"] == "broadcast"
    try:
        urllib.request.urlopen(url + "/receipt/0x" + "ff" * 32, timeout=10)
        raise AssertionError("an unknown receipt must 404")
    except urllib.error.HTTPError as exc:
        assert exc.code == 404


def test_logs_never_contain_the_signature_the_token_or_the_key(live, caplog):
    """Executable log hygiene, not a review item."""
    signer, url = live
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    log = logging.getLogger("escrow_signer")
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    try:
        good = sign_debit(signer)
        _client(url).submit(_tx(signer, good))
        for bad in (sign_debit(signer, amount=10_001, receipt=b"\x05" * 32),
                    sign_debit(signer, deadline=1, receipt=b"\x06" * 32)):
            try:
                _client(url).submit(_tx(signer, bad))
            except SubmissionRefused:
                pass
        captured = stream.getvalue()
    finally:
        log.removeHandler(handler)

    secrets = [good.signature.hex(), good.signature.hex()[:32], "test-token",
               signer.s.private_key[2:], cd.encode_debit(good).hex()]
    for secret in secrets:
        assert secret not in captured, "a secret reached the log"
    assert "0x" + good.receipt_id.hex() in captured, "the receipt id must be logged"
    assert "digest16" in captured
