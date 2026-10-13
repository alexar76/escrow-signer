"""An unauthenticated slow client must not block health checks or signing."""
import concurrent.futures
import json
import socket
import threading
import time
import urllib.request
from types import SimpleNamespace

from escrow_signer.policy import Decision
from escrow_signer.server import make_server


def test_partial_header_does_not_block_health_and_expires():
    signer = SimpleNamespace(ready=True, address="0x" + "00" * 20,
        not_ready_reason="", ledger=SimpleNamespace(halted=False))
    server = make_server(signer, "127.0.0.1", 0)
    server.request_deadline_s = .4
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    first = socket.create_connection(server.server_address, timeout=2)
    try:
        first.sendall(b"GET /health HTTP/1.1\r\nHost: local\r\n")
        url = "http://%s:%s/health" % server.server_address
        with urllib.request.urlopen(url, timeout=.3) as response:
            assert response.status == 200
            assert json.load(response)["ok"]
        assert first.recv(1024) == b""
    finally:
        first.close()
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_signing_stays_serial_with_concurrent_http_clients():
    active = 0
    peak = 0
    count = 0
    def handle(raw):
        nonlocal active, peak, count
        active += 1
        peak = max(peak, active)
        time.sleep(.015)
        count += 1
        active -= 1
        return Decision(status=200, body={"ok": True})
    signer = SimpleNamespace(s=SimpleNamespace(sign_path="/sign"),
        authorized=lambda value: value == "Bearer test", handle=handle,
        ledger=SimpleNamespace(audit=lambda **kw: None))
    server = make_server(signer, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def request(_):
        req = urllib.request.Request("http://%s:%s/sign" % server.server_address,
            data=b"{}", headers={"Authorization": "Bearer test"})
        with urllib.request.urlopen(req, timeout=3) as response:
            assert response.status == 200
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(request, range(8)))
        assert count == 8 and peak == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
