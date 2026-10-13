"""An instance serves one compiled-in escrow, chosen by name — never by address."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _escrow(deployment: str | None) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SIGNER_")}
    if deployment is not None:
        env["SIGNER_DEPLOYMENT"] = deployment
    code = (
        "from escrow_signer import config as c\n"
        "print(c.ESCROW)\n"
        "try:\n    c.load()\nexcept c.ConfigError as e:\n    print('refused:', e)\n"
    )
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)


def test_the_default_is_the_aicom_v2_escrow():
    out = _escrow(None).stdout.splitlines()
    assert out[0] == "0xa4cb6ef73B982B847fB06Ec75540d05D0311B2Eb"


def test_independent_selects_its_own_escrow_by_name():
    out = _escrow("independent").stdout.splitlines()
    assert out[0] == "0x0BFCa46A324fe534Eb6E71c52C8b5AD74B969534"
    # Past the deployment check, the next refusal is the missing key — not the deployment.
    assert "SIGNER_PRIVATE_KEY" in out[1]


def test_an_unknown_deployment_or_an_address_refuses_to_boot():
    for value in ("indep", "0x0BFCa46A324fe534Eb6E71c52C8b5AD74B969534"):
        out = _escrow(value).stdout.splitlines()
        assert out[0] == ""
        assert out[1].startswith("refused:") and "not a compiled-in deployment" in out[1]
