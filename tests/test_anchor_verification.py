"""Offline RFC 3161 anchor verification in the standalone bundle verifier.

Uses a committed, real timestamp token (minted with OpenSSL acting as a test
TSA) so the test is hermetic. Proves the verifier: binds the token to the exact
batch root, trusts it only against a supplied TSA root, and fails closed on a
tampered root or an untrusted root — never raising.
"""

from __future__ import annotations

import base64
import datetime
import importlib.util
import json
from pathlib import Path

import pytest

rfc3161_client = pytest.importorskip("rfc3161_client")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FIX = Path(__file__).resolve().parent / "fixtures" / "anchor"


def _load_verify_module():
    # Load verify.py the way an auditor would run it — as a standalone file.
    verify_path = ROOT / "app" / "bundle" / "verify.py"
    spec = importlib.util.spec_from_file_location("attest_verify", verify_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify = _load_verify_module()
TOKEN_B64 = base64.b64encode((FIX / "token.tsr").read_bytes()).decode("ascii")
ROOT_HEX = json.loads((FIX / "meta.json").read_text())["root_hex"]
CA_PEM = (FIX / "tsa_ca.crt").read_bytes()


def _unrelated_ca_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated Root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_anchor_bound_without_roots() -> None:
    res = verify.verify_anchor(TOKEN_B64, ROOT_HEX, None)
    assert res["status"] == "bound"
    assert res["gen_time"]  # third-party timestamp is readable
    assert res["tsa"]


def test_anchor_trusted_with_correct_root() -> None:
    res = verify.verify_anchor(TOKEN_B64, ROOT_HEX, CA_PEM)
    assert res["status"] == "trusted", res["detail"]


def test_anchor_fails_on_tampered_root() -> None:
    tampered = ("b" + ROOT_HEX[1:])  # different root than the token attests
    res = verify.verify_anchor(TOKEN_B64, tampered, CA_PEM)
    assert res["status"] == "failed"
    assert "imprint" in res["detail"]


def test_anchor_fails_on_untrusted_root() -> None:
    res = verify.verify_anchor(TOKEN_B64, ROOT_HEX, _unrelated_ca_pem())
    assert res["status"] == "failed"


def test_anchor_never_raises_on_garbage_token() -> None:
    res = verify.verify_anchor("not-base64-or-token", ROOT_HEX, CA_PEM)
    assert res["status"] == "failed"
