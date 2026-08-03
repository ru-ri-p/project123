"""This SDK instance's own signing key — provisioned automatically, invisibly.

Why the SDK has a key at all: when Attest is unreachable, buffered events would
otherwise be nothing but the client's word. Signing them into a local chain means
that when they are grafted in later, Attest can prove they were not edited or
selectively dropped in the meantime.

The customer does nothing. On first run the SDK generates an Ed25519 keypair,
stores it under the state directory with 0600 permissions, and registers the
public half. The private key never leaves the host.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

DEFAULT_STATE_DIR = Path(os.environ.get("ATTEST_STATE_DIR", "~/.attest")).expanduser()
_DEVICE_FILE = "device.json"


class DeviceKey:
    """An Ed25519 keypair identifying one SDK instance."""

    def __init__(self, device_id: str, private_pem: bytes, public_pem: bytes) -> None:
        self.device_id = device_id
        self._private_pem = private_pem
        self.public_pem = public_pem

    # --- persistence -------------------------------------------------------

    @classmethod
    def load_or_create(cls, state_dir: Path | None = None) -> DeviceKey:
        directory = Path(state_dir) if state_dir else DEFAULT_STATE_DIR
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / _DEVICE_FILE

        if path.exists():
            data: dict[str, Any] = json.loads(path.read_text())
            return cls(
                device_id=data["device_id"],
                private_pem=data["private_pem"].encode("utf-8"),
                public_pem=data["public_pem"].encode("utf-8"),
            )

        key = ed25519.Ed25519PrivateKey.generate()
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        # Host name is a convenience label for the dashboard, not an identifier —
        # the random suffix is what makes the id unique.
        try:
            host = socket.gethostname()[:32]
        except Exception:  # noqa: BLE001 — a label is never worth an exception
            host = "host"
        device_id = f"{host}-{secrets.token_hex(8)}"

        payload = json.dumps(
            {
                "device_id": device_id,
                "private_pem": private_pem.decode("utf-8"),
                "public_pem": public_pem.decode("utf-8"),
            }
        )
        # Written 0600 from the outset — never world-readable, not even briefly.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(payload)
        return cls(device_id=device_id, private_pem=private_pem, public_pem=public_pem)

    # --- signing -----------------------------------------------------------

    def sign_hex(self, message_hex: str) -> str:
        key = serialization.load_pem_private_key(self._private_pem, password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            msg = "device key is not Ed25519"
            raise ValueError(msg)
        return key.sign(bytes.fromhex(message_hex)).hex()
