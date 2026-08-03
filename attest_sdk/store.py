"""Durable local buffer for events recorded while Attest was unreachable.

Design notes worth knowing:

  * ON DISK, not in memory. Outages and process restarts correlate — a deploy or
    a crash during the incident is exactly when an in-memory queue evaporates.
  * ENCRYPTED. Plaintext AI output must not sit on the customer's disk, in their
    backups, or in a container image layer. Each record is sealed with
    AES-256-GCM under a key held in the state directory at 0600.
  * The encryption protects against disk exposure — snapshots, backups, stray
    copies. It is NOT protection against an attacker who already has the state
    directory: they hold the key too. That is an honest, bounded claim.
  * Records are removed only after Attest confirms it accepted them, so a crash
    mid-flush replays rather than loses. Duplicate submission is preferable to
    silent loss, and the server verifies before recording either way.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_FILE = "buffer.key"
_QUEUE_FILE = "buffer.jsonl"
_NONCE_BYTES = 12


class OfflineStore:
    """Append-only encrypted queue of pending events."""

    def __init__(self, state_dir: Path) -> None:
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / _QUEUE_FILE
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        path = self.dir / _KEY_FILE
        if path.exists():
            return base64.b64decode(path.read_text().strip())
        key = AESGCM.generate_key(bit_length=256)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(base64.b64encode(key).decode("ascii"))
        return key

    # --- queue operations --------------------------------------------------

    def append(self, record: dict[str, Any]) -> None:
        nonce = secrets.token_bytes(_NONCE_BYTES)
        blob = AESGCM(self._key).encrypt(
            nonce, json.dumps(record).encode("utf-8"), b"attest-offline"
        )
        line = base64.b64encode(nonce + blob).decode("ascii")
        # Opened per-append and flushed: a crash loses at most the record being
        # written, never the ones already queued.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                raw = base64.b64decode(line)
                nonce, blob = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
                out.append(
                    json.loads(AESGCM(self._key).decrypt(nonce, blob, b"attest-offline"))
                )
            except Exception:  # noqa: BLE001
                # A corrupt or foreign line must not stall the whole queue; skip
                # it and keep the rest recoverable.
                continue
        return out

    def drop(self, count: int) -> None:
        """Remove the first `count` records — called only after Attest accepts."""
        if not self.path.exists() or count <= 0:
            return
        lines = [line for line in self.path.read_text().splitlines() if line.strip()]
        remaining = lines[count:]
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(remaining) + ("\n" if remaining else ""))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)  # atomic

    def pending(self) -> int:
        return len(self.read_all())

    # --- local chain head --------------------------------------------------

    def chain_state(self) -> tuple[int, str | None]:
        """(next local_seq, previous claim hash) for the local chain."""
        records = self.read_all()
        head = self.dir / "chain.json"
        if records:
            last = records[-1]
            return int(last["local_seq"]) + 1, str(last["claim_hash"])
        if head.exists():
            data = json.loads(head.read_text())
            return int(data.get("next_seq", 1)), data.get("prev_local")
        return 1, None

    def remember_head(self, next_seq: int, prev_local: str | None) -> None:
        """Persist the chain head so it survives the queue being drained.

        Without this the local sequence would restart at 1 after every flush,
        and a gap in the device's chain would be indistinguishable from a
        deletion."""
        (self.dir / "chain.json").write_text(
            json.dumps({"next_seq": next_seq, "prev_local": prev_local})
        )
