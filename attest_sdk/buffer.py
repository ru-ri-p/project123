"""Async background flush queue for provenance events (never block the hot path)."""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

FlushKind = Literal["event", "precheck"]


@dataclass(frozen=True)
class FlushItem:
    kind: FlushKind
    payload: dict[str, Any]


class AsyncFlushBuffer:
    """Background worker POSTs queued items to the Attest API."""

    def __init__(
        self,
        *,
        flush_fn: Callable[[FlushItem], None],
        max_queue: int = 10_000,
    ) -> None:
        self._flush_fn = flush_fn
        self._queue: queue.Queue[FlushItem | None] = queue.Queue(maxsize=max_queue)
        self._errors: list[str] = []
        self._lock = threading.Lock()
        self._stopped = False
        self._worker = threading.Thread(target=self._run, name="attest-flush", daemon=True)
        self._worker.start()

    def enqueue(self, item: FlushItem) -> None:
        if self._stopped:
            msg = "buffer is closed"
            raise RuntimeError(msg)
        self._queue.put(item)

    def flush_sync(self, timeout: float = 30.0) -> int:
        """Drain the queue on the calling thread (for tests and shutdown)."""
        drained = 0
        while True:
            try:
                item = self._queue.get(timeout=0.05)
            except queue.Empty:
                break
            if item is None:
                self._queue.task_done()
                break
            try:
                self._flush_fn(item)
                drained += 1
            except Exception as exc:  # noqa: BLE001 — collect flush failures
                with self._lock:
                    self._errors.append(str(exc))
            finally:
                self._queue.task_done()
        return drained

    def close(self, *, wait: bool = True, timeout: float = 30.0) -> None:
        self._stopped = True
        self._queue.put(None)
        if wait and self._worker.is_alive():
            self._worker.join(timeout=timeout)
        self.flush_sync(timeout=timeout)

    @property
    def errors(self) -> list[str]:
        with self._lock:
            return list(self._errors)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                self._flush_fn(item)
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self._errors.append(str(exc))
            finally:
                self._queue.task_done()
