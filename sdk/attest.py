"""Attest Python SDK — thin HTTP client + thick local precheck + async buffer."""

from __future__ import annotations

import uuid
from typing import Any

import requests

from sdk.buffer import AsyncFlushBuffer, FlushItem
from sdk.policy.bundle import PolicyBundle
from sdk.policy.evaluator import needs_server_escalation

DEFAULT_SERVER_TIMEOUT = 5.0
ESCALATION_SERVER_TIMEOUT = 30.0


class AttestClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "http://localhost:8000",
        *,
        fail_mode: str = "deny_on_error",
        enable_local_precheck: bool = True,
        enable_buffer: bool = False,
        server_timeout: float = DEFAULT_SERVER_TIMEOUT,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.fail_mode = fail_mode
        self.enable_local_precheck = enable_local_precheck
        self.enable_buffer = enable_buffer
        self.server_timeout = server_timeout
        self._bundle: PolicyBundle | None = None
        self._trace_seq: dict[str, int] = {}
        self._buffer: AsyncFlushBuffer | None = None
        if enable_buffer:
            self._buffer = AsyncFlushBuffer(flush_fn=self._flush_item)

    def new_trace(self) -> str:
        return str(uuid.uuid4())

    def next_seq(self, trace_id: str) -> int:
        current = self._trace_seq.get(trace_id, 0)
        return current + 1

    def load_policy_bundle(self, *, force: bool = False) -> PolicyBundle:
        if self._bundle is not None and not force:
            return self._bundle
        try:
            response = requests.get(
                f"{self.base_url}/v1/policies/active",
                headers={"x-api-key": self.api_key},
                timeout=self.server_timeout,
            )
            response.raise_for_status()
            self._bundle = PolicyBundle.from_api_response(
                response.json(),
                fail_mode=self.fail_mode,
            )
        except (requests.RequestException, ValueError, KeyError):
            self._bundle = PolicyBundle.default(fail_mode=self.fail_mode)
        return self._bundle

    def evaluate_local(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Microsecond-scale local policy evaluation (no network)."""
        bundle = self.load_policy_bundle()
        return bundle.evaluate(action, payload).to_dict()

    def precheck_smart(
        self,
        trace_id: str,
        seq: int,
        action: str,
        payload: dict[str, Any],
        policy_version: str | None = None,
        *,
        buffer_policy_decision: bool = False,
    ) -> dict[str, Any]:
        """Local precheck for green/yellow; server escalation for orange/red."""
        self._trace_seq[trace_id] = max(self._trace_seq.get(trace_id, 0), seq)

        if not self.enable_local_precheck:
            return self.precheck(trace_id, seq, action, payload, policy_version)

        bundle = self.load_policy_bundle()
        local = bundle.evaluate(action, payload)

        if needs_server_escalation(local):
            result = self.precheck(trace_id, seq, action, payload, policy_version)
            result["local_only"] = False
            result["escalated"] = True
            return result

        result = local.to_dict()
        result["trace_id"] = trace_id
        result["policy_version"] = bundle.version
        result["local_only"] = True
        result["escalated"] = False
        result.setdefault("approval_id", None)
        result.setdefault("policy_decision_seq", seq)
        result.setdefault("policy_decision_hash", "")

        if buffer_policy_decision and self._buffer is not None:
            self._buffer.enqueue(
                FlushItem(
                    kind="precheck",
                    payload={
                        "trace_id": trace_id,
                        "seq": seq,
                        "action": action,
                        "payload": payload,
                        "policy_version": policy_version,
                    },
                )
            )
            result["policy_decision_buffered"] = True

        return result

    def record_event(
        self,
        trace_id: str,
        seq: int,
        event_type: str,
        payload: dict[str, Any],
        policy_version: str | None = None,
        *,
        buffered: bool | None = None,
    ) -> dict[str, Any]:
        use_buffer = self.enable_buffer if buffered is None else buffered
        self._trace_seq[trace_id] = max(self._trace_seq.get(trace_id, 0), seq)

        body = {
            "trace_id": trace_id,
            "seq": seq,
            "type": event_type,
            "payload": payload,
            "policy_version": policy_version,
        }

        if use_buffer and self._buffer is not None:
            self._buffer.enqueue(FlushItem(kind="event", payload=body))
            return {
                "hash": "",
                "signature": "",
                "seq": seq,
                "prev_hash": "",
                "buffered": True,
            }

        response = requests.post(
            f"{self.base_url}/v1/event",
            headers={"x-api-key": self.api_key},
            json=body,
            timeout=self.server_timeout,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    def precheck(
        self,
        trace_id: str,
        seq: int,
        action: str,
        payload: dict[str, Any],
        policy_version: str | None = None,
    ) -> dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/v1/precheck",
            headers={"x-api-key": self.api_key},
            json={
                "trace_id": trace_id,
                "seq": seq,
                "action": action,
                "payload": payload,
                "policy_version": policy_version,
            },
            timeout=ESCALATION_SERVER_TIMEOUT,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    def workflow_gate(self, trace_id: str) -> dict[str, Any]:
        response = requests.get(
            f"{self.base_url}/v1/trace/{trace_id}/gate",
            headers={"x-api-key": self.api_key},
            timeout=self.server_timeout,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    def resolve_approval(
        self,
        approval_id: str,
        status: str,
        approver_id: str,
        comment: str | None = None,
    ) -> dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/v1/approvals/{approval_id}/resolve",
            headers={"x-api-key": self.api_key},
            json={"status": status, "approver_id": approver_id, "comment": comment},
            timeout=self.server_timeout,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    def mitigate(
        self,
        trace_id: str,
        seq: int,
        mitigation_ids: list[str],
        source_payload: dict[str, Any],
        *,
        policy_decision_seq: int | None = None,
        policy_version: str | None = None,
    ) -> dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/v1/mitigate",
            headers={"x-api-key": self.api_key},
            json={
                "trace_id": trace_id,
                "seq": seq,
                "mitigation_ids": mitigation_ids,
                "source_payload": source_payload,
                "policy_decision_seq": policy_decision_seq,
                "policy_version": policy_version,
            },
            timeout=self.server_timeout,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    def flush(self, *, timeout: float = 30.0) -> int:
        if self._buffer is None:
            return 0
        return self._buffer.flush_sync(timeout=timeout)

    def close(self) -> None:
        if self._buffer is not None:
            self._buffer.close()

    @property
    def buffer_errors(self) -> list[str]:
        if self._buffer is None:
            return []
        return self._buffer.errors

    def _flush_item(self, item: FlushItem) -> None:
        if item.kind == "event":
            response = requests.post(
                f"{self.base_url}/v1/event",
                headers={"x-api-key": self.api_key},
                json=item.payload,
                timeout=self.server_timeout,
            )
            response.raise_for_status()
            return

        if item.kind == "precheck":
            response = requests.post(
                f"{self.base_url}/v1/precheck",
                headers={"x-api-key": self.api_key},
                json=item.payload,
                timeout=ESCALATION_SERVER_TIMEOUT,
            )
            response.raise_for_status()
