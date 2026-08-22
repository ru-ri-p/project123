"""Attest Python SDK — thin HTTP client + thick local precheck + async buffer."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

from .buffer import AsyncFlushBuffer, FlushItem
from .device import DEFAULT_STATE_DIR, DeviceKey
from .gate import GateResult
from .offline import OfflineBundle
from .policy.bundle import PolicyBundle
from .policy.evaluator import needs_server_escalation
from .store import OfflineStore

DEFAULT_SERVER_TIMEOUT = 5.0
ESCALATION_SERVER_TIMEOUT = 30.0


def _configuration_error(exc: Exception) -> dict[str, Any] | None:
    """Return the server's structured complaint if this was a config problem.

    Distinguishes "you have not finished setting up" (409, actionable, must not
    be buffered) from "we could not reach Attest" (buffer it and carry on).
    """
    response = getattr(exc, "response", None)
    if response is None or response.status_code != 409:
        return None
    try:
        detail = response.json().get("detail")
    except ValueError:
        return None
    if isinstance(detail, dict) and detail.get("code"):
        return detail
    return None


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
        offline_enabled: bool = True,
        state_dir: str | Path | None = None,
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
        # Offline resilience is ON by default: an outage must not create a hole
        # in the audit trail, and the safe behaviour should not be opt-in.
        self.offline_enabled = offline_enabled
        self.state_dir = Path(state_dir) if state_dir else DEFAULT_STATE_DIR
        self._device_key: DeviceKey | None = None
        self._store: OfflineStore | None = None
        self._bundle_cache: OfflineBundle | None = None
        self._device_registered = False
        self._prepared = False

    def gate(
        self,
        output: dict[str, Any],
        action: str = "model_completion",
        *,
        trace: str | None = None,
        policy_version: str | None = None,
        remediates: int | None = None,
        on_error: str = "flag",
    ) -> GateResult:
        """Check and log one AI output. This is the whole integration.

        Replaces new_trace + precheck + record_event + sequence bookkeeping with
        a single call. Attest evaluates the output against your policy and any
        jurisdiction rulebooks you have adopted, records both the decision and
        the output as signed, chained events, and returns a verdict.

            result = attest.gate({"output": answer})
            if result.blocked:
                answer = "This response needs review before release."

        Attest never changes your behaviour — read the verdict and decide.

        Args:
            output: the AI output (and any context) to evaluate and record.
            action: what happened, in your own vocabulary.
            trace: omit for a standalone record; pass one to group several steps
                into a single chained story. Sequence numbers are assigned
                server-side, so you never manage them.
            on_error: what to do if Attest is unreachable. "flag" (default)
                returns a result with recorded=False so your application keeps
                serving; "raise" propagates the exception.
        """
        if self.offline_enabled and not self._prepared:
            self._prepared = True
            self.prepare_offline()

        body: dict[str, Any] = {"action": action, "output": output}
        if trace:
            body["trace_id"] = trace
        if policy_version:
            body["policy_version"] = policy_version
        if remediates is not None:
            # Naming the flagged decision this output cures. Requires trace:
            # the fix must land in the same sealed story as the flag. A
            # remediation is never buffered offline — the link must be
            # validated against the real chain, so if Attest is unreachable
            # the caller retries rather than queueing a claim we cannot check.
            body["remediates"] = remediates
        try:
            response = requests.post(
                f"{self.base_url}/v1/gate",
                headers={"x-api-key": self.api_key},
                json=body,
                timeout=self.server_timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            # A configuration problem is NOT an outage. If onboarding is
            # incomplete the server says so explicitly; buffering that would fill
            # the queue with events that can never be replayed, and hide the real
            # problem behind an apparent network fault.
            config_error = _configuration_error(exc)
            if config_error is not None:
                if on_error == "raise":
                    raise
                return GateResult.misconfigured(config_error, trace_id=trace or "")
            if on_error == "raise":
                raise
            if remediates is not None:
                # A remediation claim is only true once the server has checked
                # it against the real chain (right org, right trace, actually
                # flagged). Queueing it unvalidated would let a dead network
                # mint "fixed" links nobody verified — retry when we're back.
                return GateResult.unreachable(exc, trace_id=trace or "")
            if self.offline_enabled:
                # Attest is down; keep serving AND keep the trail.
                return self._gate_offline(action, output, trace)
            return GateResult.unreachable(exc, trace_id=trace or "")
        data: dict[str, Any] = response.json()
        # Back up: hand over anything buffered during the outage we just left.
        self._drain_offline()
        return GateResult.from_response(data)

    # --- offline resilience ------------------------------------------------

    def _gate_offline(
        self, action: str, output: dict[str, Any], trace: str | None
    ) -> GateResult:
        """Evaluate locally, sign the claim, and queue it durably."""
        from .canonical import sha256_hex
        from .offline_envelope import build_offline_claim, offline_claim_hash

        bundle = self._offline_bundle()
        verdict = bundle.evaluate(action, output)

        store = self._offline_store()
        device = self._device()
        local_seq, prev_local = store.chain_state()
        occurred_at = datetime.now(UTC).isoformat()
        claim = build_offline_claim(
            device_id=device.device_id,
            local_seq=local_seq,
            prev_local=prev_local,
            occurred_at=occurred_at,
            action=action,
            payload_hash=sha256_hex(output),
        )
        claim_hash = offline_claim_hash(claim)
        store.append(
            {
                "action": action,
                "output": output,
                "occurred_at": occurred_at,
                "local_seq": local_seq,
                "prev_local": prev_local,
                "payload_hash": claim["payload_hash"],
                "client_signature": device.sign_hex(claim_hash),
                "claim_hash": claim_hash,
                "trace_id": trace,
                "local_status": verdict["status"],
            }
        )
        store.remember_head(local_seq + 1, claim_hash)
        return GateResult.from_offline(verdict, trace_id=trace or "")

    def _drain_offline(self, *, batch: int = 100) -> int:
        """Hand buffered events to Attest. Records are dropped only once accepted."""
        if not self.offline_enabled:
            return 0
        store = self._offline_store()
        pending = store.read_all()
        if not pending:
            return 0
        device = self._device()
        self._ensure_device_registered()

        sent = 0
        while pending:
            chunk, pending = pending[:batch], pending[batch:]
            items = [
                {
                    "action": r["action"],
                    "output": r["output"],
                    "occurred_at": r["occurred_at"],
                    "local_seq": r["local_seq"],
                    "prev_local": r["prev_local"],
                    "payload_hash": r["payload_hash"],
                    "client_signature": r["client_signature"],
                    "trace_id": r.get("trace_id"),
                    "local_status": r.get("local_status"),
                }
                for r in chunk
            ]
            try:
                response = requests.post(
                    f"{self.base_url}/v1/sdk/replay",
                    headers={"x-api-key": self.api_key},
                    json={"device_id": device.device_id, "items": items},
                    timeout=self.server_timeout * 4,
                )
                response.raise_for_status()
            except requests.RequestException:
                break  # still down, or rejected — leave the queue intact and retry later
            store.drop(len(chunk))
            sent += len(chunk)
        return sent

    def flush_offline(self) -> int:
        """Force a replay attempt. Returns how many events Attest accepted."""
        return self._drain_offline()

    @property
    def pending_offline(self) -> int:
        """Events waiting to be handed over. Should be 0 in steady state."""
        if not self.offline_enabled:
            return 0
        return self._offline_store().pending()

    def refresh_offline_bundle(self) -> bool:
        """Cache the rules used if Attest becomes unreachable. Safe to call often."""
        if not self.offline_enabled:
            return False
        try:
            response = requests.get(
                f"{self.base_url}/v1/sdk/bundle",
                headers={"x-api-key": self.api_key},
                timeout=self.server_timeout,
            )
            response.raise_for_status()
        except requests.RequestException:
            return False
        bundle = self._offline_bundle()
        bundle.data = response.json()
        bundle.save()
        return True

    def _device(self) -> DeviceKey:
        if self._device_key is None:
            self._device_key = DeviceKey.load_or_create(self.state_dir)
        return self._device_key

    def _offline_store(self) -> OfflineStore:
        if self._store is None:
            self._store = OfflineStore(self.state_dir)
        return self._store

    def _offline_bundle(self) -> OfflineBundle:
        if self._bundle_cache is None:
            self._bundle_cache = OfflineBundle.load(self.state_dir)
        return self._bundle_cache

    def _ensure_device_registered(self) -> bool:
        if self._device_registered:
            return True
        device = self._device()
        try:
            response = requests.post(
                f"{self.base_url}/v1/sdk/devices",
                headers={"x-api-key": self.api_key},
                json={
                    "device_id": device.device_id,
                    "public_pem": device.public_pem.decode("utf-8"),
                },
                timeout=self.server_timeout,
            )
            response.raise_for_status()
        except requests.RequestException:
            return False
        self._device_registered = True
        return True

    def prepare_offline(self) -> bool:
        """Register this instance and cache the rules, so an outage is survivable.

        Called automatically on the first gate(); call it at startup to be ready
        before the first request rather than after it.
        """
        registered = self._ensure_device_registered()
        refreshed = self.refresh_offline_bundle()
        return registered and refreshed

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

        body: dict[str, Any] = {
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
