"""RFC 3161 trusted timestamp anchoring over Merkle batch roots."""

from __future__ import annotations

import base64
import logging
from collections.abc import Callable

import requests
from requests.exceptions import RequestException
from rfc3161_client import TimestampRequestBuilder, decode_timestamp_response

logger = logging.getLogger(__name__)


class TsaRequestError(OSError):
    """Raised when the timestamp authority request fails."""


def request_tsa_timestamp(
    root_bytes: bytes,
    *,
    tsa_url: str,
    post_fn: Callable[..., requests.Response] | None = None,
    timeout: float = 30.0,
) -> bytes:
    """Request an RFC 3161 timestamp token for root_bytes from tsa_url."""
    # Resolve requests.post at call time (not as a default arg bound at import)
    # so it stays injectable/patchable — keeps anchoring tests off the network.
    post = post_fn or requests.post
    timestamp_request = TimestampRequestBuilder().data(root_bytes).build()
    try:
        response = post(
            tsa_url,
            data=timestamp_request.as_bytes(),
            headers={"Content-Type": "application/timestamp-query"},
            timeout=timeout,
        )
        response.raise_for_status()
    except RequestException as exc:
        msg = f"TSA request failed: {exc}"
        raise TsaRequestError(msg) from exc

    decode_timestamp_response(response.content)
    return response.content


def encode_token_b64(token_bytes: bytes) -> str:
    return base64.b64encode(token_bytes).decode("ascii")


def decode_token_b64(token_b64: str) -> bytes:
    return base64.b64decode(token_b64.encode("ascii"))
