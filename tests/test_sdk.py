"""SDK client tests (mocked HTTP)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from attest_sdk.attest import AttestClient


def test_record_event_posts_to_api() -> None:
    client = AttestClient(api_key="test-key", base_url="http://example.com")
    mock_response = MagicMock()
    mock_response.json.return_value = {"hash": "abc", "signature": "def", "seq": 1}
    mock_response.raise_for_status = MagicMock()

    with patch("attest_sdk.attest.requests.post", return_value=mock_response) as mock_post:
        result = client.record_event("trace-1", 1, "model_completion", {"prompt": "hi"})

    assert result["hash"] == "abc"
    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["headers"]["x-api-key"] == "test-key"
    assert call_kwargs["json"]["trace_id"] == "trace-1"
    assert call_kwargs["json"]["seq"] == 1
