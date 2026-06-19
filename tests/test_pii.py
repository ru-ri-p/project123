"""PII redaction unit tests."""

from app.services.pii import redact_payload, redact_text


def test_redact_emirates_id() -> None:
    text = "Customer ID 784-1990-1234567-1 verified"
    redacted, labels = redact_text(text)
    assert "[REDACTED:emirates_id]" in redacted
    assert "emirates_id" in labels


def test_redact_email_and_phone() -> None:
    text = "Contact ali@example.com or +971501234567"
    redacted, labels = redact_text(text)
    assert "[REDACTED:email]" in redacted
    assert "[REDACTED:phone_ae]" in redacted
    assert "email" in labels
    assert "phone_ae" in labels


def test_redact_payload_nested() -> None:
    payload = {"user": {"note": "Email me at test@bank.ae"}}
    redacted, labels = redact_payload(payload)
    assert "[REDACTED:email]" in redacted["user"]["note"]
    assert "email" in labels
    assert payload["user"]["note"] == "Email me at test@bank.ae"
