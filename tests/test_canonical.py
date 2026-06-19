from app.crypto.canonical import canonical_bytes, sha256_hex


def test_key_order_does_not_change_hash() -> None:
    a = sha256_hex({"b": 2, "a": 1})
    b = sha256_hex({"a": 1, "b": 2})
    assert a == b


def test_unicode_and_arabic_are_stable() -> None:
    obj = {"label": "", "value": 1}
    h1 = sha256_hex(obj)
    h2 = sha256_hex({"value": 1, "label": ""})
    assert h1 == h2
    assert "".encode() in canonical_bytes(obj)


def test_whitespace_is_not_incidental() -> None:
    """Canonical form uses compact separators — no stray spaces."""
    raw = canonical_bytes({"a": 1})
    assert raw == b'{"a":1}'
