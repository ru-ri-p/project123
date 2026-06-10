"""Proves the property the whole product rests on: same meaning -> same
fingerprint; one-character change -> different fingerprint."""

from app.crypto.canonical import canonical_bytes, sha256_hex


def test_key_order_does_not_change_hash():
    # Same data, keys written in a different order -> identical fingerprint.
    a = {"a": 1, "b": 2, "nested": {"x": 10, "y": 20}}
    b = {"b": 2, "nested": {"y": 20, "x": 10}, "a": 1}
    assert sha256_hex(a) == sha256_hex(b)


def test_one_character_change_changes_hash():
    # A single-character difference must produce a different fingerprint.
    a = {"msg": "approved"}
    b = {"msg": "approvee"}
    assert sha256_hex(a) != sha256_hex(b)


def test_arabic_text_hashes_identically_to_itself():
    # Non-ASCII content must canonicalise stably (ensure_ascii=False, UTF-8).
    a = {"note": "تم اعتماد الطلب"}
    b = {"note": "تم اعتماد الطلب"}
    assert canonical_bytes(a) == canonical_bytes(b)
    assert sha256_hex(a) == sha256_hex(b)
