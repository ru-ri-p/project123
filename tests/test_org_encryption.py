"""The 'locked box only the customer can open' crypto core.

Proves: Attest (public key only) can lock a content key but cannot open it; the
org (private key) can; and on approval the org can release exactly one record's
key to a grantee — without ever exposing the master private key."""

from __future__ import annotations

import os

import pytest

from app.crypto.org_encryption import (
    KeyWrappingError,
    generate_wrapping_keypair,
    regrant_key,
    unwrap_key,
    wrap_key,
)


def test_org_can_open_what_attest_locked() -> None:
    org_private, org_public = generate_wrapping_keypair()
    dek = os.urandom(32)  # a content key

    wrapped = wrap_key(org_public, dek)  # Attest locks it (public key only)
    assert wrapped != dek
    assert unwrap_key(org_private, wrapped) == dek  # org opens it (private key)


def test_attest_cannot_open_without_the_org_private_key() -> None:
    _org_private, org_public = generate_wrapping_keypair()
    other_private, _other_public = generate_wrapping_keypair()  # anyone else
    dek = os.urandom(32)

    wrapped = wrap_key(org_public, dek)
    # Attest holds only the public key; nobody else's private key opens it.
    with pytest.raises(KeyWrappingError):
        unwrap_key(other_private, wrapped)


def test_consent_release_of_one_record_to_a_grantee() -> None:
    org_private, org_public = generate_wrapping_keypair()
    grantee_private, grantee_public = generate_wrapping_keypair()  # Attest's ephemeral access key
    dek = os.urandom(32)

    wrapped_for_org = wrap_key(org_public, dek)  # stored, dark to Attest

    # On approval the org re-wraps just this record to the grantee.
    regranted = regrant_key(org_private, wrapped_for_org, grantee_public)

    # The grantee can now open exactly this record.
    assert unwrap_key(grantee_private, regranted) == dek
    # ...but the grantee's key still cannot open the org-wrapped original.
    with pytest.raises(KeyWrappingError):
        unwrap_key(grantee_private, wrapped_for_org)


def test_corrupt_wrapped_key_fails_closed() -> None:
    org_private, org_public = generate_wrapping_keypair()
    wrapped = bytearray(wrap_key(org_public, os.urandom(32)))
    wrapped[-1] ^= 0x01  # tamper
    with pytest.raises(KeyWrappingError):
        unwrap_key(org_private, bytes(wrapped))
