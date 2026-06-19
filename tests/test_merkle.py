"""Merkle tree unit tests."""

from app.crypto.merkle import merkle_proof, merkle_root, verify_merkle_proof


def test_empty_root_is_deterministic() -> None:
    assert merkle_root([]) == merkle_root([])


def test_same_leaves_same_root() -> None:
    leaves = ["aa" * 32, "bb" * 32, "cc" * 32]
    assert merkle_root(leaves) == merkle_root(list(leaves))


def test_changing_one_leaf_changes_root() -> None:
    leaves = ["aa" * 32, "bb" * 32]
    root_a = merkle_root(leaves)
    tampered = ["aa" * 32, "cc" * 32]
    assert merkle_root(tampered) != root_a


def test_odd_leaf_count_duplicates_last() -> None:
    three = merkle_root(["11" * 32, "22" * 32, "33" * 32])
    four = merkle_root(["11" * 32, "22" * 32, "33" * 32, "33" * 32])
    assert three == four


def test_merkle_proof_verifies() -> None:
    leaves = ["aa" * 32, "bb" * 32, "cc" * 32, "dd" * 32]
    root = merkle_root(leaves)
    for index, leaf in enumerate(leaves):
        proof = merkle_proof(leaves, index)
        assert verify_merkle_proof(leaf, index, proof, root) is True

    bad_proof = merkle_proof(leaves, 0)
    assert verify_merkle_proof("ff" * 32, 0, bad_proof, root) is False
