#!/usr/bin/env python3
"""Verify the pinned upstream sources and the sole allowed source modification."""

from __future__ import annotations

import hashlib
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
TREE = REPO / "crates/dom-ethereum-tree-hash"
SSZ = REPO / "crates/dom-ethereum-ssz-types"

TREE_UPSTREAM = {
    "UPSTREAM-README.md": "66a2db8347ad654c4b05f3960a7797fac73a79a0b9b6f23be303d91630bbbb13",
    "src/impls.rs": "86aacc7bc425d4cda0224a51b2f72f0ed1063a061cf8b216f63de59eace2720e",
    "src/lib.rs": "fc11313ae313bb9b2efb44dc179e1ff67c3cebd4afecdd4b2751da2e5c41a16c",
    "src/merkleize_padded.rs": "9215663b49dc53a4130dae7272a8d99afeec65216e9e4fbae2f5d2a80b31f6da",
    "src/merkleize_standard.rs": "5decb662d50caeacf7061ae4b3d2fe38a3382646f417848c7282802a9d161f80",
    "tests/tests.rs": "aa314d61ae3fbf806306439c0963521e66004310d19e99cf7a154377366552bd",
}
TREE_MERKLE_UPSTREAM_DIGEST = "0867ef9105ed2a4b223f2a9f08131db0e34d03a4fb96fbfd9d346e482ded98d9"
SSZ_UPSTREAM = {
    "UPSTREAM-README.md": "af9dd4c1e365f23b20c8e894a4515fd6f87cc60324031be3c7204ba396b00a14",
    "src/fixed_vector.rs": "c3e28a1ef00a7a6c6de09b13ed6bbe35d57e35f80f400c392d9969848ddcb0a3",
    "src/lib.rs": "98a7db15070e1a0fd8d79dfb745de82a3cc2b5663579e127ecf98608bb937a0f",
    "src/serde_utils/hex_fixed_vec.rs": "b1beb136790e1dc81990eda20db29fc6448a23dba163d7913b887431bd7c1a73",
    "src/serde_utils/hex_var_list.rs": "49d26ae1c408b9b71fe72bf48cc376593d69af7cfc4888bd351fd2203398cbfc",
    "src/serde_utils/list_of_hex_fixed_vec.rs": "1e18aa5bc2fd1c02c43e0805052e26499191cff19f0d6debc1d4aadcd7a5a652",
    "src/serde_utils/list_of_hex_var_list.rs": "94f8649352745001ee890f68ac7603e9e512e3879481e8f479e4aced81ca1d8c",
    "src/serde_utils/mod.rs": "73083a94013de1c52207ccffdac10decb16b57567c4663ca395dcabf9840307e",
    "src/serde_utils/quoted_u64_fixed_vec.rs": "b28de06222df40a785af298351899b4ce3aa0aa02753cfec1c001f1c2c86a06f",
    "src/serde_utils/quoted_u64_var_list.rs": "42e2403317114c36ea9da5bee82d462b38949f82d4a940b521636632cbb4afef",
    "src/tree_hash.rs": "254ec1c7d1df38a78c0102e8eea485f9f9a9d4afe93beaab0036040033d097cd",
    "src/variable_list.rs": "4c52cfc725c5702da9e6b53367d240cbbd00934b5e3fd18d9725e25ca72564b7",
}

UPSTREAM_CONTEXT_TEST = '''    /// This test is just to ensure that the stack size of the `Context` remains the same. We choose
    /// our smallvec size based upon this, so it's good to know if it suddenly changes in size.
    #[test]
    fn context_size() {
        assert_eq!(
            mem::size_of::<HalfNode>(),
            232,
            "Halfnode size should be as expected"
        );
    }
'''
LOCAL_CONTEXT_TEST = '''    /// Freeze the stack size of the path-pinned RustCrypto context. The upstream
    /// runtime-dispatch context is larger because it also stores `ring` state.
    /// A change here requires re-evaluating the inline `SmallVec` capacity.
    #[test]
    fn context_size() {
        assert_eq!(
            mem::size_of::<HalfNode>(),
            120,
            "Halfnode size should be as expected"
        );
    }
'''


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def verify_exact(root: Path, expected: dict[str, str]) -> None:
    for relative, expected_digest in expected.items():
        path = root / relative
        if not path.is_file() or digest(path) != expected_digest:
            fail(f"upstream source drift: {path.relative_to(REPO)}")


def main() -> None:
    verify_exact(TREE, TREE_UPSTREAM)
    verify_exact(SSZ, SSZ_UPSTREAM)
    merkle = TREE / "src/merkle_hasher.rs"
    source = merkle.read_text(encoding="utf-8")
    if source.count(LOCAL_CONTEXT_TEST) != 1 or UPSTREAM_CONTEXT_TEST in source:
        fail("tree_hash context-size modification is not exact")
    restored = source.replace(LOCAL_CONTEXT_TEST, UPSTREAM_CONTEXT_TEST)
    if hashlib.sha256(restored.encode()).hexdigest() != TREE_MERKLE_UPSTREAM_DIGEST:
        fail("tree_hash contains a modification outside the frozen context-size test")
    print(
        "PASS: tree_hash 0.10.0 and ssz_types 0.11.0 match their crates.io "
        "sources except the one frozen pure-Rust context-size test"
    )


if __name__ == "__main__":
    main()
