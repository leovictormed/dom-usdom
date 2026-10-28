// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IDOMCheckpointVerifier} from "./IDOMCheckpointVerifier.sol";
import {IRiscZeroVerifierV3} from "./IRiscZeroVerifierV3.sol";

/// @title Immutable RISC Zero verifier adapter for DOM checkpoint extensions
/// @notice Binds the checkpoint registry ABI to one chain, one immutable
/// verifier bytecode hash, one RISC Zero Groth16 parameter selector and one
/// guest ImageID. The guest's complete journal is the exact 32-byte checkpoint
/// statement hash; private block, state and consensus witnesses stay private.
contract DOMCheckpointRiscZeroVerifier is IDOMCheckpointVerifier {
    bytes4 public constant RISC_ZERO_GROTH16_V3_SELECTOR = 0x73c457ba;
    /// @notice Reviewed direct verifier deployed by risc0-ethereum v3.0.1.
    address public constant MAINNET_RISC_ZERO_VERIFIER = 0x2a098988600d87650Fb061FfAff08B97149Fa84D;
    bytes32 public constant MAINNET_RISC_ZERO_VERIFIER_CODE_HASH =
        0xfe03c66078969d097f867351171b4639d726c8376c35022675ed44cbbcbaa720;
    /// @notice Four-byte selector plus the eight canonical BN254 proof words.
    uint256 public constant EVM_PROOF_BYTES = 4 + 8 * 32;
    /// @notice Leaves deterministic gas for exact-return checks and the registry
    /// after an upstream verifier failure instead of forwarding the full frame.
    uint256 public constant RISC_ZERO_VERIFIER_GAS_LIMIT = 4_500_000;
    bytes32 public constant PROOF_ACCEPTED = keccak256("DOM_CHECKPOINT_PROOF_V3");
    bytes32 public constant JOURNAL_SCHEMA_HASH = keccak256("raw-statement-hash-32-bytes-v1");
    bytes32 public constant VERIFIER_CONFIG_TYPEHASH = keccak256(
        "DOMCheckpointRiscZeroVerifier(uint256 chainId,address riscZeroVerifier,bytes32 riscZeroVerifierCodeHash,bytes4 verifierSelector,bytes32 imageId,bytes32 journalSchemaHash,bytes32 proofAccepted)"
    );

    IRiscZeroVerifierV3 public immutable riscZeroVerifier;
    bytes32 public immutable riscZeroVerifierCodeHash;
    bytes4 public immutable verifierSelector;
    bytes32 public immutable imageId;
    uint256 public immutable deploymentChainId;
    bytes32 public immutable override verifierConfigHash;

    error InvalidConfiguration();
    error InvalidProof();
    error VerifierChanged();

    constructor(IRiscZeroVerifierV3 verifier_, bytes32 imageId_) {
        address verifierAddress = address(verifier_);
        bytes32 verifierCodeHash = verifierAddress.codehash;
        if (
            verifierAddress.code.length == 0 || verifierCodeHash == bytes32(0) || imageId_ == bytes32(0)
                || verifierAddress == address(this)
        ) revert InvalidConfiguration();
        // Mainnet proof authority is the reviewed direct immutable verifier.
        // A router/proxy can preserve its own code hash while changing delegated
        // implementation state, so selector and arbitrary code-hash binding alone
        // are insufficient for the real-funds chain.
        if (
            block.chainid == 1
                && (verifierAddress != MAINNET_RISC_ZERO_VERIFIER
                    || verifierCodeHash != MAINNET_RISC_ZERO_VERIFIER_CODE_HASH)
        ) revert InvalidConfiguration();

        (bool selectorOk, bytes4 selector) = _readSelector(verifierAddress);
        if (!selectorOk || selector != RISC_ZERO_GROTH16_V3_SELECTOR) revert InvalidConfiguration();

        riscZeroVerifier = verifier_;
        riscZeroVerifierCodeHash = verifierCodeHash;
        verifierSelector = selector;
        imageId = imageId_;
        deploymentChainId = block.chainid;
        verifierConfigHash = keccak256(
            abi.encode(
                VERIFIER_CONFIG_TYPEHASH,
                block.chainid,
                verifierAddress,
                verifierCodeHash,
                selector,
                imageId_,
                JOURNAL_SCHEMA_HASH,
                PROOF_ACCEPTED
            )
        );
    }

    /// @notice SHA-256 commitment expected by RISC Zero for the exact,
    /// unframed 32-byte journal emitted by the checkpoint guest.
    function journalDigest(bytes32 statementHash) public pure returns (bytes32) {
        return sha256(abi.encodePacked(statementHash));
    }

    /// @inheritdoc IDOMCheckpointVerifier
    function verifyDOMCheckpoint(bytes32 statementHash, bytes calldata proof) external view returns (bytes32) {
        if (statementHash == bytes32(0) || proof.length != EVM_PROOF_BYTES || bytes4(proof[:4]) != verifierSelector) {
            revert InvalidProof();
        }
        (bool selectorOk, bytes4 currentSelector) = _readSelector(address(riscZeroVerifier));
        if (
            block.chainid != deploymentChainId || address(riscZeroVerifier).codehash != riscZeroVerifierCodeHash
                || !selectorOk || currentSelector != verifierSelector
        ) revert VerifierChanged();

        _verifyReceipt(proof, journalDigest(statementHash));
        return PROOF_ACCEPTED;
    }

    /// @dev Exact ABI enforcement matters here: `verify` returns nothing, so
    /// any nonempty returndata is an incompatible verifier response. Output is
    /// not copied, which also bounds the effect of a return-data bomb.
    function _verifyReceipt(bytes calldata proof, bytes32 digest) private view {
        bytes memory callData = abi.encodeCall(IRiscZeroVerifierV3.verify, (proof, imageId, digest));
        bool ok;
        uint256 returnSize;
        address target = address(riscZeroVerifier);
        assembly ("memory-safe") {
            ok := staticcall(RISC_ZERO_VERIFIER_GAS_LIMIT, target, add(callData, 32), mload(callData), 0, 0)
            returnSize := returndatasize()
        }
        if (!ok || returnSize != 0) revert InvalidProof();
    }

    /// @dev Copies only one word from an immutable verifier candidate and
    /// rejects noncanonical ABI returndata. The gas cap also bounds return bombs.
    function _readSelector(address verifierAddress) private view returns (bool ok, bytes4 selector) {
        uint32 callSelector = uint32(IRiscZeroVerifierV3.SELECTOR.selector);
        bytes32 word;
        assembly ("memory-safe") {
            let pointer := mload(0x40)
            mstore(pointer, shl(224, callSelector))
            ok := staticcall(50000, verifierAddress, pointer, 4, pointer, 32)
            if iszero(eq(returndatasize(), 32)) { ok := 0 }
            word := mload(pointer)
        }
        // bytes4 ABI words are left-aligned and must have zero right padding.
        // Treat dirty padding as an identity mismatch instead of silently
        // truncating two distinct return words to the same selector.
        ok = ok && (uint256(word) & type(uint224).max) == 0;
        // forge-lint: disable-next-line(unsafe-typecast)
        selector = bytes4(word);
    }
}
