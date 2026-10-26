// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IDOMFinalizedBurnVerifier} from "./USDOMProofReserve.sol";
import {IRiscZeroVerifierV3} from "./IRiscZeroVerifierV3.sol";

/// @title Immutable RISC Zero verifier adapter for finalized native USDOM burns
/// @notice Binds the reserve verifier ABI to one chain, one immutable verifier
/// bytecode hash, one RISC Zero Groth16 parameter selector and one guest ImageID.
/// A successful guest commits the exact 32-byte finalized-burn statement hash as
/// its complete journal; unrelated private witness data is never published here.
contract DOMFinalizedBurnRiscZeroVerifier is IDOMFinalizedBurnVerifier {
    bytes4 public constant RISC_ZERO_GROTH16_V3_SELECTOR = 0x73c457ba;
    /// @notice Reviewed direct verifier deployed by risc0-ethereum v3.0.1.
    address public constant MAINNET_RISC_ZERO_VERIFIER = 0x2a098988600d87650Fb061FfAff08B97149Fa84D;
    bytes32 public constant MAINNET_RISC_ZERO_VERIFIER_CODE_HASH =
        0xfe03c66078969d097f867351171b4639d726c8376c35022675ed44cbbcbaa720;
    /// @notice Four-byte selector plus the eight canonical BN254 proof words.
    uint256 public constant EVM_PROOF_BYTES = 4 + 8 * 32;
    /// @notice Leaves deterministic gas for exact-return checks and the caller
    /// after an upstream verifier failure instead of forwarding the full frame.
    uint256 public constant RISC_ZERO_VERIFIER_GAS_LIMIT = 4_500_000;
    bytes32 public constant PROOF_ACCEPTED = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    bytes32 public constant JOURNAL_SCHEMA_HASH = keccak256("raw-statement-hash-32-bytes-v1");
    bytes32 public constant VERIFIER_CONFIG_TYPEHASH = keccak256(
        "DOMFinalizedBurnRiscZeroVerifier(uint256 chainId,address riscZeroVerifier,bytes32 riscZeroVerifierCodeHash,bytes4 verifierSelector,bytes32 imageId,bytes32 journalSchemaHash,bytes32 proofAccepted)"
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
        // Mainnet proof authority must not be a mutable router/proxy whose own
        // bytecode remains stable while its delegated implementation changes.
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

    /// @notice SHA-256 commitment expected by the RISC Zero verifier for the
    /// guest's exact, unframed 32-byte journal.
    function journalDigest(bytes32 statementHash) public pure returns (bytes32) {
        return sha256(abi.encodePacked(statementHash));
    }

    /// @inheritdoc IDOMFinalizedBurnVerifier
    function verifyFinalizedBurn(bytes32 statementHash, bytes calldata proof) external view returns (bytes32) {
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

    /// @dev The verifier ABI returns no value. A contract that returns `false`,
    /// acceptance magic or oversized data is not ABI-compatible and must not be
    /// interpreted as a valid proof merely because its call succeeded.
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

    /// @dev Never copies unbounded returndata from a hostile candidate. The
    /// canonical selector getter must return exactly one ABI word within the
    /// same small gas budget used by reserve configuration reads.
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
        // Canonical ABI encoding of bytes4 is left-aligned with 28 zero bytes.
        // Rejecting dirty padding prevents an alternate return encoding from
        // being treated as the same immutable verifier identity.
        ok = ok && (uint256(word) & type(uint224).max) == 0;
        // forge-lint: disable-next-line(unsafe-typecast)
        selector = bytes4(word);
    }
}
