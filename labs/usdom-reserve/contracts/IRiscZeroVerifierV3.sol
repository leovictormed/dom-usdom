// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice Minimal immutable ABI exposed by the RISC Zero Groth16 verifier.
interface IRiscZeroVerifierV3 {
    function SELECTOR() external view returns (bytes4);
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}
