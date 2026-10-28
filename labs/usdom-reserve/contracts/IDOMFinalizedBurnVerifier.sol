// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice The verifier must authenticate DOM consensus finality, the USDOM state
/// transition and inclusion of the exact public burn statement. Implementations
/// may hide all unrelated notes and transfer history inside a zero-knowledge proof.
interface IDOMFinalizedBurnVerifier {
    function verifierConfigHash() external view returns (bytes32);
    function verifyFinalizedBurn(bytes32 statementHash, bytes calldata proof) external view returns (bytes32);
}
