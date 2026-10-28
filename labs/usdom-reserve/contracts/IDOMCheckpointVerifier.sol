// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice A verifier implementation must prove that `statementHash` names a
/// valid DOM consensus extension from the previous checkpoint to the proposed
/// checkpoint. Returning any value other than the expected capability is rejection.
interface IDOMCheckpointVerifier {
    function verifierConfigHash() external view returns (bytes32);
    function verifyDOMCheckpoint(bytes32 statementHash, bytes calldata proof) external view returns (bytes32);
}
