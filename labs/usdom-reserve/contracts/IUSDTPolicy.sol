// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice Policy surface of the intended Ethereum USDT implementation.
interface IUSDTPolicy {
    function paused() external view returns (bool);
    function deprecated() external view returns (bool);
    function basisPointsRate() external view returns (uint256);
    function maximumFee() external view returns (uint256);
    function isBlackListed(address account) external view returns (bool);
}
