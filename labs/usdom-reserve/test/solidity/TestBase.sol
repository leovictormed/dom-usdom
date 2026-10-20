// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

interface Vm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function addr(uint256 key) external pure returns (address);
    function sign(uint256 key, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function expectRevert() external;
    function expectRevert(bytes4 selector) external;
    function expectRevert(bytes calldata data) external;
    function warp(uint256 timestamp) external;
    function chainId(uint256 chainId_) external;
    function deal(address who, uint256 amount) external;
    function etch(address who, bytes calldata code) external;
    function load(address target, bytes32 slot) external view returns (bytes32);
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory entries);
    function envOr(string calldata name, uint256 defaultValue) external view returns (uint256);
}

abstract contract TestBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant BN254_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    function canonicalCommitment(bytes32 entropy) internal pure returns (bytes32) {
        return bytes32(uint256(entropy) % (BN254_SCALAR_FIELD - 1) + 1);
    }

    function assertEq(uint256 a, uint256 b) internal pure {
        require(a == b, "uint equality");
    }

    function assertEq(address a, address b) internal pure {
        require(a == b, "address equality");
    }

    function assertEq(bytes32 a, bytes32 b) internal pure {
        require(a == b, "bytes32 equality");
    }

    function assertTrue(bool a) internal pure {
        require(a, "expected true");
    }

    function assertFalse(bool a) internal pure {
        require(!a, "expected false");
    }
}
