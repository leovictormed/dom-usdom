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
    function store(address target, bytes32 slot, bytes32 value) external;
    function getNonce(address account) external view returns (uint64 nonce);
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory entries);
    function envOr(string calldata name, uint256 defaultValue) external view returns (uint256);
    function readFile(string calldata path) external view returns (string memory);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseBytes(string calldata value) external pure returns (bytes memory);
}

abstract contract TestBase {
    function canonicalRiscZeroProof(bytes32 payload) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes4(0x73c457ba), new bytes(7 * 32), payload);
    }

    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant BN254_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    address internal constant SAFE_MAINNET_FALLBACK_HANDLER = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;
    bytes32 internal constant SAFE_MAINNET_FALLBACK_HANDLER_CODE_HASH =
        0x7c6007a5d711cea8dfd5d91f5940ec29c7f200fe511eb1fc1397b367af3c42f9;

    function installMainnetSafeFallbackHandler() internal {
        string memory fixture = vm.readFile("test/fixtures/safe-1.4.1-mainnet.json");
        bytes memory runtime = vm.parseJsonBytes(fixture, ".fallbackHandlerRuntimeCode");
        assertEq(keccak256(runtime), SAFE_MAINNET_FALLBACK_HANDLER_CODE_HASH);
        vm.etch(SAFE_MAINNET_FALLBACK_HANDLER, runtime);
    }

    function installPinnedRiscZeroMainnetVerifier(address verifier, bytes32 expectedCodeHash) internal {
        bytes memory encoded = bytes(vm.readFile("test/fixtures/risc0-mainnet-v3-runtime.hex"));
        uint256 length = encoded.length;
        while (length != 0 && (encoded[length - 1] == 0x0a || encoded[length - 1] == 0x0d)) --length;
        assembly ("memory-safe") {
            mstore(encoded, length)
        }
        bytes memory runtime = vm.parseBytes(string(encoded));
        assertEq(keccak256(runtime), expectedCodeHash);
        vm.etch(verifier, runtime);
        assertEq(verifier.codehash, expectedCodeHash);
    }

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
