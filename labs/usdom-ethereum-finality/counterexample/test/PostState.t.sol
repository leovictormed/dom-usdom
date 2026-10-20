// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

interface Vm {
    struct Log { bytes32[] topics; bytes data; address emitter; }
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

// Deliberately upgradeable toy emitter. Not USDOMReserve and never a deployment candidate.
contract ToyProxy {
    address public implementation;
    address public immutable administrator;
    constructor(address initial) { implementation = initial; administrator = msg.sender; }
    function setImplementation(address next) external {
        require(msg.sender == administrator);
        implementation = next;
    }
    fallback() external {
        address target = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(success) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}

contract RefusingImplementation {
    function pretendDeposit(bytes32, address, uint64, bytes32) external pure {
        revert("No eligible deposit");
    }
}

contract ForgingImplementation {
    event Deposited(bytes32 indexed id, address indexed funder, uint64 amount, bytes32 receivingCommitment);
    function pretendDeposit(bytes32 id, address funder, uint64 amount, bytes32 commitment) external {
        emit Deposited(id, funder, amount, commitment);
    }
}

contract PostStateTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testRestoredImplementationAndCodeHashDoNotAuthenticateEventTimeBehavior() external {
        address good = address(new RefusingImplementation());
        address bad = address(new ForgingImplementation());
        ToyProxy proxy = new ToyProxy(good);
        bytes32 originalCodeHash = address(proxy).codehash;
        bytes memory callData = abi.encodeCall(ForgingImplementation.pretendDeposit,
            (bytes32(uint256(1)), address(this), uint64(100_000_000), bytes32(uint256(2))));
        (bool refused,) = address(proxy).call(callData);
        require(!refused, "normal implementation must reject");

        vm.recordLogs();
        proxy.setImplementation(bad);
        (bool forged,) = address(proxy).call(callData);
        require(forged);
        proxy.setImplementation(good);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 1);
        require(logs[0].emitter == address(proxy));
        require(logs[0].topics[0] == keccak256("Deposited(bytes32,address,uint64,bytes32)"));
        (uint64 amount, bytes32 commitment) = abi.decode(logs[0].data, (uint64, bytes32));
        require(amount == 100_000_000 && commitment == bytes32(uint256(2)));
        require(proxy.implementation() == good);
        require(address(proxy).codehash == originalCodeHash);
        require(address(proxy).balance == 0);
        // Even the same implementation slot before AND after does not reveal the
        // temporary implementation. No actual token deposit occurred anywhere.
    }
}
