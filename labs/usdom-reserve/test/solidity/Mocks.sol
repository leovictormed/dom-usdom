// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// TEST ONLY. An unrestricted governance caller, NOT a production multisig.
contract MockGovernance {
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory result) = target.call(data);
        if (!ok) {
            assembly { revert(add(result, 32), mload(result)) }
        }
        return result;
    }
}

/// TEST ONLY. Models the SafeProxy identity surface while allowing a test to
/// exercise a post-deployment singleton migration.
contract MockMutableSingletonControl {
    address private singleton;
    address[] private owners;
    uint256 private safeThreshold = 2;
    address private module;
    address private safeGuard;
    address private fallbackHandler;
    uint8 private ownersReturnMode;
    uint8 private thresholdReturnMode;
    uint8 private modulesReturnMode;
    uint8 private storageReturnMode;

    constructor(address initialSingleton) {
        singleton = initialSingleton;
        owners.push(address(0x101));
        owners.push(address(0x102));
        owners.push(address(0x103));
    }

    function masterCopy() external view returns (address) {
        return singleton;
    }

    function setMasterCopy(address replacement) external {
        singleton = replacement;
    }

    function getOwners() external view returns (address[] memory) {
        if (ownersReturnMode == 1) revert("owners unavailable");
        if (ownersReturnMode != 0) {
            uint256 size = ownersReturnMode == 2 ? 159 : ownersReturnMode == 3 ? 161 : 0x100000;
            uint8 mode = ownersReturnMode;
            assembly ("memory-safe") {
                mstore(0, 32)
                mstore(32, 3)
                mstore(64, 0x101)
                mstore(96, 0x102)
                mstore(128, 0x103)
                if eq(mode, 5) {
                    mstore(0, 64)
                    size := 160
                }
                if eq(mode, 6) {
                    mstore(32, 2)
                    size := 160
                }
                if eq(mode, 7) {
                    mstore(64, or(shl(160, 1), 0x101))
                    size := 160
                }
                return(0, size)
            }
        }
        return owners;
    }

    function setOwnersReturnMode(uint8 replacement) external {
        ownersReturnMode = replacement;
    }

    function setThresholdReturnMode(uint8 replacement) external {
        thresholdReturnMode = replacement;
    }

    function setModulesReturnMode(uint8 replacement) external {
        modulesReturnMode = replacement;
    }

    function setStorageReturnMode(uint8 replacement) external {
        storageReturnMode = replacement;
    }

    function getThreshold() external view returns (uint256) {
        uint8 mode = thresholdReturnMode;
        if (mode != 0) {
            uint256 value = safeThreshold;
            uint256 size = mode == 1 ? 31 : mode == 2 ? 33 : 0x100000;
            assembly ("memory-safe") {
                mstore(0, value)
                return(0, size)
            }
        }
        return safeThreshold;
    }

    function getModulesPaginated(address, uint256) external view returns (address[] memory modules, address next) {
        uint8 mode = modulesReturnMode;
        if (mode != 0) {
            uint256 size = mode == 1 ? 95 : mode == 2 ? 97 : mode == 3 ? 0x100000 : 96;
            assembly ("memory-safe") {
                mstore(0, 64)
                mstore(32, 1)
                mstore(64, 0)
                if eq(mode, 4) { mstore(0, 32) }
                return(0, size)
            }
        }
        if (module == address(0)) return (new address[](0), address(1));
        modules = new address[](1);
        modules[0] = module;
        next = address(1);
    }

    function setThreshold(uint256 replacement) external {
        safeThreshold = replacement;
    }

    function setOwnerCount(uint256 replacement) external {
        while (owners.length > replacement) owners.pop();
        while (owners.length < replacement) owners.push(address(uint160(0x101 + owners.length)));
    }

    function setOwner(uint256 index, address replacement) external {
        owners[index] = replacement;
    }

    function setOwners(address first, address second, address third) external {
        owners[0] = first;
        owners[1] = second;
        owners[2] = third;
    }

    function setModule(address replacement) external {
        module = replacement;
    }

    function setGuard(address replacement) external {
        safeGuard = replacement;
    }

    function setFallbackHandler(address replacement) external {
        fallbackHandler = replacement;
    }

    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory result) {
        require(length == 1, "length");
        result = new bytes(32);
        if (offset == 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8) {
            address current = safeGuard;
            assembly ("memory-safe") {
                mstore(add(result, 32), current)
            }
        } else if (offset == 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5) {
            address current = fallbackHandler;
            assembly ("memory-safe") {
                mstore(add(result, 32), current)
            }
        }
        uint8 mode = storageReturnMode;
        if (mode != 0) {
            bytes32 value;
            assembly ("memory-safe") {
                value := mload(add(result, 32))
            }
            uint256 size = mode == 1 ? 95 : mode == 2 ? 97 : mode == 3 ? 0x100000 : 96;
            assembly ("memory-safe") {
                mstore(0, 32)
                mstore(32, 32)
                mstore(64, value)
                if eq(mode, 4) { mstore(32, 31) }
                return(0, size)
            }
        }
    }

    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory result) = target.call(data);
        if (!ok) {
            assembly { revert(add(result, 32), mload(result)) }
        }
        return result;
    }
}

/// TEST ONLY. Exercises nonstandard ERC20 behavior and hostile callback paths.
contract HostileToken is ERC20 {
    enum Mode {
        Standard,
        NoReturn,
        FalseReturn,
        MalformedReturn,
        Lie,
        FeeOnTop,
        FeeOnReceive,
        ReturnBomb,
        BalanceReturnBomb,
        ShortReturn,
        TrailingReturn,
        GasGrief,
        ResidualAllowance
    }
    Mode public mode;
    address public blocked;
    address public callbackTarget;
    bytes public callbackData;
    bool public callbackSucceeded;
    bytes4 public callbackError;
    uint8 public tokenDecimals = 6;
    bool private pausedValue;
    bool private deprecatedValue;
    address private upgradedAddressValue;
    uint256 private basisPointsRateValue;
    uint256 private maximumFeeValue;
    bool public failPolicy;
    bytes4 private policyReturnSelector;
    uint8 private policyReturnMode;

    function isBlackListed(address who) external view returns (bool) {
        require(!failPolicy, "policy unavailable");
        return _policyWord(blocked != address(0) && who == blocked ? bytes32(uint256(1)) : bytes32(0)) != bytes32(0);
    }

    function setPolicy(bool paused_, bool deprecated_, uint256 rate, uint256 fee, bool fail_) external {
        pausedValue = paused_;
        deprecatedValue = deprecated_;
        basisPointsRateValue = rate;
        maximumFeeValue = fee;
        failPolicy = fail_;
    }

    function setUpgradedAddress(address value) external {
        upgradedAddressValue = value;
    }

    function setPolicyReturnMode(bytes4 selector, uint8 value) external {
        policyReturnSelector = selector;
        policyReturnMode = value;
    }

    function paused() external view returns (bool) {
        return _policyWord(pausedValue ? bytes32(uint256(1)) : bytes32(0)) != bytes32(0);
    }

    function deprecated() external view returns (bool) {
        return _policyWord(deprecatedValue ? bytes32(uint256(1)) : bytes32(0)) != bytes32(0);
    }

    function upgradedAddress() external view returns (address) {
        return address(uint160(uint256(_policyWord(bytes32(uint256(uint160(upgradedAddressValue)))))));
    }

    function basisPointsRate() external view returns (uint256) {
        return uint256(_policyWord(bytes32(basisPointsRateValue)));
    }

    function maximumFee() external view returns (uint256) {
        return uint256(_policyWord(bytes32(maximumFeeValue)));
    }

    function _policyWord(bytes32 value) private view returns (bytes32) {
        uint8 selectedMode = policyReturnMode;
        if (msg.sig == policyReturnSelector && selectedMode != 0) {
            if (selectedMode == 5) {
                assembly {
                    for {} 1 {} {}
                }
            }
            uint256 size = selectedMode == 1 ? 31 : selectedMode == 2 ? 33 : selectedMode == 3 ? 0x100000 : 32;
            if (selectedMode == 4) value = bytes32(uint256(2));
            assembly ("memory-safe") {
                mstore(0, value)
                return(0, size)
            }
        }
        return value;
    }

    constructor() ERC20("Hostile test token", "HOSTILE") {}

    function decimals() public view override returns (uint8) {
        return uint8(uint256(_policyWord(bytes32(uint256(tokenDecimals)))));
    }

    function setDecimals(uint8 value) external {
        tokenDecimals = value;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function confiscate(address from, uint256 amount) external {
        _burn(from, amount);
    }

    function setMode(Mode value) external {
        mode = value;
    }

    function setBlocked(address who) external {
        blocked = who;
    }

    function setCallback(address target, bytes calldata data) external {
        callbackTarget = target;
        callbackData = data;
    }

    function balanceOf(address account) public view override returns (uint256) {
        if (mode == Mode.BalanceReturnBomb) {
            assembly {
                mstore(0, 0)
                return(0, 0x100000)
            }
        }
        return uint256(_policyWord(bytes32(super.balanceOf(account))));
    }

    function allowance(address owner, address spender) public view override returns (uint256) {
        return uint256(_policyWord(bytes32(super.allowance(owner, spender))));
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        if (mode != Mode.Lie) _transfer(msg.sender, to, amount);
        _callback();
        return _returnValue();
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        if (mode != Mode.ResidualAllowance) _spendAllowance(from, msg.sender, amount);
        if (mode != Mode.Lie) _transfer(from, to, amount);
        _callback();
        return _returnValue();
    }

    function _update(address from, address to, uint256 amount) internal override {
        require(blocked == address(0) || (from != blocked && to != blocked), "blacklisted");
        if (from != address(0) && to != address(0) && amount > 0) {
            if (mode == Mode.FeeOnReceive) {
                super._update(from, to, amount - 1);
                super._update(from, address(0), 1);
                return;
            }
            if (mode == Mode.FeeOnTop) super._update(from, address(0), 1);
        }
        super._update(from, to, amount);
    }

    function _returnValue() private view returns (bool) {
        if (mode == Mode.NoReturn) {
            assembly { return(0, 0) }
        }
        if (mode == Mode.MalformedReturn) {
            assembly {
                mstore(0, 2)
                return(0, 32)
            }
        }
        if (mode == Mode.ReturnBomb) {
            assembly {
                mstore(0, 1)
                return(0, 0x100000)
            }
        }
        if (mode == Mode.ShortReturn || mode == Mode.TrailingReturn) {
            uint256 size = mode == Mode.ShortReturn ? 31 : 33;
            assembly {
                mstore(0, 1)
                return(0, size)
            }
        }
        if (mode == Mode.GasGrief) {
            assembly {
                for {} 1 {} {}
            }
        }
        return mode != Mode.FalseReturn;
    }

    function _callback() private {
        if (callbackTarget == address(0)) return;
        (bool ok, bytes memory data) = callbackTarget.call(callbackData);
        callbackSucceeded = ok;
        if (data.length >= 4) callbackError = bytes4(data);
    }
}

/// TEST ONLY. Mutable stand-in for the immutable checkpoint registry boundary.
contract MockGracefulShutdownRegistry {
    bytes32 public immutable bridgeDomain;
    bytes32 public immutable activationScheduleCommitment;
    bytes32 private checkpointConfigHashValue = keccak256("mock checkpoint registry configuration");
    bool private haltedValue;
    bool private gracefullyShutdownValue;
    bool private latestIssuanceClosedValue;
    uint128 private latestTotalIssuedValue;
    uint128 private latestTotalBurnedValue;
    bytes4 private hostileSelector;
    uint8 private returnMode;

    constructor(bytes32 domain, bytes32 activation) {
        bridgeDomain = domain;
        activationScheduleCommitment = activation;
    }

    function setTerminal(uint128 issued, uint128 burned, bool issuanceClosed, bool shutdown) external {
        latestTotalIssuedValue = issued;
        latestTotalBurnedValue = burned;
        latestIssuanceClosedValue = issuanceClosed;
        gracefullyShutdownValue = shutdown;
    }

    function setHalted(bool value) external {
        haltedValue = value;
    }

    function setCheckpointConfigHash(bytes32 value) external {
        checkpointConfigHashValue = value;
    }

    function setReturnMode(bytes4 selector, uint8 mode) external {
        hostileSelector = selector;
        returnMode = mode;
    }

    function checkpointConfigHash() external view returns (bytes32) {
        return _word(checkpointConfigHashValue);
    }

    function halted() external view returns (bool) {
        return _word(haltedValue ? bytes32(uint256(1)) : bytes32(0)) != bytes32(0);
    }

    function gracefullyShutdown() external view returns (bool) {
        return _word(gracefullyShutdownValue ? bytes32(uint256(1)) : bytes32(0)) != bytes32(0);
    }

    function latestIssuanceClosed() external view returns (bool) {
        return _word(latestIssuanceClosedValue ? bytes32(uint256(1)) : bytes32(0)) != bytes32(0);
    }

    function latestTotalIssued() external view returns (uint128) {
        return uint128(uint256(_word(bytes32(uint256(latestTotalIssuedValue)))));
    }

    function latestTotalBurned() external view returns (uint128) {
        return uint128(uint256(_word(bytes32(uint256(latestTotalBurnedValue)))));
    }

    function _word(bytes32 value) private view returns (bytes32) {
        uint8 mode = returnMode;
        if (msg.sig == hostileSelector && mode != 0) {
            uint256 size = mode == 1 ? 31 : mode == 2 ? 33 : mode == 3 ? 0x100000 : 32;
            if (mode == 4) value = bytes32(uint256(2));
            assembly ("memory-safe") {
                mstore(0, value)
                return(0, size)
            }
        }
        return value;
    }
}
