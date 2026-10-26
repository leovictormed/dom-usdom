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
            assembly ("memory-safe") {
                mstore(0, 32)
                mstore(32, 3)
                mstore(64, 0x101)
                mstore(96, 0x102)
                mstore(128, 0x103)
                return(0, size)
            }
        }
        return owners;
    }

    function setOwnersReturnMode(uint8 replacement) external {
        ownersReturnMode = replacement;
    }

    function getThreshold() external view returns (uint256) {
        return safeThreshold;
    }

    function getModulesPaginated(address, uint256) external view returns (address[] memory modules, address next) {
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
        GasGrief
    }
    Mode public mode;
    address public blocked;
    address public callbackTarget;
    bytes public callbackData;
    bool public callbackSucceeded;
    bytes4 public callbackError;
    uint8 public tokenDecimals = 6;
    bool public paused;
    bool public deprecated;
    address public upgradedAddress;
    uint256 public basisPointsRate;
    uint256 public maximumFee;
    bool public failPolicy;

    function isBlackListed(address who) external view returns (bool) {
        require(!failPolicy, "policy unavailable");
        return blocked != address(0) && who == blocked;
    }

    function setPolicy(bool paused_, bool deprecated_, uint256 rate, uint256 fee, bool fail_) external {
        paused = paused_;
        deprecated = deprecated_;
        basisPointsRate = rate;
        maximumFee = fee;
        failPolicy = fail_;
    }

    function setUpgradedAddress(address value) external {
        upgradedAddress = value;
    }

    constructor() ERC20("Hostile test token", "HOSTILE") {}

    function decimals() public view override returns (uint8) {
        return tokenDecimals;
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
        return super.balanceOf(account);
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        if (mode != Mode.Lie) _transfer(msg.sender, to, amount);
        _callback();
        return _returnValue();
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        _spendAllowance(from, msg.sender, amount);
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
    bytes32 public checkpointConfigHash = keccak256("mock checkpoint registry configuration");
    bool public halted;
    bool public gracefullyShutdown;
    bool public latestIssuanceClosed;
    uint128 public latestTotalIssued;
    uint128 public latestTotalBurned;

    constructor(bytes32 domain, bytes32 activation) {
        bridgeDomain = domain;
        activationScheduleCommitment = activation;
    }

    function setTerminal(uint128 issued, uint128 burned, bool issuanceClosed, bool shutdown) external {
        latestTotalIssued = issued;
        latestTotalBurned = burned;
        latestIssuanceClosed = issuanceClosed;
        gracefullyShutdown = shutdown;
    }

    function setHalted(bool value) external {
        halted = value;
    }

    function setCheckpointConfigHash(bytes32 value) external {
        checkpointConfigHash = value;
    }
}
