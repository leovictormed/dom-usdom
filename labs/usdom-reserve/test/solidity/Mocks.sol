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

/// TEST ONLY. Exercises nonstandard ERC20 behavior and hostile callback paths.
contract HostileToken is ERC20 {
    enum Mode {
        Standard,
        NoReturn,
        FalseReturn,
        MalformedReturn,
        Lie,
        FeeOnTop,
        FeeOnReceive
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
        return mode != Mode.FalseReturn;
    }

    function _callback() private {
        if (callbackTarget == address(0)) return;
        (bool ok, bytes memory data) = callbackTarget.call(callbackData);
        callbackSucceeded = ok;
        if (data.length >= 4) callbackError = bytes4(data);
    }
}
