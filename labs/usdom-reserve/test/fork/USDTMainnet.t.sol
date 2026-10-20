// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;
import {USDOMReserve} from "../../contracts/USDOMReserve.sol";
import {IDOMFinalizedBurnVerifier, USDOMProofReserve} from "../../contracts/USDOMProofReserve.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {TestBase} from "../solidity/TestBase.sol";
import {MockGovernance} from "../solidity/Mocks.sol";

interface ITetherFork {
    function owner() external view returns (address);
    function decimals() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function paused() external view returns (bool);
    function deprecated() external view returns (bool);
    function basisPointsRate() external view returns (uint256);
    function maximumFee() external view returns (uint256);
    function isBlackListed(address who) external view returns (bool);
    function issue(uint256 amount) external;
    function approve(address spender, uint256 amount) external;
    function transfer(address to, uint256 amount) external;
    function addBlackList(address who) external;
    function pause() external;
}

contract ForkBurnVerifier is IDOMFinalizedBurnVerifier {
    function verifierConfigHash() external pure returns (bytes32) {
        return keccak256("fork-only verifier configuration");
    }

    function verifyFinalizedBurn(bytes32, bytes calldata) external pure returns (bytes32) {
        return keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    }
}

/// Local fork only: owner impersonation changes local VM state, never mainnet.
/// Certificates are synthetic fixtures, not evidence of a real DOM burn.
contract USDTMainnetForkTest is TestBase {
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant GUARDIAN = address(0x600D);
    uint256 constant DEPOSIT = 10_000e6;
    bytes32 constant DOMAIN = keccak256("DOM fork test only");
    bytes32 constant ACTIVATION_SCHEDULE = keccak256("DOM fork test activation only");
    ITetherFork token = ITetherFork(USDT);
    USDOMReserve reserve;
    uint256[4] keys;
    address owner;

    function setUp() public {
        require(
            block.chainid == 1 && block.number == vm.envOr("USDOM_FORK_BLOCK", uint256(26201446)), "wrong fork identity"
        );
        require(
            USDT.codehash == 0xb44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55,
            "unexpected mainnet token runtime"
        );
        // Keep real Ethereum token state, but deploy only on a local test chain ID.
        vm.chainId(31337);
        vm.etch(GUARDIAN, hex"00");
        owner = token.owner();
        address[] memory signers = new address[](4);
        for (uint256 i; i < 4; ++i) {
            keys[i] = 101 + i;
            signers[i] = vm.addr(keys[i]);
        }
        for (uint256 i; i < 4; ++i) {
            for (uint256 j = i + 1; j < 4; ++j) {
                if (signers[j] < signers[i]) {
                    (signers[i], signers[j]) = (signers[j], signers[i]);
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                }
            }
        }
        MockGovernance gov = new MockGovernance();
        reserve = new USDOMReserve(
            USDOMReserve.Config(IERC20(USDT), DOMAIN, address(gov), GUARDIAN, 1 days, 2 days, 100_000e6, 2_000e6),
            signers,
            3
        );
        vm.startPrank(owner);
        token.issue(DEPOSIT);
        token.transfer(ALICE, DEPOSIT);
        vm.stopPrank();
        vm.startPrank(ALICE);
        token.approve(address(reserve), 0);
        token.approve(address(reserve), DEPOSIT);
        reserve.deposit(uint64(DEPOSIT), bytes32(uint256(1)), bytes32(uint256(2)));
        vm.stopPrank();
    }

    function queue() private returns (USDOMReserve.Burn memory b) {
        b = USDOMReserve.Burn(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            BOB,
            100e6,
            DOMAIN,
            1,
            bytes32(uint256(3)),
            reserve.currentEpoch(),
            uint64(block.timestamp + 6 days)
        );
        bytes[] memory sigs = new bytes[](3);
        for (uint256 i; i < 3; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], reserve.burnDigest(b));
            sigs[i] = abi.encodePacked(r, s, v);
        }
        reserve.queueWithdrawal(b, sigs);
    }

    function testPinnedStateAndActualNoReturnUSDTTransfer() public {
        assertEq(token.decimals(), 6);
        assertFalse(token.paused());
        assertFalse(token.deprecated());
        assertEq(token.basisPointsRate(), 0);
        assertEq(token.maximumFee(), 0);
        assertEq(reserve.outstanding(), DEPOSIT);
        assertEq(token.balanceOf(address(reserve)), DEPOSIT);
        USDOMReserve.Burn memory b = queue();
        uint256 before = token.balanceOf(BOB);
        vm.warp(block.timestamp + 1 days);
        reserve.executeWithdrawal(b);
        assertEq(token.balanceOf(BOB), before + b.amount);
        assertEq(reserve.totalReleased(), b.amount);
    }

    function testQuorumPrototypeRefusesMainnetEvenWithActualUSDT() public {
        address[] memory signers = new address[](4);
        for (uint256 i; i < 4; ++i) {
            signers[i] = vm.addr(keys[i]);
        }
        MockGovernance gov = new MockGovernance();
        vm.chainId(1);
        vm.expectRevert(USDOMReserve.PrototypeOnly.selector);
        new USDOMReserve(
            USDOMReserve.Config(IERC20(USDT), DOMAIN, address(gov), GUARDIAN, 1 days, 2 days, 100_000e6, 2_000e6),
            signers,
            3
        );
    }

    function testProofReserveRefusesMainnetUntilRatifiedVerifierHashesArePinned() public {
        MockGovernance gov = new MockGovernance();
        ForkBurnVerifier proofVerifier = new ForkBurnVerifier();
        vm.chainId(1);
        vm.expectRevert(USDOMProofReserve.ProductionUnavailable.selector);
        new USDOMProofReserve(
            USDOMProofReserve.Config(
                IERC20(USDT),
                proofVerifier,
                DOMAIN,
                ACTIVATION_SCHEDULE,
                address(gov),
                GUARDIAN,
                1 days,
                2 days,
                100_000e6,
                2_000e6
            )
        );
    }

    function testActualUSDTBlacklistAllowsReceiptButPreventsSpending() public {
        vm.prank(owner);
        token.addBlackList(BOB);
        assertTrue(token.isBlackListed(BOB));
        uint256 before = token.balanceOf(BOB);
        vm.prank(ALICE); // no-return behavior with a frozen destination
        token.transfer(BOB, 0);
        vm.startPrank(owner);
        token.issue(100e6);
        token.transfer(BOB, 100e6);
        vm.stopPrank();
        assertEq(token.balanceOf(BOB), before + 100e6);
        vm.prank(BOB);
        vm.expectRevert();
        token.transfer(ALICE, 1);
    }

    function testFrozenRecipientCannotConsumeBurnAfterQueue() public {
        USDOMReserve.Burn memory b = queue();
        vm.prank(owner);
        token.addBlackList(BOB);
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(abi.encodeWithSelector(USDOMReserve.FrozenTokenAccount.selector, BOB));
        reserve.executeWithdrawal(b);
        assertFalse(reserve.paidBurns(b.burnId));
        assertTrue(token.isBlackListed(BOB));
        assertEq(reserve.totalPendingAmount(), b.amount);
        assertEq(reserve.totalReleased(), 0);
        vm.prank(BOB);
        vm.expectRevert();
        token.transfer(ALICE, 1);
    }

    function testFrozenReserveRollsBackPaymentAndReservation() public {
        USDOMReserve.Burn memory b = queue();
        vm.prank(owner);
        token.addBlackList(address(reserve));
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert();
        reserve.executeWithdrawal(b);
        assertFalse(reserve.paidBurns(b.burnId));
        assertEq(reserve.totalPendingAmount(), b.amount);
        assertEq(reserve.totalReleased(), 0);
    }

    function testPausedTokenRollsBackPayment() public {
        USDOMReserve.Burn memory b = queue();
        vm.prank(owner);
        token.pause();
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert();
        reserve.executeWithdrawal(b);
        assertFalse(reserve.paidBurns(b.burnId));
    }
}
