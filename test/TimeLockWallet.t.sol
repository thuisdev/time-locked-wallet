// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Test} from "forge-std/Test.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

import {TimeLockWallet} from "../src/TimeLockWallet.sol";

/// @title ReentrantAttacker – malicious contract that tries to re-enter every ETH-moving path
/// @notice Plays beneficiary (claim, batch), depositor (reclaim) or owner (fee withdrawal). Whenever it receives ETH,
///         its receive() immediately calls back into the same wallet function that is currently paying it.
/// @dev receive() has no parameters, so the attack mode and target IDs are stored before each attack starts.
contract ReentrantAttacker {
    /// @notice Which wallet function receive() re-enters.
    enum AttackMode {
        Claim,
        Batch,
        Reclaim,
        WithdrawFees
    }

    /// @notice The wallet under attack, fixed at deployment.
    TimeLockWallet private immutable WALLET;

    /// @dev Lock ID used by the Claim and Reclaim attacks.
    uint256 private _targetLockId;

    /// @dev Lock IDs used by the Batch attack.
    uint256[] private _targetLockIds;

    /// @dev Fee amount used by the WithdrawFees attack.
    uint256 private _targetAmount;

    /// @dev The attack that is currently running.
    AttackMode private _mode;

    /// @param wallet_ The wallet this attacker will target.
    constructor(TimeLockWallet wallet_) {
        WALLET = wallet_;
    }

    /// @notice Re-enters whichever function is currently sending ETH to this contract.
    receive() external payable {
        if (_mode == AttackMode.Claim) {
            WALLET.claimLock(_targetLockId);
        } else if (_mode == AttackMode.Batch) {
            WALLET.claimBatch(_targetLockIds);
        } else if (_mode == AttackMode.Reclaim) {
            WALLET.reclaimLock(_targetLockId);
        } else if (_mode == AttackMode.WithdrawFees) {
            WALLET.withdrawFees(address(this), _targetAmount);
        }
    }

    /// @notice Lets the attacker act as a depositor so it can attack reclaimLock.
    /// @param beneficiary Beneficiary of the new lock.
    /// @param unlockTime  Unlock time of the new lock.
    /// @return lockId     ID of the created lock.
    function createLock(address beneficiary, uint64 unlockTime) external payable returns (uint256 lockId) {
        lockId = WALLET.createLock{value: msg.value}(beneficiary, unlockTime);
    }

    /// @notice Accepts a pending ownership transfer so the attacker can attack withdrawFees as owner.
    function acceptOwnership() external {
        WALLET.acceptOwnership();
    }

    /// @notice Starts a reentrancy attack on claimLock.
    /// @param lockId Lock to claim (attacker must be its beneficiary).
    function attackClaim(uint256 lockId) external {
        _mode = AttackMode.Claim;
        _targetLockId = lockId;
        WALLET.claimLock(lockId);
    }

    /// @notice Starts a reentrancy attack on claimBatch.
    /// @param lockIds Locks to claim (attacker must be their beneficiary).
    function attackBatch(uint256[] calldata lockIds) external {
        _mode = AttackMode.Batch;
        _targetLockIds = lockIds;
        WALLET.claimBatch(lockIds);
    }

    /// @notice Starts a reentrancy attack on reclaimLock.
    /// @param lockId Lock to reclaim (attacker must be its depositor).
    function attackReclaim(uint256 lockId) external {
        _mode = AttackMode.Reclaim;
        _targetLockId = lockId;
        WALLET.reclaimLock(lockId);
    }

    /// @notice Starts a reentrancy attack on withdrawFees.
    /// @param amount Fee amount to withdraw (attacker must be the owner).
    function attackWithdrawFees(uint256 amount) external {
        _mode = AttackMode.WithdrawFees;
        _targetAmount = amount;
        WALLET.withdrawFees(address(this), amount);
    }
}

/// @title TimeLockWallet tests
/// @notice Proves that all value-moving paths (single claim, batch claim, reclaim, fee withdrawal) are not reentrant,
///         covers the key spec rules (pause, batch cap, duplicate IDs, direct ETH) and fuzzes the fee accounting.
contract TimeLockWalletTest is Test {
    uint256 private constant LOCK_AMOUNT = 1 ether;

    address private owner = makeAddr("owner");
    address private depositor = makeAddr("depositor");
    address private beneficiary = makeAddr("beneficiary");

    TimeLockWallet private timeLock;
    ReentrantAttacker private attacker;

    function setUp() public {
        timeLock = new TimeLockWallet(owner);
        attacker = new ReentrantAttacker(timeLock);

        vm.deal(depositor, 100 ether);
    }

    // -------------------------------------------------------------------------
    // Reentrancy (TLW-12)
    // -------------------------------------------------------------------------

    /// @dev The re-entry reverts with ReentrancyGuardReentrantCall inside the attacker's receive(). The low-level call
    ///      in the wallet only sees success = false, so the error that reaches the test is TransferFailed.
    function test_claimLock_reentrancy_reverts() public {
        uint256 lockId = _createMaturedLock(address(attacker));

        vm.expectRevert(TimeLockWallet.TransferFailed.selector);
        attacker.attackClaim(lockId);

        _assertLockStillOpen(lockId);
    }

    function test_claimBatch_reentrancy_reverts() public {
        uint256[] memory lockIds = new uint256[](2);
        lockIds[0] = _createMaturedLock(address(attacker));
        lockIds[1] = _createMaturedLock(address(attacker));

        vm.expectRevert(TimeLockWallet.TransferFailed.selector);
        attacker.attackBatch(lockIds);

        _assertLockStillOpen(lockIds[0]);
        _assertLockStillOpen(lockIds[1]);
    }

    function test_reclaimLock_reentrancy_reverts() public {
        vm.deal(address(attacker), LOCK_AMOUNT);
        uint64 unlockTime = uint64(block.timestamp + timeLock.MIN_DELAY());
        uint256 lockId = attacker.createLock{value: LOCK_AMOUNT}(beneficiary, unlockTime);

        vm.warp(unlockTime + timeLock.GRACE_PERIOD());

        vm.expectRevert(TimeLockWallet.TransferFailed.selector);
        attacker.attackReclaim(lockId);

        _assertLockStillOpen(lockId);
    }

    function test_withdrawFees_reentrancy_reverts() public {
        // Generate fees with a normal claim
        uint256 lockId = _createMaturedLock(beneficiary);
        vm.prank(beneficiary);
        timeLock.claimLock(lockId);
        uint256 fees = timeLock.accruedFees();

        // Hand ownership to the attacker (Ownable2Step: transfer + accept)
        vm.prank(owner);
        timeLock.transferOwnership(address(attacker));
        attacker.acceptOwnership();

        vm.expectRevert(TimeLockWallet.TransferFailed.selector);
        attacker.attackWithdrawFees(fees);

        assertEq(timeLock.accruedFees(), fees);
    }

    // -------------------------------------------------------------------------
    // Spec rules
    // -------------------------------------------------------------------------

    /// @dev TLW-11: one paused state blocks all five state-changing user/admin paths.
    function test_pause_blocksAllValuePaths() public {
        uint256 lockId = _createMaturedLock(beneficiary);
        uint256[] memory lockIds = new uint256[](1);
        lockIds[0] = lockId;
        // Computed up front: MIN_DELAY() is an external call and would consume vm.prank / vm.expectRevert
        uint64 unlockTime = uint64(block.timestamp + timeLock.MIN_DELAY());

        vm.prank(owner);
        timeLock.pause();

        vm.prank(depositor);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        timeLock.createLock{value: LOCK_AMOUNT}(beneficiary, unlockTime);

        vm.startPrank(beneficiary);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        timeLock.claimLock(lockId);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        timeLock.claimBatch(lockIds);
        vm.stopPrank();

        vm.prank(depositor);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        timeLock.reclaimLock(lockId);

        vm.prank(owner);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        timeLock.withdrawFees(owner, 1);
    }

    /// @dev TLW-8: more than MAX_BATCH IDs is rejected before any lock is touched.
    function test_claimBatch_overCap_reverts() public {
        uint256 count = timeLock.MAX_BATCH() + 1;
        uint256[] memory lockIds = new uint256[](count);

        vm.prank(beneficiary);
        vm.expectRevert(abi.encodeWithSelector(TimeLockWallet.BatchTooLarge.selector, count, timeLock.MAX_BATCH()));
        timeLock.claimBatch(lockIds);
    }

    /// @dev TLW-8: the same ID twice cannot be paid twice, because the first iteration marks it Claimed.
    function test_claimBatch_duplicateIds_reverts() public {
        uint256 lockId = _createMaturedLock(beneficiary);
        uint256[] memory lockIds = new uint256[](2);
        lockIds[0] = lockId;
        lockIds[1] = lockId;

        vm.prank(beneficiary);
        vm.expectRevert(
            abi.encodeWithSelector(TimeLockWallet.LockNotOpen.selector, lockId, TimeLockWallet.LockStatus.Claimed)
        );
        timeLock.claimBatch(lockIds);
    }

    /// @dev TLW-2: plain ETH must go through createLock.
    function test_receive_plainEth_reverts() public {
        vm.prank(depositor);
        (bool success, bytes memory data) = address(timeLock).call{value: LOCK_AMOUNT}("");

        assertFalse(success);
        assertEq(bytes4(data), TimeLockWallet.DirectEthNotAccepted.selector);
    }

    // -------------------------------------------------------------------------
    // Fuzz
    // -------------------------------------------------------------------------

    /// @dev TLW-5 + TLW-9: for any amount, payout + fee == amount, fee follows FEE_BPS, and the contract balance
    ///      afterwards equals exactly the accrued fees (no ETH lost or created).
    function testFuzz_claimLock_anyAmount_accountingHolds(uint256 amount) public {
        amount = bound(amount, 1, 1_000_000 ether);
        vm.deal(depositor, amount);

        uint64 unlockTime = uint64(block.timestamp + timeLock.MIN_DELAY());
        vm.prank(depositor);
        uint256 lockId = timeLock.createLock{value: amount}(beneficiary, unlockTime);
        vm.warp(unlockTime);

        vm.prank(beneficiary);
        timeLock.claimLock(lockId);

        uint256 expectedFee = (amount * timeLock.FEE_BPS()) / timeLock.BPS_DENOMINATOR();
        assertEq(timeLock.accruedFees(), expectedFee);
        assertEq(beneficiary.balance, amount - expectedFee);
        assertEq(address(timeLock).balance, timeLock.accruedFees());
    }

    /// @dev TLW-8: for any batch size up to MAX_BATCH, one transfer pays the sum and fees are accrued once.
    function testFuzz_claimBatch_anyCount_accountingHolds(uint256 count) public {
        count = bound(count, 1, timeLock.MAX_BATCH());

        uint256[] memory lockIds = new uint256[](count);
        for (uint256 i = 0; i < count; ++i) {
            lockIds[i] = _createMaturedLock(beneficiary);
        }

        vm.prank(beneficiary);
        timeLock.claimBatch(lockIds);

        uint256 total = count * LOCK_AMOUNT;
        uint256 feePerLock = (LOCK_AMOUNT * timeLock.FEE_BPS()) / timeLock.BPS_DENOMINATOR();
        assertEq(timeLock.accruedFees(), count * feePerLock);
        assertEq(beneficiary.balance, total - count * feePerLock);
        assertEq(address(timeLock).balance, timeLock.accruedFees());
    }

    /// @dev TLW-5: nobody except the beneficiary can claim, for any caller address.
    function testFuzz_claimLock_anyNonBeneficiary_reverts(address caller) public {
        vm.assume(caller != beneficiary);
        uint256 lockId = _createMaturedLock(beneficiary);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(TimeLockWallet.NotBeneficiary.selector, caller));
        timeLock.claimLock(lockId);
    }

    /// @dev TLW-1: any unlock time earlier than now + MIN_DELAY is rejected.
    function testFuzz_createLock_tooEarly_reverts(uint256 delay) public {
        delay = bound(delay, 0, timeLock.MIN_DELAY() - 1);
        uint64 unlockTime = uint64(block.timestamp + delay);

        vm.prank(depositor);
        vm.expectRevert(
            abi.encodeWithSelector(
                TimeLockWallet.UnlockTimeTooEarly.selector, unlockTime, block.timestamp + timeLock.MIN_DELAY()
            )
        );
        timeLock.createLock{value: LOCK_AMOUNT}(beneficiary, unlockTime);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// @dev Creates a 1 ETH lock from the depositor for `lockBeneficiary` and warps to its unlock time.
    function _createMaturedLock(address lockBeneficiary) internal returns (uint256 lockId) {
        uint64 lockUnlockTime = uint64(block.timestamp + timeLock.MIN_DELAY());

        vm.prank(depositor);
        lockId = timeLock.createLock{value: LOCK_AMOUNT}(lockBeneficiary, lockUnlockTime);

        vm.warp(lockUnlockTime);
    }

    /// @dev After a reverted attack the whole transaction is rolled back, so the lock must still be Open and funded.
    function _assertLockStillOpen(uint256 lockId) internal view {
        TimeLockWallet.Lock memory lock = timeLock.getLock(lockId);
        assertEq(uint256(lock.status), uint256(TimeLockWallet.LockStatus.Open));
        assertGe(address(timeLock).balance, lock.amount);
    }
}
