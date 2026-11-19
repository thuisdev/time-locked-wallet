// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @title TimeLockWallet – ETH time-locks for beneficiaries
/// @author Adrian (thuisdev)
/// @notice Anyone can lock ETH for a beneficiary until a future unlock time. The beneficiary claims after unlock, either
///         to themselves or to a chosen recipient. If a lock stays unclaimed past a grace period, the depositor can
///         reclaim it. A small protocol fee is taken on claims and withdrawn separately by the owner.
/// @dev All ETH-moving functions follow checks-effects-interactions and use nonReentrant (TLW-12). Internal accounting
///      (lock amounts + accruedFees) is the source of truth, never address(this).balance, because ETH can be
///      force-sent to the contract (e.g. via selfdestruct) without ever hitting receive().
contract TimeLockWallet is Ownable2Step, Pausable, ReentrancyGuard {
    // -------------------------------------------------------------------------
    // Type declarations
    // -------------------------------------------------------------------------

    using SafeCast for uint256;

    /// @notice Lifecycle of a lock. Starts Open and ends in exactly one terminal state, so a lock can never be both
    ///         claimed and reclaimed.
    enum LockStatus {
        Open,
        Claimed,
        Reclaimed
    }

    /// @notice A single time-lock.
    /// @dev Packed into 3 storage slots: depositor | beneficiary | amount (16 B) + unlockTime (8 B) + status (1 B).
    struct Lock {
        address depositor;
        address beneficiary;
        uint128 amount;
        uint64 unlockTime;
        LockStatus status;
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /// @notice Minimum time between lock creation and unlock time.
    uint256 public constant MIN_DELAY = 1 days;

    /// @notice Time after unlock before the depositor may reclaim an unclaimed lock.
    uint256 public constant GRACE_PERIOD = 30 days;

    /// @notice Maximum number of lock IDs per batch claim. Keeps the batch gas-bounded.
    uint256 public constant MAX_BATCH = 32;

    /// @notice Protocol fee charged on each claim payout, in basis points (50 = 0.5%).
    uint256 public constant FEE_BPS = 50;

    /// @notice Basis point denominator (10_000 = 100%).
    uint256 public constant BPS_DENOMINATOR = 10_000;

    // -------------------------------------------------------------------------
    // State variables
    // -------------------------------------------------------------------------

    /// @notice Protocol fees accrued from claims and not yet withdrawn by the owner, in wei.
    uint256 public accruedFees;

    /// @notice ID that will be assigned to the next created lock. Starts at 1 so ID 0 is never a valid lock.
    uint256 public nextLockId = 1;

    /// @dev Lock ID => lock data. Private because the auto-getter would return a tuple instead of the struct.
    mapping(uint256 => Lock) private _locks;

    /// @dev Beneficiary => all lock IDs created for them. Private because the auto-getter needs an index per element.
    mapping(address => uint256[]) private _beneficiaryLockIds;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a new lock is created.
    /// @param lockId      Unique ID of the new lock.
    /// @param beneficiary Address allowed to claim the lock after unlock.
    /// @param depositor   Address that funded the lock.
    /// @param amount      Locked amount in wei.
    /// @param unlockTime  Timestamp from which the lock can be claimed.
    event LockCreated(
        uint256 indexed lockId,
        address indexed beneficiary,
        address indexed depositor,
        uint256 amount,
        uint256 unlockTime
    );

    /// @notice Emitted for every lock paid out to the beneficiary or their chosen recipient (single and batch claim).
    /// @param lockId      ID of the claimed lock.
    /// @param recipient   Address that received the payout.
    /// @param beneficiary Beneficiary of the lock (the caller).
    /// @param depositor   Address that originally funded the lock.
    /// @param payout      Amount sent to the recipient after the fee, in wei.
    /// @param fee         Protocol fee accrued from this lock, in wei.
    event FundsClaimed(
        uint256 indexed lockId,
        address indexed recipient,
        address indexed beneficiary,
        address depositor,
        uint256 payout,
        uint256 fee
    );

    /// @notice Emitted when a depositor reclaims an unclaimed lock after the grace period.
    /// @param lockId      ID of the reclaimed lock.
    /// @param beneficiary Beneficiary who did not claim in time.
    /// @param depositor   Depositor who received the full amount back.
    /// @param amount      Full locked amount returned, in wei (no fee on reclaims).
    event FundsReclaimed(uint256 indexed lockId, address beneficiary, address indexed depositor, uint256 amount);

    /// @notice Emitted when the owner withdraws accrued protocol fees.
    /// @param to     Address that received the fees.
    /// @param amount Amount withdrawn, in wei.
    event FeesWithdrawn(address indexed to, uint256 amount);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @notice Thrown when an address parameter is the zero address.
    error ZeroAddress();

    /// @notice Thrown when an amount (ETH sent or fee withdrawal) is zero.
    error ZeroAmount();

    /// @notice Thrown when the requested unlock time is earlier than now + MIN_DELAY.
    /// @param unlockTime      The unlock time that was requested.
    /// @param earliestAllowed The earliest unlock time that would have been accepted.
    error UnlockTimeTooEarly(uint256 unlockTime, uint256 earliestAllowed);

    /// @notice Thrown when a lock ID does not exist.
    /// @param lockId The ID that was looked up.
    error LockNotFound(uint256 lockId);

    /// @notice Thrown when a lock was already claimed or reclaimed.
    /// @param lockId        ID of the lock.
    /// @param currentStatus The terminal status the lock is already in.
    error LockNotOpen(uint256 lockId, LockStatus currentStatus);

    /// @notice Thrown when someone other than the beneficiary tries to claim a lock.
    /// @param caller The address that attempted the claim.
    error NotBeneficiary(address caller);

    /// @notice Thrown when someone other than the depositor tries to reclaim a lock.
    /// @param caller The address that attempted the reclaim.
    error NotDepositor(address caller);

    /// @notice Thrown when a lock is claimed before its unlock time.
    /// @param currentTimestamp Current block timestamp.
    /// @param unlockTime       Timestamp from which the lock can be claimed.
    error FundsStillLocked(uint256 currentTimestamp, uint256 unlockTime);

    /// @notice Thrown when a lock is reclaimed before unlock time + GRACE_PERIOD.
    /// @param currentTimestamp Current block timestamp.
    /// @param reclaimableAt    Timestamp from which the depositor can reclaim.
    error FundsNotAvailableToReclaim(uint256 currentTimestamp, uint256 reclaimableAt);

    /// @notice Thrown when a batch claim contains more than MAX_BATCH IDs.
    /// @param count    Number of IDs passed.
    /// @param maxBatch Maximum allowed number of IDs.
    error BatchTooLarge(uint256 count, uint256 maxBatch);

    /// @notice Thrown when a batch claim is called with an empty ID list.
    error EmptyBatch();

    /// @notice Thrown when the owner tries to withdraw more than the accrued fees.
    /// @param available Accrued fees currently available, in wei.
    /// @param requested Amount the owner tried to withdraw, in wei.
    error InsufficientFees(uint256 available, uint256 requested);

    /// @notice Thrown when a low-level ETH transfer fails.
    error TransferFailed();

    /// @notice Thrown when plain ETH is sent to the contract without creating a lock.
    error DirectEthNotAccepted();

    /// @notice Thrown when the contract is called with unknown calldata.
    error FallbackNotSupported();

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @param initialOwner Admin address that can pause/unpause and withdraw protocol fees. OZ reverts on zero address.
    constructor(address initialOwner) Ownable(initialOwner) {}

    // -------------------------------------------------------------------------
    // Receive / fallback
    // -------------------------------------------------------------------------

    // TLW-2: reject plain ETH that bypasses lock creation
    /// @notice Rejects plain ETH transfers. Use createLock to deposit.
    receive() external payable {
        revert DirectEthNotAccepted();
    }

    // TLW-2: reject calls with unknown calldata
    /// @notice Rejects calls that do not match any function.
    fallback() external {
        revert FallbackNotSupported();
    }

    // -------------------------------------------------------------------------
    // External: payable
    // -------------------------------------------------------------------------

    // TLW-1: create a lock for a non-zero beneficiary with amount > 0 and unlock time >= now + MIN_DELAY
    /// @notice Locks the sent ETH for `beneficiary` until `unlockTime`.
    /// @dev Emits LockCreated. Reverts if paused, beneficiary is zero, unlock time is too early, no ETH is sent, or
    ///      msg.value exceeds uint128 (SafeCast). No external calls, so nonReentrant is not required.
    /// @param beneficiary Address that will be allowed to claim the lock.
    /// @param unlockTime  Timestamp from which the beneficiary can claim. Must be at least MIN_DELAY in the future.
    /// @return lockId     Unique ID of the newly created lock.
    function createLock(address beneficiary, uint64 unlockTime)
        external
        payable
        whenNotPaused
        returns (uint256 lockId)
    {
        // Checks
        if (beneficiary == address(0)) {
            revert ZeroAddress();
        }

        uint256 earliestAllowed = block.timestamp + MIN_DELAY;
        if (unlockTime < earliestAllowed) {
            revert UnlockTimeTooEarly(unlockTime, earliestAllowed);
        }

        if (msg.value == 0) {
            revert ZeroAmount();
        }

        // Effects
        lockId = nextLockId;
        nextLockId = lockId + 1;

        _locks[lockId] = Lock({
            depositor: msg.sender,
            beneficiary: beneficiary,
            amount: msg.value.toUint128(),
            unlockTime: unlockTime,
            status: LockStatus.Open
        });

        // TLW-4: index by beneficiary so lookups never scan storage
        _beneficiaryLockIds[beneficiary].push(lockId);

        emit LockCreated(lockId, beneficiary, msg.sender, msg.value, unlockTime);

        // Interactions: none
    }

    // -------------------------------------------------------------------------
    // External: state-changing
    // -------------------------------------------------------------------------

    // TLW-5: beneficiary claims a matured lock to themselves
    // TLW-12: nonReentrant on every ETH-moving function
    /// @notice Claims a matured lock and sends the payout (minus protocol fee) to the caller.
    /// @dev Emits FundsClaimed. Reverts if paused, lock does not exist or is not open, caller is not the beneficiary,
    ///      or the lock has not matured yet.
    /// @param lockId ID of the lock to claim.
    function claimLock(uint256 lockId) external nonReentrant whenNotPaused {
        _claim(lockId, msg.sender);
    }

    // TLW-6: same as TLW-5, but the payout goes to a chosen non-zero recipient
    // TLW-12: nonReentrant on every ETH-moving function
    /// @notice Claims a matured lock and sends the payout (minus protocol fee) to `recipient`.
    /// @dev Emits FundsClaimed. Same reverts as claimLock, plus ZeroAddress if recipient is the zero address.
    /// @param lockId    ID of the lock to claim.
    /// @param recipient Address that receives the payout.
    function claimTo(uint256 lockId, address recipient) external nonReentrant whenNotPaused {
        if (recipient == address(0)) {
            revert ZeroAddress();
        }
        _claim(lockId, recipient);
    }

    // TLW-7: depositor reclaims an unclaimed lock after unlock time + GRACE_PERIOD
    // TLW-12: nonReentrant on every ETH-moving function
    /// @notice Returns the full amount of an unclaimed lock to its depositor once the grace period has passed.
    /// @dev Emits FundsReclaimed. No protocol fee on reclaims. Reverts if paused, lock does not exist or is not open,
    ///      caller is not the depositor, or unlock time + GRACE_PERIOD has not been reached. After the grace period
    ///      both the beneficiary (claim) and the depositor (reclaim) may act; whoever comes first wins.
    /// @param lockId ID of the lock to reclaim.
    function reclaimLock(uint256 lockId) external nonReentrant whenNotPaused {
        // Checks
        Lock storage lock = _getOpenLock(lockId);

        if (lock.depositor != msg.sender) {
            revert NotDepositor(msg.sender);
        }

        uint256 reclaimableAt = lock.unlockTime + GRACE_PERIOD;
        if (block.timestamp < reclaimableAt) {
            revert FundsNotAvailableToReclaim(block.timestamp, reclaimableAt);
        }

        uint256 amount = lock.amount;

        // Effects
        lock.status = LockStatus.Reclaimed;

        emit FundsReclaimed(lockId, lock.beneficiary, msg.sender, amount);

        // Interactions
        (bool success,) = msg.sender.call{value: amount}("");
        if (!success) {
            revert TransferFailed();
        }
    }

    // TLW-8: claim several matured locks in one transaction with a single transfer
    // TLW-12: state for all IDs is updated before the one external call
    /// @notice Claims up to MAX_BATCH matured locks at once and sends the combined payout to the caller.
    /// @dev Emits FundsClaimed per lock. Constant work per ID, no storage scans. Reverts if paused, the list is empty
    ///      or longer than MAX_BATCH, or any ID is invalid or ineligible. Duplicate IDs revert with LockNotOpen because
    ///      each lock is marked Claimed inside the loop before the next ID is checked.
    /// @param lockIds IDs of the locks to claim.
    function claimBatch(uint256[] calldata lockIds) external nonReentrant whenNotPaused {
        // Checks
        uint256 count = lockIds.length;

        if (count == 0) {
            revert EmptyBatch();
        }

        if (count > MAX_BATCH) {
            revert BatchTooLarge(count, MAX_BATCH);
        }

        uint256 totalPayout = 0;
        uint256 totalFees = 0;

        for (uint256 i = 0; i < count;) {
            uint256 lockId = lockIds[i];

            // Checks per ID: exists, open, caller is beneficiary, matured
            Lock storage lock = _getClaimableLock(lockId);

            uint256 amount = lock.amount;
            uint256 fee = _calculateFee(amount);
            uint256 payout = amount - fee;

            // Effects per ID
            lock.status = LockStatus.Claimed;
            totalFees += fee;
            totalPayout += payout;

            emit FundsClaimed(lockId, msg.sender, msg.sender, lock.depositor, payout, fee);

            // Safe: i is bounded by MAX_BATCH, overflow is impossible
            unchecked {
                ++i;
            }
        }

        // Effects
        // TLW-9: accrue fees internally, never forwarded inline
        accruedFees += totalFees;

        // Interactions
        (bool success,) = msg.sender.call{value: totalPayout}("");
        if (!success) {
            revert TransferFailed();
        }
    }

    // TLW-10: owner withdraws accrued protocol fees through a separate path
    // TLW-12: nonReentrant on every ETH-moving function
    /// @notice Withdraws `amount` of accrued protocol fees to `to`.
    /// @dev Emits FeesWithdrawn. Reverts if caller is not the owner, contract is paused, `to` is zero, amount is
    ///      zero, or amount exceeds accruedFees.
    /// @param to     Address that receives the fees.
    /// @param amount Amount to withdraw, in wei.
    function withdrawFees(address to, uint256 amount) external nonReentrant onlyOwner whenNotPaused {
        // Checks
        if (to == address(0)) {
            revert ZeroAddress();
        }

        if (amount == 0) {
            revert ZeroAmount();
        }

        if (amount > accruedFees) {
            revert InsufficientFees(accruedFees, amount);
        }

        // Effects
        accruedFees -= amount;

        emit FeesWithdrawn(to, amount);

        // Interactions
        (bool success,) = to.call{value: amount}("");
        if (!success) {
            revert TransferFailed();
        }
    }

    // TLW-11: owner can pause create, claim, reclaim, batch claim and fee withdrawal
    /// @notice Pauses all lock creation, claims, reclaims, batch claims and fee withdrawals.
    /// @dev Emits Paused (from OZ Pausable). OZ's _pause already reverts if the contract is already paused.
    function pause() external onlyOwner {
        _pause();
    }

    // TLW-11: owner can unpause
    /// @notice Unpauses the contract.
    /// @dev Emits Unpaused (from OZ Pausable). OZ's _unpause already reverts if the contract is not paused.
    function unpause() external onlyOwner {
        _unpause();
    }

    // -------------------------------------------------------------------------
    // External: view
    // -------------------------------------------------------------------------

    // TLW-3: return stored lock data for an existing ID
    /// @notice Returns the full data of a lock.
    /// @dev Reverts with LockNotFound if the ID was never created.
    /// @param lockId ID of the lock.
    /// @return lock  The stored lock struct.
    function getLock(uint256 lockId) external view returns (Lock memory lock) {
        lock = _locks[lockId];

        if (lock.depositor == address(0)) {
            revert LockNotFound(lockId);
        }
    }

    // TLW-4: return lock IDs of a beneficiary without scanning storage
    /// @notice Returns all lock IDs ever created for `beneficiary`, including already claimed or reclaimed ones.
    /// @dev Returns an empty array for addresses without locks. That is a valid answer, not an error.
    /// @param beneficiary Address to look up.
    /// @return lockIds    All lock IDs created for this beneficiary.
    function getBeneficiaryLockIds(address beneficiary) external view returns (uint256[] memory lockIds) {
        lockIds = _beneficiaryLockIds[beneficiary];
    }

    // -------------------------------------------------------------------------
    // Internal: state-changing
    // -------------------------------------------------------------------------

    /// @notice Shared claim logic for claimLock and claimTo.
    /// @dev Internal and without modifiers on purpose: it can only be reached through the guarded external entry
    ///      points, so pause and reentrancy protection cannot be bypassed.
    /// @param lockId    ID of the lock to claim.
    /// @param recipient Address that receives the payout.
    function _claim(uint256 lockId, address recipient) internal {
        // Checks: exists, open, caller is beneficiary, matured
        Lock storage lock = _getClaimableLock(lockId);

        uint256 amount = lock.amount;
        uint256 fee = _calculateFee(amount);
        uint256 payout = amount - fee;

        // Effects
        lock.status = LockStatus.Claimed;

        // TLW-9: accrue fee internally, never forwarded inline
        accruedFees += fee;

        emit FundsClaimed(lockId, recipient, msg.sender, lock.depositor, payout, fee);

        // Interactions
        (bool success,) = recipient.call{value: payout}("");
        if (!success) {
            revert TransferFailed();
        }
    }

    // -------------------------------------------------------------------------
    // Internal: view
    // -------------------------------------------------------------------------

    /// @notice Loads a lock and checks that it exists and is still open.
    /// @dev Returns a storage pointer so callers can update the status in place. Used by claim, batch and reclaim.
    /// @param lockId ID of the lock.
    /// @return lock  Storage pointer to the lock.
    function _getOpenLock(uint256 lockId) internal view returns (Lock storage lock) {
        lock = _locks[lockId];

        if (lock.depositor == address(0)) {
            revert LockNotFound(lockId);
        }

        if (lock.status != LockStatus.Open) {
            revert LockNotOpen(lockId, lock.status);
        }
    }

    /// @notice Loads a lock and checks everything needed for a claim.
    /// @dev Builds on _getOpenLock (exists + open) and adds beneficiary and maturity checks. Used by single and batch
    ///      claim so every check exists exactly once.
    /// @param lockId ID of the lock.
    /// @return lock  Storage pointer to the lock.
    function _getClaimableLock(uint256 lockId) internal view returns (Lock storage lock) {
        lock = _getOpenLock(lockId);

        if (lock.beneficiary != msg.sender) {
            revert NotBeneficiary(msg.sender);
        }

        if (block.timestamp < lock.unlockTime) {
            revert FundsStillLocked(block.timestamp, lock.unlockTime);
        }
    }

    // -------------------------------------------------------------------------
    // Internal: pure
    // -------------------------------------------------------------------------

    /// @notice Calculates the protocol fee for a given amount.
    /// @dev Multiplies before dividing to avoid truncating to zero. Rounds down, so tiny amounts (< 200 wei) pay no
    ///      fee and any rounding favours the user.
    /// @param amount Amount in wei.
    /// @return fee   Protocol fee in wei.
    function _calculateFee(uint256 amount) internal pure returns (uint256 fee) {
        fee = (amount * FEE_BPS) / BPS_DENOMINATOR;
    }
}
