# TimeLockWallet

A time-locked ETH wallet. Anyone can lock ETH for a beneficiary until a future unlock time. The beneficiary claims
after unlock (to themselves or to a chosen recipient), a depositor can reclaim an unclaimed lock after a grace period,
and a 0.5% protocol fee is accrued on claims and withdrawn separately by the owner.

```bash
forge build
forge test          # 12 tests, 4 of them fuzz tests (256 runs each)
forge test -vvvv --mt reentrancy   # see the blocked re-entry in the traces
```

| Parameter | Value | Why |
|---|---|---|
| `MIN_DELAY` | 1 day | Long enough to be a real lock, short enough to test easily |
| `GRACE_PERIOD` | 30 days | Gives the beneficiary a fair window before the depositor can take the funds back |
| `MAX_BATCH` | 32 | Caps a batch claim well below the block gas limit |
| `FEE_BPS` | 50 (0.5%) | A small protocol fee on claims |

---

## Design

**Checks-effects-interactions, plus `nonReentrant`.** Every ETH-moving function validates, updates storage, then makes
exactly one external call. In the batch claim this matters most: all locks are marked `Claimed` and `accruedFees` is
updated before the single transfer at the end.

**Helpers return `Lock storage`, not a copy.** A `Lock memory` is a copy. Setting its status to `Claimed` would
change nothing in the mapping, and the same lock could be claimed again. `_getOpenLock` and `_getClaimableLock`
return a storage pointer.

**One status, not two flags.** `LockStatus` (`Open`, `Claimed`, `Reclaimed`) can only be one of those values, so a
lock can never be both claimed and reclaimed. "Still payable" is a single check: `status == Open`.

**Checks live in internal functions.** A batch claim has to run the same checks for every ID inside a loop, and a
modifier only runs once at function entry. The chain is `_claim` / `claimBatch` → `_getClaimableLock` (beneficiary,
matured) → `_getOpenLock` (exists, open). Each check exists once.

**One internal worker, several guarded entry points.** `claimLock` and `claimTo` call the internal `_claim`. The
modifiers sit on the external functions, and `_claim` has no external door, so pause and reentrancy protection
cannot be bypassed.

**Storage packing.** The `Lock` struct uses 3 slots: `address` | `address` | `uint128 amount` + `uint64 unlockTime` +
`LockStatus`. `uint128` is still far more than all ETH that exists. `SafeCast.toUint128` reverts on an oversized
`msg.value` instead of truncating it.

**Fees in basis points.** 0.5% is `amount * 50 / 10_000`. The multiplication comes first, because `50 / 10_000` alone
is `0`. Division rounds down, so amounts under 200 wei pay no fee and rounding favours the user.

**Fees are accounted internally.** ETH can be forced into a contract (for example via `selfdestruct`) without hitting
`receive()`. `accruedFees` is the only source of truth for fee withdrawal, not `address(this).balance`.

**Other choices:**
- `Ownable2Step` instead of `AccessControl`. There is one admin. A second access system would add a second authority
  and a larger attack surface. `AccessControl` would fit separate roles, such as a pauser and a treasury multisig.
- An empty batch reverts with `EmptyBatch`. A 0 ETH transfer would almost certainly be a caller bug.
- `getBeneficiaryLockIds` returns an empty array for unknown addresses. "No locks yet" is a valid answer.
- After the grace period both the beneficiary (claim) and the depositor (reclaim) can act. Whoever comes first wins;
  the status check guarantees only one payout. Exactly `now + MIN_DELAY` is a valid unlock time.

---

## Testing

12 tests, each aimed at one property.

**Reentrancy.** A `ReentrantAttacker` stores an `AttackMode` and re-enters the same function from its `receive()`.
`receive()` has no parameters, so the attacker records the mode and target IDs before each attack.

| Test | Attacker plays | Path |
|---|---|---|
| `test_claimLock_reentrancy_reverts` | beneficiary | single claim |
| `test_claimBatch_reentrancy_reverts` | beneficiary of 2 locks | batch claim |
| `test_reclaimLock_reentrancy_reverts` | depositor | reclaim |
| `test_withdrawFees_reentrancy_reverts` | owner (via `transferOwnership` + `acceptOwnership`) | fee withdrawal |

Each test expects `TransferFailed` and then checks that the lock is still `Open` (or the fees are untouched), so no
ETH left the contract. The re-entry itself reverts with `ReentrancyGuardReentrantCall` inside the attacker's
`receive()`. The wallet's low-level call only sees `success = false` and turns that into `TransferFailed`. A `-vvvv`
trace shows the chain:

```
ReentrantAttacker::attackClaim(1)
 └─ TimeLockWallet::claimLock(1)
     ├─ emit FundsClaimed(...)
     ├─ ReentrantAttacker::receive{value: 0.995 ETH}
     │   └─ TimeLockWallet::claimLock(1)
     │       └─ ← [Revert] ReentrancyGuardReentrantCall()
     └─ ← [Revert] TransferFailed()
```

**Guards.**
- `test_pause_blocksAllValuePaths`: one paused state blocks create, claim, batch claim, reclaim and fee withdrawal.
- `test_claimBatch_overCap_reverts`: 33 IDs revert with `BatchTooLarge`.
- `test_claimBatch_duplicateIds_reverts`: `[id, id]` reverts with `LockNotOpen`, so a lock cannot be paid twice in one
  batch.
- `test_receive_plainEth_reverts`: plain ETH is rejected.

**Fuzz tests (256 runs each).**
- `testFuzz_claimLock_anyAmount_accountingHolds`: for any amount from 1 wei to 1M ETH, payout + fee = amount, the fee
  matches `FEE_BPS`, and afterwards the contract holds exactly `accruedFees`. This also covers the rounding edge case.
- `testFuzz_claimBatch_anyCount_accountingHolds`: for any batch size from 1 to 32, one transfer pays the correct sum.
- `testFuzz_claimLock_anyNonBeneficiary_reverts`: no address except the beneficiary can claim.
- `testFuzz_createLock_tooEarly_reverts`: every unlock time below `now + MIN_DELAY` is rejected.
