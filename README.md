# TimeLockWallet – Module 6

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
| `MAX_BATCH` | 32 | From the spec; keeps a batch claim far below the block gas limit |
| `FEE_BPS` | 50 (0.5%) | Small enough to be a "small protocol fee" |

All requirement IDs (TLW-1 to TLW-12) are tagged in the contract at the exact place where they are fulfilled.

---

## What I Learned

**Checks-Effects-Interactions is a habit, not a rule you check at the end.** Every ETH-moving function is written in
the same three blocks: validate, update storage, then make exactly one external call. Combined with `nonReentrant`
this gives two independent layers. In the batch claim this mattered most: all locks are marked `Claimed` and
`accruedFees` is updated before the single transfer at the end.

**`storage` vs `memory` is a security question.** A `Lock memory` is a copy. Setting its status to `Claimed` would
change nothing in the mapping, and the same lock could be claimed again and again. The internal helpers
`_getOpenLock` and `_getClaimableLock` therefore return a `Lock storage` pointer.

**Make invalid states unrepresentable.** I first wanted two bools, `claimed` and `reclaimed`. That allows the
impossible state "claimed AND reclaimed". A `LockStatus` enum (`Open`, `Claimed`, `Reclaimed`) can only ever be one
of them, and "not claimed and not reclaimed" collapses into a single check: `status == Open`.

**Reuse checks with internal functions, not modifiers.** The batch claim has to run the same checks for every ID
inside a loop, and a modifier only runs once at the function entry. So the checks live in an internal helper chain:
`_claim` / `claimBatch` → `_getClaimableLock` (beneficiary, matured) → `_getOpenLock` (exists, open). Every check
exists exactly once.

**One internal worker, several guarded entry points.** `claimLock` and `claimTo` are one-liners that call the
internal `_claim`. The modifiers sit on the external functions, and `_claim` has no external door, so pause and
reentrancy protection cannot be bypassed.

**Storage packing.** The `Lock` struct uses 3 slots instead of 5: `address` | `address` | `uint128 amount` +
`uint64 unlockTime` + `LockStatus`. `uint128` is still far more than all ETH that exists. `SafeCast.toUint128`
makes sure an oversized `msg.value` reverts instead of being silently truncated. (With `uint96` for the amount it
would even fit in 2 slots; I kept `uint128` for readability.)

**Fees in basis points and rounding.** Solidity has no decimals, so 0.5% is `amount * 50 / 10_000`. Multiplying
first matters: `50 / 10_000` alone is `0`. Division rounds down, so amounts under 200 wei pay no fee and rounding
always favours the user.

**Internal accounting beats `address(this).balance`.** Even with a reverting `receive()`, ETH can be forced into a
contract (e.g. via `selfdestruct`). So `accruedFees` is tracked in its own variable and is the only source of truth
for the fee withdrawal.

**Design decisions I made on purpose:**
- `Ownable2Step` instead of `AccessControl`. The spec has exactly one admin role. Having both systems would create
  two "bosses" and a bigger attack surface. `AccessControl` would make sense with separate roles (e.g. a pauser and a
  treasury multisig).
- An empty batch reverts with `EmptyBatch`. It would otherwise send a 0 ETH transfer, which is almost certainly a
  frontend bug.
- `getBeneficiaryLockIds` returns an empty array for unknown addresses instead of reverting. "No locks yet" is a valid
  answer, not an error.
- After the grace period both the beneficiary (claim) and the depositor (reclaim) can act. Whoever comes first wins;
  the status check guarantees only one payout.

---

## Problems & Solutions

**1. Every new lock overwrote the previous one.** I wrote `nextLockId = id++`. Post-increment returns the *old*
value, so `nextLockId` stayed at 1 forever and every lock got ID 1. The first depositor's ETH would have been lost.
Fix: `nextLockId = lockId + 1`.

**2. I compared a point in time with a duration.** My first check was `unlockTime <= MIN_DELAY`, which compares a
timestamp (~1.7 billion) with 86,400 seconds, so it never triggered. The correct check is
`unlockTime < block.timestamp + MIN_DELAY`. I also fixed an off-by-one: the spec says "at least", so exactly
`now + MIN_DELAY` must be allowed (`<`, not `<=`). Renaming the variable from `minDelay` to `earliestAllowed` made
the difference between time point and duration impossible to miss.

**3. My maturity check was the wrong way round.** `if (block.timestamp > lock.unlockTime) revert` would have
allowed claims before unlock and blocked them forever after. Fix: revert when `block.timestamp < unlockTime`.

**4. Small Solidity traps that don't exist in JavaScript:**
- `msg.value < 0` is always false; a `uint` can't be negative. Fix: `== 0`.
- `new` is only for deploying contracts. A struct is built with `Lock({field: value, ...})`.
- `_locks[lockId];` only reads; writing needs `_locks[lockId] = ...`.
- Re-declaring a named return variable (`returns (Lock memory lock)` and then `Lock memory lock = ...`) shadows it,
  and the function returns an empty struct.
- A variable declared inside a `for` loop is reset every iteration and doesn't exist after the loop. My batch sum
  had to move above the loop.
- An `external` function can't be called internally, so `getLock` couldn't be reused inside the claim logic.

**5. Foundry: `vm.prank` and `vm.expectRevert` apply to the next external call, any call.**
`createLock(beneficiary, uint64(block.timestamp + timeLock.MIN_DELAY()))` makes `MIN_DELAY()` the next call, so it
consumed the cheatcode and my pause test failed with "next call did not revert as expected". Fix: compute the unlock
time in a variable before `vm.prank` / `vm.expectRevert`.

**6. Which error does a reentrancy test expect?** I expected the guard's error, but the test receives
`TransferFailed`. The re-entry reverts with `ReentrancyGuardReentrantCall` inside the attacker's `receive()`, the
low-level call swallows that revert and returns `success = false`, and my own check turns it into `TransferFailed`.
The `-vvvv` trace shows the whole chain:

```
ReentrantAttacker::attackClaim(1)
 └─ TimeLockWallet::claimLock(1)
     ├─ emit FundsClaimed(...)                     ← effects already done (CEI)
     ├─ ReentrantAttacker::receive{value: 0.995 ETH}
     │   └─ TimeLockWallet::claimLock(1)
     │       └─ ← [Revert] ReentrancyGuardReentrantCall()
     └─ ← [Revert] TransferFailed()
```

---

## Testing Approach

I kept the suite lean: 12 tests that each prove something specific, instead of one test per line.

**Reentrancy (the core requirement).** A `ReentrantAttacker` contract stores an `AttackMode` and re-enters the same
function from its `receive()`. Because `receive()` has no parameters, the attacker remembers the mode and target IDs
before each attack.

| Test | Attacker plays | Path |
|---|---|---|
| `test_claimLock_reentrancy_reverts` | beneficiary | single claim |
| `test_claimBatch_reentrancy_reverts` | beneficiary of 2 locks | batch claim |
| `test_reclaimLock_reentrancy_reverts` | depositor | reclaim |
| `test_withdrawFees_reentrancy_reverts` | owner (via `transferOwnership` + `acceptOwnership`) | fee withdrawal |

Each test expects `TransferFailed` and then checks that the lock is still `Open` (or the fees untouched), proving no
ETH left the contract. The traces confirm that `ReentrancyGuardReentrantCall` is what blocks every attempt.

**Spec rules.**
- `test_pause_blocksAllValuePaths`: one paused state blocks create, claim, batch claim, reclaim and fee withdrawal
  (TLW-11).
- `test_claimBatch_overCap_reverts`: 33 IDs revert with `BatchTooLarge` (TLW-8).
- `test_claimBatch_duplicateIds_reverts`: `[id, id]` reverts with `LockNotOpen`, so a lock can't be paid twice in one
  batch.
- `test_receive_plainEth_reverts`: plain ETH is rejected (TLW-2).

**Fuzz tests (256 runs each).**
- `testFuzz_claimLock_anyAmount_accountingHolds`: for any amount from 1 wei to 1M ETH, payout + fee = amount, the fee
  matches `FEE_BPS`, and afterwards the contract holds exactly `accruedFees`. This also covers the rounding edge case.
- `testFuzz_claimBatch_anyCount_accountingHolds`: for any batch size from 1 to 32, one transfer pays the correct sum.
- `testFuzz_claimLock_anyNonBeneficiary_reverts`: no address except the beneficiary can claim.
- `testFuzz_createLock_tooEarly_reverts`: every unlock time below `now + MIN_DELAY` is rejected.
