# Security-research-writeups
### This contains writeups about my past audit findings, while these does not contain all as i keep updating them, thanks for checking!
I am a security researcher specializing in smart contract auditing, with a proven track record of identifying high-impact vulnerabilities in competitive audit environments. My approach combines deep technical expertise in blockchain security with an AI‑assisted audit agent that enhances detection capabilities, enabling me to deliver thorough and efficient audits.

### Security Experience & Achievements

1. Folks Smart Contract Library Audit (Immunefi)

    Rank: 5th place
    
    Reward: $1,308
    
    Details: Competed in a public audit competition for the Folks Smart Contract Library, a curated collection of reusable smart contracts on the Algorand blockchain. Leveraged my proprietary   AI agent to systematically analyze the codebase, contributing to the discovery of valid vulnerabilities.
    
    Leaderboard: https://immunefi.com/audit-competition/folks-sc-library/leaderboard/#top

2. Reserve Governor Audit (Cantina)

    Rank: 3rd place
    
    Reward: $371
    
    Details: Participated in a competitive audit of the Reserve Governor protocol on Cantina. My AI‑assisted methodology played a key role in identifying critical issues, securing a podium finish.
    
    Leaderboard:  https://cantina.xyz/code/980a5976-9a7d-4014-b2e1-c248b4c6fa44/overview/leaderboard

### My Audit Approach

My audit process is built on a hybrid methodology that combines:

Manual Security Review: In‑depth analysis of business logic, access controls, and economic assumptions.

AI‑Assisted Vulnerability Detection: A custom‑built AI agent that augments traditional static analysis with advanced pattern recognition, enabling me to surface subtle vulnerabilities more efficiently.

Proven Results: This integrated approach has consistently delivered competitive results, as demonstrated by my top‑5 placements in high‑stakes audit competitions.

### Why Work With Me

I am committed to delivering valuable, actionable audits that help secure your protocol. By combining my security skills with my AI agent, I provide a comprehensive assessment that goes beyond standard tooling offering clear vulnerability classifications, evidence snippets, impact explanations, and remediation guidance. I look forward to contributing to the security of your projec


# Reserve Governor Audit Findings | Cantina Competition

**Competition:** Cantina - Reserve Governor  
**Rank:** 🥉 3rd Place  
**Reward:** $371  
**Date:** 10th May 2026  
**Repository:** [Reserve Protocol / Governor](https://github.com/reserve-protocol/reserve-governor)

---

## Overview

This portfolio entry documents two distinct vulnerabilities identified during the Reserve Governor audit competition. My approach combined manual security review with an AI‑assisted detection agent, which helped prioritize high-risk code paths and led to the discovery of subtle economic and governance logic flaws.

The findings below include:
1. **Economic Griefing via Zero-Value Transfers** (Reward Rounding Exploit)
2. **Optimistic Veto Threshold Manipulation** (Temporary Staking Attack)

---

## Finding #1: Economic Griefing via Zero-Value Transfers

- **Severity:** Medium (Economic Griefing)
- **Category:** Reward Accounting / Integer Rounding
- **Affected Contract:** `StakingVault.sol`

### Description
The `StakingVault` allows anyone to trigger reward accrual for any staker by calling `transfer(victim, 0)`. When this happens, the contract calculates rewards using integer division, which can round down to zero for small balances or short time intervals.

The critical flaw is that **even when zero rewards are calculated**, the contract still advances the victim's `lastRewardIndex` pointer to the current global index. This permanently "burns" the victim's fractional reward entitlement—they can never claim it.

### Root Cause
The reward index pointer advances **unconditionally** when global rewards change, discarding fractional user entitlements that rounded to zero.

**Vulnerable Code Snippet:**
```solidity
function _accrueUser(address _user, address _rewardToken) internal {
    // ...
    if (deltaIndex != 0) { //  Only checks if global index changed
        uint256 supplierDelta = Math.mulDiv(balanceOf(_user), deltaIndex, uint256(10 ** decimals()) * SCALAR);
        userRewardTracker.accruedRewards += supplierDelta; // Can be 0.
        userRewardTracker.lastRewardIndex = rewardInfo.rewardIndex; //  Advances regardless of supplierDelta
    }
}

Attack Vector
An attacker can weaponize this by calling vault.transfer(victim, 0) repeatedly. Each call:

Triggers the _update() function.

Runs accrueRewards for the victim.

Calculates zero rewards due to the short interval.

Advances the victim's index anyway, burning their fractional reward entitlement.

The attacker pays only gas costs, making this a permissionless economic griefing attack.

Proof of Concept (PoC)

```solidity
function test_poc_zeroValueTransferCanBurnVictimRewardAccrual() public {
    address attacker = makeAddr("attacker");
    _mintAndDepositFor(ACTOR_ALICE, 10e18);   // Small staker
    _mintAndDepositFor(ACTOR_BOB, 990e18);    // Large staker

    reward.mint(address(vault), 1e6);
    vault.poke();
    vm.warp(block.timestamp + 1);

    // Attacker triggers accrual for Alice via zero-value transfer
    vm.prank(attacker);
    vault.transfer(ACTOR_ALICE, 0);

    (, uint256 rewardIndex,,,) = vault.rewardTrackers(address(reward));
    (uint256 aliceLastRewardIndex, uint256 aliceAccruedRewards) =
        vault.userRewardTrackers(address(reward), ACTOR_ALICE);

    // Alice's index was advanced but she got zero rewards
    assertEq(aliceLastRewardIndex, rewardIndex);
    assertEq(aliceAccruedRewards, 0); // Rewards are permanently lost
}
```
# Finding #2: Optimistic Veto Threshold Manipulation

- **Severity:** Medium (Governance Bypass)
- **Category:** Governance Logic
- **Affected Contracts:** `ReserveOptimisticGovernor.sol` & `StakingVault.sol`

---

## Description

An attacker can temporarily stake before an optimistic proposal's veto snapshot to inflate `pastTotalSupply`, raising the number of **Against** votes required to veto the proposal.

The veto threshold is calculated as:

```solidity
(_vetoThreshold * pastSupply) / 1e18
Since the snapshot is taken after the vetoDelay, the total supply used for the threshold is not fixed when the optimistic proposal is created. A malicious user can deposit a large amount during the delay period, inflating the supply and thus the absolute number of votes required to block the proposal.

Impact
This breaks the expected veto guarantee. A malicious proposer can make a controversial optimistic proposal harder to veto by temporarily increasing the snapshot supply. If the honest voters cannot meet the newly inflated threshold, the proposal succeeds on the fast path without going through the slower confirmation vote.

Proof of Concept (PoC)
```soldity
function test_temporaryPreSnapshotStakeCanRaiseVetoThresholdAndPreventVeto() public {
    address attacker = makeAddr("vetoThresholdInflator");
    // Community has exactly 200,000 votes (initial supply is 1,000,000).
    // Veto threshold is 20%, so 200,000 votes are required.

    // Proposer creates the optimistic proposal.
    vm.prank(optimisticProposer);
    uint256 proposalId = governor.proposeOptimistic(targets, values, calldatas, "PoC");

    // Attacker deposits 250,000 shares during the vetoDelay.
    _mintDepositAndDelegate(attacker, 250_000e18);

    // Snapshot is taken. Total supply is now 1,250,000.
    _warpToActive(proposalId);
    uint256 snapshot = governor.proposalSnapshot(proposalId);

    // Veto threshold is now 250,000 votes.
    assertEq((VETO_THRESHOLD * stakingVault.getPastTotalSupply(snapshot)) / 1e18, 250_000e18);

    // Community casts their 200,000 Against votes.
    _communityCastAgainst(communityMembers, proposalId);

    // Proposal remains Active because 200,000 < 250,000.
    assertEq(uint256(governor.state(proposalId)), uint256(IGovernor.ProposalState.Active));

    // Veto period ends. Proposal succeeds without being blocked.
    _warpPastDeadline(proposalId);
    assertEq(uint256(governor.state(proposalId)), uint256(IGovernor.ProposalState.Succeeded));
}
```

Run with:

```solidity
forge test --match-test test_temporaryPreSnapshotStakeCanRaiseVetoThresholdAndPreventVeto
```
Recommendation
Do not calculate the optimistic veto threshold from a supply snapshot that can be inflated after proposal creation. Use a fixed snapshot taken at proposal creation time, or implement a minimum veto period that accounts for potential staking changes.

Detection Methodology
Both of these vulnerabilities were identified using a hybrid audit approach:

AI-Assisted Triage: My proprietary AI agent extracted structural features (opcode frequencies, state updates, visibility modifiers) and used a stacked ML ensemble (XGBoost, Random Forest, MLP) to flag high-risk functions. For example, the agent flagged _accrueUser due to the unconditional state update pattern following arithmetic division, prompting a manual deep-dive.

Manual Verification: Each flagged area was manually reviewed to confirm exploitability and build the Proof of Concept.


Conclusion
The Reserve Governor audit highlighted the importance of rigorous logic validation in both reward accounting and governance mechanisms. The vulnerabilities discovered range from economic griefing to governance threshold bypasses. By combining AI-assisted pattern recognition with manual expertise, I was able to produce actionable, high-value findings that earned a top-3 placement in this competitive audit.

# Finding: Underflow in `remove_item` Function in `Uint64SetLib`

- **Report ID:** #49687
- **Platform:** Immunefi – Folks Smart Contract Library
- **Rank:** 🥉 11th Place(but ideally 5th because it was a tie)  
- **Reward:** $1308 
- **Severity:** Low
- **Category:** Error Handling / Denial of Service
- **Affected Contract:** `Uint64SetLib.py`
- **Target Repository:** [Folks-Finance/algorand-smart-contract-library](https://github.com/Folks-Finance/algorand-smart-contract-library/blob/main/contracts/library/UInt64SetLib.py)
- **Submitted:** July 18, 2025

---

## Description

The `remove_item` function in `Uint64SetLib` computes `last_idx = items.length - 1` as its first operation. This line does **not** check whether the array is empty (length = 0). When called on an empty array, this results in an **underflow** (in Python/Algorand context, this causes a runtime error/revert).

While the function behaves correctly for non-empty arrays, the absence of an empty-array guard leads to unexpected reverts without meaningful feedback, causing confusion for developers and users interacting with the library.

---

## Vulnerability Details

The current implementation is:

```python
def remove_item(to_remove: UInt64, items: DynamicArray[ARC4UInt64]) -> Tuple[Bool, DynamicArray[ARC4UInt64]]:
    last_idx = items.length - 1  # Underflow if items.length == 0
    for idx, item in uenumerate(items):
        if item.native == to_remove:
            last_item = items.pop()
            if idx != last_idx:
                items[idx] = last_item
            return Bool(True), items.copy()
    return Bool(False), items.copy()
```
The root cause is that items.length - 1 is evaluated unconditionally. If the array is empty (items.length == 0), the expression evaluates to -1, which is invalid and causes the contract call to revert with no specific error message.

Impact
This issue has two primary impacts:

Temporary Denial of Service: Any call to remove_item on an empty array will revert, preventing the transaction from succeeding during that block. Since the contract is stateless or reverts deterministically, the functionality is restored in subsequent blocks (if the array is non-empty), but the revert causes unnecessary friction.

Poor Developer Experience: The revert occurs without any descriptive error. Developers or users invoking the function on an empty array will be left with a cryptic underflow error, making debugging and integration unnecessarily difficult.

Proof of Concept (PoC)
Consider the following scenario:
```soldity
# items is an empty DynamicArray
empty_array = DynamicArray[ARC4UInt64]()

# Attempt to remove an item from an empty array
result, updated = remove_item(UInt64(5), empty_array)
#  Reverts due to underflow on last_idx = 0 - 1
```
Without the guard, the call fails immediately with an arithmetic underflow error, rather than gracefully returning (False, empty_array).
Recommendation
Add a simple length check at the beginning of the function to handle the empty-array case gracefully. This improves robustness and aligns with standard library patterns (e.g., OpenZeppelin's EnumerableSet).

Suggested Fix:
```solidity
def remove_item(to_remove: UInt64, items: DynamicArray[ARC4UInt64]) -> Tuple[Bool, DynamicArray[ARC4UInt64]]:
    # Guard against empty array
    if items.length == 0:
        return Bool(False), items.copy()

    last_idx = items.length - 1
    for idx, item in uenumerate(items):
        if item.native == to_remove:
            last_item = items.pop()
            if idx != last_idx:
                items[idx] = last_item
            return Bool(True), items.copy()
    return Bool(False), items.copy()
```
This ensures:

The function returns (False, empty_array) predictably when called on an empty set.

No underflow occurs.

Developers receive a clear boolean signal indicating the item was not present.
