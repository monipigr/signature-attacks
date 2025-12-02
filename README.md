# 🔏 Signature Attacks

This project provides a clear, practical and security-focused explanation of how off-chain signatures work in Ethereum and how they should be handled safely within smart contracts. It covers the most commons signature-related attacks and demonstrates how to prevent them using Solidity best practices and OpenZeppelin’s ECDSA library.

## 🤔 What are off-chain signatures and how do they work?

Signatures are used by smart contracts to ensure that a specific action has been authorized by a particular user. So off-chain signatures allow a user to sign a set of data without executing any transaction on-chain. The signature itself does not perform the action; it only represents the **user’s authorization**. Later, this signed data can be submitted to the smart contract either by the signer or by another user, who then executes the action on-chain.
A signature basically serves as proof that a transaction or function call has been authorized by the private key owner.

A **normal transaction** in blockchain follows this flow:

1. There is an on-chain smart contract that user A wants to interact with.
2. User A signs the transaction using their wallet.
3. User A pays the gas fee.
4. The transaction is executed immediately and stored on-chain.

An **off-chain signature transaction** follows a different logic:

1. There is a user A (signer) and a user B (the executor).
2. User A signs the off-chain data, delegating the execution of a specific and limited action to user B.
3. User A’s signature authorizes the spending of their funds under the exact conditions encoded in the signed data.
4. User B submits the signed data to the smart contract, executes the authorized action on-chain, and pays the gas fee.

Ensuring that signatures implementation are correctly handled by smart contracts is critically important, since incorrect handling of off-chain signatures can lead to critical vulnerabilities or explotations where attackers may steal funds.
Below are some common attacks related to off-chain signatures and how to prevent them.

## ✔️ Signature validity

One of the most common signature-related vulnerabilities is the **lack of proper signature validation**. Every time we use off-chain signatures, we must ensure that the signature is valid before executing any action.

The first step is recovering the `signer` using Solidity built-in `ecrecover(hash, v, r, s)`function:

```solidity
function authorizeUser(bytes32 hash, uint8 v, bytes32 r, bytes32 s, address user) {
    address signer = ecrecover(hash, v, r, s);
}
```

Once we recover the `signer`, we must verifiy that it is not the zero address:
`require(signer != address(0), "Invalid signature")`;
This check is critical because attackers can deliberately pass invalid values for `v` , `r` or `s`. When this happens, `ecrecover()` cannot recover the real signer and returns `address(0)`, which would bypass the intend authentication if not properly validated.

A safer alternative is to use the `ECDSA` library from OpenZeppelin (e.g., inside an `authorizeUserWithECDSA()` function). This library perfoms additional validations related to elliptic curve rules, which also protects against issues such as **signature malleability**, explained in a later section.

### 🔁 Replay attack

A replay attack occurs when an attacker reuses the same off-chain signature **multiple times**, even though it was intended to be used only once.

For example, if user A signs an authorization to spend 5 tokens, a malicious user could repeatedly submit that same signature to the contract. Each submission would spend another 5 tokens, leading to unexpected and unauthorized loss of funds.

To prevent replay attacks, we must ensure each signature can be used only once. The common ways to enforce this are:

- using a unique nonce in the signed data
- or keeping a mapping that stores whether a specific hash has already been used

```solidity
// Global used hashes mapping
mapping(bytes32 => bool) usedHashes;

// Check if hash has been used before
require(!usedHash[hash], "Hash already used");
// Mark hash as used
usedHash[hash] = true;
```

By marking the hash as used before executing the action, we guarantee that the signature cannot be reused again.

## 📈 Signature malleability

Signature malleability occurs when an attacker can modify a valid signature in such a way that the altered version is still valid for the same signed action. As a result, two different signatures can authenticate the same message, both being considered valid by the smart contract.

For example:

1. User A signs the message "Transfer 100 tokens" → Original valid signature → Smart contract accepts it.
2. An attacker modifies the signature to produce an alternative but still valid signature → Smart contract also accepts it.
   ==> Result: The action is executed twice, transferring 200 tokens when the user only intended to transfer 100.

This happens because Ethereum signatures are based on elliptic curve cryptography (ECDSA), and elliptic curves are symmetric by nature.
For any given signature `v, r, s`, there exists another valid signature `v', r, s'` that corresponds to the same message. Without additional checks, both are cryptographically valid and recover the same signer address.

To mitigate signature malleability, we must ensure that the value s lies in the **lower half of the elliptic curve**. If s is in the upper half, the signature is considered malleable and should be rejected. This is exactly how OpenZeppelin's `ECDSA` library prevents malleability internally.

The verification steps typically include:

1. Check that the signature length is exactly 65 bytes, because Ethereum ECDSA signatures use 65 bytes (32 bytes for `r`, 32 bytes for `s`, 1 byte for `v`)
   `require(signature.length == 65, "Invalid signature");`

2. Extract `v`, `r` and `s` using inline assembly.

```solidity
assembly {
    r := mload(add(signature, 32))
    s := mload(add(signature, 64))
    v := byte(0, mload(add(signature, 96)))
}
```

3. Ensure that `v` is either 27 or 28 (the only valid recovery IDs in legacy Ethereum signatures)

```solidity
if (v != 27 && v != 28) {
	revert(“Invalid signature ‘v’ value”);
}
```

4. Ensure that `s` is within the lower half of the elliptic curve

```solidity
if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
    revert("Invalid signature 's' value");
}
```

Using OpenZeppelin’s `ECDSA` library is the safest approach, since these validations are already implemented and audited.

```solidity
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

mapping(bytes32 => bool) public usedHashes;

function authorizeUserWithECDSA(bytes memory signature, bytes32 hash) external {
    bytes32 ethSignedHash = ECDSA.toEthSignedMessageHash(hash);
    address signer = ECDSA.recover(ethSignedHash, signature);
    require(!usedHashes[ethSignedHash], "Hash already used"); // @audit Replay attack protection
    usedHashes[ethSignedHash] = true;
}
```

This implementation automatically protects against signature malleability because it validates:

- Signature length is 65 bytes
- `v` is either 27 or 28
- `s` is in the lower half of the elliptic curve
- `signer` is not the address zero
  ⚠️ `ECDSA.recover` does NOT protect against replay attacks. You must validate and store used hashes manually.

## 📚 Resources

- [Replay attacks](https://scsfg.io/hackers/signature-attacks/#replay-attacks)
- [Signature malleability](https://zokyo.io/blog/signature-malleability-risks-and-solutions/)
- [OpenZeppelin ECDSA](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol)
