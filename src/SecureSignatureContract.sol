// SPDX-License-Identifier: MIT

pragma solidity ^0.8.13;

/**
 * @title SecureSignatureContract
 * @dev This contract demonstrates the secure way to handle signature verification
 * by properly validating ecrecover results and using OpenZeppelin's ECDSA library.
 */
contract SecureSignatureContract {
    mapping(address => bool) authorizedUsers;
    mapping(bytes32 => bool) usedHashes;

    event UserAuthorized(address indexed user, bytes32 indexed hash);
    event InvalidSignatureRejected(
        address indexed signer,
        bytes32 indexed hash
    );

    /**
     * @dev Secure function that recovers signer from signature with proper validation
     * @param v The v component of the signature
     * @param r The r component of the signature
     * @param s The s component of the signature
     * @param hash The hash that was signed
     * @param user The user to authorize
     */
    function authorizeUsers(
        uint8 v,
        bytes32 r,
        bytes32 s,
        bytes32 hash,
        address user
    ) external {
        // Secure: Proper validation of ecrecover result
        address signer = ecrecover(hash, v, r, s);

        // Critical fix: Check that ecrecover returned a valid address
        require(signer != address(0), "Invalid signature");

        // Check if hash has been used before
        require(!usedHashes[hash], "Has already used");

        // Mark hash as¡ used
        usedHashes[hash] = true;

        // Authorize the user
        authorizedUsers[user] = true;

        emit UserAuthorized(user, hash);
    }

    function authorizeUserWithECDSA(
        bytes memory signature,
        bytes32 hash,
        address user
    ) external {
        // This would be implemented using OpenZeppelin's ECDSA.recover() function,
        // which automatically reverts on invalid signatures
        // address signer = ECDSA.recover(hash, signature);

        // But for demonstration, we have used ecrecover with proper validation
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            revert("Invalid signature 's' value"); // @audit Signature malleability protection
        }

        if (v != 27 && v != 28) {
            revert("Invalid signature 'v' value"); // @audit Signature malleability protection
        }

        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signature"); // @audit Signature validation protection

        require(!usedHashes[hash], "Has already used"); // @audit Replay attack protection

        // Mark hash as¡ used
        usedHashes[hash] = true;

        // Authorize the user
        authorizedUsers[user] = true;

        emit UserAuthorized(user, hash);
    }
}
