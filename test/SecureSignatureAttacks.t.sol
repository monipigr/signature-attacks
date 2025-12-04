// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/SecureSignatureContract.sol";

contract SignatureAttacksTest is Test {
    SecureSignatureContract public secureContract;

    address public alice = address(0x1);
    address public bob = address(0x2);
    address public attacker = address(0x3);

    function setUp() public {
        secureContract = new SecureSignatureContract();
    }

    function test_validSignature() public {
        // Create a valid signature
        bytes32 hash = secureContract.createAuthorizationHash(bob, 1);

        // Sign the hash with Alice's signature
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash); // private key 1 corresponds to alice

        // Authorize Bob using Alice's signature
        secureContract.authorizeUsers(v, r, s, hash, bob);

        // Verify Bob is now authorize
        assertTrue(secureContract.isAuthorized(bob));
    }

    function test_revertIfInvalidSignature() public {
        // Create a hash
        bytes32 hash = secureContract.createAuthorizationHash(attacker, 1);

        // Use invalid signature components that will cause ecrecover to return address(0)
        uint8 v = 0;
        bytes32 r = bytes32(0);
        bytes32 s = bytes32(0);

        // This should now fail due to the security fix
        vm.expectRevert("Invalid signature");
        secureContract.authorizeUsers(v, r, s, hash, attacker);

        // The attacker should not be authorized
        assertFalse(secureContract.isAuthorized(attacker));
    }

    function test_revertIfMalformedSignature() public {
        // Create a hash
        bytes32 hash = secureContract.createAuthorizationHash(attacker, 2);

        // Use malformed signature components
        uint8 v = 255; // Invalid v value: v must be 27 or 28 in Ethereum signatures
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(1));

        // This should also fail due to the security fix
        vm.expectRevert("Invalid signature");
        secureContract.authorizeUsers(v, r, s, hash, attacker);

        // The attacker should not be authorized
        assertFalse(secureContract.isAuthorized(attacker));
    }

    function test_revertIfRecoverSignerIsInvalid() public {
        // Test the recoverSigner function with invalid signature
        bytes32 hash = keccak256("test");
        uint8 v = 0;
        bytes32 r = bytes32(0);
        bytes32 s = bytes32(0);

        // This should revert due to the security fix
        vm.expectRevert("Invalid signature");
        secureContract.recoverSigner(v, r, s, hash);
    }

    function test_replayAttack() public {
        // Create a valid signature
        bytes32 hash = secureContract.createAuthorizationHash(bob, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash);

        // Alice authorizes Bob
        secureContract.authorizeUsers(v, r, s, hash, bob);

        // Try to use the same signature again fails due to hash reuse protection
        vm.expectRevert("Hash already used");
        secureContract.authorizeUsers(v, r, s, hash, bob);
    }

    function test_revertIfSignatureIsMalleable() public {
        // Create a valid signature
        bytes32 hash = secureContract.createAuthorizationHash(attacker, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash);

        // Force s to be in the upper range (malleable signature)
        bytes32 malleableS = bytes32(
            uint256(s) +
                0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
        );

        // Try using the malleable signature reverts due to to lower-half 's' rule protection
        vm.expectRevert("Invalid signature 's' value");
        secureContract.authorizeUserWithECDSA(
            abi.encodePacked(r, malleableS, v),
            hash,
            attacker
        );
    }
}
