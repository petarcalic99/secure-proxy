// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import "../src/SecureProxy.sol";
import {RoleSetServer} from "@limitbreak/tm-role-server/src/RoleSetServer.sol";

contract SecureProxyMissingTests is Test {
    RoleSetServer public roleServer;
    SecureProxy public secureProxy;
    MissingTestImplementation1 internal testImplementation1;
    IMissingTestImplementation internal testProxy;
    bytes32 internal roleSet;

    address constant ROLE_SERVER = 0x00000000d7b37203F54e165Fb204B57c30d15835;
    address constant PROXY_ADMIN = address(0x1337);
    address constant PROXY_CODE_MANAGER = address(0xCCCC);
    bytes32 constant PROXY_ROLE_SERVER_SET_SALT = keccak256("PROXY_ROLES");

    address constant TEST_USER_ALLOWED = address(0xAAAA);
    address constant TEST_USER_BLOCKED = address(0xBBBB);
    address constant RANDOM_USER = address(0xDEAD);

    function setUp() public {
        RoleSetServer roleServerTmp = new RoleSetServer();
        vm.etch(ROLE_SERVER, address(roleServerTmp).code);
        roleServer = RoleSetServer(ROLE_SERVER);
        changePrank(PROXY_ADMIN);
        roleSet = roleServer.createRoleSet(PROXY_ROLE_SERVER_SET_SALT);

        roleServer.setRoleHolder(roleSet, SECURE_PROXY_CODE_MANAGER_BASE_ROLE, PROXY_CODE_MANAGER, false, new IRoleClient[](0));
        roleServer.setRoleHolder(roleSet, SECURE_PROXY_ADMIN_BASE_ROLE, PROXY_ADMIN, false, new IRoleClient[](0));

        vm.warp(block.timestamp + 1);

        testImplementation1 = new MissingTestImplementation1();
        secureProxy = new SecureProxy(address(testImplementation1), ROLE_SERVER, roleSet, bytes(""));
        testProxy = IMissingTestImplementation(address(secureProxy));

        address[] memory allowedCallers = new address[](2);
        allowedCallers[0] = PROXY_ADMIN;
        allowedCallers[1] = TEST_USER_ALLOWED;
        secureProxy.secureSetAllowedCallersDuringPause(true, allowedCallers);
    }

    // =========================================================================
    // Gap 1: Authorization Rejection Tests
    // Verify that unauthorized callers are reverted for each protected function.
    // =========================================================================

    // Test that secureAdminPause reverts when called by an unauthorized user.
    function testRevertUnauthorizedSecureAdminPause() public {
        changePrank(RANDOM_USER);
        vm.expectRevert();
        secureProxy.secureAdminPause(false);
    }

    // Test that secureSetAllowedCallersDuringPause reverts when called by an unauthorized user.
    function testRevertUnauthorizedSecureSetAllowedCallersDuringPause() public {
        changePrank(RANDOM_USER);
        address[] memory callers = new address[](1);
        callers[0] = address(0x9999);
        vm.expectRevert();
        secureProxy.secureSetAllowedCallersDuringPause(true, callers);
    }

    // Test that secureExpireCodeSets reverts when called by an unauthorized user.
    function testRevertUnauthorizedSecureExpireCodeSets() public {
        changePrank(RANDOM_USER);
        uint256[] memory codeSetIds = new uint256[](1);
        codeSetIds[0] = 0;
        vm.expectRevert();
        secureProxy.secureExpireCodeSets(codeSetIds);
    }

    // Test that secureUpgrade reverts when called by an unauthorized user.
    function testRevertUnauthorizedSecureUpgrade() public {
        changePrank(RANDOM_USER);
        vm.expectRevert();
        secureProxy.secureUpgrade(address(testImplementation1));
    }

    // Test that secureAddPauseCodes reverts when called by an unauthorized user (not code manager).
    function testRevertUnauthorizedSecureAddPauseCodes() public {
        changePrank(RANDOM_USER);
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert();
        secureProxy.secureAddPauseCodes(false, empty, empty, empty);
    }

    // =========================================================================
    // Gap 2: receive() Happy Path Tests
    // Test that ETH can be sent to the proxy via receive() and that it is
    // blocked for unauthorized callers during pause.
    // =========================================================================

    // Test that ETH can be sent to the proxy when not paused (implementation has receive).
    function testReceiveETHWhenNotPaused() public {
        // Deploy a proxy backed by an implementation that has receive() payable
        MissingTestImplementationWithReceive implWithReceive = new MissingTestImplementationWithReceive();
        changePrank(PROXY_ADMIN);
        SecureProxy proxyWithReceive = new SecureProxy(address(implWithReceive), ROLE_SERVER, roleSet, bytes(""));

        // Fund the sender
        changePrank(RANDOM_USER);
        vm.deal(RANDOM_USER, 1 ether);

        // Send ETH - should not revert since not paused and implementation has receive()
        (bool success,) = address(proxyWithReceive).call{value: 0.5 ether}("");
        assertTrue(success, "ETH transfer should succeed when not paused");
        assertEq(address(proxyWithReceive).balance, 0.5 ether);
    }

    // Test that ETH transfers are blocked for unauthorized callers during pause.
    function testReceiveETHBlockedForUnauthorizedDuringPause() public {
        // Deploy a proxy backed by an implementation that has receive() payable
        MissingTestImplementationWithReceive implWithReceive = new MissingTestImplementationWithReceive();
        changePrank(PROXY_ADMIN);
        SecureProxy proxyWithReceive = new SecureProxy(address(implWithReceive), ROLE_SERVER, roleSet, bytes(""));

        // Pause the proxy
        proxyWithReceive.secureAdminPause(false);

        // Unauthorized caller tries to send ETH during pause
        changePrank(TEST_USER_BLOCKED);
        vm.deal(TEST_USER_BLOCKED, 1 ether);

        (bool success, bytes memory returnData) = address(proxyWithReceive).call{value: 0.5 ether}("");
        assertFalse(success, "ETH transfer should fail for unauthorized caller during pause");

        // Verify the revert reason is SecureProxy__Paused
        bytes4 returnSelector;
        assembly ("memory-safe") {
            returnSelector := mload(add(0x20, returnData))
        }
        assertEq(returnSelector, SecureProxy__Paused.selector, "Should revert with SecureProxy__Paused");
    }

    // =========================================================================
    // Gap 3: Boundary Condition - pauseExpiration == block.timestamp
    // When pauseExpiration == block.timestamp, the pause should still be active.
    // =========================================================================

    // Test that the contract is still paused when block.timestamp equals pauseExpiration exactly,
    // and that it unpauses one second later.
    function testPauseBoundaryExactExpiration() public {
        // Set up pause codes
        changePrank(PROXY_CODE_MANAGER);
        bytes32[] memory tier1Hashes = new bytes32[](1);
        tier1Hashes[0] = keccak256(bytes("a1111111111111111111"));
        bytes32[] memory empty = new bytes32[](0);
        secureProxy.secureAddPauseCodes(false, tier1Hashes, empty, empty);

        // Record the current timestamp before pausing
        uint256 pauseTimestamp = block.timestamp;

        // Issue a tier 1 pause
        changePrank(TEST_USER_BLOCKED);
        secureProxy.securePause(0, "a1111111111111111111");

        // pauseExpiration = pauseTimestamp + TIER_1_PAUSE_DURATION
        uint256 expectedExpiration = pauseTimestamp + TIER_1_PAUSE_DURATION;

        // Warp to exactly the expiration timestamp (NOT +1)
        vm.warp(expectedExpiration);

        // The contract should still be paused because _checkPauseState checks
        // pauseExpiration < block.timestamp, and here pauseExpiration == block.timestamp
        changePrank(TEST_USER_BLOCKED);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(42);

        // Warp one more second past the expiration
        vm.warp(expectedExpiration + 1);

        // Now the contract should be unpaused
        changePrank(TEST_USER_BLOCKED);
        testProxy.set(42);
        assertEq(testProxy.get(), 42);
    }

    // =========================================================================
    // Gap 4: Duplicate Code Hash Handling
    // Adding the same code hash to two different tiers should silently overwrite,
    // resulting in the hash being stored at the second tier.
    // =========================================================================

    // Test that adding the same code hash in tier 1 and tier 2 results in it being tier 2.
    function testDuplicateCodeHashOverwrite() public {
        changePrank(PROXY_CODE_MANAGER);

        // Use the same hash for tier 1 and tier 2
        bytes32 duplicateHash = keccak256(bytes("duplicate_code_12345678"));
        bytes32[] memory tier1Hashes = new bytes32[](1);
        tier1Hashes[0] = duplicateHash;
        bytes32[] memory tier2Hashes = new bytes32[](1);
        tier2Hashes[0] = duplicateHash;
        bytes32[] memory empty = new bytes32[](0);

        (,,, uint256 currentCodeSetId) = secureProxy.securePauseState();

        // Add the same hash to both tier 1 and tier 2
        // _addCodesToTier processes tier1 first, then tier2, so tier2 overwrites tier1
        secureProxy.secureAddPauseCodes(false, tier1Hashes, tier2Hashes, empty);

        // Check that the code is now at tier 2 (the second write wins)
        uint256 codeTier = secureProxy.secureCheckPauseCode(currentCodeSetId, duplicateHash);
        assertEq(codeTier, TIER_2, "Duplicate hash should be overwritten to tier 2");
    }

    // Test that adding the same code hash in tier 1 and tier 3 results in it being tier 3.
    function testDuplicateCodeHashOverwriteTier1ToTier3() public {
        changePrank(PROXY_CODE_MANAGER);

        bytes32 duplicateHash = keccak256(bytes("another_dup_code_12345"));
        bytes32[] memory tier1Hashes = new bytes32[](1);
        tier1Hashes[0] = duplicateHash;
        bytes32[] memory tier3Hashes = new bytes32[](1);
        tier3Hashes[0] = duplicateHash;
        bytes32[] memory empty = new bytes32[](0);

        (,,, uint256 currentCodeSetId) = secureProxy.securePauseState();

        // Tier 1 is processed first, then tier 2 (empty), then tier 3 overwrites
        secureProxy.secureAddPauseCodes(false, tier1Hashes, empty, tier3Hashes);

        uint256 codeTier = secureProxy.secureCheckPauseCode(currentCodeSetId, duplicateHash);
        assertEq(codeTier, TIER_3, "Duplicate hash should be overwritten to tier 3");
    }

    // =========================================================================
    // Gap 5: Empty Array Inputs
    // Verify that calling functions with empty arrays succeeds without revert.
    // =========================================================================

    // Test that secureAddPauseCodes with all empty arrays succeeds.
    function testEmptyArraySecureAddPauseCodes() public {
        changePrank(PROXY_CODE_MANAGER);
        bytes32[] memory empty = new bytes32[](0);
        // Should not revert
        secureProxy.secureAddPauseCodes(false, empty, empty, empty);
    }

    // Test that secureExpireCodeSets with an empty array succeeds.
    function testEmptyArraySecureExpireCodeSets() public {
        changePrank(PROXY_ADMIN);
        uint256[] memory empty = new uint256[](0);
        // Should not revert
        secureProxy.secureExpireCodeSets(empty);
    }

    // Test that secureSetAllowedCallersDuringPause with an empty array succeeds.
    function testEmptyArraySecureSetAllowedCallersDuringPause() public {
        changePrank(PROXY_ADMIN);
        address[] memory empty = new address[](0);
        // Should not revert
        secureProxy.secureSetAllowedCallersDuringPause(true, empty);
    }

    // =========================================================================
    // Gap 6: securePauseState View Correctness
    // Verify that securePauseState returns the correct values across different
    // pause states: not paused, tier 1 paused, admin paused, and stale state.
    // =========================================================================

    // Test securePauseState when not paused.
    function testSecurePauseStateNotPaused() public view {
        (bool paused, uint256 pauseExpiration, uint256 currentEscalationTier, uint256 currentCodeSetId) =
            secureProxy.securePauseState();

        assertFalse(paused, "Should not be paused");
        assertEq(pauseExpiration, UNPAUSED_EXPIRATION, "Pause expiration should be 0");
        assertEq(currentEscalationTier, TIER_NOT_PAUSED, "Escalation tier should be 0");
        assertEq(currentCodeSetId, 0, "Code set ID should be 0");
    }

    // Test securePauseState when tier 1 paused.
    function testSecurePauseStateTier1Paused() public {
        // Set up a tier 1 pause code and trigger it
        changePrank(PROXY_CODE_MANAGER);
        bytes32[] memory tier1Hashes = new bytes32[](1);
        tier1Hashes[0] = keccak256(bytes("tier1_pause_code_1234"));
        bytes32[] memory empty = new bytes32[](0);
        secureProxy.secureAddPauseCodes(false, tier1Hashes, empty, empty);

        uint256 pauseTimestamp = block.timestamp;
        changePrank(RANDOM_USER);
        secureProxy.securePause(0, "tier1_pause_code_1234");

        (bool paused, uint256 pauseExpiration, uint256 currentEscalationTier, uint256 currentCodeSetId) =
            secureProxy.securePauseState();

        assertTrue(paused, "Should be paused");
        assertEq(pauseExpiration, pauseTimestamp + TIER_1_PAUSE_DURATION, "Pause expiration should be timestamp + 30 minutes");
        assertEq(currentEscalationTier, TIER_1, "Escalation tier should be TIER_1");
        assertEq(currentCodeSetId, 0, "Code set ID should still be 0");
    }

    // Test securePauseState when admin paused.
    function testSecurePauseStateAdminPaused() public {
        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);

        (bool paused, uint256 pauseExpiration, uint256 currentEscalationTier, uint256 currentCodeSetId) =
            secureProxy.securePauseState();

        assertTrue(paused, "Should be paused");
        assertEq(pauseExpiration, FULL_PAUSE_EXPIRATION, "Pause expiration should be type(uint256).max");
        assertEq(currentEscalationTier, TIER_ADMIN, "Escalation tier should be TIER_ADMIN");
        assertEq(currentCodeSetId, 0, "Code set ID should be 0");
    }

    // Test securePauseState returns stale state after pause expires (view does not clear state).
    // The view function reports paused=false because pauseExpiration < block.timestamp,
    // but the underlying storage still holds the old escalation tier until a stateful call clears it.
    function testSecurePauseStateStaleAfterExpiry() public {
        // Set up a tier 1 pause code and trigger it
        changePrank(PROXY_CODE_MANAGER);
        bytes32[] memory tier1Hashes = new bytes32[](1);
        tier1Hashes[0] = keccak256(bytes("stale_test_code_12345"));
        bytes32[] memory empty = new bytes32[](0);
        secureProxy.secureAddPauseCodes(false, tier1Hashes, empty, empty);

        uint256 pauseTimestamp = block.timestamp;
        changePrank(RANDOM_USER);
        secureProxy.securePause(0, "stale_test_code_12345");

        // Warp past the expiration
        vm.warp(pauseTimestamp + TIER_1_PAUSE_DURATION + 1);

        (bool paused, uint256 pauseExpiration, uint256 currentEscalationTier,) =
            secureProxy.securePauseState();

        // The view function checks: paused = pauseExpiration >= block.timestamp
        // Since we're past expiration, paused should be false
        assertFalse(paused, "Should report not paused after expiry");

        // However, the storage still holds the stale values because no stateful call has
        // cleared them yet. The view shows the raw storage values for expiration and tier.
        assertEq(pauseExpiration, pauseTimestamp + TIER_1_PAUSE_DURATION, "Stale pause expiration should remain in storage");
        assertEq(currentEscalationTier, TIER_1, "Stale escalation tier should remain in storage");
    }
}

// =========================================================================
// Helper contracts and interfaces (duplicated from SecureProxy.t.sol since
// this is a separate test file).
// =========================================================================

interface IMissingTestImplementation {
    error TestRevert1();
    error TestRevert2();
    function set(uint256) external;
    function get() external view returns(uint256);
}

contract MissingTestImplementation1 is IMissingTestImplementation {
    uint256 value;
    function set(uint256 value_) external { value = value_; }
    function get() external view returns (uint256) { return value; }
}

contract MissingTestImplementationWithReceive is IMissingTestImplementation {
    uint256 value;
    function set(uint256 value_) external { value = value_; }
    function get() external view returns (uint256) { return value; }
    receive() external payable {}
}
