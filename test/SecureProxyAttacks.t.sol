// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import "../src/SecureProxy.sol";
import {RoleSetServer} from "@limitbreak/tm-role-server/src/RoleSetServer.sol";

// =========================================================================
// Helper Contracts
// =========================================================================

interface IAttackImpl {
    function set(uint256) external;
    function get() external view returns (uint256);
    function corruptPauseState() external;
    function hijackImplementation(address) external;
}

contract AttackImpl {
    uint256 value;
    function set(uint256 value_) external { value = value_; }
    function get() external view returns (uint256) { return value; }
    receive() external payable {}
}

contract MaliciousStorageImpl {
    uint256 value;
    function set(uint256 value_) external { value = value_; }
    function get() external view returns (uint256) { return value; }

    function corruptPauseState() external {
        // Write 0 to SECURITY_SLOT, zeroing out pauseExpiration
        bytes32 slot = 0x5EC00000000000005EC00000000000005EC00000000000005EC0000000000000;
        assembly { sstore(slot, 0) }
    }

    function hijackImplementation(address newImpl) external {
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly { sstore(slot, newImpl) }
    }

    receive() external payable {}
}

contract NoReceiveImpl {
    uint256 value;
    function set(uint256 value_) external { value = value_; }
    function get() external view returns (uint256) { return value; }
    // No receive() function
}

contract MinimalImpl {
    // Minimal contract that does nothing but has code
    fallback() external payable {}
}

contract StorageCorruptingInitializer {
    uint256 value;
    function set(uint256 value_) external { value = value_; }
    function get() external view returns (uint256) { return value; }

    function initialize() external {
        // Corrupt SECURITY_SLOT during init
        bytes32 slot = 0x5EC00000000000005EC00000000000005EC00000000000005EC0000000000000;
        assembly { sstore(slot, 999) }
    }

    receive() external payable {}
}

// =========================================================================
// Main Attack Test Contract
// =========================================================================

contract SecureProxyAttackTests is Test {
    RoleSetServer public roleServer;
    SecureProxy public secureProxy;
    AttackImpl internal attackImpl;
    MaliciousStorageImpl internal maliciousImpl;
    IAttackImpl internal testProxy;
    bytes32 internal roleSet;

    address constant ROLE_SERVER = 0x00000000d7b37203F54e165Fb204B57c30d15835;
    address constant PROXY_ADMIN = address(0x1337);
    address constant PROXY_CODE_MANAGER = address(0xCCCC);
    bytes32 constant PROXY_ROLE_SERVER_SET_SALT = keccak256("ATTACK_TEST_ROLES");

    address constant ATTACKER = address(0xDEAD);
    address constant ALLOWED_USER = address(0xAAAA);
    address constant BLOCKED_USER = address(0xBBBB);
    address constant FRONT_RUNNER = address(0xF00F);

    // Pause codes (all >= 20 chars)
    string constant T1_CODE_A = "tier1_attack_code_aa";
    string constant T1_CODE_B = "tier1_attack_code_bb";
    string constant T1_CODE_C = "tier1_attack_code_cc";
    string constant T2_CODE_A = "tier2_attack_code_aa";
    string constant T2_CODE_B = "tier2_attack_code_bb";
    string constant T3_CODE_A = "tier3_attack_code_aa";
    string constant T3_CODE_B = "tier3_attack_code_bb";

    function setUp() public {
        RoleSetServer roleServerTmp = new RoleSetServer();
        vm.etch(ROLE_SERVER, address(roleServerTmp).code);
        roleServer = RoleSetServer(ROLE_SERVER);
        changePrank(PROXY_ADMIN);
        roleSet = roleServer.createRoleSet(PROXY_ROLE_SERVER_SET_SALT);

        roleServer.setRoleHolder(roleSet, SECURE_PROXY_CODE_MANAGER_BASE_ROLE, PROXY_CODE_MANAGER, false, new IRoleClient[](0));
        roleServer.setRoleHolder(roleSet, SECURE_PROXY_ADMIN_BASE_ROLE, PROXY_ADMIN, false, new IRoleClient[](0));

        vm.warp(block.timestamp + 1);

        attackImpl = new AttackImpl();
        maliciousImpl = new MaliciousStorageImpl();
        secureProxy = new SecureProxy(address(attackImpl), ROLE_SERVER, roleSet, bytes(""));
        testProxy = IAttackImpl(address(secureProxy));

        // Allow ALLOWED_USER and PROXY_ADMIN during pause
        address[] memory allowedCallers = new address[](2);
        allowedCallers[0] = PROXY_ADMIN;
        allowedCallers[1] = ALLOWED_USER;
        secureProxy.secureSetAllowedCallersDuringPause(true, allowedCallers);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _addCodes(
        bool increment,
        string[] memory t1,
        string[] memory t2,
        string[] memory t3
    ) internal {
        bytes32[] memory h1 = new bytes32[](t1.length);
        bytes32[] memory h2 = new bytes32[](t2.length);
        bytes32[] memory h3 = new bytes32[](t3.length);
        for (uint256 i; i < t1.length; ++i) h1[i] = keccak256(bytes(t1[i]));
        for (uint256 i; i < t2.length; ++i) h2[i] = keccak256(bytes(t2[i]));
        for (uint256 i; i < t3.length; ++i) h3[i] = keccak256(bytes(t3[i]));
        secureProxy.secureAddPauseCodes(increment, h1, h2, h3);
    }

    function _singleStr(string memory s) internal pure returns (string[] memory arr) {
        arr = new string[](1);
        arr[0] = s;
    }

    function _emptyStr() internal pure returns (string[] memory) {
        return new string[](0);
    }

    function _addTier1Code(string memory code) internal {
        changePrank(PROXY_CODE_MANAGER);
        _addCodes(false, _singleStr(code), _emptyStr(), _emptyStr());
    }

    function _addTier2Code(string memory code) internal {
        changePrank(PROXY_CODE_MANAGER);
        _addCodes(false, _emptyStr(), _singleStr(code), _emptyStr());
    }

    function _addTier3Code(string memory code) internal {
        changePrank(PROXY_CODE_MANAGER);
        _addCodes(false, _emptyStr(), _emptyStr(), _singleStr(code));
    }

    function _addAllTierCodes() internal {
        changePrank(PROXY_CODE_MANAGER);
        _addCodes(
            false,
            _singleStr(T1_CODE_A),
            _singleStr(T2_CODE_A),
            _singleStr(T3_CODE_A)
        );
    }

    function _triggerTier1() internal {
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T1_CODE_A);
    }

    // =========================================================================
    // GROUP A: Pause State Machine Boundary Attacks
    // =========================================================================

    // A1: Escalate at exact expiry boundary (pauseExpiration == block.timestamp)
    // At boundary, pause is still active (line 429 uses <, not <=)
    function testAttack_EscalateAtExactExpiry() public {
        _addAllTierCodes();
        _triggerTier1();

        (,uint256 pauseExp,,) = secureProxy.securePauseState();

        // At exact boundary: pause still active, tier2 escalation should work
        vm.warp(pauseExp);
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T2_CODE_A);

        (bool paused,, uint256 tier,) = secureProxy.securePauseState();
        assertTrue(paused, "Should still be paused after tier2 escalation");
        assertEq(tier, TIER_2, "Should be at tier 2");
    }

    // A1b: One second past expiry, escalation fails because state is cleared
    function testAttack_EscalateOneSecondPastExpiry() public {
        _addAllTierCodes();
        _triggerTier1();

        (,uint256 pauseExp,,) = secureProxy.securePauseState();

        // One past boundary: _checkPauseState(true) clears state, tier2 fails
        vm.warp(pauseExp + 1);
        changePrank(BLOCKED_USER);
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(0, T2_CODE_A);
    }

    // A2: Re-pause after auto-expiry with a fresh tier1 code
    function testAttack_ReEscalateAfterAutoExpiry() public {
        _addTier1Code(T1_CODE_A);
        _addTier1Code(T1_CODE_B);

        // Trigger first pause
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T1_CODE_A);
        (,uint256 pauseExp,,) = secureProxy.securePauseState();

        // Let it expire
        vm.warp(pauseExp + 1);

        // Fresh tier1 code should work because state was cleared
        secureProxy.securePause(0, T1_CODE_B);
        (bool paused,, uint256 tier,) = secureProxy.securePauseState();
        assertTrue(paused, "Should be paused again");
        assertEq(tier, TIER_1, "Should be at tier 1 again");
    }

    // A3: Code escalation blocked during admin pause
    function testAttack_CodeEscalationDuringAdminPause() public {
        _addAllTierCodes();

        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);

        changePrank(BLOCKED_USER);
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(0, T1_CODE_A);
    }

    // A4: Admin clear then immediate code pause
    function testAttack_AdminClearThenImmediateCodePause() public {
        _addTier1Code(T1_CODE_A);

        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);
        secureProxy.secureAdminPause(true); // clear

        // State should be fully reset
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T1_CODE_A);

        (bool paused,, uint256 tier,) = secureProxy.securePauseState();
        assertTrue(paused);
        assertEq(tier, TIER_1);
    }

    // A5: Double admin pause is idempotent
    function testAttack_DoubleAdminPause() public {
        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);
        secureProxy.secureAdminPause(false); // second call, same state

        (bool paused,, uint256 tier,) = secureProxy.securePauseState();
        assertTrue(paused);
        assertEq(tier, TIER_ADMIN);
    }

    // =========================================================================
    // GROUP B: Code Consumption & Re-Registration (CRITICAL)
    // =========================================================================

    // B1 [P0]: Consumed code can be re-registered by code manager
    // _addCodesToTier (line 391) does ptrCodeTier[codeHash] = tier unconditionally
    function testAttack_CodeReRegistrationAfterConsumption() public {
        bytes32 codeHash = keccak256(bytes(T1_CODE_A));

        // Add and consume the code
        _addTier1Code(T1_CODE_A);
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T1_CODE_A);

        // Verify code is consumed
        assertEq(secureProxy.secureCheckPauseCode(0, codeHash), TIER_INVALID);

        // Admin clears pause
        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(true);

        // Code manager re-adds the SAME hash - no guard prevents this!
        _addTier1Code(T1_CODE_A);

        // Verify code is valid again - ONE-TIME-USE INVARIANT BROKEN
        assertEq(secureProxy.secureCheckPauseCode(0, codeHash), TIER_1);

        // Use it again successfully
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T1_CODE_A);

        (bool paused,, uint256 tier,) = secureProxy.securePauseState();
        assertTrue(paused, "Code was reused successfully");
        assertEq(tier, TIER_1);
    }

    // B2: Tier swap via overwrite - code manager can silently change a code's tier
    function testAttack_TierSwapViaOverwrite() public {
        bytes32 codeHash = keccak256(bytes(T1_CODE_A));

        // Add as tier 3
        _addTier3Code(T1_CODE_A);
        assertEq(secureProxy.secureCheckPauseCode(0, codeHash), TIER_3);

        // Code manager silently downgrades to tier 1
        _addTier1Code(T1_CODE_A);
        assertEq(secureProxy.secureCheckPauseCode(0, codeHash), TIER_1);

        // Use it as tier1 (not tier3!) - starts 30min pause instead of escalating
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T1_CODE_A);

        (,, uint256 tier,) = secureProxy.securePauseState();
        assertEq(tier, TIER_1, "Code was used as tier1 despite being originally tier3");
    }

    // B3: bytes32(0) as code hash - can be stored but never triggered
    function testAttack_Bytes32ZeroAsCodeHash() public {
        bytes32[] memory h1 = new bytes32[](1);
        h1[0] = bytes32(0);
        bytes32[] memory empty = new bytes32[](0);

        changePrank(PROXY_CODE_MANAGER);
        secureProxy.secureAddPauseCodes(false, h1, empty, empty);

        // The hash is stored as tier1
        assertEq(secureProxy.secureCheckPauseCode(0, bytes32(0)), TIER_1);

        // But keccak256 of any string can never be bytes32(0), so it can never be triggered
        // This is just informational - wasted slot
    }

    // =========================================================================
    // GROUP C: Code Set Rotation Attacks
    // =========================================================================

    // C1: Rapid rotation - 3 rotations in same block
    function testAttack_RapidRotationCollapse() public {
        changePrank(PROXY_CODE_MANAGER);
        
        // Add codes to set 0, then rotate 3 times
        _addCodes(false, _singleStr(T1_CODE_A), _emptyStr(), _emptyStr());
        _addCodes(true, _singleStr(T1_CODE_B), _emptyStr(), _emptyStr()); // set 0->1
        _addCodes(true, _singleStr(T1_CODE_C), _emptyStr(), _emptyStr()); // set 1->2

        (,,,uint256 currentSet) = secureProxy.securePauseState();
        assertEq(currentSet, 2, "Should be on set 2");

        // All old sets (0 and 1) expire at block.timestamp + 1 hour
        // Set 0's codes should still work during grace
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T1_CODE_A);

        (bool paused,,uint256 tier,) = secureProxy.securePauseState();
        assertTrue(paused);
        assertEq(tier, TIER_1);
    }

    // C2 [P0]: Grace period destruction - admin kills grace window
    function testAttack_GracePeriodDestruction() public {
        // Add codes to set 0
        _addTier1Code(T1_CODE_A);

        // Rotate to set 1
        changePrank(PROXY_CODE_MANAGER);
        _addCodes(true, _singleStr(T1_CODE_B), _emptyStr(), _emptyStr());

        // Admin immediately expires old set, killing grace period
        changePrank(PROXY_ADMIN);
        uint256[] memory expireIds = new uint256[](1);
        expireIds[0] = 0;
        secureProxy.secureExpireCodeSets(expireIds);

        // Old set 0 code should now fail (grace period destroyed)
        changePrank(BLOCKED_USER);
        vm.expectRevert(SecureProxy__CodeSetExpired.selector);
        secureProxy.securePause(0, T1_CODE_A);
    }

    // C3: Cross-set escalation - start with old set code, escalate with new set
    function testAttack_CrossSetEscalation() public {
        // Set 0: tier1 code
        _addTier1Code(T1_CODE_A);

        // Rotate to set 1 with tier2 code
        changePrank(PROXY_CODE_MANAGER);
        _addCodes(true, _emptyStr(), _singleStr(T2_CODE_A), _emptyStr());

        // Use tier1 from old set 0 (still in grace period)
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T1_CODE_A);

        (,,uint256 tier,) = secureProxy.securePauseState();
        assertEq(tier, TIER_1);

        // Escalate to tier2 using new set 1 - cross-set escalation!
        secureProxy.securePause(1, T2_CODE_A);

        (,,tier,) = secureProxy.securePauseState();
        assertEq(tier, TIER_2, "Cross-set escalation succeeded");
    }

    // C4: Pause with expired code set fails
    function testAttack_PauseWithExpiredCodeSet() public {
        _addTier1Code(T1_CODE_A);

        // Rotate to new set, then warp past grace period
        changePrank(PROXY_CODE_MANAGER);
        _addCodes(true, _singleStr(T1_CODE_B), _emptyStr(), _emptyStr());

        vm.warp(block.timestamp + CODE_ROTATION_PRIOR_SET_VALID_DURATION + 1);

        changePrank(BLOCKED_USER);
        vm.expectRevert(SecureProxy__CodeSetExpired.selector);
        secureProxy.securePause(0, T1_CODE_A);
    }

    // =========================================================================
    // GROUP D: Storage Collision via Implementation (CRITICAL)
    // =========================================================================

    // D1 [P0]: Implementation corrupts pause state via SECURITY_SLOT write
    function testAttack_ImplementationCorruptsPauseState() public {
        // Deploy proxy with malicious implementation
        changePrank(PROXY_ADMIN);
        SecureProxy malProxy = new SecureProxy(address(maliciousImpl), ROLE_SERVER, roleSet, bytes(""));
        IAttackImpl malTestProxy = IAttackImpl(address(malProxy));

        // Allow ALLOWED_USER during pause
        address[] memory allowed = new address[](2);
        allowed[0] = PROXY_ADMIN;
        allowed[1] = ALLOWED_USER;
        malProxy.secureSetAllowedCallersDuringPause(true, allowed);

        // Admin pause
        malProxy.secureAdminPause(false);

        (bool paused,,uint256 tier,) = malProxy.securePauseState();
        assertTrue(paused, "Should be paused");
        assertEq(tier, TIER_ADMIN);

        // Allowed user calls corruptPauseState through proxy
        // This delegatecalls into malicious impl which zeros SECURITY_SLOT
        changePrank(ALLOWED_USER);
        malTestProxy.corruptPauseState();

        // Pause state should now be corrupted
        (paused,,tier,) = malProxy.securePauseState();
        assertFalse(paused, "Pause was corrupted - pauseExpiration zeroed");

        // Blocked user can now call through - pause was bypassed!
        changePrank(BLOCKED_USER);
        malTestProxy.set(42);
        assertEq(malTestProxy.get(), 42, "Blocked user bypassed pause via storage corruption");
    }

    // D2: Implementation overwrites IMPLEMENTATION_SLOT - proxy hijack
    function testAttack_ImplementationOverwritesImplementationSlot() public {
        changePrank(PROXY_ADMIN);
        SecureProxy malProxy = new SecureProxy(address(maliciousImpl), ROLE_SERVER, roleSet, bytes(""));
        IAttackImpl malTestProxy = IAttackImpl(address(malProxy));

        // Normal call works with malicious impl
        malTestProxy.set(10);
        assertEq(malTestProxy.get(), 10);

        // Hijack: overwrite implementation to point to attackImpl
        malTestProxy.hijackImplementation(address(attackImpl));

        // Now calls go to attackImpl instead of maliciousImpl
        // This proves implementation can redirect the proxy
        malTestProxy.set(20);
        assertEq(malTestProxy.get(), 20);
    }

    // =========================================================================
    // GROUP E: Role & Access Control Attacks
    // =========================================================================

    // E1: TTL=0 mitigates role cache staleness
    function testAttack_RoleCacheStaleness_MitigatedByTTL0() public {
        // Roles configured with TTL=0 (line 488-489), so cache always refreshes
        // Revoke admin on role server
        changePrank(PROXY_ADMIN);
        address NEW_ADMIN = address(0x9999);
        roleServer.setRoleHolder(roleSet, SECURE_PROXY_ADMIN_BASE_ROLE, NEW_ADMIN, false, new IRoleClient[](0));

        vm.warp(block.timestamp + 1);

        // Old admin should fail because TTL=0 means cache always re-queries
        vm.expectRevert();
        secureProxy.secureAdminPause(false);

        // New admin should work
        changePrank(NEW_ADMIN);
        secureProxy.secureAdminPause(false);
        (bool paused,,,) = secureProxy.securePauseState();
        assertTrue(paused);
    }

    // E2: Allowed callers persist across pause cycles
    function testAttack_AllowedCallerPersistsAcrossPauseCycles() public {
        // Admin pause and add attacker to allowed list
        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);

        address[] memory attackerArr = new address[](1);
        attackerArr[0] = ATTACKER;
        secureProxy.secureSetAllowedCallersDuringPause(true, attackerArr);

        // Attacker can call during this pause
        changePrank(ATTACKER);
        testProxy.set(1);

        // Admin clears pause
        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(true);

        // New pause triggered via code
        _addTier1Code(T1_CODE_A);
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T1_CODE_A);

        // Attacker STILL in allowed list from previous cycle
        changePrank(ATTACKER);
        testProxy.set(2);
        assertEq(testProxy.get(), 2, "Attacker retained access across pause cycles");

        // Blocked user cannot
        changePrank(BLOCKED_USER);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(3);
    }

    // E3: Admin removed from allowed list still works (role check is separate)
    function testAttack_AdminRemovedFromAllowedListStillWorks() public {
        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);

        // Remove admin from allowed list
        address[] memory adminArr = new address[](1);
        adminArr[0] = PROXY_ADMIN;
        secureProxy.secureSetAllowedCallersDuringPause(false, adminArr);

        // Admin can still call through because line 438 checks role directly
        testProxy.set(42);
        assertEq(testProxy.get(), 42, "Admin bypasses allowed list via role check");
    }

    // E4: Allowed caller list modified mid-pause takes effect immediately
    function testAttack_AllowedCallerModifiedDuringActivePause() public {
        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);

        // Add attacker mid-pause
        address[] memory attackerArr = new address[](1);
        attackerArr[0] = ATTACKER;
        secureProxy.secureSetAllowedCallersDuringPause(true, attackerArr);

        // Attacker immediately gains access
        changePrank(ATTACKER);
        testProxy.set(1);
        assertEq(testProxy.get(), 1, "Attacker gained access immediately");

        // Revoke attacker mid-pause
        changePrank(PROXY_ADMIN);
        secureProxy.secureSetAllowedCallersDuringPause(false, attackerArr);

        // Attacker immediately loses access
        changePrank(ATTACKER);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(2);
    }

    // =========================================================================
    // GROUP F: Upgrade Path Attacks
    // =========================================================================

    // F1: Upgrade to minimal contract (just STOP opcode)
    function testAttack_UpgradeToMinimalContract() public {
        MinimalImpl minimal = new MinimalImpl();

        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);
        secureProxy.secureUpgrade(address(minimal));
        secureProxy.secureAdminPause(true);

        // Calls go through but do nothing (minimal impl just STOPs)
        changePrank(BLOCKED_USER);
        testProxy.set(42);
        // get() returns 0 because minimal impl doesn't implement it
        assertEq(testProxy.get(), 0, "Minimal impl returns nothing");
    }

    // F2: Upgrade to impl without receive() - ETH transfers revert
    function testAttack_UpgradeToContractWithoutReceive() public {
        NoReceiveImpl noReceive = new NoReceiveImpl();

        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);
        secureProxy.secureUpgrade(address(noReceive));
        secureProxy.secureAdminPause(true);

        // Regular calls work
        changePrank(BLOCKED_USER);
        testProxy.set(5);
        assertEq(testProxy.get(), 5);

        // ETH transfer fails because impl has no receive()
        vm.deal(BLOCKED_USER, 1 ether);
        (bool success,) = address(secureProxy).call{value: 0.5 ether}("");
        assertFalse(success, "ETH transfer should fail without receive()");
    }

    // F3: Codes and allowed list survive upgrade
    function testAttack_CodesAndAllowListSurviveUpgrade() public {
        // Add codes and allowed callers before upgrade
        _addTier1Code(T1_CODE_A);

        changePrank(PROXY_ADMIN);
        address[] memory attackerArr = new address[](1);
        attackerArr[0] = ATTACKER;
        secureProxy.secureSetAllowedCallersDuringPause(true, attackerArr);

        // Upgrade
        AttackImpl newImpl = new AttackImpl();
        secureProxy.secureAdminPause(false);
        secureProxy.secureUpgrade(address(newImpl));
        secureProxy.secureAdminPause(true);

        // Codes survive: tier1 code should still be valid
        bytes32 codeHash = keccak256(bytes(T1_CODE_A));
        assertEq(secureProxy.secureCheckPauseCode(0, codeHash), TIER_1, "Code survived upgrade");

        // Use the code to pause
        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, T1_CODE_A);

        // Allowed list survived: attacker can still call
        changePrank(ATTACKER);
        testProxy.set(7);
        assertEq(testProxy.get(), 7, "Allowed list survived upgrade");
    }

    // =========================================================================
    // GROUP G: Gas Griefing
    // =========================================================================

    // G1: Massive array in secureSetAllowedCallersDuringPause
    function testAttack_MassiveAllowedCallerArray() public {
        uint256 count = 500;
        address[] memory callers = new address[](count);
        for (uint256 i; i < count; ++i) {
            callers[i] = address(uint160(0x10000 + i));
        }

        changePrank(PROXY_ADMIN);
        uint256 gasBefore = gasleft();
        secureProxy.secureSetAllowedCallersDuringPause(true, callers);
        uint256 gasUsed = gasBefore - gasleft();

        // Just document the gas cost - no assertion on exact value
        assertTrue(gasUsed > 0, "Gas was consumed");

        // Verify last entry was set
        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);
        changePrank(callers[count - 1]);
        testProxy.set(1); // Should succeed - allowed during pause
    }

    // G2: Massive array in secureAddPauseCodes
    function testAttack_MassiveCodeHashArray() public {
        uint256 count = 500;
        bytes32[] memory hashes = new bytes32[](count);
        for (uint256 i; i < count; ++i) {
            hashes[i] = keccak256(abi.encodePacked("massive_code_", i));
        }
        bytes32[] memory empty = new bytes32[](0);

        changePrank(PROXY_CODE_MANAGER);
        uint256 gasBefore = gasleft();
        secureProxy.secureAddPauseCodes(false, hashes, empty, empty);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(gasUsed > 0, "Gas was consumed");

        // Verify last hash was stored
        assertEq(secureProxy.secureCheckPauseCode(0, hashes[count - 1]), TIER_1);
    }

    // =========================================================================
    // GROUP H: Constructor & Edge Cases
    // =========================================================================

    // H1: Constructor delegatecall corrupts security storage
    function testAttack_ConstructorDelegatecallCorruptsStorage() public {
        StorageCorruptingInitializer corruptInit = new StorageCorruptingInitializer();

        changePrank(PROXY_ADMIN);
        SecureProxy corruptProxy = new SecureProxy(
            address(corruptInit),
            ROLE_SERVER,
            roleSet,
            abi.encodeWithSignature("initialize()")
        );

        // pauseExpiration was overwritten to 999 by the initializer
        (bool paused,,,) = corruptProxy.securePauseState();
        // pauseExpiration=999 < block.timestamp (which is > 1), so paused=false
        // But the storage value 999 is non-zero, meaning _checkPauseState will enter
        // the pauseExpiration != UNPAUSED_EXPIRATION branch and try to clear it
        assertFalse(paused, "Storage was corrupted but pause shows as expired");
    }

    // H2: Pause code minimum length boundary
    function testAttack_PauseCodeMinimumLengthBoundary() public {
        // Exactly 20 chars - should pass
        string memory exact20 = "12345678901234567890";
        _addTier1Code(exact20);

        changePrank(BLOCKED_USER);
        secureProxy.securePause(0, exact20);
        (bool paused,,,) = secureProxy.securePauseState();
        assertTrue(paused, "20-char code should work");

        // 19 chars - should fail
        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(true);

        string memory short19 = "1234567890123456789";
        _addTier1Code(short19);

        changePrank(BLOCKED_USER);
        vm.expectRevert(SecureProxy__PauseCodeTooShort.selector);
        secureProxy.securePause(0, short19);
    }
}
