// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import "../src/SecureProxy.sol";
import {RoleSetServer} from "@limitbreak/tm-role-server/src/RoleSetServer.sol";

contract SecureProxyTest is Test {
    RoleSetServer public roleServer;
    SecureProxy public secureProxy;
    TestImplementation1 internal testImplementation1;
    TestImplementation2 internal testImplementation2;
    TestImplementation3 internal testImplementation3;
    ITestImplementation internal testProxy;
    bytes32 internal roleSet;

    address constant ROLE_SERVER = 0x00000000d7b37203F54e165Fb204B57c30d15835;
    address constant PROXY_ADMIN = address(0x1337);
    address constant PROXY_CODE_MANAGER = address(0xCCCC);
    bytes32 constant PROXY_ROLE_SERVER_SET_SALT = keccak256("PROXY_ROLES");

    address constant TEST_USER_ALLOWED = address(0xAAAA);
    address constant TEST_USER_BLOCKED = address(0xBBBB);

    address constant NO_CODE_ADDRESS = address(0x123456789abcdef0);

    function setUp() public {
        RoleSetServer roleServerTmp = new RoleSetServer();
        vm.etch(ROLE_SERVER, address(roleServerTmp).code);
        roleServer = RoleSetServer(ROLE_SERVER);
        changePrank(PROXY_ADMIN);
        roleSet = roleServer.createRoleSet(PROXY_ROLE_SERVER_SET_SALT);

        roleServer.setRoleHolder(roleSet, SECURE_PROXY_CODE_MANAGER_BASE_ROLE, PROXY_CODE_MANAGER, false, new IRoleClient[](0));
        roleServer.setRoleHolder(roleSet, SECURE_PROXY_ADMIN_BASE_ROLE, PROXY_ADMIN, false, new IRoleClient[](0));

        vm.warp(block.timestamp + 1);

        testImplementation1 = new TestImplementation1();
        testImplementation2 = new TestImplementation2();
        testImplementation3 = new TestImplementation3();
        secureProxy = new SecureProxy(address(testImplementation1), ROLE_SERVER, roleSet, bytes(""));
        testProxy = ITestImplementation(address(secureProxy));

        address[] memory allowedCallers = new address[](2);
        allowedCallers[0] = PROXY_ADMIN;
        allowedCallers[1] = TEST_USER_ALLOWED;
        vm.expectEmit(true, true, true, true);
        emit SecureProxy.AllowedCallerDuringPauseSet(allowedCallers[0], true);
        emit SecureProxy.AllowedCallerDuringPauseSet(allowedCallers[1], true);
        secureProxy.secureSetAllowedCallersDuringPause(true, allowedCallers);
    }

    function testDeployWithNoCodeReverts() public {
        vm.expectRevert(SecureProxy__ImplementationDoesNotHaveCode.selector);
        new SecureProxy(NO_CODE_ADDRESS, ROLE_SERVER, roleSet, bytes(""));
    }

    function testInitialImplementation() public {
        assertEq(testProxy.get(), testImplementation1.get());
        testImplementation1.set(1);
        assertNotEq(testProxy.get(), testImplementation1.get());
        testProxy.set(1);
        assertEq(testProxy.get(), testImplementation1.get());
    }

    function testInitializableImplementation() public {
        TestInitializable testInitializable = new TestInitializable();

        vm.expectRevert(SecureProxy__InitializationFailed.selector);
        secureProxy = new SecureProxy(
            address(testInitializable),
            ROLE_SERVER,
            roleSet,
            abi.encodeWithSelector(
                TestInitializable.initialize.selector,
                0x1000000
            )
        );

        secureProxy = new SecureProxy(
            address(testInitializable),
            ROLE_SERVER,
            roleSet,
            abi.encodeWithSelector(
                TestInitializable.initialize.selector,
                0x31337
            )
        );
        testProxy = ITestImplementation(address(secureProxy));
        assertEq(testProxy.get(), 0x31337);
    }

    function testAdminPauseRevertsCalls() public {
        changePrank(PROXY_ADMIN);
        vm.expectEmit(true, true, true, true);
        emit SecureProxy.SecurityPause(TIER_ADMIN, FULL_PAUSE_EXPIRATION);
        secureProxy.secureAdminPause(false);

        changePrank(TEST_USER_BLOCKED);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(1);
        changePrank(TEST_USER_ALLOWED);
        assertEq(testProxy.get(), 0);
        changePrank(PROXY_ADMIN);
        assertEq(testProxy.get(), 0);

        changePrank(PROXY_ADMIN);
        vm.expectEmit(true, true, true, true);
        emit SecureProxy.SecurityUnpause();
        secureProxy.secureAdminPause(true);

        changePrank(TEST_USER_BLOCKED);
        testProxy.set(1);
        assertEq(testProxy.get(), 1);
    }

    function testAllowedUserRevertsWhenAllowanceRevoked() public {
        changePrank(PROXY_ADMIN);
        vm.expectEmit(true, true, true, true);
        emit SecureProxy.SecurityPause(TIER_ADMIN, FULL_PAUSE_EXPIRATION);
        secureProxy.secureAdminPause(false);

        changePrank(TEST_USER_ALLOWED);
        testProxy.set(1);
        changePrank(PROXY_ADMIN);
        address[] memory revokeAllowedCallers = new address[](1);
        revokeAllowedCallers[0] = TEST_USER_ALLOWED;
        secureProxy.secureSetAllowedCallersDuringPause(false, revokeAllowedCallers);
        changePrank(TEST_USER_ALLOWED);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(1);
    }

    function testCodesPauseContract() public {
        changePrank(PROXY_CODE_MANAGER);
        string[] memory tier1Codes = new string[](5);
        string[] memory tier2Codes = new string[](5);
        string[] memory tier3Codes = new string[](5);
        bytes32[] memory tier1CodeHashes = new bytes32[](5);
        bytes32[] memory tier2CodeHashes = new bytes32[](5);
        bytes32[] memory tier3CodeHashes = new bytes32[](5);

        tier1Codes[0] = "a1111111111111111111";
        tier1Codes[1] = "b1111111111111111111";
        tier1Codes[2] = "c1111111111111111111";
        tier1Codes[3] = "d1111111111111111111";
        tier1Codes[4] = "e1111111111111111111";
        tier2Codes[0] = "f1111111111111111111";
        tier2Codes[1] = "g1111111111111111111";
        tier2Codes[2] = "h1111111111111111111";
        tier2Codes[3] = "i1111111111111111111";
        tier2Codes[4] = "j1111111111111111111";
        tier3Codes[0] = "k1111111111111111111";
        tier3Codes[1] = "l1111111111111111111";
        tier3Codes[2] = "m1111111111111111111";
        tier3Codes[3] = "n1111111111111111111";
        tier3Codes[4] = "o1111111111111111111";

        (,,,uint256 currentCodeSetId) = secureProxy.securePauseState();

        vm.expectEmit(true, true, true, true);

        for (uint256 i; i < tier1Codes.length; ++i) {
            tier1CodeHashes[i] = keccak256(bytes(tier1Codes[i]));
            emit SecureProxy.PauseCodeAdded(currentCodeSetId, tier1CodeHashes[i], TIER_1);
        }

        for (uint256 i; i < tier2Codes.length; ++i) {
            tier2CodeHashes[i] = keccak256(bytes(tier2Codes[i]));
            emit SecureProxy.PauseCodeAdded(currentCodeSetId, tier2CodeHashes[i], TIER_2);
        }

        for (uint256 i; i < tier3Codes.length; ++i) {
            tier3CodeHashes[i] = keccak256(bytes(tier3Codes[i]));
            emit SecureProxy.PauseCodeAdded(currentCodeSetId, tier3CodeHashes[i], TIER_3);
        }

        secureProxy.secureAddPauseCodes(false, tier1CodeHashes, tier2CodeHashes, tier3CodeHashes);

        changePrank(TEST_USER_ALLOWED);
        testProxy.set(1);

        uint256 snapshotId = vm.snapshot();

        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);
        changePrank(TEST_USER_BLOCKED);
        // Invalid escalation, admin paused
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier1Codes[0]);

        vm.revertTo(snapshotId);

        changePrank(TEST_USER_BLOCKED);
        secureProxy.securePause(currentCodeSetId, tier1Codes[0]);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(1);

        snapshotId = vm.snapshot();

        vm.warp(block.timestamp + TIER_1_PAUSE_DURATION + 1);
        vm.expectEmit(true, true, true, true);
        emit SecureProxy.SecurityUnpause();
        testProxy.set(1);

        vm.revertTo(snapshotId);

        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);
        changePrank(TEST_USER_BLOCKED);
        // Invalid escalation, admin paused
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier2Codes[0]);

        vm.revertTo(snapshotId);

        // Cannot reuse code
        vm.expectRevert(SecureProxy__CodeInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier1Codes[0]);
        // Invalid escalation, same tier
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier1Codes[1]);
        // Invalid escalation, skipping tier 2
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier3Codes[1]);

        secureProxy.securePause(currentCodeSetId, tier2Codes[0]);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(1);

        snapshotId = vm.snapshot();

        vm.warp(block.timestamp + TIER_1_PAUSE_DURATION + TIER_2_PAUSE_DURATION + 1);
        // Invalid escalation, pause reset
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier2Codes[2]);
        // Invalid escalation, pause reset
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier3Codes[2]);
        // New pause successful
        secureProxy.securePause(currentCodeSetId, tier1Codes[2]);

        vm.revertTo(snapshotId);

        vm.warp(block.timestamp + TIER_1_PAUSE_DURATION + TIER_2_PAUSE_DURATION + 1);
        vm.expectEmit(true, true, true, true);
        emit SecureProxy.SecurityUnpause();
        testProxy.set(1);

        vm.revertTo(snapshotId);

        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);
        changePrank(TEST_USER_BLOCKED);
        // Invalid escalation, admin paused
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier3Codes[0]);

        vm.revertTo(snapshotId);

        // Cannot reuse code
        vm.expectRevert(SecureProxy__CodeInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier2Codes[0]);
        // Invalid escalation, same tier
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier2Codes[1]);
        // Invalid escalation, lower tier
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier1Codes[1]);

        secureProxy.securePause(currentCodeSetId, tier3Codes[0]);

        // Cannot reuse code
        vm.expectRevert(SecureProxy__CodeInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier3Codes[0]);
        // Invalid escalation, same tier
        vm.expectRevert(SecureProxy__EscalationInvalid.selector);
        secureProxy.securePause(currentCodeSetId, tier3Codes[1]);
        
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(1);

        vm.warp(block.timestamp + TIER_1_PAUSE_DURATION + TIER_2_PAUSE_DURATION + TIER_3_PAUSE_DURATION + 1);
        vm.expectEmit(true, true, true, true);
        emit SecureProxy.SecurityUnpause();
        testProxy.set(1);
    }

    function testCodesPauseContractWithIncrementedSet() public {
        changePrank(PROXY_CODE_MANAGER);
        string[] memory tier1Codes = new string[](5);
        string[] memory tier2Codes = new string[](5);
        string[] memory tier3Codes = new string[](5);
        bytes32[] memory tier1CodeHashes = new bytes32[](5);
        bytes32[] memory tier2CodeHashes = new bytes32[](5);
        bytes32[] memory tier3CodeHashes = new bytes32[](5);

        tier1Codes[0] = "a1111111111111111111";
        tier1Codes[1] = "b1111111111111111111";
        tier1Codes[2] = "c1111111111111111111";
        tier1Codes[3] = "d1111111111111111111";
        tier1Codes[4] = "e1111111111111111";
        tier2Codes[0] = "f1111111111111111111";
        tier2Codes[1] = "g1111111111111111111";
        tier2Codes[2] = "h1111111111111111111";
        tier2Codes[3] = "i1111111111111111111";
        tier2Codes[4] = "j1111111111111111111";
        tier3Codes[0] = "k1111111111111111111";
        tier3Codes[1] = "l1111111111111111111";
        tier3Codes[2] = "m1111111111111111111";
        tier3Codes[3] = "n1111111111111111111";
        tier3Codes[4] = "o1111111111111111111";

        (,,,uint256 oldCodeSetId) = secureProxy.securePauseState();

        vm.expectEmit(true, true, true, true);

        for (uint256 i; i < tier1Codes.length; ++i) {
            tier1CodeHashes[i] = keccak256(bytes(tier1Codes[i]));
            emit SecureProxy.PauseCodeAdded(oldCodeSetId, tier1CodeHashes[i], TIER_1);
        }

        for (uint256 i; i < tier2Codes.length; ++i) {
            tier2CodeHashes[i] = keccak256(bytes(tier2Codes[i]));
            emit SecureProxy.PauseCodeAdded(oldCodeSetId, tier2CodeHashes[i], TIER_2);
        }

        for (uint256 i; i < tier3Codes.length; ++i) {
            tier3CodeHashes[i] = keccak256(bytes(tier3Codes[i]));
            emit SecureProxy.PauseCodeAdded(oldCodeSetId, tier3CodeHashes[i], TIER_3);
        }

        secureProxy.secureAddPauseCodes(false, tier1CodeHashes, tier2CodeHashes, tier3CodeHashes);

        vm.expectEmit(true, true, true, true);
        uint256 newCodeSetId = oldCodeSetId + 1;

        emit SecureProxy.PauseCodeSetExpired(oldCodeSetId, block.timestamp + CODE_ROTATION_PRIOR_SET_VALID_DURATION);
        emit SecureProxy.PauseCodeSetIncremented(newCodeSetId);

        for (uint256 i; i < tier1Codes.length; ++i) {
            tier1CodeHashes[i] = keccak256(bytes(tier1Codes[i]));
            emit SecureProxy.PauseCodeAdded(newCodeSetId, tier1CodeHashes[i], TIER_1);
        }

        for (uint256 i; i < tier2Codes.length; ++i) {
            tier2CodeHashes[i] = keccak256(bytes(tier2Codes[i]));
            emit SecureProxy.PauseCodeAdded(newCodeSetId, tier2CodeHashes[i], TIER_2);
        }

        for (uint256 i; i < tier3Codes.length; ++i) {
            tier3CodeHashes[i] = keccak256(bytes(tier3Codes[i]));
            emit SecureProxy.PauseCodeAdded(newCodeSetId, tier3CodeHashes[i], TIER_3);
        }

        secureProxy.secureAddPauseCodes(true, tier1CodeHashes, tier2CodeHashes, tier3CodeHashes);

        changePrank(TEST_USER_ALLOWED);
        testProxy.set(1);
        changePrank(TEST_USER_BLOCKED);
        uint256 snapshotId = vm.snapshot();

        // Short code fails due to minimum length check
        assertEq(secureProxy.secureCheckPauseCode(oldCodeSetId, tier1CodeHashes[4]), TIER_1);
        vm.expectRevert(SecureProxy__PauseCodeTooShort.selector);
        secureProxy.securePause(oldCodeSetId, tier1Codes[4]);
        // Old code set works during rotation period
        assertEq(secureProxy.secureCheckPauseCode(oldCodeSetId, tier1CodeHashes[0]), TIER_1);
        secureProxy.securePause(oldCodeSetId, tier1Codes[0]);
        assertEq(secureProxy.secureCheckPauseCode(oldCodeSetId, tier1CodeHashes[0]), TIER_INVALID);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(1);

        vm.revertTo(snapshotId);

        // Old code set fails after rotation period
        vm.warp(block.timestamp + CODE_ROTATION_PRIOR_SET_VALID_DURATION);
        assertEq(secureProxy.secureCheckPauseCode(oldCodeSetId, tier1CodeHashes[0]), TIER_INVALID);
        vm.expectRevert(SecureProxy__CodeSetExpired.selector);
        secureProxy.securePause(oldCodeSetId, tier1Codes[0]);

        // New code set works after migration period
        assertEq(secureProxy.secureCheckPauseCode(newCodeSetId, tier1CodeHashes[0]), TIER_1);
        secureProxy.securePause(newCodeSetId, tier1Codes[0]);
        assertEq(secureProxy.secureCheckPauseCode(newCodeSetId, tier1CodeHashes[0]), TIER_INVALID);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(1);

        vm.revertTo(snapshotId);

        // New code set works during migration period
        assertEq(secureProxy.secureCheckPauseCode(newCodeSetId, tier1CodeHashes[0]), TIER_1);
        secureProxy.securePause(newCodeSetId, tier1Codes[0]);
        assertEq(secureProxy.secureCheckPauseCode(newCodeSetId, tier1CodeHashes[0]), TIER_INVALID);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(1);
    }

    function testAdminUpgradeWithCodeSetExpiration() public {
        changePrank(PROXY_CODE_MANAGER);
        string[] memory tier1Codes = new string[](5);
        string[] memory tier2Codes = new string[](5);
        string[] memory tier3Codes = new string[](5);
        bytes32[] memory tier1CodeHashes = new bytes32[](5);
        bytes32[] memory tier2CodeHashes = new bytes32[](5);
        bytes32[] memory tier3CodeHashes = new bytes32[](5);

        tier1Codes[0] = "a1111111111111111111";
        tier1Codes[1] = "b1111111111111111111";
        tier1Codes[2] = "c1111111111111111111";
        tier1Codes[3] = "d1111111111111111111";
        tier1Codes[4] = "e1111111111111111111";
        tier2Codes[0] = "f1111111111111111111";
        tier2Codes[1] = "g1111111111111111111";
        tier2Codes[2] = "h1111111111111111111";
        tier2Codes[3] = "i1111111111111111111";
        tier2Codes[4] = "j1111111111111111111";
        tier3Codes[0] = "k1111111111111111111";
        tier3Codes[1] = "l1111111111111111111";
        tier3Codes[2] = "m1111111111111111111";
        tier3Codes[3] = "n1111111111111111111";
        tier3Codes[4] = "o1111111111111111111";

        (,,,uint256 oldCodeSetId) = secureProxy.securePauseState();

        vm.expectEmit(true, true, true, true);

        for (uint256 i; i < tier1Codes.length; ++i) {
            tier1CodeHashes[i] = keccak256(bytes(tier1Codes[i]));
            emit SecureProxy.PauseCodeAdded(oldCodeSetId, tier1CodeHashes[i], TIER_1);
        }

        for (uint256 i; i < tier2Codes.length; ++i) {
            tier2CodeHashes[i] = keccak256(bytes(tier2Codes[i]));
            emit SecureProxy.PauseCodeAdded(oldCodeSetId, tier2CodeHashes[i], TIER_2);
        }

        for (uint256 i; i < tier3Codes.length; ++i) {
            tier3CodeHashes[i] = keccak256(bytes(tier3Codes[i]));
            emit SecureProxy.PauseCodeAdded(oldCodeSetId, tier3CodeHashes[i], TIER_3);
        }

        secureProxy.secureAddPauseCodes(false, tier1CodeHashes, tier2CodeHashes, tier3CodeHashes);

        vm.expectEmit(true, true, true, true);
        uint256 newCodeSetId = oldCodeSetId + 1;

        emit SecureProxy.PauseCodeSetExpired(oldCodeSetId, block.timestamp + CODE_ROTATION_PRIOR_SET_VALID_DURATION);
        emit SecureProxy.PauseCodeSetIncremented(newCodeSetId);

        for (uint256 i; i < tier1Codes.length; ++i) {
            tier1CodeHashes[i] = keccak256(bytes(tier1Codes[i]));
            emit SecureProxy.PauseCodeAdded(newCodeSetId, tier1CodeHashes[i], TIER_1);
        }

        for (uint256 i; i < tier2Codes.length; ++i) {
            tier2CodeHashes[i] = keccak256(bytes(tier2Codes[i]));
            emit SecureProxy.PauseCodeAdded(newCodeSetId, tier2CodeHashes[i], TIER_2);
        }

        for (uint256 i; i < tier3Codes.length; ++i) {
            tier3CodeHashes[i] = keccak256(bytes(tier3Codes[i]));
            emit SecureProxy.PauseCodeAdded(newCodeSetId, tier3CodeHashes[i], TIER_3);
        }

        secureProxy.secureAddPauseCodes(true, tier1CodeHashes, tier2CodeHashes, tier3CodeHashes);

        changePrank(TEST_USER_ALLOWED);
        testProxy.set(1);

        uint256 snapshotId = vm.snapshot();

        changePrank(TEST_USER_BLOCKED);
        // Old code set works during rotation period
        assertEq(secureProxy.secureCheckPauseCode(oldCodeSetId, tier1CodeHashes[0]), TIER_1);
        secureProxy.securePause(oldCodeSetId, tier1Codes[0]);
        assertEq(secureProxy.secureCheckPauseCode(oldCodeSetId, tier1CodeHashes[0]), TIER_INVALID);
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(1);

        vm.revertTo(snapshotId);
        
        changePrank(PROXY_ADMIN);
        uint256[] memory expireCodeSetIds = new uint256[](2);
        expireCodeSetIds[0] = oldCodeSetId;
        expireCodeSetIds[1] = newCodeSetId;
        // Invalid expirations
        vm.expectRevert(SecureProxy__CodeSetInvalid.selector);
        secureProxy.secureExpireCodeSets(expireCodeSetIds);
        expireCodeSetIds = new uint256[](1);
        expireCodeSetIds[0] = oldCodeSetId;
        vm.expectEmit(true, true, true, true);
        emit SecureProxy.PauseCodeSetExpired(oldCodeSetId, block.timestamp);
        secureProxy.secureExpireCodeSets(expireCodeSetIds);

        // Old code set does not work after expiry
        assertEq(secureProxy.secureCheckPauseCode(oldCodeSetId, tier1CodeHashes[0]), TIER_INVALID);
        vm.expectRevert(SecureProxy__CodeSetExpired.selector);
        secureProxy.securePause(oldCodeSetId, tier1Codes[0]);

        snapshotId = vm.snapshot();

        vm.expectRevert(SecureProxy__ContractMustBeFullyPausedToUpgrade.selector);
        secureProxy.secureUpgrade(address(testImplementation2));

        secureProxy.secureAdminPause(false);

        vm.expectEmit(true, true, true, true);
        emit SecureProxy.Upgraded(address(testImplementation2));
        secureProxy.secureUpgrade(address(testImplementation2));

        changePrank(TEST_USER_BLOCKED);
        // Contract is still paused after upgrade
        vm.expectRevert(SecureProxy__Paused.selector);
        testProxy.set(1);
        changePrank(TEST_USER_ALLOWED);
        // Allowed user can still execute during pause
        testProxy.set(4);
        assertEq(testProxy.get(), 2); // TestImplementation2 divides value set by 2

        changePrank(PROXY_ADMIN);
        vm.expectEmit(true, true, true, true);
        emit SecureProxy.SecurityUnpause();
        secureProxy.secureAdminPause(true);

        changePrank(TEST_USER_BLOCKED);
        // Contract is now unpaused
        testProxy.set(6);
        assertEq(testProxy.get(), 3); // TestImplementation2 divides value set by 2

        // Upgrade to TestImplementation3 for revert tests in proxy implementation
        changePrank(PROXY_ADMIN);
        secureProxy.secureAdminPause(false);
        // First clear, testImplementation3 to test no code on upgrade
        bytes memory testImplementation3Code = address(testImplementation3).code;
        vm.etch(address(testImplementation3), bytes(""));
        vm.expectRevert(SecureProxy__ImplementationDoesNotHaveCode.selector);
        secureProxy.secureUpgrade(address(testImplementation3));

        // Restore testImplementation3 code to test reverts in proxy
        vm.etch(address(testImplementation3), testImplementation3Code);
        secureProxy.secureUpgrade(address(testImplementation3));
        secureProxy.secureAdminPause(true);

        changePrank(TEST_USER_BLOCKED);
        // Implementation will revert on set
        vm.expectRevert(ITestImplementation.TestRevert1.selector);
        testProxy.set(8);
        assertEq(testProxy.get(), 3); // Value remains at 3

        // Test receive
        vm.deal(TEST_USER_BLOCKED, 1 ether);
        (bool success, bytes memory returnData) = address(testProxy).call{value: 1 ether}("");
        assertFalse(success);
        bytes4 returnSelector;
        assembly ("memory-safe") {
            returnSelector := mload(add(0x20, returnData))
        }
        assertEq(returnSelector, ITestImplementation.TestRevert2.selector);
    }
}

interface ITestImplementation {
    error TestRevert1();
    error TestRevert2();
    function set(uint256) external;
    function get() external view returns(uint256);
}

contract TestImplementation1 is ITestImplementation {
    uint256 value;

    function set(uint256 value_) external {
        value = value_;
    }

    function get() external view returns (uint256) {
        return value;
    }
}

contract TestImplementation2 is ITestImplementation {
    uint256 value;

    function set(uint256 value_) external {
        value = value_ / 2;
    }

    function get() external view returns (uint256) {
        return value;
    }
}

contract TestImplementation3 is ITestImplementation {
    uint256 value;

    function set(uint256) external pure {
        revert TestRevert1();
    }

    function get() external view returns (uint256) {
        return value;
    }
    
    receive() external payable {
        revert TestRevert2();
    }
}

contract TestInitializable is ITestImplementation {
    uint256 value;
    bool initialized;

    function set(uint256 value_) external {
        value = value_;
    }

    function get() external view returns (uint256) {
        return value;
    }

    function initialize(uint256 value_) external {
        if (initialized) revert();
        if (value_ > 0x99999) revert();
        value = value_;
        initialized = true;
    }
}