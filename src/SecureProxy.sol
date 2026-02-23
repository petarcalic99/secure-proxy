// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import "./Constants.sol";
import "./DataTypes.sol";
import "./Errors.sol";

import "@limitbreak/tm-core-lib/src/utils/security/RoleSetClient.sol";

/**
 * @title   SecureProxy
 * @author  Limit Break, Inc
 * 
 * @notice  Upgradeable proxy designed to allow for rapid execution of protocol pausing
 *          across all blockchains that the protocol is operating on without requiring
 *          signatures to be issued for each chain through "pause codes" which may be
 *          replayed by any account when revealed.
 * 
 * @dev     Pause codes are held by trusted parties to issue escalating pauses of the
 *          protocol from tier 1 to tier 3 pause.
 * @dev     Pause codes are managed by the account granted the `SECURE_PROXY_CODE_MANAGER_ROLE`
 *          in the RoleSetServer.
 * @dev     Pause codes may be added by the code manager to the current set of codes or 
 *          fully rotated by incrementing the code set. When code set is incremented, 
 *          the codes for the prior set will remain in effect for a duration of time
 *          specified by `CODE_ROTATION_PRIOR_SET_VALID_DURATION`.
 * @dev     The proxy admin may clear the pause or extend the pause so that it does not expire.
 * @dev     The proxy admin can expire code sets that are not the current code set to
 *          prevent griefing of protocol pauses with revealed codes if an upgrade is required.
 * @dev     Intended usage: 
 *              - Monitor detects a condition that requires pause.
 *              - Tier 1 pause code is revealed by executing on blockchains.
 *              - Pause code is replicated to all blockchains the protocol is on.
 *              - Condition is triaged to determine if a Tier 2 pause is required.
 *              - If Tier 2 is not required, the pause expires after Tier 1 duration.
 *              - If Tier 2 is required, the Tier 2 pause code is revealed and replicated.
 *              - Continue triage and escalate to Tier 3 if required.
 *              - If required, proxy admin escalates to a full pause pending contract upgrade.
 *              - Code manager issues new pause codes.
 *              - Admin expires the previous code set.
 *              - Admin upgrades the proxy implementation address.
 *              - Admin allows specific callers while paused to perform necessary upgrade operations.
 *              - Admin clears pause.
 *              - Protocol resumes operations.
 */
contract SecureProxy is RoleSetClient {
    /// @dev Role identifier for address authorized to manage pause codes.
    bytes32 private immutable SECURE_PROXY_CODE_MANAGER_ROLE;

    /// @dev Role identifier for address authorized to perform administrative actions.
    bytes32 private immutable SECURE_PROXY_ADMIN_ROLE;

    /// @dev Emitted when a caller is added to the list of allowed callers while paused.
    event AllowedCallerDuringPauseSet(address indexed caller, bool allowed);
    /// @dev Emitted when a pause code is added to a code set.
    event PauseCodeAdded(uint256 indexed codeSetId, bytes32 indexed codeHash, uint256 indexed tier);
    /// @dev Emitted when a pause code set is set to expire.
    event PauseCodeSetExpired(uint256 codeSetId, uint256 expiration);
    /// @dev Emitted when the pause code set is incremented.
    event PauseCodeSetIncremented(uint256 newCodeSetId);
    /// @dev Emitted when a pause is issued.
    event SecurityPause(uint256 indexed tier, uint256 pausedUntil);
    /// @dev Emitted when a pause expires or is cleared.
    event SecurityUnpause();
    /// @dev Emitted when the implementation address is updated.
    event Upgraded(address indexed implementation);

    constructor (
        address initialImplementation_,
        address roleServer_,
        bytes32 roleSet_,
        bytes memory initializationData_
    ) RoleSetClient(roleServer_, roleSet_) {
        _setImplementation(initialImplementation_);
        SECURE_PROXY_CODE_MANAGER_ROLE = _hashRoleSetRole(roleSet_, SECURE_PROXY_CODE_MANAGER_BASE_ROLE);
        SECURE_PROXY_ADMIN_ROLE = _hashRoleSetRole(roleSet_, SECURE_PROXY_ADMIN_BASE_ROLE);

        SecurityStorage storage ptrSecurityStorage = _securityStorage();

        // Initialize first set of pause codes to not expire
        CodeStorage storage ptrCodeStorage = ptrSecurityStorage.codeSet[ptrSecurityStorage.codeSetId];
        ptrCodeStorage.expires = type(uint256).max;

        // Allow address(0) as a caller during pause to permit offchain view function access
        ptrSecurityStorage.allowedCallerDuringPause[address(0)] = true;

        if (initializationData_.length > 0) {
            (bool success, ) = initialImplementation_.delegatecall(initializationData_);
            if (!success) {
                revert SecureProxy__InitializationFailed();
            }
        }
    }

    ///////////////////////////////////////////////////////
    //                 ADMIN FUNCTIONS                   //
    ///////////////////////////////////////////////////////

    /**
     * @notice  Administrative function to set a non-expiring pause or to clear the current pause.
     * 
     * @dev     This function allows clearing when no pause is in effect to prevent blocking
     *          admin multisig transaction sequence when an admin clears a temporary pause that
     *          may not have been replicated to all chains.
     * 
     * @dev     Throws when the caller does not have the `SECURE_PROXY_ADMIN_ROLE` role.
     * 
     * @param clearPause  True if the pause is to be cleared.
     */
    function secureAdminPause(bool clearPause) external callerHasRole(SECURE_PROXY_ADMIN_ROLE) {
        SecurityStorage storage ptrSecurityStorage = _securityStorage();

        if (clearPause) {
            // Set escalation to not paused to allow pause codes to escalate
            ptrSecurityStorage.pauseExpiration = UNPAUSED_EXPIRATION;
            ptrSecurityStorage.currentEscalationTier = TIER_NOT_PAUSED;

            emit SecurityUnpause();
        } else {
            // Set escalation to admin tier to prevent pause code usage
            ptrSecurityStorage.pauseExpiration = FULL_PAUSE_EXPIRATION;
            ptrSecurityStorage.currentEscalationTier = TIER_ADMIN;

            emit SecurityPause(TIER_ADMIN, FULL_PAUSE_EXPIRATION);
        }
    }

    /**
     * @notice  Administrative function to set permissions for address to call through to the implementation
     *          while a pause is in effect.
     * 
     * @dev     Throws when the caller does not have the `SECURE_PROXY_ADMIN_ROLE` role.
     * 
     * @param allowed  True if the addresses in `callers` are to be set as allowed during pause.
     * @param callers  Array of addresses that should be allowed or have allowance revoked during pause.
     */
    function secureSetAllowedCallersDuringPause(bool allowed, address[] calldata callers) external callerHasRole(SECURE_PROXY_ADMIN_ROLE) {
        SecurityStorage storage ptrSecurityStorage = _securityStorage();
        mapping (address => bool) storage allowedCallerDuringPause = ptrSecurityStorage.allowedCallerDuringPause;
        
        address caller;
        for (uint256 i = 0; i < callers.length; ++i) {
            caller = callers[i];

            allowedCallerDuringPause[caller] = allowed;

            emit AllowedCallerDuringPauseSet(caller, allowed);
        }
    }

    /**
     * @notice  Administrative function to expire code sets to prevent reuse of codes after a new code set is issued.
     * 
     * @dev     Throws when the caller does not have the `SECURE_PROXY_ADMIN_ROLE` role.
     * @dev     Throws when a supplied code set does not exist.
     * @dev     Throws when a supplied code set is the current code set.
     *  
     * @param codeSetIds  Array of code sets to expire.
     */
    function secureExpireCodeSets(uint256[] calldata codeSetIds) external callerHasRole(SECURE_PROXY_ADMIN_ROLE) {
        SecurityStorage storage ptrSecurityStorage = _securityStorage();
        uint256 currentCodeSetId = ptrSecurityStorage.codeSetId;

        uint256 expireCodeSetId;
        for (uint256 i = 0; i < codeSetIds.length; ++i) {
            expireCodeSetId = codeSetIds[i];
            if (expireCodeSetId >= currentCodeSetId) {
                revert SecureProxy__CodeSetInvalid();
            }

            ptrSecurityStorage.codeSet[expireCodeSetId].expires = block.timestamp;

            emit PauseCodeSetExpired(expireCodeSetId, block.timestamp);
        }
    }

    /**
     * @notice  Administrative function to set the new implementation address for the proxy.
     * 
     * @dev     Throws when the caller does not have the `SECURE_PROXY_ADMIN_ROLE` role.
     * 
     * @param newImplementation  Address of the new implementation to set.
     */
    function secureUpgrade(address newImplementation) external callerHasRole(SECURE_PROXY_ADMIN_ROLE) {
        SecurityStorage storage ptrSecurityStorage = _securityStorage();

        if (ptrSecurityStorage.currentEscalationTier != TIER_ADMIN) {
            revert SecureProxy__ContractMustBeFullyPausedToUpgrade();
        }

        _setImplementation(newImplementation);
    }

    ///////////////////////////////////////////////////////
    //              CODE MANAGER FUNCTIONS               //
    ///////////////////////////////////////////////////////

    /**
     * @notice  Management function to add new pause codes and increment the code set for code rotation.
     * 
     * @dev     Code hashes are the keccak256 hash of the string code.
     * 
     * @dev     Throws when the caller does not have the `SECURE_PROXY_CODE_MANAGER_ROLE` role.
     * 
     * @param incrementCodeSet  True if the supplied codes should create a new code set and expire old codes.
     * @param tier1CodeHashes   Array of hashes of Tier 1 codes.
     * @param tier2CodeHashes   Array of hashes of Tier 2 codes.
     * @param tier3CodeHashes   Array of hashes of Tier 3 codes.
     */
    function secureAddPauseCodes(
        bool incrementCodeSet,
        bytes32[] calldata tier1CodeHashes,
        bytes32[] calldata tier2CodeHashes,
        bytes32[] calldata tier3CodeHashes
    ) external callerHasRole(SECURE_PROXY_CODE_MANAGER_ROLE) {
        SecurityStorage storage ptrSecurityStorage = _securityStorage();
        uint256 codeSetId = ptrSecurityStorage.codeSetId;
        CodeStorage storage ptrCodeStorage = ptrSecurityStorage.codeSet[codeSetId];

        if (incrementCodeSet) {
            uint256 priorSetExpiration = block.timestamp + CODE_ROTATION_PRIOR_SET_VALID_DURATION;
            ptrCodeStorage.expires = priorSetExpiration;

            emit PauseCodeSetExpired(codeSetId, priorSetExpiration);

            ptrSecurityStorage.codeSetId = ++codeSetId;
            ptrCodeStorage = ptrSecurityStorage.codeSet[codeSetId];
            ptrCodeStorage.expires = type(uint256).max;

            emit PauseCodeSetIncremented(codeSetId);
        }

        mapping (bytes32 => uint256) storage ptrCodeTier = ptrCodeStorage.codeTier;
        _addCodesToTier(codeSetId, ptrCodeTier, TIER_1, tier1CodeHashes);
        _addCodesToTier(codeSetId, ptrCodeTier, TIER_2, tier2CodeHashes);
        _addCodesToTier(codeSetId, ptrCodeTier, TIER_3, tier3CodeHashes);
    }

    ///////////////////////////////////////////////////////
    //                 PAUSE FUNCTIONS                   //
    ///////////////////////////////////////////////////////

    /**
     * @notice  Executes the supplied pause code to pause the protocol.
     * 
     * @dev     Throws when code set has expired.
     * @dev     Throws when the code is not in the code set.
     * @dev     Throws when the code has been used previously.
     * @dev     Throws when the code tier does not follow the escalation path.
     * 
     * @param codeSetId  ID of the code set the pause code is in.
     * @param pauseCode  Pause code string to execute.
     */
    function securePause(
        uint256 codeSetId,
        string calldata pauseCode
    ) external {
        // Check for existing pause and clear if it has expired
        _checkPauseState(true);

        if (bytes(pauseCode).length < PAUSE_CODE_MINIMUM_LENGTH) {
            revert SecureProxy__PauseCodeTooShort();
        }
        
        SecurityStorage storage ptrSecurityStorage = _securityStorage();
        CodeStorage storage ptrCodeStorage = ptrSecurityStorage.codeSet[codeSetId];

        if (ptrCodeStorage.expires <= block.timestamp) {
            revert SecureProxy__CodeSetExpired();
        }

        bytes32 pauseCodeHash = keccak256(bytes(pauseCode));
        mapping (bytes32 => uint256) storage ptrCodeTier = ptrCodeStorage.codeTier;
        uint256 codeTier = ptrCodeTier[pauseCodeHash];

        if (codeTier == TIER_INVALID) {
            revert SecureProxy__CodeInvalid();
        }

        if (ptrSecurityStorage.currentEscalationTier != codeTier - 1) {
            revert SecureProxy__EscalationInvalid();
        }

        // Consume code when used
        ptrCodeTier[pauseCodeHash] = TIER_INVALID;

        ptrSecurityStorage.currentEscalationTier = codeTier;
        uint256 pausedUntil;
        if (codeTier == TIER_1) {
            // Initial pause, use block time + duration
            ptrSecurityStorage.pauseExpiration = pausedUntil = block.timestamp + TIER_1_PAUSE_DURATION;
        } else if (codeTier == TIER_2) {
            // Second level escalation, extend pause
            ptrSecurityStorage.pauseExpiration = pausedUntil = ptrSecurityStorage.pauseExpiration + TIER_2_PAUSE_DURATION;
        } else {
            // Third level escalation, extend pause
            ptrSecurityStorage.pauseExpiration = pausedUntil = ptrSecurityStorage.pauseExpiration + TIER_3_PAUSE_DURATION;
        }

        emit SecurityPause(codeTier, pausedUntil);
    }

    ///////////////////////////////////////////////////////
    //                  VIEW FUNCTIONS                   //
    ///////////////////////////////////////////////////////

    /**
     * @notice  Returns the tier of the pause code.
     * 
     * @dev     Returns the invalid tier if the code set has expired.
     * 
     * @param  codeSetId      ID of the code set the pause code is in.
     * @param  pauseCodeHash  Pause code hash to check.
     * @return codeTier       The tier of the code hash in the code set.
     */
    function secureCheckPauseCode(
        uint256 codeSetId,
        bytes32 pauseCodeHash
    ) external view returns (uint256 codeTier) {
        SecurityStorage storage ptrSecurityStorage = _securityStorage();
        CodeStorage storage ptrCodeStorage = ptrSecurityStorage.codeSet[codeSetId];

        if (ptrCodeStorage.expires <= block.timestamp) {
            return TIER_INVALID;
        }

        codeTier = ptrCodeStorage.codeTier[pauseCodeHash];
    }

    /**
     * @notice  Returns the current pause state.
     * 
     * @return paused                 True if the proxy is paused.
     * @return pauseExpiration        Time that the pause will expire.
     * @return currentEscalationTier  Tier that issued the current pause.
     * @return currentCodeSetId       Current active code set id.
     */
    function securePauseState() external view returns (
        bool paused,
        uint256 pauseExpiration,
        uint256 currentEscalationTier,
        uint256 currentCodeSetId
    ) {
        SecurityStorage storage ptrSecurityStorage = _securityStorage();
        pauseExpiration = ptrSecurityStorage.pauseExpiration;
        currentEscalationTier = ptrSecurityStorage.currentEscalationTier;
        currentCodeSetId = ptrSecurityStorage.codeSetId;
        paused = pauseExpiration >= block.timestamp;
    }

    ///////////////////////////////////////////////////////
    //                  FALLBACK FUNCTIONS               //
    ///////////////////////////////////////////////////////

    /**
     * @dev  Proxy fallback function to forward calls to implementation contract when not paused.
     */
    fallback() external payable {
        _fallback();
    }

    /**
     * @dev  Proxy receive function to forward calls to implementation contract when not paused.
     */
    receive() external payable {
        _fallback();
    }

    ///////////////////////////////////////////////////////
    //                  INTERNAL FUNCTIONS               //
    ///////////////////////////////////////////////////////

    /**
     * @dev  Adds an array of pause code hashes to the code set mapping, sets their tier 
     *       and emits `PauseCodeAdded` events.
     * 
     * @param codeSetId       ID of the code set the pause code is being added to.
     * @param ptrCodeTier     Storage pointer to the code tier mapping for the code set.
     * @param tier            The tier to set for the pause code.
     * @param tierCodeHashes  Pause code hashes to add to the code set.
     */
    function _addCodesToTier(
        uint256 codeSetId,
        mapping (bytes32 => uint256) storage ptrCodeTier,
        uint256 tier,
        bytes32[] calldata tierCodeHashes
    ) internal {
        bytes32 codeHash;
        for (uint256 i = 0; i < tierCodeHashes.length; ++i) {
            codeHash = tierCodeHashes[i];
            ptrCodeTier[codeHash] = tier;

            emit PauseCodeAdded(codeSetId, codeHash, tier);
        }
    }

    /**
     * @dev  Internal function to store the implementation address at the implementation storage slot
     *       and emit the `Upgraded` event.
     */
    function _setImplementation(address newImplementation) internal {
        if (newImplementation.code.length == 0) {
            revert SecureProxy__ImplementationDoesNotHaveCode();
        }

        assembly ("memory-safe") {
            sstore(IMPLEMENTATION_SLOT, newImplementation)
        }

        emit Upgraded(newImplementation);
    }

    /**
     * @dev  Checks the current pause state to revert if a pause is in effect.
     * 
     * @dev  Clears pause status and emits a `SecurityUnpause` event if the pause has expired.
     * @dev  Static calls will fail after the pause has expired until a stateful call is executed.
     * @dev  Proxy admin and callers allowed by the proxy admin may call to the implementation when paused.
     * 
     * @dev  Throws when the proxy is paused and the caller does not have permission to call during pause.
     * 
     * @param  clearOnly  True if the check should only clear pause state if a pause has expired.
     *                    False if the check should revert if paused and the caller is not allowed.
     */
    function _checkPauseState(bool clearOnly) internal {
        SecurityStorage storage ptrSecurityStorage = _securityStorage();
        uint256 pauseExpiration = ptrSecurityStorage.pauseExpiration;
        if (pauseExpiration != UNPAUSED_EXPIRATION) {
            if (pauseExpiration < block.timestamp) {
                // Pause has expired, clear the pause
                ptrSecurityStorage.pauseExpiration = UNPAUSED_EXPIRATION;
                ptrSecurityStorage.currentEscalationTier = TIER_NOT_PAUSED;

                emit SecurityUnpause();
            } else if (!clearOnly) {
                // Pause is active, check if the caller is allowed during pause
                if (
                    msg.sender != _getRoleHolderView(SECURE_PROXY_ADMIN_ROLE) && 
                    !ptrSecurityStorage.allowedCallerDuringPause[msg.sender]
                ) {
                    revert SecureProxy__Paused();
                }
            }
        }
    }

    /**
     * @dev  Internal fallback function to forward calls to the implementation after checking pause state.
     */
    function _fallback() internal {
        _checkPauseState(false);

        assembly ("memory-safe") {
            calldatacopy(0x00, 0x00, calldatasize())
            let success := delegatecall(gas(), sload(IMPLEMENTATION_SLOT), 0x00, calldatasize(), 0x00, 0x00)

            returndatacopy(0x00, 0x00, returndatasize())

            if success {
                return(0x00, returndatasize())
            }
            revert(0x00, returndatasize())
        }
    }

    /**
     * @dev  Returns the secure proxy root storge.
     */
    function _securityStorage() internal pure returns (SecurityStorage storage s) {
        assembly ("memory-safe") {
            s.slot := SECURITY_SLOT
        }
    }

    /**
     * @dev Sets up fee manager and fee receiver roles for the contract.
     *
     *      Overrides the virtual function from RoleSetClient to configure contract-specific roles.
     *      Establishes SECURE_PROXY_CODE_MANAGER_BASE_ROLE and SECURE_PROXY_ADMIN_BASE_ROLE with appropriate permissions.
     *
     *      <h4>Postconditions:</h4>
     *      1. SECURE_PROXY_CODE_MANAGER_ROLE configured for code management.
     *      2. SECURE_PROXY_ADMIN_ROLE configured for administrative actions.
     *
     * @param roleSet The role set identifier to derive specific roles from.
     */
    function _setupRoles(bytes32 roleSet) internal virtual override {
        _setupRole(_hashRoleSetRole(roleSet, SECURE_PROXY_CODE_MANAGER_BASE_ROLE), 0);
        _setupRole(_hashRoleSetRole(roleSet, SECURE_PROXY_ADMIN_BASE_ROLE), 0);
    }
}
