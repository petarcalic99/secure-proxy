// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

/// @dev Minimum length of a pause code.
uint256 constant PAUSE_CODE_MINIMUM_LENGTH = 20;

/// @dev Duration of a tier 1 pause.
uint256 constant TIER_1_PAUSE_DURATION = 30 minutes;
/// @dev Duration of a tier 2 pause.
uint256 constant TIER_2_PAUSE_DURATION = 6 hours;
/// @dev Duration of a tier 3 pause.
uint256 constant TIER_3_PAUSE_DURATION = 7 days;

/// @dev Time that the prior code set is valid after code rotation.
uint256 constant CODE_ROTATION_PRIOR_SET_VALID_DURATION = 1 hours;

/// @dev Constant representation of Tier 1.
uint256 constant TIER_1 = 1;
/// @dev Constant representation of Tier 2.
uint256 constant TIER_2 = 2;
/// @dev Constant representation of Tier 3.
uint256 constant TIER_3 = 3;
/// @dev Constant representation of admin tier.
uint256 constant TIER_ADMIN = 4;

/// @dev Constant representation of an invalid tier.
uint256 constant TIER_INVALID = 0;
/// @dev Constant representation of escalation tier when not paused.
uint256 constant TIER_NOT_PAUSED = 0;

/// @dev Constant value for expiration to set when not paused.
uint256 constant UNPAUSED_EXPIRATION = 0;
/// @dev Constant value for expiration when admin sets full pause.
uint256 constant FULL_PAUSE_EXPIRATION = type(uint256).max;

/// @dev Storage slot of the implementation address for the proxy
/// @dev keccak-256 hash of "eip1967.proxy.implementation" minus 1
bytes32 constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

/// @dev Storage slot for the root of the secure proxy storage.
bytes32 constant SECURITY_SLOT = 0x5EC00000000000005EC00000000000005EC00000000000005EC0000000000000;

/// @dev Role hash for address authorized to manage pause codes.
bytes32 constant SECURE_PROXY_CODE_MANAGER_BASE_ROLE = keccak256("SECURE_PROXY_CODE_MANAGER_ROLE");

/// @dev Role hash for address authorized to perform administrative actions.
bytes32 constant SECURE_PROXY_ADMIN_BASE_ROLE = keccak256("SECURE_PROXY_ADMIN_ROLE");