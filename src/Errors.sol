// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

/// @dev thrown when a code is used from an expired code set.
error SecureProxy__CodeSetExpired();

/// @dev thrown when a supplied code is not a valid code.
error SecureProxy__CodeInvalid();

/// @dev thrown when an admin attempts to expire a code set that is not below the current code set.
error SecureProxy__CodeSetInvalid();

/// @dev thrown when an admin issues an upgrade without the contract fully paused.
error SecureProxy__ContractMustBeFullyPausedToUpgrade();

/// @dev thrown when a code is used that is at or below the current escalation tier.
error SecureProxy__EscalationInvalid();

/// @dev thrown when the implementation being set does not have deployed code.
error SecureProxy__ImplementationDoesNotHaveCode();

/// @dev thrown when the proxy deploy includes initialization data and the initialization call fails.
error SecureProxy__InitializationFailed();

/// @dev thrown when a pause code is submitted that does not meet the minimum length requirements.
error SecureProxy__PauseCodeTooShort();

/// @dev thrown when a call is made while the proxy is paused and the caller is not allowed.
error SecureProxy__Paused();
