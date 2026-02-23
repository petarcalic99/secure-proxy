// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

/**
 * @dev Storage data for the secure proxy.
 *
 * @dev **pauseExpiration**           Timestamp that the pause expires.
 * @dev **currentEscalationTier**     Current escalation tier.
 * @dev **codeSetId**                 Current code set id.
 * @dev **codeSet**                   Mapping to CodeStorage data for code sets.
 * @dev **allowedCallerDuringPause**  Mapping of callers that are allowed to make calls while paused.
 */
struct SecurityStorage {
    uint256 pauseExpiration;
    uint256 currentEscalationTier;
    uint256 codeSetId;
    mapping (uint256 => CodeStorage) codeSet;
    mapping (address => bool) allowedCallerDuringPause;
}

/**
 * @dev Storage data for a set of pause codes.
 *
 * @dev **codeTier**  Mapping of pause code hashes to their tier.
 * @dev **expires**   Timestamp that the code set expires at.
 */
struct CodeStorage {
    mapping (bytes32 => uint256) codeTier;
    uint256 expires;
}