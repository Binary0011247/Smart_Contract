// contracts/SecureCertificateRegistry.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title SecureCertificateRegistry
 * @author Shubh Gupta
 * @notice A secure implementation of the certificate registry using best practices.
 * @dev Inherits from OpenZeppelin for ownership and reentrancy protection.
 */
contract SecureCertificateRegistry is Ownable, ReentrancyGuard {
    mapping(address => bool) public isCertifier;

    struct Certificate {
        string courseName;
        address issuer;
        uint256 issueTimestamp;
    }
    mapping(address => Certificate) public certificates;

    address payable public partnerWallet;
    uint256 public partnerFee;

    event CertificateIssued(address indexed student, string courseName, address indexed issuer);
    event CertificateRevoked(address indexed student);

    modifier onlyCertifier() {
        require(isCertifier[msg.sender], "Caller is not a certifier");
        _;
    }

    constructor(address payable _partner, uint256 _fee) {
        partnerWallet = _partner;
        partnerFee = _fee;
    }

    // --- Administrative Functions (Secure) ---

    // FIX: `onlyOwner` modifier ensures only the contract owner can manage certifiers.
    function addCertifier(address _newCertifier) public onlyOwner {
        isCertifier[_newCertifier] = true;
    }

    function removeCertifier(address _certifier) public onlyOwner {
        isCertifier[_certifier] = false;
    }

    // --- Core Functions (Secure) ---

    // FIX: `nonReentrant` and Checks-Effects-Interactions pattern prevent reentrancy.
    function issueCertificate(address _student, string calldata _courseName) public payable nonReentrant onlyCertifier {
        // 1. Checks
        require(msg.value >= partnerFee, "Insufficient fee");
        require(certificates[_student].issuer == address(0), "Student already certified");

        // 2. Effects (State Changes)
        certificates[_student] = Certificate({
            courseName: _courseName,
            issuer: msg.sender,
            issueTimestamp: block.timestamp
        });
        emit CertificateIssued(_student, _courseName, msg.sender);

        // 3. Interactions (External Calls)
        if (partnerFee > 0) {
            (bool sent, ) = partnerWallet.call{value: msg.value}("");
            require(sent, "Fee transfer failed");
        }
    }

    // FIX: `onlyOwner` modifier restricts who can revoke certificates.
    function revokeCertificate(address _student) public onlyOwner {
        require(certificates[_student].issuer != address(0), "Certificate not found");
        delete certificates[_student];
        emit CertificateRevoked(_student);
    }

    // NOTE: Vulnerable functions `updateCertifierProfile` and `issueBulkCertificates`
    // have been removed as they represent unsafe patterns.
}