// contracts/VulnerableCertificateRegistry.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

/**
 * @title VulnerableCertificateRegistry
 * @author Shubh Gupta
 * @notice A decentralized certificate registry with intentional, severe vulnerabilities.
 * THIS CONTRACT IS FOR EDUCATIONAL/EVALUATION PURPOSES ONLY.
 */
contract VulnerableCertificateRegistry {
    // VULNERABILITY #3: `admin` is in storage slot 0, making it a target for storage pointer attacks.
    address public admin;
    mapping(address => bool) public isCertifier;

    // VULNERABILITY #4: `uint8` is too small and can overflow, wrapping from 255 back to 0.
    uint8 public totalCertifiers;

    struct Certificate {
        string courseName;
        address issuer;
        uint256 issueTimestamp;
    }
    mapping(address => Certificate) public certificates;

    address payable public partnerWallet;
    uint256 public partnerFee = 0.01 ether;

    event CertificateIssued(address indexed student, string courseName, address indexed issuer);

    constructor(address payable _partner) {
        admin = msg.sender;
        partnerWallet = _partner;
    }

    /**
     * VULNERABILITY #1A: Broken Access Control. Anyone can call this and become a certifier.
     */
    function addCertifier(address _newCertifier) public {
        isCertifier[_newCertifier] = true;
        totalCertifiers++; // Prone to overflow
    }

    /**
     * VULNERABILITY #3: Uninitialized Storage Pointer.
     * MODIFICATION: We use an assembly block to explicitly point to slot 0.
     * This satisfies the modern compiler but preserves the vulnerability for analysis.
     */
    function updateCertifierProfile(string calldata _name) public {
        Certificate storage profile;
        // The following assembly block makes the vulnerability explicit.
        // It tells the compiler "I am intentionally pointing this 'profile' variable to storage slot 0".
        assembly {
            profile.slot := 0
        }
        // The vulnerability remains: This line still overwrites the `admin` address in slot 0.
        profile.courseName = _name;
    }

    /**
     * VULNERABILITY #2: Reentrancy. External call is made before state is updated.
     */
    function issueCertificate(address _student, string calldata _courseName) public payable {
        require(isCertifier[msg.sender], "Not a certifier");
        require(msg.value >= partnerFee, "Insufficient fee");

        // INTERACTION before EFFECT: Classic reentrancy vulnerability
        (bool sent, ) = partnerWallet.call{value: msg.value}("");
        require(sent, "Fee transfer failed");

        // State is updated last, after the potentially malicious external call
        certificates[_student] = Certificate({
            courseName: _courseName,
            issuer: msg.sender,
            issueTimestamp: block.timestamp
        });
        emit CertificateIssued(_student, _courseName, msg.sender);
    }

    /**
     * VULNERABILITY #5: Denial of Service. An unbounded loop can exceed the block gas limit.
     */
    function issueBulkCertificates(address[] calldata _students, string calldata _courseName) public {
        require(isCertifier[msg.sender], "Not a certifier");
        for (uint i = 0; i < _students.length; i++) {
            certificates[_students[i]] = Certificate({ courseName: _courseName, issuer: msg.sender, issueTimestamp: block.timestamp });
        }
    }

    /**
     * VULNERABILITY #1B: Broken Access Control. Anyone can revoke anyone's certificate.
     */
    function revokeCertificate(address _student) public {
        delete certificates[_student];
    }

    function withdraw() public {
        require(msg.sender == admin, "Only admin");
        payable(msg.sender).transfer(address(this).balance);
    }
}