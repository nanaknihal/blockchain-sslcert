//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import { WTFUtils } from "contracts/WTFUtils.sol";
import { ASN1Utils } from "contracts/ASN1Utils.sol";
import "hardhat/console.sol";

contract VerifySSLCertificate {
    // e and n are exponent and modulus of the authority's public key
    uint256 public e;
    bytes public n;
    // pubkeyStart is the bytes that public key part of the tbsCertifcate shoud start with
    bytes public pubkeyStart; 
    // pubkeyLength is how long the public key part of the tbsCertificate should be
    uint8 public pubkeyLength;

    mapping(bytes => address) public domainToAddr;
    mapping(address => bytes) public addrToDomain;



    constructor(uint256 e_, bytes memory n_) {
        e = e_;
        n = n_;
    }

    // function keyRotate(bytes calldata newE, bytes calldata newN) public onlyOwner {
    //     e = newE;
    //     n = newN;
    // }
    
    function verifyMe(bytes memory tbsCert, bytes calldata tbsCertSignature, bytes memory addr, bytes calldata signedAddr) public {
        // 1. Require that CA signed tbsCertificate
        require(
            WTFUtils.verifyRSASignature(e, n, tbsCertSignature, tbsCert),
            "Validation of certifiate signature failed"
        );
        // 2. If valid signature, get for the domain name and public key listen in tbsCertificate. These both belong to the website owner
        ASN1Utils.OwnershipInfo memory certOwner = ASN1Utils.getCertOwner(tbsCert);

        // 3. Verify signedAddr is signed by certOwner
        require(WTFUtils.verifyRSASignature(65537, certOwner.pubkeyModulus, addr, signedAddr), "failed to validate signature of your address");
        
        // 4. Give domain name to addr
        address asAddr = WTFUtils.bytesToAddress(addr);
        domainToAddr[certOwner.domainName] = asAddr;
        addrToDomain[asAddr] = certOwner.domainName;
    }
}
