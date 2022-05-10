// //SPDX-License-Identifier: Unlicense
// pragma solidity ^0.8.0;

// import { WTFUtils } from "contracts/WTFUtils.sol";
// import "hardhat/console.sol";

// contract VerifySSLCertificate {
//     // e and n are exponent and modulus of the authority's public key
//     bytes public e;
//     bytes public n;
//     // pubkeyStart is the bytes that public key part of the tbsCertifcate shoud start with
//     bytes public pubkeyStart; 
//     // pubkeyLength is how long the public key part of the tbsCertificate should be
//     uint8 public pubkeyLength;

//     // bytes public domainNameBottomBread; 
//     // bytes public domainNameTopBread;

//     constructor(bytes calldata e_, bytes calldata n_) {
//         e = e_;
//         n = n_;
//         pubkeyStart = pubkeyStart_;
//         pubkeyLength = pubkeyLenght_;
//     }

//     function keyRotate(bytes calldata newE, bytes calldata newN) public onlyOwner {
//         e = newE;
//         n = newN;
//     }

//     function verifyMe(bytes tbsCertificate, bytes signature, WTFUtils.ProposedSandwichAt tbsDomainName, WTFUtils.ProposedSandwichAt tbsPubkey, bytes mySignedAddress) {
//         // 1. Require that CA signed tbsCertificate
//         require(
//             WTFUtils.verifyRSASignature(e, n, signature, tbsCertifcate),
//             "Validation of certifiate signature failed"
//         );
//         // 2. If valid signature, check for the domain name and public key listen in tbsCertificate. These both belong to the website owner
//         require(tbsPubKey.sandwichValue.length == pubkey.length, "proposed RSA public key has wrong length");
//         // requrie(domain name???)
//         // 3. check that signedAddress == msg.sender and signedAddress was signed by the website owner's private key (i.e., validated against their public key)
//         require(signedAddress == msg.sender, "signed address should be the one you submitted this transaction with");
//         require(WTFUtils.verifyRSASignature(tbsPubKey, 65537, msg.sender, mySignedAddress), "failed to validate signature of your address");
//     }
// }
