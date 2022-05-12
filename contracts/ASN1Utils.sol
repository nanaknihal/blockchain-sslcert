// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import 'hardhat/console.sol';
import { WTFUtils } from "contracts/WTFUtils.sol";

library ASN1Utils { 
    struct ObjectLengths {
        uint256 numLengthBytes; // number of bytes encoding length of the value
        uint256 numValueBytes; // number of bytes in the value

    }
    // Ownership info from a ASN1 DER X.509 SSL certificate
    struct OwnershipInfo {
        bytes domainName;
        bytes pubkeyModulus;
    }

    function firstBitIsOne(bytes1 b_) public pure returns (bool oneOrZero) {
        return (b_ & 0x80) == 0x80;
    }

    // DER Objects are encoded as (tag, length, value). The problem is that length can sometimes be > 256 bytes, so can't always be encoded in one byte
    // In case it's over 127 bytes, the length-encoding byte will be set to 1xxxxxxx, where xxxxxxx is a binary number representing the number of
    // additional bytes in which the length is encoded

    // The input to DERLength is therefore not the length byte but a pointer to it, in case the next bytes need to be read:
    function DERObjectLengths(uint256 ptr) public view returns (ObjectLengths memory) {
        // bytes1 tagByte;
        bytes1 lengthByte;
        assembly {
            lengthByte := mload(add(ptr, 1))
        }
        // If the first bit is 1, the rest encodes the number of bytes
        if(firstBitIsOne(lengthByte)){
            uint256 result = 0;
            uint256 tmpPtr = ptr + 1; 
            uint8 numBytes = uint8(lengthByte & 0x7f); //all but first bit which is 1
            uint256 places;
            bytes1 nextByte;
            uint i;
            for(i = numBytes; i > 0; i--){
                tmpPtr += 1;
                places = 2 ** (8 * (i-1));
                assembly {
                    nextByte := mload(tmpPtr)
                }
                result += uint8(nextByte)*places;
            }

            return ObjectLengths(1 + numBytes, result);
        } else {
            return ObjectLengths(1, uint256(uint8(lengthByte)));
        }

    }

    // Takes a pointer to DER object start and goes within it (i.e., skips tag and length bytes then returns a pointer to the next byte, the start of the object's value)
    function goIn(uint256 curPtr) public view returns (uint256 newPtr) {
        ObjectLengths memory lengths = DERObjectLengths(curPtr);
        return curPtr + lengths.numLengthBytes + 1;
    }

    // Takes a pointer to DER object start and skips it (i.e., skips tag, length, and value bytes then returns a pointer to the next object's start)
    function skip(uint256 curPtr) public view returns (uint256 newPtr) {
        ObjectLengths memory lengths = DERObjectLengths(curPtr);
        return curPtr + lengths.numLengthBytes + lengths.numValueBytes + 1;
    }

    // // If it's 0x00, just ignore as if it has no length and skip? Couldn't find this in ASN1 spec but in practice it seems to be done???
    // } else if(tag == 0x00) {
    //     return ptr + 1;


    // Takes a pointer to the start of a DER object and returns a pointer to the start of the next DER Object
    // If the Object is a sequence, it will go within the sequence
    // function getNextDERObjectPtr(uint256 ptr) public view returns (uint256 newPtr) {
    //     ObjectLengths memory lengths = DERObjectLengths(ptr);
    //     // Find whether it's a sequence (starts with 0x30)
    //     bytes1 tag;
    //     assembly {
    //         tag := mload(ptr)
    //     }
    //     // console.log('adding numLengthBytes numValueBytes', lengths.numLengthBytes, lengths.numValueBytes);
    //     // If it's a sequence or set, go inside for the next object
    //     if ((tag == 0x30) || (tag == 0x31) || (tag == 0x03)) {
    //         return ptr + lengths.numLengthBytes + 1;
    //     // If it's 0x00, just ignore as if it has no length and skip? Couldn't find this in ASN1 spec but in practice it seems to be done???
    //     } else if(tag == 0x00) {
    //         return ptr + 1;
    //     // Otherwise, skip it for the next object
    //     } else {
    //         return ptr + lengths.numLengthBytes + lengths.numValueBytes + 1;
    //     }
        
        
    // }

    // Takes a pointer to the start of a DER object and returns the bytes of the DER object
    function getDERObjectContents(bytes memory derBytes, uint256 ptr) public view returns (bytes memory value) {
        uint256 rootPtr = getFirstDERObjectPtr(derBytes);
        ObjectLengths memory lengths = DERObjectLengths(ptr);
        uint256 startPtr = ptr + 1 + lengths.numLengthBytes;
        uint256 endPtr = startPtr + lengths.numValueBytes;
        uint256 idxStart = startPtr - rootPtr;
        uint256 idxEnd = endPtr - rootPtr;
        return WTFUtils.sliceBytesMemory(derBytes, idxStart, idxEnd);
    }


    function getFirstDERObjectPtr(bytes memory derBytes) public pure returns (uint256 start) {
        assembly {
            // Start of pointer is 256 bits (0x20 bytes) encoding length of b. Skip those and start at the actual content:
            start := add(derBytes, 0x20)
        }
    }
    
    // gets the owner domain name and private keyfrom the SSL certificate in DER format
    function getCertOwner(bytes memory tbsCertificate) public view returns (OwnershipInfo memory subject) {
        bytes1 tag;
        uint256 firstPtr = getFirstDERObjectPtr(tbsCertificate);
        uint256 tmp = firstPtr;
        uint8 i;
        
        // Go nested level in to get to the subject field:
        tmp = goIn(firstPtr);
        // Skip the five fields in RFC spec to end up at subject field
        for(i=0; i<5; i++){
            tmp = skip(tmp);
        }
        // Save this location for use later -- we will neede to goIn() now and revert back to this pointer later to keep traversing at the outer level
        uint256 subject = tmp; 
        // go three levels deep, then skip to the second field to get the domain name //TODO : ensure this is where domain name is for all certificate types
        tmp = skip(goIn(goIn(goIn(tmp))));

        assembly {
            tag := mload(tmp)
        }
        require(tag == 0x13, "PrintableString not found in second subfield of the DER-format SSL certificate's subject field"); 

        bytes memory domainName = getDERObjectContents(tbsCertificate, tmp);
        
        tmp = goIn(1 + goIn(skip(goIn(skip(subject))))); //for some reason, there's an extra 00 in the certificate which seems to go against RFC spec but obviously must be right -- hence, skipping it with +1
        assembly {
            tag := mload(tmp)
        }
        require(tag == 0x02, "Integer not found at the predicted subfield for subject public key info"); 
        bytes memory pubkeyModulus = getDERObjectContents(tbsCertificate, tmp);
        require(pubkeyModulus.length == 257, "public key is of wrong length"); //why is this 257 with 0 in front, not 256??
        // return OwnershipInfo(domainName, pubkeyModulus);
        return OwnershipInfo(domainName, pubkeyModulus);
    }

    // Testing functions
    function DERObjectLengthTest(bytes memory derBytes) public view returns (uint256 derObjectlength) {
        uint256 ptr = getFirstDERObjectPtr(derBytes);
        ObjectLengths memory lengths = DERObjectLengths(ptr);
        return lengths.numValueBytes;
    }

    function DERObjectValueTest(bytes memory derBytes) public view returns (bytes memory value) {
        return getDERObjectContents(derBytes, getFirstDERObjectPtr(derBytes));
    }

    function nextDERObjectPtrTest(bytes memory derBytes) public view returns (bytes1 value) {
        // uint256 newPtr = getNextDERObjectPtr(
        //     getNextDERObjectPtr(
        //         getNextDERObjectPtr(
        //             getFirstDERObjectPtr(derBytes)
        //         )
        //     )
        // );
        // assembly {
        //     value := mload(newPtr)
        // }
    }

}