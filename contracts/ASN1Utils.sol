// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import 'hardhat/console.sol';
import { WTFUtils } from "contracts/WTFUtils.sol";

library ASN1Utils { 
    struct ObjectLengths {
        uint256 numLengthBytes; // number of bytes encoding length of the value
        uint256 numValueBytes; // number of bytes in the value

    }

    function firstBitIsOne(bytes1 b_) public pure returns (bool oneOrZero) {
        return (b_ & 0x80) == 0x80;
    }

    // DER Objects are encoded as (tag, length, value). The problem is that length can sometimes be > 256 bytes, so can't always be encoded in one byte
    // In case it's over 127 bytes, the length-encoding byte will be set to 1xxxxxxx, where xxxxxxx is a binary number representing the number of
    // additional bytes in which the length is encoded

    // The input to DERLength is therefore not the length byte but a pointer to it, in case the next bytes need to be read:
    function DERObjectLengths(bytes32 ptr) public view returns (ObjectLengths memory) {
        // bytes1 tagByte;
        bytes1 lengthByte;
        uint256 ObjectLength;
        assembly {
            // tagByte := mload(ptr)
            lengthByte := mload(add(ptr, 1))
        }
        // If the first bit is 1, the rest encodes the number of bytes
        if(firstBitIsOne(lengthByte)){
            uint256 result = 0;
            uint256 tmpPtr = uint256(ptr) + 1; 
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

            return ObjectLengths(numBytes, result);
        } else {
            return ObjectLengths(1, uint256(uint8(lengthByte)));
        }

    }

    // Takes a pointer to the start of a DER object and returns a pointer to the start of the next DER Object
    // If the Object is a sequence, it will go within the sequence
    function getNextDERObjectPtr(bytes32 ptr) public view returns (bytes32 newPtr) {
        uint8 tag;
        assembly {
            tag := mload(ptr)
        }
        if (tag == 0x30) {
            console.log('is sequence');
        } else {
            console.log('is not sequence');
        }
        
    }

    // Takes a pointer to the start of a DER object and returns the bytes of the DER object
    function getDERObjectContents(bytes memory derBytes, bytes32 ptr) public view returns (bytes memory value) {
        uint256 rootPtr = uint256( getFirstDERObjectPtr(derBytes) );
        ObjectLengths memory lengths = DERObjectLengths(ptr);
        uint256 startPtr = uint256(ptr) + lengths.numLengthBytes;
        uint256 endPtr = startPtr + lengths.numValueBytes;
        uint256 idxStart = startPtr - rootPtr;
        uint256 idxEnd = endPtr - rootPtr;
        return WTFUtils.sliceBytesMemory(derBytes, idxStart, idxEnd);
    }


    function getFirstDERObjectPtr(bytes memory derBytes) public pure returns (bytes32 start) {
        assembly {
            // Start of pointer is 256 bits (0x20 bytes) encoding length of b. Skip those and start at the actual content:
            start := add(derBytes, 0x20)
        }
    }

    // Testing functions
    function DERObjectLengthTest(bytes memory derBytes) public view returns (uint256 derObjectlength) {
        bytes32 ptr = getFirstDERObjectPtr(derBytes);
        ObjectLengths memory lengths = DERObjectLengths(ptr);
        return lengths.numValueBytes;
    }

    function abcde(bytes memory derBytes) public view returns (uint256 ) {}

}