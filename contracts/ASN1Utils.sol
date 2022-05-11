// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import 'hardhat/console.sol';

library ASN1Utils { 
    struct Position {
        uint256 start; // index of first byte
        uint256 end; // index of last byte + 1 (like slice notation)
    }

    function firstBitIsOne(bytes1 b_) public pure returns (bool oneOrZero) {
        return (b_ & 0x80) == 0x80;
    }

    // DER fields are encoded as (tag, length, value). The problem is that length can sometimes be > 256 bytes, so can't always be encoded in one byte
    // In case it's over 127 bytes, the length-encoding byte will be set to 1xxxxxxx, where xxxxxxx is a binary number representing the number of
    // additional bytes in which the length is encoded

    // The input to DERLength is therefore not the length byte but a pointer to it, in case the next bytes need to be read:
    function DERFieldPosition(bytes32 ptr) public view returns (Position memory) {
        // bytes1 tagByte;
        bytes1 lengthByte;
        uint256 fieldLength;
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
            uint256 start = uint(ptr) + 2 + numBytes; // Where field starts (beginning ptr + 1 lengthByte + number of additional bytes to encode length + 1 byte to reach next byte)
            uint256 end = start + result;
            return Position(start, end);
        } else {
            uint256 result = uint256(uint8(lengthByte));
            uint256 start = uint(ptr) + 2; // Where field starts (beginning ptr + 1 lengthByte + 1 to reach next byte)
            uint end = start + result;
            return Position(start, end);
        }

    }

    // Takes a pointer to the start of a DER field and returns a pointer to the start of the next DER field
    function skipDERField(bytes32 ptr) public pure returns (bytes32 newPtr) {
        
    }

    function getFirstDERFieldPtr(bytes memory derBytes) public pure returns (bytes32 start) {
        assembly {
            // Start of pointer is 256 bits (0x20 bytes) encoding length of b. Skip those and start at the actual content:
            start := add(derBytes, 0x20)
        }
    }

    function DERFieldLengthTest(bytes memory derBytes) public view returns (uint256 derFieldlength) {
        bytes32 ptr = getFirstDERFieldPtr(derBytes);
        Position memory pos = DERFieldPosition(ptr);
        return pos.end - pos.start;
    }

}