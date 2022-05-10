// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import 'hardhat/console.sol';
import "contracts/Base64.sol"; 

library WTFUtils { 
    // Represents a sandwich that *supposedly* starts at idxStart in a string and ends at idxEnd in a string. These values should *not* be assumed to be correct unless later validated.
    struct ProposedSandwichAt {
      uint idxStart;
      uint idxEnd;
      bytes sandwichValue;
    }


    event JWTVerification(bool result_);

    // https://ethereum.stackexchange.com/questions/8346/convert-address-to-string
    function bytesToAddress(bytes memory b_) private pure returns (address addr) {
        assembly {
            addr := mload(add(b_,20))
        } 
    }

    // Covnerts bytes32 to address
    function bytes32ToAddress(bytes32 b_) private pure returns (address addr) {
        assembly {
            addr := mload(add(b_,20)) //shouldn't it be 0x20 or is that equivalent
        } 
    }

    // Converts bytes32 to uint256
    function bytes32ToUInt256(bytes32 b_) public pure returns (uint256 u_) {
        assembly {
            u_ := mload(add(b_,20)) //shouldn't it be 0x20 or is that equivalent
        } 
    }

    // Converts the first 32 bytes of input_ to bytes32
    function bytesToFirst32BytesAsBytes32Type(bytes memory input_) public pure returns (bytes32 b_) {
        assembly {
            // there is probably an easier way to do this
            let unshifted := mload(add(input_,32))
            b_ := shr(96, unshifted)
        } 
    }

    // Converts the last 32 bytes of input_ to bytes32
    // (Used to take the last 32 bytes of the PKCS1-v1_5 padded value, which is the sha256 hash of the input)
    function bytesToLast32BytesAsBytes32Type(bytes memory input_) public pure returns (bytes32 b_) {
        assembly {
            // there is probably an easier way to do this
            let len := mload(input_)
            let end := add(input_, len)
            b_ := mload(end)
        }
    }
    
    // Converts an address to bytes 
    function addressToBytes(address a) public pure returns (bytes memory) {
        return abi.encodePacked(a);
    }
    
    // Converts bytes32 to bytes
    function bytes32ToBytes(bytes32 b_) public pure returns (bytes memory){
        return abi.encodePacked(b_);
    }
    // function addressToBytes32(address a) public pure returns (bytes32) {
    //   return abi.encodePacked(a);
    // }

    // Converts a string to bytes
    function stringToBytes(string memory s) public pure returns (bytes memory) {
        return abi.encodePacked(s);
    }

    // Compares equality of bytes
    function bytesAreEqual(bytes memory  a_, bytes memory b_) public pure returns (bool) {
        return (a_.length == b_.length) && (keccak256(a_) == keccak256(b_));
    }

    // // Can't figure out why this isn't working right now, so using less efficient version instead:
    // function sliceBytesMemory(bytes memory input_, uint256 start_, uint256 end_) public view returns (bytes memory r) {
    //   require(start_ < end_, "index start must be less than inded end");
    //   uint256 sliceLength = end_ - start_;
    //   bytes memory r = new bytes(sliceLength);
    //   console.log('HERE');
    //   console.logBytes(r);
    //   assembly {
    //     let offset := add(start_, 0x20)
    //     if iszero(staticcall(not(0), add(input_, offset), sliceLength, add(r, 0x20), sliceLength)) {
    //         revert(0, 0)
    //     }
    //   }
    //  
    //
    // }

    // Returns input_[start_ : end_] (slicing operation)
    // This could be more efficient by not copying the whole thing, rather just the parts that matter
    function sliceBytesMemory(bytes memory input_, uint256 start_, uint256 end_) public view returns (bytes memory r) {
        uint256 len_ = input_.length;
        r = new bytes(len_);
        
        assembly {
            // Use identity to copy data
            if iszero(staticcall(not(0), 0x04, add(input_, 0x20), len_, add(r, 0x20), len_)) {
                revert(0, 0)
            }
        }
        return destructivelySliceBytesMemory(r, start_, end_);
    }
    
    function destructivelySliceBytesMemory(bytes memory m, uint256 start, uint256 end) public pure returns (bytes memory r) {
        require(start < end, "index start must be less than inded end");
        assembly {
            let offset := add(start, 0x20) //first 0x20 bytes of bytes type is length (no. of bytes)
            r := add(m, start)
            mstore(r, sub(end, start))
        }
    }

    // Performs modular exponentiation; returns base ** exponent (mod modulus)
    // BIG thanks to dankrad for this function: https://github.com/dankrad/rsa-bounty/blob/master/contract/rsa_bounty.sol
    // Expmod for bignum operands (encoded as bytes, only base and modulus)
    function modExp(bytes memory base, uint exponent, bytes memory modulus) public view returns (bytes memory o) {
        assembly {
            // Get free memory pointer
            let p := mload(0x40)

            // Get base length in bytes
            let bl := mload(base)
            // Get modulus length in bytes
            let ml := mload(modulus)

            // Store parameters for the Expmod (0x05) precompile
            mstore(p, bl)               // Length of Base
            mstore(add(p, 0x20), 0x20)  // Length of Exponent
            mstore(add(p, 0x40), ml)    // Length of Modulus
            // Use Identity (0x04) precompile to memcpy the base
            if iszero(staticcall(10000, 0x04, add(base, 0x20), bl, add(p, 0x60), bl)) {
                revert(0, 0)
            }
            mstore(add(p, add(0x60, bl)), exponent) // Exponent
            // Use Identity (0x04) precompile to memcpy the modulus
            if iszero(staticcall(10000, 0x04, add(modulus, 0x20), ml, add(add(p, 0x80), bl), ml)) {
                revert(0, 0)
            }
            
            // Call 0x05 (EXPMOD) precompile
            if iszero(staticcall(not(0), 0x05, p, add(add(0x80, bl), ml), add(p, 0x20), ml)) {
                revert(0, 0)
            }

            // Update free memory pointer
            mstore(0x40, add(add(p, ml), 0x20))

            // Store correct bytelength at p. This means that with the output
            // of the Expmod precompile (which is stored as p + 0x20)
            // there is now a bytes array at location p
            mstore(p, ml)

            // Return p
            o := p
        }
    }
    
    // returns whether JWT is signed by public key e_, n_, and emits an event with verification result
    function verifyRSASignature(uint256 e_, bytes memory n_, bytes memory signature_, bytes memory message_) public returns (bool) {
        bytes32 hashed = hashFromSignature(e_, n_, signature_);
        bool verified = hashed == sha256(message_);
        emit JWTVerification(verified);
        return verified;
    }

    // Get the hash of the JWT from the signature
    function hashFromSignature(uint256 e_, bytes memory n_, bytes memory signature_) public view returns (bytes32) {
        bytes memory encrypted = modExp(signature_, e_, n_);
        bytes32 unpadded = bytesToLast32BytesAsBytes32Type(encrypted);
        return unpadded;
    }

    function verifySandwich(bytes memory string_, ProposedSandwichAt calldata proposedSandwich_, bytes memory correctBottomBread_, bytes memory correctTopBread_) public view returns (bool validString) {
      require(bytesAreEqual(
                            sliceBytesMemory(proposedSandwich_.sandwichValue, 0, correctBottomBread_.length),
                            correctBottomBread_
              ),
              "Failed to find correct bottom bread in sandwich"
      );

      require(bytesAreEqual(
                            sliceBytesMemory(proposedSandwich_.sandwichValue, proposedSandwich_.sandwichValue.length-correctTopBread_.length, proposedSandwich_.sandwichValue.length),
                            correctTopBread_
              ),
              "Failed to find correct top bread in sandwich"
      );

      require(bytesAreEqual(
                            sliceBytesMemory(string_, proposedSandwich_.idxStart, proposedSandwich_.idxEnd),
                            proposedSandwich_.sandwichValue
              ),
            "Proposed sandwich not found"
      );
      return true;
  }

  // Used for aud claim, where bread is not necessary. substringAt isn't really a sandwich this time, but a ProposedSandwichAt struct works well for it as it can encode string value, idxStart, and idxEnd
  function verifySubstring(bytes memory str, ProposedSandwichAt calldata substringAt, bytes memory correctSubstring) public view returns (bool validString) {
      require(bytesAreEqual(
                            substringAt.sandwichValue,
                            correctSubstring
              ),
            "Substring is incorrect"
      );
      require(bytesAreEqual(
                            sliceBytesMemory(str, substringAt.idxStart, substringAt.idxEnd),
                            substringAt.sandwichValue
              ),
            "Substring not found"
      );
      return true;
  }

    // Decodes base64-encoded bytes
    // Base64 Library modified from https://github.com/Brechtpd/base64/blob/main/base64.sol
    function decodeFromBytes(bytes memory input) public pure returns (bytes memory output) {
        return Base64.decodeFromBytes(input);
    }
    
    // from willitscale: https://github.com/willitscale/solidity-util/blob/master/lib/Integers.sol
    // /**
    // * Parse Int
    // * 
    // * Converts an ASCII string value into an uint as long as the string 
    // * its self is a valid unsigned integer
    // * 
    // * @param _value The ASCII string to be converted to an unsigned integer
    // * @return _ret The unsigned value of the ASCII string
    // */
    // function parseInt(string memory _value) public view returns (uint256 _ret) {
    //     bytes memory _bytesValue = bytes(_value);
    //     uint256 j = 1;
    //     uint256 i = _bytesValue.length-1;
    //     while(i >= 0) {
    //         assert(uint8(_bytesValue[i]) >= 48 && uint8(_bytesValue[i]) <= 57);
    //         _ret += (uint8(_bytesValue[i]) - 48)*j;
    //         j*=10;
    //         if(i > 0){i--;}else{break;}
    //     }
    // }

    
    // modified from willitscale: https://github.com/willitscale/solidity-util/blob/master/lib/Integers.sol
    /**
    * Parse Int
    * Bytes instead of string parseInt override
    * @param _bytesValue The bytes to be converted to an unsigned integer. *this is a bytes representation of a string*
    * @return _ret The unsigned value of the ASCII string
    */
    function parseInt(bytes memory _bytesValue) public pure returns (uint256 _ret) {
        uint256 j = 1;
        uint256 i = _bytesValue.length-1;
        while(i >= 0) {
            assert(uint8(_bytesValue[i]) >= 48 && uint8(_bytesValue[i]) <= 57);
            _ret += (uint8(_bytesValue[i]) - 48)*j;
            j*=10;
            if(i > 0){i--;}else{break;}
        }
    }

}