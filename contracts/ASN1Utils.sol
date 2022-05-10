// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import 'hardhat/console.sol';

library ASN1Utils { //Should be library, not contract
    bytes1 constant oneBitFollowedByZeroes = 0x80;

    function firstBitIsOne(bytes1 b_) public view returns (bool oneOrZero) {
        return (b_ & 0x80) == 0x80;
    }

}