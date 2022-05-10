const { expect } = require("chai");
const { ethers } = require("hardhat");

describe('ASN.1 parsing', function () {
  it('getTagAndLength()', async function () {
    const a1u = await (await ethers.getContractFactory('ASN1Utils')).deploy()
    console.log(a1u)
    expect(await a1u.firstBitIsOne(0b10000000)).to.equal(true)
    expect(await a1u.firstBitIsOne(0b00000000)).to.equal(false)
    expect(await a1u.firstBitIsOne(0b11000000)).to.equal(true)
    expect(await a1u.firstBitIsOne(0b01100000)).to.equal(false)
    expect(await a1u.firstBitIsOne(0b0000001)).to.equal(false)
  });
});
