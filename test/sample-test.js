const { expect } = require("chai");
const { ethers } = require("hardhat");


describe('ASN.1 parsing', function () {
  before(async function(){
    this.a1u = await (await ethers.getContractFactory('ASN1Utils')).deploy()
  });

  it('getTagAndLength()', async function () {
    expect(await this.a1u.firstBitIsOne(0b10000000)).to.equal(true)
    expect(await this.a1u.firstBitIsOne(0b00000000)).to.equal(false)
    expect(await this.a1u.firstBitIsOne(0b11000000)).to.equal(true)
    expect(await this.a1u.firstBitIsOne(0b01100000)).to.equal(false)
    expect(await this.a1u.firstBitIsOne(0b0000001)).to.equal(false)
  });

  it('indirectly test DERFieldLength (it is hard to test as it requries memory pointer as the argument)', async function () {
    expect(await this.a1u.DERFieldLengthTest(ethers.utils.arrayify('0x3082051A'))).to.equal(1306)
    expect(await this.a1u.DERFieldLengthTest(ethers.utils.arrayify('0x3002051A'))).to.equal(2)
  });
});
