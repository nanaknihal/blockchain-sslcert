const { ethers } = require('ethers')
const { create } = require('ipfs-http-client')

const client = create('https://ipfs.infura.io:5001/api/v0');

// This appends a suffix constisting of address and signature to as a HTML comment the end of the content
// Note this suffix will be of fixed length so very easy to find at end of file 
// 4 bytes <!--
// 64 bytes signature 
// 20 bytes address key 
// 3 bytes --> 
// It's the last 91 bytes of the file

// Takes original content to be uploaded and adds the suffix:
const formatContent = (signer, original) => {
    const formatted = `${original}<!--${signer.getAddress()}${signer.signMessage('Signature for IPFS of ' + original)}-->`
    return Buffer.from(formatted)
}

// Takes ethers signer object and message string, signs & uploads to IPFS, and returns the IPFS path (CID)
exports.uploadIPFS = async (signer, original) => {
    let signed = formatContent(signer, original)
    result = await ipfsClient.add(file)
    return result.path
}