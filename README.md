# Bridging Web2 URLs to Web3
The ability to do so enables briding all of an entity's domains and subdomains (e.g. google.com, mail.google.com) to the blockchain. Doing so, users can trust the party on the blockchain. This allows a plethora of institutional and other use cases, bringing Web2 data to the blockchain without oracles, increasing security and paying data providers instead of oracles.

### Mapping a domain name to blockchain address and vice versa
contracts/VerifySSLCertificate.sol is the smart contract to verify an SSL certificate. Upon verification it adds the wesbite to lookup tables: (blockchain address => domain name) and (domain name => blockchain address)
### Using it to signing IPFS content
scripts/sign-ipfs.js signs content with your blockchain address and uploads it to IPFS. This content is now verifiably signed by your domain name!
