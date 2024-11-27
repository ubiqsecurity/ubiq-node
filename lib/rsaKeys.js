const forge = require('node-forge');
const crypto = require('crypto');


async function generateKeyPair() {
  const { publicKey, privateKey } = await crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096, // Standard key size
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    }
  });
  return { publicKey, privateKey };
}

async function generateCsr(papi, publicKey, privateKey) {

  const csrDetails = [
    { name: 'commonName', value: papi },
    { name: 'countryName', value: 'US' },
    { name: 'stateOrProvinceName', value: 'California' },
    { name: 'localityName', value: 'San Diego' },
    { name: 'organizationName', value: 'Ubiq Security, Inc.' },
    { shortName: 'OU', value: 'Ubiq Platform' }
  ];

  // 3. Create CSR
  csr = await forge.pki.createCertificationRequest();
  csr.publicKey = forge.pki.publicKeyFromPem(publicKey)
  csr.setSubject = csrDetails
  await csr.sign(forge.pki.privateKeyFromPem(privateKey))
  var verified = csr.verify()

  // 4. Convert CSR to PEM format
  var pem = await forge.pki.certificationRequestToPem(csr);
  return pem
}


module.exports = { generateKeyPair, generateCsr };
