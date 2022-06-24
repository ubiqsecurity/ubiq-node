const Encryption = require('./lib/encryption');
const Decryption = require('./lib/decryption');
const { ConfigCredentials, Credentials } = require('./lib/credentials');
const fpeEncryptDecrypt = require('./lib/fpeEncryptDecrypt');

module.exports = {
  async encrypt(params, data) {
    const enc = await new Encryption(params, 1);
    const result = Buffer.concat([enc.begin(), enc.update(data), enc.end()]);
    enc.close();
    return result;
  },

  async decrypt(params, data) {
    const dec = new Decryption(params);
    const beginResult = dec.begin();
    const updateResult = await dec.update(data);
    const endResult = dec.end();
    const result = beginResult + updateResult + endResult;
    dec.close();
    return result;
  },
  Encryption,
  Decryption,
  ConfigCredentials,
  Credentials,
  fpeEncryptDecrypt,
};
