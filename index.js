const Encryption = require('./lib/encryption');
const Decryption = require('./lib/decryption');
const { ConfigCredentials, Credentials } = require('./lib/credentials');
const fpeEncryptDecrypt = require('./lib/fpeEncryptDecrypt');
const structuredEncryptDecrypt = require('./lib/structuredEncryptDecrypt');
const { Configuration } = require('./lib/configuration');

module.exports = {
  async encrypt(params, data) {
    try {
      const enc = await new Encryption(params, 1);
      const result = Buffer.concat([enc.begin(), enc.update(data), enc.end()]);
      enc.close();
      return result;
    } catch (ex) {
      throw new Error(ex.message)
    }
  },

  async decrypt(params, data) {
    try {
      const dec = new Decryption(params);
      const beginResult = dec.begin();
      const updateResult = await dec.update(data);
      const endResult = dec.end();
      const result = beginResult + updateResult + endResult;
      dec.close();
      return result;
    } catch (ex) {
      throw new Error(ex.message)
    }
  },
  Encryption,
  Decryption,
  ConfigCredentials,
  Credentials,
  Configuration,
  fpeEncryptDecrypt,
  structuredEncryptDecrypt,
};
