const Encryption = require('./lib/encryption');
const Decryption = require('./lib/decryption');
const { ConfigCredentials, Credentials } = require('./lib/credentials');
const fpeEncryptDecrypt = require('./lib/fpeEncryptDecrypt');
const structuredEncryptDecrypt = require('./lib/structuredEncryptDecrypt');
const { Configuration } = require('./lib/configuration');
const { UbiqFactory } = require('./lib/ubiqFactory');
const { CryptographyBuilder } = require('./lib/cryptographyBuilder');

module.exports = {
  async encrypt(params, data) {
    try {
      // Need the wait to make sure the encryption object is created.
      // Without it, we were getting enc.begin() not defined

      const enc = await (new CryptographyBuilder()).withCredentialsObject(params).buildEncryptionAsync()
      const result = Buffer.concat([enc.begin(), enc.update(data), enc.end()]);
      await enc.close();
      return result;
    } catch (ex) {
      throw new Error(ex.message)
    }
  },

  async decrypt(params, data) {
    try {
      const dec = await (new CryptographyBuilder()).withCredentialsObject(params).buildDecryptionAsync()
      const beginResult = dec.begin();
      const updateResult = await dec.update(data);
      const endResult = dec.end();
      const result = beginResult + updateResult + endResult;
      await dec.close();
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
  UbiqFactory,
  CryptographyBuilder
};
