const { ConfigCredentials, Credentials } = require('./credentials');
const { Configuration } = require('./configuration');
const { UbiqFactory } = require('./ubiqFactory');
const { StructuredEncryptDecrypt } = require('./structuredEncryptDecrypt');
const Encryption = require('./encryption');
const Decryption = require('./decryption');


class CryptographyBuilder {


  constructor() {
    this._configuration = null;
    this._credentials = null;
    return this;
  }

  async buildStructuredAsync() {
    if (this._credentials == null) {
      this._credentials = UbiqFactory.defaultCredentials();
    }
    if (this._configuration == null) {
      this._configuration = UbiqFactory.defaultConfiguration();
    }
    await this._credentials.initAsync(this._configuration);

    return new StructuredEncryptDecrypt({
      ubiqCredentials: this._credentials,
      ubiqConfiguration: this._configuration
    });
  }

  async buildEncryptionAsync() {
    if (this._credentials == null) {
      this._credentials = UbiqFactory.defaultCredentials();
    }
    if (this._configuration == null) {
      this._configuration = UbiqFactory.defaultConfiguration();
    }
    await this._credentials.initAsync(this._configuration);
    const enc = new Encryption(this._credentials, 1, this._configuration);
    await enc.initAsync();
    return enc;
  }

  async buildDecryptionAsync() {
    if (this._credentials == null) {
      this._credentials = UbiqFactory.defaultCredentials();
    }
    if (this._configuration == null) {
      this._configuration = UbiqFactory.defaultConfiguration();
    }
    await this._credentials.initAsync(this._configuration);

    return new Decryption(this._credentials, this._configuration);
  }

  withCredentialsObject(ubiqCredentials) {
    this._credentials = ubiqCredentials;
    return this;
  }

  withCredentialsDefault() {
    this._credentials = UbiqFactory.defaultCredentials();
    return this;
  }

  withCredentialsFile(pathname, profile) {
    this._credentials = UbiqFactory.readCredentialsFromFile(pathname, profile);
    return this;
  }

  withCredentialsIdp(idp_username, idp_password, host) {
    this._credentials = UbiqFactory.createCredentialsWithIdp(idp_username, idp_password, host);
    return this;
  }

  withCredentialsIdp(accessKeyId, secretSigningKey, secretCryptoAccessKey, host) {
    this._credentials = UbiqFactory.createCredentials(accessKeyId, secretSigningKey, secretCryptoAccessKey, host);
    return this;
  }

  withConfigurationObject(ubiqConfiguration) {
    this._configuration = ubiqConfiguration;
    return this;
  }

  withConfigurationDefault() {
    this._configuration = UbiqFactory.defaultConfiguration();
    return this;
  }

  withConfiguration(eventReporting, nodeJsSpecific, keyCaching, idp) {
    this._configuration = UbiqFactory.createConfiguration(eventReporting, nodeJsSpecific, keyCaching, idp);
    return this;
  }

}

module.exports = { CryptographyBuilder };
