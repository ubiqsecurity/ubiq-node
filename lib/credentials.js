const fs = require('fs');
const forge = require('node-forge');
const ConfigParser = require('configparser');
const { generateKeyPair, generateCsr } = require('./rsaKeys');
const { UbiqWebServices } = require('./ubiqWebServices');
const crypto = require('crypto');

class Credentials {
  constructor(access_key_id, secret_signing_key, secret_crypto_access_key, host, idp_username, idp_password) {
    this.initialized = false
    this.access_key_id = ((access_key_id) || process.env.UBIQ_ACCESS_KEY_ID || "").trim();
    this.secret_signing_key = ((secret_signing_key) || process.env.UBIQ_SECRET_SIGNING_KEY || "").trim();
    this.secret_crypto_access_key = ((secret_crypto_access_key) || process.env.UBIQ_SECRET_CRYPTO_ACCESS_KEY || "").trim();
    this.host = ((host) || process.env.UBIQ_SERVER || 'https://api.ubiqsecurity.com').trim()
    if (this.host.indexOf('http://') !== 0 && this.host.indexOf('https://') !== 0) {
      this.host = `https://${this.host}`;
    }

    this.idp_username = ((idp_username) || process.env.UBIQ_IDP_USERNAME || "").trim();
    this.idp_password = ((idp_password) || process.env.UBIQ_IDP_PASSWORD || "").trim();

    this.cert_expires = new Date(new Date() - 60000)

    if ((this.secret_crypto_access_key) || ((this.idp_username) && (this.idp_password))) {
      // NOP
    }
    else {
      throw (new Error("Credentials data is incomplete"))
    }
  }

  isIdp() {
    let ret = (this.idp_username.length > 0)

    // If this is IDP mode, make sure the init has been called and everything had been setup
    if (ret && !this.initialized) {
      throw (new Error("Credentials.init(configuration) has not been called or failed but is required when using IDP authentication"))
    }

    return ret
  }

  getEncryptedPrivateKey() {
    return (this.encryptedPrivateKey)
  }

  // Check to see if the access token needs to be renewed or the cert needs to be 
  // renewed and if so, refresh both and get the signed cert
  async renewIdpCertAsync() {
    if (this.isIdp()) {
      if (this.cert_expires < new Date()) {
        await this.getIdpTokenAndCertAsync()
      }
    }
  }

  async getIdpTokenAndCertAsync() {
    this.token = await this.ubiqWebServices.GetOAuthToken();
    this.sso = await this.ubiqWebServices.GetSso(this.token.access_token, this.csr);
    this.idp_cert_base64 = Buffer.from(this.sso.api_cert).toString('base64');
    // Parse cert for expiration date
    const x509 = new crypto.X509Certificate(this.sso.api_cert)
    // Set cert expiration 1 minute before actual to avoid edge case
    this.cert_expires = new Date(new Date(x509.validTo) - 60000);

    // Private key is still the same as before
  }

  async initAsync(ubiqConfiguration) {
    if (this.idp_username) {
      this.ubiqConfiguration = ubiqConfiguration
      // Webservice needed to fetch the token and sso.  These are sync calls so can use
      // the same webservice
      this.ubiqWebServices = new UbiqWebServices(this, this.ubiqConfiguration)

      this.secret_crypto_access_key = await forge.util.encode64(forge.random.getBytesSync(33));

      const { publicKey: apiPublicKey_pem, privateKey: apiPrivateKey_pem } = await generateKeyPair()
      this.csr = await generateCsr(apiPublicKey_pem, apiPrivateKey_pem)

      await this.getIdpTokenAndCertAsync()

      this.access_key_id = this.sso.public_value
      this.secret_signing_key = this.sso.signing_value

      let rsaPrivateKey = await forge.pki.privateKeyToAsn1(forge.pki.privateKeyFromPem(apiPrivateKey_pem));
      let privateKeyInfo = await forge.pki.wrapRsaPrivateKey(rsaPrivateKey);

      let encryptedPrivateKeyInfo = await forge.pki.encryptPrivateKeyInfo(
        privateKeyInfo,
        this.secret_crypto_access_key,
        {
          algorithm: 'aes256',
        }
      );

      this.encryptedPrivateKey = await forge.pki.encryptedPrivateKeyToPem(
        encryptedPrivateKeyInfo
      );
      // console.log("secret_crypto_access_key", this.secret_crypto_access_key, "\nencryptedPrivateKey", this.encryptedPrivateKey)

    }
    this.initialized = true
  }

}

class ConfigCredentials {
  constructor(config_file, profile) {
    // If config_file is undefined or empty string,
    // try to use either standard credentials else credentials.json
    if (!config_file) {
      config_file = `${require('os').homedir()}/.ubiq/credentials`;
      if (!fs.existsSync(config_file)) {
        config_file = `${require('os').homedir()}/.ubiq/credentials.json`;
      }
    }
    return (this.load_credentials(config_file, profile));
  }

  process_json_credentials(credentials_data, profile) {
    let def = {};
    let prof = {};

    if ((credentials_data.default)) {
      def = credentials_data.default;
    }
    if (profile) {
      if (credentials_data[profile]) {
        prof = credentials_data[profile];
      }
    }

    const papi = (prof.ACCESS_KEY_ID) ? prof.ACCESS_KEY_ID : def.ACCESS_KEY_ID;
    const sapi = (prof.SECRET_SIGNING_KEY) ? prof.SECRET_SIGNING_KEY : def.SECRET_SIGNING_KEY;
    const srsa = (prof.SECRET_CRYPTO_ACCESS_KEY) ? prof.SECRET_CRYPTO_ACCESS_KEY : def.SECRET_CRYPTO_ACCESS_KEY;
    const server = (prof.SERVER) ? prof.SERVER : def.SERVER;
    const idp_username = (prof.IDP_USERNAME) ? prof.IDP_USERNAME : def.IDP_USERNAME;
    const idp_password = (prof.IDP_PASSWORD) ? prof.IDP_PASSWORD : def.IDP_PASSWORD;

    return new Credentials(papi, sapi, srsa, server, idp_username, idp_password);
  }

  load_credentials_file(credentials_file, profile) {
    const config = new ConfigParser();
    config.read(credentials_file);
    const papi = ((config.get(profile, 'ACCESS_KEY_ID')) ? config.get(profile, 'ACCESS_KEY_ID') : config.get('default', 'ACCESS_KEY_ID') || '').trim();
    const sapi = ((config.get(profile, 'SECRET_SIGNING_KEY')) ? config.get(profile, 'SECRET_SIGNING_KEY') : config.get('default', 'SECRET_SIGNING_KEY') || '').trim();
    const srsa = ((config.get(profile, 'SECRET_CRYPTO_ACCESS_KEY')) ? config.get(profile, 'SECRET_CRYPTO_ACCESS_KEY') : config.get('default', 'SECRET_CRYPTO_ACCESS_KEY') || '').trim();
    const server = ((config.get(profile, 'SERVER')) ? config.get(profile, 'SERVER') : config.get('default', 'SERVER') || '');
    const idp_username = ((config.get(profile, 'IDP_USERNAME')) ? config.get(profile, 'IDP_USERNAME') : config.get('default', 'IDP_USERNAME') || '');
    const idp_password = ((config.get(profile, 'IDP_PASSWORD')) ? config.get(profile, 'IDP_PASSWORD') : config.get('default', 'IDP_PASSWORD') || '');

    return new Credentials(papi, sapi, srsa, server, idp_username, idp_password);
  }

  load_credentials(credentials_file, profile) {
    let credentials_data = fs.readFileSync(credentials_file);

    let ret;
    try {
      credentials_data = JSON.parse(credentials_data);
      ret = this.process_json_credentials(credentials_data, profile);
    } catch (e) {
      // config parser library requires file name, not data
      ret = this.load_credentials_file(credentials_file, profile);
    }
    return ret;
  }
}

module.exports = { ConfigCredentials, Credentials };
