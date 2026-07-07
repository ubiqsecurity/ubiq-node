const { UrlHelper } = require('./urlHelper');
const { ubiqCache } = require('./ubiqCache');
const forge = require('node-forge');

const delay = ms => new Promise(res => setTimeout(res, ms));
const verbose = false;

class StructuredKeyCache {

  // Cache is the URL, value is the web-response
  // private_encrypted_key and wrapped_data_key
  // Key_number
  // For configuration where the key is cached un-encrypted, we have added it here too
  // decrypted_data_key which is the raw decrypted key but stored as base64 string.  Will be NULL or undefined
  // if the key is cached encrypted



  constructor(ubiqCredentials, ubiqWebServices, ubiqConfiguration) {

    this.ubiqCredentials = ubiqCredentials;
    this.ubiqWebServices = ubiqWebServices;
    this.ubiqConfiguration = ubiqConfiguration;

    let ttl = this.ubiqConfiguration.key_caching_ttl_seconds
    // If no key caching, set TTL to 0 to expire immediately but the remaining flow is unchanged
    if (!this.ubiqConfiguration.key_caching_structured) {
      ttl = 0;
    }

    this.cacheMap = new ubiqCache(ttl)
  }

  async LoadAsync(datasetName, keyNumber) {
    // Payload is 
    // {
    //   "encrypted_private_key": "-\r\n",
    //   "key_number": "3",
    //   "wrapped_data_key": "kI="
    // }
    if (verbose) console.log(`StructuredKeyCache LoadAsync: ${datasetName} ${keyNumber}`);
    let fpe = await this.ubiqWebServices.GetFpeEncryptionKeyAsync(datasetName, keyNumber);
    return fpe
  }

  async DecryptWrappedDataKeyAsync(decryptedPrivateKey, wrappedDataKey) {
    const wdk = forge.util.decode64(wrappedDataKey);
    let raw = null
    try {
      const decrypted = decryptedPrivateKey.decrypt(wdk, 'RSA-OAEP');
      raw = new Uint8Array(Buffer.from(decrypted, 'binary'));
      if (verbose) console.log(`StructuredKeyCache::GetAsync raw(${raw})`);

    } catch (err) {
      throw new Error('Problem decrypting ENCRYPTED private key' + err);
    }
    return raw
  }

  async DecryptEncryptedPrivateKeyAsync(encryptedPrivateKey) {
    if (this.ubiqCredentials.isIdp()) {
      // Only getting private key here, so cert is still OK
      encryptedPrivateKey = this.ubiqCredentials.getEncryptedPrivateKey()
    }
    const privateKey = forge.pki.decryptRsaPrivateKey(encryptedPrivateKey, this.ubiqCredentials.secret_crypto_access_key);
    return privateKey
  }

  // DecryptedPrivateKey is only needed if we are caching decrypted keys
  async AddToCache(datasetName, keyNumber, structured_key, decryptedPrivateKey) {
    // let verbose = true
    const csu = "StructuredKeyCache::AddToCache"
    let url;

    if (verbose) { console.log(`${csu}: datasetName: ${datasetName} keyNumber: ${keyNumber} structured_key: `, structured_key) }

    if (keyNumber == null) {
      url = UrlHelper.GenerateFpeUrlEncrypt(datasetName, this.ubiqCredentials);
    } else {
      url = UrlHelper.GenerateFpeUrlDecrypt(datasetName, keyNumber, this.ubiqCredentials);
    }
    if (verbose) { console.log(`${csu}: url: ${url}`) }
    let fpe = this.cacheMap.get(url)
    // Does record already exist?
    if (!fpe) {
      if (verbose) { console.log(`${csu}: fpe: null`) }
      fpe = structured_key;
      if (this.ubiqConfiguration.key_caching_structured) {
        // Is encryption key supposed to be encrypted ? save cache then set necessary value
        if (this.ubiqConfiguration.key_caching_encrypt) {
          if (verbose) { console.log(`${csu}: key_caching_encrypt: true`) }
          this.cacheMap.set(url, fpe);
        } else {
          // Set decrypted key and then save into cache
          fpe.decrypted_data_key = await this.DecryptWrappedDataKeyAsync(decryptedPrivateKey, fpe.wrapped_data_key)
          this.cacheMap.set(url, fpe);
          if (verbose) { console.log(`${csu}: fpe: ${fpe}`) }
        }
        // Is Encrypt?, If so, add key for Decrypt too
        if (keyNumber == null) {
          const decryptUrl = UrlHelper.GenerateFpeUrlDecrypt(datasetName, fpe.key_number, this.ubiqCredentials);
          if (verbose) { console.log(`${csu}: decryptUrl: ${decryptUrl}`) }
          if (verbose) { console.log(`${csu}: fpe: ${fpe}`) }
          this.cacheMap.set(decryptUrl, fpe);
        }
      }
    }
    return fpe
  }

  async GetAsync(datasetName, keyNumber) {
    if (verbose) console.log(`StructuredKeyCache GetAsync: datasetName(${datasetName}) keyNumber(${keyNumber})`);
    let space = ""
    let retry_count = this.ubiqConfiguration.nodejs_lock_max_retry_count;
    let url;
    let fpe = null
    let decryptedPrivateKey = null;
    if (keyNumber == null) {
      url = UrlHelper.GenerateFpeUrlEncrypt(datasetName, this.ubiqCredentials);
    } else {
      url = UrlHelper.GenerateFpeUrlDecrypt(datasetName, keyNumber, this.ubiqCredentials);
    }

    if (verbose) console.log(`StructuredKeyCache:: GetAsync: url(${url})`);
    try {
      let keyBase64
      fpe = this.cacheMap.get(url)
      if (!fpe) {
        fpe = await this.LoadAsync(datasetName, keyNumber);
        if (verbose) console.log(`StructuredKeyCache::LoadAsync return : fpe(${fpe})`);
        decryptedPrivateKey = await this.DecryptEncryptedPrivateKeyAsync(fpe.encrypted_private_key)
        fpe = await this.AddToCache(datasetName, keyNumber, fpe, decryptedPrivateKey)
      } else {
        // nop
        if (verbose) console.log(`StructuredKeyCache::LoadAsync fpe found: fpe(${fpe})`);
      }
      if (!fpe) {
        throw new Error(`Could not load Fpe for: ${datasetName} `);
      }
      // If we need to decrypt the key
      if (verbose) console.log(`StructuredKeyCache:: GetAsync: fpe(${fpe})`);

      // fpe key has not been decrypted, so decrypt the private key and decrypt the wrapped key
      if (fpe.decrypted_data_key == null) {

        if (!decryptedPrivateKey) { decryptedPrivateKey = await this.DecryptEncryptedPrivateKeyAsync(fpe.encrypted_private_key) }
        fpe.decrypted_data_key = await this.DecryptWrappedDataKeyAsync(decryptedPrivateKey, fpe.wrapped_data_key)
      }
    } catch (err) {
      if (verbose) console.log(`catch StructuredKeyCache GetAsync: ubiqCredentials empty ? (${!this.ubiqCredentials})`);
      if (verbose) console.log(`catch StructuredKeyCache GetAsync: datasetName(${datasetName}) keyNumber(${keyNumber})`);

      console.error(err.stack)
      if (verbose) console.log(`StructuredKeyCache::GetAsync Caught err: ${datasetName}   ${err} `);
      throw err
    }
    if (verbose) console.log(`StructuredKeyCache Returning: ${datasetName}   ${url} `);
    // }
    return fpe

  }
}
module.exports = {
  StructuredKeyCache,
};
