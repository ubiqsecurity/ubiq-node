const { UrlHelper } = require('./urlHelper');
const { ubiqCache } = require('./ubiqCache');

const delay = ms => new Promise(res => setTimeout(res, ms));
const verbose = false;

class FpeCacheManager {

  // Cache is the URL, value is the web-response
  // private_encrypted_key and wrapped_data_key
  // Key_number


  constructor(ubiqCredentials, ubiqWebServices, ubiqConfiguration) {

    this.credentials = ubiqCredentials;
    this.ubiqWebServices = ubiqWebServices;
    this.ubiqConfiguration = ubiqConfiguration;

    let ttl = this.ubiqConfiguration.key_caching_ttl_seconds
    // If no key caching, set TTL to 0 to expire immediately but the remaining flow is unchanged
    if (!this.ubiqConfiguration.key_caching_structured) {
      ttl = 0;
    }

    this.cacheMap = new ubiqCache(ttl)
  }

  async LoadAsync(ffsName, keyNumber) {
    if (verbose) console.log(`FpeCacheManager LoadAsync: ${ffsName} ${keyNumber}`);
    return await this.ubiqWebServices.GetFpeEncryptionKeyAsync(ffsName, keyNumber);
  }

  async GetAsync(FfsName, keyNumber) {
    let space = ""
    let retry_count = this.ubiqConfiguration.nodejs_lock_max_retry_count;
    let url;
    if (keyNumber === null) {
      url = UrlHelper.GenerateFpeUrlEncrypt(FfsName, this.credentials);
    } else {
      url = UrlHelper.GenerateFpeUrlDecrypt(FfsName, keyNumber, this.credentials);
    }
    let fpe = null

    if (verbose) console.log(`FpeCacheManager::GetAsync : ${url}`);
    try {
      fpe = this.cacheMap.get(url)
      if (!fpe) {
        fpe = await this.LoadAsync(FfsName, keyNumber);
      } else {

      }
      if (!fpe) {
        throw new Error(`Could not load Fpe for: ${FfsName}`);
      }
      // Set to store and update the expiration
      this.cacheMap.set(url, fpe);
    } catch (err) {
      if (verbose) console.log(`Caught err: ${FfsName}   ${err} `);
      throw err
    }
    if (verbose) console.log(`FpeCacheManager Returning: ${FfsName}   ${url} `);
    // }
    return fpe //await this.cacheMap.get(url);

  }
}
module.exports = {
  FpeCacheManager,
};
