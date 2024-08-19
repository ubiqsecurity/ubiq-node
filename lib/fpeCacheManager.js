const { UrlHelper } = require('./urlHelper');

const delay = ms => new Promise(res => setTimeout(res, ms));
const verbose = false;

class FpeCacheManager {

  constructor(ubiqCredentials, ubiqWebServices, ubiqConfiguration) {
    this.cacheMap = new Map();
    this.queryMap = new Map();
    this.credentials = ubiqCredentials;
    this.ubiqWebServices = ubiqWebServices;
    this.ubiqConfiguration = ubiqConfiguration;
  }

  LoadAsync(ffsName, keyNumber) {
    return this.ubiqWebServices.GetFpeEncryptionKeyAsync(ffsName, keyNumber);
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

    if (this.queryMap.has(url)) {
      if (verbose) console.log(`FpeCacheManager this.queryMap ${FfsName} true`);
      while (retry_count-- > 0 && this.queryMap.has(url) && this.cacheMap.has(url) == false) {
        if (verbose) console.log(`${space} FpeCacheManager cacheMap ${FfsName} false`);
        await delay(this.ubiqConfiguration.nodejs_lock_sleep_before_retry);
        space = space + " "
      }
    } else {
      if (verbose) console.log(`FpeCacheManager this.queryMap ${FfsName} false`);
      this.queryMap.set(url, url)

      // if (!this.cacheMap.has(url)) {
      if (verbose) console.log(`Fetching URL: ${url}`);
      try {
        const fpe = await this.LoadAsync(FfsName, keyNumber);
        if (!fpe) {
          throw new Error(`Could not load Fpe for: ${FfsName}`);
        }
        if (verbose) console.log(`FpeCacheManager Adding: ${url} ${FfsName} `);
        this.cacheMap.set(url, fpe);
      } catch (err) {
        // Clear the query map if necessary
        if (this.queryMap.has(url) && this.cacheMap.has(url) == false) {
          if (verbose) console.log(`FpeCacheManager Removing ${FfsName} this.queryMap`);
          this.queryMap.delete(url)
        }
        throw err
      }
      // }
      if (verbose) console.log(`FpeCacheManager Returning: ${FfsName}   ${url} `);
    }
    return this.cacheMap.get(url);

  }
}
module.exports = {
  FpeCacheManager,
};
