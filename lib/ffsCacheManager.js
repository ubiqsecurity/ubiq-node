const { UrlHelper } = require('./urlHelper');

const delay = ms => new Promise(res => setTimeout(res, ms));
const verbose = false;

class FfsCacheManager {
  constructor(ubiqCredentials, ubiqWebServices, ubiqConfiguration) {
    this.cacheMap = new Map();
    this.queryMap = new Map();
    this.credentials = ubiqCredentials;
    this.ubiqWebServices = ubiqWebServices;
    this.ubiqConfiguration = ubiqConfiguration;
  }

  // Needed async notation.  eslint doesn't like a "return await" so just to be sure, perform in two stpes
  async LoadAsync(ffsName) {
    var x = await this.ubiqWebServices.GetFfsConfigurationsync(ffsName);
    return x
  }


  async GetAsync(FfsName) {
    // Debug
    let space = ""
    let retry_count = this.ubiqConfiguration.nodejs_lock_max_retry_count;

    const url = UrlHelper.GenerateFfsUrl(FfsName, this.credentials);
    if (this.queryMap.has(url)) {
      if (verbose) console.log(`FfsCacheManager this.queryMap ${FfsName} true`);
      while (retry_count-- > 0 && this.queryMap.has(url) && this.cacheMap.has(url) == false) {
        if (verbose) console.log(`${space} FfsCacheManager cacheMap ${FfsName} false`);
        await delay(this.ubiqConfiguration.nodejs_lock_sleep_before_retry);
        if (verbose) space = space + " ";
      }
    } else {
      if (verbose) console.log(`FfsCacheManager this.queryMap ${FfsName} false`);
      this.queryMap.set(url, url);

      // if (!this.cacheMap.has(url)) {
      if (verbose) console.log(`FfsCacheManager Fetching URL: ${url}`);
      try {
        const ffs = await this.LoadAsync(FfsName);
        if (!ffs) {
          throw new Error(`Could not load FfsName: ${FfsName}`);
        }
        if (verbose) console.log(`FfsCacheManager Adding: ${url} ${ffs.name}`);
        this.cacheMap.set(url, ffs);
      } catch (err) {
        // Clear the query map if necessary
        if (this.queryMap.has(url) && this.cacheMap.has(url) == false) {
          if (verbose) console.log(`FfsCacheManager Removing this.queryMap ${FfsName} `);
          this.queryMap.delete(key)
        }
        throw err
      }
      // }
      if (verbose) console.log(`FfsCacheManager Returning: ${FfsName}   ${url} ${this.cacheMap.get(url).name}`);


    }
    return this.cacheMap.get(url);
  }

  // Add the value to the cache
  async AddToCache(FfsName, ffs) {
    let space = ""
    let retry_count = this.ubiqConfiguration.nodejs_lock_max_retry_count;

    const url = UrlHelper.GenerateFfsUrl(FfsName, this.credentials);

    // Query map is set if another request is trying to get the ffs definition.
    if (this.queryMap.has(url)) {
      if (verbose) console.log(`FfsCacheManager this.queryMap ${FfsName} true`);
      while (retry_count-- > 0 && this.queryMap.has(url) && this.cacheMap.has(url) == false) {
        if (verbose) console.log(`${space} FfsCacheManager cacheMap ${FfsName} false`);
        await delay(this.ubiqConfiguration.nodejs_lock_sleep_before_retry);
        if (verbose) space = space + " ";
      }
    } else {
      if (verbose) console.log(`FfsCacheManager this.queryMap ${FfsName} false`);
      this.queryMap.set(url, url);
      this.cacheMap.set(url, ffs);
    }
  }


}
module.exports = {
  FfsCacheManager,
};
