const { ubiqCache } = require('./ubiqCache');

const verbose = false;

class Ff1CacheManager {
  constructor(ubiqConfiguration) {

    this.ubiqConfiguration = ubiqConfiguration;

    let ttl = this.ubiqConfiguration.key_caching_ttl_seconds
    // If no key caching, set TTL to 0 to expire immediately but the remaining flow is unchanged
    // If encrypted caching, then set TTL to 0 to expire immediately.  The FPE cache will still
    // keep the key encrypted but thie FF1 object will be re-built as needed if cached key is encrypted
    if (!this.ubiqConfiguration.key_caching_structured || this.ubiqConfiguration.key_caching_encrypt) {
      ttl = 0;
    }

    this.map = new ubiqCache(ttl)
  }

  GetCacheKey(FfsName, KeyNumber) {
    // KeyNumber 0 was being treated the same as undefined or Null which caused a caching issue.
    let key = `${FfsName}-` + ((KeyNumber === undefined || KeyNumber == null) ? 'isNull' : KeyNumber)

    return key
  }

  Set(FfsName, KeyNumber, data) {
    const cacheKey = this.GetCacheKey(FfsName, KeyNumber);
    if (verbose) console.log("Ff1CacheManager::Set: ", cacheKey)
    this.map.set(cacheKey, data);
    return data
  }

  Get(FfsName, KeyNumber) {
    const cacheKey = this.GetCacheKey(FfsName, KeyNumber);
    let ret = null
    // ret = this.map.opts.store.get(cacheKey)
    // console.log("this.map.opts.store.get: ", ret)
    ret = this.map.get(cacheKey)
    if (verbose) { console.log("Ff1CacheManager::Get: ", ret) }
    if (!ret) {
      ret = null
    }
    return ret;
  }
}
module.exports = {
  Ff1CacheManager,
};
