const { ubiqCache } = require('./ubiqCache');
const { FF1 } = require('./structured/FF1');
const forge = require('node-forge');

const verbose = false;

class Ff1CacheManager {
  constructor(ubiqConfiguration, dataset_cache, structured_key_cache) {

    this.ubiqConfiguration = ubiqConfiguration;
    this.dataset_cache = dataset_cache
    this.structured_key_cache = structured_key_cache

    let ttl = this.ubiqConfiguration.key_caching_ttl_seconds
    // If no key caching, set TTL to 0 to expire immediately but the remaining flow is unchanged
    // If encrypted caching, then set TTL to 0 to expire immediately.  The FPE cache will still
    // keep the key encrypted but thie FF1 object will be re-built as needed if cached key is encrypted
    if (!this.ubiqConfiguration.key_caching_structured || this.ubiqConfiguration.key_caching_encrypt) {
      ttl = 0;
    }

    this.map = new ubiqCache(ttl)
  }

  GetCacheKey(datasetName, KeyNumber) {
    // KeyNumber 0 was being treated the same as undefined or Null which caused a caching issue.
    let key = `${datasetName}-` + ((KeyNumber === undefined || KeyNumber == null) ? 'isNull' : KeyNumber)

    return key
  }

  Set(datasetName, keyNumber, data) {
    const cacheKey = this.GetCacheKey(datasetName, keyNumber);
    if (verbose) console.log("Ff1CacheManager::Set: ", cacheKey)
    this.map.set(cacheKey, data);
    return data
  }

  async GetAsync(datasetName, keyNumber) {
    const csu = "Ff1CacheManager::GetAsync"
    if (verbose) { console.log(`${csu}: datasetName ${datasetName} keyNumber ${keyNumber}`) }
    const cacheKey = this.GetCacheKey(datasetName, keyNumber);
    if (verbose) { console.log(`${csu}: cacheKey ${cacheKey}`) }
    let ret = { ctx: null, activeKeyNumber: null }
    ret = this.map.get(cacheKey)
    if (verbose) { console.log(`${csu}: ret`, ret) }
    if (!ret) {
      ret = null
    }
    // Checks for null or undefined
    if (ret == null) {
      const dataset = await this.dataset_cache.GetAsync(datasetName)
      const tweakUint8 = Uint8Array.from(Buffer.from(dataset.tweak, 'base64'));
      if (verbose) { console.log(`${csu} dataset: `, dataset) }

      // GetAsync will return decrypted key.  Difference is whether it has
      // to decrypt each time or if it is stored in the cache that way
      const structured_key = await this.structured_key_cache.GetAsync(datasetName, keyNumber)
      if (verbose) { console.log(`${csu} structured_key: `, structured_key) }

      if (verbose) { console.log(`structured_key.decrypted_data_key  ${structured_key.decrypted_data_key}`) }
      if (verbose) { console.log(`tweakUint8  ${tweakUint8}`) }

      const ctx = new FF1(
        structured_key.decrypted_data_key,
        tweakUint8,
        this.tweak_min_len,
        this.tweak_max_len,
        dataset.inputCharacterSet.length,
        dataset.inputCharacterSet
      );
      ret = { ctx: ctx, activeKeyNumber: structured_key.key_number }
      if (this.ubiqConfiguration.key_caching_structured && !this.ubiqConfiguration.key_caching_encrypt) {
        this.map.set(cacheKey, ret)
      }
      // TODO - If keyNumber was passed in as undefined, this is encrypt, but we know the actual key number
      // so we can add this object again as a decrypt
    }
    if (verbose) { console.log(`RET: ${ret}`) }
    return ret;
  }
}
module.exports = {
  Ff1CacheManager,
};
