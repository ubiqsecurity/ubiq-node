const { UrlHelper } = require('./urlHelper');

const delay = ms => new Promise(res => setTimeout(res, ms));
const verbose = false;

const Passthrough_Priorities = Object.freeze({
  None: Symbol("none"),
  Passthrough: Symbol("passthrough"),
  Prefix: Symbol("prefix"),
  Suffix: Symbol("suffix")
});

class FfsCacheManager {
  constructor(ubiqCredentials, ubiqWebServices, ubiqConfiguration) {
    this.cacheMap = new Map();
    this.queryMap = new Map();
    this.credentials = ubiqCredentials;
    this.ubiqWebServices = ubiqWebServices;
    this.ubiqConfiguration = ubiqConfiguration;
  }

  /*
  {
    "name": "SSN_passthrough_last",
    "salt": "omtdWDHmRoa1BmefXy1sMLAPxsg+WgjYEytV/WDprnw=",
    "min_input_length": 5,
    "max_input_length": 255,
    "tweak_source": "constant",
    "encryption_algorithm": "FF1",
    "passthrough": "- /",
    "input_character_set": "abcdefghijklmnopqrstuvwxyz0123456789",
    "output_character_set": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "msb_encoding_bits": 3,
    "tweak_min_len": 6,
    "tweak_max_len": 32,
    "tweak": "Pw2ECl4u10diag26Tm9wBjxVRqt4qDAxIH6aek9+dws=",
    "fpe_definable_type": "EfpeDefinition",
    "passthrough_rules": [
      {
        "type": "passthrough",
        "value": "- /",
        "priority": 3
      },
      {
        "type": "prefix",
        "value": 2,
        "priority": 2
      },
      {
        "type": "suffix",
        "value": 3,
        "priority": 1
      }
    ]
  }
   */

  processFFS(ffs) {
    ffs.partial_encryption = false;
    ffs.prefix_length = 0;
    ffs.suffix_length = 0;
    ffs.passthrough_priorities = [];

    // Will only be partial encryption if there is an element with prefix / suffix
    if (typeof ffs.passthrough_rules != 'undefined' && ffs.passthrough_rules) {
      if (Array.isArray(ffs.passthrough_rules)) {
        let ar = []
        // By putting into an array using the priority, they are put in order
        for (const rec of ffs.passthrough_rules.values()) {
          ar[rec.priority] = rec;
        }
        // Removes gaps in array
        ar = ar.filter(Boolean)

        let idx = 0;
        for (const rec of ar.values()) {
          if (rec.type == "prefix") {
            ffs.partial_encryption = true;
            ffs.prefix_length = rec.value;
            ffs.passthrough_priorities.push(Passthrough_Priorities.Prefix);
          } else if (rec.type == "suffix") {
            ffs.partial_encryption = true;
            ffs.suffix_length = rec.value;
            ffs.passthrough_priorities.push(Passthrough_Priorities.Suffix);
          } else if (rec.type == "passthrough") {
            if (typeof ffs.passthrough == 'undefined') {
              ffs.passthrough = rec.value;
            }
            ffs.passthrough_priorities.push(Passthrough_Priorities.Passthrough);
          }
        }
      }
    }
    if (verbose) console.log(`FFS: ${JSON.stringify(ffs)}`);
    return ffs;
  }


  // Needed async notation.  eslint doesn't like a "return await" so just to be sure, perform in two stpes
  async LoadAsync(ffsName) {
    const verbose = false
    var ffs = await this.ubiqWebServices.GetFfsConfigurationsync(ffsName);

    // Post process the FFS - 
    ffs = this.processFFS(ffs)

    return ffs
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
          this.queryMap.delete(url)
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

    ffs = this.processFFS(ffs);
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
    return ffs
  }


}
module.exports = {
  FfsCacheManager,
  Passthrough_Priorities
};
