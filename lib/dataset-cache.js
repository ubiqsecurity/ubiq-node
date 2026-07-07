const { UrlHelper } = require('./urlHelper');
const { DatasetRecord } = require('./dataset-record');

const delay = ms => new Promise(res => setTimeout(res, ms));
const verbose = false;

const Passthrough_Priorities = Object.freeze({
  None: Symbol("none"),
  Passthrough: Symbol("passthrough"),
  Prefix: Symbol("prefix"),
  Suffix: Symbol("suffix")
});

class DatasetCache {
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

  // Needed async notation.  eslint doesn't like a "return await" so just to be sure, perform in two stpes
  async LoadAsync(datasetName) {
    const verbose = false
    var dataset = await this.ubiqWebServices.GetFfsConfigurationsync(datasetName);

    // process the dataset - 
    dataset = DatasetRecord.parse(dataset)

    return dataset
  }


  async GetAsync(datasetName) {
    // Debug
    let space = ""
    let retry_count = this.ubiqConfiguration.nodejs_lock_max_retry_count;

    const url = UrlHelper.GenerateFfsUrl(datasetName, this.credentials);
    if (this.queryMap.has(url)) {
      if (verbose) console.log(`DatasetCache this.queryMap ${datasetName} true`);
      while (retry_count-- > 0 && this.queryMap.has(url) && this.cacheMap.has(url) == false) {
        if (verbose) console.log(`${space} DatasetCache cacheMap ${datasetName} false`);
        await delay(this.ubiqConfiguration.nodejs_lock_sleep_before_retry);
        if (verbose) space = space + " ";
      }
    } else {
      if (verbose) console.log(`DatasetCache this.queryMap ${datasetName} false`);
      this.queryMap.set(url, url);

      // if (!this.cacheMap.has(url)) {
      if (verbose) console.log(`DatasetCache Fetching URL: ${url}`);
      try {
        const dataset = await this.LoadAsync(datasetName);
        if (!dataset) {
          throw new Error(`Could not load datasetName: ${datasetName}`);
        }
        if (verbose) console.log(`DatasetCache Adding: ${url} ${dataset.name}`);
        this.cacheMap.set(url, dataset);
      } catch (err) {
        // Clear the query map if necessary
        if (this.queryMap.has(url) && this.cacheMap.has(url) == false) {
          if (verbose) console.log(`DatasetCache Removing this.queryMap ${datasetName} `);
          this.queryMap.delete(url)
        }
        throw err
      }
      // }
      if (verbose) console.log(`DatasetCache Returning: ${datasetName}   ${url} ${this.cacheMap.get(url).name}`);


    }
    return this.cacheMap.get(url);
  }

  // Add the value to the cache
  async AddToCache(datasetName, datasetJson) {
    // let verbose = true
    const csu = "DatasetCache::AddToCache"
    let space = ""
    let retry_count = this.ubiqConfiguration.nodejs_lock_max_retry_count;

    const dataset = DatasetRecord.parse(datasetJson);
    if (verbose) { console.log(`${csu}: dataset`, dataset) }
    const url = UrlHelper.GenerateFfsUrl(datasetName, this.credentials);

    // Query map is set if another request is trying to get the dataset definition.
    if (this.queryMap.has(url)) {
      if (verbose) console.log(`DatasetCache this.queryMap ${datasetName} true`);
      while (retry_count-- > 0 && this.queryMap.has(url) && this.cacheMap.has(url) == false) {
        if (verbose) console.log(`${space} DatasetCache cacheMap ${datasetName} false`);
        await delay(this.ubiqConfiguration.nodejs_lock_sleep_before_retry);
        if (verbose) space = space + " ";
      }
    } else {
      if (verbose) console.log(`DatasetCache this.queryMap ${datasetName} false`);
      this.queryMap.set(url, url);
      this.cacheMap.set(url, dataset);
    }
    return dataset
  }


}
module.exports = {
  DatasetCache,
  Passthrough_Priorities
};
