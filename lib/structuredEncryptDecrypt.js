const forge = require('node-forge');
const { FF1 } = require('./structured/FF1');
const { bigint_get_str, bigint_set_str, convertRadix } = require('./structured/Bn');
const { DatasetRecord } = require('./dataset-record');
const { DatasetCache } = require('./dataset-cache');
const { StructuredKeyCache } = require('./structured-key-cache');
const { UbiqWebServices } = require('./ubiqWebServices');
const { BillingEventsProcessor } = require('./billingEventsProcessor');
const { Ff1CacheManager } = require('./ff1CacheManager');
const { BillingEvents } = require('./billingEvents');
const { Configuration } = require('./configuration');
const { Passthrough_Priorities } = require('./dataset-cache')
const { OperationContext } = require('./pipeline/operation-context')
const { EncryptionPipeline } = require('./pipeline/encryption-pipeline')
const { DecryptionPipeline } = require('./pipeline/decryption-pipeline')
const strUtils = require('./structured/strUtils');

const verbose = false;


class StructuredEncryptDecrypt {
  constructor({ ubiqCredentials, ubiqConfiguration }) {
    this.ubiqCredentials = ubiqCredentials;

    if (!ubiqConfiguration) {
      this.ubiqConfiguration = new Configuration();
    } else {
      this.ubiqConfiguration = ubiqConfiguration;
    }
    this.isInited = false;

    this.ubiqWebServices = new UbiqWebServices(this.ubiqCredentials);
    // dataset used to create URL and the results is the dataset JSON from web call
    this.datasetCache = new DatasetCache(this.ubiqCredentials, new UbiqWebServices(this.ubiqCredentials), this.ubiqConfiguration);
    // dataset and key number used to create URL and result is the JSON response from the web call
    this.structuredKeyCache = new StructuredKeyCache(this.ubiqCredentials, new UbiqWebServices(this.ubiqCredentials), this.ubiqConfiguration);
    // this.fpeTransactions = new FpeTransactionManager();
    this.billing_events = new BillingEvents(this.ubiqConfiguration);
    // datasetname & key number - returns FF1.  Keynumber could be undefined or null for active key
    this.Ff1CacheManager = new Ff1CacheManager(this.ubiqConfiguration, this.datasetCache, this.structuredKeyCache);
    this.billingEventsProcessor = new BillingEventsProcessor(new UbiqWebServices(this.ubiqCredentials), this.billing_events, this.ubiqConfiguration);

    this.srsa = this.ubiqCredentials.secret_crypto_access_key;


    if (verbose) { console.log(`datasetCache: ${this.datasetCache}`) }
    if (verbose) { console.log(`structuredKeyCache: ${this.structuredKeyCache}`) }
    if (verbose) { console.log(`Ff1CacheManager: ${this.Ff1CacheManager}`) }
  }

  // eslint doesn't like a "return await" so just to be sure, perform in two stpes
  async close() {
    if (verbose) console.log(`StructuredEncryptDecrypt close   `);
    await this.billingEventsProcessor.close()
    this.billing_events = null;
  }

  async loadCache(datasetName) {
    // let verbose = true
    const csu = "StructuredEncryptDecrypt::loadCache"
    const data = await this.ubiqWebServices.GetFFSAndDataKeys(datasetName);
    if (verbose) { console.log("data: ", data) }

    if (verbose) { console.log(`${csu} Object.entries(data).length: `, Object.entries(data).length) }
    let ret = {}
    // datasetName can be empty, an empty array, or an array of dataset names.
    for (const [dataset_name, dataset_data] of Object.entries(data)) {

      const dataset = DatasetRecord.parse(dataset_data['ffs'])
      if (verbose) { console.log(`${csu} dataset: `, dataset) }

      await this.datasetCache.AddToCache(dataset_name, dataset)

      const encrypted_private_key = dataset_data['encrypted_private_key']
      const decryptedPrivateKey = await this.structuredKeyCache.DecryptEncryptedPrivateKeyAsync(encrypted_private_key)
      const current_key_number = dataset_data['current_key_number']
      const keys = dataset_data['keys']

      ret = { dataset: dataset, key_count: keys.length }

      let structured_key = {
        encrypted_private_key: encrypted_private_key,
        wrapped_data_key: keys[current_key_number],
        key_number: current_key_number
      }
      await this.structuredKeyCache.AddToCache(dataset_name, null, structured_key, decryptedPrivateKey)
      for (let i = 0; i < keys.length; i++) {
        // Load the keys to the key-cache
        const structured_key = {
          encrypted_private_key: encrypted_private_key,
          wrapped_data_key: keys[i],
          key_number: i
        }
        await this.structuredKeyCache.AddToCache(dataset_name, i, structured_key, decryptedPrivateKey)
      }
    }
    // If there was more than one dataset loaded, then this will be the last one.
    // If there was only one requested, it will be the one requested
    return ret
  }

  async EncryptForSearchAsync(datasetName, plainText, tweak) {
    try {

      const { dataset, key_count } = await this.loadCache(datasetName)
      if (verbose) { console.log(`dataset: ${dataset}`) }
      if (verbose) { console.log(`key_count: ${key_count}`) }
      // Will return the array of keys from 0 .. current_key unless the data key has been rotated too many times

      let ct = []
      // let structured_key = {
      //   encrypted_private_key: encrypted_private_key,
      //   wrapped_data_key: keys[current_key_number],
      //   key_number: current_key_number
      // }
      // this.structuredKeyCache.AddToCache(datasetName, null, structured_key, decryptedPrivateKey)
      for (let i = 0; i < key_count; i++) {
        // Load the keys to the key-cache
        let x = await this.encryptPipelineAsync(dataset, i, this.Ff1CacheManager, plainText, tweak);
        ct.push(x)
        if (verbose) { console.log(`i: ${i} x: ${x}`) }
      }

      // Add for active key (null) and actual current_key_number.
      // await this.AddFF1(dataset, privateKey, keys[current_key_number], null, current_key_number)

      return ct
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
  }

  addReportingUserDefinedMetadata(jsonString) {
    this.billing_events.addUserDefinedMetadata(jsonString);
  }

  getCopyOfUsage() {
    return this.billing_events.getSerializedData();
  }

  async encryptPipelineAsync(dataset, keyNumber, ffxCache, plaintext, tweak) {

    if (!dataset.canEncrypt()) {
      throw new Error(`Credentials do not have encrypt rights for dataset '${dataset.name}'`)
    }

    const context = new OperationContext();
    context.setDataset(dataset);
    context.setKeyNumber(keyNumber);
    context.setOriginalValue(plaintext);
    context.setCurrentValue(plaintext);
    context.setIsEncrypt(true);
    context.setUserSuppliedTweak(tweak);
    context.setFfxCache(ffxCache);

    const pipeline = new EncryptionPipeline(dataset);
    const results = await pipeline.invokeAsync(context);

    const be = await this.billing_events.addBillingEvent(this.ubiqCredentials.access_key_id, dataset.name, "", BillingEvents.ENCRYPTION, BillingEvents.STRUCTURED, context.getKeyNumber, 1);
    return results
  }

  async EncryptAsync(datasetName, plainText, tweak) {
    let cipher = "";

    const dataset = await this.getDataset(datasetName)
    if (verbose) { console.log(`dataset: ${dataset} tweak: (${tweak})`) }

    switch (dataset.dataType) {
      case "integer":
      case "date":
      case "datetime":
        throw new Error(
          `Dataset '${datasetName}' is for '${dataset.dataType}' and not Strings. Use the appropriate method for this type`
        );
    }
    try {
      cipher = await this.encryptPipelineAsync(dataset, null, this.Ff1CacheManager, plainText, tweak)
      if (verbose) { console.log(`EncryptAsync: cipher(${cipher})`); }
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }

    return cipher

  }

  async getDataset(datasetName) {
    if (this.datasetCache == null) {
      throw new Error("object closed");
    }
    const ret = await this.datasetCache.GetAsync(datasetName)
    return ret
  }

  async decryptPipelineAsync(dataset, ffxCache, cipherText, tweak) {
    if (verbose) { console.log(`decryptPipeline: cipherText(${cipherText})`) }
    if (verbose) { console.log(`decryptPipelineAsync cipherText: ${cipherText} ${typeof cipherText}`) }

    if (!dataset.canDecrypt()) {
      throw new Error(`Credentials do not have decrypt rights for dataset '${dataset.name}'`)
    }

    // Cannot check type of cipherText here against dataset because all logic passes through
    // here and would flag items incorrectly

    const context = new OperationContext();
    context.setDataset(dataset);
    context.setKeyNumber(null);
    context.setOriginalValue(cipherText);
    context.setCurrentValue(cipherText);
    context.setIsEncrypt(false);
    context.setUserSuppliedTweak(tweak);
    context.setFfxCache(ffxCache);

    const pipeline = new DecryptionPipeline(dataset);
    const results = await pipeline.invokeAsync(context);
    if (verbose) { console.log(`results: ${results}  ${typeof results}`) }
    const be = await this.billing_events.addBillingEvent(this.ubiqCredentials.access_key_id, dataset.name, "", BillingEvents.DECRYPTION, BillingEvents.STRUCTURED, context.getKeyNumber, 1);
    return results
  }

  async DecryptAsync(datasetName, cipherText, tweak) {
    let verbose = false;
    var plaintext = "";

    var dataset = await this.getDataset(datasetName)
    if (verbose) { console.log(`dataset: ${dataset}`) }

    switch (dataset.dataType) {
      case "integer":
      case "date":
      case "datetime":
        throw new Error(
          `Dataset '${datasetName}' is for '${dataset.dataType}' and not Strings. Use the appropriate method for this type`
        );
    }

    try {
      plaintext = await this.decryptPipelineAsync(dataset, this.Ff1CacheManager, cipherText, tweak)
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
    return plaintext
  }

  toBigNumber(value) {
    let bigintNumber = 0n

    switch (typeof value) {
      case 'string':
        bigintNumber = BigInt(value)
        break;
      case 'number':
        bigintNumber = BigInt(value)
        break;

      case 'bigint':
        bigintNumber = value
        break;
      default:
        throw new Error(`Unable to convert ${value} of type ${typeof value} to a BigInt`)
    }
    return bigintNumber
  }

  // Single function to handle numbers, the maxInputIntValue and minInputIntValue will control the range of the input
  async encryptNumberPipelineAsync(dataset, keyNumber, ffxCache, bigIntPlainNumber, tweak) {

    if (dataset.dataType != 'integer') {
      throw new Error(
        `Dataset '${dataset.name}' is for '${dataset.dataType}' and is not in 'integer' dataset. Use the appropriate method for this type`
      );
    }

    let cfg = dataset.dataTypeConfig
    if (!cfg) {
      throw new Error(
        `Dataset '${dataset.name}' is missing data_type_config`
      );
    }

    if (!cfg.size || (cfg.size != 32 && cfg.size != 64)) {
      throw new Error(
        `Dataset '${dataset.name}' does not have a 32 or 64 bit DataSize`
      );
    }

    if (bigIntPlainNumber > cfg.maxInputIntValue) {
      throw new IllegalArgumentException("Integer '" + bigIntPlainNumber.toString() + "'  <= " + cfg.maxInputIntValue.toString());
    }

    if (bigIntPlainNumber < cfg.minInputIntValue) {
      throw new IllegalArgumentException("Integer '" + bigIntPlainNumber.toString() + "'  >= " + cfg.minInputIntValue.toString());
    }

    let isNegative = bigIntPlainNumber < 0n;
    let plainText = isNegative ? (-bigIntPlainNumber).toString() : (bigIntPlainNumber).toString()
    plainText = strUtils.padLeft('0', dataset.minInputLength, plainText)

    let results = await this.encryptPipelineAsync(dataset, keyNumber, ffxCache, plainText, tweak)
    if (verbose) { console.log(`encryptNumberPipeline: results: ${results}`) }
    let results_base10 = convertRadix(results, dataset.outputCharacterSet, dataset.inputCharacterSet, true)
    if (verbose) { console.log(`encryptNumberPipeline: results_base10: ${results_base10}`) }
    let bigIntResults = BigInt(results_base10)
    if (isNegative) {
      bigIntResults *= -1n
    }

    // Billnig is handled in the encryptPipelineAsync
    if (verbose) { console.log(`encryptNumberPipeline: bigIntResults: ${bigIntResults}`) }
    return bigIntResults
  }

  async EncryptNumberAsync(datasetName, plainNumber, tweak) {
    // let verbose = true
    const csu = "StructuredEncryptDecrypt::EncryptNumberAsync"
    let cipher = 0n;

    const dataset = await this.getDataset(datasetName)

    let bigintNumber = this.toBigNumber(plainNumber)
    if (verbose) { console.log(`${csu} dataset: ${dataset} plainNumber: ${plainNumber} bigintNumber: ${bigintNumber} tweak: (${tweak})`) }

    try {
      cipher = await this.encryptNumberPipelineAsync(dataset, null, this.Ff1CacheManager, bigintNumber, tweak)
      if (verbose) { console.log(`EncryptNumberAsync: cipher(${cipher})`); }
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
    if (verbose) { console.log(`EncryptNumberAsync: ${cipher}`) }
    return cipher
  }

  async EncryptNumberForSearchAsync(datasetName, plainNumber, tweak) {
    try {

      const { dataset, key_count } = await this.loadCache(datasetName)
      if (verbose) { console.log(`dataset: ${dataset}`) }
      if (verbose) { console.log(`key_count: ${key_count}`) }

      // Will return the array of keys from 0 .. current_key unless the data key has been rotated too many times

      let bigintNumber = this.toBigNumber(plainNumber)

      let ct = []
      for (let i = 0; i < key_count; i++) {
        // Load the keys to the key-cache
        //ff1cache will simply build the ff1 and perform the action
        let x = await this.encryptNumberPipelineAsync(dataset, i, this.Ff1CacheManager, bigintNumber, tweak);
        ct.push(x)
        if (verbose) { console.log(`i: ${i} x: ${x}`) }
      }

      return ct
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
  }

  // Single function to handle numbers, the maxInputIntValue and minInputIntValue will control the range of the input
  async decryptNumberPipelineAsync(dataset, keyNumber, ffxCache, bigIntCipherNumber, tweak) {

    if (dataset.dataType != 'integer') {
      throw new Error(
        `Dataset '${dataset.name}' is for '${dataset.dataType}' and is not in 'integer' dataset. Use the appropriate method for this type`
      );
    }

    let cfg = dataset.dataTypeConfig
    if (!cfg) {
      throw new Error(
        `Dataset '${dataset.name}' is missing data_type_config`
      );
    }

    if (!cfg.size || (cfg.size != 32 && cfg.size != 64)) {
      throw new Error(
        `Dataset '${dataset.name}' does not have a 32 or 64 bit DataSize`
      );
    }

    let isNegative = bigIntCipherNumber < 0n;
    let cipherText = isNegative ? (-bigIntCipherNumber).toString() : (bigIntCipherNumber).toString()
    cipherText = convertRadix(cipherText, dataset.inputCharacterSet, dataset.outputCharacterSet, false)
    if (verbose) { console.log(`decryptNumberPipeline cipherText before: ${cipherText} ${typeof cipherText}`) }
    cipherText = strUtils.padLeft('0', dataset.minInputLength, cipherText)

    if (verbose) { console.log(`decryptNumberPipeline cipherText after: ${cipherText} ${typeof cipherText}`) }
    let results = await this.decryptPipelineAsync(dataset, ffxCache, cipherText, tweak)

    // let results_base10 = convertRadix(results, dataset.outputCharacterSet, dataset.inputCharacterSet)
    let bigIntResults = BigInt(results)
    if (isNegative) {
      bigIntResults *= -1n
    }

    // Billing handled in decryptPipelineAsync
    return bigIntResults
  }

  async DecryptNumberAsync(datasetName, cipherNumber, tweak) {
    // let verbose = true
    const csu = "StructuredEncryptDecrypt::DecryptNumberAsync"
    let plainNumber = 0n;

    const dataset = await this.getDataset(datasetName)
    // if (verbose) { console.log(`dataset: ${dataset} tweak: (${tweak})`) }

    let bigintNumber = this.toBigNumber(cipherNumber)
    if (verbose) { console.log(`${csu} dataset: ${dataset} plainNumber: ${plainNumber} bigintNumber: ${bigintNumber} tweak: (${tweak})`) }

    try {
      plainNumber = await this.decryptNumberPipelineAsync(dataset, null, this.Ff1CacheManager, bigintNumber, tweak)
      if (verbose) { console.log(`${csu}: plainNumber(${plainNumber})`); }
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
    if (verbose) { console.log(`${csu}: plainNumber ${plainNumber}`) }

    return plainNumber
  }

  isDate(value) {
    let d

    if (value instanceof Date && !isNaN(value)) {
      d = value
    } else {
      d = new Date(value)
    }

    const [h, m, s, ms] = [d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), d.getUTCMilliseconds()];

    if (Number.isNaN(h) || Number.isNaN(m) || Number.isNaN(s) || Number.isNaN(ms) ||
      h !== 0 || m !== 0 || s !== 0 || ms !== 0) {
      throw new Error(`Value ${value} is not a valid date with hours, minutes, seconds all set to zero, `)
    }
    return d
  }

  daysBetweenUTC(a, b) {
    const MS_PER_DAY = 24 * 60 * 60 * 1000;
    return Math.floor((b.getTime() - a.getTime()) / MS_PER_DAY);
  };

  addDays(date, days) {
    let result = new Date(date);
    result = new Date(result.getTime() + days * 24 * 60 * 60 * 1000);
    return result;
  };

  async encryptDatePipelineAsync(dataset, keyNumber, ffxCache, plainDate, tweak) {
    if (dataset.dataType != 'date') {
      throw new Error(
        `Dataset '${dataset.name}' is for '${dataset.dataType}' and is not in 'date' dataset. Use the appropriate method for this type`
      );
    }

    let cfg = dataset.dataTypeConfig
    if (!cfg) {
      throw new Error(
        `Dataset '${dataset.name}' is missing data_type_config`
      );
    }

    if (plainDate.getTime() > cfg.maxInputDateValue.getTime()) {
      throw new IllegalArgumentException("Date '" + plainDate + "'  > " + cfg.maxInputDateValue);
    }

    if (plainDate.getTime() < cfg.minInputDateValue.getTime()) {
      throw new IllegalArgumentException("Date '" + plainDate + "'  < " + cfg.minInputDateValue);
    }

    let daysToEpoch = this.daysBetweenUTC(cfg.epoch, plainDate);
    let isNegative = daysToEpoch < 0;

    let plainText = isNegative ? (-1 * daysToEpoch).toString() : (daysToEpoch).toString()
    if (verbose) { console.log(`encryptDatePipeline: daysToEpoch: ${daysToEpoch}`) }
    plainText = convertRadix(plainText, "0123456789", dataset.inputCharacterSet)
    if (verbose) { console.log(`encryptDatePipeline: ICS plainText: ${plainText}`) }
    plainText = strUtils.padLeft(dataset.inputCharacterSet[0], dataset.minInputLength, plainText)
    if (verbose) { console.log(`encryptDatePipeline: plainText: ${plainText}`) }

    let results = await this.encryptPipelineAsync(dataset, keyNumber, ffxCache, plainText, tweak)
    if (verbose) { console.log(`encryptDatePipeline: results: ${results}`) }
    let results_base10 = Number(convertRadix(results, dataset.outputCharacterSet, "0123456789", true))
    if (isNegative) {
      results_base10 *= -1
    }
    if (verbose) { console.log(`encryptDatePipeline: results_base10: ${results_base10}`) }
    let ret = this.addDays(cfg.epoch, results_base10)

    // Billing is handled in the encryptPipelineAsync
    if (verbose) { console.log(`encryptDatePipeline: ret: ${ret}`) }
    return ret
  }

  async EncryptDateAsync(datasetName, plainDate, tweak) {
    let cipher;

    const dataset = await this.getDataset(datasetName)
    if (verbose) { console.log(`dataset: ${dataset} tweak: (${tweak})`) }

    let d = this.isDate(plainDate)

    try {
      cipher = await this.encryptDatePipelineAsync(dataset, null, this.Ff1CacheManager, d, tweak)
      if (verbose) { console.log(`EncryptDateAsync: cipher(${cipher})`); }
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
    if (verbose) { console.log(`EncryptDateAsync: ${cipher}`) }
    return cipher
  }

  async EncryptDateForSearchAsync(datasetName, plainDate, tweak) {
    try {

      const { dataset, key_count } = await this.loadCache(datasetName)
      if (verbose) { console.log(`dataset: ${dataset}`) }
      if (verbose) { console.log(`key_count: ${key_count}`) }

      // Will return the array of keys from 0 .. current_key unless the data key has been rotated too many times
      let d = this.isDate(plainDate)

      let ct = []
      for (let i = 0; i < key_count; i++) {
        // Load the keys to the key-cache
        //ff1cache will simply build the ff1 and perform the action
        let x = await this.encryptDatePipelineAsync(dataset, i, this.Ff1CacheManager, d, tweak);
        ct.push(x)
        if (verbose) { console.log(`i: ${i} x: ${x}`) }
      }

      return ct
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
  }


  async decryptDatePipelineAsync(dataset, ffxCache, cipherDate, tweak) {
    if (dataset.dataType != 'date') {
      throw new Error(
        `Dataset '${dataset.name}' is for '${dataset.dataType}' and is not in 'date' dataset. Use the appropriate method for this type`
      );
    }

    let cfg = dataset.dataTypeConfig
    if (!cfg) {
      throw new Error(
        `Dataset '${dataset.name}' is missing data_type_config`
      );
    }
    if (verbose) { console.log(`decryptDatePipelineAsync: cipherDate: ${cipherDate}`) }

    let daysToEpoch = this.daysBetweenUTC(cfg.epoch, cipherDate);
    let isNegative = daysToEpoch < 0;

    let cipherText = isNegative ? (-1 * daysToEpoch).toString() : (daysToEpoch).toString()
    if (verbose) { console.log(`decryptDatePipelineAsync: daysToEpoch: ${daysToEpoch}`) }
    cipherText = convertRadix(cipherText, "0123456789", dataset.outputCharacterSet)
    cipherText = strUtils.padLeft(dataset.outputCharacterSet[0], dataset.minInputLength, cipherText)
    if (verbose) { console.log(`decryptDatePipelineAsync: cipherText OCS: ${cipherText}`) }

    let results = await this.decryptPipelineAsync(dataset, ffxCache, cipherText, tweak)
    if (verbose) { console.log(`decryptDatePipelineAsync: results: ${results}`) }
    let results_base10 = Number(convertRadix(results, dataset.inputCharacterSet, "0123456789", true))
    if (verbose) { console.log(`decryptDatePipelineAsync: results_base10: ${results_base10}`) }
    if (isNegative) {
      results_base10 *= -1
    }
    let ret = this.addDays(cfg.epoch, results_base10)
    // Billing handled in decryptPipelineAsync
    if (verbose) { console.log(`decryptDatePipelineAsync: ret: ${ret}`) }
    return ret
  }

  async DecryptDateAsync(datasetName, cipherDate, tweak) {
    let plainDate;

    const dataset = await this.getDataset(datasetName)
    if (verbose) { console.log(`dataset: ${dataset} tweak: (${tweak})`) }

    let d = this.isDate(cipherDate)

    try {
      plainDate = await this.decryptDatePipelineAsync(dataset, this.Ff1CacheManager, d, tweak)
      if (verbose) { console.log(`DecryptDateAsync: plainDate(${plainDate})`); }
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
    if (verbose) { console.log(`DecryptDateAsync: ${plainDate}`) }
    return plainDate
  }

  secondsBetweenUTC(a, b) {
    const SEC_PER_MS = 1000;
    return Math.floor((b.getTime() - a.getTime()) / SEC_PER_MS);
  };

  addSeconds(date, seconds) {
    let result = new Date(date);
    result = new Date(result.getTime() + seconds * 1000);
    return result;
  };

  isDateTime(value) {
    let d

    if (value instanceof Date && !isNaN(value)) {
      d = value
    } else {
      d = new Date(value)
      // Recheck to make sure the new Date() returned a valid object
      if (!(d instanceof Date && !isNaN(d))) {
        throw new Error(`Value ${d} is not a valid datetime`)
      }
    }

    const ms = d.getUTCMilliseconds();

    if (Number.isNaN(ms) || ms !== 0) {
      throw new Error(`Value ${value} millicsecond value must be zero, `)
    }

    return d
  }

  async encryptDateTimePipelineAsync(dataset, keyNumber, ffxCache, plainDateTime, tweak) {
    const csu = "encryptDateTimePipelineAsync"
    if (dataset.dataType != 'datetime') {
      throw new Error(
        `Dataset '${dataset.name}' is for '${dataset.dataType}' and is not in 'datetime' dataset. Use the appropriate method for this type`
      );
    }

    let cfg = dataset.dataTypeConfig
    if (!cfg) {
      throw new Error(
        `Dataset '${dataset.name}' is missing data_type_config`
      );
    }

    if (plainDateTime.getTime() > cfg.maxInputDateValue.getTime()) {
      throw new Error("DateTime '" + plainDateTime + "'  > " + cfg.maxInputDateValue);
    }

    if (plainDateTime.getTime() < cfg.minInputDateValue.getTime()) {
      throw new Error("DateTime '" + plainDateTime + "'  < " + cfg.minInputDateValue);
    }

    let secondsToEpoch = this.secondsBetweenUTC(cfg.epoch, plainDateTime);
    if (verbose) { console.log(`${csu}: secondsToEpoch: ${secondsToEpoch}`) }
    let isNegative = secondsToEpoch < 0;

    let plainText = isNegative ? (-1 * secondsToEpoch).toString() : (secondsToEpoch).toString()
    if (verbose) { console.log(`${csu}: abs secondsToEpoch: ${secondsToEpoch} isNegative: ${isNegative}`) }
    plainText = convertRadix(plainText, "0123456789", dataset.inputCharacterSet)
    if (verbose) { console.log(`${csu}: ICS plainText: ${plainText}`) }
    plainText = strUtils.padLeft(dataset.inputCharacterSet[0], dataset.minInputLength, plainText)
    if (verbose) { console.log(`${csu}: plainText: ${plainText}`) }

    let results = await this.encryptPipelineAsync(dataset, keyNumber, ffxCache, plainText, tweak)
    if (verbose) { console.log(`${csu}: results: ${results}`) }
    let results_base10 = Number(convertRadix(results, dataset.outputCharacterSet, "0123456789", true))
    if (verbose) { console.log(`${csu}: results_base10: ${results_base10} isNegative: ${isNegative}`) }
    if (isNegative) {
      results_base10 *= -1
    }
    if (verbose) { console.log(`${csu}: results_base10: ${results_base10}`) }
    let ret = this.addSeconds(cfg.epoch, results_base10)
    // Billing handled in decryptPipelineAsync
    if (verbose) { console.log(`${csu}: ret: ${ret}`) }
    return ret
  }

  async EncryptDateTimeAsync(datasetName, plainDateTime, tweak) {
    let cipher;

    const dataset = await this.getDataset(datasetName)
    if (verbose) { console.log(`dataset: ${dataset} tweak: (${tweak})`) }

    let d = this.isDateTime(plainDateTime)

    try {
      cipher = await this.encryptDateTimePipelineAsync(dataset, null, this.Ff1CacheManager, d, tweak)
      if (verbose) { console.log(`EncryptDateTimeAsync: cipher(${cipher})`); }
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
    if (verbose) { console.log(`EncryptDateAsync: ${cipher}`) }
    return cipher
  }

  async EncryptDateTimeForSearchAsync(datasetName, plainDateTime, tweak) {
    try {

      const { dataset, key_count } = await this.loadCache(datasetName)
      if (verbose) { console.log(`dataset: ${dataset}`) }
      if (verbose) { console.log(`key_count: ${key_count}`) }

      // Will return the array of keys from 0 .. current_key unless the data key has been rotated too many times
      let d = this.isDateTime(plainDateTime)
      let ct = []
      for (let i = 0; i < key_count; i++) {
        // Load the keys to the key-cache
        //ff1cache will simply build the ff1 and perform the action
        let x = await this.encryptDateTimePipelineAsync(dataset, i, this.Ff1CacheManager, d, tweak);
        ct.push(x)
        if (verbose) { console.log(`i: ${i} x: ${x}`) }
      }

      return ct
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
  }

  async decryptDateTimePipelineAsync(dataset, ffxCache, cipherDateTime, tweak) {
    const csu = "decryptDateTimePipelineAsync"
    if (dataset.dataType != 'datetime') {
      throw new Error(
        `Dataset '${dataset.name}' is for '${dataset.dataType}' and is not in 'datetime' dataset. Use the appropriate method for this type`
      );
    }

    let cfg = dataset.dataTypeConfig
    if (!cfg) {
      throw new Error(
        `Dataset '${dataset.name}' is missing data_type_config`
      );
    }
    if (verbose) { console.log(`${csu}: cipherDateTime: ${cipherDateTime}`) }

    let secondsToEpoch = this.secondsBetweenUTC(cfg.epoch, cipherDateTime);
    let isNegative = secondsToEpoch < 0;

    let cipherText = isNegative ? (-1 * secondsToEpoch).toString() : (secondsToEpoch).toString()
    if (verbose) { console.log(`${csu}: secondsToEpoch: ${secondsToEpoch}`) }
    cipherText = convertRadix(cipherText, "0123456789", dataset.outputCharacterSet)
    cipherText = strUtils.padLeft(dataset.outputCharacterSet[0], dataset.minInputLength, cipherText)
    if (verbose) { console.log(`${csu}: cipherText OCS: ${cipherText}`) }

    let results = await this.decryptPipelineAsync(dataset, ffxCache, cipherText, tweak)
    if (verbose) { console.log(`${csu}: results: ${results}`) }
    let results_base10 = Number(convertRadix(results, dataset.inputCharacterSet, "0123456789", true))
    if (verbose) { console.log(`${csu}: results_base10: ${results_base10} isNegative: ${isNegative}`) }
    if (isNegative) {
      results_base10 *= -1
    }
    if (verbose) { console.log(`${csu}: results_base10: ${results_base10}`) }
    let ret = this.addSeconds(cfg.epoch, results_base10)
    // Billing handled in decryptPipelineAsync
    if (verbose) { console.log(`${csu}: ret: ${ret}`) }
    return ret
  }

  async DecryptDateTimeAsync(datasetName, cipherDateTime, tweak) {
    const csu = "DecryptDateTimeAsync"
    let plainDateTime;

    const dataset = await this.getDataset(datasetName)
    if (verbose) { console.log(`dataset: ${dataset} tweak: (${tweak})`) }

    let d = this.isDateTime(cipherDateTime)

    try {
      plainDateTime = await this.decryptDateTimePipelineAsync(dataset, this.Ff1CacheManager, d, tweak)
      if (verbose) { console.log(`${csu}: plainDateTime(${plainDateTime})`); }
    } catch (ex) {
      console.error(ex.stack);
      throw new Error(ex.message);
    }
    if (verbose) { console.log(`${csu}: ${plainDateTime}`) }
    return plainDateTime
  }
}

module.exports = {
  StructuredEncryptDecrypt
};
