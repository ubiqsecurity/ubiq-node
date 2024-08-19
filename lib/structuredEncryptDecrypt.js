const forge = require('node-forge');
const { FF1 } = require('./structured/FF1');
const { bigint_get_str, bigint_set_str } = require('./structured/Bn');
const { FfsCacheManager } = require('./ffsCacheManager');
const { FpeCacheManager } = require('./fpeCacheManager');
const { UbiqWebServices } = require('./ubiqWebServices');
const { BillingEventsProcessor } = require('./billingEventsProcessor');
const { Ff1CacheManager } = require('./ff1CacheManager');
const { BillingEvents } = require('./billingEvents');
const { Configuration } = require('./configuration');
const { Passthrough_Priorities } = require('./ffsCacheManager')


class StructuredEncryptDecrypt {
  constructor({ ubiqCredentials, ubiqConfiguration }) {
    this.ubiqCredentials = ubiqCredentials;

    if (!ubiqConfiguration) {
      this.ubiqConfiguration = new Configuration();
    } else {
      this.ubiqConfiguration = ubiqConfiguration;
    }
    this.isInited = false;
    this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);
    this.ffsCacheManager = new FfsCacheManager(ubiqCredentials, this.ubiqWebServices, this.ubiqConfiguration);
    this.fpeCacheManager = new FpeCacheManager(ubiqCredentials, this.ubiqWebServices, this.ubiqConfiguration);
    // this.fpeTransactions = new FpeTransactionManager();
    this.billing_events = new BillingEvents(this.ubiqConfiguration);
    this.Ff1CacheManager = new Ff1CacheManager(this.ubiqCredentials);
    this.billingEventsProcessor = new BillingEventsProcessor(new UbiqWebServices(this.ubiqCredentials), this.billing_events, this.ubiqConfiguration);

    this.srsa = this.ubiqCredentials.secret_crypto_access_key;
  }

  // eslint doesn't like a "return await" so just to be sure, perform in two stpes
  async close() {
    // console.log(`StructuredEncryptDecrypt close   `);
    await this.billingEventsProcessor.close()
    this.billing_events = null;
  }

  // eslint doesn't like a "return await" so just to be sure, perform in two stpes
  async GetFfsConfigurationAsync(ffsname) {
    var x = await this.ffsCacheManager.GetAsync(ffsname);
    return x
  }

  // eslint doesn't like a "return await" so just to be sure, perform in two steps
  async GetFpeEncryptionKeyAsync(ffsname, keyNumber = null) {
    var x = await this.fpeCacheManager.GetAsync(ffsname, keyNumber);
    return x
  }

  EncodeKeyNum(ffs, keyNumber, str, position) {
    if (position < 0) {
      throw new Error(`Bad String decoding position for: ${str}`);
    }
    const strChars = str.split('');
    const charBuf = strChars[position];

    let ct_value = ffs.OutputCharacters.indexOf(charBuf);
    const msb_encoding_bits = ffs.MsbEncodingBits;

    ct_value += (keyNumber << msb_encoding_bits.Value);

    const ch = ffs.OutputCharacters.subString(ct_value, 1);
    strChars[position] = ch[0];
    return String(strChars);
  }

  async GetFF1(ffs, keyNumber) {
    // Only check cache once
    {
      const ctx_and_key = this.Ff1CacheManager.GetCache(ffs.name, keyNumber);
      if (ctx_and_key) {
        return ctx_and_key;
      }
    }
    // assume keynumber if -1 and check the cache with keynumber1+ffs and get the cache. :
    // example cache value = ff1
    // get ffe + keynumber = -1
    const fpe = await this.GetFpeEncryptionKeyAsync(ffs.name, keyNumber);
    // Get wrapped data key from response body
    // key_number is json field, but set value to activeKey variable
    const { encrypted_private_key, wrapped_data_key, key_number: activeKey } = fpe;

    var privateKey = forge.pki.decryptRsaPrivateKey(encrypted_private_key, this.srsa);

    return this.AddFF1(ffs, privateKey, wrapped_data_key, keyNumber, activeKey);
  }

  // Add to the cache.  Key number may not always be the same as active key.
  AddFF1(ffs, privateKey, wrapped_data_key, keyNumber, activeKey) {

    const wdk = forge.util.decode64(wrapped_data_key);
    const tweakUint8 = Uint8Array.from(Buffer.from(ffs.tweak, 'base64'));

    // Decrypt the encryped private key using @srsa supplied
    try {
      const decrypted = privateKey.decrypt(wdk, 'RSA-OAEP');
      this.keyRaw = new Uint8Array(Buffer.from(decrypted, 'binary'));
    } catch (err) {
      throw new Error('Problem decrypting ENCRYPTED private key' + err);
    }
    const ctx = new FF1(
      this.keyRaw,
      tweakUint8,
      this.tweak_min_len,
      this.tweak_max_len,
      ffs.input_character_set.length,
      ffs.input_character_set,
    );

    // If key number is NULL, then add this one again so we have for NULL and the actual active key
    this.Ff1CacheManager.SetCache(ffs.name, keyNumber, { ctx, activeKey });
    if (keyNumber === undefined || keyNumber == null) {
      this.Ff1CacheManager.SetCache(ffs.name, activeKey, { ctx, activeKey });
    }
    return { ctx, activeKey };
  }




  async EncryptAsync(ffsName, plainText, tweak) {
    try {
      let verbose = false;
      const ffs = await this.GetFfsConfigurationAsync(ffsName);

      // active key will be used during decryption
      const { ctx, activeKey } = await this.GetFF1(ffs, null);

      var x = await this.EncryptAsyncKeyNumber(ctx, ffs, plainText, tweak, activeKey);
      return x
    } catch (ex) {
      throw new Error(ex.message);
    }
  };

  parsePrefix(plainTextArr, prefix_length) {
    return [plainTextArr.slice(0, prefix_length), plainTextArr.slice(prefix_length)]
  }

  parsePrefixTrimmed(trimmed, formatted, prefix_length, passthrough) {

    let prefix_str = [];

    // Passthrough characters are ignored from the count, but added to prefix string for convenience
    let i = 0;
    while (i < prefix_length) {
      let ch = formatted.shift();
      if (passthrough.has(ch) === true) {
        prefix_str.push(ch);
      } else {
        prefix_str.push(trimmed.shift());
        i++;
      }
    }
    return [prefix_str, trimmed, formatted]
  }

  parseSuffixTrimmed(trimmed, formatted, suffix_length, passthrough) {

    let suffix_str = [];

    // Passthrough characters are ignored from the count, but added to prefix string for convenience
    let i = 0;
    while (i < suffix_length) {
      let ch = formatted.pop();
      if (passthrough.has(ch) === true) {
        suffix_str.unshift(ch);
      } else {
        suffix_str.unshift(trimmed.pop());
        i++;
      }
    }
    return [suffix_str, trimmed, formatted]
  }

  parseSuffix(plainTextArr, suffix_length) {
    return [plainTextArr.slice(plainTextArr.length - suffix_length), plainTextArr.slice(0, plainTextArr.length - suffix_length)]
  }

  trimInput(input, passthrough, zeroth_characer) {

    let trimmed = []
    let formatted = []

    for (const currentChar of input) {

      if (passthrough.has(currentChar) === false) {
        trimmed.push(currentChar);
        formatted.push(zeroth_characer);
      } else {
        formatted.push(currentChar);
      }
    }
    return [trimmed, formatted];
  }
  async EncryptAsyncKeyNumber(ctx, ffs, plainText, tweak, keyNumber) {
    let verbose = false;
    let plainTextArr = plainText.split('');
    const setInputChar = new Set(ffs.input_character_set.split(''));
    const setPassthrough = new Set(ffs.passthrough.split(''));

    let trimText = [];
    let formattedDestination = [];
    let prefix_str = [];
    let suffix_str = [];
    let passthrough_processed = false;

    for (const action of ffs.passthrough_priorities.values()) {
      if (action == Passthrough_Priorities.Prefix) {
        if (!passthrough_processed) {
          [prefix_str, plainTextArr] = this.parsePrefix(plainTextArr, ffs.prefix_length);
          if (verbose) console.log(`prefix_str: ${prefix_str}`);
          if (verbose) console.log(`plainTextArr: ${plainTextArr}`);
        } else {
          [prefix_str, trimText, formattedDestination] = this.parsePrefixTrimmed(trimText, formattedDestination, ffs.prefix_length, setPassthrough);
          if (verbose) console.log(`prefix_str: ${prefix_str}`);
          if (verbose) console.log(`trimText: ${trimText}`);
          if (verbose) console.log(`formattedDestination: ${formattedDestination}`);
        }
      } else if (action == Passthrough_Priorities.Suffix) {
        if (!passthrough_processed) {
          [suffix_str, plainTextArr] = this.parseSuffix(plainTextArr, ffs.suffix_length);
          if (verbose) console.log(`suffix_str: ${suffix_str}`);
          if (verbose) console.log(`plainTextArr: ${plainTextArr}`);
        } else {
          [suffix_str, trimText, formattedDestination] = this.parseSuffixTrimmed(trimText, formattedDestination, ffs.suffix_length, setPassthrough);
          if (verbose) console.log(`suffix_str: ${suffix_str}`);
          if (verbose) console.log(`trimText: ${trimText}`);
          if (verbose) console.log(`formattedDestination: ${formattedDestination}`);

        }
      } else if (action == Passthrough_Priorities.Passthrough) {
        passthrough_processed = true;

        [trimText, formattedDestination] = this.trimInput(plainTextArr, setPassthrough, ffs.output_character_set[0])
      }
    }

    // Wasn't a partial encryption dataset, we still need to parse da
    if (!passthrough_processed) {
      [trimText, formattedDestination] = this.trimInput(plainTextArr, setPassthrough, ffs.output_character_set[0])
    }

    // Validate trimmed is all from input characterset
    for (const ch of trimText) {
      if (setInputChar.has(ch) === false) {
        throw new Error(`invalid character found in the input:${ch}`);
      }
    }

    if (trimText.length < ffs.min_input_length || trimText.length > ffs.max_input_length) {
      throw new Error(`Invalid input len min: ${ffs.min_input_length} max: ${ffs.max_input_length}`);
    }
    const encrypted = ctx.encrypt(trimText.join(''));
    const bigNum1 = bigint_set_str(encrypted, ffs.input_character_set);
    const cipherText = bigint_get_str(ffs.output_character_set, bigNum1);
    const cipherTextPad = cipherText.padStart(trimText.length, ffs.output_character_set[0]);
    const keyNumIndex = ffs.output_character_set.indexOf(cipherTextPad[0]);
    const ct_value = keyNumIndex + (parseInt(keyNumber, 10) << ffs.msb_encoding_bits);
    const cipherTextPadArr = cipherTextPad.split('');
    cipherTextPadArr[0] = ffs.output_character_set[ct_value];
    let k = 0;
    for (let i = 0; i < formattedDestination.length; i++) {
      if (formattedDestination[i] === ffs.output_character_set[0]) {
        formattedDestination[i] = cipherTextPadArr[k];
        k++;
      }
    }

    const be = await this.billing_events.addBillingEvent(this.ubiqCredentials.access_key_id, ffs.name, "", BillingEvents.ENCRYPTION, BillingEvents.STRUCTURED, keyNumber, 1);

    return prefix_str.concat(formattedDestination).concat(suffix_str).join('');
  }

  async DecryptAsync(ffsName, cipherText, tweak) {
    try {
      let verbose = false;
      const ffs = await this.GetFfsConfigurationAsync(ffsName);
      let cipherTextPadArr = cipherText.split('');

      const setOutputChar = new Set(ffs.output_character_set.split(''));
      const setPassthrough = new Set(ffs.passthrough.split(''));

      let trimText = [];
      let formattedDestination = [];

      let prefix_str = [];
      let suffix_str = [];
      let passthrough_processed = false;

      for (const action of ffs.passthrough_priorities.values()) {
        if (action == Passthrough_Priorities.Prefix) {
          if (!passthrough_processed) {
            [prefix_str, cipherTextPadArr] = this.parsePrefix(cipherTextPadArr, ffs.prefix_length);
            if (verbose) console.log(`prefix_str: ${prefix_str}`);
            if (verbose) console.log(`cipherTextPadArr: ${cipherTextPadArr}`);
          } else {
            [prefix_str, trimText, formattedDestination] = this.parsePrefixTrimmed(trimText, formattedDestination, ffs.prefix_length, setPassthrough);
            if (verbose) console.log(`prefix_str: ${prefix_str}`);
            if (verbose) console.log(`trimText: ${trimText}`);
            if (verbose) console.log(`formattedDestination: ${formattedDestination}`);
          }
        } else if (action == Passthrough_Priorities.Suffix) {
          if (!passthrough_processed) {
            [suffix_str, cipherTextPadArr] = this.parseSuffix(cipherTextPadArr, ffs.suffix_length);
            if (verbose) console.log(`suffix_str: ${suffix_str}`);
            if (verbose) console.log(`cipherTextPadArr: ${cipherTextPadArr}`);
          } else {
            [suffix_str, trimText, formattedDestination] = this.parseSuffixTrimmed(trimText, formattedDestination, ffs.suffix_length, setPassthrough);
            if (verbose) console.log(`suffix_str: ${suffix_str}`);
            if (verbose) console.log(`trimText: ${trimText}`);
            if (verbose) console.log(`formattedDestination: ${formattedDestination}`);

          }
        } else if (action == Passthrough_Priorities.Passthrough) {
          passthrough_processed = true;

          [trimText, formattedDestination] = this.trimInput(cipherTextPadArr, setPassthrough, ffs.input_character_set[0])
        }
      }

      // Wasn't a partial encryption dataset, we still need to parse data
      if (!passthrough_processed) {
        [trimText, formattedDestination] = this.trimInput(cipherTextPadArr, setPassthrough, ffs.input_character_set[0])
      }

      // Validate trimmed is all from input characterset
      for (const ch of trimText) {
        if (setOutputChar.has(ch) === false) {
          throw new Error(`invalid character found in the input:${ch}`);
        }
      }

      let first = ffs.output_character_set.indexOf(trimText[0]);
      const activeKey = first >> ffs.msb_encoding_bits;
      first -= (activeKey << ffs.msb_encoding_bits);
      trimText[0] = ffs.output_character_set[first];

      // active key will be used during decryption
      const { ctx } = await this.GetFF1(ffs, activeKey);

      const bigNum1 = bigint_set_str(
        trimText.join(''),
        ffs.output_character_set,
      );
      const plainText = bigint_get_str(ffs.input_character_set, bigNum1);
      const plainTextPad = plainText.padStart(
        trimText.length,
        ffs.input_character_set[0],
      );
      const plainTextValue = ctx.decrypt(plainTextPad);
      let k = 0;
      for (let i = 0; i < formattedDestination.length; i++) {
        if (formattedDestination[i] === ffs.input_character_set[0]) {
          formattedDestination[i] = plainTextValue[k];
          k++;
        }
      }
      // const decryptedPlainText = formattedDestination.join('');
      const be = this.billing_events.addBillingEvent(this.ubiqCredentials.access_key_id, ffsName, "", BillingEvents.DECRYPTION, BillingEvents.STRUCTURED, activeKey, 1);
      // this.billingEventsProcessor.close();

      return prefix_str.concat(formattedDestination).concat(suffix_str).join('');
    } catch (ex) {
      throw new Error(ex.message);
    }
  }

  async EncryptForSearchAsync(ffsName, plainText, tweak) {
    try {

      // Will return the array of keys from 0 .. current_key unless the data key has been rotated too many times
      const data = await this.ubiqWebServices.GetFFSAndDataKeys(ffsName);

      var ffs = data[ffsName]['ffs']

      this.ffsCacheManager.AddToCache(ffsName, ffs)

      var encrypted_private_key = data[ffsName]['encrypted_private_key']
      var privateKey = forge.pki.decryptRsaPrivateKey(encrypted_private_key, this.srsa);

      var current_key_number = data[ffsName]['current_key_number']

      var keys = data[ffsName]['keys']

      // Add for active key (null) and actual current_key_number.
      this.AddFF1(ffs, privateKey, keys[current_key_number], null, current_key_number)

      let ct = []

      // Add of the the Dataset keys to the cache and calculate the cipher text
      for (let i = 0; i < keys.length; i++) {
        var ctx = null
        const ctx_and_key = this.Ff1CacheManager.GetCache(ffs.name, i)
        if (!ctx_and_key) {
          let ctx2 = this.AddFF1(ffs, privateKey, keys[i], i, i)
          ctx = ctx2.ctx
        } else {
          ctx = ctx_and_key.ctx
        }
        ct.push(await this.EncryptAsyncKeyNumber(ctx, ffs, plainText, tweak, i))
      }

      return ct
    } catch (ex) {
      throw new Error(ex.message);
    }
  }

  addReportingUserDefinedMetadata(jsonString) {
    this.billing_events.addUserDefinedMetadata(jsonString);
  }

  getCopyOfUsage() {
    return this.billing_events.getSerializedData();
  }

}

module.exports = {
  StructuredEncryptDecrypt
};
