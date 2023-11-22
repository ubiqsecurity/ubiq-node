const { FF1, Bn } = require('ubiq-security-fpe');
const forge = require('node-forge');
const { FfsCacheManager } = require('./ffsCacheManager');
const { FpeCacheManager } = require('./fpeCacheManager');
const { UbiqWebServices } = require('./ubiqWebServices');
// const { FpeTransactionManager } = require('./fpeTransactionManager');
const { BillingEventsProcessor } = require('./billingEventsProcessor');
const { Ff1CacheManager } = require('./ff1CacheManager');
const { BillingEvents } = require('./billingEvents');
const { Configuration } = require('./configuration');

class FpeEncryptDecrypt {
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
    // console.log(`FpeEncryptDecrypt close   `);
    await this.billingEventsProcessor.close()
    this.billing_events = null;
  }

  // eslint doesn't like a "return await" so just to be sure, perform in two stpes
  async GetFfsConfigurationAsync(ffsname) {
    var x = await this.ffsCacheManager.GetAsync(ffsname);
    return x
  }

  // eslint doesn't like a "return await" so just to be sure, perform in two stpes
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
    const ffs = await this.GetFfsConfigurationAsync(ffsName);
    // active key will be used during decryption
    const { ctx, activeKey } = await this.GetFF1(ffs, null);

    var x = await this.EncryptAsyncKeyNumber(ctx, ffs, plainText, tweak, activeKey);
    return x
  }

  async EncryptAsyncKeyNumber(ctx, ffs, plainText, tweak, keyNumber) {

    const plainTextArr = plainText.split('');
    const setInputChar = new Set(ffs.input_character_set.split(''));
    const setPassthrough = new Set(ffs.passthrough.split(''));

    const trimText = [];
    const formattedDestination = [];

    // eslint-disable-next-line no-restricted-syntax
    for (const currentChar of plainTextArr) {
      if (setPassthrough.has(currentChar) === false) {
        if (setInputChar.has(currentChar) === false) {
          throw new Error(`invalid character found in the input:${currentChar}`);
        }
        trimText.push(currentChar);
        formattedDestination.push(ffs.output_character_set[0]);
      } else {
        formattedDestination.push(currentChar);
      }
    }
    if (trimText.length < ffs.min_input_length || trimText.length > ffs.max_input_length) {
      throw new Error(`Invalid input len min: ${ffs.min_input_length} max: ${ffs.max_input_length}`);
    }
    const encrypted = ctx.encrypt(trimText.join(''));
    const bigNum1 = Bn.bigint_set_str(encrypted, ffs.input_character_set);
    const cipherText = Bn.bigint_get_str(ffs.output_character_set, bigNum1);
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

    const be = await this.billing_events.addBillingEvent(this.ubiqCredentials.access_key_id, ffs.ffsName, "", BillingEvents.ENCRYPTION, BillingEvents.STRUCTURED, keyNumber, 1);

    return formattedDestination.join('');
  }

  async DecryptAsync(ffsName, cipherText, tweak) {
    const ffs = await this.GetFfsConfigurationAsync(ffsName);
    const cipherTextPadArr = cipherText.split('');

    const setOutputChar = new Set(ffs.output_character_set.split(''));
    const setPassthrough = new Set(ffs.passthrough.split(''));

    const cipherTrimText = [];
    const formattedDestination = [];

    // eslint-disable-next-line no-restricted-syntax
    for (const currentChar of cipherTextPadArr) {
      if (setPassthrough.has(currentChar) === false) {
        if (setOutputChar.has(currentChar) === false) {
          throw new Error(`Invalid input char:${currentChar}`);
        }
        cipherTrimText.push(currentChar);
        formattedDestination.push(ffs.input_character_set[0]);
      } else {
        formattedDestination.push(currentChar);
      }
    }
    let first = ffs.output_character_set.indexOf(cipherTrimText[0]);
    const activeKey = first >> ffs.msb_encoding_bits;
    first -= (activeKey << ffs.msb_encoding_bits);
    cipherTrimText[0] = ffs.output_character_set[first];

    // active key will be used during decryption
    const { ctx } = await this.GetFF1(ffs, activeKey);

    const bigNum1 = Bn.bigint_set_str(
      cipherTrimText.join(''),
      ffs.output_character_set,
    );
    const plainText = Bn.bigint_get_str(ffs.input_character_set, bigNum1);
    const plainTextPad = plainText.padStart(
      cipherTrimText.length,
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
    const decryptedPlainText = formattedDestination.join('');
    const be = this.billing_events.addBillingEvent(this.ubiqCredentials.access_key_id, ffsName, "", BillingEvents.DECRYPTION, BillingEvents.STRUCTURED, activeKey, 1);
    // this.billingEventsProcessor.close();

    return decryptedPlainText;
  }

  async EncryptForSearchAsync(ffsName, plainText, tweak) {

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
  }

  addReportingUserDefinedMetadata(jsonString) {
    this.billing_events.addUserDefinedMetadata(jsonString);
  }

  getCopyOfUsage() {
    return this.billing_events.getSerializedData();
  }

}

async function Decrypt({ ubiqCredentials, ffsname, data }) {
  const ubiqEncryptDecrypt = new FpeEncryptDecrypt({ ubiqCredentials });
  const tweakFF1 = [];

  try {

    var plainText = await ubiqEncryptDecrypt.DecryptAsync(
      ffsname,
      data,
      tweakFF1,
    );
  } catch (ex) {
    throw ex
  } finally {
    await ubiqEncryptDecrypt.close();
  }
  return plainText;
}

async function Encrypt({ ubiqCredentials, ffsname, data }) {
  const ubiqEncryptDecrypt = new FpeEncryptDecrypt({ ubiqCredentials });
  const tweakFF1 = [];
  try {
    var cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      ffsname,
      data,
      tweakFF1,
    );
  }
  catch (ex) {
    throw ex
  } finally {
    await ubiqEncryptDecrypt.close();
  }
  return cipherText;
}

async function EncryptForSearch({ ubiqCredentials, ffsname, data }) {
  const ubiqEncryptDecrypt = new FpeEncryptDecrypt({ ubiqCredentials });
  const tweakFF1 = [];
  try {
    var cipherText = await ubiqEncryptDecrypt.EncryptForSearchAsync(
      ffsname,
      data,
      tweakFF1,
    );
  }
  catch (ex) {
    throw ex
  } finally {
    await ubiqEncryptDecrypt.close();
  }

  return cipherText;
}

module.exports = {
  FpeEncryptDecrypt,
  Decrypt,
  Encrypt,
  EncryptForSearch
};
