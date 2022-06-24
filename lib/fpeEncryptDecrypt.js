const { FF1, Bn } = require('ubiq-security-fpe');
const forge = require('node-forge');
const { FfsCacheManager } = require('./ffsCacheManager');
const { FpeCacheManager } = require('./fpeCacheManager');
const { UbiqWebServices } = require('./ubiqWebServices');
const { FpeTransactionManager } = require('./fpeTransactionManager');
const { FpeProcessor } = require('./fpeProcessor');
const { Ff1CacheManager } = require('./ff1CacheManager');

class FpeEncryptDecrypt {
  constructor({ ubiqCredentials }) {
    this.ubiqCredentials = ubiqCredentials;
    this.isInited = false;
    this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);
    this.ffsCacheManager = new FfsCacheManager(ubiqCredentials, this.ubiqWebServices);
    this.fpeCacheManager = new FpeCacheManager(ubiqCredentials, this.ubiqWebServices);
    this.fpeTransactions = new FpeTransactionManager(new UbiqWebServices(this.ubiqCredentials));
    this.Ff1CacheManager = new Ff1CacheManager(this.ubiqCredentials);
    this.fpeProcessor = new FpeProcessor(this.fpeTransactions, 1);
    this.srsa = this.ubiqCredentials.secret_crypto_access_key;
  }

  async GetFfsConfigurationAsync(ffsname) {
    return this.ffsCacheManager.GetAsync(ffsname);
  }

  async GetFpeEncryptionKeyAsync(ffsname, keyNumber = null) {
    return this.fpeCacheManager.GetAsync(ffsname, keyNumber);
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
    const { encrypted_private_key, wrapped_data_key, key_number: activeKey } = fpe;

    const wdk = forge.util.decode64(wrapped_data_key);
    const tweakUint8 = Uint8Array.from(Buffer.from(ffs.tweak, 'base64'));

    // Decrypt the encryped private key using @srsa supplied
    try {
      const privateKey = forge.pki.decryptRsaPrivateKey(encrypted_private_key, this.srsa);
      const decrypted = privateKey.decrypt(wdk, 'RSA-OAEP');
      this.keyRaw = new Uint8Array(Buffer.from(decrypted, 'binary'));
    } catch (err) {
      throw new Error('Problem decrypting ENCRYPTED private key');
    }
    const ctx = new FF1(
      this.keyRaw,
      tweakUint8,
      this.tweak_min_len,
      this.tweak_max_len,
      ffs.input_character_set.length,
      ffs.input_character_set,
    );
    this.Ff1CacheManager.SetCache(ffs.name, keyNumber, { ctx, activeKey });
    if (!keyNumber) {
      this.Ff1CacheManager.SetCache(ffs.name, activeKey, { ctx, activeKey });
    }
    return { ctx, activeKey };
  }

  async EncryptAsync(ffsName, plainText, tweak) {
    const ffs = await this.GetFfsConfigurationAsync(ffsName);
    // active key will be used during decryption
    const { ctx, activeKey } = await this.GetFF1(ffs, null);
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
    const ct_value = keyNumIndex + (parseInt(activeKey, 10) << ffs.msb_encoding_bits);
    const cipherTextPadArr = cipherTextPad.split('');
    cipherTextPadArr[0] = ffs.output_character_set[ct_value];
    let k = 0;
    for (let i = 0; i < formattedDestination.length; i++) {
      if (formattedDestination[i] === ffs.output_character_set[0]) {
        formattedDestination[i] = cipherTextPadArr[k];
        k++;
      }
    }
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
    return decryptedPlainText;
  }
}
async function Decrypt({ ubiqCredentials, ffsname, data }) {
  const ubiqEncryptDecrypt = new FpeEncryptDecrypt({ ubiqCredentials });
  const tweakFF1 = [];

  const plainText = await ubiqEncryptDecrypt.DecryptAsync(
    ffsname,
    data,
    tweakFF1,
  );
  return plainText;
}
async function Encrypt({ ubiqCredentials, ffsname, data }) {
  const ubiqEncryptDecrypt = new FpeEncryptDecrypt({ ubiqCredentials });
  const tweakFF1 = [];
  const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffsname,
    data,
    tweakFF1,
  );
  return cipherText;
}
module.exports = {
  FpeEncryptDecrypt,
  Decrypt,
  Encrypt,
};
