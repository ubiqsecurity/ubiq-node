const { StructuredEncryptDecrypt } = require('./structuredEncryptDecrypt')

class FpeEncryptDecrypt extends StructuredEncryptDecrypt { }

/**
 * @deprecated Since version 2.2.1 and will be deleted in future version.  Use the StructuredEncryptDecrypt.DecryptAsync function instead.
 */

async function Decrypt({ ubiqCredentials, ffsname, data }) {
  const ubiqEncryptDecrypt = new StructuredEncryptDecrypt({ ubiqCredentials });
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

/**
 * @deprecated Since version 2.2.1 and will be deleted in future version.  Use the StructuredEncryptDecrypt.EncryptAsync function instead.
 */

async function Encrypt({ ubiqCredentials, ffsname, data }) {
  const ubiqEncryptDecrypt = new StructuredEncryptDecrypt({ ubiqCredentials });
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

/**
 * @deprecated Since version 2.2.1 and will be deleted in future version.  Use the StructuredEncryptDecrypt.EncryptForSearchAsync function instead.
 */

async function EncryptForSearch({ ubiqCredentials, ffsname, data }) {
  const ubiqEncryptDecrypt = new StructuredEncryptDecrypt({ ubiqCredentials });
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
  Encrypt,
  Decrypt,
  EncryptForSearch
};
