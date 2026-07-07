const cipher = require('node-forge/lib/cipher');
const { expect } = require('chai');
const { Console } = require('console');
const ubiq = require('../index');
const { TimeGranularity } = require('../lib/configuration');

const verbose = false

async function testStructuredRt({
  options, tweakFF1 = [], ubiqCredentials = null, cipherText = null, checkResult = true,
}) {
  await testBatchStructuredRt(arguments[0]);
}


async function testBatchStructuredRt({
  options, tweakFF1 = [], ubiqCredentials = null, cipherText = null, checkResult = true,
}) {
  // let verbose = true
  if (!ubiqCredentials) {
    ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);
  }


  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();
  let ct
  let plainText
  for (const v of options.EncryptText) {
    if (verbose) { console.log(`v: ${v} ${typeof v}`) }
    ct = await ubiqEncryptDecrypt.EncryptAsync(
      options.FfsName,
      v,
      tweakFF1,
    );
    if (verbose) { console.log(`ct: ${ct} typeof ${typeof ct}`) }

    plainText = await ubiqEncryptDecrypt.DecryptAsync(
      options.FfsName,
      ct,
      tweakFF1,
    );
    if (verbose) { console.log(`plainText: ${plainText} typeof ${typeof plainText}`) }

    expect(plainText).to.equal(v);

    const searchText = await ubiqEncryptDecrypt.EncryptForSearchAsync(
      options.FfsName,
      v,
      tweakFF1,
    );
    // // Make sure the supplied cipher text matches at least one of the search cipher texts
    let foundCt = false;

    for (let i = 0; i < searchText.length; i++) {
      if (verbose) { console.log(`ct: ${ct}  searchText[i]${searchText[i]}`) }
      foundCt = foundCt || (ct == searchText[i]);

      const plainText = await ubiqEncryptDecrypt.DecryptAsync(
        options.FfsName,
        searchText[i],
        tweakFF1,
      );
      expect(plainText).to.equal(v);
    }
    expect(foundCt).to.equal(true);
  }

  await ubiqEncryptDecrypt.close();

  return { cipherText, plainText };
}

it('token64_Success', async () => {
  const tweakFF1 = [];

  const values = [
    "",
    "  ",
    "123",
    "ABC",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  ]

  const options = {
    FfsName: 'token64',
    EncryptText: values
  };

  await testStructuredRt({ options, tweakFF1 });
});

it('token128_Success', async () => {
  const tweakFF1 = [];

  const values = [
    "",
    "  ",
    "123",
    "ABC",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  ]

  const options = {
    FfsName: 'token128',
    EncryptText: values
  };

  await testStructuredRt({ options, tweakFF1 });
});
