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
  let plainText
  if (!ubiqCredentials) {
    ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);
  }


  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  for (const v of options.EncryptText) {
    if (verbose) { console.log(`v: ${v} ${typeof v}`) }
    ct = await ubiqEncryptDecrypt.EncryptDateAsync(
      options.FfsName,
      v,
      tweakFF1,
    );
    if (verbose) { console.log(`ct: ${ct}`) }

    plainText = await ubiqEncryptDecrypt.DecryptDateAsync(
      options.FfsName,
      ct,
      tweakFF1,
    );
    expect((new Date(plainText)).getTime()).to.equal((new Date(v)).getTime());

    const searchText = await ubiqEncryptDecrypt.EncryptDateForSearchAsync(
      options.FfsName,
      v,
      tweakFF1,
    );
    // // Make sure the supplied cipher text matches at least one of the search cipher texts
    let foundCt = false;

    for (let i = 0; i < searchText.length; i++) {
      // console.log(`ct: ${ ct }  searchText[i]${ searchText[i]}`)
      foundCt = foundCt || ((new Date(ct)).getTime() == (new Date(searchText[i])).getTime());

      const plainText = await ubiqEncryptDecrypt.DecryptDateAsync(
        options.FfsName,
        searchText[i],
        tweakFF1,
      );
      expect((new Date(plainText)).getTime()).to.equal((new Date(v)).getTime());
    }
    expect(foundCt).to.equal(true);
  }

  await ubiqEncryptDecrypt.close();

  return { cipherText, plainText };
}

it('date_Success', async () => {
  const tweakFF1 = [];

  const values = [
    new Date("0001-01-01T00:00:00Z"),
    new Date(new Date().setUTCHours(0, 0, 0, 0)),
    new Date("0001-01-01T00:00:00Z"),
    new Date(new Date().setUTCHours(0, 0, 0, 0)),
    new Date("2738-11-28T00:00:00Z")
  ]

  const options = {
    FfsName: 'date',
    EncryptText: values
  };

  await testStructuredRt({ options, tweakFF1 });
});

