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
  let plainText
  if (!ubiqCredentials) {
    ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);
  }


  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  for (const v of options.EncryptText) {
    if (verbose) { console.log(`v: ${v} ${typeof v}`) }
    ct = await ubiqEncryptDecrypt.EncryptDateTimeAsync(
      options.FfsName,
      v,
      tweakFF1,
    );
    if (verbose) { console.log(`ct: ${ct}`) }

    plainText = await ubiqEncryptDecrypt.DecryptDateTimeAsync(
      options.FfsName,
      ct,
      tweakFF1,
    );
    // const p = (new Date(plainText)).getTime()
    // const o = (new Date(v)).getTime()
    // console.log(`p: ${p} ${new Date(plainText)}`)
    // console.log(`o: ${o} ${new Date(v)}`)
    expect((new Date(plainText)).getTime()).to.equal((new Date(v)).getTime());

    const searchText = await ubiqEncryptDecrypt.EncryptDateTimeForSearchAsync(
      options.FfsName,
      v,
      tweakFF1,
    );
    // // Make sure the supplied cipher text matches at least one of the search cipher texts
    let foundCt = false;

    for (let i = 0; i < searchText.length; i++) {
      // console.log(`ct: ${ ct }  searchText[i]${ searchText[i]}`)
      foundCt = foundCt || ((new Date(ct)).getTime() == (new Date(searchText[i])).getTime());

      const plainText = await ubiqEncryptDecrypt.DecryptDateTimeAsync(
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

it('datetime_Success', async () => {
  const tweakFF1 = [];

  const values = [
    new Date("1653-02-10T06:13:21.000+00:00"),
    new Date(new Date().setUTCMilliseconds(0)),
    new Date("1970-01-01T00:00:00Z"),
    new Date(new Date().setUTCMilliseconds(0)),
    new Date("2286-11-20T17:46:39.000+00:00")
  ]

  const options = {
    FfsName: 'datetime',
    EncryptText: values
  };

  await testStructuredRt({ options, tweakFF1 });
});

