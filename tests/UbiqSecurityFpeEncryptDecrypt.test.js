const cipher = require('node-forge/lib/cipher');
const ubiq = require('../index');
const { Console } = require('console');
const { TimeGranularity } = require('../lib/configuration.js')


async function testFpeRt({
  options, tweakFF1 = [], ubiqCredentials = null, cipherText = null, checkResult = true }) {

  await testBatchFpeRt(arguments[0])
  await testSimpleFpeRt(arguments[0])

}



async function testSimpleFpeRt({
  options, tweakFF1 = [], ubiqCredentials = null, cipherText = null, checkResult = true,
}) {
  if (!ubiqCredentials) {
    ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');
  }

  if (!cipherText) {
    cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: options.FfsName,
      data: options.EncryptText,
    });
  }

  let plainText = await ubiq.fpeEncryptDecrypt.Decrypt({
    ubiqCredentials: ubiqCredentials,
    ffsname: options.FfsName,
    data: cipherText,
  });


  if (checkResult) {
    expect(plainText).toBe(options.EncryptText);
  }

  const searchText = await ubiq.fpeEncryptDecrypt.EncryptForSearch({
    ubiqCredentials: ubiqCredentials,
    ffsname: options.FfsName,
    data: options.EncryptText
  });

  var foundCt = false;

  for (let i = 0; i < searchText.length; i++) {
    foundCt = foundCt || (options.CipherText == searchText[i])

    let plainText = await ubiq.fpeEncryptDecrypt.Decrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: options.FfsName,
      data: searchText[i]
    })
    expect(plainText).toBe(options.EncryptText);
  }

  expect(foundCt).toBe(true);

  return { cipherText, plainText };
}


async function testBatchFpeRt({
  options, tweakFF1 = [], ubiqCredentials = null, cipherText = null, checkResult = true,
}) {

  if (!ubiqCredentials) {
    ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');
  }

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });


  if (!cipherText) {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      options.FfsName,
      options.EncryptText,
      tweakFF1,
    );
  }

  const plainText = await ubiqEncryptDecrypt.DecryptAsync(
    options.FfsName,
    cipherText,
    tweakFF1,
  );

  if (checkResult) {
    expect(plainText).toBe(options.EncryptText);
  }

  const searchText = await ubiqEncryptDecrypt.EncryptForSearchAsync(
    options.FfsName,
    options.EncryptText,
    tweakFF1,
  );

  // Make sure the supplied cipher text matches at least one of the search cipher texts
  var foundCt = false;

  for (let i = 0; i < searchText.length; i++) {
    foundCt = foundCt || (options.CipherText == searchText[i])

    let plainText = await ubiqEncryptDecrypt.DecryptAsync(
      options.FfsName,
      searchText[i],
      tweakFF1,
    );
    expect(plainText).toBe(options.EncryptText);
  }

  expect(foundCt).toBe(true);

  await ubiqEncryptDecrypt.close();

  return { cipherText, plainText };
}


test('ALPHANUM_SSN_Success', async () => {
  const tweakFF1 = [];

  const options = {
    FfsName: 'ALPHANUM_SSN',
    EncryptText: ';0123456-789ABCDEF|',
    CipherText: ';!!!E7`+-ai1ykOp8r|',
  };
  await testFpeRt({ options, tweakFF1 });
});

test('BIRTH_DATE_Success', async () => {
  const tweakFF1 = [];

  const options = {
    FfsName: 'BIRTH_DATE',
    EncryptText: ";01\\02-1960|",
    CipherText: ";!!\\!!-oKzi|",
  };
  await testFpeRt({ options, tweakFF1 });
});

test('SSN_Success', async () => {
  const tweakFF1 = [];

  const options = {
    FfsName: 'SSN',
    EncryptText: '-0-1-2-3-4-5-6-7-8-9-',
    CipherText: '-0-0-0-0-1-I-L-8-j-D-',
  };
  await testFpeRt({ options, tweakFF1 });
});

test('UTF8_STRING_COMPLEX_Success', async () => {
  const tweakFF1 = [];

  const options = {
    FfsName: 'UTF8_STRING_COMPLEX',
    EncryptText: 'ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ',
    CipherText: 'ÑÒÓにΪΪΪΪΪΪ3ÔÕoeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはʑʒʓÏRϼĶufÝK3MXaʔʕ',
  };
  await testFpeRt({ options, tweakFF1 });
});

test('UTF8_STRING_COMPLEX_2_Success', async () => {
  const tweakFF1 = [];

  const options = {
    FfsName: 'UTF8_STRING_COMPLEX',
    EncryptText: 'ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ',
    CipherText: 'にΪΪΪΪΪΪ3oeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはÏRϼĶufÝK3MXa',
  };
  await testFpeRt({ options, tweakFF1 });
});

test('BULK_INVALID_ffs', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  // Expect an exception to skip over expect truthy
  try {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      'ERROR FFS',
      '123456789',
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('SIMPLE_INVALID_ffs', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  // Expect an exception to skip over expect truthy
  try {
    await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: 'ERROR FFS',
      data: '123456789',
    });
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }

});


test('BULK_INVALID_pt_ct', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  let ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  // Expect an exception to skip over expect truthy
  try {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      'SSN',
      ' 123456789$',
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }
  finally {
    ubiqEncryptDecrypt.close();
  }

  ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  // Expect an exception to skip over expect truthy
  try {
    cipherText = await ubiqEncryptDecrypt.DecryptAsync(
      'SSN',
      ' 123456789$',
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }
});

test('SIMPLE_INVALID_pt_ct', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  // Expect an exception to skip over expect truthy
  try {
    await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: 'SSN',
      data: ' 123456789$',
    });

    expect(false).toBeTruthy()
  }
  catch (ex) {
  }

  // Expect an exception to skip over expect truthy
  try {
    await ubiq.fpeEncryptDecrypt.Decrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: 'SSN',
      data: ' 123456789$'
    });
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }
});


test('BULK_INVALID_len', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  // Expect an exception to skip over expect truthy
  try {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      'SSN',
      '1234',
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }

  try {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      'SSN',
      '12345678901234567890',
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }
});

test('SIMPLE_INVALID_len', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  // Expect an exception to skip over expect truthy
  try {
    await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: 'SSN',
      data: '1234',
    });
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }

  try {
    await ubiq.fpeEncryptDecrypt.Decrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: 'SSN',
      data: '12345678901234567890',
    });
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }
});

test('BULK_INVALID_keynum', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });


  let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    'SSN',
    '0123456789',
    tweakFF1,
  );

  cipherText[0] = '}'
  // Expect an exception to skip over expect truthy
  try {
    plainText = await ubiqEncryptDecrypt.DecryptAsync(
      'SSN',
      cipherText,
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }
});

test('SIMPLE_INVALID_keynum', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');


  let cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
    ubiqCredentials: ubiqCredentials,
    ffsname: 'SSN',
    data: '123456789',
  });

  cipherText[0] = '}'
  // Expect an exception to skip over expect truthy
  try {
    plainText = await ubiq.fpeEncryptDecrypt.Decrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: 'SSN',
      data: cipherText
    });
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }
});


test('BULK_cached', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    'SSN',
    '0123456789',
    tweakFF1,
  );

  let cipherText2 = await ubiqEncryptDecrypt.EncryptAsync(
    'SSN',
    '0123456789',
    tweakFF1,
  );

  expect(cipherText).toBe(cipherText2)
  await ubiqEncryptDecrypt.close();
});

test('BULK_cached_2', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  const plainText = '0123456789'
  const ffs = 'SSN'
  let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  let cipherText2 = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  let pt = await ubiqEncryptDecrypt.DecryptAsync(
    ffs,
    cipherText,
    tweakFF1,
  );

  let pt2 = await ubiqEncryptDecrypt.DecryptAsync(
    ffs,
    cipherText2,
    tweakFF1,
  );

  expect(pt).toBe(pt2)
  expect(plainText).toBe(pt2)
  await ubiqEncryptDecrypt.close();
});


test('MIXED_forward', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  const plainText = ";0123456-789ABCDEF|"
  const ffs = 'ALPHANUM_SSN'

  let cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
    ubiqCredentials: ubiqCredentials,
    ffsname: ffs,
    data: plainText
  });

  let pt = await ubiqEncryptDecrypt.DecryptAsync(
    ffs,
    cipherText,
    tweakFF1,
  );

  expect(plainText).toBe(pt)
  await ubiqEncryptDecrypt.close();
});

test('MIXED_backward', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  const plainText = ";0123456-789ABCDEF|"
  const ffs = 'ALPHANUM_SSN'

  let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  let pt = await ubiq.fpeEncryptDecrypt.Decrypt({
    ubiqCredentials: ubiqCredentials,
    ffsname: ffs,
    data: cipherText
  });

  expect(plainText).toBe(pt)
  await ubiqEncryptDecrypt.close();
});


test('CREDS_invalid_papi', async () => {
  const tweakFF1 = [];

  const ubiqCredentials_orig = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqCredentials = new ubiq.Credentials(ubiqCredentials_orig.secret_signing_key,
    ubiqCredentials_orig.secret_signing_key,
    ubiqCredentials_orig.secret_crypto_access_key,
    ubiqCredentials_orig.host)

  const plainText = ";0123456-789ABCDEF|"
  const ffs = 'ALPHANUM_SSN'

  try {
    let cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: ffs,
      data: plainText
    });
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }


  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  try {
    let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      ffs,
      plainText,
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  } finally {
    ubiqEncryptDecrypt.close();
  }

});

test('CREDS_invalid_sapi', async () => {
  const tweakFF1 = [];

  const ubiqCredentials_orig = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqCredentials = new ubiq.Credentials(ubiqCredentials_orig.access_key_id,
    ubiqCredentials_orig.access_key_id,
    ubiqCredentials_orig.secret_crypto_access_key,
    ubiqCredentials_orig.host)

  const plainText = ";0123456-789ABCDEF|"
  const ffs = 'ALPHANUM_SSN'

  try {
    let cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: ffs,
      data: plainText
    });
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }


  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  try {
    let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      ffs,
      plainText,
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('CREDS_invalid_rsa', async () => {
  const tweakFF1 = [];

  const ubiqCredentials_orig = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqCredentials = new ubiq.Credentials(ubiqCredentials_orig.access_key_id,
    ubiqCredentials_orig.secret_signing_key,
    ubiqCredentials_orig.secret_signing_key,
    ubiqCredentials_orig.host)

  const plainText = ";0123456-789ABCDEF|"
  const ffs = 'ALPHANUM_SSN'

  try {
    let cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: ffs,
      data: plainText
    });
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }


  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  try {
    let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      ffs,
      plainText,
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('CREDS_invalid_host', async () => {
  const tweakFF1 = [];

  const ubiqCredentials_orig = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqCredentials = new ubiq.Credentials(ubiqCredentials_orig.access_key_id,
    ubiqCredentials_orig.secret_signing_key,
    ubiqCredentials_orig.secret_crypto_access_key,
    ubiqCredentials_orig.host.substr(0, ubiqCredentials_orig.host.length - 2))

  const plainText = ";0123456-789ABCDEF|"
  const ffs = 'ALPHANUM_SSN'

  try {
    let cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials: ubiqCredentials,
      ffsname: ffs,
      data: plainText
    });
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }


  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  try {
    let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      ffs,
      plainText,
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('BULK_INVALID_creds', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials('a', 'b', 'c', 'd')//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  // Expect an exception
  try {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      'ERROR FFS',
      '123456789',
      tweakFF1,
    );
    expect(false).toBeTruthy()
  }
  catch (ex) {
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('addUserDefinedMetdata_InvalidJson', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata("{123}")

    expect(false).toBeTruthy()
  }
  catch (ex) {
    // console.log(ex);
    expect(true).toBeTruthy()
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('addUserDefinedMetdata_EmptyString', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata("")

    expect(false).toBeTruthy()
  }
  catch (ex) {
    // console.log(ex);
    expect(true).toBeTruthy()
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }

});


test('addUserDefinedMetdata_MissingJson', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata()

    expect(false).toBeTruthy()
  }
  catch (ex) {
    // console.log(ex);
    expect(true).toBeTruthy()
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('addUserDefinedMetdata_RandomJson', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  var token = require('crypto').randomBytes(100).toString('hex');

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{"test": "' + token + '"}')

    expect(true).toBeTruthy()
  }
  catch (ex) {
    // console.log(ex);
    expect(false).toBeTruthy()
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('addUserDefinedMetdata_LongJson', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  var token = require('crypto').randomBytes(1200).toString('hex');

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{"test": "' + token + '"}')

    expect(false).toBeTruthy()
  }
  catch (ex) {
    // console.log(ex);
    expect(true).toBeTruthy()
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('addUserDefinedMetdata_EmptyJson', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata("{}")

    expect(true).toBeTruthy()
  }
  catch (ex) {
    console.log(ex);
    expect(false).toBeTruthy()
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('addUserDefinedMetdata_ValidJson', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)//'./credentials');

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{"test":"value", "array":[1,2,3,4]}')

    expect(true).toBeTruthy()
  }
  catch (ex) {
    console.log(ex);
    expect(false).toBeTruthy()
  }
  finally {
    await ubiqEncryptDecrypt.close();
  }

});

test('Structured_GetCopyOfUsage_Minutes', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)
  var config = new ubiq.Configuration();
  config.event_reporting_wake_interval = 10;
  config.event_reporting_minimum_count = 10;
  config.event_reporting_timestamp_granularity = TimeGranularity.MINUTES // ending should be :00.000Z

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials: ubiqCredentials, ubiqConfiguration: config })
  ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[1,2,3,4]}')

  const plainText = ";0123456-789ABCDEF|"
  const ffs = 'ALPHANUM_SSN'

  let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  let str = ubiqEncryptDecrypt.getCopyOfUsage();
  let s = JSON.stringify(str.usage[0].user_defined.test).toString()
  let found = s.match(/Gary Schneir/);
  expect(found != null).toBeTruthy
  found = s.match(/:00.000Z/);
  expect(found != null).toBeTruthy

  await ubiqEncryptDecrypt.close();
});

test('Structured_GetCopyOfUsage_DAYS', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)
  var config = new ubiq.Configuration();
  config.event_reporting_wake_interval = 10;
  config.event_reporting_minimum_count = 10;
  config.event_reporting_timestamp_granularity = TimeGranularity.DAYS // ending should be :00.000Z

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials: ubiqCredentials, ubiqConfiguration: config })
  ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[1,2,3,4]}')

  const plainText = ";0123456-789ABCDEF|"
  const ffs = 'ALPHANUM_SSN'

  let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  let str = ubiqEncryptDecrypt.getCopyOfUsage();
  let s = JSON.stringify(str.usage[0].user_defined.test).toString()
  let found = s.match(/Gary Schneir/);
  expect(found != null).toBeTruthy
  found = s.match(/00:00:00.000Z/);
  expect(found != null).toBeTruthy

  await ubiqEncryptDecrypt.close();
});

test('Structured_GetCopyOfUsage_Missing', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = new ubiq.Credentials(null, null, null, null)
  var config = new ubiq.Configuration();
  config.event_reporting_wake_interval = 10;
  config.event_reporting_minimum_count = 10;

  const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials: ubiqCredentials, ubiqConfiguration: config })

  const plainText = ";0123456-789ABCDEF|"
  const ffs = 'ALPHANUM_SSN'

  let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  let str = ubiqEncryptDecrypt.getCopyOfUsage();
  expect(str.usage[0] != null).toBeTruthy

  await ubiqEncryptDecrypt.close();
});

