const cipher = require('node-forge/lib/cipher');
const { expect } = require('chai');
const { Console } = require('console');
const ubiq = require('../index');
const { TimeGranularity } = require('../lib/configuration');

async function testStructuredRt({
  options, tweakFF1 = [], ubiqCredentials = null, cipherText = null, checkResult = true,
}) {
  await testBatchStructuredRt(arguments[0]);
  await testSimpleStructuredRt(arguments[0]);
}

async function testSimpleStructuredRt({
  options, tweakFF1 = [], ubiqCredentials = null, cipherText = null, checkResult = true,
}) {
  if (!ubiqCredentials) {
    ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);
  }

  if (!cipherText) {
    cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials,
      ffsname: options.FfsName,
      data: options.EncryptText,
    });
  }

  const plainText = await ubiq.fpeEncryptDecrypt.Decrypt({
    ubiqCredentials,
    ffsname: options.FfsName,
    data: cipherText,
  });

  if (checkResult) {
    expect(plainText).to.equal(options.EncryptText);
  }

  const searchText = await ubiq.fpeEncryptDecrypt.EncryptForSearch({
    ubiqCredentials,
    ffsname: options.FfsName,
    data: options.EncryptText,
  });

  let foundCt = false;

  for (let i = 0; i < searchText.length; i++) {
    foundCt = foundCt || (options.CipherText == searchText[i]);

    const plainText = await ubiq.fpeEncryptDecrypt.Decrypt({
      ubiqCredentials,
      ffsname: options.FfsName,
      data: searchText[i],
    });
    expect(plainText).to.equal(options.EncryptText);
  }

  expect(foundCt).to.equal(true);

  return { cipherText, plainText };
}

async function testBatchStructuredRt({
  options, tweakFF1 = [], ubiqCredentials = null, cipherText = null, checkResult = true,
}) {
  if (!ubiqCredentials) {
    ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);
  }

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

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
    expect(plainText).to.equal(options.EncryptText);
  }

  const searchText = await ubiqEncryptDecrypt.EncryptForSearchAsync(
    options.FfsName,
    options.EncryptText,
    tweakFF1,
  );

  // Make sure the supplied cipher text matches at least one of the search cipher texts
  let foundCt = false;

  for (let i = 0; i < searchText.length; i++) {
    foundCt = foundCt || (options.CipherText == searchText[i]);

    const plainText = await ubiqEncryptDecrypt.DecryptAsync(
      options.FfsName,
      searchText[i],
      tweakFF1,
    );
    expect(plainText).to.equal(options.EncryptText);
  }

  expect(foundCt).to.equal(true);

  await ubiqEncryptDecrypt.close();

  return { cipherText, plainText };
}

it('ALPHANUM_SSN_Success', async () => {
  const tweakFF1 = [];

  const options = {
    FfsName: 'ALPHANUM_SSN',
    EncryptText: ';0123456-789ABCDEF|',
    CipherText: ';!!!E7`+-ai1ykOp8r|',
  };

  await testStructuredRt({ options, tweakFF1 });
});

it('BIRTH_DATE_Success', async () => {
  const tweakFF1 = [];

  const options = {
    FfsName: 'BIRTH_DATE',
    EncryptText: ';01\\02-1960|',
    CipherText: ';!!\\!!-oKzi|',
  };
  await testStructuredRt({ options, tweakFF1 });
});

it('SSN_Success', async () => {
  const tweakFF1 = [];

  const options = {
    FfsName: 'SSN',
    EncryptText: '-0-1-2-3-4-5-6-7-8-9-',
    CipherText: '-0-0-0-0-1-I-L-8-j-D-',
  };
  await testStructuredRt({ options, tweakFF1 });
});

it('UTF8_STRING_COMPLEX_Success', async () => {
  const tweakFF1 = [];

  const options = {
    FfsName: 'UTF8_STRING_COMPLEX',
    EncryptText: 'ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ',
    CipherText: 'ÑÒÓにΪΪΪΪΪΪ3ÔÕoeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはʑʒʓÏRϼĶufÝK3MXaʔʕ',
  };
  await testStructuredRt({ options, tweakFF1 });
});

it('UTF8_STRING_COMPLEX_2_Success', async () => {
  const tweakFF1 = [];

  const options = {
    FfsName: 'UTF8_STRING_COMPLEX',
    EncryptText: 'ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ',
    CipherText: 'にΪΪΪΪΪΪ3oeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはÏRϼĶufÝK3MXa',
  };
  await testStructuredRt({ options, tweakFF1 });
});

it('BULK_INVALID_ffs', async () => {
  const tweakFF1 = [];

  ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  // Expect an exception to skip over expect truthy
  try {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      'ERROR FFS',
      '123456789',
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('SIMPLE_INVALID_ffs', async () => {
  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  // Expect an exception to skip over expect truthy
  try {
    await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials,
      ffsname: 'ERROR FFS',
      data: '123456789',
    });
    expect(false).to.equal(true);
  } catch (ex) {
  }
});

it('BULK_INVALID_pt_ct', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  let ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  // Expect an exception to skip over expect truthy
  try {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      'SSN',
      ' 123456789$',
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    ubiqEncryptDecrypt.close();
  }

  ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  // Expect an exception to skip over expect truthy
  try {
    cipherText = await ubiqEncryptDecrypt.DecryptAsync(
      'SSN',
      ' 123456789$',
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('SIMPLE_INVALID_pt_ct', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  // Expect an exception to skip over expect truthy
  try {
    await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials,
      ffsname: 'SSN',
      data: ' 123456789$',
    });

    expect(false).to.equal(true);
  } catch (ex) {
  }

  // Expect an exception to skip over expect truthy
  try {
    await ubiq.fpeEncryptDecrypt.Decrypt({
      ubiqCredentials,
      ffsname: 'SSN',
      data: ' 123456789$',
    });
    expect(false).to.equal(true);
  } catch (ex) {
  }
});

it('BULK_INVALID_len', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  // Expect an exception to skip over expect truthy
  try {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      'SSN',
      '1234',
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }

  try {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      'SSN',
      '12345678901234567890',
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('SIMPLE_INVALID_len', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  // Expect an exception to skip over expect truthy
  try {
    await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials,
      ffsname: 'SSN',
      data: '1234',
    });
    expect(false).to.equal(true);
  } catch (ex) {
  }

  try {
    await ubiq.fpeEncryptDecrypt.Decrypt({
      ubiqCredentials,
      ffsname: 'SSN',
      data: '12345678901234567890',
    });
    expect(false).to.equal(true);
  } catch (ex) {
  }
});

it('BULK_INVALID_keynum', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    'SSN',
    '0123456789',
    tweakFF1,
  );

  cipherText[0] = '}';
  // Expect an exception to skip over expect truthy
  try {
    plainText = await ubiqEncryptDecrypt.DecryptAsync(
      'SSN',
      cipherText,
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('SIMPLE_INVALID_keynum', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
    ubiqCredentials,
    ffsname: 'SSN',
    data: '123456789',
  });

  cipherText[0] = '}';
  // Expect an exception to skip over expect truthy
  try {
    plainText = await ubiq.fpeEncryptDecrypt.Decrypt({
      ubiqCredentials,
      ffsname: 'SSN',
      data: cipherText,
    });
    expect(false).to.equal(true);
  } catch (ex) {
  }
});

it('BULK_cached', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    'SSN',
    '0123456789',
    tweakFF1,
  );

  const cipherText2 = await ubiqEncryptDecrypt.EncryptAsync(
    'SSN',
    '0123456789',
    tweakFF1,
  );

  expect(cipherText).to.equal(cipherText2);
  await ubiqEncryptDecrypt.close();
});

it('BULK_cached_2', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  const plainText = '0123456789';
  const ffs = 'SSN';
  const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  const cipherText2 = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  const pt = await ubiqEncryptDecrypt.DecryptAsync(
    ffs,
    cipherText,
    tweakFF1,
  );

  const pt2 = await ubiqEncryptDecrypt.DecryptAsync(
    ffs,
    cipherText2,
    tweakFF1,
  );

  expect(pt).to.equal(pt2);
  expect(plainText).to.equal(pt2);
  await ubiqEncryptDecrypt.close();
});

it('MIXED_forward', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  const plainText = ';0123456-789ABCDEF|';
  const ffs = 'ALPHANUM_SSN';

  const cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
    ubiqCredentials,
    ffsname: ffs,
    data: plainText,
  });

  const pt = await ubiqEncryptDecrypt.DecryptAsync(
    ffs,
    cipherText,
    tweakFF1,
  );

  expect(plainText).to.equal(pt);
  await ubiqEncryptDecrypt.close();
});

it('MIXED_backward', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  const plainText = ';0123456-789ABCDEF|';
  const ffs = 'ALPHANUM_SSN';

  const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  const pt = await ubiq.fpeEncryptDecrypt.Decrypt({
    ubiqCredentials,
    ffsname: ffs,
    data: cipherText,
  });

  expect(plainText).to.equal(pt);
  await ubiqEncryptDecrypt.close();
});

it('CREDS_invalid_papi', async () => {
  const tweakFF1 = [];

  const ubiqCredentials_orig = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(
    ubiqCredentials_orig.secret_signing_key,
    ubiqCredentials_orig.secret_signing_key,
    ubiqCredentials_orig.secret_crypto_access_key,
    ubiqCredentials_orig.host,
  );

  const plainText = ';0123456-789ABCDEF|';
  const ffs = 'ALPHANUM_SSN';

  try {
    const cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials,
      ffsname: ffs,
      data: plainText,
    });
    expect(false).to.equal(true);
  } catch (ex) {
  }

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  try {
    const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      ffs,
      plainText,
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    ubiqEncryptDecrypt.close();
  }
});

it('CREDS_invalid_sapi', async () => {
  const tweakFF1 = [];

  const ubiqCredentials_orig = ubiq.UbiqFactory.createCredentials(null, null, null, null);// './credentials');

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(
    ubiqCredentials_orig.access_key_id,
    ubiqCredentials_orig.access_key_id,
    ubiqCredentials_orig.secret_crypto_access_key,
    ubiqCredentials_orig.host,
  );

  const plainText = ';0123456-789ABCDEF|';
  const ffs = 'ALPHANUM_SSN';

  try {
    const cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials,
      ffsname: ffs,
      data: plainText,
    });
    expect(false).to.equal(true);
  } catch (ex) {
  }

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  try {
    const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      ffs,
      plainText,
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('CREDS_invalid_rsa', async () => {
  const tweakFF1 = [];

  const ubiqCredentials_orig = ubiq.UbiqFactory.createCredentials(null, null, null, null);// './credentials');

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(
    ubiqCredentials_orig.access_key_id,
    ubiqCredentials_orig.secret_signing_key,
    ubiqCredentials_orig.secret_signing_key,
    ubiqCredentials_orig.host,
  );

  const plainText = ';0123456-789ABCDEF|';
  const ffs = 'ALPHANUM_SSN';

  try {
    const cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials,
      ffsname: ffs,
      data: plainText,
    });
    expect(false).to.equal(true);
  } catch (ex) {
  }

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  try {
    const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      ffs,
      plainText,
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('CREDS_invalid_host', async () => {
  const tweakFF1 = [];

  const ubiqCredentials_orig = ubiq.UbiqFactory.createCredentials(null, null, null, null);// './credentials');

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(
    ubiqCredentials_orig.access_key_id,
    ubiqCredentials_orig.secret_signing_key,
    ubiqCredentials_orig.secret_crypto_access_key,
    ubiqCredentials_orig.host.substr(0, ubiqCredentials_orig.host.length - 2),
  );

  const plainText = ';0123456-789ABCDEF|';
  const ffs = 'ALPHANUM_SSN';

  try {
    const cipherText = await ubiq.fpeEncryptDecrypt.Encrypt({
      ubiqCredentials,
      ffsname: ffs,
      data: plainText,
    });
    expect(false).to.equal(true);
  } catch (ex) {
  }

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  try {
    const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      ffs,
      plainText,
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('BULK_INVALID_creds', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials('a', 'b', 'c', 'd');// './credentials');

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  // Expect an exception
  try {
    cipherText = await ubiqEncryptDecrypt.EncryptAsync(
      'ERROR FFS',
      '123456789',
      tweakFF1,
    );
    expect(false).to.equal(true);
  } catch (ex) {
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('addUserDefinedMetdata_InvalidJson', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);// './credentials');

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{123}');

    expect(false).to.equal(true);
  } catch (ex) {
    // console.log(ex);
    expect(true).to.equal(true);
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('addUserDefinedMetdata_EmptyString', async () => {
  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata('');

    expect(false).to.equal(true);
  } catch (ex) {
    // console.log(ex);
    expect(true).to.equal(true);
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('addUserDefinedMetdata_MissingJson', async () => {
  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata();

    expect(false).to.equal(true);
  } catch (ex) {
    // console.log(ex);
    expect(true).to.equal(true);
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('addUserDefinedMetdata_RandomJson', async () => {
  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);// './credentials');

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  const token = require('crypto').randomBytes(100).toString('hex');

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata(`{"test": "${token}"}`);

    expect(true).to.equal(true);
  } catch (ex) {
    // console.log(ex);
    expect(false).to.equal(true);
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('addUserDefinedMetdata_LongJson', async () => {
  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);// './credentials');

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  const token = require('crypto').randomBytes(1200).toString('hex');

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata(`{"test": "${token}"}`);

    expect(false).to.equal(true);
  } catch (ex) {
    // console.log(ex);
    expect(true).to.equal(true);
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('addUserDefinedMetdata_EmptyJson', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);// './credentials');

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{}');

    expect(true).to.equal(true);
  } catch (ex) {
    console.log(ex);
    expect(false).to.equal(true);
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('addUserDefinedMetdata_ValidJson', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);// './credentials');

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).buildStructuredAsync();

  // Expect no exception
  try {
    ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{"test":"value", "array":[1,2,3,4]}');

    expect(true).to.equal(true);
  } catch (ex) {
    console.log(ex);
    expect(false).to.equal(true);
  } finally {
    await ubiqEncryptDecrypt.close();
  }
});

it('Structured_GetCopyOfUsage_Minutes', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);
  const config = ubiq.UbiqFactory.defaultConfiguration()
  config.event_reporting_wake_interval = 10;
  config.event_reporting_minimum_count = 10;
  config.event_reporting_timestamp_granularity = TimeGranularity.MINUTES; // ending should be :00.000Z

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).withConfigurationObject(config).buildStructuredAsync();

  ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[1,2,3,4]}');

  const plainText = ';0123456-789ABCDEF|';
  const ffs = 'ALPHANUM_SSN';

  const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  const str = ubiqEncryptDecrypt.getCopyOfUsage();
  const s = JSON.stringify(str.usage[0].user_defined.test).toString();
  const found = s.match(/Gary Schneir/);
  expect(found != null).to.equal(true);

  await ubiqEncryptDecrypt.close();
});

it('Structured_GetCopyOfUsage_DAYS', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);
  const config = ubiq.UbiqFactory.defaultConfiguration()
  config.event_reporting_wake_interval = 10;
  config.event_reporting_minimum_count = 10;
  config.event_reporting_timestamp_granularity = TimeGranularity.DAYS; // ending should be :00.000Z

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).withConfigurationObject(config).buildStructuredAsync();

  ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[1,2,3,4]}');

  const plainText = ';0123456-789ABCDEF|';
  const ffs = 'ALPHANUM_SSN';

  const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  const str = ubiqEncryptDecrypt.getCopyOfUsage();
  const s = JSON.stringify(str.usage[0].user_defined.test).toString();
  const found = s.match(/Gary Schneir/);
  expect(found).to.not.be.null;

  await ubiqEncryptDecrypt.close();
});

it('Structured_GetCopyOfUsage_Missing', async () => {
  const tweakFF1 = [];

  const ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);
  const config = ubiq.UbiqFactory.defaultConfiguration()
  config.event_reporting_wake_interval = 10;
  config.event_reporting_minimum_count = 10;

  const ubiqEncryptDecrypt = await (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).withConfigurationObject(config).buildStructuredAsync();

  const plainText = ';0123456-789ABCDEF|';
  const ffs = 'ALPHANUM_SSN';

  const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    ffs,
    plainText,
    tweakFF1,
  );

  const str = ubiqEncryptDecrypt.getCopyOfUsage();

  expect(str.usage[0] != null).to.equal(true);

  await ubiqEncryptDecrypt.close();
});
