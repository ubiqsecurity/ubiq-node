const { expect } = require('chai');
const ubiq = require('../index');
const { TimeGranularity } = require('../lib/configuration');

async function testRt({ options }) {
  await testBatchRt(arguments[0]);
  await testSimpleRt(arguments[0]);
}

async function testSimpleRt({
  options,
}) {
  ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  cipherText = await ubiq.encrypt(ubiqCredentials, options.plainText);

  const plainText = await ubiq.decrypt(ubiqCredentials, cipherText);

  expect(plainText).to.equal(options.plainText);
}

async function testBatchRt({ options }) {
  ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);
  builder = (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).withConfigurationDefault();
  const enc = await builder.buildEncryptionAsync();

  enc.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[1,2,3,4], "Encrypting":true}');
  const data_begin = enc.begin();

  const data = enc.update(Buffer.from(options.plainText, 'utf-8'));

  const data_end = enc.end();
  await enc.close();

  // Uses same credentials and config as above
  const dec = await builder.buildDecryptionAsync();
  dec.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[5,6,7], "Decrypting":true}');

  const pt_begin = dec.begin();
  // var pt_mid = await dec.update(y);
  const pt_mid = await dec.update(Buffer.concat([data_begin, data, data_end]));
  const pt_end = dec.end();
  await dec.close();

  expect(options.plainText).to.equal(pt_begin + pt_mid + pt_end);
}

it('Test_small', async () => {
  const options = {
    plainText: 'ABC',
    uses: 1,
  };
  await testRt({ options });
});

it('Test_block_size', async () => {
  const options = {
    plainText: 'ABCDEFGHIJKLMNOP',
    uses: 2,
  };
  await testRt({ options });
});

it('Test_block_size_2xm1', async () => {
  const options = {
    plainText: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ01234',
    uses: 3,
  };
  await testRt({ options });
});

it('Test_block_size_2x', async () => {
  const options = {
    plainText: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345',
    uses: 4,
  };
  await testRt({ options });
});

it('Test_block_size_2xp1', async () => {
  const options = {
    plainText: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456',
    uses: 5,
  };
  await testRt({ options });
});

it('Unstructured_GetCopyOfUsage', async () => {
  ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  builder = (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).withConfigurationDefault();

  const enc = await builder.buildEncryptionAsync();

  enc.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[1,2,3,4], "Encrypting":true}');
  const data_begin = enc.begin();

  const data = enc.update(Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456', 'utf-8'));

  const data_end = enc.end();

  let str = enc.getCopyOfUsage();
  let s = JSON.stringify(str.usage[0].user_defined.test).toString();
  let found = s.match(/Gary Schneir/);
  expect(found != null).to.equal(true);

  await enc.close();

  const dec = await builder.buildDecryptionAsync();
  dec.addReportingUserDefinedMetadata('{"test":"gARY sCHNEIR", "array":[5,6,7], "Decrypting":true}');

  const pt_begin = dec.begin();
  const pt_mid = await dec.update(Buffer.concat([data_begin, data, data_end]));
  const pt_end = dec.end();

  str = dec.getCopyOfUsage();
  s = JSON.stringify(str.usage[0].user_defined.test).toString();
  found = s.match(/gARY sCHNEIR/);
  expect(found != null).to.equal(true);

  await dec.close();
});

it('Unstructured_GetCopyOfUsage_Missing', async () => {
  ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  builder = (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).withConfigurationDefault();
  const enc = await builder.buildEncryptionAsync();
  const data_begin = enc.begin();

  const data = enc.update(Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456', 'utf-8'));

  const data_end = enc.end();

  let str = enc.getCopyOfUsage();
  expect(str.usage[0] != null).to.equal(true);

  await enc.close();

  const dec = await builder.buildDecryptionAsync();

  const pt_begin = dec.begin();
  const pt_mid = await dec.update(Buffer.concat([data_begin, data, data_end]));
  const pt_end = dec.end();

  str = dec.getCopyOfUsage();
  expect(str.usage[0] != null).to.equal(true);

  await dec.close();
});

it('Unstructured_GetCopyOfUsage_Minutes', async () => {
  ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);

  const config = ubiq.UbiqFactory.defaultConfiguration();

  config.event_reporting_wake_interval = 10;
  config.event_reporting_minimum_count = 10;
  config.event_reporting_timestamp_granularity = TimeGranularity.MINUTES; // ending should be :00.000Z

  builder = (new ubiq.CryptographyBuilder()).withCredentialsObject(ubiqCredentials).withConfigurationObject(config);

  const enc = await builder.buildEncryptionAsync();

  enc.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[1,2,3,4], "Encrypting":true}');
  const data_begin = enc.begin();

  const data = enc.update(Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456', 'utf-8'));

  const data_end = enc.end();

  let str = enc.getCopyOfUsage();
  let s = JSON.stringify(str.usage[0].user_defined.test).toString();
  let found = s.match(/Gary Schneir/);
  expect(found != null).to.equal(true);

  await enc.close();

  config.event_reporting_timestamp_granularity = TimeGranularity.DAYS; // ending should be :00.000Z
  builder.withConfigurationObject(config);
  const dec = await builder.buildDecryptionAsync();

  dec.addReportingUserDefinedMetadata('{"test":"gARY sCHNEIR", "array":[5,6,7], "Decrypting":true}');

  const pt_begin = dec.begin();
  const pt_mid = await dec.update(Buffer.concat([data_begin, data, data_end]));
  const pt_end = dec.end();

  str = dec.getCopyOfUsage();
  s = JSON.stringify(str.usage[0].user_defined.test).toString();
  found = s.match(/gARY sCHNEIR/);
  expect(found != null).to.equal(true);

  await dec.close();
});

it('Configuration_default', async () => {
  // Default
  const config = ubiq.UbiqFactory.defaultConfiguration();

  expect(config.key_caching_unstructured).to.equal(true);
  expect(config.key_caching_encrypt).to.equal(false);
  expect(config.idp_type).to.equal('');
});

it('Configuration_file', async () => {
  // explicit value
  const config = ubiq.UbiqFactory.readConfigurationFromFile('./tests/configuration-key-cache');

  expect(config.key_caching_unstructured).to.equal(false);
  expect(config.key_caching_encrypt).to.equal(true);
  expect(config.idp_type).to.equal('entra');
  expect(config.idp_customer_id).to.equal('Ubiq');
  expect(config.idp_client_secret).to.equal('');
});

it('Credentials', async () => {
  ubiqCredentials = ubiq.UbiqFactory.createCredentialsWithIdp('user@ubiqsecurity.com', 'password', 'host');

  expect(ubiqCredentials.idp_username).to.equal('user@ubiqsecurity.com');
  expect(ubiqCredentials.idp_password).to.equal('password');
});

it('Credentials_no_idp', async () => {
  try {
    ubiqCredentials = ubiq.UbiqFactory.createCredentials(null, null, null, null);
    expect(ubiqCredentials.idp_username).to.equal('');
    expect(ubiqCredentials.idp_password).to.equal('');
  } catch (ex) {
    // Should not fail since env variables will have valid access ID
    expect(false).to.equal(true);
  }
});
