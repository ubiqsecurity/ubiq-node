const cipher = require('node-forge/lib/cipher');
const ubiq = require('../index');
const { TimeGranularity } = require('../lib/configuration.js')


async function testRt({
  options }) {

  await testBatchRt(arguments[0])
  await testSimpleRt(arguments[0])
}



async function testSimpleRt({
  options
}) {
  ubiqCredentials = new ubiq.Credentials(null, null, null, null)

  cipherText = await ubiq.encrypt(ubiqCredentials, options.plainText);

  let plainText = await ubiq.decrypt(ubiqCredentials, cipherText);

  expect(plainText).toBe(options.plainText);

}


async function testBatchRt({
  options }) {

  ubiqCredentials = new ubiq.Credentials(null, null, null, null)

  const enc = await new ubiq.Encryption(ubiqConfiguration = ubiqCredentials, options.uses);
  enc.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[1,2,3,4], "Encrypting":true}')
  var data_begin = enc.begin();

  var data = enc.update(Buffer.from(options.plainText, 'utf-8'))

  var data_end = enc.end();
  enc.close();

  const dec = new ubiq.Decryption(ubiqConfiguration = ubiqCredentials);
  dec.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[5,6,7], "Decrypting":true}')

  var pt_begin = dec.begin()
  // var pt_mid = await dec.update(y);
  var pt_mid = await dec.update(Buffer.concat([data_begin, data, data_end]));
  var pt_end = dec.end();
  await dec.close()

  expect(options.plainText).toBe(pt_begin + pt_mid + pt_end);
}

test('Test_small', async () => {

  const options = {
    plainText: 'ABC',
    uses: 1
  };
  await testRt({ options });
});

test('Test_block_size', async () => {

  const options = {
    plainText: 'ABCDEFGHIJKLMNOP',
    uses: 2
  };
  await testRt({ options });
});

test('Test_block_size_2xm1', async () => {

  const options = {
    plainText: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ01234',
    uses: 3
  };
  await testRt({ options });
});

test('Test_block_size_2x', async () => {

  const options = {
    plainText: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345',
    uses: 4
  };
  await testRt({ options });
});

test('Test_block_size_2xp1', async () => {

  const options = {
    plainText: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456',
    uses: 5
  };
  await testRt({ options });
});

test('Unstructured_GetCopyOfUsage', async () => {

  ubiqCredentials = new ubiq.Credentials(null, null, null, null)

  const enc = await new ubiq.Encryption(ubiqConfiguration = ubiqCredentials, 1);
  enc.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[1,2,3,4], "Encrypting":true}')
  var data_begin = enc.begin();

  var data = enc.update(Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456', 'utf-8'))

  var data_end = enc.end();

  let str = enc.getCopyOfUsage();
  let s = JSON.stringify(str.usage[0].user_defined.test).toString()
  let found = s.match(/Gary Schneir/);
  expect(found != null).toBeTruthy

  enc.close();

  const dec = new ubiq.Decryption(ubiqConfiguration = ubiqCredentials);
  dec.addReportingUserDefinedMetadata('{"test":"gARY sCHNEIR", "array":[5,6,7], "Decrypting":true}')

  var pt_begin = dec.begin()
  var pt_mid = await dec.update(Buffer.concat([data_begin, data, data_end]));
  var pt_end = dec.end();

  str = dec.getCopyOfUsage();
  s = JSON.stringify(str.usage[0].user_defined.test).toString()
  found = s.match(/gARY sCHNEIR/);
  expect(found != null).toBeTruthy

  await dec.close()

});


test('Unstructured_GetCopyOfUsage_Missing', async () => {

  ubiqCredentials = new ubiq.Credentials(null, null, null, null)

  const enc = await new ubiq.Encryption(ubiqConfiguration = ubiqCredentials, 1);
  var data_begin = enc.begin();

  var data = enc.update(Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456', 'utf-8'))

  var data_end = enc.end();

  let str = enc.getCopyOfUsage();
  expect(str.usage[0] != null).toBeTruthy

  enc.close();

  const dec = new ubiq.Decryption(ubiqConfiguration = ubiqCredentials);

  var pt_begin = dec.begin()
  var pt_mid = await dec.update(Buffer.concat([data_begin, data, data_end]));
  var pt_end = dec.end();

  str = dec.getCopyOfUsage();
  expect(str.usage[0] != null).toBeTruthy

  await dec.close()

});



test('Unstructured_GetCopyOfUsage_Minutes', async () => {

  ubiqCredentials = new ubiq.Credentials(null, null, null, null)
  var config = new ubiq.Configuration();
  config.event_reporting_wake_interval = 10;
  config.event_reporting_minimum_count = 10;
  config.event_reporting_timestamp_granularity = TimeGranularity.MINUTES // ending should be :00.000Z
  const enc = await new ubiq.Encryption(params = ubiqCredentials, uses = 1, ubiqConfiguration = config);
  enc.addReportingUserDefinedMetadata('{"test":"Gary Schneir", "array":[1,2,3,4], "Encrypting":true}')
  var data_begin = enc.begin();

  var data = enc.update(Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456', 'utf-8'))

  var data_end = enc.end();

  let str = enc.getCopyOfUsage();
  let s = JSON.stringify(str.usage[0].user_defined.test).toString()
  let found = s.match(/Gary Schneir/);
  expect(found != null).toBeTruthy
  found = s.match(/00:00.000Z/);
  expect(found != null).toBeTruthy

  enc.close();

  config.event_reporting_timestamp_granularity = TimeGranularity.DAYS // ending should be :00.000Z
  const dec = new ubiq.Decryption(ubiqConfiguration = ubiqCredentials, ubiqConfiguration = config);
  dec.addReportingUserDefinedMetadata('{"test":"gARY sCHNEIR", "array":[5,6,7], "Decrypting":true}')

  var pt_begin = dec.begin()
  var pt_mid = await dec.update(Buffer.concat([data_begin, data, data_end]));
  var pt_end = dec.end();

  str = dec.getCopyOfUsage();
  s = JSON.stringify(str.usage[0].user_defined.test).toString()
  found = s.match(/gARY sCHNEIR/);
  expect(found != null).toBeTruthy
  found = s.match(/00:00:00.000Z/);
  expect(found != null).toBeTruthy

  await dec.close()

});