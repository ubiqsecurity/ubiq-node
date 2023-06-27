const cipher = require('node-forge/lib/cipher');
const ubiq = require('../index');


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
  var data_begin = enc.begin();

  var data = enc.update(Buffer.from(options.plainText, 'utf-8'))

  var data_end = enc.end();
  enc.close();

  const dec = new ubiq.Decryption(ubiqConfiguration = ubiqCredentials);

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

