const { expect } = require('chai');
const ubiq = require('../index');

it('Test_builder_buildStructured', async () => {
  let y = await (new ubiq.CryptographyBuilder()).buildStructuredAsync();
  expect(y.constructor.name).to.equal('StructuredEncryptDecrypt')
  y.close();
});

it('Test_builder_buildStructuredDefault', async () => {
  let y = await (new ubiq.CryptographyBuilder()).withCredentialsDefault().withConfigurationDefault().buildStructuredAsync();
  expect(y.constructor.name).to.equal('StructuredEncryptDecrypt')
  y.close();
});

it('Test_builder_buildEncryption', async () => {
  let y = await (new ubiq.CryptographyBuilder()).buildEncryptionAsync();
  expect(y.constructor.name).to.equal('Encryption')
  y.close();
});

it('Test_builder_buildEncryptionDefault', async () => {
  let y = await (new ubiq.CryptographyBuilder()).withCredentialsDefault().withConfigurationDefault().buildEncryptionAsync();
  expect(y.constructor.name).to.equal('Encryption')
  y.close();
});

it('Test_builder_buildDecryption', async () => {
  let y = await (new ubiq.CryptographyBuilder()).buildDecryptionAsync();
  expect(y.constructor.name).to.equal('Decryption')
  y.close();
});

it('Test_builder_buildDecryptionDefault', async () => {
  let y = await (new ubiq.CryptographyBuilder()).withCredentialsDefault().withConfigurationDefault().buildDecryptionAsync();
  expect(y.constructor.name).to.equal('Decryption')
  y.close();
});

