const { expect } = require('chai');
const ubiq = require('../index');

it('Test_factory_readCredentialsFromFile', async () => {
  let x = ubiq.UbiqFactory.readCredentialsFromFile(null, null)
  expect(x.host).to.equal('https://api.ubiqsecurity.com');
});

it('Test_factory_createCredentials', async () => {
  let x = ubiq.UbiqFactory.createCredentials('1', '2', '3', 'http://host');
  expect(x.host).to.equal('http://host');
});

it('Test_factory_createCredentialsWithIdp', async () => {
  let x = ubiq.UbiqFactory.createCredentialsWithIdp('user', 'pwd', 'http://host')
  expect(x.host).to.equal('http://host');
});

it('Test_factory_defaultCredentials', async () => {
  let x = ubiq.UbiqFactory.defaultCredentials()
  expect(x.host).to.equal('https://api.ubiqsecurity.com');
});

it('Test_factory_readConfigurationFromFile', async () => {
  let x = ubiq.UbiqFactory.readConfigurationFromFile(null)
  expect(x.event_reporting_minimum_count).to.equal(5);
});

it('Test_factory_defaultConfiguration', async () => {
  let x = ubiq.UbiqFactory.defaultConfiguration()
  expect(x.event_reporting_minimum_count).to.equal(5);
});

it('Test_factory_createConfigEventReporting', async () => {
  let x = ubiq.UbiqFactory.createConfigEventReporting(1, 2, 3, 'HOURS', 5)
  expect(x.minimum_count).to.equal(2);
});

it('Test_factory_createConfigNodeSpecific', async () => {
  let x = ubiq.UbiqFactory.createConfigNodeSpecific(10, 20)
  expect(x.lock_sleep_before_retry).to.equal(10);
});

it('Test_factory_createConfigKeyCaching', async () => {
  let x = ubiq.UbiqFactory.createConfigKeyCaching(true, false, true, 90)
  expect(x.ttl_seconds).to.equal(90);
});

it('Test_factory_createConfigIdp', async () => {
  let x = ubiq.UbiqFactory.createConfigIdp('a', 'b', 'c', 'd', 'e')
  expect(x.idp_token_endpoint_url).to.equal('e');
});

it('Test_factory_createConfiguration', async () => {
  let er = ubiq.UbiqFactory.createConfigEventReporting(1, 2, 3, 'HOURS', 5)
  let njs = ubiq.UbiqFactory.createConfigNodeSpecific(10, 20)
  let kc = ubiq.UbiqFactory.createConfigKeyCaching(true, false, true, 90)
  let idp = ubiq.UbiqFactory.createConfigIdp('a', 'b', 'c', 'd', 'e')
  let x = ubiq.UbiqFactory.createConfiguration(er, njs, kc, idp)

  expect(x.event_reporting_flush_interval).to.equal(3);
  expect(x.nodejs_lock_max_retry_count).to.equal(20);
  expect(x.key_caching_encrypt).to.equal(true);
  expect(x.idp_customer_id).to.equal('b');
});
