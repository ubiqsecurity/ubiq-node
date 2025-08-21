const { ConfigCredentials, Credentials } = require('./credentials');
const { Configuration } = require('./configuration');

const UbiqFactory = {
  readCredentialsFromFile: function (pathname, profile) {
    return new ConfigCredentials(pathname, profile);
  },

  createCredentials: function (accessKeyId, secretSigningKey, secretCryptoAccessKey, host) {
    return new Credentials(accessKeyId, secretSigningKey, secretCryptoAccessKey, host, null, null);
  },

  createCredentialsWithIdp: function (idp_username, idp_password, host) {
    return new Credentials(null, null, null, host, idp_username, idp_password)
  },

  defaultCredentials: function () {
    return new ConfigCredentials();
  },

  readConfigurationFromFile: function (pathname) {
    return (new Configuration()).loadFromFile(pathname);
  },

  defaultConfiguration: function () {
    return (new Configuration()).loadFromFile(null);
  },

  createConfigEventReporting: function (
    wakeInterval,
    minimumCount,
    flushInterval,
    timestampGranularity,
    trapExceptions) {
    var er = {};

    er.wake_interval = wakeInterval;
    er.minimum_count = minimumCount;
    er.flush_interval = flushInterval;
    er.timestamp_granularity = timestampGranularity;
    er.trap_exceptions = trapExceptions;

    return er;
  },

  createConfigNodeSpecific: function (
    lockMaxRetryCount,
    lockSleepBeforeRetry) {
    var njs = {};

    njs.lock_sleep_before_retry = lockMaxRetryCount;
    njs.lock_max_retry_count = lockSleepBeforeRetry;

    return njs;
  },

  createConfigKeyCaching: function (
    unstructured,
    structured,
    encrypt,
    ttlSeconds) {
    var kc = {};

    kc.unstructured = unstructured;
    kc.structured = structured;
    kc.encrypt = encrypt;
    kc.ttl_seconds = ttlSeconds;

    return kc;
  },

  createConfigIdp: function (
    provider,
    ubiqCustomerId,
    idpTenantId,
    idpClientSecret,
    idpTokenEndpointUrl) {
    var idp = {};

    idp.provider = provider;
    idp.ubiq_customer_id = ubiqCustomerId;
    idp.idp_tenant_id = idpTenantId;
    idp.idp_client_secret = idpClientSecret;
    idp.idp_token_endpoint_url = idpTokenEndpointUrl;

    return idp;
  },

  createConfiguration: function (eventReporting, nodeJsSpecific, keyCaching, idp) {
    return (new Configuration()).set_attributes(eventReporting, nodeJsSpecific, keyCaching, idp)
  }
}


module.exports = {
  UbiqFactory,
};
