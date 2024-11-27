const fs = require('fs');
const ConfigParser = require('configparser');

const TimeGranularity = {
  DAYS: Symbol("DAYS"),
  HALF_DAYS: Symbol("HALF_DAYS"),
  HOURS: Symbol("HOURS"),
  MINUTES: Symbol("MINUTES"),
  SECONDS: Symbol("SECONDS"),
  MILLIS: Symbol("MILLIS"),
  NANOS: Symbol("NANOS")
}

function getTimestampGranularity(value) {
  let s = value.toUpperCase()
  let ret = TimeGranularity.NANOS;
  switch (s) {
    case "DAYS":
      ret = TimeGranularity.DAYS;
      break;
    case "HALF_DAYS":
      ret = TimeGranularity.HALF_DAYS;
      break;
    case "HOURS":
      ret = TimeGranularity.HOURS;
      break;
    case "MINUTES":
      ret = TimeGranularity.MINUTES;
      break;
    case "SECONDS":
      ret = TimeGranularity.SECONDS;
      break;
    case "MILLIS":
      ret = TimeGranularity.MILLIS;
      break;
    default:
      ret = TimeGranularity.NANOS;
  }
  return ret
}

// Returns a simple object that contains the necessary fields

function set_attributes(er, njs, kc, idp) {
  let unstructured = true
  let encrypt = false
  if (typeof kc.unstructured !== "undefined") {
    unstructured = kc.unstructured
  }
  if (typeof kc.encrypt !== "undefined") {
    encrypt = kc.encrypt
  }

  idp_type = ''
  idp_customer_id = ''
  idp_tenant_id = ''
  idp_client_secret = ''
  idp_token_endpoint_url = ''

  if (typeof idp.type !== "undefined") {
    idp_type = idp.type
  }
  if (typeof idp.customer_id !== "undefined") {
    idp_customer_id = idp.customer_id
  }
  if (typeof idp.tenant_id !== "undefined") {
    idp_tenant_id = idp.tenant_id
  }
  if (typeof idp.client_secret !== "undefined") {
    idp_client_secret = idp.client_secret
  }
  if (typeof idp.token_endpoint_url !== "undefined") {
    idp_token_endpoint_url = idp.token_endpoint_url
  }

  return {
    event_reporting_wake_interval: ((er.wake_interval) || 1),
    event_reporting_minimum_count: ((er.minimum_count) || 5),
    event_reporting_flush_interval: ((er.flush_interval) || 10),
    nodejs_lock_sleep_before_retry: ((njs.lock_sleep_before_retry) || 250),
    nodejs_lock_max_retry_count: ((njs.lock_max_retry_count) || 15),
    event_reporting_timestamp_granularity: (getTimestampGranularity(er.timestamp_granularity || "NANOS")),
    key_caching_unstructured: unstructured,
    key_caching_encrypt: encrypt,
    idp_type: idp_type,
    idp_customer_id: idp_customer_id,
    idp_tenant_id: idp_tenant_id,
    idp_client_secret: idp_client_secret,
    idp_token_endpoint_url: idp_token_endpoint_url
  };

}



class Configuration {

  constructor(config_file) {
    // If config_file is undefined or empty string,
    // use the system one, if it exists, otherwize the default.
    let ret;
    if (!config_file) {
      config_file = `${require('os').homedir()}/.ubiq/configuration`;
    }
    if (fs.existsSync(config_file)) {
      ret = this.load_configuration(config_file)
    } else {
      ret = set_attributes({}, {}, {}, {});
    }
    return ret;
  }

  process_json_configuration(configuration_data) {
    let ret;
    let er = {}; // Event Reporting
    let njs = {}; // Node JS Specific 
    let kc = {}; // Key Caching
    let idp = {}; // IDP parameters

    er = ((configuration_data.event_reporting) || {})
    njs = ((configuration_data.nodejs) || {});
    kc = ((configuration_data.key_caching) || {});
    idp = ((configuration_data.idp) || {});
    ret = set_attributes(er, njs, kc, idp);

    return ret;
  }

  load_configuration(configuration_file) {
    let configuration_data = fs.readFileSync(configuration_file);
    let ret;
    try {
      configuration_data = JSON.parse(configuration_data);

      ret = this.process_json_configuration(configuration_data)
    } catch (e) {
      // config parser library requires file name, not data
      ret = set_attributes({}, {}, {}, {})
    }
    return ret;
  }
}

module.exports = { Configuration, TimeGranularity };
