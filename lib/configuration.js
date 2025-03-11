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

class Configuration {

  // Returns a simple object that contains the necessary fields

  set_attributes(er, njs, kc, idp) {
    let unstructured = true
    let encrypt = false
    let structured = true
    let ttl_seconds = 1800
    if (typeof kc.unstructured !== "undefined") {
      unstructured = kc.unstructured
    }
    if (typeof kc.encrypt !== "undefined") {
      encrypt = kc.encrypt
    }
    if (typeof kc.structured !== "undefined") {
      structured = kc.structured
    }
    if (typeof kc.ttl_seconds !== "undefined") {
      ttl_seconds = kc.ttl_seconds
    }

    let idp_type = ''
    let idp_customer_id = ''
    let idp_tenant_id = ''
    let idp_client_secret = ''
    let idp_token_endpoint_url = ''

    if (typeof idp.provider !== "undefined") {
      idp_type = idp.provider
    }
    if (typeof idp.ubiq_customer_id !== "undefined") {
      idp_customer_id = idp.ubiq_customer_id
    }
    if (typeof idp.idp_tenant_id !== "undefined") {
      idp_tenant_id = idp.idp_tenant_id
    }
    if (typeof idp.idp_client_secret !== "undefined") {
      idp_client_secret = idp.idp_client_secret
    }
    if (typeof idp.idp_token_endpoint_url !== "undefined") {
      idp_token_endpoint_url = idp.idp_token_endpoint_url
    }

    this.event_reporting_wake_interval = ((er.wake_interval) || 1)
    this.event_reporting_minimum_count = ((er.minimum_count) || 5)
    this.event_reporting_flush_interval = ((er.flush_interval) || 10)
    this.nodejs_lock_sleep_before_retry = ((njs.lock_sleep_before_retry) || 250)
    this.nodejs_lock_max_retry_count = ((njs.lock_max_retry_count) || 15)
    this.event_reporting_timestamp_granularity = (getTimestampGranularity(er.timestamp_granularity || "NANOS"))
    this.key_caching_unstructured = unstructured
    this.key_caching_encrypt = encrypt
    this.key_caching_structured = structured
    this.key_caching_ttl_seconds = ttl_seconds
    this.idp_type = idp_type
    this.idp_customer_id = idp_customer_id
    this.idp_tenant_id = idp_tenant_id
    this.idp_client_secret = idp_client_secret
    this.idp_token_endpoint_url = idp_token_endpoint_url
  }


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
      ret = this.set_attributes({}, {}, {}, {});
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
    ret = this.set_attributes(er, njs, kc, idp);

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
      ret = this.set_attributes({}, {}, {}, {})
    }
    return ret;
  }
}

module.exports = { Configuration, TimeGranularity };
