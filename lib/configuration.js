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

function set_attributes(er, njs, kc) {
  let unstructured = true
  let encrypt = false
  if (typeof kc.unstructured !== "undefined") {
    unstructured = kc.unstructured
  }
  if (typeof kc.encrypt !== "undefined") {
    encrypt = kc.encrypt
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
      ret = set_attributes({}, {}, {});
    }
    return ret;
  }

  process_json_configuration(configuration_data) {
    let ret;
    let er = {}; // Event Reporting
    let njs = {}; // Node JS Specific 
    let kc = {}; // Key Caching

    er = ((configuration_data.event_reporting) || {})
    njs = ((configuration_data.nodejs) || {});
    kc = ((configuration_data.key_caching) || {});
    ret = set_attributes(er, njs, kc);

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
      ret = set_attributes({}, {}, {})
    }
    return ret;
  }
}

module.exports = { Configuration, TimeGranularity };
