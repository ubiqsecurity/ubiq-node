const fs = require('fs');
const ConfigParser = require('configparser');

// Returns a simple object that contains the necessary fields

function set_attributes(er, njs) {
  return {
    event_reporting_wake_interval: ((er.wake_interval) || 1),
    event_reporting_minimum_count: ((er.minimum_count) || 5),
    event_reporting_flush_interval: ((er.flush_interval) || 10),
    nodejs_lock_sleep_before_retry: ((njs.lock_sleep_before_retry) || 250),
    nodejs_lock_max_retry_count: ((njs.lock_max_retry_count) || 15)
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
      ret = set_attributes({}, {});
    }
    return ret;
  }

  process_json_configuration(configuration_data) {
    let ret;
    let er = {};
    let njs = {};

    er = ((configuration_data.event_reporting) || {})
    njs = ((configuration_data.nodejs) || {});
    ret = set_attributes(er, njs);

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
      ret = set_attributes({}, {})
    }
    return ret;
  }
}

module.exports = { Configuration };
