const Package = require('../package.json');

const { TimeGranularity } = require('./configuration.js')

class BillingEvent {
  api_key;
  dataset_name;
  dataset_group_name;
  billing_action;
  dataset_type;
  key_number;
  count;
  first_call_timestamp;
  last_call_timestamp;

  static getKey(api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number) {
    if (billing_action !== BillingEvents.ENCRYPTION && billing_action !== BillingEvents.DECRYPTION) {
      throw new Error("Billing action: '" + billing_action + "' is not valid");
    } else if (dataset_type !== BillingEvents.STRUCTURED && dataset_type !== BillingEvents.UNSTRUCTURED) {
      throw new Error("Billing dataset_type: '" + dataset_type + "' is not valid");
    } else {
      return "api_key='" + api_key + "' datasets='" + dataset_name + "' billing_action='" + billing_action + "' dataset_groups='" + dataset_group_name + "' dataset_type='" + dataset_type + "' key_number='" + key_number + "'";
    }
  }

  getKey() {
    return BillingEvent.getKey(this.api_key, this.dataset_name, this.dataset_group_name, this.billing_action, this.dataset_type, this.key_number);
  }


  constructor(
    api_key,
    dataset_name,
    dataset_group_name,
    billing_action, //    TODO ENUM ?
    dataset_type,
    key_number,
    count) {

    if (billing_action !== BillingEvents.ENCRYPTION && billing_action !== BillingEvents.DECRYPTION) {
      throw new Error("Billing action: '" + billing_action + "' is not valid");
    } else if (dataset_type !== BillingEvents.STRUCTURED && dataset_type !== BillingEvents.UNSTRUCTURED) {
      throw new Error("Billing dataset_type: '" + dataset_type + "' is not valid");
    } else {
      this.api_key = api_key;
      this.dataset_name = dataset_name;
      this.dataset_group_name = dataset_group_name;
      this.billing_action = billing_action;
      this.dataset_type = dataset_type;
      this.count = count;
      this.key_number = key_number;
      this.first_call_timestamp = new Date();
      this.last_call_timestamp = this.first_call_timestamp;
    }
  }

  update_count(additional_count) {
    this.count += additional_count;
    this.last_call_timestamp = new Date();
  }

  formatTimestamp(timestamp, timestampGranularity) {
    var dt
    if (timestampGranularity == TimeGranularity.NANOS) {
      dt = timestamp
    } else {
      dt = new Date(timestamp.getUTCFullYear(), timestamp.getUTCMonth(), timestamp.getUTCDate())
      switch (timestampGranularity) {
        // No break since want to fall through and continue setting other fields
        case TimeGranularity.MILLIS:
          dt.setUTCMilliseconds(timestamp.getUTCMilliseconds())
        case TimeGranularity.SECONDS:
          dt.setUTCSeconds(timestamp.getUTCSeconds())
        case TimeGranularity.MINUTES:
          dt.setUTCMinutes(timestamp.getUTCMinutes())
        case TimeGranularity.HOURS:
          dt.setUTCHours(timestamp.getUTCHours())
        case TimeGranularity.HALF_DAYS:
          if (timestamp.getUTCHours() >= 12) {
            dt.setUTCHours(12)
          }
      }
    }
    return dt.toISOString()
  }

  serialize(userDefinedMetadata, timestampGranularity) {

    let ret = {
      "datasets": this.dataset_name,
      "dataset_groups": this.dataset_group_name,
      "api_key": this.api_key,
      "count": this.count,
      "key_number": this.key_number,
      "action": this.billing_action,
      "dataset_type": this.dataset_type,
      "product": "ubiq-node",
      "product_version": Package.version,
      "user-agent": `ubiq-node${Package.version}`,
      "api_version": "V3",
      "last_call_timestamp": this.formatTimestamp(this.last_call_timestamp, timestampGranularity),
      "first_call_timestamp": this.formatTimestamp(this.first_call_timestamp, timestampGranularity)
    };

    if (userDefinedMetadata) {
      ret["user_defined"] = userDefinedMetadata;
    }
    return ret;
  }

}

class BillingEvents {

  static ENCRYPTION = 'encrypt';
  static DECRYPTION = 'decrypt';

  static STRUCTURED = 'structured';
  static UNSTRUCTURED = 'unstructured';

  billing_events;
  ubiqConfiguration;


  constructor(ubiqConfiguration) {
    this.billing_events = new Map()
    this.userDefinedMetadata = null;
    this.ubiqConfiguration = ubiqConfiguration
  }

  async addBillingEvent(
    api_key,
    dataset_name,
    dataset_group_name,
    billing_action,
    dataset_type,
    key_number,
    count) {

    var key = BillingEvent.getKey(api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number);

    var e = this.billing_events.get(key);
    if (e === undefined) {
      e = new BillingEvent(api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, count);
    }
    else {
      e.update_count(count);
    }

    this.billing_events.set(key, e);
    return new Promise((response) => {
      response(true);
    });
  }

  // return a json object
  serialize_events(map, timestamp_granularity) {
    var data = [];

    for (let value of map.values()) {
      data.push(value.serialize(this.userDefinedMetadata, timestamp_granularity));
    }

    var ret = { usage: data }

    return ret
  }

  getEventCount() {
    return this.billing_events.size;
  }

  // return is an json object, not a string
  async getAndResetSerializedData() {
    const local_map = this.billing_events
    this.billing_events = new Map()
    const data = this.serialize_events(local_map, this.ubiqConfiguration.event_reporting_timestamp_granularity)
    return data
  }

  getSerializedData() {
    return this.serialize_events(this.billing_events, this.ubiqConfiguration.event_reporting_timestamp_granularity)
  }

  addUserDefinedMetadata(jsonString) {
    if (!jsonString) {
      throw new Error(`User defined Metadata cannot be null`);
    }
    if (jsonString.length >= 1024) {
      throw new Error(`User defined Metadata cannot be longer than 1024 characters`);
    }
    try {
      let element = JSON.parse(jsonString);
      this.userDefinedMetadata = element
    } catch (ex) {
      throw new Error("User defined Metadata must be a valid Json object");
    }
  }

}
module.exports = {
  BillingEvents,
};
