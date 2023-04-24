const Package = require('../package.json');

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

  serialize() {


    return {
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
      "last_call_timestamp": this.last_call_timestamp.toISOString(),
      "first_call_timestamp": this.first_call_timestamp.toISOString()
    };

  }

}

class BillingEvents {

  static ENCRYPTION = 'encrypt';
  static DECRYPTION = 'decrypt';

  static STRUCTURED = 'structured';
  static UNSTRUCTURED = 'unstructured';

  billing_events;

  constructor() {
    this.billing_events = new Map()
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
  serialize_events(map) {
    var data = [];

    for (let value of map.values()) {
      data.push(value.serialize());
    }

    var ret = { usage: data }

    return ret
  }

  getEventCount() {
    return this.billing_events.size;
  }

  // return is an json object, not a string
  async getBillingEvents() {
    const local_map = this.billing_events
    this.billing_events = new Map()
    const data = this.serialize_events(local_map)
    return data
  }

}
module.exports = {
  BillingEvents,
};
