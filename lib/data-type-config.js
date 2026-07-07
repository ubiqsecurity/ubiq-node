class DataTypeConfig {
  constructor(data) {
    data = (data === null || data === undefined) ? {} : data;

    this.epoch = data.epoch ? new Date(data.epoch) : null;
    this.maxInputDateValue = data.max_input_date_value ? new Date(data.max_input_date_value) : null;
    this.minInputDateValue = data.min_input_date_value ? new Date(data.min_input_date_value) : null;
    this.size = data.size;
    this.maxInputIntValue = data.max_input_int_value_as_string ? BigInt(data.max_input_int_value_as_string) : null;
    this.minInputIntValue = data.min_input_int_value_as_string ? BigInt(data.min_input_int_value_as_string) : null;
  }
}


module.exports = {
  DataTypeConfig
};