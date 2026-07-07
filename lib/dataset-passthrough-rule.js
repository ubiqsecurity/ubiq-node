class DatasetPassthroughRule {
  constructor(data) {
    data = (data === null || data === undefined) ? {} : data;

    this.type = data.type
    this.priority = data.priority
    this.value = data.value
  }
}


module.exports = {
  DatasetPassthroughRule
};