const Operation = require('../operation');
const strUtils = require('../../structured/strUtils');

class ExpandPassthroughPrefixOperation extends Operation {
  async invokeAsync(context) {
    let ret = context.getCurrentValue();
    const prefixLength = context.getDataset().passthroughPrefixLength;

    if (prefixLength == null || prefixLength === 0 || !context.getData().has("Prefix")) {
      // NOP
    } else {
      ret = context.getData().get("Prefix") + context.getCurrentValue();
    }

    return ret;
  }
}

module.exports = { ExpandPassthroughPrefixOperation }