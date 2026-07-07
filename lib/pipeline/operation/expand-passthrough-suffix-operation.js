const Operation = require('../operation');

class ExpandPassthroughSuffixOperation extends Operation {
  invokeAsync(context) {
    let ret = context.getCurrentValue();
    const suffixLength = context.getDataset().passthroughSuffixLength;

    if (suffixLength == null || suffixLength === 0 || !context.getData().has("Suffix")) {
      // NOP
    } else {
      ret = context.getCurrentValue() + context.getData().get("Suffix");
    }

    return ret;
  }
}

module.exports = { ExpandPassthroughSuffixOperation }