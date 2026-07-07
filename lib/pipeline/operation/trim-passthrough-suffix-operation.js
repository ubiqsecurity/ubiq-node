const Operation = require('../operation');

class TrimPassthroughSuffixOperation extends Operation {
  async invokeAsync(context) {
    let ret = context.getCurrentValue();

    const suffixLength = context.getDataset().passthroughSuffixLength;

    if (suffixLength == null || suffixLength === 0) {
      // NOP
    } else if (suffixLength > context.getCurrentValue().length) {
      throw new RangeError("Suffix length is greater than string length");
    } else {
      const currentValue = context.getCurrentValue();
      context.getData().set("Suffix", currentValue.substring(currentValue.length - suffixLength));
      ret = currentValue.substring(0, currentValue.length - suffixLength);
    }

    return ret;
  }
}

module.exports = { TrimPassthroughSuffixOperation }