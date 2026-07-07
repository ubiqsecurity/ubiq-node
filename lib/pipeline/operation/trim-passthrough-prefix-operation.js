
const Operation = require('../operation');

class TrimPassthroughPrefixOperation extends Operation {

  invokeAsync(context) {
    const verbose = false;
    let ret = context.getCurrentValue();

    const prefixLength = context.getDataset().passthroughPrefixLength;
    if (verbose) { console.log(`prefixLength: '${prefixLength}'`); }

    if (prefixLength == null || prefixLength === 0) {
      // NOP
    } else if (prefixLength > context.getCurrentValue().length) {
      throw new RangeError("Prefix length is greater than string length");
    } else {
      context.getData().set("Prefix", context.getCurrentValue().substring(0, prefixLength));
      if (verbose) { console.log(`Prefix: '${context.getCurrentValue().substring(0, prefixLength)}'`); }
      ret = context.getCurrentValue().substring(prefixLength);
      if (verbose) { console.log(`ret: '${ret}'`); }
    }

    return ret;
  }
}

module.exports = { TrimPassthroughPrefixOperation }