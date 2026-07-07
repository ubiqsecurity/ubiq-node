const Operation = require('../operation');
const strUtils = require('../../structured/strUtils');

class DecodeKeyNumberOperation extends Operation {

  async invokeAsync(context) {
    const verbose = false;
    const dataset = context.getDataset();
    const keyNumber = { value: 0 };

    // { str : <decoded> , "key_number" : key_number}
    const ret = strUtils.decodeKeyNumber(
      context.getCurrentValue(),
      dataset.outputCharacterSet,
      dataset.msbEncodingBits
    );

    if (DecodeKeyNumberOperation.verbose) {
      console.log(`${this.constructor.name} keyNumber: ${ret.key_number}`);
    }

    context.setKeyNumber(ret.key_number);
    return ret.str;
  }
}

module.exports = { DecodeKeyNumberOperation }