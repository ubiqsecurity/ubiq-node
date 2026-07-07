const Operation = require('../operation');
const strUtils = require('../../structured/strUtils');

class EncodeKeyNumberOperation extends Operation {
  async invokeAsync(context) {
    const verbose = false
    const dataset = context.getDataset();
    if (verbose) console.log(`getCurrentValue ${context.getCurrentValue()}`)

    if (verbose) console.log(`outputCharacterSet ${dataset.outputCharacterSet}`)
    if (verbose) console.log(`msbEncodingBits ${dataset.msbEncodingBits}`)
    if (verbose) console.log(`getKeyNumber ${context.getKeyNumber()}`)
    return strUtils.encodeKeyNumber(
      context.getCurrentValue(),
      dataset.outputCharacterSet,
      dataset.msbEncodingBits,
      context.getKeyNumber()
    );
  }
}


module.exports = { EncodeKeyNumberOperation }