const Operation = require('../operation');
const strUtils = require('../../structured/strUtils');

class DecodeInputOperation extends Operation {
  /**
   * @param {OperationContext} context
   * @returns {Promise<string>}
   */
  async invokeAsync(context) {
    const verbose = false;
    const csu = "DecodeInputOperation::invoke"
    const inputEncoding = context.getDataset().inputEncoding;
    let ret = context.getCurrentValue();

    if (verbose) {
      console.log(`${csu} ${this.constructor.name} : ${new Date()} Start: inputEncoding: ${inputEncoding} getCurrentValue: ${ret}`);
    }

    if (!inputEncoding || !inputEncoding.trim()) {
      // NOP - nothing to do
    } else if (inputEncoding == 'base64') {
      if (verbose) { console.log(`${csu} inputEncoding == base64`) }
      ret = Buffer.from(context.getCurrentValue(), 'base64').toString('utf8');
    } else if (inputEncoding == 'base32') {
      if (verbose) { console.log(`${csu} inputEncoding == base32`) }
      ret = strUtils.base32Decode(context.getCurrentValue());
    } else {
      throw new Error(`context.dataset.inputEncoding value '${inputEncoding}' is not currently supported`);
    }

    return ret;
  }
}



module.exports = {
  DecodeInputOperation
};