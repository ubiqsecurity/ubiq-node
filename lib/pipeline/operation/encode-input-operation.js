const Operation = require('../operation');
const strUtils = require('../../structured/strUtils');


class EncodeInputOperation extends Operation {
  async invokeAsync(context) {
    const verbose = false;
    const csu = "EncodeInputOperation::invoke"
    const inputEncoding = context.getDataset().inputEncoding;
    let ret = context.getCurrentValue();

    if (verbose) {
      console.log(`${csu} ${this.constructor.name} : ${new Date()} Start: inputEncoding: ${inputEncoding} getCurrentValue: ${ret}`);
    }

    if (verbose) { console.log(`${csu} inputEncoding: ${inputEncoding}`) }
    if (inputEncoding == null || inputEncoding.trim() == "") {
      // NOP - nothing to do
    } else if (inputEncoding == "base64") {
      if (verbose) { console.log(`${csu} inputEncoding == base64`) }
      ret = Buffer.from(context.getCurrentValue(), "utf8").toString("base64");
    } else if (inputEncoding == "base32") {
      if (verbose) { console.log(`${csu} inputEncoding == base32`) }
      ret = strUtils.base32Encode(Buffer.from(context.getCurrentValue(), "utf8"));
    } else {
      throw new Error(`context.dataset.inputEncoding value '${inputEncoding}' is not currently supported`);
    }

    if (verbose) {
      console.log(`${this.constructor.name} : ${new Date()} End: inputEncoding: ${inputEncoding} getCurrentValue: ${ret}`);
    }

    return ret;
  }
}

module.exports = { EncodeInputOperation };