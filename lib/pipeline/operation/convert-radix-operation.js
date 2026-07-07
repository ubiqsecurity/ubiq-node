const Operation = require('../operation');
const bn = require('../../structured/Bn');

class ConvertRadixOperation extends Operation {
  /**
   * @param {OperationContext} context
   * @returns {Promise<string>}
   */
  async invokeAsync(context) {
    const dataset = context.getDataset();

    if (context.getIsEncrypt()) {
      return bn.convertRadix(context.getCurrentValue(), dataset.inputCharacterSet, dataset.outputCharacterSet, true)
    } else {
      return bn.convertRadix(context.getCurrentValue(), dataset.outputCharacterSet, dataset.inputCharacterSet, true)
    }
  }
}

module.exports = { ConvertRadixOperation }