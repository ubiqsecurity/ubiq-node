const Operation = require('../operation');
const strUtils = require('../../structured/strUtils');

class PadInputOperation extends Operation {
  /**
   * @param {OperationContext} context
   * @returns {Promise<string>}
   */
  async invokeAsync(context) {
    let ret = context.getCurrentValue();
    const dataset = context.getDataset();

    if (!dataset.inputPadCharacter) {
      // NOP
    } else {
      if (context.getCurrentValue().includes(dataset.inputPadCharacter)) {
        throw new Error(`Input string already includes the padding character: '${dataset.inputPadCharacter}'`);
      }

      // Pad the current value but also pad the template if necessary
      ret = strUtils.padLeft(dataset.inputPadCharacter, dataset.minInputLength, context.getCurrentValue());

      if (context.getData().has('PassthroughTemplate')) {
        context.getData().set(
          'PassthroughTemplate',
          strUtils.padLeft(dataset.inputPadCharacter, dataset.minInputLength, context.getData().get('PassthroughTemplate'))
        );
      }
    }

    return ret;
  }
}

module.exports = { PadInputOperation };