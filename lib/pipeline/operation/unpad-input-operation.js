
const Operation = require('../operation');
const strUtils = require('../../structured/strUtils');

class UnpadInputOperation extends Operation {
  async invokeAsync(context) {
    let ret = context.getCurrentValue();
    const dataset = context.getDataset();

    if (strUtils.isNullOrEmpty(dataset.inputPadCharacter)) {
      // NOP
    } else {
      ret = strUtils.trimLeftPad(context.getCurrentValue(), dataset.inputPadCharacter);
      if (context.getData().has("PassthroughTemplate")) {
        context.getData().set(
          "PassthroughTemplate",
          strUtils.trimLeftPad(context.getData().get("PassthroughTemplate"), dataset.inputPadCharacter)
        );
      }
    }

    return ret;
  }
}

module.exports = { UnpadInputOperation };