
const Operation = require('../operation');
const strUtils = require('../../structured/strUtils');

class ExpandPassthroughCharactersOperation extends Operation {
  async invokeAsync(context) {
    let ret = context.getCurrentValue();
    const passthroughCharacterSet = context.getDataset().passthroughCharacterSet;
    if (
      passthroughCharacterSet == null ||
      passthroughCharacterSet.trim() === "" ||
      !context.getData().has("PassthroughTemplate")
    ) {
      // NOP
    } else {
      ret = strUtils.formatToTemplate(
        context.getCurrentValue(),
        context.getData().get("PassthroughTemplate"),
        passthroughCharacterSet
      );
    }

    return ret;
  }
}


module.exports = { ExpandPassthroughCharactersOperation }