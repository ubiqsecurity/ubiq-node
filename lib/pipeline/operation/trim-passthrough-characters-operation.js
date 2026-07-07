const Operation = require('../operation');
const strUtils = require('../../structured/strUtils');

class TrimPassthroughCharactersOperation extends Operation {
  /**
   * @param {OperationContext} context
   * @returns {Promise<string>}
   */
  async invokeAsync(context) {
    let ret = context.getCurrentValue();
    const passthroughCharacterSet = context.getDataset().passthroughCharacterSet;

    if (!passthroughCharacterSet) {
      // NOP - Return existing current value
    } else {
      // Get the first character of either the output or input character set
      const templateChar = context.getIsEncrypt()
        ? context.getDataset().outputCharacterSet[0]
        : context.getDataset().inputCharacterSet[0];

      let templateBuilder = '';
      let trimmedBuilder = '';

      for (const c of context.getCurrentValue()) {
        // Character is in the passthrough character set
        if (passthroughCharacterSet.includes(c)) {
          templateBuilder += c;
        } else {
          trimmedBuilder += c;
          templateBuilder += templateChar;
        }
      }

      context.getData().set('PassthroughTemplate', templateBuilder);
      ret = trimmedBuilder;
    }

    return ret;
  }
}

module.exports = { TrimPassthroughCharactersOperation }