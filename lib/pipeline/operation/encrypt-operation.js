const Operation = require('../operation');

const verbose = false
class EncryptOperation extends Operation {
  async invokeAsync(context) {
    const currentValue = context.getCurrentValue();
    const dataset = context.getDataset();

    if (!context.getIsEncrypt()) {
      throw new Error("EncryptOperation not allowed in a decryption pipeline");
    }

    if (currentValue.length < dataset.minInputLength) {
      throw new RangeError("Input length is less than the dataset's minimum input length");
    }
    if (currentValue.length > dataset.maxInputLength) {
      throw new RangeError("Input length is greater than the dataset's maximum input length");
    }

    const inputChars = dataset.inputCharacterSet;
    if (verbose) { console.log(`inputChars: "${inputChars}"`) }
    if (verbose) { console.log(`passthroughCharacterSet: "${dataset.passthroughCharacterSet}"`) }
    for (let idx = 0; idx < currentValue.length; idx++) {
      const c = currentValue[idx];
      if (inputChars.indexOf(c) === -1) {
        throw new RangeError(`Input string has invalid character: '${c}'`);
      }
    }

    const { ctx, activeKeyNumber } = await context.getFfxCache().GetAsync(dataset.name, context.getKeyNumber());
    // If context.getKeyNumber() is null, then use the dataset key_number
    if (verbose) { console.log(`activeKeyNumber: ${activeKeyNumber}`) }
    if (verbose) { console.log(`ctx: ${ctx}`) }
    context.setKeyNumber(activeKeyNumber);
    if (verbose) { console.log(`context.getUserSuppliedTweak(): (${context.getUserSuppliedTweak()})`) }

    return ctx.encrypt(currentValue, context.getUserSuppliedTweak());
  }
}


module.exports = { EncryptOperation }