const Operation = require('../operation');

class DecryptOperation extends Operation {
  static verbose = false
  async invokeAsync(context) {
    const currentValue = context.getCurrentValue();
    const dataset = context.getDataset();

    if (context.getIsEncrypt()) {
      throw new Error("DecryptOperation not allowed in a encryption pipeline");
    }

    if (currentValue.length < dataset.minInputLength) {
      throw new RangeError("Input length is less than the dataset's minimum input length");
    }
    if (currentValue.length > dataset.maxInputLength) {
      throw new RangeError("Input length is greater than the dataset's maximum input length");
    }

    const { ctx, activeKeyNumber } = await context.getFfxCache().GetAsync(dataset.name, context.getKeyNumber());

    return ctx.decrypt(currentValue, context.getUserSuppliedTweak());
  }
}

module.exports = { DecryptOperation }