class StructuredPipeline {
  static verbose = false;

  constructor(operations = []) {
    this.operations = operations;
  }

  async invokeAsync(context) {
    if (StructuredPipeline.verbose) {
      console.log(`Start ${this.constructor.name} start: ${context.getCurrentValue()}`);
    }

    for (const operation of this.operations) {
      if (StructuredPipeline.verbose) {
        console.log(`Invoke ${operation.constructor.name} start: ${context.currentValue}`);
      }
      context.setCurrentValue(await operation.invokeAsync(context));
      if (StructuredPipeline.verbose) {
        console.log(`Invoke ${operation.constructor.name} end: ${context.currentValue}`);
      }
    }

    if (StructuredPipeline.verbose) {
      console.log(`End ${this.constructor.name} end: ${context.getCurrentValue()}`);
    }

    return context.getCurrentValue();
  }
}


module.exports = { StructuredPipeline }