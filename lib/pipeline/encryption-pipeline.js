const { StructuredPipeline } = require('./structured-pipeline');

const { EncodeInputOperation } = require('./operation/encode-input-operation');
const { PadInputOperation } = require('./operation/pad-input-operation');
const { EncryptOperation } = require('./operation/encrypt-operation');
const { ConvertRadixOperation } = require('./operation/convert-radix-operation');
const { EncodeKeyNumberOperation } = require('./operation/encode-key-number-operation');
const { TrimPassthroughCharactersOperation } = require('./operation/trim-passthrough-characters-operation');
const { TrimPassthroughPrefixOperation } = require('./operation/trim-passthrough-prefix-operation');
const { TrimPassthroughSuffixOperation } = require('./operation/trim-passthrough-suffix-operation');
const { ExpandPassthroughCharactersOperation } = require('./operation/expand-passthrough-characters-operation');
const { ExpandPassthroughPrefixOperation } = require('./operation/expand-passthrough-prefix-operation');
const { ExpandPassthroughSuffixOperation } = require('./operation/expand-passthrough-suffix-operation');
const strUtils = require('../structured/strUtils');

class EncryptionPipeline extends StructuredPipeline {
  static baseOperations = [
    new EncodeInputOperation(),
    new PadInputOperation(),
    new EncryptOperation(),
    new ConvertRadixOperation(),
    new EncodeKeyNumberOperation(),
  ];

  constructor(operationsOrDataset) {
    super();

    // Called with no args
    if (operationsOrDataset === undefined) {
      this.operations = EncryptionPipeline.baseOperations;
      return;
    }

    // Called with a custom operations list
    if (Array.isArray(operationsOrDataset)) {
      this.operations = operationsOrDataset;
      return;
    }

    // Called with a dataset (FFS_Record)
    const dataset = operationsOrDataset;
    this.operations = [...EncryptionPipeline.baseOperations];

    // Rules are returned in order sorted by priority. Run in descending order of priority.
    const rules = dataset.passthroughRules;
    for (let i = rules.length - 1; i >= 0; i--) {
      const rule = rules[i];
      switch (rule.type) {
        case "passthrough":
          this.operations.unshift(new TrimPassthroughCharactersOperation());
          this.operations.push(new ExpandPassthroughCharactersOperation());
          break;
        case "prefix":
          this.operations.unshift(new TrimPassthroughPrefixOperation());
          this.operations.push(new ExpandPassthroughPrefixOperation());
          break;
        case "suffix":
          this.operations.unshift(new TrimPassthroughSuffixOperation());
          this.operations.push(new ExpandPassthroughSuffixOperation());
          break;
        default:
        // Ignore other rule types
      }
    }

    // If there aren't any passthrough rules but there are passthrough characters from
    // an old dataset, need to add passthrough handling
    if (rules.length === 0 && !strUtils.isNullOrEmpty(dataset.passthroughCharacterSet)) {
      this.operations.unshift(new TrimPassthroughCharactersOperation());
      this.operations.push(new ExpandPassthroughCharactersOperation());
    }
  }
}

module.exports = { EncryptionPipeline }