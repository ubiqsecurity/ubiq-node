const { ExpandPassthroughSuffixOperation } = require('../lib/pipeline/operation/expand-passthrough-suffix-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const strUtils = require('../lib/structured/strUtils');
const { expect } = require('chai');



// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ExpandPassthroughSuffixOperation', () => {

  /** Mirrors the Java setup() helper. */
  function setup(includeSuffixRule) {
    const oc = new OperationContext();
    oc.setIsEncrypt(true);

    c = {
      "name": "sample",
      "data_type": "formatted_string",
      "input_character_set": "abc123",
      "output_character_set": "xyz456"
    }

    if (includeSuffixRule) {
      c["passthrough_rules"] = [{
        "type": "suffix",
        "value": "3",
        "priority": 1
      }]
    }

    const dataset = DatasetRecord.parse(c);

    oc.setCurrentValue('abc');
    oc.setDataset(dataset);

    oc.getData().set('Suffix', '123');
    return oc;
  }

  it('simple_NoSuffixRules_ReturnsCurrentValue', async () => {
    const context = setup(false);

    const dataset = context.getDataset();

    const op = new ExpandPassthroughSuffixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc');
  });

  it('simple_NoSuffix_ReturnsCurrentValue', async () => {
    const context = setup(true);
    context.getData().delete('Suffix');

    const op = new ExpandPassthroughSuffixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc');
  });

  it('simple_SuffixExists_ReturnsFormattedValue', async () => {
    const context = setup(true);

    const op = new ExpandPassthroughSuffixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc123');
  });

});