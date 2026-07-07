const { ExpandPassthroughPrefixOperation } = require('../lib/pipeline/operation/expand-passthrough-prefix-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const strUtils = require('../lib/structured/strUtils');
const { expect } = require('chai');



// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ExpandPassthroughPrefixOperation', () => {

  /** Mirrors the Java setup() helper. */
  function setup(includePrefixRule) {
    const oc = new OperationContext();
    oc.setIsEncrypt(true);

    c = {
      "name": "sample",
      "data_type": "formatted_string",
      "input_character_set": "abc123",
      "output_character_set": "xyz456"
    }

    if (includePrefixRule) {
      c["passthrough_rules"] = [{
        "type": "prefix",
        "value": "3",
        "priority": 1
      }]
    }

    const dataset = DatasetRecord.parse(c);

    oc.setCurrentValue('123');
    oc.setDataset(dataset);

    oc.getData().set('Prefix', 'abc');
    return oc;
  }

  it('simple_NoPrefixRules_ReturnsCurrentValue', async () => {
    const context = setup(false);

    const dataset = context.getDataset();

    const op = new ExpandPassthroughPrefixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('123');
  });

  it('simple_NoPrefix_ReturnsCurrentValue', async () => {
    const context = setup(true);
    context.getData().delete('Prefix');

    const op = new ExpandPassthroughPrefixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('123');
  });

  it('simple_PrefixExists_ReturnsFormattedValue', async () => {
    const context = setup(true);

    const op = new ExpandPassthroughPrefixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc123');
  });

});