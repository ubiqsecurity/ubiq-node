const { TrimPassthroughSuffixOperation } = require('../lib/pipeline/operation/trim-passthrough-suffix-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const strUtils = require('../lib/structured/strUtils');
const { expect } = require('chai');



// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TrimPassthroughSuffixOperation', () => {

  /** Mirrors the Java setup() helper. */
  function setup(suffix_length) {
    const oc = new OperationContext();
    oc.setIsEncrypt(true);

    c = {
      "name": "sample",
      "data_type": "formatted_string"
    }

    if (suffix_length != null) {
      c["passthrough_rules"] = [{
        "type": "suffix",
        "value": suffix_length,
        "priority": 1
      }]
    }

    const dataset = DatasetRecord.parse(c);

    oc.setCurrentValue('abc123');
    oc.setDataset(dataset);

    return oc;
  }

  it('simple_NoPassthroughRules_ReturnsCurrentValue', async () => {
    const context = setup(null);

    const op = new TrimPassthroughSuffixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc123');
  });

  it('simple_PassthroughCharacterSetEmpty_ReturnsCurrentValue', async () => {
    const context = setup(0);

    const op = new TrimPassthroughSuffixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc123');
  });

  it('simple_SuffixLengthGreaterThanCurrentValueLength_ThrowsException', async () => {
    try {
      const context = setup(8);

      const op = new TrimPassthroughSuffixOperation();
      const encoded = await op.invokeAsync(context);

      expect(false).to.equal(true);
    } catch (ex) {
      expect(ex.message).to.match(/greater/);
    }
  });

  it('simple_SuffixLengthEqualToCurrentValueLength_ReturnsEmptyString', async () => {
    const context = setup(6);

    const op = new TrimPassthroughSuffixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('');
    expect(context.getData().get("Suffix")).to.equal('abc123');
  });

  it('simple_SuffixLengthThree_ReturnsTrimmedValue', async () => {
    const context = setup(4);

    const op = new TrimPassthroughSuffixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('ab');
    expect(context.getData().get("Suffix")).to.equal('c123');
  });

});