const { TrimPassthroughPrefixOperation } = require('../lib/pipeline/operation/trim-passthrough-prefix-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const strUtils = require('../lib/structured/strUtils');
const { expect } = require('chai');



// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TrimPassthroughPrefixOperation', () => {

  /** Mirrors the Java setup() helper. */
  function setup(prefix_length) {
    const oc = new OperationContext();
    oc.setIsEncrypt(true);

    c = {
      "name": "sample",
      "data_type": "formatted_string"
    }

    if (prefix_length != null) {
      c["passthrough_rules"] = [{
        "type": "prefix",
        "value": prefix_length,
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

    const op = new TrimPassthroughPrefixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc123');
  });

  it('simple_PassthroughCharacterSetEmpty_ReturnsCurrentValue', async () => {
    const context = setup(0);

    const op = new TrimPassthroughPrefixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc123');
  });

  it('simple_PrefixLengthGreaterThanCurrentValueLength_ThrowsException', async () => {
    try {
      const context = setup(8);

      const op = new TrimPassthroughPrefixOperation();
      const encoded = await op.invokeAsync(context);

      expect(false).to.equal(true);
    } catch (ex) {
      expect(ex.message).to.match(/greater/);
    }
  });

  it('simple_PrefixLengthEqualToCurrentValueLength_ReturnsEmptyString', async () => {
    const context = setup(6);

    const op = new TrimPassthroughPrefixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('');
    expect(context.getData().get("Prefix")).to.equal('abc123');
  });

  it('simple_PrefixLengthThree_ReturnsTrimmedValue', async () => {
    const context = setup(4);

    const op = new TrimPassthroughPrefixOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('23');
    expect(context.getData().get("Prefix")).to.equal('abc1');
  });

});