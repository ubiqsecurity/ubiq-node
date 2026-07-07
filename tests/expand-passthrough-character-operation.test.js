const { ExpandPassthroughCharactersOperation } = require('../lib/pipeline/operation/expand-passthrough-characters-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const strUtils = require('../lib/structured/strUtils');
const { expect } = require('chai');



// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ExpandPassthroughCharactersOperation', () => {

  /** Mirrors the Java setup() helper. */
  function setup(includePassThroughRule) {
    const oc = new OperationContext();
    oc.setIsEncrypt(true);

    c = {
      "name": "sample",
      "data_type": "formatted_string",
      "input_character_set": "abc123",
      "output_character_set": "xyz456"
    }

    if (includePassThroughRule) {
      c["passthrough_rules"] = [{
        "type": "passthrough",
        "value": "-",
        "priority": 1
      }]
    }

    const dataset = DatasetRecord.parse(c);

    oc.setOriginalValue('abc-123');
    oc.setCurrentValue('654zyx');
    oc.setDataset(dataset);

    oc.getData().set('PassthroughTemplate', 'xxx-xxx');
    // console.log(oc.getData())
    return oc;
  }

  it('simple_NoPassthroughRules_ReturnsCurrentValue', async () => {
    const context = setup(false);

    const dataset = context.getDataset();
    dataset.passthroughRules = [];
    context.setDataset(dataset);
    context.setData(new Map()); // mirrors new HashMap<>()

    const op = new ExpandPassthroughCharactersOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('654zyx');
  });

  it('simple_NoPassthroughTemplate_ReturnsCurrentValue', async () => {
    const context = setup(true);
    context.getData().delete('PassthroughTemplate');

    const op = new ExpandPassthroughCharactersOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('654zyx');
  });

  it('simple_ValidPassthroughTemplate_ReturnsFormattedValue', async () => {
    const context = setup(true);

    const op = new ExpandPassthroughCharactersOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('654-zyx');
  });

});