const { TrimPassthroughCharactersOperation } = require('../lib/pipeline/operation/trim-passthrough-characters-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const strUtils = require('../lib/structured/strUtils');
const { expect } = require('chai');



// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TrimPassthroughCharactersOperation', () => {

  /** Mirrors the Java setup() helper. */
  function setup(passthrough_char) {
    const oc = new OperationContext();
    oc.setIsEncrypt(true);

    c = {
      "name": "sample",
      "data_type": "formatted_string",
      "input_character_set": "abc123",
      "output_character_set": "xyz456"
    }

    if (passthrough_char != null) {
      c["passthrough_rules"] = [{
        "type": "passthrough",
        "value": '"' + passthrough_char + '"',
        "priority": 1
      }]
    }

    const dataset = DatasetRecord.parse(c);

    oc.setCurrentValue('abc-123');
    oc.setDataset(dataset);

    return oc;
  }

  it('simple_NoPassthroughRules_ReturnsCurrentValue', async () => {
    const context = setup(null);

    const op = new TrimPassthroughCharactersOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc-123');
  });

  it('simple_PassthroughCharacterSetEmpty_ReturnsCurrentValue', async () => {
    const context = setup('');

    const op = new TrimPassthroughCharactersOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc-123');
  });

  it('simple_PassthroughCharactersNotFound_ReturnsCurrentValue', async () => {
    const context = setup('!');

    const op = new TrimPassthroughCharactersOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc-123');
  });

  it('simple_PassthroughCharactersExists_ReturnsTrimmedValue', async () => {
    const context = setup('-');

    const op = new TrimPassthroughCharactersOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc123');
  });

  it('simple_Encrypt_PassthroughTemplateContainsFirstOutputCharacter', async () => {
    const context = setup('-');

    const op = new TrimPassthroughCharactersOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc123');
    expect(context.getData().get("PassthroughTemplate")).to.equal('xxx-xxx');
  });

  it('simple_Decrypt_PassthroughTemplateContainsFirstInputCharacter', async () => {
    const context = setup('-');
    context.setIsEncrypt(false);

    const op = new TrimPassthroughCharactersOperation();
    const encoded = await op.invokeAsync(context);

    expect(encoded).to.equal('abc123');
    expect(context.getData().get("PassthroughTemplate")).to.equal('aaa-aaa');
  });
});