const { EncodeKeyNumberOperation } = require('../lib/pipeline/operation/encode-key-number-operation');
const { DecodeKeyNumberOperation } = require('../lib/pipeline/operation/decode-key-number-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const strUtils = require('../lib/structured/strUtils');
const { expect } = require('chai');


describe('EncodeKeyNumberOperation', () => {
  function setup(key_number, encoding_bits) {
    const oc = new OperationContext();

    c = {
      "name": "sample",
      "data_type": "formatted_string",
      "input_character_set": "0123456789",
      "output_character_set": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "min_input_length": 4,
      "msb_encoding_bits": encoding_bits
    }

    const dataset = DatasetRecord.parse(c);
    // oc.setCurrentValue('0000');
    oc.setKeyNumber(key_number)
    oc.setDataset(dataset);
    return oc;
  }

  it('EncodeKeyNumberOperation_simple_zero_msb', async () => {
    const context = setup(1, 0);

    const data = [
      { "original": "0000", "expected": "1000" },
      { "original": "1ZZZ", "expected": "2ZZZ" }
    ]

    for (const d of data) {
      context.setCurrentValue(d.original)
      const op = new EncodeKeyNumberOperation();
      const encoded = await op.invokeAsync(context);
      expect(encoded).to.equal(d.expected);
    }

  });

  it('EncodeKeyNumberOperation_simple_3_msb', async () => {
    const context = setup(3, 3);

    const data = [
      { "original": "0000", "expected": "O000" },
      { "original": "1ZZZ", "expected": "PZZZ" }
    ]

    for (const d of data) {
      context.setCurrentValue(d.original)
      const op = new EncodeKeyNumberOperation();
      const encoded = await op.invokeAsync(context);
      expect(encoded).to.equal(d.expected);
    }

  });

  it('EncodeKeyNumberOperation_simple_rt', async () => {

    const data = [
      { "original": "0ZZZ", "expected": "OZZZ", "key_number": 3, "msb": 3 },
      { "original": "5123", "expected": "T123", "key_number": 3, "msb": 3 },
      { "original": "0ZZZ", "expected": "WZZZ", "key_number": 4, "msb": 3 },
      { "original": "0000", "expected": "1000", "key_number": 1, "msb": 0 }
    ]

    for (const d of data) {
      const context = setup(d.key_number, d.msb);
      context.setCurrentValue(d.original)
      const op = new EncodeKeyNumberOperation();
      const encoded = await op.invokeAsync(context);
      expect(encoded).to.equal(d.expected);

      const context2 = setup(0, d.msb);
      context2.setCurrentValue(d.expected)
      const op2 = new DecodeKeyNumberOperation();
      const decoded = await op2.invokeAsync(context2);
      expect(decoded).to.equal(d.original);
      expect(context2.getKeyNumber()).to.equal(d.key_number)
    }

  });

});