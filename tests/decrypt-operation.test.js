const { DecryptOperation } = require('../lib/pipeline/operation/decrypt-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const { expect } = require('chai');


describe('DecryptOperation', () => {
  function setup() {
    const oc = new OperationContext();
    const dataset = DatasetRecord.parse({});
    dataset.minInputLength = 4;
    dataset.maxInputLength = 10;
    dataset.outputCharacterSet = "abc-123"
    oc.setCurrentValue('abc-123');
    oc.setIsEncrypt(false);
    oc.setDataset(dataset);
    return oc;
  }

  it('DecryptOperation_DecryptContext_ThrowsException', async () => {
    try {
      const context = setup();
      context.setIsEncrypt(true)
      const op = new DecryptOperation();
      const v1 = await op.invokeAsync(context);
      expect(false).to.equal(true)
    } catch (ex) {
      expect(ex.message).to.match(/encryption/);
    }

  });

  it('DecryptOperation_CurrentValueLengthLessThanInputMinimum_ThrowsException', async () => {
    try {
      const context = setup();
      context.getDataset().minInputLength = 11
      const op = new DecryptOperation();
      const v1 = await op.invokeAsync(context);
      expect(false).to.equal(true)
    } catch (ex) {
      expect(ex.message).to.match(/minimum/);
    }

  });

  it('DecryptOperation_CurrentValueLengthGreaterThanInputMaximum_ThrowsException', async () => {
    try {
      const context = setup();
      context.getDataset().maxInputLength = 5
      const op = new DecryptOperation();
      const v1 = await op.invokeAsync(context);
      expect(false).to.equal(true)
    } catch (ex) {
      expect(ex.message).to.match(/maximum/);
    }

  });
});