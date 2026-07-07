const { EncryptOperation } = require('../lib/pipeline/operation/encrypt-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const { expect } = require('chai');


describe('EncryptOperation', () => {
  function setup() {
    const oc = new OperationContext();
    const dataset = DatasetRecord.parse({});
    dataset.minInputLength = 4;
    dataset.maxInputLength = 10;
    dataset.inputCharacterSet = "abc-123"
    oc.setCurrentValue('abc-123');
    oc.setIsEncrypt(true);
    oc.setDataset(dataset);
    return oc;
  }

  it('EncryptOperation_DecryptContext_ThrowsException', async () => {
    try {
      const context = setup();
      context.setIsEncrypt(false)
      const op = new EncryptOperation();
      const v1 = await op.invokeAsync(context);
      expect(false).to.equal(true)
    } catch (ex) {
      expect(ex.message).to.match(/decryption/);
    }

  });

  it('EncryptOperation_CurrentValueLengthLessThanInputMinimum_ThrowsException', async () => {
    try {
      const context = setup();
      context.getDataset().minInputLength = 11
      const op = new EncryptOperation();
      const v1 = await op.invokeAsync(context);
      expect(false).to.equal(true)
    } catch (ex) {
      expect(ex.message).to.match(/minimum/);
    }

  });

  it('EncryptOperation_CurrentValueLengthGreaterThanInputMaximum_ThrowsException', async () => {
    try {
      const context = setup();
      context.getDataset().maxInputLength = 5
      const op = new EncryptOperation();
      const v1 = await op.invokeAsync(context);
      expect(false).to.equal(true)
    } catch (ex) {
      expect(ex.message).to.match(/maximum/);
    }

  });

  it('EncryptOperation_invalidCharacter_ThrowsException', async () => {
    try {
      const context = setup();
      context.setCurrentValue("ABCD")
      const op = new EncryptOperation();
      const v1 = await op.invokeAsync(context);
      expect(false).to.equal(true)
    } catch (ex) {
      expect(ex.message).to.match(/invalid/);
    }

  });


});