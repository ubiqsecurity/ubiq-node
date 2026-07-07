const { ConvertRadixOperation } = require('../lib/pipeline/operation/convert-radix-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const { expect } = require('chai');


describe('ConvertRadixOperation', () => {
  function setup() {
    const oc = new OperationContext();
    const dataset = new DatasetRecord({});
    dataset.inputEncoding = null;
    dataset.inputCharacterSet = '0123456789'
    dataset.outputCharacterSet = '0123456789ABCDEF'
    oc.setCurrentValue('10');
    oc.setIsEncrypt(true);
    oc.setDataset(dataset);
    return oc;
  }

  it('simple_hex', async () => {
    const encrypt_context = setup();
    const decrypt_context = setup();
    const orig = "10"
    const op = new ConvertRadixOperation();
    decrypt_context.setIsEncrypt(false)
    encrypt_context.setCurrentValue(orig)
    const v1 = await op.invokeAsync(encrypt_context);
    expect(v1).to.equal("0A");
    decrypt_context.setCurrentValue(v1)
    const v2 = await op.invokeAsync(decrypt_context);
    expect(orig).to.equal(v2);
  });

  it('simple_binary_to_hex', async () => {
    const encrypt_context = setup();
    const decrypt_context = setup();
    const orig = "11"
    encrypt_context.getDataset().inputCharacterSet = "01"
    decrypt_context.getDataset().inputCharacterSet = "01"
    const op = new ConvertRadixOperation();
    decrypt_context.setIsEncrypt(false)
    encrypt_context.setCurrentValue(orig)
    const v1 = await op.invokeAsync(encrypt_context);
    expect(v1).to.equal("03");
    decrypt_context.setCurrentValue(v1)
    const v2 = await op.invokeAsync(decrypt_context);
    expect(orig).to.equal(v2);
  });

  it('simple_alternate_to_hex', async () => {
    const encrypt_context = setup();
    const decrypt_context = setup();
    const orig = "89"
    encrypt_context.getDataset().inputCharacterSet = "9876543210"
    decrypt_context.getDataset().inputCharacterSet = "9876543210"
    const op = new ConvertRadixOperation();
    decrypt_context.setIsEncrypt(false)
    encrypt_context.setCurrentValue(orig)
    const v1 = await op.invokeAsync(encrypt_context);
    expect(v1).to.equal("0A");
    decrypt_context.setCurrentValue(v1)
    const v2 = await op.invokeAsync(decrypt_context);
    expect(orig).to.equal(v2);
  });

});