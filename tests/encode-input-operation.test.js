const { EncodeInputOperation } = require('../lib/pipeline/operation/encode-input-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const strUtils = require('../lib/structured/strUtils');
const { expect } = require('chai');


describe('EncodeInputOperation', () => {
  function setup() {
    const oc = new OperationContext();
    const dataset = new DatasetRecord({});
    dataset.inputEncoding = null;
    oc.setCurrentValue('1234567890abcde');
    oc.setDataset(dataset);
    return oc;
  }

  it('simple', async () => {
    const context = setup();
    const op = new EncodeInputOperation();
    const encoded = await op.invokeAsync(context);
    expect(encoded).to.equal('1234567890abcde');
  });

  it('simple_base64', async () => {
    const context = setup();
    const dataset = context.getDataset();
    dataset.inputEncoding = 'base64';
    context.setDataset(dataset);

    const op = new EncodeInputOperation();
    const encoded = await op.invokeAsync(context);
    expect(encoded).to.equal('MTIzNDU2Nzg5MGFiY2Rl');
  });

  it('simple_base32', async () => {
    const context = setup();
    const dataset = context.getDataset();
    dataset.inputEncoding = 'base32';
    context.setDataset(dataset);

    const op = new EncodeInputOperation();
    const encoded = await op.invokeAsync(context);
    expect(encoded).to.equal('GEZDGNBVGY3TQOJQMFRGGZDF');
  });
});