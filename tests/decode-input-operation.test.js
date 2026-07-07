const { EncodeInputOperation } = require('../lib/pipeline/operation/encode-input-operation');
const { DecodeInputOperation } = require('../lib/pipeline/operation/decode-input-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const strUtils = require('../lib/structured/strUtils');
const { expect } = require('chai');


describe('DecodeInputOperation', () => {
  function setup() {
    const oc = new OperationContext();
    const dataset = new DatasetRecord({});
    dataset.inputEncoding = null;
    oc.setCurrentValue('1234567890abcde');
    oc.setDataset(dataset);
    return oc;
  }

  it('simple_NullInputEncoding_ReturnsCurrentValue', async () => {
    const context = setup();
    const op = new DecodeInputOperation();
    expect(await op.invokeAsync(context)).to.equal('1234567890abcde');
  });

  it('simple_EncodeBase64_ReturnsExpectedBase64DecodedString', async () => {
    const context = setup();
    context.setCurrentValue('MTIzNDU2Nzg5MGFiY2Rl');
    const dataset = context.getDataset();
    dataset.inputEncoding = 'base64';
    context.setDataset(dataset);

    const op = new DecodeInputOperation();
    expect(await op.invokeAsync(context)).to.equal('1234567890abcde');
  });

  it('simple_EncodeBase32_ReturnsExpectedBase32DecodedString', async () => {
    const context = setup();
    context.setCurrentValue('GEZDGNBVGY3TQOJQMFRGGZDF');
    const dataset = context.getDataset();
    dataset.inputEncoding = 'base32';
    context.setDataset(dataset);

    const op = new DecodeInputOperation();
    expect((await op.invokeAsync(context)).toString('UTF-8')).to.equal('1234567890abcde');
  });

  it('Random_utf8_rt', async () => {
    const context = setup();

    const crypto = require('crypto');

    const decode = new DecodeInputOperation();
    const encode = new EncodeInputOperation();
    const dataset = context.getDataset();
    dataset.inputEncoding = 'base32';
    context.setDataset(dataset);

    for (let i = 0; i < 1000; i++) {
      const length = crypto.randomInt(0, 26); // 0 to 25 inclusive
      const buf = Buffer.from(crypto.randomBytes(length * 3))  // over-allocate for multi-byte chars
        .toString('utf8')
        .replace(/[^\x20-\x7E]/g, () => String.fromCharCode(crypto.randomInt(0x20, 0x7F)))
        .slice(0, length);
      context.setCurrentValue(buf);
      let res = await encode.invokeAsync(context);
      context.setCurrentValue(res);
      let pt = (await decode.invokeAsync(context)).toString('utf8');

      expect(buf).to.equal(pt);

    }
  });

  it('rt', async () => {
    const context = setup();

    const decode = new DecodeInputOperation();
    const encode = new EncodeInputOperation();
    const dataset = context.getDataset();
    dataset.inputEncoding = 'base32';
    context.setDataset(dataset);
    buf = "こんにちは"
    context.setCurrentValue(buf);
    let res = await encode.invokeAsync(context);
    context.setCurrentValue(res);
    let pt = (await decode.invokeAsync(context)).toString('utf8');

    expect(buf).to.eql(pt);

  });

  it('Random_bytes_rt', async () => {
    const context = setup();

    const crypto = require('crypto');

    const decode = new DecodeInputOperation();
    const encode = new EncodeInputOperation();
    const dataset = context.getDataset();
    dataset.inputEncoding = 'base32';
    context.setDataset(dataset);

    for (let i = 0; i < 1000; i++) {
      const length = crypto.randomInt(0, 26); // 0 to 25 inclusive
      const buf = Buffer.from(crypto.randomBytes(length * 3));  // over-allocate for multi-byte chars
      context.setCurrentValue(buf);
      let res = await encode.invokeAsync(context);
      context.setCurrentValue(res);
      let pt = (await decode.invokeAsync(context))

      expect(buf.toString('utf8')).to.eql(pt);

    }
  });

});