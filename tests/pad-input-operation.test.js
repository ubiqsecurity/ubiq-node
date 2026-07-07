const { PadInputOperation } = require('../lib/pipeline/operation/pad-input-operation');
const { UnpadInputOperation } = require('../lib/pipeline/operation/unpad-input-operation');
const { OperationContext } = require('../lib/pipeline/operation-context');
const { DatasetRecord } = require('../lib/dataset-record');
const { DatasetPassthroughRule } = require('../lib/dataset-passthrough-rule');
const strUtils = require('../lib/structured/strUtils');
const { expect } = require('chai');

function setup() {
  // const x = new Map();
  // return x;
  const oc = new OperationContext();
  const dataset = new DatasetRecord({});
  dataset.inputCharacterSet = '1234567890';
  dataset.outputCharacterSet = '1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  dataset.inputPadCharacter = '*';
  dataset.minInputLength = 10;

  const rules = [];
  const pr = new DatasetPassthroughRule();
  pr.type = 'passthrough';
  pr.priority = 1;
  pr.value = '-';
  rules.push(pr);
  dataset.passthrough_Rules = rules;

  oc.dataset = dataset;
  oc.currentValue = '123-456';

  return oc;
}

it('PadInputOperationTest_simple', async () => {
  const context = setup();
  const pad = new PadInputOperation();
  const original = context.currentValue;

  const padded = await pad.invokeAsync(context);

  expect(padded).to.equal('***123-456');

  const unpad = new UnpadInputOperation();
  context.setCurrentValue(padded);

  const unpadded = await unpad.invokeAsync(context);
  expect(unpadded).to.equal(original);
});

it('PadInputOperationTest_exception', async () => {
  const context = setup();
  // Input string will contain pad character
  context.setCurrentValue('123*456');

  const pad = new PadInputOperation();

  try {
    await pad.invokeAsync(context);
    expect.fail('Should have thrown');
  } catch (err) {
    expect(err.message).to.match(/'\*'/);
  }
});

it('PadInputOperationTest_simple_none_needed', async () => {
  const context = setup();

  const data = context.getData();
  data.set('PassthroughTemplate', 'xxx-xxx');
  context.setData(data);

  const original = '1234567890';
  const op = new PadInputOperation();
  context.setCurrentValue(original);
  const padded = await op.invokeAsync(context);

  expect(padded).to.equal(original);
  expect(context.getData().get('PassthroughTemplate')).to.equal('***xxx-xxx');

  const unpad = new UnpadInputOperation();
  context.setCurrentValue(padded);

  const unpadded = await unpad.invokeAsync(context);
  expect(unpadded).to.equal(original);
});

it('PadInputOperationTest_simple_template_padded', async () => {
  const context = setup();

  const original = context.getCurrentValue();
  const data = context.getData();
  data.set('PassthroughTemplate', 'xxx-xxx');
  context.setData(data);

  const op = new PadInputOperation();
  const padded = await op.invokeAsync(context);

  expect(padded).to.equal('***123-456');
  expect(context.getData().get('PassthroughTemplate')).to.equal('***xxx-xxx');

  const unpad = new UnpadInputOperation();
  context.setCurrentValue(padded);

  const unpadded = await unpad.invokeAsync(context);
  expect(unpadded).to.equal(original);
  expect(context.getData().get('PassthroughTemplate')).to.equal('xxx-xxx');
});

it('PadInputOperationTest_trim_pad', () => {
  let src = '123045607890';
  let ret = strUtils.trimLeftPad(src, '0');
  expect(ret).to.equal(src);

  src = '01230456067890';
  ret = strUtils.trimLeftPad(src, '0');
  expect(ret).to.equal(src.substring(1));

  src = '0000';
  ret = strUtils.trimLeftPad(src, '0');
  expect(ret).to.equal('');

  src = '00001';
  ret = strUtils.trimLeftPad(src, '0');
  expect(ret).to.equal('1');
});

