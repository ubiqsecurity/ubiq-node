const bigInt = require('big-integer');
const bn = require('../lib/structured/Bn');

/*
12/20/21
Check in initial set of unit tests.

How to execute:

$ npm run test


 PASS  test/Bn.test.js
  ✓ radix_exceptions (10 ms)
  ✓ radix_edgecase (1 ms)
  ✓ radix_dec2hex (1 ms)
  ✓ radix_oct2hex
  ✓ radix_dec2dec (1 ms)
  ✓ radix_oct2dec

Test Suites: 1 passed, 1 total
Tests:       6 passed, 6 total
Snapshots:   0 total
Time:        0.258 s, estimated 1 s
Ran all test suites.
*/

test('radix_exceptions', () => {
  expect(() => bn.bigint_set_str('109', '012345678')).toThrow();
  expect(() => bn.bigint_set_str('109', '')).toThrow();
  expect(() => bn.bigint_get_str('', 0)).toThrow();
});

test('radix_edgecase', () => {
  const r1 = bn.bigint_set_str('0', '0123456789');
  expect(r1.value).toBe(bigInt(0).value);
  // expect(bn.bigint_get_str('0123456789ABCDEF', r1.value).value).toBe(bigInt(0).value); // todo enable
  expect(bn.bigint_get_str('0123456789ABCDEF', 0)).toBe('0');
});

test('radix_dec2hex', () => {
  const r1 = bn.bigint_set_str('100', '0123456789');
  expect(r1.value).toBe(bigInt(100).value);
  expect(bn.bigint_get_str('0123456789ABCDEF', r1)).toBe('64');
});

test('radix_oct2hex', () => {
  const r1 = bn.bigint_set_str('100', '01234567');
  expect(r1.value).toBe(bigInt(64).value);
  expect(bn.bigint_get_str('0123456789ABCDEF', r1)).toBe('40');
});

test('radix_dec2dec', () => {
  const r1 = bn.bigint_set_str('@$#', '!@#$%^&*()');
  expect(r1.value).toEqual(bigInt(132).value);
  expect(bn.bigint_get_str('0123456789', r1)).toBe('132');
});

test('radix_oct2dec', () => {
  const r1 = bn.bigint_set_str('@$#', '!@#$%^&*');
  expect(r1.value).toEqual(bigInt(90).value);
  expect(bn.bigint_get_str('0123456789', r1)).toEqual('90');
});

test('bigint so_alphanum_po', () => {
  const r1 = bn.bigint_set_str('1234', ' 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  expect(r1.value).toEqual(bigInt(105566).value);
  expect(bn.bigint_get_str(' 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', '105566')).toEqual('1234');
});
