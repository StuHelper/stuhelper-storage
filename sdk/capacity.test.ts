import assert from 'node:assert/strict';
import test from 'node:test';
import { defaultQuotaUnit, formatBytes, formatQuotaInput, parseQuotaBytes } from './capacity.ts';

test('capacities use binary units for both display and input', () => {
  assert.equal(formatBytes('en-US', 500 * 2 ** 30), '500 GB');
  assert.equal(formatBytes('en-US', 1023), '1,023 byte');
  assert.equal(formatBytes('en-US', 1024), '1 kB');
  assert.equal(parseQuotaBytes('1.5', 'GB'), 1_610_612_736);
  assert.equal(parseQuotaBytes('0.000000001', 'GB'), 1);
  assert.equal(defaultQuotaUnit(0), 'GB');
  assert.equal(defaultQuotaUnit(2 ** 40), 'TB');
  assert.equal(defaultQuotaUnit(1024), 'B');
  assert.equal(formatQuotaInput(50 * 2 ** 30, 'GB'), '50');
});

test('quota editing preserves every supported byte count including legacy decimal quotas', () => {
  for (const unit of ['B', 'GB', 'TB'] as const) {
    for (const bytes of [0, 1, 2, 1023, 1024, 2 ** 30 - 1, 2 ** 30, 50_000_000_000,
      2 ** 40 - 1, 2 ** 40 + 1, Number.MAX_SAFE_INTEGER - 1, Number.MAX_SAFE_INTEGER]) {
      assert.equal(parseQuotaBytes(formatQuotaInput(bytes, unit), unit), bytes);
    }
  }
});

test('invalid, sub-byte and out-of-range inputs fail validation', () => {
  for (const value of ['', 'NaN', '-1', '1e9', '1.', '.5', '0.0000000001', '9999999999999999']) {
    assert.equal(parseQuotaBytes(value, 'GB'), undefined);
  }
  assert.equal(parseQuotaBytes('1.0', 'B'), undefined);
  assert.equal(parseQuotaBytes('1.00000000000001', 'TB'), undefined);
  for (const bytes of [-1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => formatQuotaInput(bytes, 'GB'), RangeError);
  }
});
