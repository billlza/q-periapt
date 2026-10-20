// SPDX-License-Identifier: Apache-2.0 OR MIT
import {equal} from './transport.mjs';
export function require(value, message) { if (!value) throw new Error(message); }
export function fields(value, expected) {
  require(value && !Array.isArray(value) && typeof value === 'object' && equal(Object.keys(value).sort(), expected.split(' ').sort()), 'Unexpected recovery record fields');
}
export function id(value, size = 32) {
  require(Array.isArray(value) && value.length === size && value.every(b => Number.isInteger(b) && b >= 0 && b <= 255) && value.some(b => b !== 0), 'Invalid operation or device identity');
  return value;
}
export function integer(value, positive = false) {
  require(typeof value === 'bigint' || Number.isSafeInteger(value), 'Invalid exact integer');
  require(BigInt(value) >= (positive ? 1n : 0n) && BigInt(value) <= 18446744073709551615n, 'Integer outside u64 range');
}
export function checkpoint(value) {
  if (value === null) return;
  fields(value, 'version digest'); integer(value.version, true); id(value.digest);
}
