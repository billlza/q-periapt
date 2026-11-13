// SPDX-License-Identifier: Apache-2.0 OR MIT
// Use typed-array internal slots, never a caller's length/buffer/species hooks.
// These functions are imported with wasm-bindgen `catch`: exceptions must return
// through Rust so its input buffers and borrowed owner guards are released.
const prototype = Object.getPrototypeOf(Uint8Array.prototype);
const length = Object.getOwnPropertyDescriptor(prototype, 'length').get;
const tag = Object.getOwnPropertyDescriptor(prototype, Symbol.toStringTag).get;
const set = Uint8Array.prototype.set;
const apply = Reflect.apply;

export function inputLength(input, minimum, maximum) {
  if (apply(tag, input, []) !== 'Uint8Array') return -1;
  const size = apply(length, input, []);
  return size < minimum || size > maximum ? -2 : size;
}

export function copyInput(input, output) {
  if (apply(tag, input, []) !== 'Uint8Array'
      || apply(length, input, []) !== apply(length, output, [])) {
    throw new TypeError('byte-array input changed before copying');
  }
  // The intrinsic checks detached/out-of-bounds views and performs a typed-array
  // copy without invoking input iterators, index getters or constructor species.
  apply(set, output, [input]);
}
