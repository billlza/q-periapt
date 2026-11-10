// SPDX-License-Identifier: Apache-2.0 OR MIT
import { run } from './storage-suite.mjs';
self.onmessage = async event => {
  const { id, args } = event.data;
  self.postMessage({ id, result: await run(...args) });
};
