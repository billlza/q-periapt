// SPDX-License-Identifier: Apache-2.0 OR MIT
import initialize, { QPeriaptContinuityDevice, QPeriaptContinuityEnrollment } from './index.js';
export { initialize };

// Convert the retained fixture's public intent and storage identifier. Every
// operation returns the actual owner created by the installed public SDK.
async function invoke(operation, name, id, root, description) {
  if (typeof id !== 'string' || !/^[0-9a-f]{64}$/.test(id)
      || !(description instanceof Uint8Array) || description.length !== 72) {
    throw new TypeError('Enrollment fixture identifier or description differs');
  }
  const storageId = Uint8Array.from(id.match(/../g), byte => Number.parseInt(byte, 16));
  const fields = new DataView(description.buffer, description.byteOffset, description.byteLength);
  const intent = new QPeriaptContinuityEnrollment(root, description.slice(0, 16),
    fields.getBigUint64(16), description.slice(24, 56),
    fields.getBigUint64(56), fields.getBigUint64(64));
  try { return await QPeriaptContinuityDevice[operation](name, storageId, intent); }
  finally { intent.free(); }
}

export const EnrollmentFixture = Object.freeze({
  create: (...args) => invoke('create', ...args),
  open: (...args) => invoke('open', ...args),
  resume: (...args) => invoke('resume', ...args),
});
