// SPDX-License-Identifier: Apache-2.0 OR MIT
import { fail } from './storage-catalogue.js';

// The caller owns this handle before asynchronous lease/database acquisition.
// A completed root remains here until synchronous take(); abandoning a pending
// result closes it and preserves the root's actual native-release receipts.
export class StorageOpening {
  #root; #ready = false; #abandoned = false; #taken = false; #outcome;
  constructor(start) {
    this.#outcome = (async () => {
      try {
        const result = await start(root => {
          if (this.#root) throw fail('Conflict');
          this.#root = root;
          if (this.#abandoned) root.beginClose();
        });
        if (result !== this.#root) throw fail('Corrupt');
        this.#ready = true;
        return {};
      } catch (error) {
        this.#root?.beginClose();
        return { error };
      }
    })();
  }
  async ready() {
    const result = await this.#outcome;
    if (result.error) throw result.error;
    if (this.#abandoned || this.#taken) throw fail('Closed');
  }
  take() {
    if (this.#abandoned || this.#taken) throw fail('Closed');
    if (!this.#ready || !this.#root) throw fail('Busy');
    const root = this.#root;
    root.check();
    this.#root = undefined; this.#taken = true;
    return root;
  }
  abandon() {
    if (this.#taken) return;
    this.#abandoned = true;
    this.#root?.beginClose();
  }
}
