// SPDX-License-Identifier: Apache-2.0 OR MIT
// The callback owns plaintext copies and external effects. Cancelling this wait
// cannot undo those effects or stop its Promise; the original inbox stays pending.
export class ApplicationExchange {
  #timer; #poll; #cancelled; #stop; #finished = false; #code = 0; #outcome;
  static start(callback, session, message, plaintext, milliseconds, cancelled) {
    if (typeof callback !== 'function' || typeof cancelled !== 'function'
        || !(session instanceof Uint8Array) || session.length !== 32
        || !(message instanceof Uint8Array) || message.length !== 32
        || !(plaintext instanceof Uint8Array) || plaintext.length > 16384
        || !Number.isFinite(milliseconds) || milliseconds <= 0 || milliseconds > 60000) {
      throw new TypeError('invalid application invocation');
    }
    return new ApplicationExchange(callback, session.slice(), message.slice(), plaintext.slice(), milliseconds, cancelled);
  }
  constructor(callback, session, message, plaintext, milliseconds, cancelled) {
    this.#cancelled = cancelled;
    const stopped = new Promise(resolve => { this.#stop = resolve; });
    this.#timer = setTimeout(() => this.#fail(3), milliseconds);
    this.#poll = setInterval(() => { if (this.#cancelled?.()) this.#fail(2); }, 25);
    const work = this.#call(callback, session, message, plaintext);
    // Both branches resolve structured outcomes, even after the SDK stopped waiting.
    this.#outcome = Promise.race([work, stopped]).then(result => {
      this.#code = result.code; this.#finished = true; this.#detach(); return result;
    });
  }
  #detach() { clearTimeout(this.#timer); clearInterval(this.#poll); this.#cancelled = undefined; }
  #fail(code) {
    if (this.#finished) return;
    const error = new Error(code === 3 ? 'application deadline; external outcome unknown' : 'application cancelled; external outcome unknown');
    error.applicationPending = true;
    this.#stop({ ok: false, code, failure: error }); this.#detach();
  }
  async #call(callback, session, message, plaintext) {
    if (this.#cancelled?.()) {
      this.#fail(2);
      return { ok: false, code: 2, failure: new Error('application cancelled before dispatch') };
    }
    try {
      const value = await callback(session, message, plaintext);
      if (value !== undefined) throw new TypeError('application consumer must complete with void');
      return { ok: true, code: 0 };
    } catch (failure) { return { ok: false, code: 1, failure }; }
  }
  cancel() { this.#fail(2); this.#detach(); }
  code() { return this.#code; }
  async reply() {
    const result = await this.#outcome;
    if (!result.ok) throw result.failure;
  }
}
