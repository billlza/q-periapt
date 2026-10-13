// SPDX-License-Identifier: Apache-2.0 OR MIT
class WitnessTransportError extends Error {
  constructor(code, cause) { super('Witness transport: ' + code, { cause }); this.code = code; }
}
const fail = (code, cause) => new WitnessTransportError(code, cause);

export function witnessEndpoint(value, loopback) {
  if (!globalThis.isSecureContext || typeof fetch !== 'function') throw fail('Unavailable');
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096) throw fail('InvalidEndpoint');
  let url;
  try { url = new URL(value); } catch (cause) { throw fail('InvalidEndpoint', cause); }
  const allowed = loopback
    ? url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)
    : url.protocol === 'https:';
  if (!allowed || !url.hostname || url.username || url.password || url.hash) throw fail('InvalidEndpoint');
  return url.href;
}

export class WitnessExchange {
  #controller = new AbortController(); #timer; #poll; #cancelled; #reason; #finished = false; #outcome;
  static start(endpoint, request, milliseconds, cancelled) {
    if (!(request instanceof Uint8Array) || request.length !== 3674
        || !Number.isFinite(milliseconds) || milliseconds <= 0 || milliseconds > 60000
        || typeof cancelled !== 'function') throw fail('InvalidResponse');
    return new WitnessExchange(endpoint, request.slice(), milliseconds, cancelled);
  }
  constructor(endpoint, request, milliseconds, cancelled) {
    this.#cancelled = cancelled;
    this.#timer = setTimeout(() => this.#abort('Timeout'), milliseconds);
    this.#poll = setInterval(() => {
      if (this.#cancelled?.()) this.#abort('Cancelled');
    }, 25);
    // The stored outcome never rejects without a consumer. reply() exposes the
    // original failure; dropping a Rust future cancels instead of leaving an
    // unhandled rejection or a callable freed Rust closure in a JS timer.
    this.#outcome = this.#run(endpoint, request);
  }
  #detach() { clearTimeout(this.#timer); clearInterval(this.#poll); this.#cancelled = undefined; }
  #abort(code) {
    if (this.#finished) return;
    this.#reason ??= fail(code);
    this.#detach(); this.#controller.abort();
  }
  cancel() { this.#abort('Cancelled'); this.#detach(); }
  async #run(endpoint, request) {
    let reader;
    try {
      if (this.#cancelled()) this.#abort('Cancelled');
      if (this.#reason) throw this.#reason;
      const response = await fetch(endpoint, { method: 'POST', body: request,
        signal: this.#controller.signal, credentials: 'omit', redirect: 'error',
        cache: 'no-store', referrerPolicy: 'no-referrer', headers: { 'Content-Type': 'application/octet-stream' } });
      if (response.status !== 200) {
        const error = fail('HttpStatus'); error.status = response.status; throw error;
      }
      if (!response.body || response.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/octet-stream') throw fail('InvalidResponse');
      const length = response.headers.get('Content-Length');
      if (length !== null && length !== '3659') throw fail('InvalidResponse');
      reader = response.body.getReader();
      const bytes = new Uint8Array(3659); let offset = 0;
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        if (!(chunk.value instanceof Uint8Array) || offset + chunk.value.length > bytes.length) throw fail('InvalidResponse');
        bytes.set(chunk.value, offset); offset += chunk.value.length;
      }
      if (offset !== bytes.length) throw fail('InvalidResponse');
      if (this.#cancelled?.()) this.#abort('Cancelled');
      if (this.#reason) throw this.#reason;
      return { bytes };
    } catch (cause) {
      this.#controller.abort();
      return { error: this.#reason ?? (cause instanceof WitnessTransportError ? cause : fail('Network', cause)) };
    } finally {
      this.#finished = true; this.#detach(); reader?.releaseLock();
    }
  }
  async reply() {
    const result = await this.#outcome;
    if (result.error) throw result.error;
    return result.bytes;
  }
}
