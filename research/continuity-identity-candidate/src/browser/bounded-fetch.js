// SPDX-License-Identifier: Apache-2.0 OR MIT
class BrowserTransportError extends Error {
  constructor(code, cause) { super('Browser transport: ' + code, { cause }); this.code = code; }
}
const fail = (code, cause) => new BrowserTransportError(code, cause);

export function httpEndpoint(value, loopback) {
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

export class HttpExchange {
  #controller = new AbortController(); #timer; #poll; #cancelled; #reason; #finished = false; #outcome;
  static start(endpoint, request, milliseconds, cancelled, profile) {
    const bounds = profile === 1 ? [3674, 3674, 3659, 3659] : profile === 2 ? [10, 32768, 10, 32768] : undefined;
    if (!bounds || !(request instanceof Uint8Array) || request.length < bounds[0] || request.length > bounds[1]
        || !Number.isFinite(milliseconds) || milliseconds <= 0 || milliseconds > 60000
        || typeof cancelled !== 'function') throw fail('InvalidResponse');
    return new HttpExchange(endpoint, request.slice(), milliseconds, cancelled, bounds);
  }
  constructor(endpoint, request, milliseconds, cancelled, bounds) {
    this.#cancelled = cancelled;
    this.#timer = setTimeout(() => this.#abort('Timeout'), milliseconds);
    this.#poll = setInterval(() => {
      if (this.#cancelled?.()) this.#abort('Cancelled');
    }, 25);
    // The stored outcome never rejects without a consumer. reply() exposes the
    // original failure; dropping a Rust future cancels instead of leaving an
    // unhandled rejection or a callable freed Rust closure in a JS timer.
    this.#outcome = this.#run(endpoint, request, bounds);
  }
  #detach() { clearTimeout(this.#timer); clearInterval(this.#poll); this.#cancelled = undefined; }
  #abort(code) {
    if (this.#finished) return;
    this.#reason ??= fail(code);
    this.#detach(); this.#controller.abort();
  }
  cancel() { this.#abort('Cancelled'); this.#detach(); }
  async #run(endpoint, request, bounds) {
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
      if (length !== null && (!/^[1-9][0-9]{0,4}$/.test(length) || Number(length) < bounds[2] || Number(length) > bounds[3])) throw fail('InvalidResponse');
      reader = response.body.getReader();
      const bytes = new Uint8Array(bounds[3]); let offset = 0;
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        if (!(chunk.value instanceof Uint8Array) || offset + chunk.value.length > bytes.length) throw fail('InvalidResponse');
        bytes.set(chunk.value, offset); offset += chunk.value.length;
      }
      if (offset < bounds[2] || (length !== null && offset !== Number(length))) throw fail('InvalidResponse');
      if (this.#cancelled?.()) this.#abort('Cancelled');
      if (this.#reason) throw this.#reason;
      return { bytes: bytes.subarray(0, offset) };
    } catch (cause) {
      this.#controller.abort();
      return { error: this.#reason ?? (cause instanceof BrowserTransportError ? cause : fail('Network', cause)) };
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
