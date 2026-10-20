// SPDX-License-Identifier: Apache-2.0 OR MIT
// Controller test substitute, with IDs taken from the actual served HTML.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
class Element {
  constructor(select) { this.select = select; this.options = []; this.files = []; this.textContent = ''; this.disabled = false; this.current = ''; }
  get value() { return this.current; }
  set value(v) { this.current = this.select && !this.options.some(o => o.value === v) ? '' : v; }
  replaceChildren(...options) { this.options = options; this.current = options[0]?.value || ''; }
  add(option) { this.options.push(option); }
}
export async function withDOM(work) {
  const old = {document: globalThis.document, Option: globalThis.Option};
  const html = readFileSync(new URL('../../web/index.html', import.meta.url), 'utf8'), nodes = new Map();
  for (const match of html.matchAll(/<([a-z]+)[^>]*\bid="([^"]+)"/g)) nodes.set(match[2], new Element(match[1] === 'select'));
  globalThis.document = {getElementById(id) { assert.ok(nodes.has(id), `Actual HTML must contain ${id}`); return nodes.get(id); }};
  globalThis.Option = class { constructor(text, value) { this.text = text; this.value = value; } };
  try { await work(id => globalThis.document.getElementById(id)); }
  finally { globalThis.document = old.document; globalThis.Option = old.Option; }
}
