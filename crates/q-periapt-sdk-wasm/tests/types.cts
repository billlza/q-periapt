import sdk = require('q-periapt-sdk-wasm');
import expert = require('q-periapt-sdk-wasm/expert');
const data = new Uint8Array();
const runtime = new sdk.QPeriaptRuntime(data, data, data, data, 32, 4);
const key = runtime.generate_key();
const bytes: Uint8Array = expert.QPeriaptExpert.export_expanded(key);
void bytes;
