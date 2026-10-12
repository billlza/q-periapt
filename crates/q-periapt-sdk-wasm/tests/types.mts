import { QPeriaptRuntime, QPeriaptKeyPurpose } from 'q-periapt-sdk-wasm';
import { QPeriaptExpert } from 'q-periapt-sdk-wasm/expert';
import initialize, { QPeriaptRuntime as WebRuntime } from 'q-periapt-sdk-wasm/web';
import { QPeriaptExpert as WebExpert } from 'q-periapt-sdk-wasm/web/expert';
import { QPeriaptPolicyStore } from 'q-periapt-sdk-wasm/web/storage';
const data = new Uint8Array();
const runtime: QPeriaptRuntime = new QPeriaptRuntime(data, data, data, data, 32, 4);
const key = runtime.generate_key();
const secret = key.decapsulate(data, data);
const application = secret.derive_key(QPeriaptKeyPurpose.Exporter, data, data);
const bytes: Uint8Array = application.export_for_protocol();
QPeriaptExpert.import_expanded(runtime, bytes);
const ready: Promise<void> = initialize();
const web = new WebRuntime(data, data, data, data, 32, 4);
WebExpert.import_expanded(web, bytes);
void ready;
async function durablePolicy() {
  const store = await QPeriaptPolicyStore.open({ name: 'installation', root: data });
  const original: Uint8Array = store.trustedState();
  const next: Uint8Array = await store.replacePolicy(original, data, data);
  store.generateKey().close();
  await store.close();
  return next;
}
void durablePolicy;
