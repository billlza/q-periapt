// SPDX-License-Identifier: Apache-2.0 OR MIT
const worker = new Worker('./late-worker.js', { type: 'module' });
let finished = false;
const timer = setTimeout(() => finish({ completed: false, error: 'overall deadline' }), 125000);

async function finish(data) {
  if (finished) return;
  finished = true;
  clearTimeout(timer);
  worker.terminate();
  globalThis.result = data;
  document.querySelector('#result').textContent = JSON.stringify(data, null, 2);
  const response = await fetch('./capture/RESULT.json', { method: 'POST', body: JSON.stringify(data, null, 2) });
  if (!response.ok) throw Error('capture failed');
  globalThis.captureComplete = true;
}

worker.onmessage = ({ data }) => {
  if (data.progress) document.querySelector('#result').textContent = data.progress;
  else void finish(data);
};
worker.onerror = event => { void finish({ completed: false, error: event.message }); };
