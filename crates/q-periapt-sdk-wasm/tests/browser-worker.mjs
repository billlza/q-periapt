// SPDX-License-Identifier: Apache-2.0 OR MIT
import { runAcceptance } from './browser-suite.mjs';

const mode = new URL(location.href).searchParams.get('mode');
const result = await runAcceptance(mode, 'worker');
postMessage(result);
close();
