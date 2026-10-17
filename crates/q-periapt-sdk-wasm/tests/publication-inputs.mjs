// SPDX-License-Identifier: Apache-2.0 OR MIT
// Actual public JS/WASM boundary, shared by window and dedicated-worker cases.
export function checkPublicationInputs(sdk, check) {
  const {QPeriaptContinuityPublicationPlan: Plan, QPeriaptContinuityPrekeyKind: Kind} = sdk;
  const directory = new Uint8Array(32).fill(77), request = new Uint8Array(32).fill(55);
  let inspections = 0;
  const hostile = {
    get message() { inspections++; throw new Error('unexpected message access'); },
    get name() { inspections++; throw new Error('unexpected name access'); },
    get code() { inspections++; throw new Error('unexpected code access'); },
    toString() { inspections++; throw new Error('unexpected input coercion'); },
  };
  const rejected = operation => {
    let failure;
    try { operation(); } catch (error) { failure = error; }
    check(failure?.code === 'InvalidInput' && failure.ownerClosed === undefined,
      'publication input crossed the JS/WASM boundary');
  };
  const badKinds = [0, 5, -1, 1.5, 4294967297, -4294967295, NaN, Infinity,
    '1', true, null, undefined, 1n, {valueOf() {return 1}}];
  const plan = new Plan(directory, 1n, 100n);
  try {
    for (const value of badKinds) {
      rejected(() => plan.generate(value, 1n, 100n));
      rejected(() => plan.reuse(request, value, 1n, 100n));
    }
    for (const value of [-1n, -(1n << 64n) + 1n, (1n << 64n) + 1n,
      (1n << 64n) + 100n, 1, '1', true, null, undefined, {valueOf() {return 1n}}, hostile]) {
      rejected(() => new Plan(directory, value, 100n).free());
      rejected(() => new Plan(directory, 0n, value).free());
      rejected(() => plan.generate(Kind.SignedClassical, value, 100n));
      rejected(() => plan.generate(Kind.SignedClassical, 1n, value));
      rejected(() => plan.reuse(request, Kind.OneTimePq, value, 100n));
      rejected(() => plan.reuse(request, Kind.OneTimePq, 1n, value));
    }
    check(inspections === 0, 'untrusted diagnostic properties were inspected');
    plan.generate(Kind.SignedClassical, 1n, 100n);
    plan.generate(Kind.LastResortPq, 1n, 100n);
    check(plan.artifact_size_bound() > 0, 'invalid inputs damaged the original plan');
  } finally { plan.free(); }
}
