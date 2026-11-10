// Separate host business state: effect and deduplication share one transaction.
const required = (value, message) => { if (!value) throw Error(message); };
const equal = (a, b) => a.length === b.length && a.every((value, i) => value === b[i]);
const hex = value => [...value].map(x => x.toString(16).padStart(2, '0')).join('');

export async function openEffects(name) {
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open(name + '-application-effects', 1);
    let blocked = false;
    request.onupgradeneeded = () => request.result.createObjectStore('effects', {keyPath: 'key'});
    request.onerror = () => reject(request.error);
    request.onblocked = () => { blocked = true; reject(Error('host effect store blocked')); };
    request.onsuccess = () => { if (blocked) request.result.close(); else resolve(request.result); };
  });
  required(db.objectStoreNames.length === 1 && db.objectStoreNames.contains('effects'), 'host store schema differs');
  return {
    close() { db.close(); },
    async commit(session, message, plaintext) {
      required(session.length === 32 && message.length === 32 && plaintext.length <= 16384, 'host effect input bound');
      return await new Promise((resolve, reject) => {
        const transaction = db.transaction('effects', 'readwrite', {durability: 'strict'});
        required(transaction.durability === 'strict', 'host transaction durability differs');
        const store = transaction.objectStore('effects');
        const key = hex(session) + ':' + hex(message);
        let result, failure;
        transaction.oncomplete = () => resolve(result);
        transaction.onabort = () => reject(failure ?? transaction.error ?? Error('host effect transaction aborted'));
        transaction.onerror = () => { failure ??= transaction.error; };
        const request = store.get(key);
        request.onsuccess = () => {
          const old = request.result;
          if (old !== undefined && (!equal(old.session, [...session]) || !equal(old.message, [...message])
              || !equal(old.plaintext, [...plaintext]) || old.applications !== 1 || !Number.isSafeInteger(old.calls) || old.calls < 1)) {
            failure = Error('host deduplication conflicts with original effect'); transaction.abort(); return;
          }
          result = old === undefined
            ? {key, session: [...session], message: [...message], plaintext: [...plaintext], applications: 1, calls: 1}
            : {...old, calls: old.calls + 1};
          store.put(result);
        };
      });
    },
    async snapshot() {
      return await new Promise((resolve, reject) => {
        const transaction = db.transaction('effects', 'readonly');
        const request = transaction.objectStore('effects').getAll();
        transaction.oncomplete = () => resolve(request.result);
        transaction.onabort = () => reject(transaction.error ?? Error('host effect read aborted'));
        transaction.onerror = () => reject(transaction.error ?? Error('host effect read failed'));
      });
    },
  };
}
