const required = (value, message) => { if (!value) throw Error(message); };
const random = size => [...crypto.getRandomValues(new Uint8Array(size))];
const scope = {name:'installed-session-' + random(12).map(x=>x.toString(16).padStart(2,'0')).join(''),id:random(32)};
let worker, original, prepared;
async function launch() {
  worker = new Worker('/worker.js', {type:'module'});
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('Worker initialization deadline')),15000);
    worker.onmessage=({data})=>{if(data.ready){clearTimeout(timer);resolve();}};
    worker.onerror=e=>{clearTimeout(timer);reject(Error(e.message));};
  });
}
function invoke(args) {
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('Worker operation deadline')),90000);
    worker.onmessage=({data})=>{
      clearTimeout(timer);
      if(data.error) {reject(Error(JSON.stringify(data.error)));return;}
      if(data.cut) {args.cut?resolve(data.cut):reject(Error('unexpected Worker cut'));return;}
      args.cut?reject(Error('Worker returned before requested cut')):resolve(data.result);
    };
    worker.postMessage(args);
  });
}
async function terminate() {
  worker.terminate();
  const start=performance.now(),observations=[];
  for (;;) {
    const current=await navigator.locks.query();
    const count=[...current.held,...current.pending].filter(row=>row.name==='qperiapt-continuity-storage/2/'+scope.name).length;
    observations.push({elapsed_ms:performance.now()-start,count});
    if(!count)return observations;
    required(performance.now()-start<15000,'terminated Worker retained original lease');
    await new Promise(resolve=>setTimeout(resolve,20));
  }
}
globalThis.runPhase=async (phase, details)=>{
  if(phase==='create') {await launch();return {...await invoke({op:'create',scope}),scope};}
  if(phase==='witness-prepare') {
    prepared=await invoke({op:'witness-prepare',scope});return prepared;
  }
  if(['witness-missing','witness-unenrolled','witness-offline'].includes(phase)) {
    if(phase!=='witness-missing') await launch();
    const result=await invoke({op:'witness-refusal',kind:phase.slice('witness-'.length),scope,prepared});
    return {...result,leases:await terminate()};
  }
  if(phase==='activate') {
    if(prepared) await launch();
    original=await invoke({op:'activate',scope,prepared,request:random(32)});
    const leases=await terminate();
    return {...original,leases};
  }
  if(phase==='resume') {
    await launch();const result=await invoke({op:'resume',scope,original});
    const leases=await terminate();return {...result,leases};
  }
  if(phase==='receive-first' || phase==='receive-retry') await launch();
  if(['receive-first','receive-cut','receive-retry','receive-last'].includes(phase)) {
    const result=await invoke({op:'receive',scope,original,...details,
      cut:phase==='receive-cut',finish:phase==='receive-last'});
    if(phase==='receive-cut' || phase==='receive-last') return {...result,leases:await terminate()};
    return result;
  }
  throw Error('unknown phase');
};
globalThis.fixtureReady=true;
