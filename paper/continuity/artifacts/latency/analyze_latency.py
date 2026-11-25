#!/usr/bin/env python3
"""Recompute all retained means/quantiles and verify evidence and generated TeX.

python analyze_latency.py --check
python analyze_latency.py --results-dir /path/to/new-results
"""
if not __debug__:
    raise SystemExit('Refusing optimized Python: validation requires assertions to remain enabled.')
import argparse, csv, hashlib, json, math, pathlib, statistics, tarfile

ROOT=pathlib.Path(__file__).resolve().parent
NAMES=[('mlkem768_keygen','ML-KEM-768 key generation'),('mlkem768_encapsulate','ML-KEM-768 encapsulation'),('mlkem768_decapsulate','ML-KEM-768 decapsulation'),('mldsa65_keygen','ML-DSA-65 key generation'),('mldsa65_sign','ML-DSA-65 signing'),('mldsa65_verify','ML-DSA-65 verification')]
HEADER=r'''% Means recomputed from the retained 358b921a raw timing batches.
\begin{table}[t]
\centering
\small
\caption{Warmed backend operation costs on the stated virtualized host.
Each mean covers 1,600 calls; all times are in milliseconds.}
\label{tab:primitive-latency}
\begin{tabularx}{\linewidth}{@{}Xrr@{}}
\toprule
Operation & Mean wall time & Mean CPU time\\
\midrule
'''
FOOTER=r'''\bottomrule
\end{tabularx}
\end{table}
'''
DELIVERY_HEADER=r'''% Statistics recomputed from all 256 retained individual delivery intervals.
\begin{table}[t]
\centering
\small
\caption{Same-host delivery costs between two native file journals in an
established session. All times are in milliseconds. The 95th percentile
uses the nearest rank among all 256 individual message intervals.}
\label{tab:delivery-latency}
\begin{tabularx}{\linewidth}{@{}Xrrrr@{}}
\toprule
Interval & Mean & Median & 95th percentile & Maximum\\
\midrule
'''
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def stats(v):
    s=sorted(v)
    return {'mean_ms':statistics.mean(v),'sample_sd_ms':statistics.stdev(v),'median_ms':statistics.median(v),
            'p95_ms':s[math.ceil(.95*len(s))-1],'p99_ms':s[math.ceil(.99*len(s))-1],'min_ms':s[0],'max_ms':s[-1]}
def derive(base):
    raw=base/'primitive-raw.csv';rows=list(csv.DictReader(raw.open()));groups={}
    for r in rows:groups.setdefault(r['operation'],[]).append(r)
    assert set(groups)=={v[0] for v in NAMES}|{'timer_control'}, 'primitive operation set'
    primitive=[]
    for op,rs in sorted(groups.items()):
        assert len(rs)==200 and sorted(int(r['sample']) for r in rs)==list(range(200)),op
        assert all(int(r['iterations'])==8 for r in rs),op
        item={'operation':op,'samples':len(rs),'iterations_per_sample':8,'total_calls':sum(int(r['iterations']) for r in rs)}
        for field,prefix in [('wall_ns','wall'),('process_cpu_ns','cpu')]:
            values=[int(r[field])/8/1e6 for r in rs];assert min(values)>0
            item[prefix+'_mean_ms']=statistics.mean(values);item[prefix+'_sample_sd_ms']=statistics.stdev(values)
            item[prefix+'_batch_p50_ms']=statistics.median(values);item[prefix+'_batch_p95_ms']=sorted(values)[math.ceil(.95*len(values))-1]
            item[prefix+'_min_ms']=min(values);item[prefix+'_max_ms']=max(values)
        primitive.append(item)
    env=json.loads((base/'environment.json').read_text())
    assert env['exit_code']==0 and env['raw_sha256']==sha(raw), 'primitive execution/raw hash'
    summary={'schema':'qperiapt-supporting-latency-summary-v1','source_sha256':sha(raw),'all_samples_retained':True,
             'statistics':'Arithmetic means of 200 equal-size 8-call batches; no subtraction; p95 is batch-average only','rows':primitive}
    index={r['operation']:r for r in primitive}
    tex=HEADER+''.join(f"{label} & {index[name]['wall_mean_ms']:.3f} & {index[name]['cpu_mean_ms']:.3f}\\\\\n" for name,label in NAMES)+FOOTER
    raw=base/'delivery-raw.csv';rows=list(csv.DictReader(raw.open()))
    assert len(rows)==256,'delivery sample count'
    assert {(int(r['pair']),int(r['sample'])) for r in rows}=={(i,j) for i in range(16) for j in range(16)},'delivery inventory'
    assert sum(r['direction']=='i_to_r' for r in rows)==128 and sum(r['direction']=='r_to_i' for r in rows)==128,'directions'
    for r in rows:
        assert int(r['payload_bytes'])==1024 and int(r['ad_bytes'])==32
        assert int(r['wall_ns'])==int(r['sender_wall_ns'])+int(r['receiver_wall_ns'])
        assert min(int(r[k]) for k in ['wall_ns','process_cpu_ns','sender_wall_ns','receiver_wall_ns'])>0
    denv=json.loads((base/'delivery-environment.json').read_text());assert denv['exit_code']==0 and denv['raw_sha256']==sha(raw)
    delivery={'schema':'qperiapt-local-delivery-summary-v1','samples':len(rows),'all_samples_retained':True,
              'quantile_rule':'nearest rank, ceil(p*n), one indexed','metrics':{k:stats([int(r[k])/1e6 for r in rows]) for k in ['wall_ns','process_cpu_ns','sender_wall_ns','receiver_wall_ns']}}
    delivery_tex=DELIVERY_HEADER+''.join(label+' & '+' & '.join(f"{delivery['metrics'][name][k]:.3f}" for k in ['mean_ms','median_ms','p95_ms','max_ms'])+'\\\\\n' for name,label in [('wall_ns','Wall-clock'),('process_cpu_ns','Process CPU')])+FOOTER
    return summary,delivery,tex,delivery_tex
def verify_inventory():
    manifest=json.loads((ROOT/'MANIFEST.json').read_text())
    for e in manifest['files']:
        p=ROOT/e['path'];assert p.is_file(),e['path'];assert p.stat().st_size==e['bytes'],e['path'];assert sha(p)==e['sha256'],e['path']
    inv=json.loads((ROOT/'sources/inventory-358b.json').read_text());assert inv['commit']=='358b921ab3469ce49f166633fc9a762ff6ed7e3d'
    expected={e['path']:e for e in inv['files']}
    local={e['path']:e for e in inv.get('added_harness_files',[])}
    with tarfile.open(ROOT/'sources/upstream-358b.tar.gz') as archive:
        assert {m.name for m in archive.getmembers()}==set(expected)|set(local),'source archive inventory'
        for m in archive.getmembers():
            assert m.isfile() and not m.name.startswith('/') and '..' not in pathlib.PurePosixPath(m.name).parts
            b=archive.extractfile(m).read();e=expected.get(m.name) or local[m.name]
            assert hashlib.sha256(b).hexdigest()==e['sha256'],m.name
            if m.name in expected:assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==e['sha'],m.name
    return len(manifest['files']),len(expected)
def main():
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');p.add_argument('--results-dir',type=pathlib.Path);p.add_argument('--paper-table',type=pathlib.Path);a=p.parse_args()
    base=a.results_dir or ROOT/'results/358b';primitive,delivery,tex,delivery_tex=derive(base)
    outputs={base/'primitive-summary.json':json.dumps(primitive,indent=2),base/'delivery-summary.json':json.dumps(delivery,indent=2)}
    table=ROOT/'analysis/primitive-table.tex' if a.results_dir is None else base/'primitive-table.tex';outputs[table]=tex
    delivery_table=ROOT/'analysis/delivery-latency-table.tex' if a.results_dir is None else base/'delivery-latency-table.tex';outputs[delivery_table]=delivery_tex
    if a.check:
        for path,body in outputs.items():assert path.read_text()==body,'derived output differs: '+str(path)
        count,sources=verify_inventory()
        paper=a.paper_table or ROOT.parent.parent/'latency-table.tex'
        if paper.exists():assert paper.read_text()==tex,'paper table differs: '+str(paper)
        paper_delivery=paper.with_name('delivery-latency-table.tex')
        if paper_delivery.exists():assert paper_delivery.read_text()==delivery_tex,'paper delivery table differs: '+str(paper_delivery)
        print(json.dumps({'status':'pass','files':count,'verified_source_blobs':sources,'primitive_calls_per_operation':1600,'delivery_samples':256,'all_samples_retained':True,'paper_table_checked':paper.exists()},indent=2))
    else:
        for path,body in outputs.items():path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body)
        print(json.dumps({'primitive':primitive,'delivery':delivery},indent=2))
if __name__=='__main__':main()
