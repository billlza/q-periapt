from pathlib import Path
from datetime import datetime,timezone
import ast,hashlib,json,os,stat,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,"/workspace/scratch/qperiapt-recovery-20261111/unit-state-qualified/source/production")
from bounded_process import capture_output
ROOT=Path(__file__).resolve().parent
repo=ROOT/"cold"
helper=Path("/workspace/scratch/qperiapt-recovery-20261111/fixture-baab-prefetch-fix/artifact/codeql_fixture_baab.py")
tree=ast.parse(helper.read_text())
sources=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="SOURCES" for t in n.targets)))
(ROOT/"commands").mkdir(exist_ok=True)
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(v):return sha(json.dumps(v,sort_keys=True,separators=(",",":")).encode())
records={}
env={**os.environ,"GIT_TERMINAL_PROMPT":"0","GIT_CONFIG_GLOBAL":"/dev/null","GIT_CONFIG_NOSYSTEM":"1"}
def run(name,argv):
    started=time.monotonic()
    record={"argv":argv,"maximum_seconds":180,"started_utc":datetime.now(timezone.utc).isoformat()}
    save(ROOT/"commands"/(name+".started.json"),record)
    print(name+" started",flush=True)
    try:
        with (ROOT/"commands"/(name+".stdout")).open("xb") as out,(ROOT/"commands"/(name+".stderr")).open("xb") as err:
            result=capture_output(argv,timeout_seconds=180,maximum_stdout_bytes=32*1024**2,
                maximum_stderr_bytes=16*1024**2,environment={**env,"GIT_TRACE":str(ROOT/"commands"/(name+".trace"))},
                stdout_sink=out.write,stderr_sink=err.write)
        record.update(returncode=result.returncode)
        assert result.returncode==0,(name,result.stderr[-2000:])
        return result.stdout
    except BaseException as error:
        record.update(error=type(error).__name__,message=str(error),cleanup_ambiguous=getattr(error,"cleanup_ambiguous",None))
        raise
    finally:
        record["elapsed_seconds"]=time.monotonic()-started;records[name]=record
        save(ROOT/"commands"/(name+".json"),record)
        print(name+" finished "+str(record["elapsed_seconds"]),flush=True)
try:
    run("version",["/usr/bin/git","--version"])
    run("clone",["/usr/bin/git","-c","credential.interactive=false","clone","--filter=blob:none",
        "--no-checkout","--depth=1","--single-branch","--branch","diagnostic/codeql-fixture-baab",
        "https://github.com/billlza/q-periapt.git",str(repo)])
    run("fetch-sources",["/usr/bin/git","-C",str(repo),"fetch","--filter=blob:none","--no-tags","--depth=1",
        "origin",*[x[0] for x in sources.values()]])
    entries,attrs={},set()
    for side,pin in sources.items():
        listing=run("tree-"+side,["/usr/bin/git","-C",str(repo),"ls-tree","-rz",pin[0],"artifact",".gitattributes"])
        entries[side]={}
        for item in listing.rstrip(b"\0").split(b"\0"):
            header,path=item.split(b"\t",1);mode,kind,digest=header.decode().split();name=path.decode()
            assert mode in ("100644","100755") and kind=="blob" and len(digest)==40
            if name==".gitattributes":attrs.add(digest);continue
            assert name.startswith("artifact/") and name not in entries[side]
            entries[side][name]={"mode":mode,"git_blob":digest}
    oids=sorted(attrs|{v["git_blob"] for e in entries.values() for v in e.values()})
    before=run("missing-before",["/usr/bin/git","-C",str(repo),"rev-list","--objects","--missing=print",*[x[0] for x in sources.values()]])
    missing_before={x.decode()[1:] for x in before.splitlines() if x.startswith(b"?")}
    assert set(oids)&missing_before,"cold source objects were not missing"
    run("prefetch",["/usr/bin/git","-C",str(repo),"-c","fetch.negotiationAlgorithm=noop","fetch","--no-tags",
        "--no-write-fetch-head","--recurse-submodules=no","--filter=blob:none","origin",*oids])
    after=run("missing-after",["/usr/bin/git","-C",str(repo),"rev-list","--objects","--missing=print",*[x[0] for x in sources.values()]])
    missing_after={x.decode()[1:] for x in after.splitlines() if x.startswith(b"?")}
    assert not (set(oids)&missing_after)
    inventories={}
    for side,pin in sources.items():
        archive=ROOT/(side+".tar");destination=ROOT/side;destination.mkdir()
        run("archive-"+side,["/usr/bin/git","-C",str(repo),"archive","--format=tar","--prefix=artifact/","--output="+str(archive),pin[0]+":artifact"])
        trace=(ROOT/"commands"/("archive-"+side+".trace")).read_text()
        fetches=[line for line in trace.splitlines() if "run_command:" in line and any(x in line for x in (" fetch "," remote-https ","fetch-pack"))]
        assert not fetches,fetches
        run("unpack-"+side,["/usr/bin/tar","--extract","--file="+str(archive),"--no-same-owner","--directory="+str(destination)])
        files={}
        for path in sorted(destination.rglob("*")):
            assert not path.is_symlink()
            if path.is_dir():continue
            assert path.is_file()
            name=path.relative_to(destination).as_posix();data=path.read_bytes()
            blob=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
            assert blob==entries[side][name]["git_blob"]
            files[name]={"bytes":len(data),"sha256":sha(data)}
        assert set(files)==set(entries[side])
        assert files["artifact/codeql_summary_projection.json"]["sha256"]==pin[1]
        save(ROOT/(side+"-inventory.json"),{"git_entries":entries[side],"files":files})
        inventories[side]={"files":len(files),"bytes":sum(x["bytes"] for x in files.values()),
            "inventory_sha256":canonical(files),"archive_bytes":archive.stat().st_size,
            "archive_sha256":sha(archive.read_bytes()),"archive_lazy_fetches":fetches}
    result={"status":"passed_cold_public_bulk_prefetch_complete_subtree_snapshots","helper_sha256":sha(helper.read_bytes()),
        "sources":{s:p[0] for s,p in sources.items()},"blob_oids":len(oids),"attributes":sorted(attrs),
        "required_missing_before":len(set(oids)&missing_before),"required_missing_after":len(set(oids)&missing_after),
        "inventories":inventories,"commands":records,"codeql_or_ci_executed":False}
    save(ROOT/"RESULT.json",result);print(json.dumps({k:v for k,v in result.items() if k!="commands"},indent=2),flush=True)
except BaseException as error:
    save(ROOT/"FAILURE.json",{"error":type(error).__name__,"message":str(error),"commands":records})
    raise
