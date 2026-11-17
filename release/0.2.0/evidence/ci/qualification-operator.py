"""Record full CI success only after every selected job actually completes."""
from pathlib import Path
import hashlib,json,subprocess
from publication_receipt_io import canonical_json_bytes
import sdk_github_publication_contract as contract

root=Path(__file__).resolve().parents[1];base=root.parent;out=base/"qualified-inputs-af4618c8"
source=json.loads((out/"SEED.json").read_bytes())["source"]
def put(relative,data):
    path=out/relative;path.parent.mkdir(parents=True,exist_ok=True)
    assert 0<len(data)<=16*1024*1024
    with path.open("xb")as stream:stream.write(data)
    path.chmod(0o644)
    return {"path":relative,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
def ref(relative):
    path=out/relative;data=path.read_bytes();assert path.is_file()and not path.is_symlink()
    return {"path":relative,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
def get(suffix):
    result=subprocess.run(["gh","api","repos/billlza/q-periapt/actions/runs/44036376133"+suffix],capture_output=True,check=True,timeout=45)
    return json.loads(result.stdout)
run=get("");jobs=get("/jobs?per_page=100")
assert run["id"]==44036376133 and run["status"]=="completed"and run["conclusion"]=="success"
assert run["event"]=="pull_request"and run["head_sha"]=="8c77ea7153d5a1396f204bab2ad126a435f92644"and run["run_attempt"]==1
assert jobs["total_count"]==len(jobs["jobs"])==72
assert all(j["status"]=="completed"and j["conclusion"]=="success"for j in jobs["jobs"])
assert len({j["id"]for j in jobs["jobs"]})==72
assert {f"continuity-installed-{c}-{p}"for c in ["swift","kotlin","android"]for p in ["debug","release"]}|{"continuity-installed-coverage"}<={j["name"]for j in jobs["jobs"]}
normal=json.loads((out/"release/0.2.0/evidence/rust/additional-ci/RUST_SDK_PACKAGE.json").read_bytes())
assert normal["base_commit"]==source["commit"] and normal["sources_unchanged"]is True and normal["git_dirty"]is False
assert subprocess.check_output(["git","rev-parse",source["commit"]+"^{tree}"],cwd=root,text=True).strip()==source["tree"]
assert run["head_sha"]in subprocess.check_output(["git","show","-s","--format=%P",source["commit"]],cwd=root,text=True).split()
for role in ["independent","installed_coverage"]:
    decision=json.loads((out/("release/0.2.0/evidence/qualification/"+role+".json")).read_bytes())
    contract.parse_qualification(decision,role=role,source=source)
records=[put("release/0.2.0/evidence/ci/FINAL_HOSTED_RUN.json",canonical_json_bytes({"run":run,"jobs":jobs}))]
catalogs=[]
for name in ["ci-original-records","coordinated-freeze","rust-ci-equality","policy-maintenance","continuity-foreign"]:
    data=(out/"components"/(name+".json")).read_bytes();component=json.loads(data)
    assert component["completed"]is True and component["source"]==source
    for original in component["records"]:assert ref(original["path"])==original
    relative="release/0.2.0/evidence/catalogs/"+name+".json"
    if (out/relative).exists():
        assert (out/relative).read_bytes()==data;catalogs.append(ref(relative))
    else:catalogs.append(put(relative,data))
records.extend(catalogs)
cleanup_path="release/0.2.0/evidence/ci/DUPLICATE_CI_QUEUE_CLEANUP.json"
cleanup=json.loads((out/cleanup_path).read_bytes())
assert cleanup["completed"]is True and cleanup["source"]==source and cleanup["selected_full_ci_run"]==run["id"]
assert cleanup["duplicate_main_run"]["id"]==44048722826 and cleanup["duplicate_main_run"]["conclusion"]=="cancelled"
assert cleanup["identical_source_tree_verified"]is True
records.append(ref(cleanup_path))
for relative in ["release/0.2.0/evidence/rust/additional-ci/RUST_SDK_PACKAGE.json","release/0.2.0/evidence/rust/additional-ci/READBACK.json","release/0.2.0/evidence/ci/SMALL_RECORDS_READBACK.json","release/0.2.0/evidence/freeze/READBACK.json","release/0.2.0/evidence/MAIN_INTEGRATION.json"]:records.append(ref(relative))
records.append(put("release/0.2.0/evidence/ci/qualification-operator.py",Path(__file__).read_bytes()))
decision={"schema_version":1,"kind":"qperiapt.sdk_release_qualification","role":"ci","source":source,"completed":True,
    "scope":"Full selected CI run 44036376133 completed all 72 jobs successfully, including six foreign Debug/Release partitions and their required coverage join. GitHub records the PR head 8c77ea7153d5a1396f204bab2ad126a435f92644; actual selected producer/checkout records name its merge source af4618c8065d7133adfb86e1d116577089161ff0. These identities are not relabelled. The later main integration has the identical source tree and keeps its own commit. Native/source, packaging, installed consumers and original public records retain each lane's runtime/negative-control scope. Full CodeQL, Windows, independent and service runs are admitted by their separate selected qualifications.","records":records}
contract.parse_qualification(decision,role="ci",source=source)
put("release/0.2.0/evidence/qualification/ci.json",canonical_json_bytes(decision))
print(json.dumps({"qualification":"ci","completed":True,"successful_jobs":72,"qualified_source":source["commit"],"pr_head":run["head_sha"]}))
