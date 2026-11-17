"""Admit the completed four-job independent cohort from retained originals."""
from pathlib import Path
import hashlib,json
from publication_receipt_io import canonical_json_bytes
import sdk_github_publication_contract as contract

root=Path(__file__).resolve().parents[1];base=root.parent
out=base/"qualified-inputs-af4618c8"
source=json.loads((out/"SEED.json").read_bytes())["source"]
def put(relative,data):
    path=out/relative;path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():assert path.is_file()and not path.is_symlink()and path.read_bytes()==data
    else:
        with path.open("xb")as stream:stream.write(data)
        path.chmod(0o644)
    assert 0<len(data)<=16*1024*1024
    return {"path":relative,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
def ref(relative):return put(relative,(out/relative).read_bytes())

hosted=json.loads((base/"selected-run-44036838778-latest.json").read_bytes())
run=hosted["run"];jobs=hosted["jobs"]
assert run["id"]==44036838778 and run["status"]=="completed"and run["conclusion"]=="success"
assert run["head_sha"]==source["commit"] and jobs["total_count"]==len(jobs["jobs"])==4
assert all(row["status"]=="completed"and row["conclusion"]=="success"for row in jobs["jobs"])
assert {row["name"]for row in jobs["jobs"]}=={
    f"bootstrap ({host}, {arch}, {phase})"
    for host,arch in [("ubuntu-24.04","x86_64"),("macos-15","arm64")]
    for phase in ["source","installed"]}
records=[put("release/0.2.0/evidence/independent/HOSTED_RUN.json",canonical_json_bytes(hosted))]
for name in ["independent-ubuntu-24.04","independent-macos-15","independent-original-linux","independent-original-macos","independent-capture-notices"]:
    data=(out/"components"/(name+".json")).read_bytes();component=json.loads(data)
    assert component["completed"]is True and component["source"]==source
    for original in component["records"]:
        path=out/original["path"];assert path.stat().st_size==original["bytes"]and hashlib.sha256(path.read_bytes()).hexdigest()==original["sha256"]
    records.append(put("release/0.2.0/evidence/catalogs/"+name+".json",data))
    for selected in component.get("readbacks",[]):
        assert ref(selected["path"])==selected
        readback=json.loads((out/selected["path"]).read_bytes())
        assert readback["completed"]is True and readback["source"]==source
        assert readback["artifact"]["workflow_run"]["id"]==run["id"]
        records.append(selected)
for host in ["linux","macos"]:
    for phase in ["source","installed"]:
        relative=f"release/0.2.0/evidence/independent/original-index/INDEPENDENT_{host}_{phase}_INDEX.json"
        index=json.loads((out/relative).read_bytes())
        assert index["source"]==source and index["completed"]is True and index["exact_reconstruction_verified"]is True
        records.append(ref(relative))
records.append(put("release/0.2.0/evidence/independent/qualification-operator.py",Path(__file__).read_bytes()))
decision={"schema_version":1,"kind":"qperiapt.sdk_release_qualification","role":"independent","source":source,"completed":True,
    "scope":"All four selected run 44036838778 jobs completed successfully: Linux x86_64 and macOS arm64, each with source and isolated installed Python-wheel execution. Fresh original-archive readers validate exact source/native/wheel/module identities, registration and policy/composition records. Complete original captures are retained in bounded public ZIP slices with exact reconstruction checks and dependency notices. Counterpart and directory CLI remain source-built original executables; this is not an independent implementation of every SDK layer, physical-device qualification or a computational security proof.","records":records}
contract.parse_qualification(decision,role="independent",source=source)
put("release/0.2.0/evidence/qualification/independent.json",canonical_json_bytes(decision))
print(json.dumps({"qualification":"independent","completed":True,"successful_jobs":4,"original_phase_readbacks":4,"records":len(records)}))
