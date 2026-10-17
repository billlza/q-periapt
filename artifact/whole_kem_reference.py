"""Check the experimental whole-KEM transcript, confirmations and snapshot accounting."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import tomllib
from artifact import spqr_reference as ref

ROOT = ref.ROOT
CRATE = ROOT/"research/continuity-whole-kem-reference"
PROFILES = (1, 32, 64)
CONSTRUCTION = "experimental_whole_kem_v1"


def wire(data: bytes) -> dict:
    ref.require(6 <= len(data) <= 1250 and data[0] == 0xd1 and data[1] in PROFILES, "whole-KEM wire profile")
    at = 2
    def varint(maximum):
        nonlocal at
        result = 0
        for shift in range(0, 70, 7):
            ref.require(at < len(data), "whole-KEM truncated integer")
            byte = data[at]
            at += 1
            result |= (byte & 127) << shift
            if not byte & 128:
                ref.require((shift == 0 or byte != 0) and result <= maximum, "whole-KEM integer alias/overflow")
                return result
        raise ref.ReferenceError("whole-KEM unterminated integer")
    message_epoch, index, previous = varint((1<<64)-1), varint((1<<32)-1), varint((1<<32)-1)
    ref.require(index > 0 and at < len(data), "whole-KEM index/type")
    kind = data[at]
    at += 1
    ref.require(kind in (0,1,2,3), "whole-KEM control kind")
    epoch = varint((1<<64)-1) if kind else 0
    body = data[at:]
    ref.require(len(body) == {0:0,1:1216,2:1152,3:64}[kind] and (kind == 0 or epoch > 0), "whole-KEM body shape")
    ref.require(kind == 0 or message_epoch == (epoch if kind == 3 else epoch-1), "whole-KEM control/key epoch")
    return {"profile":data[1],"message_epoch":message_epoch,"index":index,"previous":previous,"kind":kind,"epoch":epoch,"body":body}


def metadata(row: dict, known: int, confirmed: int, sending: int, receiving: int, phase: int) -> dict:
    ref.require(isinstance(row,dict) and set(row) == {"known_epoch","confirmed_epoch","send_epoch","receive_epoch","phase","skipped_keys","bytes"}, "whole-KEM metadata fields")
    for field, expected in (("known_epoch",known),("confirmed_epoch",confirmed),("send_epoch",sending),("receive_epoch",receiving),("phase",phase)):
        ref.require(ref.integer(row[field],0,ref.MESSAGES,field) == expected, "whole-KEM transition differs: "+field)
    ref.integer(row["skipped_keys"],0,2000,"whole-KEM skipped keys")
    ref.integer(row["bytes"],1,2*1024*1024,"whole-KEM serialized size")
    return row


def trace(path: Path, name: str, profile: int) -> tuple[dict,str,dict,dict,dict]:
    data = ref.snapshot(path, 8*1024*1024)
    rows = [ref.decode_json(line) for line in data.splitlines()]
    config = {"event":"configuration","schema":1,"construction":CONSTRUCTION,"profile":profile,
              "scenario":name,"messages":ref.MESSAGES,"seed":ref.SEED,"public_test_entropy":True,"max_skipped":2000}
    ref.require(rows and ref.identical(rows[0],config), "whole-KEM configuration")
    ref.require([(r.get("event"),r.get("sequence")) for r in rows[1:-1]] == ref.schedule(name), "whole-KEM schedule")
    packets, statuses, indices, previous_counts, public_controls = {}, {}, {}, {}, {}
    offers, ciphertexts, received_offers, received_ciphertexts, cuts = {}, {}, set(), set(), {}
    known, confirmed, sending, receiving, phase = [0,0], [0,0], [0,0], [0,0], [0,0]
    states = [None,None]
    total = peak = peak_state = delivered = dropped = duplicates = 0
    for row in rows[1:-1]:
        sequence = ref.integer(row["sequence"],0,ref.MESSAGES-1,"whole-KEM sequence")
        event = row["event"]
        if event == "send":
            if sequence in ref.CUTS:
                cuts[sequence] = [(known[owner],phase[owner]) for owner in (0,1)]
            sender = (0 if name == "one_way" or (name == "offline_then_exchange" and sequence < 256)
                      else int(sequence%10 == 9) if name == "asymmetric" else sequence%2)
            ref.require(ref.integer(row["sender"],0,1,"sender") == sender and sequence not in packets, "whole-KEM sender")
            ref.require(isinstance(row["wire"],str) and re.fullmatch(r"(?:[0-9a-f]{2}){6,1250}",row["wire"]), "whole-KEM hex")
            encoded = bytes.fromhex(row["wire"])
            packet = wire(encoded)
            ref.require(packet["profile"] == profile and packet["message_epoch"] == sending[sender], "whole-KEM sending epoch")
            key = sender,packet["message_epoch"]
            ref.require(packet["index"] == indices.get(key,0)+1, "whole-KEM reused/skipped send key index")
            if key not in previous_counts:
                previous_counts[key] = indices.get((sender,packet["message_epoch"]-1),0)
            ref.require(packet["previous"] == previous_counts[key], "whole-KEM previous chain length")
            indices[key] = packet["index"]
            kind, epoch, body = packet["kind"],packet["epoch"],packet["body"]
            if kind:
                proposer = (epoch-1)%2
                ref.require(sender == (1-proposer if kind == 2 else proposer), "whole-KEM control role")
                control_id = sender,kind,epoch
                ref.require(control_id not in public_controls or public_controls[control_id] == body, "whole-KEM changed pending material")
                public_controls[control_id] = body
            if kind == 1:
                ref.require(epoch == known[sender]+1 and phase[sender] in (0,1), "whole-KEM offer state")
                offers[epoch] = hashlib.sha256(body[:1184]).digest()
                phase[sender] = 1
            elif kind == 2:
                ref.require((sender,epoch) in received_offers and epoch in offers and body[:32] == offers[epoch], "whole-KEM ciphertext without admitted offer")
                ref.require(phase[sender] in (2,3) and epoch in (known[sender],known[sender]+1), "whole-KEM encapsulation transition")
                ciphertexts.setdefault(epoch,(sequence,hashlib.sha256(b"QPWKR1:confirmation"+body[:32]+hashlib.sha256(body[32:1120]).digest()).digest()))
                known[sender] = epoch
                phase[sender] = 3
            elif kind == 3:
                ref.require((sender,epoch) in received_ciphertexts and epoch in ciphertexts and body[:32] == ciphertexts[epoch][1], "whole-KEM confirmation transcript")
                ref.require(phase[sender] == 4 and epoch == known[sender], "whole-KEM confirmation state")
            packets[sequence] = sender,packet
            who = sender
            total += len(encoded)
            peak = max(peak,len(encoded))
        elif event == "receive":
            ref.require(sequence in packets and sequence not in statuses, "whole-KEM receive accounting")
            sender,packet = packets[sequence]
            who = 1-sender
            ref.require(ref.integer(row["receiver"],0,1,"receiver") == who and row["key_matches"] is True, "whole-KEM key agreement")
            kind, epoch = packet["kind"],packet["epoch"]
            if kind == 1:
                received_offers.add((who,epoch))
                if epoch == known[who]+1:
                    ref.require(phase[who] in (0,2,4), "whole-KEM offer admission")
                    phase[who] = 2
            elif kind == 2:
                received_ciphertexts.add((who,epoch))
                if epoch > known[who]:
                    ref.require(epoch == known[who]+1 and phase[who] == 1, "whole-KEM decapsulation transition")
                    known[who] = confirmed[who] = sending[who] = epoch
                    phase[who] = 4
            elif kind == 3 and epoch == known[who] and phase[who] == 3:
                confirmed[who] = sending[who] = epoch
                phase[who] = 0
            ref.require(packet["message_epoch"] <= known[who], "whole-KEM receive epoch unavailable")
            receiving[who] = max(receiving[who],packet["message_epoch"])
            statuses[sequence] = "received"
            delivered += 1
        elif event == "drop":
            ref.require(sequence in packets and sequence not in statuses, "whole-KEM drop accounting")
            statuses[sequence] = "dropped"
            dropped += 1
            continue
        elif event == "duplicate":
            ref.require(statuses.get(sequence) == "received" and row["receiver"] == 1-packets[sequence][0]
                        and row["outcome"] == "KeyUnavailable", "whole-KEM duplicate result")
            duplicates += 1
            continue
        else:
            raise ref.ReferenceError("whole-KEM unknown event")
        states[who] = metadata(row["state"],known[who],confirmed[who],sending[who],receiving[who],phase[who])
        peak_state = max(peak_state,states[who]["bytes"])
    ref.require(len(packets) == len(statuses) == ref.MESSAGES and set(cuts) == set(ref.CUTS), "whole-KEM incomplete schedule")
    ref.require(known == [0,0] if name == "one_way" else min(known)>0, "whole-KEM directionality")
    summary = {"event":"summary","scenario":name,"sent":ref.MESSAGES,"delivered":delivered,"dropped":dropped,
               "duplicates_rejected":duplicates,"unique_message_keys":ref.MESSAGES,"wire_bytes":total,
               "peak_wire_bytes":peak,"peak_serialized_state_bytes":peak_state,"final_a":states[0],"final_b":states[1]}
    ref.require(ref.identical(rows[-1],summary), "whole-KEM summary")
    return summary,hashlib.sha256(data).hexdigest(),packets,cuts,ciphertexts


def snapshots(path:Path,name:str,profile:int,packets:dict,cuts:dict,ciphertexts:dict) -> dict:
    data = ref.snapshot(path,4*1024*1024)
    result = ref.decode_json(data)
    ref.require(isinstance(result,dict) and set(result) == {"schema","construction","profile","scenario","public_test_entropy","interpretation","cases"}, "whole-KEM snapshot fields")
    ref.require(type(result["schema"]) is int and result["schema"] == 1 and result["construction"] == CONSTRUCTION
                and ref.integer(result["profile"],1,64,"snapshot profile") == profile and result["scenario"] == name
                and result["public_test_entropy"] is True and result["interpretation"] == "passive retrospective derivation; not_derived is not a recovery claim", "whole-KEM snapshot scope")
    ref.require(isinstance(result["cases"],list) and len(result["cases"]) == 12, "whole-KEM snapshot coverage")
    summaries = []
    for case,(cut,owner) in zip(result["cases"],((cut,owner) for cut in ref.CUTS for owner in (0,1)),strict=True):
        known,phase = cuts[cut][owner]
        pending = known+1 if phase == 1 else None
        recovered = {"epoch":pending,"public_ciphertext_complete_at":ciphertexts[pending][0]} if pending in ciphertexts else None
        maximum = pending if recovered is not None else known
        predicted = [sequence for sequence,(_,p) in packets.items() if sequence>=cut and p["message_epoch"]<=maximum]
        unknown = [sequence for sequence,(_,p) in packets.items() if sequence>=cut and p["message_epoch"]>maximum]
        expected = {"cut_before_send":cut,"owner":owner,"snapshot_epoch":known,"snapshot_phase":phase,
                    "stolen_pending_dk_epoch":pending,"recovered_pending_epoch":recovered,"predicted_sequences":predicted,
                    "not_derived_sequences":unknown,"wrong_key_control_mismatch_at":predicted[0]}
        ref.require(ref.identical(case,expected), "whole-KEM snapshot derivation projection")
        ref.require(not unknown if name == "one_way" else bool(unknown), "whole-KEM snapshot directionality")
        summaries.append({"cut_before_send":cut,"owner":owner,"derived":len(predicted),"not_derived":len(unknown),
                          "derived_from_pending_epoch":sum(packets[sequence][1]["message_epoch"]>known for sequence in predicted)})
    return {"scenario":name,"sha256":hashlib.sha256(data).hexdigest(),"cases":summaries}


def verify(directory:Path) -> dict:
    profiles = []
    for profile in PROFILES:
        folder = directory/f"period-{profile}"
        report = ref.decode_json(ref.snapshot(folder/"report.json",4*1024*1024))
        ref.require(type(report["schema"]) is int and report["schema"] == 1 and report["construction"] == CONSTRUCTION
                    and ref.integer(report["profile"],1,64,"profile") == profile and report["production_claim_eligible"] is False, "whole-KEM report identity")
        ref.require(len(report["runs"]) == 7, "whole-KEM run count")
        traces, exposures = [], []
        for name,run in zip(ref.SCENARIOS,report["runs"],strict=True):
            summary,digest,packets,cuts,ciphertexts = trace(folder/f"{name}.jsonl",name,profile)
            ref.require(ref.identical(run["summary"],summary) and run["trace_sha256"] == digest, "whole-KEM report/trace mismatch")
            for field,count in (("send_ns",ref.MESSAGES),("receive_ns",summary["delivered"])):
                ref.require(isinstance(run[field],list) and len(run[field]) == count, "whole-KEM timing coverage")
                for value in run[field]: ref.integer(value,0,60_000_000_000,"whole-KEM CPU sample")
            traces.append({"scenario":name,"trace_sha256":digest,"summary":summary})
            exposures.append(snapshots(folder/f"{name}.compromise.json",name,profile,packets,cuts,ciphertexts))
        profiles.append({"profile":profile,"traces":traces,"snapshots":exposures})
    return {"schema":1,"construction":CONSTRUCTION,"profiles":profiles,"production_claim_eligible":False}


def dependencies() -> dict:
    upstream = ref.snapshot(ref.upstream_manifest().with_name("Cargo.lock"),1024*1024)
    ref.require(hashlib.sha256(upstream).hexdigest() == ref.UPSTREAM_LOCK, "whole-KEM dependency anchor")
    locked = ref.snapshot(CRATE/"Cargo.lock",1024*1024)
    def packages(data):
        return {(p["name"],p["version"],p.get("checksum")) for p in tomllib.loads(data.decode())["package"] if p.get("source","").startswith("registry+")}
    selected = packages(locked)
    ref.require(selected <= packages(upstream), "whole-KEM provider versions differ from comparison anchor")
    metadata = tomllib.loads(locked.decode())["package"]
    ref.require(all(not p.get("source") or p["source"].startswith("registry+") for p in metadata), "whole-KEM unexpected source")
    ref.require(any(p["name"] == "libcrux-ml-kem" and p["version"] == "0.0.8" for p in metadata), "whole-KEM provider pin")
    return {"registry_packages":len(selected),"lock_sha256":hashlib.sha256(locked).hexdigest(),"comparison_lock_sha256":ref.UPSTREAM_LOCK}


def comparison(result:dict, baseline:Path, chunk64:Path) -> list[dict]:
    original, wider = ref.verify(baseline),ref.verify(chunk64,chunk_bytes=64)
    locked = ref.decode_json(ref.snapshot(ROOT/"research/continuity-spqr-reference/TRACE_CORPUS.json",1024*1024))
    locked_snapshots = ref.decode_json(ref.snapshot(ROOT/"research/continuity-spqr-reference/COMPROMISE_CORPUS.json",1024*1024))
    wider_lock = ref.decode_json(ref.snapshot(ROOT/"research/continuity-spqr-reference/variants/CHUNK64_CORPUS.json",1024*1024))
    ref.require(ref.identical(original["verified_public_traces"],locked["traces"])
                and ref.identical(original["verified_snapshot_experiments"],locked_snapshots["traces"])
                and ref.identical(wider,wider_lock["result"]),"comparison corpus differs")
    rows=[]
    for index,name in enumerate(ref.SCENARIOS):
        entries=[]
        for label,data in (("braid32",original),("experimental_braid64",wider)):
            summary=data["verified_public_traces"][index]["summary"]
            exposure=next(c for c in data["verified_snapshot_experiments"][index]["cases"] if c["cut_before_send"]==1 and c["owner"]==0)
            entries.append({"profile":label,"bytes_per_send":summary["wire_bytes"]/ref.MESSAGES,
                            "peak_wire_bytes":summary["peak_wire_bytes"],"peak_serialized_state_bytes":summary["peak_serialized_state_bytes"],
                            "local_epochs":[summary["final_a"]["epoch"],summary["final_b"]["epoch"]],
                            "snapshot_a_cut_1_derived":exposure["predicted"]})
        for data in result["profiles"]:
            summary=data["traces"][index]["summary"]
            exposure=next(c for c in data["snapshots"][index]["cases"] if c["cut_before_send"]==1 and c["owner"]==0)
            entries.append({"profile":f"whole_kem_{data['profile']}","bytes_per_send":summary["wire_bytes"]/ref.MESSAGES,
                            "peak_wire_bytes":summary["peak_wire_bytes"],"peak_serialized_state_bytes":summary["peak_serialized_state_bytes"],
                            "local_epochs":[summary["final_a"]["known_epoch"],summary["final_b"]["known_epoch"]],
                            "snapshot_a_cut_1_derived":exposure["derived"]})
        rows.append({"scenario":name,"component_observations":entries})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory",type=Path)
    parser.add_argument("--compare",type=Path)
    parser.add_argument("--binary",type=Path)
    parser.add_argument("--baseline",type=Path)
    parser.add_argument("--chunk64",type=Path)
    parser.add_argument("--active-fork",action="store_true",help="verify the separate active session-disclosure counterexample")
    args = parser.parse_args()
    if args.active_fork:
        ref.require(not (args.binary or args.baseline or args.chunk64), "active-fork arguments")
        result = active_fork(args.directory)
        if args.compare:
            repeated = active_fork(args.compare)
            ref.require(ref.identical(result,repeated), "active-fork repeated bytes differ")
            result["repeat_public_bytes_equal"] = True
        print(json.dumps(result,sort_keys=True))
        return
    result = verify(args.directory)
    corpus = ref.decode_json(ref.snapshot(CRATE/"TRACE_CORPUS.json",1024*1024))
    ref.require(ref.identical(corpus,result), "whole-KEM locked corpus differs")
    if args.compare:
        ref.require(ref.identical(result,verify(args.compare)), "whole-KEM repeated corpus differs")
        result["repeat_public_bytes_equal"] = True
    result["dependencies"] = dependencies()
    ref.require(bool(args.baseline)==bool(args.chunk64),"both comparison inputs are required")
    if args.baseline:
        result["comparison"] = comparison(result,args.baseline,args.chunk64)
        result["comparison_scope"] = "matched public schedules; different constructions and retention policies; no security, energy or product-performance superiority claim"
    if args.binary:
        ref.require(not ref.command(["git","-C",str(ROOT),"status","--porcelain","--untracked-files=no"]), "whole-KEM source changed")
        result["source_receipt"] = {"source_commit":ref.command(["git","-C",str(ROOT),"rev-parse","HEAD"]),
            "source_tree":ref.command(["git","-C",str(ROOT),"rev-parse","HEAD^{tree}"]),
            "binary_sha256":hashlib.sha256(ref.snapshot(args.binary,128*1024*1024)).hexdigest(),
            "license_sha256":hashlib.sha256(ref.snapshot(CRATE/"LICENSE",128*1024)).hexdigest(),
            "rustc":ref.command(["rustc","-vV"]),"system":platform.system(),"machine":platform.machine()}
    print(json.dumps(result,sort_keys=True))


def active_event(row: dict, profile: int, sequence: int) -> tuple[dict, dict]:
    fields = {"sequence","sender","original_wire","replacement_wire",
              "original_message_epoch","replacement_message_epoch","sender_key_sha256",
              "attacker_received_key_sha256","attacker_sent_key_sha256","receiver_key_sha256",
              "honest_a_confirmed_epoch","honest_b_confirmed_epoch"}
    ref.require(isinstance(row,dict) and set(row) == fields, "active-fork event fields")
    ref.require(ref.integer(row["sequence"],0,511,"active-fork sequence") == sequence
                and ref.integer(row["sender"],0,1,"active-fork sender") == sequence%2,
                "active-fork exact schedule")
    parsed = []
    for name in ("original","replacement"):
        encoded = row[name+"_wire"]
        ref.require(isinstance(encoded,str) and re.fullmatch(r"(?:[0-9a-f]{2}){6,1250}",encoded), "active-fork packet hex")
        packet = wire(bytes.fromhex(encoded))
        ref.require(packet["profile"] == profile and packet["message_epoch"] ==
                    ref.integer(row[name+"_message_epoch"],0,512,"active-fork epoch"), "active-fork packet metadata")
        parsed.append(packet)
    for field in ("sender_key_sha256","attacker_received_key_sha256","attacker_sent_key_sha256","receiver_key_sha256"):
        ref.require(isinstance(row[field],str) and re.fullmatch(r"[0-9a-f]{64}",row[field]), "active-fork key commitment")
    ref.require(row["sender_key_sha256"] == row["attacker_received_key_sha256"]
                and row["attacker_sent_key_sha256"] == row["receiver_key_sha256"], "active-fork actual key agreement")
    return parsed[0], parsed[1]


def active_fork(path: Path) -> dict:
    raw = ref.snapshot(path,16*1024*1024)
    report = ref.decode_json(raw)
    expected = {"schema":1,"construction":CONSTRUCTION,
                "experiment":"continuous_active_fork_after_initial_b_session_disclosure",
                "public_test_entropy":True,"production_claim_eligible":False,
                "attacker_inputs":"one initial B session snapshot, public packets, own entropy",
                "interpretation":"confirmed fresh epochs do not establish recovery while session-authenticator impersonation continues; component key exposure, not full application execution"}
    ref.require(isinstance(report,dict) and set(report) == set(expected)|{"cases"}, "active-fork report fields")
    ref.require(all(ref.identical(report[k],v) for k,v in expected.items()), "active-fork experiment scope")
    cases = report["cases"]
    ref.require(isinstance(cases,list) and len(cases) == 3, "active-fork profiles")
    summaries = []
    for case,profile in zip(cases,PROFILES,strict=True):
        ref.require(isinstance(case,dict) and set(case) == {"profile","events","intercepted_keys","divergent_message_keys","replaced_packets","confirmed_a","confirmed_b","wrong_authenticator_rejected"}, "active-fork case fields")
        ref.require(ref.identical(case["profile"],profile) and case["wrong_authenticator_rejected"] is True, "active-fork profile/control")
        rows = case["events"]
        ref.require(isinstance(rows,list) and len(rows) == 512, "active-fork complete event count")
        confirmed = [0,0]
        indices, controls, offers, ciphertexts = {}, {}, {}, {}
        original_keys, replacement_keys = set(),set()
        different_keys = different_packets = 0
        for sequence,row in enumerate(rows):
            packets = active_event(row,profile,sequence)
            sender = sequence%2
            for stream,packet in enumerate(packets):
                leg = sender if stream == 0 else 1-sender
                slot = leg,sender,packet["message_epoch"]
                ref.require(packet["index"] == indices.get(slot,0)+1, "active-fork per-leg key sequence")
                indices[slot] = packet["index"]
                kind,epoch,body = packet["kind"],packet["epoch"],packet["body"]
                if kind:
                    ref.require(sender == ((epoch-1)%2 if kind in (1,3) else epoch%2), "active-fork control role")
                    control = leg,kind,epoch
                    ref.require(control not in controls or controls[control] == body, "active-fork control replacement within one leg")
                    controls[control] = body
                    if kind == 1:
                        offers[leg,epoch] = hashlib.sha256(body[:1184]).digest()
                    elif kind == 2:
                        ref.require(body[:32] == offers.get((leg,epoch)), "active-fork ciphertext key binding")
                        ciphertexts[leg,epoch] = body[32:1120]
                    else:
                        ref.require((leg,epoch) in ciphertexts, "active-fork confirmation without ciphertext")
                        expected_id = hashlib.sha256(b"QPWKR1:confirmation"+offers[leg,epoch]+hashlib.sha256(ciphertexts[leg,epoch]).digest()).digest()
                        ref.require(body[:32] == expected_id, "active-fork exact confirmation")
            if packets[1]["kind"] in (2,3):
                confirmed[1-sender] = max(confirmed[1-sender],packets[1]["epoch"])
            ref.require([ref.integer(row[f"honest_{role}_confirmed_epoch"],0,512,"active-fork confirmed epoch") for role in ("a","b")] == confirmed, "active-fork confirmation transition")
            ref.require(row["sender_key_sha256"] not in original_keys and row["receiver_key_sha256"] not in replacement_keys, "active-fork reused directional message key")
            original_keys.add(row["sender_key_sha256"])
            replacement_keys.add(row["receiver_key_sha256"])
            different_keys += row["sender_key_sha256"] != row["receiver_key_sha256"]
            different_packets += row["original_wire"] != row["replacement_wire"]
        summary = {"profile":profile,"intercepted_keys":512,"divergent_message_keys":different_keys,
                   "replaced_packets":different_packets,"confirmed_a":confirmed[0],"confirmed_b":confirmed[1]}
        ref.require(different_keys > 0 and different_packets > 0 and min(confirmed) >= 3, "active-fork fresh separated epochs")
        ref.require(all(ref.identical(case[k],v) for k,v in summary.items()), "active-fork summary accounting")
        summaries.append(summary)
    return {"schema":1,"experiment":expected["experiment"],"report_sha256":hashlib.sha256(raw).hexdigest(),
            "intercepted_keys":1536,"wrong_authenticator_controls":3,"cases":summaries,"production_claim_eligible":False}


if __name__ == "__main__":
    main()
