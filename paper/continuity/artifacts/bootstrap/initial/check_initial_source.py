#!/usr/bin/env python3
"""Exact source and finite-model controls for the initial-source adapter.

The models exercise the analytical proof's original-slot, cache and stopping
accounting. They do not execute ML-KEM or assert a finite experiment proves
an asymptotic cryptographic theorem.
"""

from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path


PACKET = Path(__file__).resolve().parent


def require(value, message):
    if not value:
        raise AssertionError(message)


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def git_blob(value):
    return hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()


def section(text, start, end):
    first = text.index(start)
    return text[first:text.index(end, first)]


def source_pins(root):
    raw = (PACKET / "SOURCE_PINS.json").read_bytes()
    pins = json.loads(raw)
    for row in pins["files"]:
        data = (root / row["path"]).read_bytes()
        require(len(data) == row["bytes"], "length: " + row["path"])
        require(git_blob(data) == row["git_blob"], "Git blob: " + row["path"])
        require(sha256(data) == row["sha256"], "SHA-256: " + row["path"])
    return {
        "checked_files": len(pins["files"]),
        "base_commit": pins["base_commit"],
        "base_tree": pins["base_tree"],
        "source_pins_sha256": sha256(raw),
    }


def source_correspondence(root):
    src = root / "research/continuity-identity-candidate/src"
    inv = (src / "durable/prekeys.rs").read_text()
    ini = (src / "durable/initiator.rs").read_text()
    plan = (src / "bootstrap/staged.rs").read_text()
    boot = (src / "bootstrap.rs").read_text()
    response = (src / "bootstrap/response_staged.rs").read_text()
    manifest = (src / "manifest.rs").read_text()
    sdk = (root / "crates/q-periapt-sdk/src/lib.rs").read_text()
    replay = (root / "crates/q-periapt-sdk/src/expert/replay.rs").read_text()
    backend = (root / "crates/q-periapt-backends/src/contextbound_key.rs").read_text()
    checks = []

    def check(value, label):
        require(value, label)
        checks.append(label)

    generation = section(inv, "pub async fn generate_prekey(", "pub async fn prekey_leaf(")
    check(generation.index("self.persist(&mut image).await?;") < generation.index("recovery.generate_key("), "inventory reservation is durable before generation")
    check(generation.index("entry.public = public_component(&key, kind)?;") < generation.rindex("self.persist(&mut image).await?;"), "generated public component is committed before publication")
    check("other.leaf()?.key_fingerprint() == leaf.key_fingerprint()" in generation, "inventory rejects duplicate published component fingerprints")
    scope = section(inv, "fn scope(&self, image: &Image)", "fn leaf(&self)")
    check(all(s in scope for s in ["image.id", "image.owner", "id(self.request)", "self.intent()"]), "inventory generation scope keeps image owner request and intent")
    restore = section(inv, "fn restore_inventory_key(", "/// Resolve the actual authenticated selection")
    check(".generate_key(" in restore and "import_expanded" not in restore, "selected inventory owner restores from original sealed seed")
    check("public_component(&key, entry.kind)? != entry.public" in restore, "inventory restore checks published component")
    recover = section(inv, "pub async fn respond_from_inventory(", "\nfn find(")
    check("let [pq_ref, classical_ref] = refs;" in recover, "actual PQ and traditional references remain separate")
    check("PqKeySource::from_key(&pq)" in recover and "TraditionalKeySource::from_key(&classical)" in recover, "response receives components from their respective owners")
    check(recover.index("self.persist(&mut image).await?;") < recover.index("self.restore_inventory_key("), "response commits both inventory references before restoration")
    consume = section(inv, "pub(super) fn consume(", "pub(super) fn validate_image(")
    check(consume.index("if one_time(entry.kind)") < consume.index("entry.data.zeroize()") < consume.index("entry.data.extend_from_slice(operation)"), "only selected one-time tokens become operation tombstones")
    fp = section(manifest, "pub fn key_fingerprint(&self)", "fn encode(&self)")
    check("self.kind.algorithm()" in fp and "self.public" in fp, "prekey fingerprint binds algorithm and exact public bytes")
    init = section(ini, "pub async fn initiate(", "let operation = match plan.complete(")
    check(init.index("self.persist(&mut image).await?;") < init.index("plan.advance("), "initial plan is durable before private advancement")
    check("self.persist(&mut image).await?;" in init[init.index("plan.advance("):], "each advanced initial phase persists before further advancement")
    advance = section(plan, "pub(crate) fn advance(", "pub(crate) fn complete(")
    check(advance.index("if self.kem.is_none()") < advance.index("recovery.reserve_encapsulation(") < advance.index("self.compute("), "separate initial reservation and encapsulation stages")
    compute = section(plan, "fn compute(", "pub(crate) fn advance(")
    check(all(s in compute for s in ["initial_prefix(context, key, &self.nonce)", "durable-initial-kem", "&context.peer", "kem-initial", "self.kem.as_ref()"]), "Initial encapsulation retains original prefix peer context and tape")
    check("if expected != *body" in plan, "restored initial plan checks exact recomputed body")
    auth = section(boot, "fn authenticate_initial(", "struct Schedule")
    check(auth.index(".verify(Purpose::BootstrapInitiator") < auth.index("expert::decapsulate_components("), "initial body signature verifies before private decapsulation")
    check(auth.index("context.peer.to_bytes()") < auth.index("expert::decapsulate_components("), "initial decapsulation checks actual selected composite peer")
    initial = section(boot, "fn initial_body(", "fn nonce()")
    check(initial.index("initial_key(&result.secret") < initial.index("mac(key.as_bytes()") < initial.index("export_for_protocol()"), "SDK short confirmation is computed with first contribution")
    complete = section(plan, "pub(crate) fn complete(", "pub(crate) fn encode(")
    check(complete.index("let (expected, first) = self.compute(") < complete.index("let signature = reservation.sign("), "Initial short confirmation precedes purpose-5 signing")
    sched = section(boot, "fn schedule(", "fn final_prefix(")
    check(sched.index("left.copy_from_slice(first.as_bytes())") < sched.index("right.copy_from_slice(second.as_bytes())"), "long IKM order is S0 then S1")
    check(sched.count("derive(ikm.as_bytes(), core,") == 3, "three bootstrap labels use the same long Extract")
    check("hash(b\"initial-wire\", initial)" in section(boot, "fn response_prefix(", "fn response_body("), "complete Initial wire affects Reply family")
    final = section(boot, "fn final_prefix(", "fn pending(")
    check("initial-wire" in final and "reply-wire" in final, "both complete wires affect session descriptor")
    checks_prekeys = section(response, "pub(crate) fn check_prekeys(", "pub(crate) fn reserve(")
    check("expert::component_public_key" in checks_prekeys and "context.peer.to_bytes()" in checks_prekeys, "response verifies composite selected public key")
    check("Self::Generate => 64 + 32" in replay and "Self::Encapsulate => 32 + 32" in replay, "original replay tape widths")
    check("const BINDING_LEN: usize = 8 + 1 + 68 + 32 + 32" in replay and "const HEADER_LEN: usize = BINDING_LEN + 24" in replay, "sealed-operation binding and nonce widths")
    gen = section(sdk, "fn generate_with(", "/// Encapsulate with platform")
    check(gen.index("rng(seed.as_mut_bytes())?") < gen.index("rng(traditional.as_mut_bytes())?"), "generation consumes PQ then traditional tape")
    prepare = section(backend, "pub fn prepare(", "/// Import an expanded key")
    check("embedded_public_key(decapsulation_key.as_bytes()) != &encapsulation_key" in prepare, "seed regeneration retains embedded-public consistency check")
    return {"count": len(checks), "checks": checks}


def original_slot_history():
    """An independent trace model separates draw, retention and execution."""
    traces = []
    for failed_reservations, failed_final_writes, retries, one_time in itertools.product(range(3), range(3), range(3), [False, True]):
        draws = list(range(1, failed_reservations + 2))
        retained = draws[-1]
        executed = [retained] * (1 + failed_final_writes + retries)
        acquired = {("available", retained)}
        live = ("tombstone", "operation") if one_time else ("available", retained)
        require(set(executed) == {retained}, "retry changed an executed origin")
        require(len(draws) == failed_reservations + 1, "failed draws were omitted")
        require(("available", retained) in acquired, "consumption erased an earlier acquired version")
        traces.append((len(draws), tuple(executed), live))
    # Composite key owners are deliberately distinct. A traditional-only opening
    # supplies no selected PQ seed; opening the selected PQ token does.
    selected = {"pq": "generation-7", "traditional": "generation-11"}
    for opened, expected in [(set(), False), ({"generation-11"}, False), ({"generation-7"}, True), ({"generation-7", "generation-11"}, True)]:
        require((selected["pq"] in opened) == expected, "wrong component owner attributed")
    return {"traces": len(traces), "component_owner_cases": 4, "failed_draws_and_live_consumption_preserved": True}


def exact_entry_aliases():
    secret = bytes(range(32))
    pad = b"\x80" + bytes(23) + (768).to_bytes(8, "big")
    full_pad = b"\x80" + bytes(55) + (1024).to_bytes(8, "big")
    inner = bytes([0xA5]) * 32
    short_raw = secret + pad + inner
    long_raw = secret + pad + inner
    require(short_raw == long_raw and len(short_raw) == 96, "short/long shared raw point")
    require((secret + pad)[-8:] != full_pad[-8:], "short-outer and full-pad ranges must remain disjoint")
    # Two salt strings have deliberately equal pad states; a third shares
    # only the inner state. The complete descriptor is the actual relation.
    requests = [("salt-a", "v0", 0, 0), ("salt-alias", "v0", 0, 0), ("salt-b", "v0", 0, 1), ("salt-a", "v1", 0, 0), ("salt-a", "v0", 0, 0)]
    cache, ranks = {}, []
    for _, known, alpha, beta in requests:
        descriptor = (known, alpha, beta)
        if descriptor not in cache:
            cache[descriptor] = len(cache) + 1
        ranks.append(cache[descriptor])
    require(ranks == [1, 1, 2, 3, 1], "complete descriptor cache")
    salt_only = len({(salt, known) for salt, known, _, _ in requests})
    inner_only = len({alpha for _, _, alpha, _ in requests})
    require(salt_only != len(cache) and inner_only != len(cache), "negative cache controls did not separate")
    # A failed first use still allocates its family. A later accepted Reply
    # gets rank 2, and neither deletion nor retry can transfer that rank.
    retained = {("v-rejected", 1, 1): 1, ("v-accepted", 2, 2): 2}
    require(retained[("v-accepted", 2, 2)] == 2, "failed attempt rank omitted")
    active_only = dict(retained)
    del active_only[("v-rejected", 1, 1)]
    wrong_next = len(active_only) + 1
    correct_next = len(retained) + 1
    require(wrong_next in active_only.values() and correct_next == 3, "rank recycling must expose a duplicate allocation identity")
    return {
        "shared_raw_input_sha256": sha256(short_raw),
        "shared_raw_bytes": len(short_raw),
        "descriptor_ranks": ranks,
        "complete_descriptors": len(cache),
        "wrong_salt_cache_classes": salt_only,
        "wrong_inner_cache_classes": inner_only,
        "accepted_rank_after_failed_use": 2,
        "new_rank_after_live_deletion": correct_next,
        "wrong_recycled_rank_collides": wrong_next,
    }


def deferred_table_parent():
    """Compare eager/lazy independent table cells under adaptive allocation."""
    eager, deferred = Counter(), Counter()
    coincidences = 0
    for initial_tag, p0, p1, p2, choice, stop in itertools.product(range(2), range(4), range(4), range(4), range(2), range(2)):
        values = [p0, p1, p2]
        # The second descriptor is chosen from the first public derived tag.
        order = [(initial_tag, 0), ((p0 % 2) ^ choice, 1), (p1 % 2, 2)]
        seen = []
        for rank, descriptor in enumerate(order):
            seen.append((descriptor, values[rank]))
            if stop and rank == 1:
                break
        eager[(initial_tag, tuple(seen))] += 1
        delayed = []
        # Pick allocation slot 2 before any execution and defer its unused
        # presampled challenge p1 until that slot's descriptor is requested.
        challenge = p1
        for rank, descriptor in enumerate(order):
            value = challenge if rank == 1 else values[rank]
            delayed.append((descriptor, value))
            if stop and rank == 1:
                break
        deferred[(initial_tag, tuple(delayed))] += 1
        coincidences += int(p0 == p1 or p1 == p2 or p0 == p2)
    require(eager == deferred, "fixed allocation-slot deferral changed the joint view")
    # Countermodel: selecting a parent after seeing both derived bits biases it.
    selected_one = sum(int(x == 1 or y == 1) for x, y in itertools.product(range(2), repeat=2))
    adaptive = Fraction(selected_one, 4)
    fresh_after_selection = Fraction(1, 2)
    require(adaptive == Fraction(3, 4) and adaptive != fresh_after_selection, "posthoc challenge control")
    return {
        "executions_each": sum(eager.values()),
        "distinct_joint_views": len(eager),
        "numerical_coincidence_executions_retained": coincidences,
        "posthoc_selected_one_probability": str(adaptive),
        "fresh_after_selection_one_probability": str(fresh_after_selection),
        "posthoc_gap": str(adaptive - fresh_after_selection),
    }


def controller(bits, replace_count):
    """Two-source/two-descriptor finite controller with failed and opened uses.

    Inputs are exhausted public model coins. Parent and replacement bits are
    toy values, not native keys. All registration and capture choices occur
    from the available prefix, including previously returned ACK bits.
    """
    initial, p00, p01, p10, p11, fresh0, fresh1, fail_first, open_source, open_family, post_open, capture_before, capture_after, fallback = bits
    parents = {(0, 0): p00, (0, 1): p01, (1, 0): p10, (1, 1): p11}
    fresh = [fresh0, fresh1]
    ranks = {0: {}, 1: {}}
    captured, source_opened, family_opened = set(), set(), set()
    registrations, acknowledgements, events = [], [], []
    stopped, latched = False, False

    def allocate(family):
        src, desc = family
        if desc not in ranks[src]:
            ranks[src][desc] = len(ranks[src]) + 1
        return ranks[src][desc]

    def eligible(family):
        return family[0] not in source_opened and family not in family_opened

    def register(family):
        nonlocal latched
        rank = allocate(family)
        if not eligible(family) or any(old[0] == family for old in registrations):
            return
        number = len(registrations)
        if number >= 2:
            return
        value = fresh[number] if number < replace_count else parents[family]
        registrations.append((family, rank))
        acknowledgements.append(value)
        events.append(("register", family, rank, value))
        latched = latched or bool(value and family[1])

    rejected = (initial, 0)
    allocate(rejected)
    if fail_first:
        events.append(("failed-reply", rejected))
    if open_source:
        source_opened.add(initial)
        events.append(("source-open", initial))
    if open_family:
        family_opened.add((1 - initial, 0))
        events.append(("family-open", (1 - initial, 0)))
    if capture_before:
        captured.add(initial)
    # Deleting a live record never removes acquisition or opening facts.
    before_deletion = (set(captured), set(source_opened), set(family_opened))
    live = {"record": rejected}
    live.clear()
    require(before_deletion == (captured, source_opened, family_opened), "live deletion erased cumulative facts")
    first = (initial, 1 if fail_first else 0)
    register(first)
    if not registrations and fallback:
        register((1 - initial, 1))
    if registrations:
        first_family = registrations[0][0]
        if capture_after and acknowledgements[0]:
            captured.add(first_family[0])
        if post_open and acknowledgements[0]:
            # U1 stops before returning the protected recipe, while keeping
            # the already latched event and prefix.
            stopped = True
            events.append(("global-stop", first_family))
        if not stopped:
            second = ((first_family[0] ^ acknowledgements[0]), 1 - first_family[1])
            register(second)
    # A public toy confirmation bit can correlate the terminal test with the
    # real parent. This makes the accounting run exercise nonzero adjacent
    # gaps; no secrecy conclusion is asserted for this two-bit toy primitive.
    public_confirmation = p00
    terminal = int(latched or (bool(acknowledgements) and acknowledgements[0] == public_confirmation and bool(fallback)))
    return {
        "registrations": tuple(registrations), "acks": tuple(acknowledgements),
        "captured": frozenset(captured), "source_opened": frozenset(source_opened),
        "family_opened": frozenset(family_opened), "stopped": stopped,
        "latched": latched, "D": terminal, "events": tuple(events),
        "ranks": tuple((src, tuple(sorted(table.items()))) for src, table in ranks.items()),
    }


def two_level_localization():
    runs = 0
    totals = Counter()
    late_stop_witness = None
    capture_witness = None
    for bits in itertools.product(range(2), repeat=14):
        outcomes = [controller(bits, k) for k in range(3)]
        runs += len(outcomes)
        for r in [1, 2]:
            left, right = outcomes[r - 1], outcomes[r]
            bottom_scores = []
            for side, result in enumerate([left, right]):
                reg = result["registrations"][r - 1] if len(result["registrations"]) >= r else None
                bottom_scores.append(result["D"] if reg is None else 0)
                pair_sum, rank_sum, capture_sum = 0, 0, 0
                for source in [0, 1]:
                    pair_score = result["D"] * int(reg is not None and reg[0][0] == source)
                    pair_sum += pair_score
                    source_rank_sum = 0
                    for ell in [1, 2]:
                        candidate = result["D"] * int(reg is not None and reg[0][0] == source and reg[1] == ell)
                        source_rank_sum += candidate
                        if source in result["source_opened"]:
                            require(candidate == 0, "a prior-opened source was promoted")
                        if reg is not None and reg[0] in result["family_opened"]:
                            require(candidate == 0, "a prior-opened family was promoted")
                    require(source_rank_sum == pair_score, "second allocation-rank partition")
                    rank_sum += source_rank_sum
                    capture_sum += pair_score * int(source in result["captured"])
                require(pair_sum + bottom_scores[-1] == result["D"], "first source-pair partition")
                require(pair_sum == rank_sum, "two-level pointwise identity")
                exact_capture = result["D"] * int(reg is not None and reg[0][0] in result["captured"])
                require(capture_sum == exact_capture, "disjoint source capture accounting")
                totals[(r, side, "D")] += result["D"]
                totals[(r, side, "capture_score")] += exact_capture
                totals[(r, side, "capture_probability")] += int(reg is not None and reg[0][0] in result["captured"])
                if result["stopped"] and result["latched"] and late_stop_witness is None:
                    late_stop_witness = {"bits": bits, "rank": r, "side": side, "latched": result["latched"], "D": result["D"]}
            require(bottom_scores[0] == bottom_scores[1], "absent r-th registrations must cancel")
            def cap(result):
                return len(result["registrations"]) >= r and result["registrations"][r - 1][0][0] in result["captured"]
            if not cap(left) and cap(right) and right["D"] and capture_witness is None:
                capture_witness = {"bits": bits, "rank": r, "left_capture": False, "right_capture": True, "right_score": 1}
    require(late_stop_witness is not None, "missing global-stop negative control")
    require(capture_witness is not None, "missing endpoint-dependent capture control")
    denominator = 2**14
    summaries = []
    for r in [1, 2]:
        gap = Fraction(totals[(r, 0, "D")] - totals[(r, 1, "D")], denominator)
        eta = Fraction(sum(totals[(r, b, "capture_probability")] for b in [0, 1]), denominator)
        changed = Fraction(abs(totals[(r, 0, "capture_score")] - totals[(r, 1, "capture_score")]), denominator)
        require(changed <= eta, "two-endpoint residual bound")
        summaries.append({"registration_rank": r, "endpoint_score_gap": str(gap), "two_endpoint_capture_residual": str(eta), "capture_zeroing_gap_change": str(changed)})
    # The second partition occurs after each pair's upstream comparison.
    # Its rank count consequently multiplies only terminal comparisons.
    R, G, A, L, upstream, tail = 2, 3, 5, 7, Fraction(1, 1000), Fraction(1, 10000)
    staged = sum(upstream + sum(tail for _ in range(L)) for _ in range(R * G * A * 2))
    formula = 2 * R * G * A * (upstream + L * tail)
    naive = 2 * R * G * A * L * (upstream + tail)
    require(staged == formula and staged < naive, "two-level cost factor")
    return {
        "coin_tapes": denominator, "endpoint_executions": runs,
        "source_count": 2, "descriptor_budget_per_source": 2, "registration_budget": 2,
        "adjacent_summaries": summaries,
        "global_stop_must_keep_prefix_witness": late_stop_witness,
        "one_endpoint_capture_bound_fails_witness": capture_witness,
        "two_level_cost": str(staged), "naive_all_costs_times_rank": str(naive),
    }


def original_fresh_slot_bound():
    # A selected challenge m* and two previously reserved fresh messages.
    # Execute a match if either reservation matches; counting one executed
    # ciphertext undercounts the adaptive selection risk.
    domain = range(4)
    hits = total = 0
    for challenge, m0, m1 in itertools.product(domain, repeat=3):
        total += 1
        hits += int(m0 == challenge or m1 == challenge)
    actual = Fraction(hits, total)
    correct = Fraction(2, 4)
    wrong = Fraction(1, 4)
    require(actual == Fraction(7, 16) and actual <= correct and actual > wrong, "original fresh-slot collision budget")
    return {"executions": total, "actual_match_probability": str(actual), "two_original_slots_bound": str(correct), "one_executed_ciphertext_bound_fails": str(wrong)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {
        "schema": "q-periapt/bootstrap-initial-source-check/v1",
        "source_pins": source_pins(args.source_root),
        "source_correspondence": source_correspondence(args.source_root),
        "original_slot_history": original_slot_history(),
        "exact_entry_aliases": exact_entry_aliases(),
        "deferred_table_parent": deferred_table_parent(),
        "two_level_localization": two_level_localization(),
        "original_fresh_slot_bound": original_fresh_slot_bound(),
        "scope": "exact source identities, byte encodings, finite online accounting and explicit negative controls; no native KEM/provider execution",
    }
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
