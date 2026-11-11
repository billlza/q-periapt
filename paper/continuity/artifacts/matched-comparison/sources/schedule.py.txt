#!/usr/bin/env python3
"""Exact directed opportunities and finite accounting controls for matched runs."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

SCENARIOS = ('alternating', 'lossy', 'reordered', 'duplicates', 'asymmetric',
             'offline_then_exchange', 'one_way')
MESSAGES = 2048
FRAME_CAP = 8192
CAPTURE_BEFORE = 1


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sender(scenario: str, opportunity: int) -> int:
    require(scenario in SCENARIOS, 'unknown scenario')
    require(type(opportunity) is int and opportunity >= 0, 'invalid opportunity')
    if scenario == 'one_way' or (scenario == 'offline_then_exchange' and opportunity < 256):
        return 0
    if scenario == 'asymmetric':
        return int(opportunity % 10 == 9)
    return opportunity % 2


def schedule(scenario: str, count: int = MESSAGES) -> list[dict]:
    require(type(count) is int and 0 < count <= 65536, 'invalid opportunity count')
    pending: list[int] = []
    rows = []
    for i in range(count):
        deliveries: list[int] = []
        duplicate = False
        dropped = scenario == 'lossy' and i % 10 == 4
        if not dropped:
            if scenario == 'reordered':
                pending.append(i)
                if i % 7 == 6:
                    deliveries = list(reversed(pending))
                    pending.clear()
            elif scenario == 'offline_then_exchange' and i < 256:
                pending.append(i)
            else:
                if scenario == 'offline_then_exchange' and i == 256:
                    deliveries.extend(pending)
                    pending.clear()
                deliveries.append(i)
                duplicate = scenario == 'duplicates' and i % 13 == 0
        rows.append({'opportunity': i, 'sender': sender(scenario, i),
                     'request': i, 'drop': dropped, 'deliveries': deliveries,
                     'duplicate_last': duplicate})
    rows.append({'terminal_delivery_only': pending})
    return rows


@dataclass(frozen=True)
class Emission:
    opportunity: int
    owner: int
    logical: str
    frame: bytes


def verify_trace(scenario: str, count: int, emissions: list[Emission],
                 deliveries: list[tuple[int, int, bytes]], capture_before: int = 1) -> dict:
    require(capture_before == CAPTURE_BEFORE, 'capture coordinate differs')
    slots = schedule(scenario, count)
    by_slot: dict[int, Emission] = {}
    by_logical: dict[tuple[int, str], bytes] = {}
    for item in emissions:
        require(type(item.opportunity) is int and 0 <= item.opportunity < count,
                'emission outside opportunity range')
        require(item.opportunity not in by_slot, 'multiple emissions in one opportunity')
        require(type(item.owner) is int and item.owner == sender(scenario, item.opportunity),
                'wrong emission direction')
        require(isinstance(item.logical, str) and bool(item.logical), 'missing logical identity')
        require(type(item.frame) is bytes and 0 < len(item.frame) <= FRAME_CAP, 'invalid frame')
        identity = (item.owner, item.logical)
        require(identity not in by_logical or by_logical[identity] == item.frame,
                'logical retry changes exact frame')
        by_logical[identity] = item.frame
        by_slot[item.opportunity] = item
    for delivery in deliveries:
        require(type(delivery) is tuple and len(delivery) == 3, 'invalid delivery')
        at, source, frame = delivery
        require(type(at) is int and 0 <= at <= count and type(source) is int
                and 0 <= source < count and type(frame) is bytes, 'invalid delivery fields')
    expected = []
    for row in slots[:-1]:
        for source in row['deliveries']:
            if source in by_slot:
                expected.append((row['opportunity'], source, by_slot[source].frame))
        if row['duplicate_last'] and row['opportunity'] in by_slot:
            source = row['opportunity']
            expected.append((source, source, by_slot[source].frame))
    for source in slots[-1]['terminal_delivery_only']:
        if source in by_slot:
            expected.append((count, source, by_slot[source].frame))
    require(deliveries == expected, 'delivery schedule or frame identity differs')
    return {'opportunities': count, 'emissions': len(emissions),
            'delivered_frames': len(deliveries), 'emitted_bytes': sum(len(x.frame) for x in emissions),
            'delivered_bytes': sum(len(x[2]) for x in deliveries),
            'capture_before_opportunity': capture_before}


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def manifest() -> dict:
    entries = {}
    for name in SCENARIOS:
        rows = schedule(name)
        entries[name] = {
            'opportunities': MESSAGES,
            'owners': [sum(row['sender'] == owner for row in rows[:-1]) for owner in [0, 1]],
            'network_drops': sum(row['drop'] for row in rows[:-1]),
            'network_duplicates': sum(row['duplicate_last'] for row in rows[:-1]),
            'terminal_deliveries': len(rows[-1]['terminal_delivery_only']),
            'sha256': hashlib.sha256(canonical(rows)).hexdigest(),
        }
    return {'schema': 1, 'kind': 'matched_directed_opportunities',
            'frame_cap_bytes': FRAME_CAP, 'capture_before_opportunity': CAPTURE_BEFORE,
            'payload_bytes': 32, 'scenarios': entries}


def charged_exchange(owners: list[int], uncharged_replies: bool = False) -> dict:
    """Four-flight accounting model; messages denote actual native flight roles."""
    queued = [[0], []]
    seen = set()
    emitted = []
    for i, owner in enumerate(owners):
        require(type(owner) is int and owner in (0, 1), 'owner')
        if not queued[owner]:
            continue
        flight = queued[owner].pop(0)
        emitted.append({'opportunity': i, 'owner': owner, 'flight': flight})
        while True:
            seen.add(flight)
            if flight == 3:
                break
            reply = flight + 1
            reply_owner = 1 - (flight % 2)
            if not uncharged_replies:
                queued[reply_owner].append(reply)
                break
            emitted.append({'opportunity': i, 'owner': reply_owner, 'flight': reply})
            flight = reply
    return {'complete': len(seen) == 4, 'emitted': emitted, 'queued': queued}


if __name__ == '__main__':
    print(json.dumps(manifest(), indent=2))
