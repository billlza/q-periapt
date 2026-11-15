#!/usr/bin/env python3
"""Indexed evaluation of the manuscript's finite record-derivation closure.

Construction and incremental evaluation do not enumerate containment paths.
For a fixed graph, every key, record and source is introduced at most once;
the closure traversal visits each derivation/guard/payload incidence at most
once. Graph preprocessing makes a constant number of additional passes. Under indexed
identities and constant-time dictionary/set operations, preprocessing and a
complete cumulative history take O(N + M + U) time and O(N + M) working space.
The per-event result contains only newly exposed sources. Full ``snapshot``
exports additionally cost their output size.

``forward`` preserves the retained checker's input/output convention. Explicit
``routes`` or ``normalized`` requests invoke its path-enumerating reference
model lazily; their costs are outside the indexed-evaluation bound. The old
checker and its archived evidence are kept unchanged.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys
from types import MappingProxyType


def _load_reference():
    """Load the fixed sibling without changing the isolated import search path."""
    source = Path(__file__).resolve().with_name('check_exposure.py')
    module_name = '_q_periapt_guarded_reference_model'
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        if Path(getattr(loaded, '__file__', '')).resolve() != source:
            raise ImportError('retained exposure module identity conflicts with its fixed source')
        return loaded
    spec = importlib.util.spec_from_file_location(module_name, source)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load retained exposure model')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_reference = _load_reference()
ReferenceModel, Record, Route = _reference.Model, _reference.Record, _reference.Route


@dataclass
class Work:
    """Structural visits, independent of machine speed or wall-clock timing."""

    input_events: int = 0
    key_visits: int = 0
    record_visits: int = 0
    derivation_visits: int = 0
    guard_visits: int = 0
    payload_visits: int = 0
    records_opened: int = 0
    sources_added: int = 0

    @property
    def indexed_visits(self) -> int:
        return (self.key_visits + self.record_visits + self.derivation_visits
                + self.guard_visits + self.payload_visits)


class IndexedModel:
    """Immutable graph indexes with the retained Model's forward interface."""

    def __init__(self, records: list[Record], derives: tuple[tuple[str, str], ...] = ()):
        record_map = {record.name: record for record in records}
        if len(record_map) != len(records):
            raise ValueError('duplicate record identity')
        derivations = tuple(derives)
        keys = {record.key for record in records}
        keys.update(key for pair in derivations for key in pair)
        origins = {origin for record in records for origin in record.origins}
        incoming = dict.fromkeys(record_map, 0)
        guarded: dict[str, list[str]] = {key: [] for key in keys}
        for record in records:
            if not record.key or not record.name:
                raise ValueError('empty record or key identity')
            guarded[record.key].append(record.name)
            for child in record.children:
                if child not in record_map:
                    raise ValueError('unknown child record')
                incoming[child] += 1
        # Kahn's algorithm validates the declared DAG without recursion or paths.
        roots = deque(name for name, degree in incoming.items() if degree == 0)
        visited = 0
        while roots:
            name = roots.popleft()
            visited += 1
            for child in record_map[name].children:
                incoming[child] -= 1
                if incoming[child] == 0:
                    roots.append(child)
        if visited != len(record_map):
            raise ValueError('cyclic record containment')
        derived: dict[str, list[str]] = {key: [] for key in keys}
        for parent, child in derivations:
            derived[parent].append(child)
        self.records = MappingProxyType(record_map)
        self.derives = derivations
        self.keys = frozenset(keys)
        self.origins = frozenset(origins)
        self._guarded = {key: tuple(names) for key, names in guarded.items()}
        self._derived = {key: tuple(names) for key, names in derived.items()}
        self._reference_model: ReferenceModel | None = None

    def new_state(self) -> IndexedClosure:
        return IndexedClosure(self)

    def forward(self, acquired: set[str], disclosed: set[str], direct: set[str] | None = None) -> tuple[set[str], set[str], set[str]]:
        """Return (exposed sources, available records, known keys) in linear work."""
        direct = set() if direct is None else direct
        if not acquired <= self.records.keys() or not disclosed <= self.keys:
            raise ValueError('unknown acquisition or key')
        if not direct <= self.origins:
            raise ValueError('unknown directly disclosed source')
        state = self.new_state()
        for name in acquired:
            state.acquire(name)
        for key in disclosed:
            state.disclose_key(key)
        for origin in direct:
            state.disclose_origin(origin)
        return state.snapshot()

    def _reference(self) -> ReferenceModel:
        if self._reference_model is None:
            self._reference_model = ReferenceModel(list(self.records.values()), self.derives)
        return self._reference_model

    @property
    def routes(self) -> tuple[Route, ...]:
        """Explicit small-graph oracle request; may enumerate exponentially many paths."""
        return self._reference().routes

    def normalized(self, acquired: set[str], disclosed: set[str], direct: set[str] | None = None) -> tuple[set[str], list[dict]]:
        """Retained path oracle, requested explicitly and outside the linear bound."""
        return self._reference().normalized(acquired, disclosed, direct)


class IndexedClosure:
    """Cumulative closure; each input operation returns only new source facts."""

    def __init__(self, model: IndexedModel):
        self.model = model
        self.work = Work()
        self._available: set[str] = set()
        self._keys: set[str] = set()
        self._exposed: set[str] = set()
        self._opened: set[str] = set()
        self._queue: deque[tuple[str, str]] = deque()

    def _record(self, name: str) -> None:
        if name not in self._available:
            self._available.add(name)
            self._queue.append(('record', name))

    def _key(self, key: str) -> None:
        if key not in self._keys:
            self._keys.add(key)
            self._queue.append(('key', key))

    def _origin(self, origin: str, delta: set[str]) -> None:
        if origin not in self._exposed:
            self._exposed.add(origin)
            delta.add(origin)
            self.work.sources_added += 1

    def _open(self, name: str, delta: set[str]) -> None:
        record = self.model.records[name]
        if name in self._opened or name not in self._available or record.key not in self._keys:
            return
        # Latch before introducing children: duplicate facts never rescan payloads.
        self._opened.add(name)
        self.work.records_opened += 1
        for child in record.children:
            self.work.payload_visits += 1
            self._record(child)
        for origin in record.origins:
            self.work.payload_visits += 1
            self._origin(origin, delta)

    def _drain(self, delta: set[str]) -> frozenset[str]:
        while self._queue:
            kind, item = self._queue.popleft()
            if kind == 'key':
                self.work.key_visits += 1
                for child in self.model._derived[item]:
                    self.work.derivation_visits += 1
                    self._key(child)
                for name in self.model._guarded[item]:
                    self.work.guard_visits += 1
                    self._open(name, delta)
            else:
                self.work.record_visits += 1
                self._open(item, delta)
        return frozenset(delta)

    def acquire(self, name: str) -> frozenset[str]:
        if name not in self.model.records:
            raise ValueError('unknown acquisition or key')
        self.work.input_events += 1
        self._record(name)
        return self._drain(set())

    def disclose_key(self, key: str) -> frozenset[str]:
        if key not in self.model.keys:
            raise ValueError('unknown acquisition or key')
        self.work.input_events += 1
        self._key(key)
        return self._drain(set())

    def disclose_origin(self, origin: str) -> frozenset[str]:
        if origin not in self.model.origins:
            raise ValueError('unknown directly disclosed source')
        self.work.input_events += 1
        delta: set[str] = set()
        self._origin(origin, delta)
        return self._drain(delta)

    def is_exposed(self, origin: str) -> bool:
        if origin not in self.model.origins:
            raise ValueError('unknown source')
        return origin in self._exposed

    def snapshot(self) -> tuple[set[str], set[str], set[str]]:
        """Export a fresh full state; its O(output size) cost is explicit."""
        return set(self._exposed), set(self._available), set(self._keys)


class IndexedHistory:
    """Local deletion controls later acquisition; previous facts stay known.

    ``step`` returns newly exposed sources, rather than copying the full closure
    at every prefix. Call ``state.snapshot()`` to export the complete state.
    """

    def __init__(self, model: IndexedModel):
        self.model = model
        self.state = model.new_state()
        self.live = set(model.records)
        self.event_count = 0

    def step(self, kind: str, item: str) -> frozenset[str]:
        if kind == 'acquire':
            if item not in self.live:
                raise ValueError('acquisition of unavailable local record')
            result = self.state.acquire(item)
        elif kind == 'disclose_key':
            result = self.state.disclose_key(item)
        elif kind == 'disclose_origin':
            result = self.state.disclose_origin(item)
        elif kind == 'delete_local':
            if item not in self.live:
                raise ValueError('record already unavailable')
            self.live.remove(item)
            result = frozenset()
        else:
            raise ValueError('unknown event kind')
        self.event_count += 1
        return result
