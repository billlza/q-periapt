"""Local renewal counterexamples using genuine grants and preserved private state."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import shutil
from peer.local_renewal import LocalRenewal
from peer.local_renewal_protocol import Proposal
from peer.renewal import verify
from peer.state_codec import encode, decode
from peer.wire import require
from peer.witness import Client, TcpTransport
from peer.witness_session import WitnessSession


class Controls:
    def __init__(self, path, scope, key, context, signer, pin, address):
        self.path, self.scope, self.key, self.context = path, scope, key, context
        self.signer, self.pin, self.address = signer, pin, address
        self.results = []

    def refuses(self, name, call, reason=None):
        from cryptography.exceptions import InvalidSignature, InvalidTag
        try:
            call()
        except (ValueError, OSError, InvalidSignature, InvalidTag) as error:
            require(reason is None or reason in str(error), 'wrong local renewal refusal: ' + name + ': ' + str(error))
            self.results.append({'case': name, 'type': type(error).__name__, 'error': str(error)})
        else:
            raise ValueError('missing local renewal refusal: ' + name)

    def client(self, transport=None):
        return Client(self.pin, self.context.witness.subject(self.scope.identity), self.signer,
                      transport or TcpTransport(self.address))

    def open(self, operation, transport=None):
        return LocalRenewal.open(self.path, self.scope, self.key, self.context, operation,
                                 client=self.client(transport))

    def grants(self, materials):
        operation, wire, target = materials; ctx = self.context
        from peer.local_credential import LocalCredentialRenewal
        self.refuses('required-policy-cannot-use-local-coordinator',
                     lambda: LocalCredentialRenewal.open(self.path, self.scope, self.key, ctx, operation),
                     'original local-only policy')
        def check(data=wire, checkpoint=target, policy=ctx.policy_digest, device=ctx.devices[0], now=210):
            return verify(data, device, ctx.family, policy, checkpoint, now=now)
        for size in (0, 7, 8, 9, len(wire) - 1):
            self.refuses('local-grant-truncated-' + str(size), lambda size=size: check(wire[:size]))
        for offset in (0, 8, 9, 14, 54, 150, len(wire) - 1):
            data = wire[:offset] + bytes([wire[offset] ^ 1]) + wire[offset + 1:]
            self.refuses('local-grant-mutated-' + str(offset), lambda data=data: check(data))
        self.refuses('local-grant-trailing', lambda: check(wire + b'\0'))
        self.refuses('local-grant-wrong-target', lambda: check(checkpoint=bytes(40)))
        self.refuses('local-grant-wrong-policy', lambda: check(policy=bytes(32)))
        self.refuses('local-grant-wrong-device', lambda: check(device=ctx.devices[1]))
        self.refuses('local-grant-expired-target', lambda: check(now=300), 'expired or premature authority')
        require(check().operation == operation, 'genuine local operation')

    def prepared(self, materials, proposal_wire):
        operation, wire, target = materials
        original = (self.path / 'intent').read_bytes()
        # Local supplied-time admission must refuse a new Commit before any
        # Commit request is dispatched. The witness clock remains 210 here.
        owner = self.open(operation)
        try:
            self.refuses('expired-target-new-commit', lambda: owner.commit(300), 'expired or premature authority')
        finally:
            owner.close()
        require((self.path / 'intent').read_bytes() == original, 'refused commit replaced exact intent')
        proposal = Proposal.decode(proposal_wire)
        self.refuses('proposal-trailing', lambda: Proposal.decode(proposal_wire + b'\0'))
        self.refuses('proposal-not-next-head', lambda: replace(proposal, target=proposal.expected))
        wrong = self.client()
        try:
            self.refuses('proposal-wrong-subject', lambda: replace(proposal, subject=bytes([1]) * 96).exchange(wrong, 6),
                         'renewal client scope')
        finally:
            wrong.close()
        owner = None; armed = False; transport = TcpTransport(self.address)
        def reenter(request, deadline):
            result = transport(request, deadline)
            if armed:
                self.refuses('same-owner-reentrant-transaction', lambda: owner.prepare(wire, target, 210),
                             'operation already in progress')
            return result
        owner = self.open(operation, reenter); armed = True
        try:
            require(owner.status() == 'Prepared', 'reentrant refusal damaged outer transaction')
        finally:
            owner.close()
        require((self.path / 'intent').read_bytes() == original, 'nested transaction changed target')
        armed = False
        def cancel(request, deadline):
            result = transport(request, deadline)
            if armed:
                owner.close()
            return result
        owner = self.open(operation, cancel); armed = True
        try:
            self.refuses('closed-owner-withholds-valid-status', owner.status, 'closed witness client during exchange')
        finally:
            owner.close()
        require((self.path / 'intent').read_bytes() == original, 'cancellation erased original intent')

    def adopted(self, private):
        opening = []; carrier = TcpTransport(self.address)
        def transport(request, deadline):
            opening.append(request[204])
            return carrier(request, deadline)
        owner = WitnessSession.open(self.path, self.scope, self.key, self.context, client=self.client(transport))
        try:
            require(opening == [1], 'renewed opening repeated its authenticated witness query')
            with owner._state(operational=False) as (snapshot, state):
                require(state.format_version == 6 and state.local_authority is not None, 'adopted local metadata')
                require(encode(state) == snapshot.payload, 'canonical local snapshot')
                for version in range(1, 6):
                    state.format_version = version
                    self.refuses('local-authority-downgrade-' + str(version), lambda: encode(state),
                                 'local authority requires snapshot version six')
                state.format_version = 6
                for offset in (42, 82, 85, 86, 100):
                    data = snapshot.payload[:offset] + bytes([snapshot.payload[offset] ^ 0xff]) + snapshot.payload[offset + 1:]
                    self.refuses('stored-local-authority-' + str(offset), lambda data=data: decode(data, self.context))
                derived = replace(self.context, current_local=state.local_authority)
                self.refuses('derived-local-context-open', lambda: WitnessSession._scope(derived, self.scope),
                             'derived session authority')
        finally:
            owner.close()
        # Negative clones are isolated and retained; the real lineage is never
        # modified/restored to manufacture recovery or erase a failed operation.
        for mode in ('missing', 'corrupt'):
            path = private / ('negative-authority-' + mode); path.mkdir(mode=0o700)
            shutil.copyfile(self.path / 'head', path / 'head'); (path / 'head').chmod(0o600)
            if mode == 'corrupt':
                data = (self.path / 'authority').read_bytes()
                (path / 'authority').write_bytes(data[:-1] + bytes([data[-1] ^ 1])); (path / 'authority').chmod(0o600)
            reason = 'missing original local authority control' if mode == 'missing' else 'authority control authentication'
            self.refuses('retained-local-control-' + mode,
                         lambda: WitnessSession.open(path, self.scope, self.key, self.context, client=self.client()), reason)
