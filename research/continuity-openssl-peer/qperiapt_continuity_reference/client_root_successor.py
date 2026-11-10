"""Exact prepared successor admission through the existing root adoption owner."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .account_root_protocol import _target_statement
from .client_configuration import Configuration
from .client_root_adoption import RootAdoption, begin
from .enrollment_client import EnrollmentClient
from .owner_guard import coordinated
from .registration_session import validate_context
from .wire import require


@coordinated
def prepare(target, registry, expected, retained, now, transport):
    """Consume an original target client or its interrupted adoption owner."""
    try:
        target._alive(); configuration = Configuration.read(target._configuration.read().payload)
        require(target._authority.application == expected.application
                and target._authority.root == retained.target.successor, 'successor client authority differs')
        if type(target) is RootAdoption:
            require(target._registry() is registry, 'successor adoption registry differs')
            _, image = target._image(); parent = target
        else:
            require(type(target) is EnrollmentClient and target._registration._child is None,
                    'original successor client without a borrowed child required')
            parent = target._registration; _, image = parent._image()
        require(image.admission is not None and image.child is not None and image.confirmation is None,
                'successor activation requires original prepared child')
        context = image.child.inputs.current(now)
        require(context.digest == image.child.context and context.witness is not None,
                'successor original context differs')
        validate_context(parent, image, context)
        intent, admission = image.effective(parent._intent)
        actual,_=_target_statement(registry.witness,retained.target.operation,retained.target.previous,
            admission.pin(intent),admission.certificate,admission.roster,context.original_policy,
            admission.journal,retained.target.genesis)
        require(actual==retained.target.unbound(),'successor signed target differs from approved target')
        lease = registry.admit(expected)
        genesis = retained.target.subject + retained.target.genesis
        if configuration.root_binding is None:
            require(type(target) is EnrollmentClient, 'successor adoption has no original root binding')
            return begin(target, registry, now, transport=transport, expected_genesis=genesis)
        configuration.root_binding.check(lease)
        require(configuration.root_adoption, 'successor is not the original prepared root adoption')
        if type(target) is RootAdoption:
            target._genesis = genesis; return target
        path, identity, key, observer = (target._root.path, target._configuration.scope.identity,
                                         target._registration._key, target._observer)
        target.close()
        return RootAdoption.open(path, identity, key, registry, observer=observer, _genesis=genesis)
    except BaseException:
        target.close(); raise
