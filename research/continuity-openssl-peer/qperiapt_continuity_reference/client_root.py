"""Original client/registration association with an independently retained registry."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
from .account_authority import AccountAuthority
from .account_authority_state import Checkpoint
from .wire import require


def selected(configuration,registry):
    require(type(registry) is AccountAuthority,'original account registry required')
    binding=configuration.root_binding
    require(binding is not None,'client root association absent')
    expected=Checkpoint(binding.application,binding.revision,binding.account)
    lease=registry.admit(expected);binding.check(lease)
    authority,_=configuration.inputs();lease.check_account(binding.account,authority.family)
    return lease


def finish(client,configuration):
    from .enrollment_client import Configuration
    binding=configuration.root_binding;require(binding is not None,'original client root association absent')
    require(not configuration.root_adoption or configuration.root_ready,'original root adoption remains pending')
    binding.check(client._root_lease)
    require(client._registration.bind_account_root(client._root_lease)==binding,'registration root association differs')
    if not configuration.root_ready:
        snapshot=client._configuration.read()
        require(Configuration.read(snapshot.payload)==configuration,'client root association changed')
        client._configuration.update(snapshot.digest,replace(configuration,root_ready=True).wire())
    final=Configuration.read(client._configuration.read().payload)
    require(final==replace(configuration,root_ready=True),'client root association durable readback')
    client._alive();return binding


def bind(client,registry):
    from .enrollment_client import Configuration
    client._alive();require(type(registry) is AccountAuthority,'original account registry required')
    snapshot=client._configuration.read();configuration=Configuration.read(snapshot.payload)
    if configuration.root_binding is not None:
        client._root_lease=selected(configuration,registry)
        return finish(client,configuration)
    require(client._registration._child is None,'close borrowed child before root association')
    _,image=client._registration._image()
    require(image.admission is not None,'root association requires accepted registration')
    require(image.child is None,'existing unbound child requires explicit root-binding migration')
    intent,admission=image.effective(client._registration._intent)
    expected=registry.associate(client._authority.application,admission.pin(intent),admission.certificate,admission.roster)
    lease=registry.admit(expected);lease.check_account(expected.account,intent.family)
    updated=replace(configuration,root_binding=lease.binding,root_ready=False)
    client._configuration.update(snapshot.digest,updated.wire())
    client._root_lease=lease
    return finish(client,updated)
