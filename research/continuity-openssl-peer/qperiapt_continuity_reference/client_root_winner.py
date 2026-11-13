"""Reconcile an approved committed winner into the original fenced installation."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from contextlib import ExitStack
from .account_authority import AccountAuthority
from .account_root_protocol import CommittedAdoption
from .client_configuration import Configuration
from .enrollment_client import scope
from .journal import Journal
from .root_child_snapshot import open_child,inspect
from .root_fence import _Adoption
from .wire import require


def resume(cls,path,client_id,key,registry,operation,adoption,now,*,observer,check):
    require(type(registry) is AccountAuthority and type(adoption) is CommittedAdoption,
            'independent original registry and committed adoption required')
    require(type(now) is int and 0<=now<1<<64,'explicit committed adoption time required')
    if check is None:check=registry._alive
    with registry._checked_recovery(check):
        old,winner=adoption.verify()
        require(operation in (old.target.operation,winner.target.operation),
                'committed adoption operation differs')
        operation=old.target.operation
        expected,phase,original,decision=registry.operation(operation)
        require(phase!='Committed' and original==old.original,
                'committed adoption differs from original preparation')
        if decision:
            bound=old.check_decision(decision)
            require(bound.preparation==winner.target.preparation and bound.observations==winner.target.observations,
                    'committed adoption changes original frozen snapshot')
        configuration=Journal.open(path/'configuration',scope(client_id),key,Configuration.read)
        try:
            saved=Configuration.read(configuration.read().payload)
            require(saved.ready and saved.root_ready and saved.root_binding is not None,
                    'committed adoption requires original complete association')
            original_access=registry._recovery_access(saved.root_binding,operation)
        finally:configuration.close()
        registry.close_plan(operation,adoption.noncommit)
        registry.validate_adoption(expected,adoption)
        registry.begin_adoption(expected,adoption)
        current=registry._recovery_access(saved.root_binding,winner.target.operation)
        transition=_Adoption(original_access,current,registry.witness,adoption)
        def observe(stage):
            if observer is not None:observer(stage)
            check()
        owner=cls._open(path,client_id,key,registry,winner.target.operation,observer=observe,transition=transition)
        try:
            _,image=owner._image()
            with ExitStack() as cleanup:
                child=None;observation=None
                if image.child is not None:
                    child,context=open_child(owner,image,now);cleanup.callback(child.close)
                    child._directory.observer=lambda stage:owner._observe('root-child:'+stage)
                    observation=inspect(child,context)
                    transition.prepare(child,1,observation)
                transition.prepare(owner._registration,2)
                transition.retain(owner._registration,2)
                if child is not None:transition.retain(child,1,observation)
                owner._alive()
        finally:owner.close()
        registry.commit_adoption(winner.target.operation,adoption.retirement)
        result=cls.open(path,client_id,key,registry,winner.target.operation,observer=observer)
        try:check();return result
        except BaseException:result.close();raise
