#!/usr/bin/env python3
"""Actual private inbox files and process cuts; no protocol authorization claim."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from pathlib import Path
import json
import os
import select
import signal
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import enrollment_exchange as fixture
from cryptography.exceptions import InvalidTag
from qperiapt_continuity_reference import mailbox as implementation
from qperiapt_continuity_reference.mailbox import Mailbox,encode,decode
from qperiapt_continuity_reference.traffic import message_id
from qperiapt_continuity_reference.journal import MissingState


class MailboxChecks(unittest.TestCase):
    def setUp(self):
        self.path=fixture.args.private_output/self._testMethodName;self.path.mkdir(mode=0o700)
        self.client,self.journal,self.session,self.key=(os.urandom(32) for _ in range(4))
        self.serial=0

    def directory(self):
        self.serial+=1;path=self.path/str(self.serial);path.mkdir(mode=0o700);return path

    def create(self,path,**kwargs):
        return Mailbox.provision(path,self.client,self.journal,self.session,self.key,**kwargs)

    def reopen(self,path,**kwargs):
        return Mailbox.open(path,self.client,self.journal,self.session,self.key,**kwargs)

    def message(self,index=0,epoch=0):return message_id(self.session,2,index,epoch)

    def kill_at(self,stage,work):
        read,write=os.pipe();pid=os.fork()
        if pid==0:
            os.close(read)
            def observe(current):
                if current==stage:
                    os.write(write,b'R')
                    while True:signal.pause()
            try:work(observe)
            except BaseException:
                os.write(write,b'E');os._exit(2)
            os._exit(3)
        os.close(write)
        try:
            self.assertTrue(select.select([read],[],[],15)[0],'child did not reach selected durable boundary')
            self.assertEqual(os.read(read,1),b'R')
        finally:
            os.close(read);os.kill(pid,signal.SIGKILL);_,status=os.waitpid(pid,0)
        self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGKILL)

    def test_original_effect_is_encrypted_deduplicated_and_readable_after_reopen(self):
        path=self.directory();body=b'separate host effect with retained confidential bytes'
        with self.create(path) as box:
            box.commit(self.session,self.message(),body);box.commit(self.session,self.message(),body)
            self.assertEqual(box.count(),1);self.assertEqual(box.delivery(self.message()),body)
        for entry in path.iterdir():
            self.assertNotIn(body,entry.read_bytes())
        with self.reopen(path) as box:
            box.commit(self.session,self.message(1),b'');self.assertEqual(box.delivery(self.message(1)),b'')
            with self.assertRaisesRegex(ValueError,'conflicting'):box.commit(self.session,self.message(),b'other')
        with self.reopen(path) as box:
            self.assertEqual(box.count(),2);self.assertEqual(box.delivery(self.message()),body)

    def test_wrong_client_journal_session_key_and_direction_are_refused(self):
        path=self.directory();self.create(path).close()
        selected=[self.client,self.journal,self.session,self.key]
        for index in range(4):
            changed=selected.copy();changed[index]=os.urandom(32)
            with self.assertRaises((ValueError,InvalidTag)):Mailbox.open(path,*changed)
        with self.reopen(path) as box:
            with self.assertRaisesRegex(ValueError,'message scope'):
                box.commit(self.session,message_id(self.session,1,0,0),b'bad direction')
            with self.assertRaisesRegex(ValueError,'session differs'):box.commit(os.urandom(32),self.message(),b'bad session')
            self.assertEqual(box.count(),0)

    def test_missing_or_replaced_state_never_initializes_during_open(self):
        path=self.directory()
        for recover in (False,True):
            with self.assertRaises(MissingState):self.reopen(path,recover_initial=recover)
        self.assertEqual(list(path.iterdir()),[])
        self.create(path).close()
        with self.assertRaises(ValueError):self.create(path)
        (path/'head').rename(path/'head.saved')
        with self.assertRaises(MissingState):self.reopen(path)
        self.assertFalse((path/'head').exists())
        with self.assertRaises(ValueError):self.create(path)

    def test_initialization_process_cuts_recover_only_the_original_authenticated_intent(self):
        for stage in ('stage-synced:intent','published:intent','published:head','committed:removal'):
            path=self.directory()
            self.kill_at(stage,lambda observer:self.create(path,observer=observer))
            if stage in ('stage-synced:intent','published:intent'):
                with self.assertRaises((ValueError,MissingState)):self.reopen(path)
            with self.reopen(path,recover_initial=True) as box:self.assertEqual(box.count(),0)
            with self.reopen(path) as box:box.commit(self.session,self.message(),b'after original init')

    def test_delivery_process_cuts_preserve_original_effect_and_retry_identity(self):
        for stage in ('stage-synced:intent','published:intent','published:head','committed:removal','inbox:effect-committed'):
            path=self.directory();self.create(path).close()
            def work(observer):
                with self.reopen(path,observer=observer) as box:box.commit(self.session,self.message(),b'original')
            self.kill_at(stage,work)
            with self.reopen(path) as box:
                self.assertEqual(box.count(),0 if stage=='stage-synced:intent' else 1)
                box.commit(self.session,self.message(),b'original')
                self.assertEqual(box.delivery(self.message()),b'original');self.assertEqual(box.count(),1)

    def test_capacity_error_preserves_prior_effects_without_eviction(self):
        path=self.directory()
        with self.create(path) as box:
            # Authenticated boundary fixture avoids 127 unrelated disk commits.
            rows={self.message(n):bytes(16384) for n in range(127)}
            prior=box._store.read();box._store.update(prior.digest,encode(rows))
            with self.assertRaisesRegex(ValueError,'byte capacity'):box.commit(self.session,self.message(127),bytes(16384))
        with self.reopen(path) as box:
            self.assertEqual(box.count(),127);self.assertEqual(box.delivery(self.message()),bytes(16384))
        for raw in (b'',implementation.TAG+b'\0\1',implementation.TAG+b'\0\0x'):
            with self.assertRaises(ValueError):decode(raw,self.session)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MailboxChecks))
    print(json.dumps({'tests':result.testsRun,'successful':result.wasSuccessful(),
        'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),
        'provider_version':fixture.provider.__version__,'openssl':fixture.backend.openssl_version_text(),
        'implementation':str(Path(implementation.__file__).resolve()),'private_fixtures_retained':str(fixture.args.private_output)}))
    raise SystemExit(0 if result.wasSuccessful() else 1)
