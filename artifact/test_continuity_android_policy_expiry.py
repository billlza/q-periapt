"""Synthetic expiry-reader controls are not native or cryptographic evidence."""
from pathlib import Path
import tempfile
import unittest
import continuity_android_policy_expiry as expiry

def fixture(root,profile):
    lines=[]
    for carrier in ('signed','tls'):
        for outcome in ('closed','applied'):
            applied=outcome=='applied';base=root/f'{carrier}-{profile}-{outcome}';(base/'inputs').mkdir(parents=True)
            scope=b'o'*32+b's'*32;target=(2).to_bytes(8,'big')+b't'*32
            pending=(1).to_bytes(4,'big')+scope+bytes(48);committed=(2).to_bytes(4,'big')+scope+target+bytes(8);closed=(4).to_bytes(4,'big')+scope+target+bytes(8)
            frame=bytearray(7334);frame[0]=1;frame[205]=6;transcript=bytes(frame)
            if not applied:frame[205]=7;transcript+=bytes(frame)
            values={'original.request':b'r'*5506,'activated.request':b'r'*5506,'genesis':(2).to_bytes(4,'big')+b'j'*32+b'g'*128,
             'expiry-original':b'i'*32+b'j'*32,'expiry-original-after':b'i'*32+b'j'*32,
             'inputs/credential-operation':scope[:32],'inputs/credential-statement':scope[32:],'inputs/renewal-version':target[:8],'inputs/renewal-digest':target[8:],
             'expiry-staged':pending,'expiry-before-expiration':(218).to_bytes(4,'big') if applied else pending,
             'expiry-transition':committed if applied else (104).to_bytes(4,'big'),'expiry-history':committed if applied else pending,
             'expiry-proposal':b'p'*296,'expiry-proposal-replayed':b'p'*296,
             'expiry-observation':b''.join(v.to_bytes(8,'big') for v in [100,101,500,600,1]),'expiry-sdk-binding':b'b'*68,'expiry-historical-transcript':transcript}
            for name in ['expiry-close','expiry-terminal','expiry-terminal-replayed']:values[name]=committed if applied else closed
            for name in ['expiry-stage-refused','expiry-activation-before','expiry-activation-after']:values[name]=(104).to_bytes(4,'big')
            if applied:
                request,reply=bytearray(3674),bytearray(3659);request[204]=5;reply[204]=8;values['expiry-lost-commit-request']=request;values['expiry-lost-commit-reply']=reply
            for name,mode in expiry.cases(applied):values[name+'.stdout']=f'{profile}:{mode}:passed\n'.encode();values[name+'.stderr']=b''
            for name,data in values.items():(base/name).write_bytes(data)
            lines.append(f'qualified policy expiry {carrier}/{profile}/{outcome}: 18 foreign processes; live SDK and target, expired P0, original history, no fresh commit or activation')
    lines += ['test '+expiry.TESTS[profile]+' ... ok','test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 29 filtered out;']
    return ('\n'.join(lines)+'\n').encode()

class PolicyExpiryReaderTests(unittest.TestCase):
    def test_all_carriers_outcomes_and_trust_profiles(self):
        for profile in expiry.TESTS:
            with self.subTest(profile=profile),tempfile.TemporaryDirectory() as t:
                root=Path(t);stdout=fixture(root,profile);result=expiry.verify_execution(stdout,root,profile)
                self.assertEqual(sum(x['foreign_processes'] for x in result.values()),72)
                with self.assertRaises(ValueError):expiry.verify_execution(stdout.replace(b'1 passed',b'0 passed'),root,profile)
                with self.assertRaises(ValueError):expiry.verify_execution(stdout.replace(b'qualified policy expiry tls',b'missing tls'),root,profile)
    def test_original_history_and_current_refusals_cannot_be_replaced(self):
        for name in ('expiry-original-after','expiry-proposal-replayed','expiry-stage-refused','expiry-activation-after','expiry-transition','expiry-terminal-replayed'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as t:
                root=Path(t);stdout=fixture(root,'fixed');p=root/'tls-fixed-applied'/name;data=p.read_bytes();p.write_bytes(bytes([data[0]^1])+data[1:])
                with self.assertRaises(ValueError):expiry.verify_execution(stdout,root,'fixed')
    def test_expiry_and_no_new_commit_evidence_are_required(self):
        for name,offset,value in (('expiry-observation',15,99),('expiry-observation',39,0),('expiry-historical-transcript',205,5),('expiry-lost-commit-request',204,6)):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as t:
                root=Path(t);stdout=fixture(root,'recoverable');p=root/'signed-recoverable-applied'/name;data=bytearray(p.read_bytes());data[offset]=value;p.write_bytes(data)
                with self.assertRaises(ValueError):expiry.verify_execution(stdout,root,'recoverable')

    def test_truncated_sdk_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);stdout=fixture(root,'fixed')
            (root/'signed-fixed-closed'/'expiry-sdk-binding').write_bytes(b'b'*32)
            with self.assertRaises(ValueError):expiry.verify_execution(stdout,root,'fixed')

if __name__=='__main__':unittest.main()
