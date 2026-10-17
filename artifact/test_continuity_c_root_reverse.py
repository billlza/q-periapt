"""Readback validation only; installed-process evidence tests actual execution."""
import unittest

import continuity_c_root_reverse as reverse


class ReverseReadbackTests(unittest.TestCase):
    def fixture(self):
        session = b"s" * 32
        reply = (1).to_bytes(8, "big") + bytes(8) + b"r" * 16
        outbound = reply[:16] + b"o" * 16
        payload = b"effect"
        files = {
            "public/traffic/reverse-result": reverse.MARKER,
            "public/traffic/reply-message": reply,
            "public/traffic/reply-received": reply,
            "public/traffic/effect-reply-cut": session + reply + payload,
            "public/traffic/effect-reply-recover": session + reply + payload,
            "public/traffic/application-" + reply.hex(): session + reply + payload,
            "public/traffic/reply-created-on-recovery": bytes(8),
            "public/traffic/peer-process-reply-next": (10).to_bytes(8, "big"),
            "peer-reply-next.stdout": reply.hex().encode() + b"\n",
            "peer-reply-next.stderr": b"",
            "public/traffic/cut-receiver": (11).to_bytes(8, "big"),
        }
        for stage, process in (("cut", 11), ("recover", 13)):
            files.update({
                "public/process-traffic-receive-" + stage: process.to_bytes(8, "big"),
                "public/traffic/peer-process-reply-" + stage: (process + 1).to_bytes(8, "big"),
                "root-receive-" + stage + ".stdout": b"root-listening:45000\n" +
                    (b"" if stage == "cut" else b"root-stage-pass:traffic-receive-recover\n"),
                "root-receive-" + stage + ".stderr": b"",
                "peer-reply-" + stage + ".stdout":
                    b"delivery-unknown-committed\n" if stage == "cut" else b"consumed\n",
                "peer-reply-" + stage + ".stderr": b"",
                "public/stack-traffic-receive-" + stage: (536576).to_bytes(8, "big"),
                "public/stack-default-traffic-receive-" + stage: (524288).to_bytes(8, "big"),
            })
        return files, dict(session=session, outbound=outbound, payload=payload, darwin=True)

    def verify(self, files, options):
        seen = set()
        def pid(value):
            if value <= 0 or value in seen:
                raise ValueError("process reused")
            seen.add(value)
            return value
        return reverse.verify(lambda path, maximum: files[path], pid, lambda path: files[path], **options)

    def test_complete_consistent_readback_passes_without_claiming_a_release(self):
        files, options = self.fixture()
        result = self.verify(files, options)
        self.assertEqual((result['processes'], result['receiver_sigkill'], result['application_records']), (5, 1, 1))
        self.assertFalse(result['release_claim_eligible'])

    def test_direction_effect_cut_and_outcome_changes_are_rejected(self):
        files, options = self.fixture()
        changes = {
            "public/traffic/reply-message": options['outbound'],
            "public/traffic/reply-received": b"x" * 32,
            "public/traffic/effect-reply-recover": b"changed",
            "public/traffic/reply-created-on-recovery": (1).to_bytes(8, 'big'),
            "public/traffic/cut-receiver": (12).to_bytes(8, 'big'),
            "public/traffic/peer-process-reply-recover": (10).to_bytes(8, 'big'),
            "peer-reply-recover.stdout": b"delivery-unknown-committed\n",
            "root-receive-cut.stdout": b"root-listening:0\n",
            "root-receive-recover.stderr": b"callback failed",
            "public/stack-default-traffic-receive-recover": bytes(8),
        }
        for path, value in changes.items():
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.verify(dict(files, **{path: value}), options)


if __name__ == '__main__':
    unittest.main()
