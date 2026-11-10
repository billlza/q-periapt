"""Independent grammar, public-state and package-boundary controls."""
import json
import copy
from pathlib import Path
import tomllib
import unittest
from artifact import whole_kem_reference as whole
from artifact import spqr_reference as ref


class WholeKemTests(unittest.TestCase):
    def test_active_fork_events_bind_both_actual_keys_and_exact_packet_metadata(self):
        row = {"sequence":0,"sender":0,"original_wire":"d10100010000","replacement_wire":"d10100010000",
               "original_message_epoch":0,"replacement_message_epoch":0,"sender_key_sha256":"11"*32,
               "attacker_received_key_sha256":"11"*32,"attacker_sent_key_sha256":"22"*32,
               "receiver_key_sha256":"22"*32,"honest_a_confirmed_epoch":0,"honest_b_confirmed_epoch":0}
        original,replacement = whole.active_event(row,1,0)
        self.assertEqual((original["message_epoch"],replacement["message_epoch"]),(0,0))
        for field,value,error in (("sender_key_sha256","33"*32,"actual key agreement"),
                                  ("receiver_key_sha256","33"*32,"actual key agreement"),
                                  ("attacker_sent_key_sha256","gg"*32,"key commitment"),
                                  ("original_message_epoch",1,"packet metadata"),
                                  ("sequence",1,"exact schedule"),
                                  ("sender",1,"exact schedule"),
                                  ("replacement_wire","d12000010000","packet metadata")):
            changed=copy.deepcopy(row);changed[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ref.ReferenceError,error):
                whole.active_event(changed,1,0)
        changed=dict(row,private_key="00"*32)
        with self.assertRaisesRegex(ref.ReferenceError,"event fields"):
            whole.active_event(changed,1,0)

    def test_exact_wire_shapes_and_closed_profiles(self):
        for profile in whole.PROFILES:
            for kind,size in ((0,0),(1,1216),(2,1152),(3,64)):
                data=bytes([0xd1,profile,1 if kind == 3 else 0,1,0,kind])+(b"\x01"+bytes(size) if kind else b"")
                parsed=whole.wire(data)
                self.assertEqual((parsed["profile"],parsed["index"],parsed["kind"]),(profile,1,kind))
                self.assertEqual(len(parsed["body"]),size)
                with self.assertRaises(ref.ReferenceError): whole.wire(data+b"\x00")
                if kind:
                    with self.assertRaises(ref.ReferenceError): whole.wire(data[:-1])
                    altered=bytearray(data)
                    altered[2]=0 if kind == 3 else 1
                    with self.assertRaises(ref.ReferenceError): whole.wire(bytes(altered))

    def test_malformed_integer_profile_and_type_are_rejected(self):
        for data in (b"",bytes([1,1,0,1,0,0]),bytes([0xd1,0,0,1,0,0]),bytes([0xd1,2,0,1,0,0]),
                     bytes([0xd1,1,0x80,0,1,0,0]),bytes([0xd1,1,0,0,0,0]),bytes([0xd1,1,0,1,0,9]),
                     bytes([0xd1,1])+b"\xff"*10+b"\x01\x01\x00\x00"):
            with self.subTest(data=data),self.assertRaises(ref.ReferenceError): whole.wire(data)

    def test_public_state_cannot_invent_confirmation_or_hide_resource_growth(self):
        state={"known_epoch":1,"confirmed_epoch":0,"send_epoch":0,"receive_epoch":0,"phase":3,"skipped_keys":0,"bytes":1000}
        self.assertEqual(whole.metadata(state,1,0,0,0,3),state)
        for field,value in (("known_epoch",2),("confirmed_epoch",1),("send_epoch",1),("phase",0),("skipped_keys",2001),("bytes",0),("known_epoch",True)):
            changed=dict(state);changed[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ref.ReferenceError): whole.metadata(changed,1,0,0,0,3)
        private=dict(state);private["root_key"]="00"*32
        with self.assertRaises(ref.ReferenceError): whole.metadata(private,1,0,0,0,3)

    def test_isolated_reference_does_not_enter_the_sdk_graph(self):
        manifest=tomllib.loads((whole.CRATE/"Cargo.toml").read_text())
        self.assertFalse(manifest["package"]["publish"])
        self.assertEqual(manifest["workspace"]["members"],["."])
        self.assertEqual(manifest["dependencies"]["libcrux-ml-kem"]["version"],"=0.0.8")
        self.assertEqual(manifest["dependencies"]["libcrux-hmac"],"=0.0.6")
        packages=ref.decode_json(ref.command(["cargo","metadata","--manifest-path",str(whole.ROOT/"Cargo.toml"),"--locked","--format-version","1","--no-deps"]))["packages"]
        for package in packages:
            self.assertNotEqual(package["name"],"q-periapt-whole-kem-reference")
            self.assertTrue(all(d["name"] != "q-periapt-whole-kem-reference" for d in package["dependencies"]))
        names={p["name"] for p in tomllib.loads((whole.ROOT/"Cargo.lock").read_text())["package"]}
        self.assertNotIn("q-periapt-whole-kem-reference",names)


if __name__ == "__main__":
    unittest.main(warnings="error")
