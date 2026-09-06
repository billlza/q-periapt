"""Regression coverage for the SDK DEX consumer's JNI registration boundary."""

from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

import android_elf


# Independent fixture for the Java/C ABI2 contract. Access labels use the SDK
# dexdump format; real R8 mutation cases separately exercise actual DEX files.
NATIVE_METHODS = (
    ("runtimeAbiVersionNative", "()I", "PRIVATE STATIC NATIVE"),
    ("runtimeVersionNative", "()Ljava/lang/String;", "PRIVATE STATIC NATIVE"),
    ("fixedSuiteIdNative", "()Ljava/lang/String;", "PRIVATE STATIC NATIVE"),
    ("fixedSuiteIdLenNative", "()J", "PRIVATE STATIC NATIVE"),
    ("statusNameNative", "(I)Ljava/lang/String;", "PRIVATE STATIC NATIVE"),
    ("decisionFromSignedPolicyNative", "([B[B[B[B)[B", "PRIVATE STATIC NATIVE"),
    ("generateKeypairNative", "([B[B[B[B[B)V", "PRIVATE STATIC NATIVE"),
    ("encapsulateNative", "([B[B[B[B[B[B[B)V", "PRIVATE STATIC NATIVE"),
    ("decapsulateNative", "([B[B[B[B[B[B[B[B[B)V", "PRIVATE STATIC NATIVE"),
)
CALLBACK = (
    ("<init>", "(Ljava/lang/String;ILjava/lang/String;)V", "PUBLIC CONSTRUCTOR"),
)
FACADE = "Ldev/qperiapt/android/QPeriaptAndroid;"
EXCEPTION = "Ldev/qperiapt/android/QPeriaptAndroid$QPeriaptException;"
ACCESS_BITS = {"PUBLIC": 0x1, "PRIVATE": 0x2, "STATIC": 0x8, "NATIVE": 0x100, "CONSTRUCTOR": 0x10000}


def members(methods: tuple[tuple[str, str, str], ...]) -> str:
    return "".join(
        f"    #{index} : (in fixture)\n"
        f"      name          : '{name}'\n"
        f"      type          : '{descriptor}'\n"
        f"      access        : 0x{sum(ACCESS_BITS[flag] for flag in access.split()):04x} ({access})\n"
        for index, (name, descriptor, access) in enumerate(methods)
    )


def class_dump(index: int, descriptor: str, methods: tuple[tuple[str, str, str], ...]) -> str:
    return (
        f"Class #{index}            -\n"
        f"  Class descriptor  : '{descriptor}'\n"
        "  Static fields     -\n"
        "  Instance fields   -\n"
        "  Direct methods    -\n"
        + members(methods)
        + "  Virtual methods   -\n"
    )


def complete_dump() -> str:
    return class_dump(0, FACADE, NATIVE_METHODS) + class_dump(1, EXCEPTION, CALLBACK)


class AndroidMinimalConsumerTests(unittest.TestCase):
    def test_complete_native_contract_and_callback_are_accepted(self) -> None:
        android_elf.verify_minimal_consumer_dump(complete_dump())

    def test_each_registered_method_is_required(self) -> None:
        for index, (name, _descriptor, _access) in enumerate(NATIVE_METHODS):
            with self.subTest(method=name):
                output = class_dump(0, FACADE, NATIVE_METHODS[:index] + NATIVE_METHODS[index + 1 :])
                output += class_dump(1, EXCEPTION, CALLBACK)
                with self.assertRaisesRegex(android_elf.AndroidVerificationError, "complete JNI registration"):
                    android_elf.verify_minimal_consumer_dump(output)

    def test_wrong_descriptor_extra_registration_and_duplicate_are_rejected(self) -> None:
        wrong = (("runtimeAbiVersionNative", "()J", "PRIVATE STATIC NATIVE"),) + NATIVE_METHODS[1:]
        extra = NATIVE_METHODS + (("unexpectedNative", "()V", "PRIVATE STATIC NATIVE"),)
        duplicate = NATIVE_METHODS + NATIVE_METHODS[:1]
        for methods in (wrong, extra, duplicate):
            with self.subTest(methods=methods):
                with self.assertRaises(android_elf.AndroidVerificationError):
                    android_elf.verify_minimal_consumer_dump(
                        class_dump(0, FACADE, methods) + class_dump(1, EXCEPTION, CALLBACK)
                    )

    def test_native_and_static_access_must_survive(self) -> None:
        for access in ("PRIVATE STATIC", "PRIVATE NATIVE"):
            with self.subTest(access=access):
                changed = ((NATIVE_METHODS[0][0], NATIVE_METHODS[0][1], access),) + NATIVE_METHODS[1:]
                with self.assertRaises(android_elf.AndroidVerificationError):
                    android_elf.verify_minimal_consumer_dump(
                        class_dump(0, FACADE, changed) + class_dump(1, EXCEPTION, CALLBACK)
                    )

    def test_callback_class_exact_signature_and_constructor_access_are_required(self) -> None:
        cases = (
            class_dump(0, FACADE, NATIVE_METHODS),
            class_dump(0, FACADE, NATIVE_METHODS) + class_dump(1, EXCEPTION, ()),
        )
        for descriptor, access in (
            ("(Ljava/lang/String;JLjava/lang/String;)V", "PUBLIC CONSTRUCTOR"),
            (CALLBACK[0][1], "PRIVATE CONSTRUCTOR"),
            (CALLBACK[0][1], "PUBLIC STATIC CONSTRUCTOR"),
            (CALLBACK[0][1], "PUBLIC"),
        ):
            cases += (class_dump(0, FACADE, NATIVE_METHODS) + class_dump(1, EXCEPTION, (("<init>", descriptor, access),)),)
        for output in cases:
            with self.subTest(output=output):
                with self.assertRaisesRegex(android_elf.AndroidVerificationError, "public JNI exception callback"):
                    android_elf.verify_minimal_consumer_dump(output)

    def test_field_definitions_cannot_supply_native_method_evidence(self) -> None:
        facade = class_dump(0, FACADE, ()).replace("  Direct methods    -\n", members(NATIVE_METHODS) + "  Direct methods    -\n")
        with self.assertRaisesRegex(android_elf.AndroidVerificationError, "complete JNI registration"):
            android_elf.verify_minimal_consumer_dump(facade + class_dump(1, EXCEPTION, CALLBACK))

    def test_missing_malformed_and_duplicate_class_framing_is_rejected(self) -> None:
        for output in (
            "",
            "the expected JNI names appear in an unrelated message",
            complete_dump().replace("Class descriptor  : '" + FACADE + "'", "missing descriptor"),
            complete_dump().replace("  Direct methods    -\n", "  Missing methods   -\n", 1),
            complete_dump() + class_dump(2, FACADE, NATIVE_METHODS),
        ):
            with self.subTest(output=output):
                with self.assertRaises(android_elf.AndroidVerificationError):
                    android_elf.verify_minimal_consumer_dump(output)

    def test_extra_non_native_java_methods_remain_outside_the_keep_contract(self) -> None:
        methods = NATIVE_METHODS + (("applicationHelper", "()V", "PUBLIC STATIC"),)
        android_elf.verify_minimal_consumer_dump(
            class_dump(0, FACADE, methods) + class_dump(1, EXCEPTION, CALLBACK)
        )

    def test_dexdump_receives_the_original_bounded_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "input.dex"
            original = b"dex\n039\x00fixture"
            path.write_bytes(original)
            tool = pathlib.Path(temporary) / "dexdump"

            def inspect(selected_tool: pathlib.Path, arguments: list[str], selected: pathlib.Path) -> str:
                self.assertEqual(selected_tool, tool)
                self.assertEqual(arguments, [])
                self.assertNotEqual(selected, path)
                path.write_bytes(b"changed after snapshot")
                self.assertEqual(selected.read_bytes(), original)
                return complete_dump()

            with mock.patch.object(android_elf, "run_tool", side_effect=inspect) as invoke:
                android_elf.verify_minimal_consumer_dex(path, dexdump=tool)
            invoke.assert_called_once()

    def test_invalid_dex_fails_before_tool_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "not.dex"
            path.write_bytes(b"not a dex file")
            with mock.patch.object(android_elf, "run_tool") as invoke:
                with self.assertRaisesRegex(android_elf.AndroidVerificationError, "not a DEX file"):
                    android_elf.verify_minimal_consumer_dex(path, dexdump=pathlib.Path("unused"))
            invoke.assert_not_called()

    def test_tool_failure_is_not_replaced_by_a_successful_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "input.dex"
            path.write_bytes(b"dex\n039\x00fixture")
            failure = android_elf.AndroidVerificationError("actual SDK tool failed")
            with mock.patch.object(android_elf, "run_tool", side_effect=failure):
                with self.assertRaises(android_elf.AndroidVerificationError) as observed:
                    android_elf.verify_minimal_consumer_dex(path, dexdump=pathlib.Path("unused"))
            self.assertIs(observed.exception, failure)


if __name__ == "__main__":
    unittest.main()
