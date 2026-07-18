from __future__ import annotations

import os
import pathlib
import tempfile
import unittest
from unittest import mock

import release_consumer_smoke


class ReleaseConsumerFlagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.package = pathlib.Path(self.temporary.name).resolve()
        self.include = self.package / "include/qperiapt/abi2"
        self.library = self.package / "lib"
        self.include.mkdir(parents=True)
        self.library.mkdir()
        self.dynamic = self.library / "libq_periapt_ffi.2.dylib"
        self.static = self.library / "libq_periapt_ffi_abi2.a"
        self.dynamic.write_bytes(b"dynamic fixture")
        self.static.write_bytes(b"static fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_canonical_dynamic_and_static_flags_pass(self) -> None:
        dynamic = release_consumer_smoke.validate_pkg_config_flags(
            self.package,
            [
                f"-I{self.include}",
                str(self.dynamic),
                f"-Wl,-rpath,{self.library}",
            ],
            static=False,
        )
        self.assertEqual(
            dynamic,
            [
                f"-I{self.include}",
                str(self.dynamic),
                f"-Wl,-rpath,{self.library}",
            ],
        )
        static = release_consumer_smoke.validate_pkg_config_flags(
            self.package,
            [f"-I{self.include}", str(self.static), "-liconv"],
            static=True,
        )
        self.assertEqual(static, [f"-I{self.include}", str(self.static), "-liconv"])

    def test_compiler_control_flags_fail_closed(self) -> None:
        hostile = (
            "@response-file",
            "-o",
            "-specs=hostile.specs",
            "-Wl,-plugin,/tmp/plugin.so",
            "-Xlinker",
            "-I/tmp/outside",
            "/tmp/libq_periapt_ffi.2.dylib",
        )
        for flag in hostile:
            with self.subTest(flag=flag), self.assertRaises(SystemExit):
                release_consumer_smoke.validate_pkg_config_flags(
                    self.package,
                    [f"-I{self.include}", str(self.dynamic), flag],
                    static=False,
                )

    def test_compile_and_runtime_use_allowlisted_environment(self) -> None:
        smoke = self.package / "share/q-periapt/smoke.c"
        smoke.parent.mkdir(parents=True)
        smoke.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        hostile = {
            "CFLAGS": "-fplugin=/tmp/hostile.so",
            "CPATH": "/tmp/hostile-include",
            "DEVELOPER_DIR": "/tmp/hostile-xcode",
            "HOME": "/tmp/hostile-home",
            "LIBRARY_PATH": "/tmp/hostile-lib",
            "LD_PRELOAD": "/tmp/hostile.so",
            "MACOSX_DEPLOYMENT_TARGET": "99.0",
            "SDKROOT": "/tmp/hostile-sdk",
            "TMPDIR": "/tmp/hostile-tmp",
        }
        with (
            mock.patch.dict(os.environ, hostile, clear=False),
            mock.patch.object(
                release_consumer_smoke,
                "run_cmd",
                side_effect=["", "ALL PASS\n"],
            ) as run,
        ):
            release_consumer_smoke.compile_and_run_c_smoke(
                self.package,
                self.package / "work",
                "/usr/bin/cc",
                "dynamic",
                [f"-I{self.include}", str(self.dynamic)],
            )

        compile_environment = run.call_args_list[0].kwargs["env"]
        runtime_environment = run.call_args_list[1].kwargs["env"]
        for name in hostile:
            self.assertNotIn(name, compile_environment)
            self.assertNotIn(name, runtime_environment)

    def test_tool_resolution_ignores_caller_path(self) -> None:
        hostile_tool = self.package / "cc"
        hostile_tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        hostile_tool.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": str(self.package)}):
            resolved = pathlib.Path(release_consumer_smoke.need_tool("cc"))
        self.assertNotEqual(resolved, hostile_tool)
        self.assertTrue(
            any(
                resolved.is_relative_to(trusted_root)
                for _candidate, trusted_root in release_consumer_smoke.TRUSTED_TOOL_CANDIDATES[
                    "cc"
                ]
            )
        )


if __name__ == "__main__":
    unittest.main()
