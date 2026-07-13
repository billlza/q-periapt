#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import unittest

from rust_publish_contract import (
    RustPublishContractError,
    validate_mlkem_native_build_surface,
    validate_packaged_mlkem_native_local_sources,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
SYS_CRATE = ROOT / "crates" / "q-periapt-mlkem-native-sys"


class RustPublishContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build_rs = (SYS_CRATE / "build.rs").read_text(encoding="utf-8")
        cls.build_support = (SYS_CRATE / "src" / "build_support.rs").read_text(
            encoding="utf-8"
        )
        cls.bridge_c = (SYS_CRATE / "src" / "mlkem_bridge.c").read_text(
            encoding="utf-8"
        )
        cls.bridge_h = (SYS_CRATE / "src" / "mlkem_bridge.h").read_text(
            encoding="utf-8"
        )
        cls.local_config = (SYS_CRATE / "src" / "mlkem_config.h").read_text(
            encoding="utf-8"
        )

    def validate(
        self,
        *,
        build_rs: str | None = None,
        build_support: str | None = None,
        bridge_c: str | None = None,
        bridge_h: str | None = None,
        local_config: str | None = None,
    ) -> None:
        validate_mlkem_native_build_surface(
            build_rs=self.build_rs if build_rs is None else build_rs,
            build_support=(
                self.build_support if build_support is None else build_support
            ),
            bridge_c=self.bridge_c if bridge_c is None else bridge_c,
            bridge_h=self.bridge_h if bridge_h is None else bridge_h,
            local_config=self.local_config if local_config is None else local_config,
        )

    def test_repository_build_surface_passes(self) -> None:
        self.validate()

    def test_packaged_local_source_set_is_exact(self) -> None:
        repository_sources = {
            path.relative_to(SYS_CRATE).as_posix()
            for path in (SYS_CRATE / "src").rglob("*")
            if path.is_file()
        }
        validate_packaged_mlkem_native_local_sources(repository_sources)

        for label, mutation in (
            ("extra C source", repository_sources | {"src/extra.c"}),
            ("shadow header", repository_sources | {"src/mlkem_native.h"}),
            ("missing source", repository_sources - {"src/raw.rs"}),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "packaged local source set differs",
                ):
                    validate_packaged_mlkem_native_local_sources(mutation)

    def test_every_external_rust_source_edge_fails_closed(self) -> None:
        cases = {
            "public module": {"build_rs": self.build_rs + "\npub mod hidden;\n"},
            "scoped public module": {
                "build_rs": self.build_rs + "\npub(crate) mod hidden;\n"
            },
            "comment-separated module": {
                "build_rs": self.build_rs + "\nmod /* hidden */ extra;\n"
            },
            "nested support module": {
                "build_support": self.build_support + "\nmod nested;\n"
            },
            "include macro": {
                "build_support": self.build_support + '\ninclude!("hidden.rs");\n'
            },
            "comment-separated include": {
                "build_support": self.build_support
                + '\ninclude /* hidden */ !("hidden.rs");\n'
            },
            "comment-separated include_str": {
                "build_support": self.build_support
                + '\ninclude_str /* hidden */ !("hidden.rs");\n'
            },
            "reserved token in a comment": {
                "build_support": self.build_support + "\n// mod is reserved here\n"
            },
        }
        for label, mutation in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    RustPublishContractError, "module graph differs"
                ):
                    self.validate(**mutation)

    def test_extra_or_dynamic_translation_units_fail_closed(self) -> None:
        cases = {
            "literal file": self.build_support
            + '\nfn extra(build: &mut cc::Build) { build.file("extra.c"); }\n',
            "dynamic file": self.build_support
            + "\nfn extra(build: &mut cc::Build, path: &str) { build.file(path); }\n",
            "comment-separated file": self.build_support
            + '\nfn extra(build: &mut cc::Build) { build.file /* hidden */ ("extra.c"); }\n',
            "files collection": self.build_support
            + '\nfn extra(build: &mut cc::Build) { build.files(["extra.c"]); }\n',
        }
        for label, build_support in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    RustPublishContractError, "single portable bridge translation unit"
                ):
                    self.validate(build_support=build_support)

    def test_equivalent_rust_and_c_spellings_fail_closed(self) -> None:
        rust_mutations = {
            "UFCS": self.build_support
            + '\nfn extra(build: &mut cc::Build) { cc::Build::file(build, "extra.c"); }\n',
            "qualified UFCS": self.build_support
            + '\nfn extra(build: &mut cc::Build) { <cc::Build>::file(build, "extra.c"); }\n',
            "comment-separated method": self.build_support
            + '\nfn extra(build: &mut cc::Build) { build./* hidden */file("extra.c"); }\n',
            "split native flag": self.build_support
            + '\nfn extra(build: &mut cc::Build) { build.flag(concat!("-DMLK_CONFIG_USE_NATIVE_BACKEND_", "ARITH")); }\n',
        }
        raw_calls = {
            "file": 'build.r#file("extra.c");',
            "files": 'build.r#files(["extra.c"]);',
            "object": 'build.r#object("extra.o");',
            "objects": 'build.r#objects(["extra.o"]);',
            "define": 'build.r#define("OTHER", None);',
            "try_compile": 'let _ = build.r#try_compile("extra");',
        }
        for method, call in raw_calls.items():
            rust_mutations[f"raw {method}"] = self.build_support + (
                f"\nfn extra(build: &mut cc::Build) {{ {call} }}\n"
            )
        for label, build_support in rust_mutations.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "packaged build-surface bytes differ|single portable bridge|"
                    "portable allowlist|portable-only",
                ):
                    self.validate(build_support=build_support)

        c_mutations = {
            "quoted bridge include": {
                "bridge_c": self.bridge_c + '\n#include "extra.c"\n'
            },
            "angle bridge include": {
                "bridge_c": self.bridge_c + "\n#include <extra.c>\n"
            },
            "header include": {
                "bridge_h": self.bridge_h + '\n#include "extra.h"\n'
            },
            "commented error directive": {
                "local_config": self.local_config.replace(
                    "#error External or native mlkem-native backends are not supported by this portable-only crate",
                    "/* #error External or native mlkem-native backends are not supported by this portable-only crate */",
                    1,
                )
            },
            "disabled guard": {
                "local_config": self.local_config.replace(
                    "#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH)",
                    "#if 0\n#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH)",
                    1,
                ).replace(
                    "#endif\n\n#ifndef QPN_MLKEM_CONFIG_H",
                    "#endif\n#endif\n\n#ifndef QPN_MLKEM_CONFIG_H",
                    1,
                )
            },
        }
        for label, mutation in c_mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(RustPublishContractError):
                    self.validate(**mutation)

    def test_config_bridge_guards_and_native_shapes_fail_closed(self) -> None:
        cases = {
            "missing config selection": {
                "build_rs": self.build_rs.replace(
                    '"MLK_CONFIG_FILE"', '"OTHER_CONFIG_FILE"', 1
                ),
                "message": "select packaged mlkem_config.h exactly once",
            },
            "missing pinned bridge": {
                "bridge_c": self.bridge_c.replace(
                    '#include "mlkem_native.c"', '#include "other.c"', 1
                ),
                "message": "portable C include graph differs",
            },
            "missing guard": {
                "local_config": self.local_config.replace(
                    "MLK_CONFIG_FIPS202X4_CUSTOM_HEADER", "REMOVED_GUARD", 1
                ),
                "message": "active fail-fast native-backend guard prefix",
            },
            "native backend define": {
                "local_config": self.local_config
                + "\n#define MLK_CONFIG_USE_NATIVE_BACKEND_ARITH 1\n",
                "message": "active fail-fast native-backend guard prefix",
            },
            "prebuilt object": {
                "build_support": self.build_support
                + '\nfn extra(build: &mut cc::Build) { build.object("extra.o"); }\n',
                "message": "release build is not portable-only",
            },
            "prebuilt objects": {
                "build_support": self.build_support
                + '\nfn extra(build: &mut cc::Build) { build.objects(["extra.o"]); }\n',
                "message": "release build is not portable-only",
            },
            "comment-separated object": {
                "build_support": self.build_support
                + '\nfn extra(build: &mut cc::Build) { build.object /* hidden */ ("extra.o"); }\n',
                "message": "release build is not portable-only",
            },
            "dynamic define": {
                "build_support": self.build_support
                + "\nfn extra(build: &mut cc::Build, name: &str) { build.define(name, None); }\n",
                "message": "build-script API surface differs",
            },
            "native backend flag": {
                "build_support": self.build_support
                + '\nfn extra(build: &mut cc::Build) { build.flag("-DMLK_CONFIG_USE_NATIVE_BACKEND_ARITH"); }\n',
                "message": "build-script API surface differs",
            },
            "second compilation": {
                "build_support": self.build_support
                + '\nfn extra(build: &mut cc::Build) { let _ = build.try_compile("extra"); }\n',
                "message": "build-script API surface differs",
            },
        }
        for label, case in cases.items():
            message = case["message"]
            mutation = {key: value for key, value in case.items() if key != "message"}
            with self.subTest(label=label):
                with self.assertRaisesRegex(RustPublishContractError, message):
                    self.validate(**mutation)


if __name__ == "__main__":
    unittest.main()
