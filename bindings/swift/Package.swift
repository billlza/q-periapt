// swift-tools-version:5.9
import PackageDescription

// Build the static lib first: `cargo build -p q-periapt-ffi --release`
// (produces ../../target/release/libq_periapt_ffi_abi2.a). See README.md.
let package = Package(
    name: "QPeriaptHybrid",
    products: [
        .library(name: "QPeriaptHybrid", targets: ["QPeriaptHybrid"])
    ],
    targets: [
        // C module exposing the cbindgen-generated header.
        .systemLibrary(name: "CQPeriapt", path: "Sources/CQPeriapt"),
        .target(
            name: "QPeriaptHybrid",
            dependencies: ["CQPeriapt"],
            linkerSettings: [
                .unsafeFlags(["-L../../target/release", "-lq_periapt_ffi_abi2"])
            ]
        ),
        .testTarget(name: "QPeriaptHybridTests", dependencies: ["QPeriaptHybrid"]),
    ]
)
