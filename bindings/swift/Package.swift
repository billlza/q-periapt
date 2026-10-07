// swift-tools-version:5.9
import PackageDescription

// Build the static lib first: `cargo build -p q-periapt-ffi --release`
// (produces ../../target/release/libq_periapt_ffi_abi2.a). See README.md.
let package = Package(
    name: "QPeriaptHybrid",
    products: [
        .library(name: "QPeriaptHybrid", targets: ["QPeriaptHybrid"]),
        .library(name: "QPeriaptSDK", targets: ["QPeriaptSDK"])
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
        .target(
            name: "QPeriaptSDK",
            dependencies: ["CQPeriapt"],
            linkerSettings: [
                .unsafeFlags(["-L../../target/release", "-lq_periapt_ffi_abi2"])
            ]
        ),
        .testTarget(name: "QPeriaptSDKTests", dependencies: ["QPeriaptSDK"]),
        .executableTarget(name: "QPeriaptConnectionProbe", dependencies: ["QPeriaptSDK"],
                          path: "Examples/ConnectionProbe"),
        .testTarget(name: "QPeriaptConnectionProbeTests", dependencies: ["QPeriaptConnectionProbe"]),
        .executableTarget(name: "QPeriaptPathProbe", dependencies: ["QPeriaptHybrid", "QPeriaptSDK"],
                          path: "Examples/PathProbe"),
    ]
)
