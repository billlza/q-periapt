// swift-tools-version:5.9
import PackageDescription

// Build the static lib first: `cargo build -p pqt-ffi --release`
// (produces ../../target/release/libpqt_ffi.a). See README.md.
let package = Package(
    name: "PQTHybrid",
    products: [
        .library(name: "PQTHybrid", targets: ["PQTHybrid"])
    ],
    targets: [
        // C module exposing the cbindgen-generated header.
        .systemLibrary(name: "CPQT", path: "Sources/CPQT"),
        .target(
            name: "PQTHybrid",
            dependencies: ["CPQT"],
            linkerSettings: [
                .unsafeFlags(["-L../../target/release", "-lpqt_ffi"])
            ]
        ),
        .testTarget(name: "PQTHybridTests", dependencies: ["PQTHybrid"]),
    ]
)
