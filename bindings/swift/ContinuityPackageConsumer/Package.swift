// swift-tools-version:6.0
// SPDX-License-Identifier: Apache-2.0 OR MIT
import PackageDescription

let package = Package(
    name: "QPeriaptContinuity",
    platforms: [.macOS(.v13)],
    products: [.library(name: "QPeriaptContinuity", targets: ["QPeriaptContinuity"])],
    targets: [
        .systemLibrary(name: "CQPCOwner"),
        .target(name: "QPeriaptContinuity", dependencies: ["CQPCOwner"],
                linkerSettings: [.linkedLibrary("q_periapt_continuity_c_consumer")]),
        .executableTarget(name: "ContinuityClient", dependencies: ["QPeriaptContinuity"]),
        .testTarget(name: "QPeriaptContinuityTests", dependencies: ["QPeriaptContinuity", "CQPCOwner"]),
    ]
)
