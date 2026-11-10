// swift-tools-version:6.0
// SPDX-License-Identifier: Apache-2.0 OR MIT
import PackageDescription
let package = Package(
    name: "ContinuityBinaryConsumer",
    platforms: [.macOS(.v13), .iOS(.v16)],
    dependencies: [.package(path: "../QPeriaptContinuity")],
    targets: [.executableTarget(name: "ContinuityBinaryConsumer", dependencies: [
        .product(name: "QPeriaptContinuity", package: "QPeriaptContinuity")
    ], path: "Sources")]
)
