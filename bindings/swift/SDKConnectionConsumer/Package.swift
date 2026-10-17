// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "QPeriaptConnectionConsumer",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "QPeriaptConnectionProbe", targets: ["QPeriaptConnectionProbe"])],
    dependencies: [.package(path: "../QPeriapt")],
    targets: [
        .executableTarget(name: "QPeriaptConnectionProbe", dependencies: [
            .product(name: "QPeriaptSDK", package: "QPeriapt")])
    ]
)
