// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "NeoClashSwiftCore",
    platforms: [
        .macOS(.v26)
    ],
    products: [
        .library(name: "NeoClashSwiftCoreLib", targets: ["NeoClashSwiftCoreLib"]),
        .executable(name: "NeoClashSwiftCore", targets: ["NeoClashSwiftCore"])
    ],
    dependencies: [
        .package(url: "https://github.com/jpsim/Yams.git", from: "6.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.83.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.25.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "NeoClashSwiftCoreLib",
            dependencies: [
                .product(name: "Yams", package: "Yams"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOWebSocket", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "Sources/NeoClashSwiftCoreLib"
        ),
        .executableTarget(
            name: "NeoClashSwiftCore",
            dependencies: ["NeoClashSwiftCoreLib"],
            path: "Sources/NeoClashSwiftCore"
        ),
        .testTarget(
            name: "NeoClashSwiftCoreTests",
            dependencies: [
                "NeoClashSwiftCoreLib",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl")
            ],
            path: "Tests/NeoClashSwiftCoreTests"
        )
    ]
)
