// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AppAttestClient",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(name: "AppAttestClient", targets: ["AppAttestClient"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "AppAttestClient",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux]))
            ],
            path: ".",
            exclude: ["Tests", "README.md"],
            sources: ["AppAttestClient.swift"]
        ),
        .testTarget(
            name: "AppAttestClientTests",
            dependencies: [
                "AppAttestClient",
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux]))
            ],
            path: "Tests"
        )
    ]
)
