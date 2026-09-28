// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "LanternIdentity",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "LanternIdentity", targets: ["LanternIdentity"])],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.7.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.9.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.3.0"),
    ],
    targets: [
        .target(name: "LanternIdentity", dependencies: [.product(name: "X509", package: "swift-certificates")]),
    ]
)
