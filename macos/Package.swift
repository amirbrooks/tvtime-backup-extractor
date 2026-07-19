// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "TVTimeRecovery",
  platforms: [
    .macOS(.v14)
  ],
  products: [
    .executable(name: "TVTimeRecoveryApp", targets: ["TVTimeRecoveryApp"])
  ],
  dependencies: [
    .package(
      url: "https://github.com/swiftlang/swift-testing.git",
      exact: "6.2.4"
    )
  ],
  targets: [
    .target(name: "TVTimeRecoveryCore"),
    .executableTarget(
      name: "TVTimeRecoveryApp",
      dependencies: ["TVTimeRecoveryCore"]
    ),
    .testTarget(
      name: "TVTimeRecoveryCoreTests",
      dependencies: [
        "TVTimeRecoveryCore",
        .product(name: "Testing", package: "swift-testing"),
      ]
    ),
  ]
)
