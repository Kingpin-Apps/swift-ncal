![GitHub Workflow Status](https://github.com/Kingpin-Apps/swift-ncal/actions/workflows/swift.yml/badge.svg)

# Swift-NaCL - Swift binding to the libsodium library

Swift-NaCL is a Swift binding to a fork of [libsodium](https://github.com/IntersectMBO/libsodium) library. These libraries have a stated goal of
improving usability, security and speed.

## Usage
To add Swift-NaCL as dependency to your Xcode project, select `File` > `Swift Packages` > `Add Package Dependency`, enter its repository URL: `https://github.com/Kingpin-Apps/swift-ncal.git` and import `SwiftNcal` as well as `Clibsodium`.

Then, to use it in your source code, add:

```swift
import SwiftNcal
```

The Sodium library itself doesn't have to be installed on the system: the repository already includes a precompiled library for armv7, armv7s, arm64, as well as for the iOS simulator, WatchOS and Catalyst.


## Features
- [x] Digital signatures
- [x] Secret-key encryption
- [x] Public-key encryption
- [x] Hashing and message authentication
- [x] Password based key derivation and password hashing
