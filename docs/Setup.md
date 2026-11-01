# Setup and operating notes

[← Back to the project README](../README.md)

## Requirements

- C++17 compiler, CMake 3.22+.
- Qt 6.5+ with Widgets. Qt Test is required for the automated GUI tests.
- libsodium 1.0.18+.

Verified using AppleClang 21.0.0, Qt 6.10.0, CMake 4.4.4, and libsodium 1.0.22. There are no runtime network requests. After dependencies are installed, the program builds and runs offline.

## Windows / VS Code

Install Visual Studio 2022 Build Tools with **Desktop development with C++**, Git, CMake, and VS Code. Install the C/C++ and CMake Tools extensions in VS Code.

Install vcpkg once if you do not already have it:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\tools"
git clone https://github.com/microsoft/vcpkg.git "$env:USERPROFILE\tools\vcpkg"
& "$env:USERPROFILE\tools\vcpkg\bootstrap-vcpkg.bat"
```

Install dependencies:

```powershell
$env:VCPKG_ROOT = "$env:USERPROFILE\tools\vcpkg"
& "$env:VCPKG_ROOT\vcpkg.exe" install libsodium:x64-windows qtbase:x64-windows
```

Open the **AccessLab** folder in VS Code. From its integrated PowerShell terminal:

```powershell
$env:VCPKG_ROOT = "$env:USERPROFILE\tools\vcpkg"
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
.\build\Release\accesslab.exe
```

An installed official Qt MSVC 2022 kit can also be used: install only libsodium with vcpkg, then add your actual Qt kit path through `-DCMAKE_PREFIX_PATH=C:/Qt/6.10.0/msvc2022_64` during configure. Use matching compiler/architecture kits and a new build folder when switching toolchains.

The included VS Code tasks build/test the project; its Windows launch configuration runs AccessLab. For Debug stepping, build Debug and change the executable folder in launch.json from Release to Debug.

To distribute a Windows executable, run that kit's `windeployqt` on `build/Release/accesslab.exe` and include the libsodium DLL, Qt DLLs, and generated `platforms` directory. Windows execution/deployment was not verified on this host.

## macOS

Install Apple developer command-line tools and Homebrew if necessary. Then install dependencies once:

```sh
brew install cmake pkg-config libsodium qt
```

Build and run from the project folder:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$(brew --prefix qt)"
cmake --build build --parallel
ctest --test-dir build --output-on-failure
open build/accesslab.app
```

For an official Qt kit, set CMAKE_PREFIX_PATH to that kit's `macos` directory instead.

A separate Apple Silicon app package is provided with bundled Qt and libsodium libraries. That supplied executable targets macOS 27+. Build from source with appropriate toolchains and dependency deployment targets for other versions. The local demonstration package is not Apple-notarized.

## Linux (Debian/Ubuntu)

```sh
sudo apt update
sudo apt install build-essential cmake pkg-config libsodium-dev qt6-base-dev qt6-base-dev-tools
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/accesslab
```

Use a distribution/kit providing Qt 6.5+. An official newer Qt kit can be supplied through CMAKE_PREFIX_PATH.

## Storage location and demonstration files

The default is a stable per-user application-data folder selected by Qt, normally:

- Windows: `%LOCALAPPDATA%\SubhamProjects\AccessLab\accounts.json`
- macOS: `~/Library/Application Support/SubhamProjects/AccessLab/accounts.json`
- Linux: `~/.local/share/SubhamProjects/AccessLab/accounts.json`

For an isolated college demonstration, pass a filename:

```powershell
.\build\Release\accesslab.exe "data\exam-accounts.json"
```

```sh
# macOS; Linux uses ./build/accesslab instead
./build/accesslab.app/Contents/MacOS/accesslab "data/exam-accounts.json"
```

The application starts empty. Screenshot records and the example JSON are fictional verification artifacts; they are not automatically loaded into your database.

The empty `.lock` sidecar coordinates a single app instance per database path and remains on disk. The OS releases its lock when the application ends. Do not remove an active lock file.

## Limits and educational scope

This demonstrates the password-verification part of website login inside a native local C++ application. A deployed website would place the authentication service/database on a trusted server and also need HTTPS, secure session cookies, request throttling, account recovery, access control, and other controls. AccessLab does not provide those network features.

- Registration uses 12–1024 password bytes; verification accepts 1–1024. Unicode passwords are processed as UTF-8 bytes. Input is never silently truncated by the hashing code.
- Names are 1–80 bytes; this demo accepts a deliberately limited ASCII email syntax of at most 254 bytes and normalizes email case/outer whitespace.
- At most 500 accounts and a 2 MiB JSON file; duplicate IDs/emails and unsupported hashing profiles are rejected.
- Account names/emails, salts, hashes, and cost settings are intentionally inspectable. The file is **not encrypted**, and its entire contents are not authenticated. An attacker with write access can replace verifiers or identity metadata. POSIX files use private permissions; Windows uses inherited ACLs.
- The records/OOP pages are deliberately available while signed out to teach with fictional data. They are not production administration or authorization features.
- Unknown-email login still performs Argon2id verification against a random dummy record. This reduces a simple no-hashing timing distinction; it is not a comprehensive side-channel guarantee.
- SecretBuffer guards and wipes temporary password buffers. Qt text fields, conversion temporaries, the OS, and earlier memory copies can retain data; cleanup is not a proof that every copy disappears.
- There is no password change/recovery, account deletion, real web deployment, MFA, persisted session token, automatic lockout, or protection from malware. The scope is a reproducible undergraduate OOP demonstration.

