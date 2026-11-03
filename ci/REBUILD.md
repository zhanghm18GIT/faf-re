# Corresponding source and relinking

The corresponding-source/engine directory contains the explicit reviewed public engine source/build files plus the exact pinned dependency sources as configured, including the recorded dependency patches. This is a source-based relinking mechanism for the statically linked FFmpeg libraries, not a bare attribution or an offer to provide sources later. The same source tree permits rebuilding the application with modified FFmpeg. Review the applicable component notices; no new root-level license is asserted here.

Inputs and versions:
- Original upstream base: 302eb87072249a4ac2195d3a30cb5475df30f31a; three exact replacements and their hashes in SOURCE_MANIFEST.json.
- LLVM 22.1.7 clang-cl/lld-link; Visual Studio 2022 MSVC 19.44; Windows SDK headers version and approved x64 static UCRT version/path/hash recorded in BUILD_MANIFEST.json. Do not substitute 26100 static UCRT math.
- CMake 3.31.6 and Ninja; fresh x64 Release build, parallelism at most 2.
- FFmpeg pinned commit 8f9ea179334d8ff01292728b9704b7da1f712c5f contains the upstream 7.1.3 source and faf/CMakeLists.txt. All five FFmpeg libraries are built statically with the repository's restricted LGPL component configuration. No GPL/nonfree component is requested by this build recipe.

Obtain the official Microsoft June 2010 DirectX SDK headers/libraries separately using the frozen cmake/FafDependencies.cmake extraction mechanism and its SHA-256 pin. Do not execute the installer or copy a retail installation into the source tree. They are excluded from this package. Obtain the matching pinned DXC archive from SOURCE_MANIFEST.json separately and extract it into corresponding-source/engine/dependencies/dxc, preserving its inc, lib and bin/x64 directories for the compile and POST_BUILD copy paths; the public package contains its required runtime DLLs and notices, not SDK developer files.

For a local rebuild, use the supplied CMake files rather than build.ps1's default copy-to-installed-game behavior. Place the separately extracted SDK in a path of your choosing. Run CMake with preset clang-x64-release, an empty external build directory, and explicit toolchain locations. Set:
- FAF_FETCH_DEPENDENCIES=OFF, because the provided dependency source trees are already pinned and patched; do not let CMake treat source-bundle folders as Git submodules.
- FAF_DXSDK_DIR to the separately extracted verified headers/libraries; FAF_UCRT_LIB_VERSION to the recorded approved version after verifying its x64 library hash.
- FAF_LLVM_ROOT, FAF_MSVC_TOOLS_DIR, FAF_WINSDK_DIR and FAF_WINSDK_VERSION to the verified input paths.
- FAF_SYNTAX_ONLY=OFF, FAF_RETAIL_LAYOUT=OFF, FAF_ENABLE_TRACY=OFF, FAF_SERVER_MODE=OFF, FAF_CALL_HASH_BUILD=OFF, CMAKE_BUILD_TYPE=Release.
- FAF_OUTPUT_NAME to a new independently named executable, not an installed game executable.

Build targets faf_main, faf_sim_math_tests, faf_math_dump, faf_coroutine_tests and faf_effect_scan_tests. Both math targets' POST_BUILD golden checks must run. Execute ctest --test-dir <build> -R "^(sim_math|math_dump)$" --output-on-failure --no-tests=error and require exactly two passing, non-skipped tests. Also execute ctest --test-dir <build> -R "^lua_coroutine$" --output-on-failure --no-tests=error and require exactly one passing, non-skipped coroutine test. Never regenerate goldens or add a known-x64-differences file to make a result pass. This is x64 only.

Preserve your modifications and describe their identity truthfully. A source-only archive lacks Git metadata, so a rebuilt executable's generated Git identity may be unknown. Do not reuse the original artifact's hash or claim your changed build is the same tested binary. Verify final link commands explicitly include the approved absolute libucrt.lib and /NODEFAULTLIB:libucrt.lib. PE imports and actual runtime prerequisites must be checked again after relinking.

## Exact approved static UCRT input

The original build uses Microsoft.Windows.SDK.CPP.x64 10.0.22000.194 from https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp.x64/10.0.22000.194/microsoft.windows.sdk.cpp.x64.10.0.22000.194.nupkg . Its Windows SDK license is https://aka.ms/WinSDKLicenseURL . Obtain and accept applicable terms yourself when rebuilding; no SDK files are redistributed here.

Package: 51,316,315 bytes; SHA-256 039c4f5e2ad62494fa7fa6cafa2b6895fb3e2601491633c47256fbdca2e56f42; official SHA-512 nXLjeIJjVayo+mDJpD5ijiXwm6b7dOp3KBZqdAGd5Bu7684qT9uW9vQAmpDbrbyDLN46RBs1VeTDTRTeVepYrQ==.

Extract only c/ucrt/x64/libucrt.lib after verifying the archive: 39,778,014 bytes, SHA-256 56378d8598e3134d5c7e844079e07c1a56ad7c138f74d5f398f7452e5abc6550. The entry is a static COFF library, not ucrt.lib's import library. The expected ordinary member count is 736, all AMD64. Do not run the package props/nuspec or install the old SDK.

If the approved static UCRT is not installed, use a temporary SDK overlay rather than changing Program Files or CMake source: its Include directory points to the existing modern SDK Include; its Lib/<modern version> points to the existing modern SDK library directory; its Lib/10.0.22000.0/ucrt/x64/libucrt.lib is the exact regular extracted file. Set FAF_WINSDK_DIR to that overlay and FAF_UCRT_LIB_VERSION=10.0.22000.0 while keeping FAF_WINSDK_VERSION at the recorded modern headers/UM version. Use junctions only as read-only inputs and remove the junction entries, not their SDK targets, during cleanup. Verify actual final links and run all four tests again. These build inputs are absent from the distributable by design.

The current recipe also builds faf_effect_scan_tests and runs the exact CTest effect_scan with no arguments. This standalone header/standard-library generated-text check does not link faf_engine and is not a GUI or engine UCRT test. The complete client acceptance set is five build targets and four CTests. Server-mode remote_wire is not included.
