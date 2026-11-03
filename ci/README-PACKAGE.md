# Experimental x64 RE test client

This is a public-source experimental build of Draiget/faf-re at base b6205405c9976d8f1b659db919cb537e7d2dba08 which includes the upstream-accepted PR 281 coroutine changes, plus exactly the three candidate file replacements from draft PRs 282, 283 and 284. The complete source tree is 47eb9042c333f520ef7b555dca5d1727edff4c1b. It is not an official release or an upstream endorsement of those draft changes.

The executable is independently named main_x64_test_b620_282-284.exe. Its own BuildInfo correctly reports the upstream base and a dirty tree, because the three replacements are uncommitted. SOURCE_MANIFEST.json binds the exact replacements and dependencies; BUILD_MANIFEST.json contains actual build/test/runtime evidence; FILE_MANIFEST.json and SHA256SUMS identify the supplied files. The exact outer archive SHA-256, size and AppVeyor build/job identity are provided with the artifact receipt.

The package contains matching pinned x64 DXC runtime DLLs, the public fafengine options hook, component notices, and the corresponding public application/dependency sources needed for rebuilding and relinking, including static FFmpeg and its FAF CMake build. It contains no retail game executable, commercial game DLL/PDB, game assets, maps, replays, private pack, user logs, telemetry or dumps. It does not replace a legitimate game installation.

No repository-root LICENSE/COPYING was present in the frozen upstream source. This package makes no blanket license claim. The component notices apply to their respective components. See REBUILD.md for the full-source/relink mechanism. The June 2010 DirectX SDK headers, libraries and installer are not redistributed here.

Passing compilation and public math tests does not demonstrate that the three graphics candidates fix the user's game, execute real shaders correctly, or preserve original-executable/replay/network parity. The earlier WARP environment check was only a synthetic clear/readback exercise. Consult the actual status fields in BUILD_MANIFEST.json; NOT_RUN is not a pass.
