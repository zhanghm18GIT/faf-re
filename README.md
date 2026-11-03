# Experimental, staged x64 RE build

This configuration-only branch is separate from product source. It is not an official release or upstream endorsement. Both manual stages use public upstream commit `302eb87072249a4ac2195d3a30cb5475df30f31a` and exactly the three rendering replacements in `ci/integration-manifest.json`, producing tree `9ea76a3f4509052ca6ac116581d95b0d42e6384f`.

## Two manual stages

1. Stage A (`appveyor.yml`) builds the 18 explicitly named dependency/support libraries at parallelism 2. It validates a narrowly allowlisted checkpoint, simulates newer source timestamps, freshly configures the same stable paths, restores verified bytes/timestamps and requires Ninja to report no dependency work. Only after owned-work cleanup can the exact checkpoint ZIP be uploaded.
2. Stage B uses the reviewed `appveyor-stage-b.yml` bytes copied over `appveyor.yml` in its normal fast-forward activation commit. It requires A's exact successful build/job, configuration commit, artifact filename, byte count and SHA-256. No `latest` lookup, token, native cache or cold-build fallback is used. B reconstructs source/tools, compares inputs and expanded command identities, restores only approved intermediate state, and refuses any dependency rebuild. B then freshly builds the client and tests, checks actual links/runtime files, runs all acceptance tests and packages the result.

Normal Git checkout precedes the install wrapper. The runtime contracts are disabled unless explicitly enabled for the respective reviewed manual stage. The operator must bind a fixed configuration commit using a sole-publisher branch freeze, a fresh remote ref check immediately before the manual build, and actual provider/checkout SHA verification. The project temporarily selects that branch; no unsupported SHA-selector UI is assumed. Use one standard Free Visual Studio 2022 job, a provider 60-minute limit, and disabled push/PR/scheduled triggers. Project environment overrides, notifications and Global YAML must be inspected separately. No retry, deployment, automatic cache or fallback artifact is configured.

## Identities and invalidation

The product identity is the complete immutable composite tree. The dependency recipe identity excludes unrelated product files and selects the stable owned path. This first A/B pair nevertheless requires the same complete product. Cross-product reuse is disabled. A future source update needs a fresh source/dependency-closure review and updated recipe pins, not a moving branch lookup or automatic reuse.

Complete selected compiler/header/tool/CMake-resource inventories are separate from Ninja's dependency records, which omit some system headers. Inherited compiler/configuration injection variables are removed; default Clang configuration loading is disabled. Explicit compiler include/sysroot channels and expanded response arguments are checked. External files are never retimestamped. Owned source timestamps are restored only after byte equality. Missing objects, changed headers, commands, glob membership, tools, external timestamps or checkpoint identity stop B.

Both stages set `CMAKE_SUPPRESS_REGENERATION=ON` on fresh immutable source; the driver explicitly verifies the generated glob script and source/config membership before and after build/reuse. It never edits generated Ninja rules. This avoids hiding dirty dependency edges behind automatic manifest regeneration.

## Acceptance and limits

B must build `faf_main`, `faf_sim_math_tests`, `faf_math_dump`, `faf_coroutine_tests` and `faf_effect_scan_tests`. Both mathematical POST_BUILD golden checks and all four exact CTests (`sim_math`, `math_dump`, `lua_coroutine`, `effect_scan`) must pass. The standalone effect scanner is not an engine/UCRT parity test. Engine links require the pinned 22000 static UCRT and default-library exclusions; the selected modern SDK headers and all final PE/import checks remain mandatory. No server tests, GUI behavior, original-game, replay or network parity are implied.

Each driver has a cooperative 3,300-second budget, excluding checkout/bootstrap. A build gets at most 2,100 seconds and only remaining time minus its downstream reserve (A 900 seconds; B 1,050). A shared acceptance deadline preserves 390 seconds for upload/cleanup. Individual test caps are upper bounds, not predicted durations. Filesystem operations, sockets and cleanup are cooperative, so the independent provider cap remains necessary. Stage sizes and Windows completion times are unmeasured; these reservations are not a promise of success.

The checkpoint has a 400,000,000-byte outer ZIP limit, 536,870,912-byte member limit and 3,221,225,472-byte total expanded limit. It contains only selected public-source objects/static archives, minimal validated Ninja state, generated headers and required source/notices. It never contains raw SDK/UCRT libraries, tool binaries, EXEs, PDBs, game assets, private logs or credentials. If it does not fit, the job stops rather than omitting material.

Build output is streamed to bounded local capture with progress, phase timing, parent-process resource samples and a failure tail. Parent-only samples do not measure compiler peak RAM/CPU. Raw build logs are not checkpoint artifacts. Uncertain child termination suppresses checkpoint/package publication and leaves ephemeral cleanup to the provider. A successful upload is not delivery: the exact job artifact must still be downloaded, hashed and attached separately.

## Local checks and maintenance

`python -B -m unittest discover -s ci/tests -v` runs pure/synthetic protocol tests without building RE or contacting CI. They do not establish Windows execution, actual checkpoint size, cross-worker reuse or completion time. Keep source pins, helper tests, this documentation and the exact publication manifest together. New recipes must retain all final tests, public-material requirements and fail-closed gates.

After each manual stage, restore the operator's normal project defaults, disable repository YAML execution and verify there are no queued/running jobs. No master/upstream source change is needed. Inspect `ci/README-PACKAGE.md`, `ci/TESTING.md` and `ci/REBUILD.md` for final package use, rollback, notices and reconstruction.
