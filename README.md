# One fresh AppVeyor Windows candidate: local inert draft

**Not published, configured, dispatched or natively built. Parent final GO is required.**

The previous GitHub driver is adapted into a separate directory. The old source preparation, old GitHub settings/queue and all old AppVeyor artifacts remain untouched. This task does not request any old artifact, restore cached objects, modify user installations, or buy resources.

## Source identity

Official upstream: Draiget/faf-re. Base commit: `a9225d2d2bcc17fca2075d7c534bee18f6c93273` (master rechecked 2026-11-05 08:28 UTC). Candidate tree: `ff340b16db5af1cbb76df051a9a7439c1dd08160`. Integrated once each: open, unmerged #282/#283/#284/#291/#299/#301/#303. No immature texture/cache prototype is included. The #299+#301 combination retains the reviewed adaptation. The only new compatibility edit restores Shadow::RenderShadowMap's terrain parameter name, required because current upstream had commented it out. #303 is merged without dropping upstream replay_scan.

The exact source input, patch, dependency and materials hashes are recorded in ci/DRIVER_FILES.json. The source author's independent receipt is under source_latest_0819/REPORT.md; 2,924 candidate blobs, all 34,775 dependency entries, reconstruction and tamper rejection, ten host test groups, and real BuildInfo generation were checked. These checks are not Windows-native or game acceptance.

The eventual candidate is an integrated test build. Comparing it with retail does not isolate the causal effect of PR #282. In-game evidence must label the exact build, backend, replay/time/camera and selected emitter, and show the actual game. Compilation/unit test success is not a screenshot or game/replay PASS.

## Single-job control

- Existing account/project only: zhanghm18GIT/faf-re, Free / Active, Visual Studio 2022, max_jobs=1, platform timeout=60 minutes.
- Manual forced build only, exact branch and next build number captured immediately before activation, no PR/tag/schedule/rebuild/re-run-incomplete.
- Verified driver checkout SHA must equal APPVEYOR_REPO_COMMIT; all runtime/test file bytes and their exact set are manifest-checked. No extra runtime file may enter through a broad checkout.
- There is no automatic dispatch/retry, no payment path, no new account/token/OAuth, no cache/restore, and no GitHub Actions activation.
- The driver expires work at minute 50 from the init timestamp; an independent supervisor begins forced termination at minute 51.5, leaving 30 seconds to stop the worker tree by minute 52; diagnostic finalization and upload attempts must stop by minute 55, leaving five minutes before the platform's hard 60-minute limit.
- One compile uses two workers. Extra CPU or matrix jobs are not purchased or silently selected.
- Small minimal diagnostics are atomically finalized before fuller diagnostics. Timeout cannot make a partial product eligible. A product upload requires process success, final readiness, all gates PASS, and matching final bytes/hash. Upload attempts are not retried. Delivery remains unverified until the new artifact can be retrieved and checked.
- The build-number guard prevents a later manual build from using the same authorization; provider rerun flags block rebuilding the same number. It is not a durable independent lock or authority to dispatch twice. The operator must inspect current history, dispatch once, and not reset the build number or delete history.

## Native and packaging gates

Use fixed official portable CMake 3.31.6, Ninja 1.13.2 and LLVM 22.1.7. The new CMake/Ninja ZIP size/hash pins are frozen from official release/checksum data. System PATH tool versions are not trusted. No tool installer is run; the legacy DirectX redistributable is used only for its authorized extraction mode, never to install system files.

Installed MSVC14.44/VS17.14, SDK26100 headers, legacy x64 D3DX/X3DAudio runtime availability and loadability remain preconditions. The precise Microsoft22000 static UCRT is acquired from its pinned official NuGet package into an isolated overlay; the system SDK is unchanged. DirectX June2010 is privately downloaded/extracted from Microsoft with its fixed hash. SDK files are excluded from output.

Source blob hashes, candidate tree, patch, submodule HEADs, dependency source bytes, resource set, original flags and complete math inputs remain gated. Nine native targets are mandatory, including new replay_scan and texture_quality tests. All six selected CTests and explicit image_codec run are mandatory; no earlier target/test is removed. Actual old-UCRT linking is checked for engine consumers, including replay_scan. Only standalone effect_scan and texture_quality are excluded from engine-link attribution; their native architecture/import checks still apply. Native guards reject wrong architecture/dynamic CRT, image_codec SKIP, failed/skipped JUnit cases, untruthful BuildInfo and missing headless imports gate.

Output contains only explicitly staged candidate binaries, the matching main PDB, pinned DXC runtimes, exact resources, required corresponding source/notices, immutable evidence and a read-only installation checker. Product ZIP max400MiB; diagnostics max32MiB. No game assets, SDK, system DLLs, credentials, home directory or raw environment dump. Size limits must not be met by discarding mandatory symbols/source/licenses.

## Activation and recovery checklist

1. Preserve the frozen latest source identity and finish independent review on the final complete bytes. Preserve exact base, PR heads, adaptations, source tree and candidate file inventories.
2. Parent reviews the final report, SDK/license boundaries, public driver/diagnostic/product scope and confirms GO. Keep the actual user evidence in a private operator receipt; only its SHA256 goes into the public driver authorization.
3. Refresh Free/Active/public-repository state and next build number, check no other job is active or queued for this plan, and capture current full settings. Do not assume the 08:04 reference is fresh enough. No documented numeric storage/minute remainder is available; disclose that uncertainty. Do not upgrade or alter billing.
4. Publish only the exact reviewed driver payload to the authorized dedicated branch while automatic AppVeyor triggers remain off. Leave GitHub Actions disabled. Do not overwrite master or reuse an old resume branch/script. Verify the remote commit and manifest.
5. Change the existing project's configuration to the reviewed YAML/branch, maxjobs1/timeout60; keep push/PR/tags/schedule off, inherited notifications/cache/deploy disabled. UI environment/notification settings may merge with YAML, so reread them. Remove only the deliberate draft throw after final review and regenerate final manifest; never flip authorization without corresponding evidence.
6. Record the exact intended next build number and current preflight UTC (<1h). Dispatch once. Observe the actual new build ID/job ID/commit; if dispatch outcome is uncertain, inspect before doing anything else and never blindly dispatch again.
7. Monitor until terminal. On missing tools, denied read, hash mismatch, timeout or test failure, stop, retain bounded diagnostics and report exact failed/not-run gates. Do not read old R, relay through mirrors, change identities, raise limits or try a second build.
8. Restore the original inert project settings whether build succeeds or fails: default master, Ignore YAML On, init/install/finalizers off, build/test/deploy off, no automatic artifacts/cache, push/PR/tags/schedules disabled as before. Preserve natural advancement of the build number; never reset it to28. Verify after reload. The worker intentionally has no credentials to change settings, so restoration is a parent/operator obligation, not a claimed in-job action.
9. Retrieve only this new run's final artifacts. Verify hashes/contents and native evidence before saying delivered. Any new403 also stops that retrieval; no alternate identity or mirror. Save successful authorized outputs promptly because Free AppVeyor artifacts expire after one month.
10. Use a new side-by-side game candidate directory, retain the original retail executable/path and rollback instructions. No automatic replacement of the user's game or system setup. Rendering/replay comparison remains a separate authorized runtime task.

## Feasibility limits

A complete 60-minute clean build has not been measured. An older cold job reached its2700-second compile cap with full completion unknown and no standalone tests/package; a separate42:27 log restored prebuilt objects and cannot establish clean-build time. The current input is newer and mandatory tests may grow. Large fixed LLVM/DirectX downloads, extraction/hash checks, compilation, full math tests and packaging may exceed the work budget. This is one bounded attempt, not a promise of a runnable result. Do not reduce tests or correctness to make it fit.

Run local checks without bytecode: `python -B -m unittest discover -s ci/tests -v` and `python -B ci/verify_draft.py`. They do not establish Windows-native execution or game acceptance.
