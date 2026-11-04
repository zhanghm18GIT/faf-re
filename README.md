CURRENT INERT CANDIDATE: balanced native resume via appveyor-resume-a.yml / appveyor-resume-b.yml. Read ci/README-RESUME.md. Older single-job and staged sections below are historical reference, not the current activation instructions. No configuration is activated.

# Experimental single-job x64 RE build

The current entry is `appveyor-single.yml`, which calls `ci/run-single-build.ps1` with `ci/execution-single.json`. That contract is inert until separately reviewed and activated for one manual free build. Keep push, PR and scheduled triggers disabled.

The single job uses the fixed product source described below, configures once, builds all five targets once, and requires both POST_BUILD math golden checks plus all four CTests. It exports only the final client package with required DLLs, corresponding source and notices. There is no intermediate checkpoint, cache transfer, restore rehearsal, or checkpoint precompile-test phase. See `ci/README-SINGLE.md` for the exact scope, deadline and failure behavior. Full completion within the provider limit is not established.

The following A/B documentation is historical reference only. Both A/B contracts remain disabled and none of their cache or checkpoint acceptance claims describe the current single-job path.

# Historical A/B configuration (disabled)

This configuration branch builds public upstream `6c93e3625d96d5041b3336e88e3692b88c1ec0c2` with the three rendering replacements in `ci/integration-manifest.json`, producing product tree `b7fff12cad8bc52b34be4107c9791298592bb291`. It is not an official release. The historical branch name contains `302eb`; that is not the product source identity.

## Two manual stages

Stage A reconstructs fixed public source and official tools, validates source/header/tool inventories and exact generated commands, and runs synthetic admission tests before dependency compilation. It retains the small object pilot and complete wx archive pilot within the existing dependency deadline. All 18 dependency targets use parallelism 2. The checkpoint is validated, restored into a freshly configured owned build directory, and must leave Ninja with no dependency work.

After complete owned-work cleanup, A prepares one bounded, recipe-specific `checkpoint.zip` for AppVeyor's native project build cache. It does not publish an intermediate artifact. Saving begins only after an independent readiness gate. A prepared receipt is not proof that the provider saved the cache: verify the final job and cache-save result before preparing B.

Stage B uses the same project, branch, image, platform and configuration, not a matrix job. It requires the exact successful A producer, configuration commit, size and SHA-256 in its contract. Native restored bytes are verified before semantic admission. Missing or mismatched cache stops; there is no cold-build or artifact fallback. B restores only verified intermediate state, requires a clean dependency plan, builds all five targets and runs all four CTests plus the existing math gates. Only the final accepted client package is published as an artifact.

Both contracts begin disabled. Activate only the separately reviewed manual stage. Use a normal fast-forward configuration commit, check its remote head immediately before execution, and verify the provider/checkout identity. Keep push, PR and scheduled triggers disabled. Use the existing Free Visual Studio 2022 worker; no paid upgrade or new account is required. After the run, restore normal project defaults.

## Admission and cache boundaries

The workflow uses fixed reviewed public source, official tools and a fresh owned workspace. No user game files, logs or private data are build inputs. It does not claim operating-system read isolation against arbitrary malicious sources. No system ACL or network-setting changes are part of this design.

Objects are checked as COFF/BigObj. Semantic debug/path fields, linker directives, symbol/string tables and archive text are validated; instructions, ordinary constants and typed numeric fields are not interpreted as paths. Libraries must match independently admitted object names, hashes and multiplicity. Unsupported structures fail. CodeView support is finite, not a guarantee that every future compiler object is supported.

The checkpoint retains the existing reviewed public corresponding-source/notices, generated headers and exact Ninja state. It excludes SDK/tool installations, generic logs, credentials and arbitrary workspace files. See `ci/README-CHECKPOINT.md` for the protocol. Cache access guarantees and account quota headroom are unknown, so do not rely on confidentiality. The 400 MB checkpoint cap remains; quota/save/restore failures stop without upgrading or retrying automatically.

Source/header bytes, tool identities, command identities and glob membership must match. Source timestamps change only after content equality; external files are never retimestamped. Cross-product reuse is disabled. Source updates require new fixed pins and review.

## Validation and delivery

Run `python -B -m unittest discover -s ci/tests -v` for local synthetic protocol tests. These do not establish native Windows cache behavior, full compiler dialect coverage or timing. Cache restoration occurs before the Python driver's timer; the provider's overall hour remains a separate runtime limit.

No client success is claimed until B completes its required targets and tests. Artifact upload acceptance is not delivery: retrieve the exact final artifact, verify its hash and deliver it separately. Raw build logs are not cache payloads. Uncertain child termination blocks promotion.

The Windows export retains the exact reviewed material policy, including omission of the Linux-only PGO artifacts listed there; it is not a complete Linux PGO source bundle. Product presets and compilation rules are unchanged. See `ci/README-PACKAGE.md`, `ci/TESTING.md` and `ci/REBUILD.md` for final package use and reconstruction.

Compiler command admission checks four complete CMake-generated command profiles before configure, including the fixed FFmpeg option list. The FFmpeg option-source file is hash-checked after configure acquires it and before graph admission. Native Windows command-line roundtrips run on the worker; Linux fixture generation is not evidence of the lost worker command. Rejections report argument position, category and hashes without raw argument values.

Windows timestamp restore uses checked no-reparse file handles with exact FILETIME readback, avoiding the unsupported Python 3.12 nofollow utime option. Saved timestamps are never rounded. Only newly generated rehearsal timestamps are chosen on the Windows 100ns grid. Portable guard tests and native Windows probes run before tool downloads; unknown or unequal results still stop the job.

CodeView admission uses a reviewed LLVM 22.1.7 catalog partition rather than a list of records observed in a few fixtures. Modern nonpath records receive bounded framing checks; path-bearing records retain semantic checks. Legacy/OEM, external-PDB/PCH, free-string-vector and unknown formats remain rejected. This is not complete inner-field semantic validation or malicious-source isolation. Standalone object prepasses now report the exact approved member and numeric record kind/location on rejection.
