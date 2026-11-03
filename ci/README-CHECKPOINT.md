# Fixed-public-source dependency cache

This is an intermediate dependency checkpoint, not a runnable client or proof of client test completion. Both execution contracts remain inactive until separately reviewed and authorized.

## Contents and provenance

The checkpoint contains only the admitted dependency objects/libraries, exactly validated `.ninja_log` and `.ninja_deps`, generated public headers, and the previously reviewed public source/notice materials. SDKs, compiler installations, generic logs, credentials, user game files and arbitrary workspace content are not included. Public source/material hashes and fixed product/tool identities remain mandatory. No paid service, user computer, system ACL or network-setting change is required by this design.

This is a fixed reviewed public-source and official-tool workflow in a new owned workspace. It does not claim to isolate arbitrary malicious source or compiler file reads. No user private data is supplied to the build. Expanded compiler commands use a closed option grammar and exact translation-unit/output binding; unknown options stop before dependency compilation.

## Structured object admission

Object and archive bytes are checked as COFF/BigObj and regular COFF archives. Machine instructions, ordinary constant data and typed archive index numbers are not interpreted as path strings. Parsed debug path carriers (including filenames, string IDs and build commands), linker directives, symbol/string tables and archive text retain bounded structure and path checks. Checksum and other typed numeric debug fields are not scanned as text. Supported CodeView kinds are finite; unknown kinds fail. This is not complete semantic decoding of every nested CodeView type.

Every library's names, count and object hashes must match the independently admitted standalone graph objects. Only Windows slash spelling is normalized; basename or case-insensitive fallback is not allowed. Synthetic canary negatives test the guard chain; these tests do not prove operating-system read isolation. The former wx-only literal exception is not active in this mode.

## Native cache transport

A and B use the same single-job AppVeyor project, branch, image, platform and configuration. Only the exact recipe-specific `checkpoint.zip` is configured for native caching. This is not a published artifact. Cache confidentiality/access guarantees, account quota headroom and A/B cache-key behavior have not yet been verified. Treat its contents as approved public build material rather than relying on privacy. Free account quota is not increased; any quota/save/restore failure stops with no fallback upload or new build.

A skips cache restoration and starts with cache saving disabled. After sealing, complete restore rehearsal and owned-work cleanup, the driver commits the bounded checkpoint file. A separate readiness check verifies current producer identity and bytes. Only then does the wrapper enable successful native cache finalization. `READY_FOR_NATIVE_CACHE_NOT_CONFIRMED_SAVED` means prepared, not saved: the coordinator must verify provider terminal success and cache-save result before enabling B.

B never saves cache. Its contract separately pins A's producer, size and SHA-256. Restored bytes must match before parsing; the recipe, source/tool identity, exact members, object/library relationships, generated headers and Ninja state are then verified. A cache miss or mismatch stops. Source timestamps are restored only after content equality; the dependency dry run must show no rebuild. B then builds all five required targets, retains both math gates and runs all four CTests before preparing the final client package.

The final executable package remains an explicit public artifact under the existing material and test requirements. No automatic B start, retry, broader cache or fallback publication is configured.

## Validation status

Local unit/negative tests and official LLVM local fixtures are not native-Windows full-build acceptance. Native cache save/restore, real worker archive spelling, the full dependency command/debug dialect, timing and capacity must still be established on the approved Windows worker. The worker executes the synthetic admission tests before dependency compilation. A change to any unrecognized mode, metadata dialect or command requires review, not automatic relaxation.

Official references:
- https://www.appveyor.com/docs/build-cache/
- https://www.appveyor.com/docs/environment-variables/
