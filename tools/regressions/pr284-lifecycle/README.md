# PR #284: fresh source-bound CPU lifecycle regression

PR: https://github.com/Draiget/faf-re/pull/284

Head: `41840bd3236ad7dcf8bda9ccd9fc6059d3692cc4`
Current PR base at verification: `9ed4a96d517fed91c90e48accea1febfea673ce8`

## Run

Run `bash run.sh` on a host with Python 3 and g++ with C++20 support. Or compile the included `generated.cpp` directly with the compiler command from run.sh; Python only regenerates the exact-source extraction.

Recorded run: Debian g++ 14.2.0; ASan + UBSan, UBSan halt_on_error, LSan disabled (`detect_leaks=0`). 29 cases pass. No full client build, Windows execution, GPU, WARP, replay, screenshots or smoke/shadow reproduction is performed.

## Source binding

`generate.py` checks the Git blob IDs of all three supplied source files, checks the relevant order of operations in both revisions, and generates `generated.cpp` from `harness.cpp.in`.

Exact extracted production code:

- UploadAllocator::Allocate / Retire / TakeAllocatedBytes / BusyBytes
- DescriptorArena::Allocate
- DeviceD3D12::CarryBoundPass / AllocateTable
- Constant snapshot block from BindPass (identical before/after)
- AllocateUpload, except its process-static upload accounting and environment-selected threshold become per-fixture members for isolated tests.

The core source blob `ef24a2a81ef90c2e6249bd7da004b77364fa15bf` is identical in current base and PR head. Base Device blob `b3ba08d1997ddd37a40daed7577af38ec499f5c5`, head `16eec18197654c826714c822ae2d94af960bc590`.

## Concrete counterexample

1. The descriptor arena is full (262144 entries; a real BindPass table uses 64). Fixtures establish this reachable precondition without repeating thousands of texture-binding changes.
2. In base ordering the new pass snapshots constants before AllocateTable.
3. AllocateTable submits and waits, then resets the arena.
4. Submit carries only installed mPass, before completed uploads are retired. The local new BoundPass has not been installed yet.
5. A subsequent page-sized upload reuses the completed page and overwrites the new pass's bytes.

With no previous pass this corrupts both ordinary and end-of-page cases. With a previous pass, carrying it on the **same page** protects the local snapshot incidentally: this is a negative control, not a corruption claim. At the page boundary, CarryBoundPass moves to a new page, the old page is retired, and subsequent allocation overwrites the local snapshot. In all base cases the new snapshot serial remains 1 while recording serial is 2; in all four head cases bytes survive and both serials are 2.

The fixture uses the production 8 MiB page size, 128 MiB x64 idle reserve, 64-slot table size and 262144-slot arena capacity. Host page memory replaces committed/mapped D3D12 resources; fake descriptors use numeric handles.

## Coverage

- Base/head × previous pass absent/present × ordinary/page-end boundary: 8 cases.
- Constant cache hits, version invalidation and serial invalidation in base/head: 6.
- Descriptor exact fit, oversized request rejection, empty constants: 3.
- Table cache invalidation by frame, epoch, texture version and output surface: 4.
- Upload threshold submission after table allocation, with/without previous pass and descriptor rollover: 4. Assertions require the upload-submission branch and exact total submission count.
- Uncompleted-fence negative control, completed-page reuse, oversized-page release, 256-byte relative alignment: 4.

## Deliberate limits

This is a CPU regression with production allocator code, not the full DeviceD3D12 method compiled against Windows. BindPass cache/orchestration is transcribed; texture copying/state/shaders are omitted. Submit models fence completion and preserves carry-before-retire order; no real command queue or descriptor access occurs. Immediate asynchronous completion is one legal schedule, not exhaustive scheduling coverage. Draw-preparation suppression, delayed-fence combinations, cross-device static accounting and x86 configuration are not covered. Renderer symptoms and compatibility require separate Windows build/run and visual validation.

These CPU results do not replace the Windows client build/run and rendering checks.
