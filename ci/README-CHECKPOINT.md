# Experimental dependency checkpoint

This archive contains only the exact selected public-source-derived dependency objects/static libraries, necessary generated headers and structured Ninja state, plus corresponding public source and notices. It is not a client package and does not establish a successful RE executable, math/coroutine/effect test, or gameplay result.

The consumer must independently reconstruct the identical reviewed product, use the pinned toolchain and stable layout, verify the exact producer job/file/byte count/SHA-256, validate all source/external input and command identities, restore only explicit owned paths and verified timestamps, and prove no dependency compilation/archive work is pending. Missing or stale state stops the consumer; there is no cold-build fallback. Microsoft SDK/UCRT originals, tool binaries, raw console logs, and commercial game/user files are not included.

The accompanying source/notices and REBUILD.md describe the public build inputs. No root repository LICENSE or blanket license/official upstream endorsement is implied. Redistribution obligations remain those of the individual included components. This experimental state is temporary CI transfer, not durable release storage.

## Explicit source-material selection

SOURCE_MATERIAL_POLICY.json records all 16 exact hash-bound omissions of optional test/sample data, sample bytecode, an IDE placeholder and a historical benchmark spreadsheet. These are not inputs to the selected dependency compilation, x64 relink mechanism or component notices. The original immutable checkout remains intact and actual compile inputs must stay inside the admitted source/generated closure. Four exact OpenVMS text build scripts are retained as source and are never executed. No executable/archive/database signature is allowed by this text classification. Full original public archive/commit identities are included for independent reconstruction; no further material is silently omitted to meet size or time limits.

## Object and archive validation

Only structurally checked AMD64 relocatable COFF/BigObj and regular COFF archives are admitted; PE images, import objects and unrelated binary formats remain rejected. Linker symbol tables require the exact declared number of nonempty terminated names, with only the optional parity-correct internal NUL alignment used by LLVM.

LLVM 22 can escape Windows backslashes in the CodeView compiler command line. The validator recognizes only a structurally parsed `.debug$T` type stream whose five-argument `LF_BUILDINFO` references the expected `LF_STRING_ID` command field. Its quoting/escaping must round-trip exactly to LLVM's canonical form. Decoded paths must satisfy the same approved roots, including normalized traversal checks. Only that validated command string is masked for the subsequent raw path scan; all other object bytes, CodeView fields, archive headers and metadata remain scanned. This also applies to objects inside a library. No general binary unescaping or expanded path-root permission exists.

Failures report fixed structural/path rule codes and bounded numeric offsets or header fields, not raw paths or arbitrary binary contents. The real-worker format pilot remains mandatory before the full dependency build, and a subset PASS never substitutes for the complete checkpoint seal or restore rehearsal.

### Reviewed public literal exception

The wxWindows 2.4.2 Windows PostScript AFM default is a public source constant, not a worker path. The only enabled rule binds the pinned `cmndata.cpp` bytes, its admitted wxmswu Ninja object and CMake library paths, an exact immutable UTF-16 string COMDAT with canonical symbols, and its full NUL boundary. Other bytes and paths remain scanned. This proves exact public-literal admission, not compiler-origin authenticity or runtime testing. The early format pilot includes this wx object as well as the existing Monocypher object/archive and uses the same shared build deadline. Unknown source/layout/symbol variants fail closed.
