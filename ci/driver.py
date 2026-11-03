#!/usr/bin/env python3
"""DRAFT Windows-only one-job RE build driver. Importing this file does nothing.
No build execution without --execute, an approved contract, and matching reviewed hashes.
The separate --check-interpreter mode reports identity and exits without build/download.
The only external write is an exact, explicitly enabled AppVeyor package upload.
"""
from __future__ import annotations
import argparse
import base64
import ctypes
import hashlib
import json
import os
import platform
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
import xml.etree.ElementTree as ET

BASE = "b6205405c9976d8f1b659db919cb537e7d2dba08"
BASE_TREE = "8938cd0a9a5523d191f4087c4591f5b2a889f831"
TREE = "47eb9042c333f520ef7b555dca5d1727edff4c1b"
INTEGRATION_SHA = "d8af1a42626d93c2bb08d8f6b8e6bdc24c50be1273a4c306790c13088e9a49b4"
LLVM_SHA = "3b568b5be1443d1a04c63261fa3a7aed16e126a8ed2196a1032aa8ed602144bd"
LLVM_URL = "https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.7/clang%2Bllvm-22.1.7-x86_64-pc-windows-msvc.tar.xz"
LLVM_SIZE = 862033024
EXE_NAME = "main_x64_test_b620_282-284"
REQUIRED_TARGETS = ["faf_main", "faf_sim_math_tests", "faf_math_dump", "faf_coroutine_tests"]
REQUIRED_TESTS = ["math_dump", "sim_math"]
TEST_REGEX = "^(sim_math|math_dump)$"
LUA_TEST_REGEX = "^lua_coroutine$"
DISABLED_FLAGS = ["FAF_SYNTAX_ONLY", "FAF_RETAIL_LAYOUT", "FAF_ENABLE_TRACY", "FAF_SERVER_MODE", "FAF_CALL_HASH_BUILD"]
SOURCE_COMPONENTS = ["WildMagic3p8", "zlib-1.2.3", "FX11", "vulkan", "ffmpeg", "boost_1_34_1", "wxWindows-2.4.2", "libjuice", "libdatachannel", "usrsctp", "plog", "mbedtls", "monocypher"]
GOLDEN_BLOBS = {
    "tests/sim_math/golden.txt": "700b203604dc033d84e06995fb79ba0b306c8017",
    "tests/sim_math/known_windows-x86.txt": "428b83b940332481bfb478919bdb18c260e6bedc",
    "tests/math_dump/golden.txt": "3da6b40fcc16453424c39fccdc9272286a9ea6a8",
    "tests/math_dump/retail_values.txt": "6fcb66542d31cabf8146ccbe92217622dac32b5b",
    "tests/CMakeLists.txt": "b45f09559443fd408bfe40f5ec17417a1022726d",
    "tests/lua/CoroutineTests.cpp": "0dc3a8b9e98395092d17e19a2bd2b89ec597db48",
    "tools/difffuzz/dump.cmake": "8b4ed92a0e7d969b7461a661743d96cb939d02d7",
    "cmake/FafBuildInfo.cmake": "5bf0a288b9bda00993158e9b34026670807b2926",
}
# Components' public source trees only; never walk source root, worker, or caches.
# Executable/archive media are excluded even if present in upstream sample trees.
SOURCE_DENY_SUFFIXES = {".exe", ".dll", ".pdb", ".obj", ".o", ".a", ".lib", ".so", ".dylib", ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".cab", ".msi", ".dmp", ".scfareplay", ".scmap", ".scd", ".log"}
SOURCE_DENY_DIRS = {".git", ".github", ".svn", ".hg", ".downloads", "__pycache__", "CMakeFiles"}
NOTICE_RE = re.compile(r"^(?:licen[cs]e|copying|copyright|notice)(?:[._-].*)?$", re.I)

class Blocked(RuntimeError):
    pass

def require(condition, message):
    if not condition:
        raise Blocked(message)

def interpreter_identity():
    return {"executable": sys.executable, "version": sys.version.split()[0],
            "os_name": os.name, "pointer_bits": struct.calcsize("P") * 8,
            "machine": platform.machine()}

def validate_interpreter():
    identity = interpreter_identity()
    print("INTERPRETER_IDENTITY " + json.dumps(identity, sort_keys=True), flush=True)
    require(identity["os_name"] == "nt", "Interpreter OS must be Windows (os.name=nt)")
    require(identity["pointer_bits"] == 64, "Interpreter must have 64-bit pointers; no x86 fallback")
    # Machine name is diagnostic; the wrapper checks actual AMD64 PE32+ bytes.
    require(sys.version_info >= (3, 11), "Python >=3.11 required; do not install automatically")
    return identity

def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def blob_sha(path):
    data = Path(path).read_bytes()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def checked_hash(path, expected):
    require(re.fullmatch(r"[a-f0-9]{64}", expected or ""), "Missing SHA-256 contract")
    require(Path(path).is_file(), "Missing required input: " + str(path))
    require(sha(path) == expected, "SHA-256 mismatch: " + str(path))

def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))

def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

def safe_relative(value):
    p = PurePosixPath(value)
    require(value and not p.is_absolute() and ".." not in p.parts and ":" not in value and "\\" not in value,
            "Unsafe relative path: " + value)
    return p

def resolve_contract_receipts(here, contract):
    for field in ["preflight_receipt", "distribution_review"]:
        if field in contract and not Path(contract[field]).is_absolute():
            contract[field] = str(here / safe_relative(contract[field]))


def inspect_coff_archive(path):
    data = Path(path).read_bytes()
    require(data.startswith(b"!<arch>\n"), "Static UCRT is not a COFF archive")
    offset, count, machines = 8, 0, set()
    while offset < len(data):
        header = data[offset:offset + 60]
        require(len(header) == 60 and header[58:60] == b"`\n", "Malformed COFF archive member")
        try:
            length = int(header[48:58].decode("ascii").strip())
            name = header[:16].decode("ascii").strip()
        except (ValueError, UnicodeError) as exc:
            raise Blocked("Malformed COFF archive header") from exc
        start = offset + 60
        end = start + length
        require(length >= 0 and end <= len(data), "COFF member length outside archive")
        payload = data[start:end]
        if name not in {"/", "//", "/SYM64/"}:
            require(len(payload) >= 20, "Truncated COFF object")
            first, second = struct.unpack_from("<HH", payload)
            machine = struct.unpack_from("<H", payload, 6)[0] if (first, second) == (0, 0xffff) else first
            require(machine == 0x8664, "Non-x64 or unknown COFF archive object")
            machines.add(machine)
            count += 1
        offset = end + (length & 1)
    require(offset == len(data) and count > 0 and machines == {0x8664}, "Incomplete x64 COFF archive")
    return {"members": count, "machine": "AMD64", "sha256": sha(path)}


def pe_machine(path):
    with Path(path).open("rb") as f:
        require(f.read(2) == b"MZ", "Not PE: " + str(path))
        f.seek(0x3c)
        off = struct.unpack("<I", f.read(4))[0]
        f.seek(off)
        require(f.read(4) == b"PE\0\0", "Invalid PE header")
        return struct.unpack("<H", f.read(2))[0]

def read_cache(path):
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        m = re.match(r"([^#/:][^:]*):[^=]+=(.*)$", line)
        if m:
            out[m[1]] = m[2]
    return out

def normalize_path(value):
    return str(value).replace("\\", "/").rstrip("/").lower()

def validate_test_discovery(data, source, require_commands=True):
    tests = data.get("tests", [])
    require(sorted(t["name"] for t in tests) == REQUIRED_TESTS, "CTest discovery must be exactly sim_math + math_dump")
    if not require_commands:
        return
    for test in tests:
        args = test.get("command", [])
        require(args and "--generate" not in args and "--known" not in args, "Unexpected test generation or x86 known-difference option")
        joined = " ".join(args).replace("\\", "/")
        expected = "sim_math/golden.txt" if test["name"] == "sim_math" else "math_dump/golden.txt"
        require(expected in joined, "CTest is not using its frozen golden")
        require(normalize_path(source) in normalize_path(joined), "CTest golden path outside frozen source")
        if test["name"] == "math_dump":
            require("math_dump/retail_values.txt" in joined, "Missing math_dump values")

def validate_lua_discovery(data, require_commands=True):
    tests = data.get("tests", [])
    require([t["name"] for t in tests] == ["lua_coroutine"], "Coroutine test discovery mismatch")
    if require_commands:
        args = tests[0].get("command", [])
        require(len(args) == 1 and Path(args[0]).name == "faf_coroutine_tests.exe", "Unexpected coroutine test command/args")


def validate_junit(path, expected_names=REQUIRED_TESTS):
    root = ET.parse(path).getroot()
    tests = root.findall(".//testcase")
    require(sorted(t.attrib.get("name", "") for t in tests) == sorted(expected_names), "CTest execution count/names mismatch")
    require(all(t.find("failure") is None and t.find("error") is None and t.find("skipped") is None for t in tests), "Failed, errored or skipped CTest")
    require(all(t.attrib.get("status", "run") not in {"notrun", "disabled"} for t in tests), "CTest was not executed")

def expand_rsp(command, build):
    # CMake/Ninja -d keeprsp keeps actual link response files for this inspection.
    result = command
    for name in re.findall(r'@(?:"([^"]+)"|([^\s"&]+))', command):
        p = Path(name[0] or name[1])
        if not p.is_absolute():
            p = build / p
        require(p.is_file() and p.resolve().is_relative_to(build.resolve()), "Missing/out-of-build actual link response file")
        result += "\n" + p.read_text(encoding="utf-8-sig")
    return result

def validate_actual_links(log, build, approved_ucrt):
    lines = log.splitlines()
    outputs = [EXE_NAME + ".exe", "faf_sim_math_tests.exe", "faf_math_dump.exe", "faf_coroutine_tests.exe"]
    evidence = []
    for target in outputs:
        candidates = []
        for line in lines:
            if "lld-link" not in line.lower():
                continue
            expanded = expand_rsp(line, build)
            # Match /out, not an incidental test executable in a post-build command.
            if re.search(r'/out:(?:"[^"\r\n]*|[^\s]+)' + re.escape(target), expanded, re.I):
                candidates.append(expanded)
        require(len(candidates) == 1, "Expected exactly one actual final link for " + target)
        link = candidates[0]
        normalized = normalize_path(link)
        require(normalize_path(approved_ucrt) in normalized, "Approved absolute UCRT missing from final link " + target)
        require("/nodefaultlib:libucrt.lib" in normalized, "Default static UCRT not excluded " + target)
        require("/nodefaultlib:ucrt.lib" in normalized, "Dynamic UCRT not excluded " + target)
        # Other /winsdkversion is allowed for headers/UM, not another libucrt path.
        selected = re.findall(r'(?:[a-z]:[^"\r\n]*?/|[^\s"]*/)(?:libucrtd?\.lib)', normalized)
        require(all(normalize_path(approved_ucrt) in x for x in selected), "Unapproved alternate static UCRT path")
        evidence.append({"target": target, "command_sha256": hashlib.sha256(link.encode()).hexdigest(), "approved_absolute_ucrt_verified": True})
    return evidence

class Build:
    def __init__(self, here, contract):
        self.here = here.resolve()
        self.c = contract
        self.started = time.monotonic()
        self.root = None
        self.phase = "contract"
        self.junctions = []
        self.upload_attempted = False
        self.upload_accepted = False
        self.receipt = {"schema": 1, "state": "NOT_STARTED", "source_base": BASE, "composite_tree": TREE,
                        "production_fixture": "NOT_RUN: no independently reviewed same-base fixture supplied",
                        "real_shader_execution": "NOT_RUN", "original_exe_parity": "NOT_RUN", "in_game_rendering": "NOT_RUN",
                        "replay_network_compatibility": "NOT_ESTABLISHED"}

    def remaining(self, cap):
        available = int(self.c["max_total_seconds"] - (time.monotonic() - self.started))
        require(available > 0, "Overall controlled deadline exhausted")
        return min(cap, available)

    def command(self, args, cwd=None, cap=120, env=None, name="command", binary=False, permit_failure=False, started_callback=None):
        # Never shell=True. Timeout kills only the child process tree created here.
        args = [str(x) for x in args]
        opts = dict(cwd=str(cwd or self.root or self.here), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if os.name == "nt":
            opts["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        timeout = self.remaining(cap)  # Must be checked before launching any child.
        proc = subprocess.Popen(args, **opts)
        try:
            if started_callback is not None:
                started_callback()
            output, _ = proc.communicate(timeout=timeout)
        except BaseException as exc:
            if proc.poll() is None:
                require(proc.pid != os.getpid(), "Refusing to terminate current host")
                try:
                    subprocess.run(["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=True)
                except Exception:
                    print("CHILD_TREE_CLEANUP_UNCERTAIN", name, flush=True)
                    proc.kill()
                proc.wait(timeout=15)
            if isinstance(exc, subprocess.TimeoutExpired):
                raise Blocked("Timed out bounded child: " + name) from exc
            raise
        if self.root:
            (self.root / "logs" / (name + ".txt")).write_bytes(output)
        if proc.returncode and not permit_failure:
            # Logs stay local, never copied wholesale into the public artifact.
            tail = output.decode("utf-8", errors="replace")[-1600:]
            print("CHILD_FAILURE", name, "exit", proc.returncode, flush=True)
            print(tail, flush=True)
            raise Blocked("Child failed: " + name)
        return output if binary else output.decode("utf-8", errors="replace").strip()

    def validate_contract(self):
        c = self.c
        resolve_contract_receipts(self.here, c)
        validate_interpreter()
        require(c.get("schema") == 1 and c.get("state") == "APPROVED_FOR_ONE_MANUAL_BUILD", "Draft contract is intentionally inert")
        require(c.get("root_go_reference") and "REQUIRED" not in c["root_go_reference"], "Final root GO missing")
        require(c.get("parallelism") in [1, 2] and 0 < c.get("max_total_seconds", 0) <= 3300, "Build resource bounds invalid")
        require(c.get("upload_exact_package") is True, "Exact public package upload not enabled")
        require(c.get("artifact_basename") == "faf-re-x64-b620-282-284", "Artifact basename must be exact reviewed value")
        require(os.environ.get("APPVEYOR", "").lower() == "true", "Not an AppVeyor worker")
        require(os.environ.get("APPVEYOR_ACCOUNT_NAME", "").lower() == c["account"].lower(), "AppVeyor account mismatch")
        require(os.environ.get("APPVEYOR_PROJECT_SLUG") == c["project_slug"], "AppVeyor project mismatch")
        require(os.environ.get("APPVEYOR_BUILD_WORKER_IMAGE") == c["expected_image"] == "Visual Studio 2022", "Unexpected worker image")
        require(not os.environ.get("APPVEYOR_PULL_REQUEST_NUMBER"), "PR trigger is outside manual build scope")
        require(os.environ.get("APPVEYOR_SKIP_FINALIZE_ON_EXIT", "").lower() == "true", "Finalize skip safeguard missing")
        require(os.environ.get("APPVEYOR_ARTIFACT_UPLOAD_TIMEOUT") == "300", "Upload timeout safeguard missing")
        identity = {"account": c["account"], "project_slug": c["project_slug"]}
        for key in ["BUILD_ID", "BUILD_VERSION", "JOB_ID"]:
            value = os.environ.get("APPVEYOR_" + key, "")
            require(value and re.fullmatch(r"[A-Za-z0-9_.-]+", value), "Missing provider-supplied " + key)
            identity[key.lower()] = value
        identity["provider_repository"] = os.environ.get("APPVEYOR_REPO_NAME", "")
        identity["provider_ref"] = os.environ.get("APPVEYOR_REPO_BRANCH", "")
        identity["provider_commit"] = os.environ.get("APPVEYOR_REPO_COMMIT", "")
        self.receipt["appveyor"] = identity
        require(os.environ.get("APPVEYOR_FORCED_BUILD", "").lower() == "true", "Job is not an explicit manual new build")
        require(not any(os.environ.get(k, "").lower() == "true" for k in ["APPVEYOR_SCHEDULED_BUILD", "APPVEYOR_RE_BUILD", "APPVEYOR_RE_RUN_INCOMPLETE"]), "Scheduled/rerun job is outside one-attempt scope")
        checked_hash(self.here / "driver-manifest.json", c["reviewed_driver_manifest_sha256"])
        manifest = read_json(self.here / "driver-manifest.json")
        for entry in manifest["files"]:
            checked_hash(self.here / safe_relative(entry["path"]), entry["sha256"])
        checked_hash(self.here / "integration-manifest.json", INTEGRATION_SHA)
        self.integration = read_json(self.here / "integration-manifest.json")
        checked_hash(c["preflight_receipt"], c["preflight_receipt_sha256"])
        self.preflight = read_json(c["preflight_receipt"])
        p = self.preflight
        require(p["status"] == "BLOCKED_MISSING_APPROVED_UCRT", "Preserve the actual historical preflight result")
        require(p["build_id"] == "55017328" and p["job_id"] == "qlqx8h7gn2uc63yi", "Historical preflight identity mismatch")
        require(p["account"].lower() == c["account"].lower() and p["project_slug"] == c["project_slug"], "Preflight destination mismatch")
        require(p["public_artifact_round_trip"] == "NOT_RUN" and p["native_attachment_preparation"] == "NOT_RUN", "Do not invent a preflight transport pass")
        require(p.get("documented_route_limit_source") and p.get("documented_route_limit_bytes", 0) > 0, "Artifact transfer route limit evidence missing")
        require(0 < c["max_artifact_bytes"] <= p["documented_route_limit_bytes"], "Chosen package budget exceeds documented route limit")
        require(c["ucrt"]["version"] == "10.0.22000.0" and c["ucrt"]["source"] == "pinned-official-nuget", "Only the newly approved official 22000 package is permitted")
        self.ucrt_package = read_json(self.here / "ucrt-package.json")
        require(self.ucrt_package["package_size"] == 51316315, "UCRT package identity mismatch")
        require(self.ucrt_package["license_acceptance"] == "APPROVED_FOR_THIS_TEMPORARY_BUILD", "SDK license acceptance gate missing")
        require(self.ucrt_package["entry_name"] == "c/ucrt/x64/libucrt.lib" and self.ucrt_package["entry_size"] == 39778014, "Static UCRT entry mismatch")
        require(re.fullmatch(r"[a-f0-9]{64}", self.ucrt_package.get("entry_sha256", "")), "Coordinator-verified UCRT entry SHA-256 not frozen")
        require(c["ucrt"]["sha256"] == self.ucrt_package["entry_sha256"], "Approved entry hash mismatch")
        self.receipt["prior_preflight"] = {"build_id": p["build_id"], "job_id": p["job_id"], "status": p["status"], "artifact_transport": "NOT_RUN"}
        self.receipt["full_artifact_retrieval"] = "NOT_RUN_ON_WORKER: coordinator verifies exact output after upload"
        checked_hash(c["distribution_review"], c["distribution_review_sha256"])
        self.distribution = read_json(c["distribution_review"])
        d = self.distribution
        require(d["status"] == "REVIEWED_FOR_THIS_PUBLIC_EXPERIMENT" and d["composite_tree"] == TREE, "Distribution-material review missing")
        require(d.get("review_reference") and "REQUIRED" not in d["review_reference"], "Concrete distribution-material review reference missing")
        require(d["root_license_absence_recorded"] is True, "Root license absence must remain explicit")
        require(d["material_policy"] == "exact-engine-allowlist-plus-pinned-dependency-source-v1", "Unreviewed source material selection")
        require(sorted(d["required_components"]) == sorted(SOURCE_COMPONENTS + ["luaplus", "dxc"]), "Missing linked-component material gate")
        checked_hash(self.here / "public-source-allowlist.json", d["public_source_allowlist_sha256"])

    def verify_configuration_checkout(self):
        self.phase = "configuration-checkout"
        checkout = self.here.parent
        require(Path(os.environ.get("APPVEYOR_BUILD_FOLDER", "")).resolve() == checkout, "Configuration checkout path mismatch")
        require((checkout / ".git").is_dir(), "Normal Git checkout required; ZIP/shallow_clone route is not supported")
        identity = self.receipt["appveyor"]
        expected = self.c["provider_configuration"]
        require(identity["provider_repository"].lower() == expected["repository"].lower(), "Configuration repository mismatch")
        require(identity["provider_ref"] == expected["branch"], "Configuration branch mismatch")
        require(re.fullmatch(r"[a-f0-9]{40}", identity["provider_commit"]), "Exact provider configuration commit missing")
        git = shutil.which("git.exe")
        require(git, "Installed Git missing for configuration checkout verification")
        def read(*args):
            return self.command([git, "-C", checkout, *args], cwd=checkout, cap=30, name="configuration-git")
        head = read("rev-parse", "HEAD")
        require(head == identity["provider_commit"], "Configuration checkout HEAD differs from provider commit")
        parents = re.findall(r"^parent ([a-f0-9]{40})$", read("cat-file", "-p", "HEAD"), re.M)
        require(parents == [expected["parent_commit"]], "Unexpected configuration commit parent")
        require(sorted(read("ls-tree", "-r", "--name-only", "HEAD").splitlines()) == sorted(expected["tracked_files"]), "Configuration tree contains missing or unreviewed files")
        require(not read("status", "--porcelain"), "Configuration checkout is not pristine")
        identity["configuration_checkout_verified"] = True
        identity["configuration_parent_commit"] = parents[0]

    def start_workspace(self):
        # tempfile creates a new empty worker directory, never a cached checkout.
        self.root = Path(tempfile.mkdtemp(prefix="faf-re-reviewed-", dir=os.environ["TEMP"]))
        for sub in ["logs", "tools", "build", "stage", "out"]:
            (self.root / sub).mkdir()
        require(shutil.disk_usage(self.root).free >= 20 * 1024**3, "Need >=20 GiB free before large portable tool/source build")
        self.source = self.root / "source"
        self.build = self.root / "build"
        self.stage = self.root / "stage"
        self.receipt["state"] = "RUNNING"

    def download_fixed(self, url, destination, size, seconds):
        deadline = time.monotonic() + self.remaining(seconds)
        request = urllib.request.Request(url, headers={"User-Agent": "faf-re-reviewed-source-build"})
        with urllib.request.urlopen(request, timeout=60) as response, destination.open("xb") as out:
            total = 0
            while True:
                require(time.monotonic() < deadline, "Fixed package download deadline exceeded")
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                require(total <= size, "Fixed package exceeds expected size")
                out.write(chunk)
        require(destination.stat().st_size == size, "Fixed package size mismatch")

    def make_sdk_junction(self, link, target):
        require(target.is_dir() and not link.exists(), "SDK overlay junction input invalid")
        require(link.absolute().is_relative_to(self.root.absolute()), "Junction destination outside owned workspace")
        installed = Path(self.c["windows_sdk_root"]).resolve()
        require(target.resolve().is_relative_to(installed), "Junction target outside verified installed SDK")
        for path in [link, target]:
            require(re.fullmatch(r"[A-Za-z]:[A-Za-z0-9 _().:/\\-]+", str(path)), "Unexpected shell metacharacter in SDK path")
        link.parent.mkdir(parents=True, exist_ok=True)
        self.junctions.append(link)  # Track before launch even if child outcome is uncertain.
        self.command(["cmd.exe", "/d", "/c", "mklink", "/J", link, target], cap=30, name="junction-" + link.name)
        require(link.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT, "SDK overlay entry is not a junction")
        require(link.resolve() == target.resolve(), "SDK junction resolved target mismatch")

    def provision_ucrt(self, installed_sdk):
        self.phase = "approved-ucrt-provisioning"
        pin = self.ucrt_package
        expected_url = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp.x64/10.0.22000.194/microsoft.windows.sdk.cpp.x64.10.0.22000.194.nupkg"
        expected_sha512 = "nXLjeIJjVayo+mDJpD5ijiXwm6b7dOp3KBZqdAGd5Bu7684qT9uW9vQAmpDbrbyDLN46RBs1VeTDTRTeVepYrQ=="
        require(pin["url"] == expected_url and pin["sha512_base64"] == expected_sha512, "Unapproved UCRT package URL/digest")
        expected_sdk = Path(os.environ["ProgramFiles(x86)"]) / "Windows Kits/10"
        require(installed_sdk.resolve() == expected_sdk.resolve(), "Modern SDK source is not the verified installed SDK root")
        archive = self.root / "tools/microsoft.windows.sdk.cpp.x64.10.0.22000.194.nupkg"
        self.download_fixed(expected_url, archive, 51316315, 240)
        actual_sha512 = base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode("ascii")
        require(actual_sha512 == expected_sha512, "Official UCRT package SHA-512 mismatch")
        checked_hash(archive, "039c4f5e2ad62494fa7fa6cafa2b6895fb3e2601491633c47256fbdca2e56f42")
        # Only one named regular static library entry is read. No nuspec/props/installer executes.
        extracted = self.root / "tools/libucrt-22000-x64.lib"
        with zipfile.ZipFile(archive) as z:
            entries = [x for x in z.infolist() if x.filename == pin["entry_name"]]
            require(len(entries) == 1, "Missing/duplicate exact static UCRT entry")
            entry = entries[0]
            filetype = stat.S_IFMT(entry.external_attr >> 16)
            require(not entry.is_dir() and filetype in {0, stat.S_IFREG} and not (entry.flag_bits & 1), "Unsafe/encrypted UCRT archive entry")
            require(entry.file_size == 39778014 and entry.CRC == int("0b055ab7", 16), "Static UCRT entry size/CRC mismatch")
            with z.open(entry) as source, extracted.open("xb") as target:
                shutil.copyfileobj(source, target, 1024 * 1024)
        require(extracted.stat().st_size == 39778014, "Extracted UCRT length mismatch")
        checked_hash(extracted, pin["entry_sha256"])
        coff = inspect_coff_archive(extracted)
        require(coff["members"] == 736, "Static UCRT member count differs from independent byte review")
        signature = "NOT_VERIFIED: no installed supported verifier; official package/entry hashes verified"
        env = os.environ.copy()
        env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
        env["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1"
        env["DOTNET_CLI_HOME"] = str(self.root / "tools/dotnet-home")
        env["NUGET_PACKAGES"] = str(self.root / "tools/nuget-cache")
        env["NUGET_HTTP_CACHE_PATH"] = str(self.root / "tools/nuget-http-cache")
        dotnet = shutil.which("dotnet.exe")
        verifier = None
        if dotnet:
            help_text = self.command([dotnet, "nuget", "--help"], cap=45, env=env, name="dotnet-nuget-capability", permit_failure=True)
            if re.search(r"(?m)^\s*verify\b", help_text):
                verifier = [dotnet, "nuget", "verify", archive, "--all", "--verbosity", "minimal"]
        if verifier is None:
            nuget = shutil.which("nuget.exe")
            if nuget:
                help_text = self.command([nuget, "help", "verify"], cap=45, env=env, name="nuget-verify-capability", permit_failure=True)
                if re.search(r"-Signatures\b", help_text, re.I):
                    verifier = [nuget, "verify", "-Signatures", archive, "-NonInteractive"]
        if verifier is not None:
            # Once support is established, any actual signature/trust failure blocks.
            self.command(verifier, cap=150, env=env, name="ucrt-nuget-signature")
            signature = "PASS: installed supported NuGet signature/trust verifier returned success"
        self.sdk = self.root / "sdk-overlay"
        self.sdk.mkdir()
        self.make_sdk_junction(self.sdk / "Include", installed_sdk / "Include")
        modern = self.c["windows_sdk_headers_version"]
        self.make_sdk_junction(self.sdk / "Lib" / modern, installed_sdk / "Lib" / modern)
        self.ucrt = self.sdk / "Lib/10.0.22000.0/ucrt/x64/libucrt.lib"
        self.ucrt.parent.mkdir(parents=True)
        shutil.copyfile(extracted, self.ucrt)
        checked_hash(self.ucrt, pin["entry_sha256"])
        self.receipt["ucrt_acquisition"] = {"package": "Microsoft.Windows.SDK.CPP.x64", "version": "10.0.22000.194", "url": expected_url, "package_size": archive.stat().st_size, "package_sha512_base64": expected_sha512, "package_sha256": sha(archive), "entry": pin["entry_name"], "entry_size": 39778014, "entry_sha256": sha(self.ucrt), "coff": coff, "signature": signature, "overlay": "job-owned only; Include and modern Lib junction targets are the installed SDK; static 22000 UCRT is a regular file; no system SDK write", "license_url": "https://aka.ms/WinSDKLicenseURL"}

    def tools_and_runtime(self):
        self.phase = "toolchain-runtime"
        vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
        require(vswhere.is_file(), "VS locator unavailable")
        vs = Path(self.command([vswhere, "-latest", "-version", "[17.0,18.0)", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], name="vswhere"))
        self.cmake = vs / "Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
        self.ctest = self.cmake.with_name("ctest.exe")
        self.ninja = vs / "Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe"
        for p in [self.cmake, self.ctest, self.ninja]:
            require(p.is_file(), "VS bundled build tool missing")
        require(self.command([self.cmake, "--version"], name="cmake-version").startswith("cmake version 3.31.6"), "Unexpected CMake; do not silently use PATH 4.1")
        self.command([self.ninja, "--version"], name="ninja-version")
        version = (vs / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt").read_text().strip()
        self.msvc = vs / "VC/Tools/MSVC" / version
        require(version.startswith("14.44.") and (self.msvc / "include/vcruntime.h").is_file(), "MSVC toolset differs from preflight 19.44")
        sdk = Path(self.c["windows_sdk_root"])
        require((sdk / "Include" / self.c["windows_sdk_headers_version"] / "um/d3d12.h").is_file(), "Required D3D12 SDK header missing")
        self.provision_ucrt(sdk)
        runtimes = {}
        for dll in ["d3dx9_43.dll", "X3DAudio1_7.dll"]:
            p = Path(os.environ["WINDIR"]) / "System32" / dll
            require(p.is_file() and pe_machine(p) == 0x8664, "Missing x64 legacy runtime " + dll + "; no silent installation")
            try:
                ctypes.WinDLL(str(p))
            except OSError as e:
                raise Blocked("Legacy runtime loader failed: " + dll) from e
            runtimes[dll] = {"sha256": sha(p), "architecture": "x64", "loadable": True}
        self.receipt["legacy_runtimes"] = runtimes
        self.git = shutil.which("git.exe")
        self.appveyor = shutil.which("appveyor.exe") or shutil.which("appveyor")
        require(self.git and self.appveyor, "Installed Git/AppVeyor worker CLI missing")
        self.command([self.git, "--version"], name="git-version")
        archive = self.root / "tools/llvm.tar.xz"
        # Official fixed portable archive only, bounded download, no installer execution.
        request = urllib.request.Request(LLVM_URL, headers={"User-Agent": "faf-re-reviewed-source-build"})
        deadline = time.monotonic() + self.remaining(720)
        with urllib.request.urlopen(request, timeout=60) as response, archive.open("xb") as out:
            total = 0
            while True:
                require(time.monotonic() < deadline, "LLVM download deadline exceeded")
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                require(total <= LLVM_SIZE, "Oversized LLVM archive")
                out.write(chunk)
        require(archive.stat().st_size == LLVM_SIZE, "LLVM archive size mismatch")
        checked_hash(archive, LLVM_SHA)
        unpack = self.root / "tools/llvm"
        unpack.mkdir()
        self.command([self.cmake, "-E", "tar", "xf", archive], cwd=unpack, cap=480, name="llvm-extract")
        found = list(unpack.glob("*/bin/clang-cl.exe")) + list(unpack.glob("bin/clang-cl.exe"))
        require(len(found) == 1, "Portable LLVM root ambiguous")
        self.llvm = found[0].parent.parent
        versions = {}
        for tool in ["clang-cl", "lld-link", "llvm-lib", "llvm-rc", "llvm-mt", "llvm-ml64", "llvm-readobj"]:
            p = self.llvm / "bin" / (tool + ".exe")
            require(p.is_file(), "Pinned LLVM tool absent: " + tool)
            versions[tool] = {"sha256": sha(p)}
        for tool, arg in [("clang-cl", "--version"), ("lld-link", "--version"), ("llvm-readobj", "--version")]:
            text = self.command([self.llvm / "bin" / (tool + ".exe"), arg], name=tool + "-version")
            require("22.1.7" in text, "LLVM binary version mismatch")
            versions[tool]["version"] = "22.1.7"
        coff = self.command([self.llvm / "bin/llvm-readobj.exe", "--file-headers", self.ucrt], cap=120, name="ucrt-coff")
        machines = set(re.findall(r"Machine:\s+(IMAGE_FILE_MACHINE_[A-Z0-9_]+)", coff))
        require(machines == {"IMAGE_FILE_MACHINE_AMD64"}, "LLVM did not confirm exclusively x64 UCRT objects")
        self.receipt["ucrt_acquisition"]["llvm_coff_machine"] = "IMAGE_FILE_MACHINE_AMD64"
        self.receipt["in_job_ucrt_gate"] = "PASS"
        self.receipt["driver_entry_sha256"] = sha(self.here / "driver.py")
        self.receipt["tools"] = {"llvm_archive_sha256": LLVM_SHA, "llvm_tools": versions, "cmake": "3.31.6", "cmake_sha256": sha(self.cmake), "ninja_sha256": sha(self.ninja), "msvc_tools": version, "sdk_headers": self.c["windows_sdk_headers_version"], "ucrt": {"version": "10.0.22000.0", "sha256": sha(self.ucrt), "source": "pinned Microsoft NuGet static entry", "location": "job-owned SDK overlay"}, "python": sys.version.split()[0]}

    def git_cmd(self, *args, name="git", binary=False, env=None):
        return self.command([self.git, "-c", "core.autocrlf=false", "-C", self.source, *args], cap=300, name=name, binary=binary, env=env)

    def source_assembly(self):
        self.phase = "source-assembly"
        self.source.mkdir()
        self.git_cmd("init", name="git-init")
        self.git_cmd("config", "core.autocrlf", "false", name="git-autocrlf")
        self.git_cmd("remote", "add", "origin", "https://github.com/Draiget/faf-re.git", name="git-origin")
        self.git_cmd("fetch", "--no-tags", "--depth=1", "origin", BASE, name="git-fetch-base")
        self.git_cmd("checkout", "--detach", BASE, name="git-checkout")
        require(self.git_cmd("rev-parse", "HEAD", name="base-commit") == BASE, "Base commit mismatch")
        require(self.git_cmd("rev-parse", "HEAD^{tree}", name="base-tree") == BASE_TREE, "Base tree mismatch")
        require(not self.git_cmd("status", "--porcelain", name="base-clean"), "Checkout is not pristine")
        for change in self.integration["changed_files"]:
            target = self.source / safe_relative(change["path"])
            checked_hash(target, change["before_sha256"])
            require(blob_sha(target) == change["before_blob"], "Original blob mismatch")
            self.git_cmd("fetch", "--no-tags", "--depth=1", "origin", change["head"], name="fetch-pr-" + str(change["pr"]))
            data = self.git_cmd("show", change["head"] + ":" + change["path"], name="read-pr-" + str(change["pr"]), binary=True)
            require(hashlib.sha256(data).hexdigest() == change["after_sha256"], "Draft file SHA mismatch")
            target.write_bytes(data)
            require(blob_sha(target) == change["after_blob"], "Draft blob mismatch")
        self.verify_source()
        # Separate temporary index creates a tree object but no commit or source branch.
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(self.root / "composite.index")
        self.git_cmd("read-tree", BASE, name="temp-index-base", env=env)
        self.git_cmd("add", "--", *[x["path"] for x in self.integration["changed_files"]], name="temp-index-three-files", env=env)
        require(self.git_cmd("write-tree", name="composite-tree", env=env) == TREE, "Complete composite tree mismatch")
        require(not (self.source / "dependencies/.downloads").exists(), "Dependency cache unexpectedly exists")
        require(not (self.source / "dependencies/dxsdk").exists(), "DXSDK not fresh")

    def verify_source(self):
        changed = self.git_cmd("diff", "--name-only", "--ignore-submodules=all", BASE, name="changed-source").splitlines()
        require(sorted(changed) == sorted(x["path"] for x in self.integration["changed_files"]), "Tracked source changes exceed exactly three replacements")
        require(self.git_cmd("rev-parse", "HEAD", name="source-head") == BASE, "Source HEAD changed")
        for entry in self.integration["changed_files"]:
            checked_hash(self.source / entry["path"], entry["after_sha256"])
        for name, digest in self.integration["build_file_sha256"].items():
            checked_hash(self.source / name, digest)
        for name, digest in GOLDEN_BLOBS.items():
            require(blob_sha(self.source / name) == digest, "Frozen test/build input changed: " + name)
        require(not (self.source / "tests/sim_math/known_windows-x64.txt").exists(), "Unreviewed x64 known differences")
        for e in self.integration["dependency_patch_blobs"] + self.integration["hook_files"]:
            require(blob_sha(self.source / e["path"]) == e["sha"], "Patch/hook blob mismatch")

    def configure(self):
        self.phase = "configure"
        args = [self.cmake, "--preset", "clang-x64-release", "-S", self.source, "-B", self.build,
                "-DCMAKE_MAKE_PROGRAM=" + str(self.ninja), "-DFAF_LLVM_ROOT=" + str(self.llvm),
                "-DFAF_MSVC_TOOLS_DIR=" + str(self.msvc), "-DFAF_WINSDK_DIR=" + str(self.sdk),
                "-DFAF_WINSDK_VERSION=" + self.c["windows_sdk_headers_version"],
                "-DFAF_UCRT_LIB_VERSION=" + self.c["ucrt"]["version"],
                "-DFAF_OUTPUT_NAME=" + EXE_NAME, "-DFAF_DXSDK_FORCE_DOWNLOAD=ON", "-DFAF_FETCH_DEPENDENCIES=ON"]
        args += ["-D" + flag + "=OFF" for flag in DISABLED_FLAGS]
        self.command(args, cwd=self.source, cap=900, name="configure")
        cache = read_cache(self.build / "CMakeCache.txt")
        for flag in DISABLED_FLAGS:
            require(cache.get(flag) == "OFF", "Unsafe/missing cache flag " + flag)
        for k, v in {"CMAKE_BUILD_TYPE": "Release", "CMAKE_GENERATOR": "Ninja", "FAF_WINSDK_VERSION": self.c["windows_sdk_headers_version"], "FAF_UCRT_LIB_VERSION": self.c["ucrt"]["version"], "FAF_OUTPUT_NAME": EXE_NAME, "FAF_DXSDK_FORCE_DOWNLOAD": "ON", "FAF_FETCH_DEPENDENCIES": "ON"}.items():
            require(cache.get(k) == v, "Cache selection mismatch: " + k)
        for k, v in {"FAF_LLVM_ROOT": self.llvm, "FAF_MSVC_TOOLS_DIR": self.msvc, "FAF_WINSDK_DIR": self.sdk, "FAF_DXSDK_DIR": self.source / "dependencies/dxsdk", "CMAKE_MAKE_PROGRAM": self.ninja}.items():
            require(normalize_path(cache.get(k, "")) == normalize_path(v), "Cache tool/input path mismatch: " + k)
        self.receipt["cache_selections"] = {k: cache[k] for k in DISABLED_FLAGS + ["CMAKE_BUILD_TYPE", "CMAKE_GENERATOR", "FAF_WINSDK_VERSION", "FAF_UCRT_LIB_VERSION", "FAF_OUTPUT_NAME", "FAF_DXSDK_FORCE_DOWNLOAD"]}
        self.verify_source()
        self.verify_dependencies()
        discovery = self.command([self.ctest, "--test-dir", self.build, "--show-only=json-v1", "-R", TEST_REGEX], name="ctest-discovery")
        validate_test_discovery(json.loads(discovery), self.source, require_commands=False)
        lua_discovery = self.command([self.ctest, "--test-dir", self.build, "--show-only=json-v1", "-R", LUA_TEST_REGEX], name="ctest-lua-discovery")
        validate_lua_discovery(json.loads(lua_discovery), require_commands=False)
        self.receipt["ctest_discovered"] = REQUIRED_TESTS + ["lua_coroutine"]
        # Verify POST_BUILD gate commands in generated build instructions before compiling.
        ninja_text = (self.build / "build.ninja").read_text(encoding="utf-8")
        require("sim_math/golden.txt" in ninja_text.replace("\\", "/"), "Missing sim_math POST_BUILD golden")
        require("--iters 131072" in ninja_text and "retail_values.txt" in ninja_text, "Missing math_dump POST_BUILD gate")

    def verify_dependencies(self):
        deps = self.source / "dependencies"
        info = {"gitlinks": [], "archives": [], "patches": []}
        for entry in self.integration["submodule_gitlinks"]:
            p = self.source / entry["path"]
            got = self.command([self.git, "-C", p, "rev-parse", "HEAD"], name="pin-" + p.name)
            require(got == entry["sha"], "Dependency gitlink changed: " + p.name)
            info["gitlinks"].append({"path": entry["path"], "commit": got})
        archive_hashes = {}
        for p in (deps / ".downloads").iterdir():
            if p.is_file():
                archive_hashes.setdefault(sha(p), []).append(p)
        for entry in self.integration["download_dependencies"]:
            marker = deps / entry["name"] / ".faf-download"
            require(marker.read_text().strip() == entry["sha256"], "Dependency extraction marker mismatch")
            candidates = archive_hashes.get(entry["sha256"], [])
            require(len(candidates) == 1, "Missing/ambiguous pinned archive for " + entry["name"])
            info["archives"].append({"component": entry["name"], "sha256": entry["sha256"], "archive": candidates[0].name})
        checked_hash(deps / ".downloads/DXSDK_Jun10.exe", self.integration["directx_sdk"]["sha256"])
        groups = {"WildMagic3p8": ["wildmagic3p8_faf_required.patch"], "zlib-1.2.3": ["zlib_1_2_3_faf_required.patch"], "boost_1_34_1": ["boost_1_34_1_faf_required.patch"], "wxWindows-2.4.2": ["wxwindows_2_4_2_faf_required.patch", "wxwindows_2_4_2_faf_x64.patch", "wxwindows_2_4_2_faf_x64_pointers.patch"]}
        for name, patches in groups.items():
            expected = "".join(p + " " + sha(deps / "patches" / p) + "\n" for p in patches)
            require((deps / name / ".faf-patches").read_text() == expected, "Dependency patch stamp mismatch: " + name)
            info["patches"].append({"component": name, "stamp": expected})
        for component, rel, git_blob in [("WildMagic3p8", "License/WildMagic3License.pdf", "890163881fcd939083041b3b6ac7fe5b20e29a21"), ("zlib-1.2.3", "README", "758cc50020dfefc53d518fd56072849cd5cbc9c7")]:
            require(blob_sha(deps / component / rel) == git_blob, "Pinned component notice changed: " + component)
        config = deps / "ffmpeg/faf/x64/config.h"
        require(blob_sha(config) == "2fe47091c8fcdd86483df1975efd962cf0b5f3a4", "Pinned FFmpeg configuration changed")
        config_text = config.read_text()
        for macro in ["CONFIG_GPL", "CONFIG_NONFREE", "CONFIG_VERSION3", "CONFIG_GPLV3"]:
            require("#define " + macro + " 0" in config_text, "Unexpected FFmpeg license configuration")
        info["ffmpeg_configuration"] = {"config_git_blob": "2fe47091c8fcdd86483df1975efd962cf0b5f3a4", "gpl": False, "nonfree": False, "version3": False}
        self.receipt["dependencies"] = info

    def compile_and_test(self):
        self.phase = "build-and-goldens"
        self.verify_source()
        checked_hash(self.ucrt, self.c["ucrt"]["sha256"])
        # -d keeprsp preserves actual final-link response files for independent UCRT checks.
        build_log = self.command([self.cmake, "--build", self.build, "--target", *REQUIRED_TARGETS, "--parallel", str(self.c["parallelism"]), "--verbose", "--", "-d", "keeprsp"], cap=2700, name="build")
        self.receipt["actual_final_links"] = validate_actual_links(build_log, self.build, self.ucrt)
        require("Checking the simulation's arithmetic" in build_log or "sim_math/golden.txt" in build_log.replace("\\", "/"), "Missing executed sim_math POST_BUILD evidence")
        require("--iters 131072" in build_log, "Missing executed math_dump POST_BUILD evidence")
        self.receipt["build_targets"] = REQUIRED_TARGETS
        self.receipt["post_build_goldens"] = "PASS"
        self.phase = "ctest"
        discovery = self.command([self.ctest, "--test-dir", self.build, "--show-only=json-v1", "-R", TEST_REGEX], name="ctest-discovery-built")
        validate_test_discovery(json.loads(discovery), self.source)
        junit = self.root / "ctest.xml"
        self.command([self.ctest, "--test-dir", self.build, "-R", TEST_REGEX, "--output-on-failure", "--no-tests=error", "--timeout", "180", "--parallel", "1", "--output-junit", junit], cap=420, name="ctest")
        validate_junit(junit)
        self.verify_source()
        checked_hash(self.ucrt, self.c["ucrt"]["sha256"])
        lua_discovery = self.command([self.ctest, "--test-dir", self.build, "--show-only=json-v1", "-R", LUA_TEST_REGEX], name="ctest-lua-discovery-built")
        validate_lua_discovery(json.loads(lua_discovery))
        lua_junit = self.root / "ctest-lua.xml"
        self.command([self.ctest, "--test-dir", self.build, "-R", LUA_TEST_REGEX, "--output-on-failure", "--no-tests=error", "--timeout", "180", "--parallel", "1", "--output-junit", lua_junit], cap=210, name="ctest-lua")
        validate_junit(lua_junit, ["lua_coroutine"])
        self.verify_source()
        self.receipt["ctest_executed"] = REQUIRED_TESTS + ["lua_coroutine"]
        self.receipt["ctest_result"] = "PASS"
        header = self.build / "generated/faf/BuildInfoGenerated.h"
        text = header.read_text()
        for exact in [f'#define FAF_BUILD_COMMIT "{BASE}"', '#define FAF_BUILD_DIRTY 1', '#define FAF_BUILD_ARCH "x64"', '#define FAF_BUILD_CONFIG "Release"']:
            require(exact in text, "BuildInfo is not truthful base+dirty/x64/Release")
        self.receipt["build_info"] = text

    def inspect_runtime(self, p):
        require(pe_machine(p) == 0x8664, "Non-x64 runtime output")
        result = self.command([self.llvm / "bin/llvm-readobj.exe", "--file-headers", "--coff-imports", p], name="pe-" + p.name)
        imports = sorted(set(re.findall(r"Name:\s+([^\s]+\.dll)", result, re.I)))
        require(imports, "No import inventory found for " + p.name)
        if p.suffix.lower() == ".exe":
            require(not any(re.match(r"(?:msvcp\d|vcruntime\d|api-ms-win-crt|ucrtbase)", x, re.I) for x in imports), "Unexpected dynamic C/C++ runtime import in statically linked engine/test")
        available = {}
        for dll in imports:
            if dll.lower() in {"dxcompiler.dll", "dxil.dll"}:
                candidate = self.source / "dependencies/dxc/bin/x64" / dll
            elif dll.lower().startswith(("api-ms-win-", "ext-ms-win-")):
                available[dll] = "Windows API-set contract"
                continue
            else:
                candidate = Path(os.environ["WINDIR"]) / "System32" / dll
            require(candidate.is_file() and pe_machine(candidate) == 0x8664, "Missing or wrong-architecture imported runtime: " + dll)
            available[dll] = {"sha256": sha(candidate), "origin": "pinned DXC" if "dxc/bin" in candidate.as_posix() else "Windows System32"}
        return {"sha256": sha(p), "architecture": "x64", "imports": available}

    def copy_exact(self, origin, relative):
        rel = safe_relative(relative)
        require(origin.is_file() and not origin.is_symlink(), "Non-regular package input")
        target = self.stage / rel
        require(not target.exists(), "Duplicate package destination")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, target)

    def dependency_sources(self, name, component_root):
        require(component_root.is_dir() and not component_root.is_symlink(), "Missing public source material: " + name)
        files = []
        for directory, dirs, names in os.walk(component_root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SOURCE_DENY_DIRS and not (Path(directory) / d).is_symlink())
            if name == "WildMagic3p8" and Path(directory) == component_root:
                # Only Foundation headers are consumed by the frozen CMake build.
                dirs[:] = [d for d in dirs if d in {"Foundation", "License"}]
            for filename in sorted(names):
                p = Path(directory) / filename
                if p.is_symlink() or p.suffix.lower() in SOURCE_DENY_SUFFIXES or filename == ".git":
                    continue
                # Only named pinned public-source roots, never arbitrary worker trees.
                files.append(p)
        require(files, "Empty source component")
        return files

    def stage_package(self):
        self.phase = "package-materials"
        exe = self.build / "src" / (EXE_NAME + ".exe")
        require(exe.is_file(), "Full GUI client output absent")
        runtime = {}
        self.copy_exact(exe, EXE_NAME + ".exe")
        for dll in ["dxcompiler.dll", "dxil.dll"]:
            original = self.source / "dependencies/dxc/bin/x64" / dll
            sibling = self.build / "src" / dll
            checked_hash(sibling, sha(original))
            self.copy_exact(original, dll)
        for p in [exe, self.stage / "dxcompiler.dll", self.stage / "dxil.dll", self.build / "tests/faf_sim_math_tests.exe", self.build / "tests/faf_math_dump.exe", self.build / "tests/faf_coroutine_tests.exe"]:
            runtime[p.name] = self.inspect_runtime(p)
        self.receipt["pe_runtime"] = runtime
        hook = self.integration["hook_files"]
        require(len(hook) == 1, "Unexpected hook set")
        self.copy_exact(self.source / hook[0]["path"], "fafengine/lua/options/options.lua")
        allow = read_json(self.here / "public-source-allowlist.json")
        for entry in allow["files"]:
            p = self.source / safe_relative(entry["path"])
            require(blob_sha(p) == entry["git_blob"], "Source/relink material changed: " + entry["path"])
            require(p.suffix.lower() not in SOURCE_DENY_SUFFIXES, "Prohibited root source material")
            self.copy_exact(p, "corresponding-source/engine/" + entry["path"])
        notice_inventory = {}
        for name in SOURCE_COMPONENTS:
            component_root = self.source / "dependencies" / name
            material_files = self.dependency_sources(name, component_root)
            notices = [p for p in material_files if NOTICE_RE.match(p.name)]
            # zlib and old WildMagic may place the license in a specifically reviewed README/header.
            for rel in self.distribution.get("additional_notice_paths", {}).get(name, []):
                p = component_root / safe_relative(rel)
                require(p.is_file() and p in material_files, "Reviewed notice path missing")
                notices.append(p)
            require(notices, "No applicable license/notice text found for " + name)
            notice_inventory[name] = []
            for p in material_files:
                rel = p.relative_to(component_root).as_posix()
                self.copy_exact(p, "corresponding-source/engine/dependencies/" + name + "/" + rel)
            for p in sorted(set(notices)):
                rel = p.relative_to(component_root).as_posix()
                notice_inventory[name].append({"path": rel, "sha256": sha(p)})
                self.copy_exact(p, "notices/" + name + "/" + rel)
        lua = self.source / "src/lua/luaplus/LICENSE"
        require(lua.is_file(), "LuaPlus notice missing")
        self.copy_exact(lua, "notices/luaplus/LICENSE")
        notice_inventory["luaplus"] = [{"path": "src/lua/luaplus/LICENSE", "sha256": sha(lua)}]
        dxc = self.source / "dependencies/dxc"
        dxc_notices = [p for p in self.dependency_sources("dxc", dxc) if NOTICE_RE.match(p.name)]
        require(dxc_notices and any("ms" in p.name.lower() for p in dxc_notices) and any("llvm" in p.name.lower() for p in dxc_notices), "Pinned DXC Microsoft/LLVM redistribution notices missing")
        for p in dxc_notices:
            self.copy_exact(p, "notices/dxc/" + p.relative_to(dxc).as_posix())
        notice_inventory["dxc"] = [{"path": p.relative_to(dxc).as_posix(), "sha256": sha(p)} for p in dxc_notices]
        self.receipt["notices"] = notice_inventory
        self.receipt["root_license"] = "No repository-root LICENSE/COPYING in frozen source; no blanket license or upstream endorsement is claimed."
        require((self.stage / "corresponding-source/engine/dependencies/ffmpeg/configure").is_file(), "Full FFmpeg source missing")
        require((self.stage / "corresponding-source/engine/dependencies/ffmpeg/faf/CMakeLists.txt").is_file(), "FFmpeg relink build definition missing")
        for name in ["TESTING.md", "REBUILD.md", "README-PACKAGE.md"]:
            self.copy_exact(self.here / name, name)
        public_source = {k: self.integration[k] for k in ["base_commit", "base_tree", "planned_integrated_tree", "submodule_gitlinks", "download_dependencies", "directx_sdk", "build_file_sha256", "hook_files", "dependency_patch_blobs"]}
        public_source["changed_files"] = [{k: e[k] for k in ["pr", "head", "path", "before_blob", "after_blob", "before_sha256", "after_sha256"]} for e in self.integration["changed_files"]]
        write_json(self.stage / "SOURCE_MANIFEST.json", public_source)
        self.copy_exact(self.build / "generated/faf/BuildInfoGenerated.h", "build/BuildInfoGenerated.h")
        self.receipt["state"] = "BUILT_TESTED_STAGED_NOT_UPLOADED"
        write_json(self.stage / "BUILD_MANIFEST.json", self.receipt)
        # Exact final inventory is frozen before ZIP creation. No wildcard copy of the worker.
        inventory = [{"path": p.relative_to(self.stage).as_posix(), "size": p.stat().st_size, "sha256": sha(p)}
                     for p in sorted(self.stage.rglob("*")) if p.is_file()]
        require(not any(e["path"].lower().endswith((".pdb", ".scd", ".scmap", ".scfareplay", ".dmp")) for e in inventory), "Prohibited package member")
        allowed_binaries = {EXE_NAME + ".exe", "dxcompiler.dll", "dxil.dll"}
        require({e["path"] for e in inventory if Path(e["path"]).suffix.lower() in {".exe", ".dll"}} == allowed_binaries, "Unexpected binaries in package")
        write_json(self.stage / "FILE_MANIFEST.json", {"schema": 1, "files": inventory, "self_reference": "FILE_MANIFEST.json and SHA256SUMS exclude themselves; outer ZIP SHA binds all members"})
        sums = "".join(e["sha256"] + "  " + e["path"] + "\n" for e in inventory)
        (self.stage / "SHA256SUMS").write_text(sums, encoding="utf-8")
        artifact = self.root / "out" / (self.c["artifact_basename"] + "-" + self.receipt["appveyor"]["build_id"] + "-" + self.receipt["appveyor"]["job_id"] + ".zip")
        exact_members = [e["path"] for e in inventory] + ["FILE_MANIFEST.json", "SHA256SUMS"]
        with zipfile.ZipFile(artifact, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for rel in exact_members:
                require(self.remaining(300) > 0, "Packaging deadline")
                z.write(self.stage / rel, rel)
        with zipfile.ZipFile(artifact) as z:
            require(sorted(z.namelist()) == sorted(exact_members) and z.testzip() is None, "ZIP member/hash validation failed")
        require(artifact.stat().st_size <= self.c["max_artifact_bytes"], "Package exceeds configured artifact budget; do not omit required source/notices")
        self.receipt["artifact"] = {"filename": artifact.name, "size": artifact.stat().st_size, "sha256": sha(artifact), "visibility": "public", "source_tree": TREE}
        self.artifact = artifact

    def upload(self):
        self.phase = "exact-package-upload"
        require(self.receipt["ctest_result"] == "PASS" and self.artifact.is_file(), "Upload attempted before gates")
        checked_hash(self.artifact, self.receipt["artifact"]["sha256"])
        # One exact file, one attempt. An uncertain/failed upload is not retried.
        require(self.remaining(330) == 330, "Insufficient full upload window; no upload attempted")
        print("PUBLIC_ARTIFACT_PREPARED " + json.dumps({"appveyor": self.receipt["appveyor"], "artifact": self.receipt["artifact"], "state": "PREPARED_NOT_UPLOADED"}, sort_keys=True), flush=True)
        self.command([self.appveyor, "PushArtifact", self.artifact, "-FileName", self.artifact.name], cap=330, name="upload", started_callback=lambda: setattr(self, "upload_attempted", True))
        self.upload_accepted = True
        self.receipt["state"] = "UPLOAD_ACCEPTED_RETRIEVAL_NOT_VERIFIED"
        print("PUBLIC_ARTIFACT_RECEIPT " + json.dumps({"appveyor": self.receipt["appveyor"], "artifact": self.receipt["artifact"], "state": self.receipt["state"]}, sort_keys=True), flush=True)

    def run(self):
        try:
            self.validate_contract()
            self.verify_configuration_checkout()
            self.start_workspace()
            for method in [self.tools_and_runtime, self.source_assembly, self.configure, self.compile_and_test, self.stage_package, self.upload]:
                print("PHASE " + method.__name__, flush=True)
                method()
            return 0
        except Exception as e:
            self.receipt["state"] = "BLOCKED_UPLOAD_UNCERTAIN" if self.upload_attempted and not self.upload_accepted else "BLOCKED"
            self.receipt["blocked_phase"] = self.phase
            self.receipt["reason"] = str(e)
            print("BUILD_BLOCKED " + json.dumps({"state": self.receipt["state"], "phase": self.phase, "reason": str(e), "upload_attempted": self.upload_attempted}), flush=True)
            return 1
        finally:
            # No upload in any failure/finalization path. Only our private temporary directory.
            if self.root:
                try:
                    for junction in reversed(self.junctions):
                        if os.path.lexists(junction):
                            require(junction.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT, "Cleanup found unexpected non-junction at overlay entry")
                            os.rmdir(junction)  # Remove link entry only, never its SDK target.
                    shutil.rmtree(self.root)
                    print("CLEANUP temporary worker directory removed", flush=True)
                except (OSError, Blocked):
                    print("CLEANUP_INCOMPLETE temporary files remain on ephemeral worker; no artifact fallback", flush=True)
            print("FINALIZATION no additional artifacts, caches, deployment, or retry", flush=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--check-interpreter", action="store_true", help="Identity/architecture check only; no build or download")
    args = parser.parse_args()
    if args.check_interpreter:
        try:
            validate_interpreter()
            return 0
        except Blocked as exc:
            print("INTERPRETER_BLOCKED " + str(exc), flush=True)
            return 1
    if not args.contract:
        parser.error("--contract is required unless --check-interpreter is used")
    if not args.execute:
        print("DRAFT ONLY. No execution requested.")
        return 2
    return Build(Path(__file__).parent, read_json(args.contract)).run()

if __name__ == "__main__":
    raise SystemExit(main())
