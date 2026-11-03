import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
"""Synthetic-only regression suite; does not prove any Windows host inventory."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import toolchain_fingerprint as tf


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "include"
        self.root.mkdir()
        self.header = self.root / "vector"
        self.header.write_bytes(b"template<class T> struct vector {};\n")
        self.spec = tf.RootSpec("msvc-include", self.root, version="14.44.35207")

    def capture(self, *args, **kwargs):
        return tf.capture_inventory(args or [self.spec], **kwargs)

    def mismatch(self, before, after):
        with self.assertRaises(tf.FingerprintError):
            before.assert_matches(after)

    def test_tree_all_regular_files_and_empty_directories(self):
        (self.root / "empty").mkdir()
        (self.root / "a.in").write_bytes(b"x")
        inventory = self.capture()
        summary = inventory.public_summary()
        self.assertEqual(summary["file_count"], 2)
        self.assertEqual(summary["directory_count"], 2)
        self.assertEqual(summary["total_bytes"], self.header.stat().st_size + 1)
        inventory.assert_matches(self.capture())
        self.assertNotIn(str(self.base), json.dumps(summary))
        self.assertNotIn("vector", json.dumps(summary))
        self.assertEqual(inventory.private_root_mapping()["msvc-include"], str(self.root))

    def test_same_bytes_changed_mtime_rejected(self):
        before = self.capture()
        st = self.header.stat()
        os.utime(self.header, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        after = self.capture()
        self.mismatch(before, after)
        a, b = before.public_summary()["roots"][0], after.public_summary()["roots"][0]
        self.assertEqual(a["content_sha256"], b["content_sha256"])
        self.assertNotEqual(a["timestamp_sha256"], b["timestamp_sha256"])

    def test_same_time_changed_bytes_rejected(self):
        before = self.capture()
        st = self.header.stat()
        data = self.header.read_bytes()
        self.header.write_bytes(b"X" * len(data))
        os.utime(self.header, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.mismatch(before, self.capture())

    def test_added_or_removed_header_rejected(self):
        before = self.capture()
        extra = self.root / "new.inc"
        extra.write_bytes(b"extra")
        self.mismatch(before, self.capture())
        extra.unlink()
        self.header.unlink()
        self.mismatch(before, self.capture())

    def test_optional_missing_root_must_stay_missing(self):
        absent = self.base / "atlmfc" / "include"
        spec = tf.RootSpec("msvc-atlmfc-include", absent, optional=True)
        before = self.capture(spec)
        self.assertEqual(before.public_summary()["roots"][0]["status"], "ABSENT")
        before.assert_matches(self.capture(spec))
        absent.mkdir(parents=True)
        self.mismatch(before, self.capture(spec))
        with self.assertRaises(tf.FingerprintError):
            self.capture(tf.RootSpec("must-exist", self.base / "missing"))

    def test_direct_library_namespace_shadows_and_ignores_logs(self):
        libs = self.base / "lib"
        libs.mkdir()
        (libs / "x.LIB").write_bytes(b"lib")
        (libs / "subdir").mkdir()
        (libs / "subdir" / "other.lib").write_bytes(b"not selected")
        log = libs / ".ninja_log"
        log.write_text("initial")
        spec = tf.RootSpec("cwd-libraries", libs, mode="libraries", extra_basenames=("extra.obj",))
        before = self.capture(spec)
        log.write_text("different mutable log")
        before.assert_matches(self.capture(spec))
        (libs / "shadow.lib").write_bytes(b"shadow")
        self.mismatch(before, self.capture(spec))
        (libs / "shadow.lib").unlink()
        (libs / "extra.obj").write_bytes(b"object")
        self.mismatch(before, self.capture(spec))
        self.assertEqual(before.public_summary()["file_count"], 1)

    def test_library_directory_candidate_rejected(self):
        (self.root / "shadow.lib").mkdir()
        with self.assertRaises(tf.FingerprintError):
            self.capture(tf.RootSpec("libs", self.root, mode="libraries"))

    def test_copied_ucrt_ignores_only_timestamp(self):
        lib = self.base / "libucrt.lib"
        lib.write_bytes(b"pinned")
        spec = tf.FileSpec("overlay-ucrt-22000", lib, compare_mtime=False,
                           expected_sha256=hashlib.sha256(b"pinned").hexdigest(),
                           expected_size=6, version="10.0.22000.0", expected_basename="libucrt.lib")
        before = tf.capture_inventory([], [spec])
        st = lib.stat()
        os.utime(lib, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        before.assert_matches(tf.capture_inventory([], [spec]))
        self.assertIsNone(before.public_summary()["roots"][0]["timestamp_sha256"])
        lib.write_bytes(b"broken")
        with self.assertRaises(tf.FingerprintError):
            tf.capture_inventory([], [spec])
        with self.assertRaises(tf.FingerprintError):
            tf.capture_inventory([], [tf.FileSpec("ucrt", lib, expected_basename="other.lib")])

    def test_case_colliding_files_rejected(self):
        (self.root / "VECTOR").write_bytes(b"collision")
        if len(list(self.root.iterdir())) == 1:
            self.skipTest("case-insensitive filesystem")
        with self.assertRaises(tf.FingerprintError):
            self.capture()

    def test_symlink_and_ancestor_symlink_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "escape").write_bytes(b"not allowed")
        link = self.root / "link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(tf.FingerprintError):
            self.capture()
        with self.assertRaises(tf.FingerprintError):
            self.capture(tf.RootSpec("escaped", link / "missing", optional=True))

    def test_file_symlink_rejected(self):
        alias = self.root / "alias"
        try:
            alias.symlink_to(self.header)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(tf.FingerprintError):
            self.capture()

    def test_reparse_attribute_rejected(self):
        real = self.header.lstat()
        class ReparseStat:
            st_mode = real.st_mode
            st_file_attributes = 0x400
        with patch.object(Path, "lstat", return_value=ReparseStat()):
            with self.assertRaises(tf.FingerprintError):
                tf._snapshot(self.header)

    def test_parent_escape_ads_unc_nonascii_trailing_dot_rejected(self):
        invalid = [str(self.root / ".." / "include"), str(self.root / "a:b"),
                   "//server/share/root", str(self.root / "trailing."),
                   str(self.root / "trailing "), str(self.root / "\u00e9")]
        for path in invalid:
            with self.subTest(path=path), self.assertRaises(tf.FingerprintError):
                self.capture(tf.RootSpec("invalid", path))

    def test_optional_missing_extra_basenames_are_declared(self):
        spec = tf.RootSpec("libs", self.root, mode="libraries", extra_basenames=("explicit.obj",))
        data = self.capture(spec).private_manifest()
        self.assertIn({"path": "explicit.obj", "kind": "absent-candidate"}, data["roots"][0]["records"])
        for bad in ("../escape.obj", "sub/file.lib", "*.lib", "file:stream"):
            with self.assertRaises(tf.FingerprintError):
                self.capture(tf.RootSpec("libs", self.root, mode="libraries", extra_basenames=(bad,)))

    def test_order_is_part_of_identity(self):
        other = self.base / "second"
        other.mkdir()
        second = tf.RootSpec("second-root", other)
        self.mismatch(self.capture(self.spec, second), self.capture(second, self.spec))

    def test_counts_bytes_depth_deadline_exhaustion(self):
        for bounds in [tf.Bounds(max_files=0), tf.Bounds(max_directories=0),
                       tf.Bounds(max_file_bytes=1), tf.Bounds(max_total_bytes=1),
                       tf.Bounds(max_entries=0), tf.Bounds(max_roots=0),
                       tf.Bounds(max_seconds=0)]:
            with self.subTest(bounds=bounds), self.assertRaises(tf.FingerprintError):
                self.capture(bounds=bounds)
        (self.root / "deep").mkdir()
        with self.assertRaises(tf.FingerprintError):
            self.capture(bounds=tf.Bounds(max_depth=0))
        counter = iter(range(1000))
        with self.assertRaises(tf.FingerprintError):
            self.capture(clock=lambda: float(next(counter)), bounds=tf.Bounds(max_seconds=4))
        with self.assertRaises(tf.FingerprintError):
            self.capture(bounds=tf.Bounds(max_roots=33))

    def test_job_total_allowance_consumed_by_failure(self):
        allowance = tf.PassAllowance(max_seconds=5)
        count = iter(range(1000))
        with self.assertRaises(tf.FingerprintError):
            self.capture(allowance=allowance, clock=lambda: float(next(count)))
        self.assertGreaterEqual(allowance.used_seconds, 5)
        with self.assertRaises(tf.FingerprintError):
            self.capture(allowance=allowance)

    def test_growing_file_stops_without_partial_digest(self):
        original = tf._NativeHandles.read_file
        def grow(handles, path, before):
            path.write_bytes(path.read_bytes() + b"growth")
            return original(handles, path, before)
        with patch.object(tf._NativeHandles, "read_file", grow):
            with self.assertRaises(tf.FingerprintError):
                self.capture()

    def test_directory_addition_between_pass_and_recheck_blocks(self):
        original = tf._scan
        calls = 0
        def added(path, spec, budget):
            nonlocal calls
            calls += 1
            if calls == 2:
                (path / "new").write_bytes(b"new")
            return original(path, spec, budget)
        with patch.object(tf, "_scan", added):
            with self.assertRaises(tf.FingerprintError):
                self.capture()

    def test_file_to_directory_swap_blocks(self):
        original = tf._NativeHandles.read_file
        def swap(handles, path, before):
            path.unlink()
            path.mkdir()
            return original(handles, path, before)
        with patch.object(tf._NativeHandles, "read_file", swap):
            with self.assertRaises(tf.FingerprintError):
                self.capture()

    def test_hardlink_aliases_rejected(self):
        try:
            os.link(self.header, self.root / "alias")
        except OSError:
            self.skipTest("hardlink creation unavailable")
        with self.assertRaises(tf.FingerprintError):
            self.capture()

    def test_timestamp_selection_policy_cannot_silently_change(self):
        with self.assertRaises(tf.FingerprintError):
            self.capture(tf.RootSpec("msvc-include", self.root, compare_mtime=False))
        regular = self.capture(tf.RootSpec("libs", self.root, mode="libraries"))
        weakened = self.capture(tf.RootSpec("libs", self.root, mode="libraries", compare_mtime=False))
        self.mismatch(regular, weakened)

    def test_full_pass_is_repeated_without_mtime_cache(self):
        original = tf._NativeHandles.read_file
        calls = []
        def tracked(handles, path, before):
            calls.append(path.name)
            return original(handles, path, before)
        with patch.object(tf._NativeHandles, "read_file", tracked):
            self.capture()
            self.capture()
        self.assertEqual(calls, ["vector", "vector"])

    def test_explicit_size_and_version_pins(self):
        with self.assertRaises(tf.FingerprintError):
            tf.capture_inventory([], [tf.FileSpec("tool", self.header, expected_size=999)])
        first = tf.capture_inventory([], [tf.FileSpec("tool", self.header, version="22.1.7")])
        second = tf.capture_inventory([], [tf.FileSpec("tool", self.header, version="22.1.8")])
        self.mismatch(first, second)

    def test_optional_candidate_policy_part_of_identity(self):
        first = self.capture(tf.RootSpec("libs", self.root, mode="libraries"))
        second = self.capture(tf.RootSpec("libs", self.root, mode="libraries", extra_basenames=("a.obj",)))
        self.mismatch(first, second)

    def test_misplaced_declaration_types_rejected(self):
        with self.assertRaises(tf.FingerprintError):
            tf.capture_inventory([], [self.spec])
        with self.assertRaises(tf.FingerprintError):
            tf.capture_inventory([tf.FileSpec("tool", self.header)])

    def test_empty_inventory_and_duplicate_declarations_rejected(self):
        with self.assertRaises(tf.FingerprintError):
            tf.capture_inventory([])
        with self.assertRaises(tf.FingerprintError):
            self.capture(self.spec, self.spec)

    def test_public_dict_round_trip(self):
        inv = self.capture()
        inv.assert_matches(json.loads(json.dumps(inv.public_summary())))
        bad = inv.public_summary()
        bad["roots"][0]["file_count"] += 1
        with self.assertRaises(tf.FingerprintError):
            inv.assert_matches(bad)


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = [("verified-tools", self.tmp.name)]

    def test_reject_injections_without_secret_echo(self):
        for key in ("CL", "_CL_", "LINK", "LIB", "EXTERNAL_INCLUDE", "CMAKE_CXX_FLAGS", "CMAKE_C_COMPILER", "CCC_OVERRIDE_OPTIONS", "CMAKE_AR", "CMAKE_LINKER", "CMAKE_CUDA_FLAGS"):
            with self.subTest(key=key):
                with self.assertRaises(tf.FingerprintError) as cm:
                    tf.controlled_environment({key: "SECRET_SENTINEL"}, self.path, {})
                self.assertNotIn("SECRET_SENTINEL", str(cm.exception))

    def test_from_empty_allowlist_omits_credentials_and_inherited_path(self):
        inherited = {"APPVEYOR_API_TOKEN": "SECRET_SENTINEL", "PATH": "bad-undeclared-root", "CL": ""}
        child, receipt = tf.controlled_environment(inherited, self.path, {"PYTHONNOUSERSITE": "1"})
        self.assertEqual(set(child), {"PATH", "PYTHONNOUSERSITE"})
        self.assertNotIn("SECRET_SENTINEL", json.dumps(receipt))
        self.assertNotIn("APPVEYOR", json.dumps(receipt))
        self.assertNotIn(self.tmp.name, json.dumps(receipt))
        self.assertNotIn("bad-undeclared-root", child["PATH"])

    def test_remove_is_explicit_policy(self):
        child, receipt = tf.controlled_environment({"CL": "SECRET_SENTINEL"}, self.path, {}, policy="remove")
        self.assertNotIn("CL", child)
        self.assertEqual(receipt["known_injection_status"]["CL"], "removed")
        self.assertNotIn("SECRET_SENTINEL", json.dumps(receipt))

    def test_git_fixed_acquisition_values_are_explicit_only(self):
        values = {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
        child, receipt = tf.controlled_environment({}, self.path, values)
        for name, value in values.items():
            self.assertEqual(child[name], value)
            self.assertEqual(receipt["effective_inputs"][name], value)
        inherited_only, _ = tf.controlled_environment(values, self.path, {})
        self.assertNotIn("GIT_TERMINAL_PROMPT", inherited_only)
        self.assertNotIn("GIT_LFS_SKIP_SMUDGE", inherited_only)
        for name, invalid in (("GIT_TERMINAL_PROMPT", "1"), ("GIT_LFS_SKIP_SMUDGE", "0"),
                              ("GIT_TERMINAL_PROMPT", "SECRET_SENTINEL"),
                              ("GIT_LFS_SKIP_SMUDGE", "")):
            with self.subTest(name=name, invalid=invalid):
                with self.assertRaises(tf.FingerprintError) as cm:
                    tf.controlled_environment({}, self.path, {name: invalid})
                self.assertNotIn("SECRET_SENTINEL", str(cm.exception))

    def test_clang_default_config_disable_is_fixed_explicit_input(self):
        child, receipt = tf.controlled_environment({}, self.path, {"CLANG_NO_DEFAULT_CONFIG": "1"})
        self.assertEqual(child["CLANG_NO_DEFAULT_CONFIG"], "1")
        self.assertEqual(receipt["effective_inputs"]["CLANG_NO_DEFAULT_CONFIG"], "1")
        # Existing strict inherited injection handling remains unchanged.
        with self.assertRaises(tf.FingerprintError):
            tf.controlled_environment({"CLANG_NO_DEFAULT_CONFIG": "1"}, self.path, {})
        for invalid in ("0", "", "true", "SECRET_SENTINEL"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(tf.FingerprintError) as cm:
                    tf.controlled_environment({}, self.path, {"CLANG_NO_DEFAULT_CONFIG": invalid})
                self.assertNotIn("SECRET_SENTINEL", str(cm.exception))

    def test_unapproved_effective_inputs_rejected(self):
        for key in ("CL", "APPVEYOR_API_TOKEN", "PATH", "INCLUDE"):
            with self.subTest(key=key), self.assertRaises(tf.FingerprintError):
                tf.controlled_environment({}, self.path, {key: "value"})

    def test_public_path_labels_required(self):
        with self.assertRaises(tf.FingerprintError):
            tf.controlled_environment({}, self.path, {"TEMP": self.tmp.name})
        child, receipt = tf.controlled_environment({}, self.path, {"TEMP": self.tmp.name}, effective_public_labels={"TEMP": "owned-temp"})
        self.assertEqual(child["TEMP"], self.tmp.name)
        self.assertEqual(receipt["effective_inputs"]["TEMP"], "owned-temp")
        self.assertNotIn(self.tmp.name, json.dumps(receipt))

    def test_environment_case_collisions_rejected(self):
        with self.assertRaises(tf.FingerprintError):
            tf.controlled_environment({"PATH": "x", "Path": "x"}, self.path, {})
        with self.assertRaises(tf.FingerprintError):
            tf.controlled_environment({}, self.path, {"TZ": "UTC", "tz": "UTC"})

    def test_path_order_and_duplicates(self):
        ordered = [("a", self.tmp.name), ("b", str(Path(self.tmp.name) / "bin"))]
        _, one = tf.controlled_environment({}, ordered, {})
        _, two = tf.controlled_environment({}, list(reversed(ordered)), {})
        self.assertNotEqual(one["identity_sha256"], two["identity_sha256"])
        with self.assertRaises(tf.FingerprintError):
            tf.controlled_environment({}, [*self.path, *self.path], {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
