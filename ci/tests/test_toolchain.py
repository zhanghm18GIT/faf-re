"""Offline unit tests: no downloads, Windows execution, or system mutation."""
import hashlib
import io
import tarfile
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('toolchain', Path(__file__).resolve().parents[1]/'toolchain.py')
t = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(t)


def archive_member(machine=0x8664, bigobj=False):
    payload = bytearray(20)
    struct.pack_into('<H', payload, 0, machine)
    if bigobj:
        struct.pack_into('<HHHH', payload, 0, 0, 0xffff, 2, machine)
    header = b'object.obj/     ' + b'0           ' + b'0     ' + b'0     ' + b'100644  ' + b'20        ' + b'`\n'
    assert len(header) == 60
    return b'!<arch>\n'+header+payload


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()
    def write(self, content, name='sample'):
        p = self.root/name; p.write_bytes(content); return p
    def test_hash_pass(self):
        p = self.write(b'hello'); t.checked_hash(p, hashlib.sha256(b'hello').hexdigest())
    def test_hash_fail(self):
        with self.assertRaises(t.Blocked): t.checked_hash(self.write(b'hello'), '0'*64)
    def test_pe_amd64(self):
        data = bytearray(88); data[:2] = b'MZ'; struct.pack_into('<I',data,60,64); data[64:68] = b'PE\0\0'; struct.pack_into('<H',data,68,0x8664)
        self.assertEqual(t.pe_machine(self.write(data)), 0x8664)
    def test_pe_truncated(self):
        for data in (b'', b'MZ', b'MZ'+b'\0'*62):
            with self.assertRaises(t.Blocked): t.pe_machine(self.write(data))
    def test_pe_out_of_bounds(self):
        data = bytearray(64); data[:2] = b'MZ'; struct.pack_into('<I',data,60,0xffffffff)
        with self.assertRaises(t.Blocked): t.pe_machine(self.write(data))
    def test_coff_amd64(self):
        self.assertEqual(t.inspect_coff_archive(self.write(archive_member()))['members'], 1)
    def test_coff_bigobj(self):
        self.assertEqual(t.inspect_coff_archive(self.write(archive_member(bigobj=True)))['machine'], 'AMD64')
    def test_coff_x86_rejected(self):
        with self.assertRaises(t.Blocked): t.inspect_coff_archive(self.write(archive_member(0x14c)))
    def test_coff_truncation(self):
        for data in (b'', b'!<arch>\n', archive_member()[:-1]):
            with self.assertRaises(t.Blocked): t.inspect_coff_archive(self.write(data))
    def test_owned_path(self):
        self.assertEqual(t.owned(self.root, 'tools/llvm'), self.root/'tools/llvm')
    def test_path_escapes(self):
        for name in ('../bad', '/bad', 'C:/bad', 'C:bad', '..\\bad', '\\\\server\\share', '.'):
            with self.assertRaises(t.Blocked, msg=name): t.owned(self.root, name)
    def test_symlink_escape(self):
        with tempfile.TemporaryDirectory() as outside:
            (self.root/'link').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(t.Blocked): t.owned(self.root, 'link/file')
    def test_missing_tool(self):
        with patch.object(t.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(t.Blocked, 'Required installed tool missing'): t.required_tool('missing.exe')
    def test_missing_runtime(self):
        with self.assertRaisesRegex(t.Blocked, 'd3dx9_43.dll'): t.legacy_runtimes(self.root)
    def test_nonwindows_provision_is_inert(self):
        with patch.object(t.os, 'name', 'posix'):
            with self.assertRaisesRegex(t.Blocked, 'requires Windows'): t.provision(object())
    def test_current_license_required(self):
        class C: authorizations = {}
        with self.assertRaisesRegex(t.Blocked, 'Current Windows SDK license'): t.provision_ucrt(C(), self.root, self.root)
    def test_signature_supported_failure_blocks(self):
        class C:
            def command(self, args, **kwargs):
                if kwargs['permit_failure'] if 'permit_failure' in kwargs else False: return '  verify  Verify package'
                raise t.Blocked('signature trust failure')
        with patch.object(t.shutil, 'which', return_value='dotnet.exe'):
            with self.assertRaisesRegex(t.Blocked, 'signature trust failure'): t.signature_check(C(), self.root/'a', self.root)
    def test_signature_unsupported_disclosed(self):
        with patch.object(t.shutil, 'which', return_value=None):
            self.assertIn('NOT_VERIFIED', t.signature_check(object(), self.root/'a', self.root))
    def test_actual_link_pass(self):
        lib = self.root/'libucrt.lib'
        cmd = f'lld-link /out:game.exe "{lib}" /nodefaultlib:libucrt.lib /nodefaultlib:ucrt.lib'
        self.assertEqual(len(t.validate_actual_links(cmd, self.root, lib, ['game.exe'])), 1)
    def test_engine_headless_scope_ignores_standalone_effect_scan(self):
        lib = self.root/'libucrt.lib'
        targets = ['faf_main.exe', 'headless_x64.exe', 'faf_sim_math_tests.exe',
                   'faf_math_dump.exe', 'faf_coroutine_tests.exe', 'faf_image_codec_tests.exe']
        log = '\n'.join(f'lld-link /out:{name} "{lib}" /NODEFAULTLIB:libucrt.lib /NODEFAULTLIB:ucrt.lib'
                        for name in targets)
        log += '\nlld-link /out:faf_effect_scan_tests.exe kernel32.lib'
        self.assertEqual(len(t.validate_actual_links(log, self.root, lib, targets)), 6)
        # Adding a non-consumer to this gate must not silently weaken it.
        with self.assertRaises(t.Blocked):
            t.validate_actual_links(log, self.root, lib, targets + ['faf_effect_scan_tests.exe'])
    def test_headless_still_requires_dynamic_ucrt_exclusion(self):
        lib = self.root/'libucrt.lib'
        log = f'lld-link /out:headless_x64.exe "{lib}" /NODEFAULTLIB:libucrt.lib'
        with self.assertRaisesRegex(t.Blocked, 'Default UCRT exclusions missing'):
            t.validate_actual_links(log, self.root, lib, ['headless_x64.exe'])
    def test_repeated_same_absolute_ucrt_is_not_alternate(self):
        lib = self.root/'libucrt.lib'
        log = f'lld-link /out:game.exe "{lib}" "{lib}" /NODEFAULTLIB:libucrt.lib /NODEFAULTLIB:ucrt.lib'
        self.assertEqual(len(t.validate_actual_links(log, self.root, lib, ['game.exe'])), 1)
    def test_actual_link_failures(self):
        lib = self.root/'libucrt.lib'
        cmd = f'lld-link /out:game.exe "{lib}" /nodefaultlib:libucrt.lib /nodefaultlib:ucrt.lib'
        for bad in (cmd+' C:/other/libucrt.lib', cmd+' ucrt.lib', cmd+' /defaultlib:libucrt.lib', cmd+' /wholearchive:libucrt.lib', cmd.replace('/nodefaultlib:ucrt.lib',''), cmd+'\n'+cmd):
            with self.assertRaises(t.Blocked): t.validate_actual_links(bad, self.root, lib, ['game.exe'])
    def test_rsp_pass(self):
        lib = self.root/'libucrt.lib'
        self.write(f'/out:game.exe "{lib}" /nodefaultlib:libucrt.lib /nodefaultlib:ucrt.lib'.encode(), 'game.rsp')
        self.assertEqual(len(t.validate_actual_links('lld-link @game.rsp', self.root, lib, ['game.exe'])), 1)
    def test_tar_escape_and_links(self):
        for name, kind in (('../bad', tarfile.REGTYPE), ('C:/bad', tarfile.REGTYPE), ('root/link', tarfile.SYMTYPE)):
            path = self.root/'input.tar.xz'
            with tarfile.open(path, 'w:xz') as tar:
                member = tarfile.TarInfo(name); member.type = kind
                tar.addfile(member, io.BytesIO(b''))
            with self.assertRaises(t.Blocked): t.validate_tar(path, self.root/'out')
    def test_tar_regular(self):
        path = self.root/'input.tar.xz'
        with tarfile.open(path, 'w:xz') as tar:
            member = tarfile.TarInfo('root/bin/test.exe'); member.size = 2
            tar.addfile(member, io.BytesIO(b'xx'))
        t.validate_tar(path, self.root/'out')
    def test_rsp_escape(self):
        with self.assertRaises(t.Blocked): t.expand_rsp('lld-link @../escape.rsp', self.root)


if __name__ == '__main__': unittest.main()
