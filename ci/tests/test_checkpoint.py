import dataclasses
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

# When installed as ci/tests/test_checkpoint.py, import ci/checkpoint.py.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import checkpoint as c


def coff(machine=0x8664, big=False):
    if big:
        head = struct.pack('<HHHHI', 0, 65535, 2, machine, 0) + c.BIGOBJ_ID + struct.pack('<IIIIIII', 0, 0, 0, 0, 1, 0, 0)
    else:
        head = struct.pack('<HHIIIHH', machine, 1, 0, 0, 0, 0, 0)
    return head + b'.text\0\0\0' + struct.pack('<IIIIIIHHI', 0, 0, 1, len(head)+40, 0, 0, 0, 0, 0x60000020) + b'\xc3'


def archive(data=None):
    data = coff() if data is None else data
    fields = [b'a.obj/         ', b'0           ', b'0     ', b'0     ', b'100644  ', str(len(data)).encode().ljust(10), b'`\n']
    fields[0] = b'a.obj/'.ljust(16)
    return b'!<arch>\n' + b''.join(fields) + data + (b'\n' if len(data) % 2 else b'')


def deps(paths, output=0, refs=(1,), version=4, mtime=123456789):
    data = b'# ninjadeps\n' + struct.pack('<I', version)
    for i, path in enumerate(paths):
        body = path.encode()
        body += b'\0' * (-len(body) % 4)
        body += struct.pack('<I', (~i) & 0xffffffff)
        data += struct.pack('<I', len(body)) + body
    body = struct.pack('<III', output, mtime & 0xffffffff, mtime >> 32) + b''.join(struct.pack('<I', v) for v in refs)
    return data + struct.pack('<I', len(body) | 0x80000000) + body


class TestCheckpoint(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source, self.build, self.gen = [self.base / name for name in ('source', 'build', 'generated')]
        for p in (self.source, self.build, self.gen):
            p.mkdir()
        self.source.joinpath('dep.c').write_bytes(b'int x;\n')
        self.source.joinpath('LICENSE').write_bytes(b'Example synthetic fixture only.\n')
        self.gen.joinpath('cfg.h').write_bytes(b'#define X 1\n')
        self.build.joinpath('dep.obj').write_bytes(coff())
        self.build.joinpath('dep.lib').write_bytes(archive())
        self.build.joinpath('.ninja_log').write_bytes(b'# ninja log v6\n0\t1\t123456789\tdep.obj\t1234\n0\t2\t123456789\tdep.lib\t4567\n')
        self.build.joinpath('.ninja_deps').write_bytes(deps(['dep.obj', str(self.source/'dep.c'), str(self.gen/'cfg.h')], refs=(1, 2)))
        self.payloads = (c.FileSpec('build', 'dep.obj', 'obj'), c.FileSpec('build', 'dep.lib', 'lib'), c.FileSpec('generated', 'cfg.h', 'header'), c.FileSpec('build', '.ninja_log', 'ninja_log'), c.FileSpec('build', '.ninja_deps', 'ninja_deps'), c.FileSpec('source', 'LICENSE', 'license'))
        self.inputs = (c.FileSpec('source', 'dep.c', 'source'), self.payloads[2])
        self.policy = c.Policy({'source': self.source, 'build': self.build, 'generated': self.gen}, {'source': 'source', 'build': 'build', 'generated': 'generated'}, self.payloads, self.inputs, frozenset({str(self.source/'dep.c'), str(self.gen/'cfg.h')}), frozenset({'dep.obj', 'dep.lib'}), tuple(map(str, (self.source, self.build, self.gen))), str(self.build))
        self.meta = {'product': 'fixed-source', 'external_inventory': 'separately-checked', 'source_root': str(self.source)}
        self.zip = self.base/'checkpoint.zip'
        self.receipt = c.seal_checkpoint(self.zip, self.policy, self.meta)

    def validate(self, policy=None):
        return c.validate_checkpoint(self.zip, policy or self.policy, self.receipt['sha256'], self.receipt['bytes'], self.meta)

    def restore(self):
        return c.restore_checkpoint(self.zip, self.policy, self.receipt['sha256'], self.receipt['bytes'], self.meta)

    def rewrite(self, mutate):
        with zipfile.ZipFile(self.zip) as z:
            entries = [(i, z.read(i)) for i in z.infolist()]
        entries = mutate(entries)
        with zipfile.ZipFile(self.zip, 'w') as z:
            for i, data in entries:
                z.writestr(i, data)
        self.receipt = {'bytes': self.zip.stat().st_size, 'sha256': hashlib.sha256(self.zip.read_bytes()).hexdigest()}

    def test_exact_selected_external_file_declaration(self):
        ninja=r'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
        policy=dataclasses.replace(self.policy,allowed_log_inputs=self.policy.allowed_log_inputs|{ninja})
        with self.assertRaises(c.CheckpointError):c.validate_policy(policy,self.meta)
        policy=dataclasses.replace(policy,approved_path_files=(ninja,))
        result=c.validate_policy(policy,self.meta)
        self.assertEqual(result['state'],'PASS_DECLARATIONS_ONLY')
        self.assertEqual(result['exact_external_file_count'],1)
        self.assertFalse(any(x.relpath.lower().endswith('.exe') for x in policy.payloads))

    def test_exact_ninja_absolute_relative_and_aliases(self):
        ninja=r'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
        policy=dataclasses.replace(self.policy,approved_path_files=(ninja,),log_base_root=r'C:\faf-re-staged\recipe\build')
        relative=r'..\..\..\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
        for value in [ninja,relative,ninja.upper(),ninja.replace('\\','/')]:c.approved_path(value,policy)
        for value in [ninja+'.bak',ninja+'\\child',ninja.replace('ninja.exe','other.exe'),relative.replace('ninja.exe','..\\other.exe'),ninja.rsplit('\\',1)[0]]:
            with self.assertRaises(c.CheckpointError):c.approved_path(value,policy)

    def test_drive_relative_exact_file_is_not_absolute(self):
        with self.assertRaises(c.CheckpointError):c.validate_policy(dataclasses.replace(self.policy,approved_path_files=('C:ninja.exe',)))

    def test_policy_validation_precedes_payload_reads(self):
        bad=dataclasses.replace(self.policy,allowed_log_inputs=self.policy.allowed_log_inputs|{r'C:\unapproved\tool.exe'})
        with mock.patch.object(c,'_read') as read:
            with self.assertRaises(c.CheckpointError):c.validate_policy(bad,self.meta)
            read.assert_not_called()

    def test_roundtrip_restores_ns_and_exact_content(self):
        original = self.validate()
        for spec in self.policy.inputs:
            p = self.policy.owned_roots[spec.root]/spec.relpath
            os.utime(p, ns=(9876543210, 9876543210))
        for name in ('dep.obj', 'dep.lib', '.ninja_log', '.ninja_deps'):
            self.build.joinpath(name).unlink()
        self.assertEqual(self.restore(), original)
        for section in ('inputs', 'payloads'):
            for e in original[section]:
                root, rel = e['member'].split('/', 1)
                self.assertEqual((self.policy.owned_roots[root]/rel).stat().st_mtime_ns, e['mtime_ns'])

    def test_bigobj_and_archive_valid(self):
        self.assertEqual(c.inspect_coff(coff(big=True))['format'], 'bigobj')
        self.assertEqual(c.inspect_archive(archive(coff(big=True)))['objects'], 1)

    def test_source_drift_prevents_all_writes(self):
        self.source.joinpath('dep.c').write_bytes(b'int y;\n')
        self.build.joinpath('dep.obj').write_bytes(b'untouched')
        with self.assertRaises(c.CheckpointError):
            self.restore()
        self.assertEqual(self.build.joinpath('dep.obj').read_bytes(), b'untouched')

    def test_header_drift_prevents_all_writes(self):
        self.gen.joinpath('cfg.h').write_bytes(b'#define X 2\n')
        with self.assertRaises(c.CheckpointError):
            self.restore()

    def test_outer_hash_and_size(self):
        with self.assertRaises(c.CheckpointError):
            c.validate_checkpoint(self.zip, self.policy, '0'*64, self.receipt['bytes'], self.meta)
        with self.assertRaises(c.CheckpointError):
            c.validate_checkpoint(self.zip, self.policy, self.receipt['sha256'], self.receipt['bytes']+1, self.meta)

    def test_output_tamper(self):
        self.rewrite(lambda es: [(i, b'bad' if i.filename.endswith('.obj') else d) for i,d in es])
        with self.assertRaises(c.CheckpointError):
            self.validate()

    def test_manifest_mtime_invalid(self):
        def change(es):
            for i,d in es:
                if i.filename == c.MANIFEST:
                    m = json.loads(d); m['inputs'][0]['mtime_ns'] = -1; d = json.dumps(m).encode()
                yield i,d
        self.rewrite(change)
        with self.assertRaises(c.CheckpointError):
            self.validate()

    def test_timestamp_readback_failure(self):
        os.utime(self.source/'dep.c', ns=(10, 10))
        with mock.patch.object(c.os, 'utime'):
            with self.assertRaisesRegex(c.CheckpointError, 'mtime_ns'):
                self.restore()

    def test_traversal_absolute_and_reserved_names(self):
        for name in ('../evil', '/abs', 'C:/abs', 'a/../b', 'a\\b', 'a:b', 'a//b', 'CON.txt', 'a./b', 'x/.git/config'):
            with self.subTest(name=name), self.assertRaises(c.CheckpointError):
                c.relative_name(name)

    def test_unknown_zip_path(self):
        self.rewrite(lambda es: [(c._zip_info('../bad'), es[0][1]), *es[1:]])
        with self.assertRaises(c.CheckpointError):
            self.validate()

    def test_case_duplicate(self):
        self.rewrite(lambda es: [es[0], (c._zip_info('build/DEP.obj'), es[1][1]), *es[2:]])
        with self.assertRaises(c.CheckpointError):
            self.validate()

    def test_size_bound(self):
        tiny = dataclasses.replace(self.policy, limits=dataclasses.replace(self.policy.limits, total_bytes=10))
        with self.assertRaises(c.CheckpointError):
            self.validate(tiny)

    def test_link_and_hardlink_rejection(self):
        self.source.joinpath('dep.c').unlink()
        self.source.joinpath('dep.c').symlink_to(self.source/'LICENSE')
        with self.assertRaises(c.CheckpointError):
            self.validate()
        self.source.joinpath('dep.c').unlink()
        os.link(self.source/'LICENSE', self.source/'dep.c')
        with self.assertRaises(c.CheckpointError):
            self.validate()

    def test_zip_symlink(self):
        def change(es):
            for i,d in es:
                if i.filename == 'build/dep.obj':
                    i.external_attr = 0o120777 << 16
                yield i,d
        self.rewrite(change)
        with self.assertRaises(c.CheckpointError):
            self.validate()

    def test_wrong_machine_and_import_obj(self):
        for data in (coff(machine=0x14c), b'MZ'+b'\0'*100, struct.pack('<HHHH', 0, 65535, 0, 0x8664)+b'\0'*100, coff()[:-1], coff(big=True)[:20]):
            with self.subTest(data=data[:8]), self.assertRaises(c.CheckpointError):
                c.inspect_coff(data)
        with self.assertRaises(c.CheckpointError):
            c.inspect_archive(archive(coff(machine=0x14c)))
        with self.assertRaises(c.CheckpointError):
            c.inspect_archive(b'!<thin>\n')

    def test_log_version_unknown_output_and_record(self):
        for data in (b'# ninja log v5\n', b'# ninja log v6\nunknown\n', b'# ninja log v6\n0\t1\t3\tevil.obj\tf\n', b'# ninja log v6\n1\t0\t3\tdep.obj\tf\n'):
            with self.subTest(data=data), self.assertRaises(c.CheckpointError):
                c.validate_ninja_log(data, self.policy)

    def test_deps_version_unknown_record_and_paths(self):
        paths = ['dep.obj', str(self.source/'dep.c')]
        samples = [deps(paths, version=3), deps(paths, refs=(99,)), deps(paths, output=1), deps(['evil.obj', paths[1]]), deps(paths)[:-1], b'# ninjadeps\n'+struct.pack('<II', 4, 0), deps(paths, mtime=2**63)]
        for data in samples:
            with self.subTest(data=data[-20:]), self.assertRaises(c.CheckpointError):
                c.validate_ninja_deps(data, self.policy)

    def test_external_source_timestamp_root_forbidden(self):
        bad = dataclasses.replace(self.policy, inputs=(c.FileSpec('build', 'dep.obj', 'source'),))
        with self.assertRaises(c.CheckpointError):
            self.validate(bad)

    def test_metadata_and_embedded_user_paths(self):
        with self.assertRaises(c.CheckpointError):
            c.metadata_paths({'private': 'C:\\Users\\Alice\\x'}, self.policy)
        with self.assertRaises(c.CheckpointError):
            c.inspect_public_paths(b'\0C:\\Users\\Alice\\x\0', self.policy)
        with self.assertRaises(c.CheckpointError):
            c.inspect_public_paths('C:\\Users\\Alice\\x'.encode('utf-16le'), self.policy)

    def test_boundary_receipt_veto(self):
        def deny(phase, spec, content):
            if phase == 'manifest':
                raise c.CheckpointError('missing source/license receipt')
        with self.assertRaisesRegex(c.CheckpointError, 'license'):
            c.validate_checkpoint(self.zip, self.policy, self.receipt['sha256'], self.receipt['bytes'], self.meta, deny)


    def test_source_material_drift(self):
        self.source.joinpath('LICENSE').write_bytes(b'changed license material')
        with self.assertRaises(c.CheckpointError):
            self.restore()

    def test_generated_root_nested_in_build(self):
        nested = self.build/'gen'
        self.gen.rename(nested)
        os.utime(nested/'cfg.h', ns=(1, 1))
        policy = dataclasses.replace(self.policy,
            owned_roots={**self.policy.owned_roots, 'generated': nested},
            allowed_log_inputs=frozenset({str(self.source/'dep.c'), str(nested/'cfg.h')}),
            approved_path_roots=(str(self.source), str(self.build)))
        self.build.joinpath('.ninja_deps').write_bytes(deps(['dep.obj', str(self.source/'dep.c'), str(nested/'cfg.h')], refs=(1, 2)))
        out = self.base/'nested.zip'
        receipt = c.seal_checkpoint(out, policy, self.meta)
        c.restore_checkpoint(out, policy, receipt['sha256'], receipt['bytes'], self.meta)
        self.assertEqual((nested/'cfg.h').stat().st_mtime_ns, 1)

    def test_coff_sections_and_symbols_bounds(self):
        data = bytearray(coff())
        struct.pack_into('<I', data, 20+20, 999999)
        with self.assertRaises(c.CheckpointError):
            c.inspect_coff(data)
        data = bytearray(coff())
        struct.pack_into('<II', data, 8, 60, 999999)
        with self.assertRaises(c.CheckpointError):
            c.inspect_coff(data)

    def test_archive_unknown_member_and_symbol_offset(self):
        bad = archive().replace(b'a.obj/', b'a.exe/', 1)
        with self.assertRaises(c.CheckpointError):
            c.inspect_archive(bad)
        symbol = struct.pack('>II', 1, 999999) + b'x\0'
        head = b'/'.ljust(16)+b'0'.ljust(12)+b'0'.ljust(6)+b'0'.ljust(6)+b'0'.ljust(8)+str(len(symbol)).encode().ljust(10)+b'`\n'
        with self.assertRaises(c.CheckpointError):
            c.inspect_archive(b'!<arch>\n'+head+symbol+archive()[8:])

    def test_dep_duplicate_checksum_padding(self):
        good = deps(['dep.obj', str(self.source/'dep.c')])
        bad_checksum = bytearray(good)
        size = struct.unpack_from('<I', good, 16)[0]
        struct.pack_into('<I', bad_checksum, 20+size-4, 0)
        for data in (bytes(bad_checksum), deps(['dep.obj', 'dep.obj']), good + struct.pack('<I', 0x80000004)+b'\0'*4):
            with self.assertRaises(c.CheckpointError):
                c.validate_ninja_deps(data, self.policy)



    def test_http_https_urls_are_not_drive_paths(self):
        for value in ('https://ffmpeg.org/', 'http://www.microsoft.com/', 'ftp://public.example/test', 'See https://ffmpeg.org/ for details.'):
            for encoding in ('utf-8', 'utf-16le'):
                with self.subTest(value=value, encoding=encoding):
                    c.inspect_public_paths(value.encode(encoding), self.policy)
            c.metadata_paths({'source_url': value}, self.policy)
        c._content(c.FileSpec('source', 'LICENSE', 'license'), b'Copyright. https://ffmpeg.org/ http://www.microsoft.com/\n', self.policy)

    def test_coff_binary_url_strings(self):
        for encoding in ('utf-8', 'utf-16le'):
            text = 'https://ffmpeg.org/ http://www.microsoft.com/'.encode(encoding)+b'\0\0'
            data = bytearray(coff()[:-1]+text)
            struct.pack_into('<I', data, 20+16, len(text))
            self.assertEqual(c.inspect_coff(data)['machine'], 'AMD64')
            c._content(c.FileSpec('build', 'dep.obj', 'obj'), bytes(data), self.policy)

    def test_real_drive_and_unc_paths_still_rejected(self):
        for path in ('C:\\Users\\Alice\\secret', 'D:/private/file', '\\\\server\\share\\secret', 'file:C:/Users/Alice/secret', 'quoted "C:/private/x"'):
            for encoding in ('utf-8', 'utf-16le'):
                with self.subTest(path=path, encoding=encoding), self.assertRaises(c.CheckpointError):
                    c.inspect_public_paths(path.encode(encoding), self.policy)
        windows = dataclasses.replace(self.policy, approved_path_roots=('C:\\stable\\source', '\\\\buildserver\\approved'))
        c.inspect_public_paths(b'C:\\stable\\source\\code.cpp\0', windows)
        c.inspect_public_paths(b'\\\\buildserver\\approved\\code.cpp\0', windows)

    def test_material_pdf_and_legacy_bytes_roundtrip(self):
        files = {
            'WildMagicLicense.pdf': b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Length 8 >>\nstream\n\0public\xff\nendstream\nendobj\n%%EOF\n',
            'legacy_source.c': b'/* Copyright \xa9 pinned author. https://ffmpeg.org/ Example C:\\example\\file */\nint value;\n',
        }
        specs = []
        for name, data in files.items():
            (self.source/name).write_bytes(data)
            specs.append(c.FileSpec('source', name, 'material'))
        policy = dataclasses.replace(self.policy, payloads=self.policy.payloads+tuple(specs), inputs=self.policy.inputs+tuple(specs))
        out = self.base/'public-material.zip'
        metadata = {**self.meta, 'material_inventory': 'driver-pinned-public-source-receipt'}
        receipt = c.seal_checkpoint(out, policy, metadata)
        for name in files:
            os.utime(self.source/name, ns=(7, 7))
        result = c.restore_checkpoint(out, policy, receipt['sha256'], receipt['bytes'], metadata)
        for name, data in files.items():
            self.assertEqual((self.source/name).read_bytes(), data)
        self.assertEqual(sum(e['kind'] == 'material' for e in result['payloads']), 2)

    def test_material_does_not_bypass_binary_or_archive_gate(self):
        spec = c.FileSpec('source', 'renamed-license.pdf', 'material')
        signatures = [b'MZfake', coff(), coff(big=True), archive(), b'!<thin>\n', b'PK\x03\x04', b'\x7fELF', b'Microsoft C/C++ MSF 7.00', b'MDMP', b'\x1f\x8b', b'MSCF', b'7z\xbc\xaf\x27\x1c', b'\0'*257+b'ustar']
        for data in signatures:
            with self.subTest(data=data[:12]), self.assertRaises(c.CheckpointError):
                c._content(spec, data, self.policy)
        for suffix in ('.dll', '.exe', '.lib', '.obj', '.pdb', '.zip', '.sys', '.tar', '.log'):
            with self.subTest(suffix=suffix), self.assertRaises(c.CheckpointError):
                c._content(c.FileSpec('source', 'public'+suffix, 'material'), b'not really binary', self.policy)

    def test_public_material_literal_paths_and_size_bound(self):
        spec = c.FileSpec('source', 'public.pdf', 'material')
        c._content(spec, b'%PDF-1.4\nC:\\example\\file\0', self.policy)
        c._content(c.FileSpec('source', 'sample.c', 'material'), b'/* C:\\example\\file and \\\\example\\share */', self.policy)
        policy = dataclasses.replace(self.policy, limits=dataclasses.replace(self.policy.limits, member_bytes=2))
        with self.assertRaises(c.CheckpointError):
            c._content(spec, b'123', policy)
        with self.assertRaises(c.CheckpointError):
            c.inspect_public_paths(b'123', policy)


    def test_nonstring_machine_bytes_are_not_windows_path(self):
        payload = b'\x01C:\\\x80\x02\xff'
        data = bytearray(coff()[:-1]+payload)
        struct.pack_into('<I', data, 20+16, len(payload))
        self.assertEqual(c.inspect_coff(data)['machine'], 'AMD64')
        c._content(c.FileSpec('build', 'dep.obj', 'obj'), bytes(data), self.policy)

    def test_chunked_path_scan_edges_and_no_full_decode(self):
        class NoWholeDecode(bytes):
            def decode(self, *args, **kwargs):
                raise AssertionError('whole-member decode forbidden')
        with mock.patch.object(c, 'SCAN_CHUNK_BYTES', 32):
            urls = NoWholeDecode((b'https://ffmpeg.org/ http://www.microsoft.com/ '+b'x'*31)*40)
            c.inspect_public_paths(urls, self.policy)
            for pad in range(30, 34):
                for encoding in ('utf-8', 'utf-16le'):
                    data = NoWholeDecode(b'\x01'*pad + 'C:\\private\\secret'.encode(encoding)+b'\0\0')
                    with self.assertRaises(c.CheckpointError):
                        c.inspect_public_paths(data, self.policy)

    def test_reviewed_configured_limits_without_large_allocations(self):
        limits = dataclasses.replace(self.policy.limits, member_bytes=536870912, total_bytes=3221225472, archive_bytes=400000000)
        policy = dataclasses.replace(self.policy, limits=limits)
        self.validate(policy)
        for field, maximum in [('member_bytes', 536870912), ('total_bytes', 3221225472), ('archive_bytes', 400000000)]:
            bad = dataclasses.replace(policy, limits=dataclasses.replace(limits, **{field: maximum+1}))
            with self.subTest(field=field), self.assertRaises(c.CheckpointError):
                self.validate(bad)

    def test_scaled_exact_member_total_and_archive_boundaries(self):
        maximum = max((self.policy.owned_roots[s.root]/s.relpath).stat().st_size for s in self.policy.payloads+self.policy.inputs)
        with zipfile.ZipFile(self.zip) as z:
            total = sum(i.file_size for i in z.infolist())
        exact = dataclasses.replace(self.policy.limits, member_bytes=maximum, total_bytes=total, archive_bytes=self.receipt['bytes'])
        self.validate(dataclasses.replace(self.policy, limits=exact))
        for field, value in [('member_bytes', maximum-1), ('total_bytes', total-1), ('archive_bytes', self.receipt['bytes']-1)]:
            bad = dataclasses.replace(self.policy, limits=dataclasses.replace(exact, **{field:value}))
            with self.subTest(field=field), self.assertRaises(c.CheckpointError):
                self.validate(bad)
        # Sealing also accepts the exact largest source/output size and refuses
        # one byte less, with small fixtures rather than 512 MiB allocations.
        seal_policy = dataclasses.replace(self.policy, limits=dataclasses.replace(self.policy.limits, member_bytes=maximum))
        c.seal_checkpoint(self.base/'exact-bound.zip', seal_policy, self.meta)
        too_small = dataclasses.replace(seal_policy, limits=dataclasses.replace(seal_policy.limits, member_bytes=maximum-1))
        with self.assertRaises(c.CheckpointError):
            c.seal_checkpoint(self.base/'too-small.zip', too_small, self.meta)


if __name__ == '__main__':
    unittest.main(verbosity=2)
