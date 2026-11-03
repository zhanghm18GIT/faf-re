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

    def test_reviewed_manifest_capacity_ceiling(self):
        c.validate_policy(dataclasses.replace(self.policy, limits=dataclasses.replace(self.policy.limits, manifest_bytes=25_165_824)))
        with self.assertRaises(c.CheckpointError):
            c.validate_policy(dataclasses.replace(self.policy, limits=dataclasses.replace(self.policy.limits, manifest_bytes=25_165_825)))

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


    def test_available_preflight_counts_and_deferred_outputs(self):
        events=[]
        for name in ('dep.obj','dep.lib','.ninja_log','.ninja_deps'):
            (self.build/name).write_bytes(b'INVALID FUTURE OUTPUT')
        before=sorted(str(p.relative_to(self.base)) for p in self.base.rglob('*'))
        receipt=c.preflight_available_content(self.policy,self.meta,lambda phase,spec,data:events.append((phase,spec.member if spec else None)))
        self.assertEqual(receipt['state'],'CHECKED_AVAILABLE_CONTENT_ONLY')
        self.assertEqual(receipt['input_count'],2)
        self.assertEqual(receipt['available_payload_count'],2)
        self.assertEqual(receipt['checked_item_count'],4)
        self.assertEqual(receipt['unique_checked_member_count'],3)
        self.assertEqual(receipt['deferred_payload_count'],4)
        self.assertEqual(receipt['deferred_by_kind'],dict(obj=1,lib=1,ninja_log=1,ninja_deps=1))
        self.assertEqual(events[0],('preflight-begin',None))
        self.assertEqual(events[-1],('preflight-end',None))
        self.assertEqual(len(events),6)
        self.assertEqual(receipt['outer_zip_validation'],'NOT_RUN')
        self.assertEqual(len(receipt['checked_identity_sha256']),64)
        self.assertNotIn(str(self.base),json.dumps(receipt))
        self.assertEqual(before,sorted(str(p.relative_to(self.base)) for p in self.base.rglob('*')))
        with self.assertRaises(c.CheckpointError):
            c.seal_checkpoint(self.base/'bad-after-preflight.zip',self.policy,self.meta)

    def test_available_preflight_all_input_kinds_and_inl(self):
        self.assertIn('.inl',c.HEADER_SUFFIXES)
        p=self.gen/'inline.inl';p.write_bytes(b'inline int value() { return 1; }\n')
        h=c.FileSpec('generated','inline.inl','header')
        p=self.source/'legacy.txt';p.write_bytes(b'legacy \xa9'.replace(b'\\xa9',b'\xa9'))
        material=c.FileSpec('source','legacy.txt','material')
        policy=dataclasses.replace(self.policy,inputs=self.policy.inputs+(h,material),payloads=self.policy.payloads+(h,material))
        receipt=c.preflight_available_content(policy,self.meta)
        self.assertEqual(receipt['input_count'],4)
        out=self.base/'inl.zip';r=c.seal_checkpoint(out,policy,self.meta)
        c.restore_checkpoint(out,policy,r['sha256'],r['bytes'],self.meta)

    def test_every_magic_has_sanitized_member_diagnostic(self):
        for name,offset,magic in c.MATERIAL_SIGNATURES:
            data=b'x'*offset+magic+b'PRIVATE_SENTINEL_DO_NOT_ECHO'
            (self.source/'dep.c').write_bytes(data)
            with self.subTest(name=name),self.assertRaises(c.CheckpointError) as caught:
                c.preflight_available_content(self.policy,self.meta)
            report=json.loads(str(caught.exception))
            self.assertEqual(report['signature_id'],name)
            self.assertEqual(report['offset'],offset)
            self.assertEqual(report['magic_hex'],magic.hex())
            self.assertEqual(report['member'],'source/dep.c')
            self.assertEqual(report['kind'],'source')
            self.assertEqual(report['bytes'],len(data))
            self.assertEqual(report['sha256'],hashlib.sha256(data).hexdigest())
            self.assertEqual(report['reason_code'],'material_magic_candidate')
            self.assertNotIn('PRIVATE_SENTINEL_DO_NOT_ECHO',str(caught.exception))
            self.assertNotIn(str(self.base),str(caught.exception))

    def test_coff_candidate_context_and_seal_context(self):
        data=coff();(self.source/'dep.c').write_bytes(data)
        with self.assertRaises(c.CheckpointError) as caught:
            c.seal_checkpoint(self.base/'no.zip',self.policy,self.meta)
        report=json.loads(str(caught.exception))
        self.assertEqual(report['phase'],'seal-input')
        self.assertEqual(report['signature_id'],'coff_6486')
        self.assertEqual(report['magic_hex'],'6486')
        self.assertEqual(report['reason_code'],'coff_machine_candidate')
        self.assertFalse((self.base/'no.zip').exists())

    def test_available_missing_material_context(self):
        (self.source/'LICENSE').unlink()
        with self.assertRaises(c.CheckpointError) as caught:
            c.preflight_available_content(self.policy,self.meta)
        report=json.loads(str(caught.exception))
        self.assertEqual(report['member'],'source/LICENSE')
        self.assertEqual(report['reason_code'],'member_read_failed')
        self.assertNotIn('sha256',report)
        self.assertNotIn(str(self.base),str(caught.exception))

    def test_provenance_and_baseline_error_redaction(self):
        for fail_phase in ('preflight-begin','preflight-inputs','preflight-payloads','preflight-end'):
            def callback(phase,spec,data):
                if phase==fail_phase:
                    raise RuntimeError(str(self.base)+'/secret PRIVATE_CONTENT')
            with self.subTest(phase=fail_phase),self.assertRaises(c.CheckpointError) as caught:
                c.preflight_available_content(self.policy,self.meta,callback)
            report=json.loads(str(caught.exception))
            self.assertEqual(report['reason_code'],'provenance_or_license_failed')
            self.assertNotIn(str(self.base),str(caught.exception))
            self.assertNotIn('PRIVATE_CONTENT',str(caught.exception))

    def test_material_receipt_mismatch_and_baseline_drift(self):
        def receipt(phase,spec,data):
            if spec is not None and spec.relpath=='LICENSE':
                raise c.CheckpointError('expected source receipt /private/do-not-echo')
        with self.assertRaises(c.CheckpointError) as caught:
            c.preflight_available_content(self.policy,self.meta,receipt)
        self.assertEqual(caught.exception.context['member'],'source/LICENSE')
        baseline=hashlib.sha256((self.source/'dep.c').read_bytes()).hexdigest()
        def drift(phase,spec,data):
            if spec is not None and spec.member=='source/dep.c':
                (self.source/'dep.c').write_bytes(b'changed during scan')
            if phase=='preflight-end' and hashlib.sha256((self.source/'dep.c').read_bytes()).hexdigest()!=baseline:
                raise c.CheckpointError('baseline drift')
        with self.assertRaises(c.CheckpointError):
            c.preflight_available_content(self.policy,self.meta,drift)

    def test_manifest_upper_and_available_total_bounds(self):
        r=c.preflight_available_content(self.policy,self.meta)
        with zipfile.ZipFile(self.zip) as z:
            self.assertGreaterEqual(r['manifest_bytes_upper'],len(z.read(c.MANIFEST)))
        exact=dataclasses.replace(self.policy,limits=dataclasses.replace(self.policy.limits,manifest_bytes=r['manifest_bytes_upper'],total_bytes=r['available_total_bytes_upper']))
        c.preflight_available_content(exact,self.meta)
        for field,n in [('manifest_bytes',r['manifest_bytes_upper']-1),('total_bytes',r['available_total_bytes_upper']-1),('members',len(self.policy.payloads))]:
            with self.subTest(field=field),self.assertRaises(c.CheckpointError):
                c.preflight_available_content(dataclasses.replace(self.policy,limits=dataclasses.replace(self.policy.limits,**{field:n})),self.meta)
        with self.assertRaises(c.CheckpointError) as caught:
            c.preflight_available_content(self.policy,{'secret_path':'C:/Users/Private/DoNotEcho'})
        self.assertNotIn('DoNotEcho',str(caught.exception))

    def text_pin_policy(self,data=b'$! public VMS build script\n$ exit\n'):
        (self.source/'build.com').write_bytes(data)
        spec=c.FileSpec('source','build.com','material')
        policy=dataclasses.replace(self.policy,inputs=self.policy.inputs+(spec,),payloads=self.policy.payloads+(spec,),material_text_pins={spec.member:hashlib.sha256(data).hexdigest()})
        return policy,spec

    def test_exact_text_pin_roundtrip_and_drift(self):
        policy,spec=self.text_pin_policy()
        c.preflight_available_content(policy,self.meta)
        out=self.base/'vms.zip';receipt=c.seal_checkpoint(out,policy,self.meta)
        c.restore_checkpoint(out,policy,receipt['sha256'],receipt['bytes'],self.meta)
        (self.source/'build.com').write_bytes(b'$ changed')
        with self.assertRaises(c.CheckpointError) as caught:
            c.seal_checkpoint(self.base/'vms-drift.zip',policy,self.meta)
        self.assertEqual(caught.exception.context['reason_code'],'material_text_pin_mismatch')
        with self.assertRaises(c.CheckpointError) as caught:
            c.restore_checkpoint(out,policy,receipt['sha256'],receipt['bytes'],self.meta)
        self.assertEqual(caught.exception.context['member'],spec.member)
        self.assertEqual(caught.exception.context['reason_code'],'member_identity_mismatch')

    def test_unlisted_com_and_wrong_pin_denied(self):
        policy,spec=self.text_pin_policy()
        for pins in ({},{spec.member:'0'*64}):
            with self.subTest(pins=pins),self.assertRaises(c.CheckpointError):
                c.preflight_available_content(dataclasses.replace(policy,material_text_pins=pins),self.meta)
        (self.source/'other.com').write_bytes((self.source/'build.com').read_bytes())
        other=c.FileSpec('source','other.com','material')
        with self.assertRaises(c.CheckpointError):
            c.preflight_available_content(dataclasses.replace(policy,inputs=policy.inputs+(other,)),self.meta)

    def test_exact_pin_never_relaxes_signature_or_encoding(self):
        for data in (b'MZplain text',b'PK\x03\x04',b'$ nul\0',b'$ legacy \xff',coff(),archive()):
            data=data.replace(b'\\x03',b'\x03').replace(b'\\x04',b'\x04').replace(b'\\0',b'\0').replace(b'\\xff',b'\xff')
            policy,_=self.text_pin_policy(data)
            with self.subTest(data=data[:8]),self.assertRaises(c.CheckpointError):
                c.preflight_available_content(policy,self.meta)

    def test_material_pin_declarations_bounded_and_exact(self):
        policy,spec=self.text_pin_policy()
        for pins in ({'source/not-declared.com':'0'*64},{'source/dep.c':'0'*64},{spec.member:'ABC'},{'../unsafe.com':'0'*64},{f'source/a{i}.com':'0'*64 for i in range(17)}):
            with self.subTest(pins=pins),self.assertRaises(c.CheckpointError):
                c.validate_policy(dataclasses.replace(policy,material_text_pins=pins))
        wrong=dataclasses.replace(policy,inputs=tuple(dataclasses.replace(x,kind='source') if x==spec else x for x in policy.inputs))
        with self.assertRaises(c.CheckpointError):
            c.validate_policy(wrong)

    def test_com_alias_requires_separate_exact_pin(self):
        policy,spec=self.text_pin_policy()
        material_root=self.base/'material';material_root.mkdir()
        (material_root/'build.com').write_bytes((self.source/'build.com').read_bytes())
        alias=c.FileSpec('material','build.com','material')
        policy=dataclasses.replace(policy,owned_roots={**policy.owned_roots,'material':material_root},root_kinds={**policy.root_kinds,'material':'material'},approved_path_roots=policy.approved_path_roots+(str(material_root),),payloads=policy.payloads+(alias,))
        with self.assertRaises(c.CheckpointError):
            c.preflight_available_content(policy,self.meta)
        policy=dataclasses.replace(policy,material_text_pins={**policy.material_text_pins,alias.member:policy.material_text_pins[spec.member]})
        c.preflight_available_content(policy,self.meta)


    def test_text_pin_16k_boundary(self):
        policy,_=self.text_pin_policy(b'$'+b' '*16383)
        c.preflight_available_content(policy,self.meta)
        policy,_=self.text_pin_policy(b'$'+b' '*16384)
        with self.assertRaises(c.CheckpointError) as caught:
            c.preflight_available_content(policy,self.meta)
        self.assertEqual(caught.exception.context['reason_code'],'material_text_size_rejected')

    def subset_members(self):
        return ['build/dep.obj','build/dep.lib','build/.ninja_log','build/.ninja_deps']

    def test_built_subset_only_receipt_and_no_archive(self):
        before=sorted(str(x.relative_to(self.base)) for x in self.base.rglob('*'))
        events=[]
        result=c.validate_built_subset(self.policy,self.subset_members(),lambda phase,spec,data:events.append((phase,spec.member if spec else None)))
        self.assertEqual(result['state'],'PASS_BUILT_SUBSET_ONLY')
        self.assertEqual(result['member_count'],4)
        self.assertEqual(result['validated_output_count'],2)
        self.assertEqual(result['counts_by_kind'],dict(obj=1,lib=1,ninja_log=1,ninja_deps=1))
        self.assertEqual(len(result['checked_identity_sha256']),64)
        self.assertEqual(result['full_checkpoint_validation'],'NOT_RUN')
        self.assertEqual(result['outer_zip_validation'],'NOT_RUN')
        self.assertEqual(len(events),6)
        self.assertEqual(events[0],('built-subset-begin',None))
        self.assertEqual(events[-1],('built-subset-end',None))
        self.assertEqual(before,sorted(str(x.relative_to(self.base)) for x in self.base.rglob('*')))

    def test_built_subset_rejects_unknown_missing_duplicate_and_material(self):
        members=self.subset_members()
        for bad in ([],members+[members[0]],members+['build/UNKNOWN.obj'],members[:-1],members+['source/LICENSE']):
            with self.subTest(bad=bad),self.assertRaises(c.CheckpointError):
                c.validate_built_subset(self.policy,bad)
        (self.build/'dep.obj').unlink()
        with self.assertRaises(c.CheckpointError) as caught:
            c.validate_built_subset(self.policy,members)
        self.assertEqual(caught.exception.context['member'],'build/dep.obj')
        self.assertEqual(caught.exception.context['reason_code'],'member_read_failed')

    def test_built_subset_preserves_object_archive_and_state_gates(self):
        fixtures={'dep.obj':b'not COFF','dep.lib':archive(coff(machine=0x14c)),'.ninja_log':b'# ninja log v5'+bytes([10]),'.ninja_deps':deps(['dep.obj',str(self.source/'dep.c')],version=3)}
        for name,bad in fixtures.items():
            path=self.build/name;original=path.read_bytes();path.write_bytes(bad)
            try:
                with self.subTest(name=name),self.assertRaises(c.CheckpointError) as caught:
                    c.validate_built_subset(self.policy,self.subset_members())
                self.assertEqual(caught.exception.context['member'],'build/'+name)
            finally:
                path.write_bytes(original)

    def write_subset_log(self, output):
        header=b'# ninja log v6'+bytes([10])
        record=bytes([9]).join([b'0',b'1',b'123',output.encode(),b'f'])+bytes([10])
        (self.build/'.ninja_log').write_bytes(header+record)

    def test_subset_restricts_log_outputs_and_does_not_promote(self):
        extra=c.FileSpec('build','future.obj','obj')
        policy=dataclasses.replace(self.policy,payloads=self.policy.payloads+(extra,),allowed_log_outputs=self.policy.allowed_log_outputs|{'future.obj',str(self.build/'future.obj')})
        c.validate_built_subset(policy,self.subset_members())
        with self.assertRaises(c.CheckpointError):
            c.seal_checkpoint(self.base/'not-promoted.zip',policy,self.meta)
        self.write_subset_log('future.obj')
        with self.assertRaises(c.CheckpointError):
            c.validate_built_subset(policy,self.subset_members())
        self.write_subset_log('dep.obj')
        (self.build/'.ninja_deps').write_bytes(deps(['future.obj',str(self.source/'dep.c')]))
        with self.assertRaises(c.CheckpointError):
            c.validate_built_subset(policy,self.subset_members())

    def test_subset_absolute_outputs_and_provenance(self):
        self.write_subset_log(str(self.build/'dep.obj'))
        (self.build/'.ninja_deps').write_bytes(deps([str(self.build/'dep.obj'),str(self.source/'dep.c')]))
        c.validate_built_subset(self.policy,self.subset_members())
        def denied(phase,spec,data):
            if spec is not None:
                raise RuntimeError('/private/NEVER_ECHO')
        with self.assertRaises(c.CheckpointError) as caught:
            c.validate_built_subset(self.policy,self.subset_members(),denied)
        self.assertEqual(caught.exception.context['reason_code'],'provenance_or_license_failed')
        self.assertNotIn('NEVER_ECHO',str(caught.exception))

    def test_subset_keeps_full_material_pin_declarations(self):
        policy,spec=self.text_pin_policy()
        material_root=self.base/'material';material_root.mkdir()
        (material_root/'build.com').write_bytes((self.source/'build.com').read_bytes())
        alias=c.FileSpec('material','build.com','material')
        policy=dataclasses.replace(policy,owned_roots={**policy.owned_roots,'material':material_root},root_kinds={**policy.root_kinds,'material':'material'},approved_path_roots=policy.approved_path_roots+(str(material_root),),payloads=policy.payloads+(alias,),material_text_pins={**policy.material_text_pins,alias.member:policy.material_text_pins[spec.member]})
        c.validate_built_subset(policy,self.subset_members())


if __name__ == '__main__':
    unittest.main(verbosity=2)


class CodeViewAndArchiveFormatTests(unittest.TestCase):
    """Synthetic records only; no copied worker/tool binaries or network."""
    def setUp(self):
        self.policy = c.Policy({}, {}, (), (), frozenset(), frozenset(), (r'C:\faf-re-staged', r'C:\Program Files\LLVM'), r'C:\faf-re-staged\recipe\build')

    @staticmethod
    def quoted(args):
        return ' '.join('"'+''.join('\\'+x if x in '\\"$' else x for x in arg)+'"' for arg in args).encode()

    @staticmethod
    def record(kind, payload):
        body = struct.pack('<H', kind)+payload
        pad = (-(len(body)+2)) % 4
        body += bytes(range(0xf0+pad, 0xf0, -1))
        return struct.pack('<H',len(body))+body

    def fixture(self, command=None, *, refs=None, parent=0, unknown_record=False, pdb=b''):
        if command is None:
            command=self.quoted(['-cc1',r'-fdebug-compilation-dir=C:\faf-re-staged\recipe\build','-internal-isystem',r'C:\Program Files\LLVM\include'])
        values=[b'C:\\faf-re-staged\\recipe\\build',b'C:\\Program Files\\LLVM\\clang-cl.exe',b'a.c',pdb,command]
        types=b'\x04\0\0\0';starts=[]
        for i,value in enumerate(values):
            starts.append(len(types));types += self.record(0x1605 if not (unknown_record and i==4) else 0x1606,struct.pack('<I',parent if i==4 else 0)+value+b'\0')
        buildinfo=len(types);types += self.record(0x1603,struct.pack('<HIIIII',5,*(refs or [0x1000,0x1001,0x1002,0x1003,0x1004])))
        header=struct.pack('<HHIIIHH',0x8664,2,0,0,0,0,0);start=101
        text=b'.text\0\0\0'+struct.pack('<IIIIIIHHI',0,0,1,100,0,0,0,0,0x60000020)
        debug=b'.debug$T'+struct.pack('<IIIIIIHHI',0,0,len(types),start,0,0,0,0,0x42300040)
        return bytearray(header+text+debug+b'\xc3'+types),{'debug':start,'strings':[start+x for x in starts],'buildinfo':start+buildinfo}

    def check(self,data,kind='obj'):
        c._content(c.FileSpec('build','a.'+kind,kind),bytes(data),self.policy)

    def reject(self,data,kind='obj'):
        with self.assertRaises(c.CheckpointError):self.check(data,kind)

    def test_known_codeview_only_escaped_path_passes(self):
        data,meta=self.fixture();c.inspect_coff(data)
        with self.assertRaisesRegex(c.CheckpointError,'unapproved embedded'):c.inspect_public_paths(data,self.policy)
        spans=c._validated_codeview_ranges(data,self.policy)
        self.assertEqual(len(spans),1);self.assertEqual(spans[0][0],meta['strings'][4]+8);self.check(data)

    def test_same_field_in_archive_passes(self):
        data,_=self.fixture();self.check(archive(bytes(data)),'lib')

    def test_generic_scanner_never_unescapes(self):
        raw=self.quoted(['-cc1',r'C:\faf-re-staged\source'])
        with self.assertRaises(c.CheckpointError):c.inspect_public_paths(raw,self.policy)

    def test_raw_private_paths_outside_mask_still_reject(self):
        data,_=self.fixture()
        for suffix in [b'\0C:\\private\\secret\0',b'\0'+r'C:\private\secret'.encode('utf-16le')+b'\0\0']:
            self.reject(data+suffix);self.reject(archive(bytes(data+suffix)),'lib')

    def test_unknown_and_traversal_decoded_paths_reject(self):
        for path in [r'C:\private\secret',r'C:\faf-re-staged\..\private\secret',r'C:\faf-re-staged-other\secret',r'\\private-host\share\x',r'C:\\faf-re-staged\\secret']:
            data,_=self.fixture(self.quoted(['-cc1',path]));self.reject(data);self.reject(archive(bytes(data)),'lib')

    def test_spaces_quotes_dollar_and_unicode_canonical(self):
        args=['-cc1',r'C:\Program Files\LLVM\include',r'-DVALUE="quoted"$', 'utf8-\u03bb']
        raw=self.quoted(args);self.assertEqual(c._canonical_codeview_args(raw),args);data,_=self.fixture(raw);self.check(data)

    def test_unknown_or_noncanonical_escapes_reject(self):
        for raw in [b'"-cc1" "\\q"',b'"-cc1" "x\\n"',b'"-cc1" "bad$',b'"-cc1" "raw$"',b'"-cc1"  "x"',b'"-cc1" "x" ',b'"-cc1" x',b'"not-cc1" "x"',b'"-cc1" ""',b'"-cc1" "x\n"',b'"-cc1" "\xff"']:
            data,_=self.fixture(raw);self.reject(data)

    def test_bad_references_and_wrong_leaf_reject(self):
        for index in [0,0xfff,0x1005,0x1006,0xffffffff]:
            data,_=self.fixture(refs=[0x1000,0x1001,0x1002,0x1003,index]);self.reject(data)
        data,_=self.fixture(unknown_record=True);self.reject(data)
        data,_=self.fixture(parent=0x1000);self.reject(data)

    def test_all_five_references_must_be_strings(self):
        data,meta=self.fixture();struct.pack_into('<H',data,meta['strings'][0]+2,0x1606);self.reject(data)
        data,meta=self.fixture();struct.pack_into('<I',data,meta['strings'][1]+4,1);self.reject(data)
        data,_=self.fixture(pdb=b'C:\\faf-re-staged\\types.pdb');self.reject(data)

    def test_buildinfo_shape_padding_and_section_signature(self):
        data,meta=self.fixture();data[meta['debug']]=2;self.reject(data)
        data,meta=self.fixture();struct.pack_into('<H',data,meta['buildinfo']+4,4);self.reject(data)
        data,meta=self.fixture();data[-1]=0;self.reject(data)

    def test_record_size_and_alignment_reject(self):
        for length in [0,1,3,65535]:
            data,meta=self.fixture();struct.pack_into('<H',data,meta['strings'][4],length);self.reject(data)
        data,_=self.fixture();self.reject(data[:-1])

    def test_command_nul_and_padding_reject(self):
        data,meta=self.fixture(b'"-cc1"');at=meta['strings'][4];stop=at+2+struct.unpack_from('<H',data,at)[0]
        for idx in range(at+8,stop):
            if data[idx]==0:data[idx]=65
        self.reject(data)
        data,meta=self.fixture(b'"-cc1"');at=meta['strings'][4];stop=at+2+struct.unpack_from('<H',data,at)[0];data[stop-1]=0;self.reject(data)

    def test_unreferenced_escaped_string_is_not_masked(self):
        data,meta=self.fixture();struct.pack_into('<H',data,meta['buildinfo']+2,0x1500);self.reject(data)
        data,meta=self.fixture();data[60:68]=b'.rdata\0\0';self.reject(data)

    def test_mask_crosses_chunks_without_hiding_neighbors(self):
        data,_=self.fixture()
        with mock.patch.object(c,'SCAN_CHUNK_BYTES',31):self.check(data)
        with mock.patch.object(c,'SCAN_CHUNK_BYTES',31):self.reject(data+b'\0C:\\private\\outside\0')

    def test_record_count_bound_is_fail_closed(self):
        data,_=self.fixture()
        with self.assertRaises(c.CheckpointError):c._validated_codeview_ranges(data,dataclasses.replace(self.policy,limits=dataclasses.replace(self.policy.limits,log_records=2)))

    def test_fixed_structural_and_path_diagnostics(self):
        data,_=self.fixture();struct.pack_into('<H',data,0,0x14c)
        with self.assertRaises(c.CheckpointError) as got:
            with c._member_guard('built-subset',c.FileSpec('build','x.obj','obj')):self.check(data)
        result=got.exception.context;self.assertEqual(result['reason_code'],'coff_structure_rejected');self.assertEqual(result['format_details']['machine'],0x14c)
        data,_=self.fixture(self.quoted(['-cc1',r'C:\private\do-not-print']))
        with self.assertRaises(c.CheckpointError) as got:
            with c._member_guard('built-subset',c.FileSpec('build','x.obj','obj')):self.check(data)
        self.assertNotIn('private',str(got.exception));self.assertIn('format_rule',got.exception.context)

    def test_archive_name_tail_exact_padding(self):
        for value,count in [(b'',0),(b'a\0',1),(b'aa\0',1),(b'aa\0\0',1),(b'a\0bbb\0',2),(b'a\0bb\0\0',2)]:c._archive_symbol_names(value,count)
        for value,count in [(b'\0',0),(b'\0',1),(b'a\0\0',1),(b'aa\0X',1),(b'aa\0\0\0',1),(b'a\0b\0',1),(b'a\0',2),(b'aa',1)]:
            with self.assertRaises(c.CheckpointError):c._archive_symbol_names(value,count)

    def test_archive_names_across_chunk_boundary(self):
        with mock.patch.object(c,'IO_CHUNK_BYTES',3):
            c._archive_symbol_names(b'long-name\0aa\0\0',2)
            with self.assertRaises(c.CheckpointError):c._archive_symbol_names(b'long-name\0aa\0\0X',2)
