import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_install as ci
import packaging_gate as pg
from native_checks import OUTPUTS

GUID = bytes(range(16))

def pe(guid=GUID, age=1, machine=0x8664):
    b = bytearray(1024); b[:2] = b'MZ'
    struct.pack_into('<I', b, 60, 128); b[128:132] = b'PE\0\0'
    struct.pack_into('<HH', b, 132, machine, 1)
    struct.pack_into('<H', b, 148, 240)
    struct.pack_into('<H', b, 152, 0x20b)
    struct.pack_into('<II', b, 152+112+48, 0x1000, 28)
    struct.pack_into('<IIII', b, 392+8, 512, 0x1000, 512, 512)
    struct.pack_into('<IIII', b, 512+12, 2, 32, 0x1040, 576)
    b[576:580] = b'RSDS'; b[580:596] = guid
    struct.pack_into('<I', b, 596, age)
    return b

def pdb(guid=GUID, age=1):
    b = bytearray(5*512)
    b[:32] = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0'
    struct.pack_into('<6I', b, 32, 512, 0, 5, 16, 0, 1)
    struct.pack_into('<I', b, 512, 2)
    struct.pack_into('<4I', b, 1024, 2, 0, 28, 3)
    struct.pack_into('<III', b, 1536, 20000404, 0, age)
    b[1548:1564] = guid
    return b

class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/'source'; self.build = self.root/'build'
        self.source.mkdir(); self.build.mkdir()
        self.ctx = types.SimpleNamespace(root=self.root, receipt={
            'native_gates':'PASS', 'native_checks':dict.fromkeys(ci.GATES, 'PASS'), 'in_game':'NOT_RUN', 'replays':'NOT_RUN'})
        def write(root, path, data):
            p = root/path; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
            return {'path':path, 'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()}
        self.write = write
        for path in OUTPUTS.values(): write(self.build, path, pe())
        write(self.build, 'src/main_x64.pdb', pdb())
        dxc = [write(self.source, 'dependencies/dxc/bin/x64/'+name, pe()) for name in ('dxcompiler.dll','dxil.dll')]
        resources = [write(self.source, 'data/fafengine/'+name, name.encode()) for name in sorted(ci.RESOURCE_NAMES)]
        self.inputs = {'dxc_runtime':dxc, 'resources':resources, 'candidate_files':resources+[write(self.source, 'LEGAL.md', b'No blanket license')]}
        self.materials = {'files':[write(self.source, 'dependencies/component/LICENSE', b'component notice'), write(self.source, 'dependencies/component/source.c', b'int source;')]}
    def create(self):
        archive = pg.create_package(self.ctx, self.source, self.build, {}, self.inputs, self.materials)
        return archive, Path(self.ctx.receipt['package']['stage'])
    def test_full_package_and_readonly_audit(self):
        archive, stage = self.create()
        before = {p:ci.file_hash(p) for p in stage.rglob('*') if p.is_file()}
        manifest = ci.check_zip(archive, stage)
        self.assertEqual(manifest['in_game'], 'NOT_RUN')
        self.assertTrue((stage/'fafengine/lua/ui/uimain.lua').is_file())
        self.assertFalse((stage/'data').exists())
        self.assertTrue((stage/'source/engine/data/fafengine/lua/ui/uimain.lua').is_file())
        self.assertEqual(before, {p:ci.file_hash(p) for p in stage.rglob('*') if p.is_file()})
        self.assertEqual(pg.match_pdb(stage/'main_x64.exe', stage/'main_x64.pdb')['status'], 'PASS')
    def test_each_gate_required(self):
        for gate in ci.GATES:
            with self.subTest(gate=gate):
                self.ctx.receipt['native_checks'][gate] = 'NOT_RUN'
                with self.assertRaises(ci.PackageError): self.create()
                self.ctx.receipt['native_checks'][gate] = 'PASS'
    def test_pdb_mismatch(self):
        (self.build/'src/main_x64.pdb').write_bytes(pdb(age=2))
        with self.assertRaisesRegex(ci.PackageError, 'GUID-age'): self.create()
    def test_non_amd64_dxc(self):
        (self.source/'dependencies/dxc/bin/x64/dxil.dll').write_bytes(pe(machine=0x14c))
        with self.assertRaisesRegex(ci.PackageError, 'Non-AMD64'): self.create()
    def test_material_hash_required(self):
        (self.source/'dependencies/component/LICENSE').write_text('changed')
        with self.assertRaisesRegex(ci.PackageError, 'Changed source material'): self.create()
    def test_extra_source_resource(self):
        (self.source/'data/fafengine/extra.lua').write_text('extra')
        with self.assertRaises(RuntimeError): self.create()
    def test_missing_material(self):
        (self.source/'dependencies/component/source.c').unlink()
        with self.assertRaises(ci.PackageError): self.create()
    def test_paths(self):
        for path in ('../escape','/absolute','x\\y','x:y','x//y','x/./y','NUL.txt','name.','x/COM1','a\x00b'):
            with self.subTest(path=path), self.assertRaises(ci.PackageError): ci.safe_path(path)
    def test_parent_symlink(self):
        outside=self.root/'outside'; outside.mkdir(); (outside/'file').write_text('x')
        (self.source/'linked').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ci.PackageError): ci.regular_path(self.source, 'linked/file')
    def test_file_tamper_and_extra(self):
        archive, stage=self.create()
        (stage/'main_x64.exe').write_bytes(b'bad')
        with self.assertRaises(ci.PackageError): ci.check_package(stage)
    def test_extra_file(self):
        archive, stage=self.create(); (stage/'extra.dll').write_bytes(b'x')
        with self.assertRaises(ci.PackageError): ci.check_package(stage)
    def test_zip_extra_traversal(self):
        archive, stage=self.create()
        with zipfile.ZipFile(archive,'a') as z: z.writestr('../escape', b'x')
        with self.assertRaises(ci.PackageError): ci.check_zip(archive,stage)
    def test_size_cap_fails_without_removing_source(self):
        with patch.object(ci, 'MAX_ZIP', 1), self.assertRaisesRegex(ci.PackageError, '400 MiB'): self.create()
        stage=next(p for p in self.root.glob('package-stage-*') if p.is_dir())
        self.assertTrue((stage/'source/engine/dependencies/component/LICENSE').is_file())
    def test_resource_manifest_cannot_omit(self):
        archive,stage=self.create(); p=stage/'FILE_MANIFEST.json'; m=json.loads(p.read_text()); m['resources'].pop(); p.write_text(json.dumps(m))
        with self.assertRaises(ci.PackageError): ci.check_package(stage)
    def test_dxc_pin_required(self):
        del self.inputs['dxc_runtime']
        with self.assertRaisesRegex(ci.PackageError, 'DXC runtime pins'): self.create()
    def test_dxc_changed_amd64_rejected(self):
        (self.source/'dependencies/dxc/bin/x64/dxil.dll').write_bytes(pe(age=2))
        with self.assertRaisesRegex(ci.PackageError, 'Changed source material'): self.create()
    def test_checker_dxc_pin_rejected(self):
        archive,stage=self.create(); p=stage/'SOURCE_INPUTS.json'; data=json.loads(p.read_text()); data['dxc_runtime'][0]['sha256']='0'*64; p.write_text(json.dumps(data))
        mf=stage/'FILE_MANIFEST.json'; manifest=json.loads(mf.read_text())
        row=next(r for r in manifest['files'] if r['path']=='SOURCE_INPUTS.json'); row['bytes']=p.stat().st_size; row['sha256']=ci.file_hash(p); mf.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ci.PackageError, 'DXC runtime pin mismatch'): ci.check_package(stage)
    def test_deadline_stops_copy(self):
        calls=[]
        def remaining(reserve):
            calls.append(reserve)
            raise ci.PackageError('deadline exhausted')
        self.ctx.remaining=remaining
        with self.assertRaisesRegex(ci.PackageError, 'deadline exhausted'): self.create()
        self.assertEqual(calls, [600])
        self.assertFalse(list(self.root.glob('*.zip')))
    def test_deadline_stops_zip_write(self):
        def remaining(reserve):
            self.assertEqual(reserve, 600)
            if list(self.root.glob('*.zip')):
                raise ci.PackageError('deadline exhausted before zip member')
        self.ctx.remaining=remaining
        with self.assertRaisesRegex(ci.PackageError, 'before zip member'): self.create()
        archive=next(self.root.glob('*.zip'))
        with zipfile.ZipFile(archive) as z: self.assertEqual(z.namelist(), [])
    def test_not_game_acceptance(self):
        self.ctx.receipt['in_game']='PASS'
        with self.assertRaises(ci.PackageError): self.create()

if __name__ == '__main__': unittest.main()
