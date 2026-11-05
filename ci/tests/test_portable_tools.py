import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import toolchain as t

class Context:
    def __init__(self):self.calls=0
    def remaining(self,cap):self.calls+=1;return cap
class PortableTools(unittest.TestCase):
    def test_official_pins_frozen(self):
        d=json.loads((Path(__file__).resolve().parents[1]/'build-tools.json').read_text())
        self.assertEqual(d['state'],'OFFICIAL_PINS_FROZEN')
        self.assertEqual(d['cmake']['sha256'],'d163cd3ab4959b0a53fa8988f2ddbd2e6c501658201e6a154386bad9dbe4f836')
        self.assertEqual(d['ninja']['sha256'],'07fc8261b42b20e71d1720b39068c2e14ffcee6396b76fb7a795fb460b78dc65')
    def test_zip_relative_file(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/'tool.zip'
            with zipfile.ZipFile(archive,'w') as z:z.writestr('a/b',b'fixture')
            ctx=Context();t.extract_tool_zip(ctx,archive,root/'out')
            self.assertEqual((root/'out/a/b').read_bytes(),b'fixture');self.assertGreater(ctx.calls,0)
    def test_zip_traversal_blocked(self):
        for name in ['../outside','C:/outside','/outside','a/../../outside']:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as d:
                root=Path(d);archive=root/'tool.zip'
                with zipfile.ZipFile(archive,'w') as z:z.writestr(name,b'x')
                with self.assertRaises(t.Blocked):t.extract_tool_zip(Context(),archive,root/'out')
    def test_zip_symlink_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/'tool.zip';entry=zipfile.ZipInfo('link');entry.create_system=3;entry.external_attr=(stat.S_IFLNK|0o777)<<16
            with zipfile.ZipFile(archive,'w') as z:z.writestr(entry,b'outside')
            with self.assertRaises(t.Blocked):t.extract_tool_zip(Context(),archive,root/'out')
    def test_zip_case_alias_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/'tool.zip'
            with zipfile.ZipFile(archive,'w') as z:z.writestr('A',b'x');z.writestr('a',b'y')
            with self.assertRaises(t.Blocked):t.extract_tool_zip(Context(),archive,root/'out')

if __name__=='__main__':unittest.main()
