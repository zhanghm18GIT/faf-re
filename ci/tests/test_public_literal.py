"""Exact public-source literal admission, including fail-closed abuse cases."""
from pathlib import Path
import dataclasses, hashlib, os, struct, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import checkpoint as c

def obj(value=None, section=b'.rdata\0\0', flags=0x40201040):
    value=c.WX_LITERAL_BYTES if value is None else value
    symbols=(b'.rdata\0\0'+struct.pack('<IhHBB',0,1,0,3,1)+struct.pack('<IHHIHBBH',len(value),0,0,0x2A79B1E3,1,2,0,0)+
             struct.pack('<IIIhHBB',0,4,0,1,0,2,0))
    strings=struct.pack('<I',5+len(c.WX_LITERAL_SYMBOL))+c.WX_LITERAL_SYMBOL+b'\0'
    return (struct.pack('<HHIIIHH',0x8664,1,0,60+len(value),3,0,0)+section+
            struct.pack('<IIIIIIHHI',0,0,len(value),60,0,0,0,0,flags)+value+symbols+strings)

def lib(value, name=None):
    name=c.WX_LITERAL_OBJECT if name is None else name
    names=name.encode()+b'\0'
    def member(label,data):
        return label.encode().ljust(16)+b'0'.ljust(12)+b'0'.ljust(6)+b'0'.ljust(6)+b'100644'.ljust(8)+str(len(data)).encode().ljust(10)+b'`\n'+data+(b'\n' if len(data)%2 else b'')
    return b'!<arch>\n'+member('//',names)+member('/0',value)

class PublicLiteralTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.source=self.root/'source';self.build=self.root/'build';self.build.mkdir()
        self.file=self.source/c.WX_LITERAL_SOURCE;self.file.parent.mkdir(parents=True);self.file.write_bytes(b'pinned synthetic source\n')
        self.hashmock=mock.patch.object(c,'WX_LITERAL_SOURCE_SHA256',hashlib.sha256(self.file.read_bytes()).hexdigest());self.hashmock.start();self.addCleanup(self.hashmock.stop)
        self.ospec=c.FileSpec('build',c.WX_LITERAL_OBJECT,'obj');self.lspec=c.FileSpec('build',c.WX_LITERAL_LIBRARY,'lib')
        self.policy=c.Policy({'source':self.source,'build':self.build},{'source':'source','build':'build'},(self.ospec,self.lspec),(c.FileSpec('source',c.WX_LITERAL_SOURCE,'material'),),frozenset(),frozenset(),(str(self.root),),str(self.build),public_literal_rules=(c.WX_LITERAL_RULE,))
    def check(self,data,spec=None,policy=None):c._content(spec or self.ospec,data,policy or self.policy)
    def rejected(self,data,spec=None,policy=None):
        with self.assertRaises(c.CheckpointError):self.check(data,spec,policy)
    def test_exact_object(self):self.check(obj())
    def test_exact_archive(self):self.check(lib(obj()),self.lspec)
    def test_exact_archive_windows_separators(self):self.check(lib(obj(),c.WX_LITERAL_OBJECT.replace('/','\\')),self.lspec)
    def test_exact_absolute_archive(self):self.check(lib(obj(),str(self.build)+'/'+c.WX_LITERAL_OBJECT),self.lspec)
    def test_disabled(self):self.rejected(obj(),policy=dataclasses.replace(self.policy,public_literal_rules=()))
    def test_source_pin(self):self.file.write_bytes(b'modified');self.rejected(obj())
    def test_source_missing(self):self.file.unlink();self.rejected(obj())
    def test_source_symlink(self):
        dest=self.root/'target';self.file.rename(dest);self.file.symlink_to(dest);self.rejected(obj())
    def test_undeclared_source(self):self.rejected(obj(),policy=dataclasses.replace(self.policy,inputs=()))
    def test_undeclared_object(self):self.rejected(obj(),policy=dataclasses.replace(self.policy,payloads=(self.lspec,)))
    def test_forged_rule(self):self.rejected(obj(),policy=dataclasses.replace(self.policy,public_literal_rules=('c:\\windows',)))
    def test_duplicate_rule(self):self.rejected(obj(),policy=dataclasses.replace(self.policy,public_literal_rules=(c.WX_LITERAL_RULE,c.WX_LITERAL_RULE)))
    def test_wrong_type_rule(self):self.rejected(obj(),policy=dataclasses.replace(self.policy,public_literal_rules=[c.WX_LITERAL_RULE]))
    def test_arbitrary_object(self):self.rejected(obj(),c.FileSpec('build','other/cmndata.cpp.obj','obj'))
    def test_arbitrary_library(self):self.rejected(lib(obj()),c.FileSpec('build','other/wxmswu.lib','lib'))
    def test_arbitrary_archive_object(self):self.rejected(lib(obj(),'evil/cmndata.cpp.obj'),self.lspec)
    def test_basename_archive_object(self):self.rejected(lib(obj(),'cmndata.cpp.obj'),self.lspec)
    def test_nested_archive(self):self.rejected(lib(lib(obj())),self.lspec)
    def test_private_suffix(self):self.rejected(obj(c.WX_LITERAL_BYTES[:-2]+'private.txt\0'.encode('utf-16le')))
    def test_missing_terminator(self):self.rejected(obj(c.WX_LITERAL_BYTES[:-2]))
    def test_prefixed_literal(self):self.assertEqual(c._public_literal_ranges(obj(b'X\0'+c.WX_LITERAL_BYTES),self.policy,self.ospec), [])
    def test_suffixed_literal(self):self.rejected(obj(c.WX_LITERAL_BYTES+b'X\0'))
    def test_extra_private_path(self):self.rejected(obj(c.WX_LITERAL_BYTES+'C:\\Users\\private\0'.encode('utf-16le')))
    def test_ascii_literal(self):self.rejected(obj('c:\\windows\\system\\\0'.encode()))
    def test_data_section(self):self.rejected(obj(section=b'.data\0\0\0',flags=0xc0200040))
    def test_debug_section(self):self.rejected(obj(section=b'.debug$S'))
    def test_writable_flag(self):self.rejected(obj(flags=0xc0201040))
    def test_not_comdat(self):self.rejected(obj(flags=0x40200040))
    def test_truncated(self):self.rejected(obj()[:-1])
    def test_overlapping_sections(self):
        d=bytearray(obj());struct.pack_into('<H',d,2,2);sec=bytearray(d[20:60]);struct.pack_into('<I',sec,20,100);d= d[:20]+sec+sec+d[60:];self.rejected(bytes(d))
    def test_duplicate_archive_identity(self):
        single=lib(obj());size=int(single[8+48:8+58]);offset=8+60+size+(size%2)
        self.rejected(single+single[offset:],self.lspec)
    def test_fake_comdat_without_symbols(self):
        d=bytearray(obj());struct.pack_into('<II',d,8,0,0);self.rejected(bytes(d))
    def test_source_hardlink(self):
        os.link(self.file,self.root/'linked');self.rejected(obj())
    def test_metadata_aliases(self):
        for relocation in (True,False):
            d=bytearray(obj());oldsyms=struct.unpack_from('<I',d,8)[0]
            struct.pack_into('<H',d,2,2);struct.pack_into('<I',d,8,oldsyms+40);struct.pack_into('<I',d,40,100)
            meta=b'.text\0\0\0'+struct.pack('<IIIIIIHHI',0,0,0,0,100 if relocation else 0,0 if relocation else 100,1 if relocation else 0,0 if relocation else 6,0x60000020)
            d=d[:60]+meta+d[60:]
            with self.assertRaisesRegex(c.CheckpointError,'overlaps COFF metadata'):self.check(bytes(d))
    def test_forged_literal_symbol(self):
        d=obj().replace(c.WX_LITERAL_SYMBOL,b'X'*len(c.WX_LITERAL_SYMBOL));self.rejected(d)
    def test_forged_comdat_aux(self):
        d=bytearray(obj());a=struct.unpack_from('<I',d,8)[0]+18;d[a+14]=3;self.rejected(bytes(d))

if __name__=='__main__':unittest.main()
