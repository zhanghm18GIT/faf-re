"""Catalog admission/framing tests, not full nonpath payload semantic validation."""
import struct,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import codeview_catalog as catalog
import structured_objects as s
from test_structured_objects import obj,validate

def symbol(kind,payload=bytes(64)):
 record=struct.pack('<HH',len(payload)+2,kind)+payload
 sub=struct.pack('<II',0xf1,len(record))+record
 return obj([(b'.debug$S',b'\x04\0\0\0'+sub+b'\0'*((-len(sub))%4))])
def typerecord(kind,payload=b''):
 used=4+len(payload);n=(-used)%4
 return struct.pack('<HH',used+n-2,kind)+payload+bytes(range(0xf0+n,0xf0,-1))
def types(*records):return obj([(b'.debug$T',b'\x04\0\0\0'+b''.join(records))])
def stringid(value):return typerecord(0x1605,struct.pack('<I',0)+value+b'\0')
class CatalogTests(unittest.TestCase):
 def test_complete_official_catalog_partition(self):
  self.assertEqual(catalog.SOURCE_TAG,'llvmorg-22.1.7')
  self.assertEqual([len(x) for x in [catalog.SYMBOL_CATALOG,catalog.TYPE_CATALOG,catalog.SUBSECTION_CATALOG]],[197,171,16])
  for rows in [catalog.SYMBOL_CATALOG,catalog.TYPE_CATALOG,catalog.SUBSECTION_CATALOG]:
   seen={}
   for name,value,category in rows:
    self.assertIn(category,{'DENY','MODERN_NONPATH_FRAMING','PATH_PARSE'})
    if value in seen:self.assertEqual(seen[value],category)
    seen[value]=category
  self.assertFalse(catalog.SYMBOL_PATH & catalog.SYMBOL_NONPATH)
  self.assertFalse(catalog.TYPE_PATH & catalog.TYPE_NONPATH)
 def test_all_reviewed_nonpath_symbol_framing(self):
  for kind in catalog.SYMBOL_NONPATH:
   with self.subTest(kind=hex(kind)):validate(symbol(kind))
 def test_all_reviewed_nonpath_type_framing(self):
  for kind in catalog.TYPE_NONPATH:
   payload=struct.pack('<H',0) if kind==0xa else bytes(64)
   with self.subTest(kind=hex(kind)):validate(types(typerecord(kind,payload)))
 def test_every_denied_catalog_symbol_and_unknown(self):
  denied={v for n,v,c in catalog.SYMBOL_CATALOG if c=='DENY'}|{0xffff}
  for kind in denied:
   with self.subTest(kind=hex(kind)),self.assertRaises(Exception):validate(symbol(kind))
 def test_every_denied_top_level_type_and_unknown(self):
  denied={v for n,v,c in catalog.TYPE_CATALOG if c=='DENY'}|{0xffff,0x1607}
  for kind in denied:
   with self.subTest(kind=hex(kind)),self.assertRaises(Exception):validate(types(typerecord(kind,bytes(64))))
 def test_every_denied_subsection_and_ignore_flag(self):
  for kind in {v for n,v,c in catalog.SUBSECTION_CATALOG if c=='DENY'}|{0x800000f1,0xffffffff}:
   with self.subTest(kind=hex(kind)),self.assertRaises(Exception):validate(obj([(b'.debug$S',b'\x04\0\0\0'+struct.pack('<II',kind,0))]))
 def test_nonpath_numeric_bytes_are_not_arbitrary_path_strings(self):
  validate(symbol(0x115e,b'C:\\private\\not-a-path-field\0'+bytes(64)))
 def test_record_extent_not_catalog_membership(self):
  b=bytearray(symbol(0x115e));struct.pack_into('<H',b,72,65535)
  with self.assertRaises(Exception):validate(bytes(b))
 def test_dangling_buildinfo_symbol_rejected(self):
  with self.assertRaises(Exception):validate(symbol(0x114c,struct.pack('<I',0x1000)))
 def test_source_line_checked_string_namespace(self):
  src=stringid(b'C:\\faf-re-staged\\source.cpp')
  validate(types(src,typerecord(0x1606,struct.pack('<III',0x74,0x1000,1))))
  for ref in [0,0x1001,0x2000]:
   with self.assertRaises(Exception):validate(types(src,typerecord(0x1606,struct.pack('<III',0x74,ref,1))))
  with self.assertRaises(Exception):validate(types(stringid(b'C:\\private\\source.cpp'),typerecord(0x1606,struct.pack('<III',0x74,0x1000,1))))
 def test_substring_list_bound_and_reference(self):
  src=stringid(b'C:\\faf-re-staged\\source.cpp')
  validate(types(src,typerecord(0x1604,struct.pack('<II',1,0x1000))))
  for payload in [struct.pack('<II',2,0x1000),struct.pack('<II',1,0x9999)]:
   with self.assertRaises(Exception):validate(types(src,typerecord(0x1604,payload)))
 def test_composed_string_still_rejected(self):
  with self.assertRaises(Exception):validate(types(typerecord(0x1605,struct.pack('<I',0x1000)+b'fragment\0')))
if __name__=='__main__':unittest.main()
