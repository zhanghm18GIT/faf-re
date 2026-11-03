from pathlib import Path
import hashlib,struct,sys,unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import checkpoint as c
import structured_objects as s
CANARY=b'PRIVATE-CANARY-938bf9a2'
POLICY=c.Policy({}, {}, (), (),frozenset(),frozenset(),(str(ROOT),r'C:\faf-re-staged'),str(ROOT))
def obj(sections,big=False):
 h=56 if big else 20;start=h+40*len(sections);parts=[];headers=[]
 for name,raw in sections:
  headers.append(name.ljust(8,b'\0')+struct.pack('<IIIIIIHHI',0,0,len(raw),start,0,0,0,0,0x40000040));parts.append(raw);start+=len(raw)
 if big:head=struct.pack('<HHHHI',0,65535,2,0x8664,0)+c.BIGOBJ_ID+struct.pack('<IIIIIII',0,0,0,0,len(sections),start,0)
 else:head=struct.pack('<HHIIIHH',0x8664,len(sections),0,start,0,0,0)
 return head+b''.join(headers)+b''.join(parts)+struct.pack('<I',4)
def member(name,b):return name.encode().ljust(16)+b'0'.ljust(12)+b'0'.ljust(6)+b'0'.ljust(6)+b'100644'.ljust(8)+str(len(b)).encode().ljust(10)+b'`\n'+b+(b'\n' if len(b)%2 else b'')
def lib(b):return b'!<arch>\n'+member('a.obj/',b)
def debug_name(name):
 rec=struct.pack('<HHI',6+len(name)+1,0x1101,0)+name+b'\0';body=struct.pack('<II',0xf1,len(rec))+rec;return b'\x04\0\0\0'+body+b'\0'*((-len(body))%4)
def validate(b):return s.validate_object(b,policy=POLICY,backend=c,canaries=(CANARY,))
class Tests(unittest.TestCase):
 def test_instruction_bytes_not_path(self):
  value=obj([(b'.text',bytes.fromhex('453a5c34f9'))])
  with self.assertRaises(c.CheckpointError):c.inspect_public_paths(value,POLICY)
  validate(value)
 def test_canary_every_byte_position(self):
  value=obj([(b'.text',bytes.fromhex('453a5c34f9'))])
  for pos in range(len(value)+1):
   with self.assertRaises(s.StructureError):validate(value[:pos]+CANARY+value[pos:])
 def test_simple_bigobj(self):self.assertEqual(validate(obj([(b'.text',b'\xc3')],True))['format'],'bigobj')
 def test_private_debug_objname(self):
  with self.assertRaises(c.CheckpointError):validate(obj([(b'.debug$S',debug_name(b'C:\\private\\x.obj'))]))
 def test_approved_debug_objname(self):validate(obj([(b'.debug$S',debug_name(b'C:\\faf-re-staged\\x.obj'))]))
 def test_unknown_debug_kind(self):
  b=b'\x04\0\0\0'+struct.pack('<II',0xff,0)
  with self.assertRaises(s.StructureError):validate(obj([(b'.debug$S',b)]))
 def test_unknown_debug_section(self):
  with self.assertRaises(s.StructureError):validate(obj([(b'.debug$X',b'')]))
 def test_overlap(self):
  b=bytearray(obj([(b'.text',b'1234'),(b'.rdata',b'5678')]))
  struct.pack_into('<I',b,20+40+20,100)
  with self.assertRaises(s.StructureError):validate(bytes(b))
 def test_trailing(self):
  with self.assertRaises(s.StructureError):validate(obj([(b'.text',b'1234')])+b'\0')
 def test_truncated(self):
  with self.assertRaises((s.StructureError,c.CheckpointError)):validate(obj([(b'.text',b'1234')])[:-1])
 def test_invalid_string_table(self):
  b=bytearray(obj([(b'.text',b'1234')]));b[-4:]=struct.pack('<I',100)
  with self.assertRaises((s.StructureError,c.CheckpointError)):validate(bytes(b))
 def test_nonzero_gap(self):
  b=bytearray(obj([(b'.text',b'1234')]));b[8:12]=struct.pack('<I',65);b[64:64]=b'X'
  with self.assertRaises(s.StructureError):validate(bytes(b))
 def test_relocations_and_symbol_integrity(self):
  head=struct.pack('<HHIIIHH',0x8664,1,0,74,1,0,0)
  sec=b'.text\0\0\0'+struct.pack('<IIIIIIHHI',0,0,4,60,64,0,1,0,0x60000020)
  symbol=b'target\0\0'+struct.pack('<IhHBB',0,1,0,2,0)
  b=head+sec+b'1234'+struct.pack('<IIH',0,0,2)+symbol+struct.pack('<I',4)
  validate(b)
  for off,fmt,value in [(68,'<I',1),(64,'<I',4),(72,'<H',0xffff),(86,'<h',2),(44,'<I',60)]:
   a=bytearray(b);struct.pack_into(fmt,a,off,value)
   with self.assertRaises((s.StructureError,c.CheckpointError)):validate(bytes(a))
 def test_invalid_symbol_string_offset(self):
  b=bytearray(obj([(b'.text',b'1234')]))
  # Replace zero-symbol table with one externally named symbol referencing past strings.
  struct.pack_into('<I',b,12,1);b[-4:]=b'\0'*4+struct.pack('<I',100)+struct.pack('<IhHBB',0,1,0,2,0)+struct.pack('<I',4)
  with self.assertRaises(s.StructureError):validate(bytes(b))
 def test_archive_exact_binding(self):
  b=obj([(b'.text',b'1234')]);d=lib(b);self.assertEqual(s.validate_archive(d,expected_objects={'a.obj':hashlib.sha256(b).hexdigest()},policy=POLICY,backend=c,canaries=(CANARY,))['objects'],1)
 def test_archive_hash_mismatch(self):
  with self.assertRaises(s.StructureError):s.validate_archive(lib(obj([(b'.text',b'1234')])),expected_objects={'a.obj':'0'*64},policy=POLICY,backend=c,canaries=(CANARY,))
 def test_archive_duplicate(self):
  b=obj([(b'.text',b'1234')]);d=lib(b)+member('a.obj/',b)
  with self.assertRaises(s.StructureError):s.validate_archive(d,expected_objects={'a.obj':hashlib.sha256(b).hexdigest()},policy=POLICY,backend=c,canaries=(CANARY,))
  table=b'dir/a.obj\0dir\\a.obj\0';duplicate=b'!<arch>\n'+member('//',table)+member('/0',b)+member('/10',b)
  with self.assertRaises(s.StructureError):s.validate_archive(duplicate,expected_objects={'dir/a.obj':hashlib.sha256(b).hexdigest()},policy=POLICY,backend=c,canaries=(CANARY,))
 def test_canary_archive_numeric_header_or_payload(self):
  b=lib(obj([(b'.text',b'1234')]))
  for at in range(len(b)+1):
   with self.assertRaisesRegex(s.StructureError,'private canary'):s.validate_archive(b[:at]+CANARY+b[at:],expected_objects={'a.obj':'0'*64},policy=POLICY,backend=c,canaries=(CANARY,))
 def test_directives(self):
  validate(obj([(b'.drectve',b' /DEFAULTLIB:libcmt.lib /FAILIFMISMATCH:"_MSC_VER=1900"')]))
  for directive in [b' /DEFAULTLIB:C:\\private\\hidden.lib',b' /DEFAULTLIB:../hidden.lib',b' /UNKNOWN:hello',b' /EXPORT:C:\\private']:
   with self.assertRaises((s.StructureError,c.CheckpointError)):validate(obj([(b'.drectve',directive)]))
 def test_unreferenced_string_table_path(self):
  b=bytearray(obj([(b'.text',b'1234')]));text=b'C:\\private\\secret.obj\0';b[-4:]=struct.pack('<I',4+len(text))+text
  with self.assertRaises(c.CheckpointError):validate(bytes(b))
 def test_exact_separator_normalization(self):
  b=obj([(b'.text',b'1234')]);name='dir\\a.obj';d=b'!<arch>\n'+member('//',name.encode()+b'\0')+member('/0',b)
  result=s.validate_archive(d,expected_objects={'dir/a.obj':hashlib.sha256(b).hexdigest()},policy=POLICY,backend=c,canaries=(CANARY,));self.assertEqual(result['objects'],1)
  with self.assertRaises(s.StructureError):s.validate_archive(d,expected_objects={'dir/a.obj':hashlib.sha256(b).hexdigest(),'dir\\a.obj':hashlib.sha256(b).hexdigest()},policy=POLICY,backend=c,canaries=(CANARY,))
  with self.assertRaises(s.StructureError):s.validate_archive(d,expected_objects={'a.obj':hashlib.sha256(b).hexdigest()},policy=POLICY,backend=c,canaries=(CANARY,))
  table=b'dir/a.obj\0dir\\a.obj\0';duplicate=b'!<arch>\n'+member('//',table)+member('/0',b)+member('/10',b)
  with self.assertRaises(s.StructureError):s.validate_archive(duplicate,expected_objects={'dir/a.obj':hashlib.sha256(b).hexdigest()},policy=POLICY,backend=c,canaries=(CANARY,))
 def test_typeserver_and_unknown_cv_numeric_diagnostics(self):
  for kind in [0x1515,0xffff]:
   b=obj([(b'.debug$T',b'\x04\0\0\0'+struct.pack('<HH',2,kind))])
   with self.assertRaises(s.StructureError) as cm:validate(b)
   self.assertEqual(cm.exception.details,{'type_index':kind,'section_index':1,'record_offset':64})
   with self.assertRaises(c.CheckpointError) as outer:
    with c._member_guard('test',c.FileSpec('build','test.obj','obj')):validate(b)
   self.assertEqual(outer.exception.context['format_details']['type_index'],kind)
 def test_vtable_shape_and_thunk_negative(self):
  b=obj([(b'.debug$T',b'\x04\0\0\0'+struct.pack('<HHH',6,0x000a,100)+b'\0\xf1')])
  with self.assertRaises(s.StructureError):validate(b)
  # Standard thunk is the only admitted variant; unknown ordinal fails.
  rec=struct.pack('<HH',26,0x1102)+bytes(20)+b'\x01x\0\0';body=struct.pack('<II',0xf1,len(rec))+rec
  with self.assertRaises(s.StructureError):validate(obj([(b'.debug$S',b'\x04\0\0\0'+body)]))
 def test_debug_checksum_numeric_not_path(self):
  # A structurally typed MD5 is arbitrary16 bytes, not a path string. This
  # intentionally spells a path to prove no blanket numeric metadata scan.
  digest=b'C:\\private\\x.obj';self.assertEqual(len(digest),16)
  def subsection(kind,payload):return struct.pack('<II',kind,len(payload))+payload+b'\0'*((-len(payload))%4)
  f3=b'\0C:\\faf-re-staged\\source.c\0';f4=struct.pack('<IBB',1,16,1)+digest+b'\0\0'
  debug=b'\x04\0\0\0'+subsection(0xf3,f3)+subsection(0xf4,f4)
  with self.assertRaises(c.CheckpointError):c.inspect_public_paths(debug,POLICY)
  validate(obj([(b'.debug$S',debug)]))
  private=f3.replace(b'faf-re-staged',b'privatexxxxx')
  with self.assertRaises(c.CheckpointError):validate(obj([(b'.debug$S',b'\x04\0\0\0'+subsection(0xf3,private)+subsection(0xf4,f4))]))
 def test_relative_debug_escape(self):
  with self.assertRaises(c.CheckpointError):validate(obj([(b'.debug$S',debug_name(b'../../../../../../outside.obj'))]))
 def test_no_canary_self_authorization(self):
  with self.assertRaises(s.StructureError):s.validate_object(obj([(b'.text',b'1234')]),policy=POLICY,backend=c,canaries=())
if __name__=='__main__':unittest.main()
