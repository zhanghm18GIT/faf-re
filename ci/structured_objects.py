"""Bounded local cache verifier. Trusted caller supplies policy, reviewed backend,
expected archive hashes and canaries; no object/manifest can authorize itself.

Not a sandbox or arbitrary-source authenticity proof. Machine code and ordinary
constant data are not interpreted as paths. Debug path-bearing fields are parsed explicitly; numeric/debug-checksum bytes
are not interpreted as text. Unknown record dialects fail closed.
The supported CodeView dialect is intentionally finite; unknown kinds fail.
"""
from collections import Counter
import hashlib
import ntpath
import re
import struct
import codeview_catalog as catalog

class StructureError(ValueError):
    def __init__(self, reason, *, details=None):
        super().__init__(reason)
        self.code='coff_structure_rejected'
        self.details=details or {}


def cv_kind(ok, reason, kind, section, offset):
    if not ok:
        raise StructureError(reason,details={'type_index':kind,'section_index':section,'record_offset':offset})

def need(ok, reason):
    if not ok:
        raise StructureError(reason)

def bounds(data, at, size):
    need(type(at) is int and type(size) is int and 0 <= at <= len(data) and 0 <= size <= len(data)-at, 'out-of-bounds field')

def canary_check(data, canaries):
    need(type(canaries) is tuple and canaries and all(type(x) is bytes and len(x)>=8 for x in canaries), 'trusted caller must supply nonempty byte canaries (>=8 bytes)')
    need(not any(x in data for x in canaries), 'private canary present')

def cstring(data, at, end):
    need(0 <= at < end <= len(data), 'invalid string offset')
    stop=data.find(b'\0',at,end)
    need(stop>=0, 'unterminated string')
    return data[at:stop],stop+1

def check_path(raw, policy, backend):
    try: text=raw.decode('utf-8')
    except UnicodeError: raise StructureError('non-UTF8 debug path') from None
    need(not any(ord(c)<32 for c in text), 'control in debug path')
    if text:
        backend.approved_path(text,policy)
    backend.inspect_public_paths(raw,policy)

# LLVM22.1.7 C/C++ embedded /Z7 dialect, classified against the complete official catalog.
# Modern nonpath framing does not claim full inner-field semantic validation.
TYPE_KINDS = (catalog.TYPE_NONPATH | catalog.TYPE_PATH) - {0x1607}  # Module/string-table context not admitted.
SYMBOL_KINDS = catalog.SYMBOL_NONPATH | catalog.SYMBOL_PATH
SUBSECTIONS = catalog.SUBSECTION_PATH

def debug_sections(data, sections, policy, backend):
    # Reviewed parser validates LF_BUILDINFO links, command escaping, roots,
    # no external type-server PDB, record lengths and CodeView padding.
    command_ranges=backend._validated_codeview_ranges(data,policy)
    path_string_ids=set();buildinfo_ids=set();source_refs=[];substring_refs=[];buildinfo_refs=[];type_sections=0
    strings=[];checksums=[];checksum_starts=set();file_refs=[];checksum_tables=0;module_refs=[]
    for section_index,(name,start,size) in enumerate(sections,1):
        if not name.startswith(b'.debug'): continue
        cv_kind(name in {b'.debug$S',b'.debug$T'},'unsupported debug section',0,section_index,start)
        body=data[start:start+size]
        need(len(body)>=4 and body[:4]==b'\x04\0\0\0','unsupported debug signature')
        pos=4
        if name==b'.debug$T':
            type_sections+=1;need(type_sections==1,'ambiguous type index namespace');type_id=0x1000
            while pos<len(body):
                bounds(body,pos,4);length,kind=struct.unpack_from('<HH',body,pos)
                stop=pos+2+length;need(length>=2 and stop<=len(body) and stop%4==0,'invalid type record extent')
                cv_kind(kind in TYPE_KINDS,'unsupported CodeView type kind',kind,section_index,start+pos)
                # External PDB/type-server kinds are deliberately not allowed.
                if kind==0x000a: # LF_VTSHAPE, observed official LLVM22 C++ output.
                    need(length>=4,'short vtable shape');count=struct.unpack_from('<H',body,pos+4)[0]
                    used=6+(count+1)//2;need(pos+used<=stop,'truncated vtable descriptors')
                    trailing=body[pos+used:stop]
                    need(len(trailing)<=3 and trailing==bytes(range(0xf0+len(trailing),0xf0,-1)),'invalid vtable padding')
                if kind==0x1605:
                    need(length>=7,'short string-id')
                    need(struct.unpack_from('<I',body,pos+4)[0]==0,'composed string-id unsupported')
                    value,end=cstring(body,pos+8,stop)
                    tail=body[end:stop]
                    need(len(tail)<=3 and tail==bytes(range(0xf0+len(tail),0xf0,-1)),'invalid string-id padding')
                    # Command strings are validated canonically by the backend.
                    if not any(a==start+pos+8 for a,b in command_ranges):
                        check_path(value,policy,backend);path_string_ids.add(type_id)
                elif kind==0x1603:buildinfo_ids.add(type_id)  # Full five-reference argv validation is performed above.
                elif kind==0x1606:
                    need(length==14,'invalid source-line reference shape')
                    source_refs.append((type_id,struct.unpack_from('<I',body,pos+8)[0]))
                elif kind==0x1604:
                    need(length>=6,'short substring list');count=struct.unpack_from('<I',body,pos+4)[0]
                    need(length==6+count*4,'invalid substring-list extent')
                    substring_refs.extend((type_id,x[0]) for x in struct.iter_unpack('<I',body[pos+8:stop]))
                pos=stop;type_id+=1
        else:
            while pos<len(body):
                bounds(body,pos,8);kind,length=struct.unpack_from('<II',body,pos);begin=pos+8;end=begin+length
                bounds(body,begin,length);cv_kind(kind in SUBSECTIONS,'unsupported CodeView subsection',kind,section_index,start+pos)
                payload=body[begin:end]
                if kind==0xf1:
                    cur=0
                    while cur<len(payload):
                        bounds(payload,cur,4);rl,rk=struct.unpack_from('<HH',payload,cur);stop=cur+2+rl
                        need(rl>=2 and stop<=len(payload),'invalid CodeView symbol extent');cv_kind(rk in SYMBOL_KINDS,'unsupported CodeView symbol kind',rk,section_index,start+begin+cur)
                        if rk==0x114c:
                            need(rl==6,'invalid buildinfo symbol reference shape');buildinfo_refs.append(struct.unpack_from('<I',payload,cur+4)[0])
                        if rk==0x1101:
                            need(rl>=7,'short object-name symbol');value,tail=cstring(payload,cur+8,stop);check_path(value,policy,backend)
                            need(stop-tail<=3 and not any(payload[tail:stop]),'invalid object-name padding')
                        if rk==0x1153: # FILESTATIC module filename is a string-table offset.
                            need(rl>=13,'short file-static symbol');module_refs.append(struct.unpack_from('<I',payload,cur+8)[0])
                            value,tail=cstring(payload,cur+14,stop)
                            need(stop-tail<=3 and not any(payload[tail:stop]),'invalid file-static padding')
                        if rk==0x113c: # COMPILE3 has a compiler version string, not numeric text.
                            need(rl>=25,'short compile3 symbol');version,tail=cstring(payload,cur+26,stop)
                            need(stop-tail<=3 and not any(payload[tail:stop]),'invalid compile3 padding')
                            backend.inspect_public_paths(version,policy)
                        if rk in {0x1112,0x1113}: # L/GTHREAD32 from observed LLVM TLS output.
                            need(rl>=13,'short TLS symbol');value,tail=cstring(payload,cur+14,stop)
                            need(stop-tail<=3 and not any(payload[tail:stop]),'invalid TLS symbol padding')
                            backend.inspect_public_paths(value,policy)
                        if rk==0x1102: # S_THUNK32 standard thunk, observed LLVM member pointer.
                            need(rl>=24 and payload[cur+24]==0,'unsupported thunk shape/ordinal')
                            value,tail=cstring(payload,cur+25,stop)
                            need(stop-tail<=3 and not any(payload[tail:stop]),'invalid thunk padding')
                            backend.inspect_public_paths(value,policy)
                        cur=stop
                elif kind==0xf3:
                    need(payload and payload[0]==0 and payload[-1]==0,'invalid debug string table')
                    cur=0;valid={}
                    while cur<len(payload):
                        value,stop=cstring(payload,cur,len(payload));valid[cur]=value;check_path(value,policy,backend);cur=stop
                    strings.append(valid)
                elif kind==0xf4:
                    checksum_tables+=1;need(checksum_tables==1,'multiple checksum tables unsupported')
                    cur=0
                    while cur<len(payload):
                        checksum_starts.add(cur)
                        bounds(payload,cur,6);off,size,alg=struct.unpack_from('<IBB',payload,cur)
                        need((alg,size) in {(0,0),(1,16),(2,20),(3,32)},'unsupported checksum kind/length')
                        bounds(payload,cur+6,size);checksums.append(off);endrec=cur+6+size;cur=(endrec+3)&~3
                        need(cur<=len(payload) and not any(payload[endrec:cur]),'invalid checksum padding')
                elif kind==0xf2:
                    need(len(payload)>=12,'short line subsection')
                    flags=struct.unpack_from('<H',payload,6)[0];code_size=struct.unpack_from('<I',payload,8)[0]
                    need(flags in {0,1},'unsupported line flags');cur=12
                    while cur<len(payload):
                        bounds(payload,cur,12);file_id,lines,block=struct.unpack_from('<III',payload,cur)
                        need(block==12+lines*(12 if flags else 8),'invalid line block size');bounds(payload,cur,block)
                        file_refs.append(file_id)
                        for j in range(lines):need(struct.unpack_from('<I',payload,cur+12+j*8)[0]<code_size,'line offset outside function')
                        cur+=block
                elif kind==0xf6:
                    need(len(payload)>=4 and struct.unpack_from('<I',payload)[0] in {0,1},'unsupported inline-line signature')
                    sig=struct.unpack_from('<I',payload)[0];cur=4
                    while cur<len(payload):
                        bounds(payload,cur,12);file_refs.append(struct.unpack_from('<I',payload,cur+4)[0]);cur+=12
                        if sig:
                            bounds(payload,cur,4);extra=struct.unpack_from('<I',payload,cur)[0];cur+=4;bounds(payload,cur,extra*4)
                            file_refs.extend(x[0] for x in struct.iter_unpack('<I',payload[cur:cur+extra*4]));cur+=extra*4
                aligned=(end+3)&~3;need(aligned<=len(body) and not any(body[end:aligned]),'invalid subsection padding');pos=aligned
        # Paths are checked only in parsed semantic fields. Checksums, line
        # tables, type references and other typed numerics are never strings.
    need(all(ref in path_string_ids and ref<owner for owner,ref in source_refs+substring_refs),'invalid path string-id reference')
    need(all(ref in buildinfo_ids for ref in buildinfo_refs),'invalid buildinfo symbol type reference')
    need(not (checksums or module_refs) or len(strings)==1,'missing/ambiguous debug filename table')
    if checksums or module_refs:need(all(x in strings[0] for x in checksums+module_refs),'filename is not a string start')
    need(all(x in checksum_starts for x in file_refs),'line references unknown checksum record')
    return len(command_ranges)

def validate_directives(raw, policy, backend):
    # Fixed clang/LLVM linker directives only; never pass unknown options.
    need(all(32<=c<127 or c==9 for c in raw),'non-ASCII/control linker directive')
    backend.inspect_public_paths(raw,policy)
    text=raw.decode('ascii');tokens=[];current=[];quote=False
    for char in text:
        if char=='"':quote=not quote
        elif char.isspace() and not quote:
            if current:tokens.append(''.join(current));current=[]
        else:current.append(char)
    need(not quote,'unbalanced directive quotes')
    if current:tokens.append(''.join(current))
    symbol=lambda v:bool(v) and not any(c in v for c in '/\\: \t')
    for token in tokens:
        need(token.startswith(('/', '-')) and ':' in token,'unsupported linker directive')
        key,value=token[1:].split(':',1);key=key.upper()
        if key=='DEFAULTLIB':need(re.fullmatch(r'[A-Za-z0-9_-]+(?:\.lib)?',value,re.I) is not None,'DEFAULTLIB must be a basename')
        elif key=='FAILIFMISMATCH':need('=' in value and all(value.split('=',1)) and not any(c in value for c in '/\\:'),'invalid mismatch directive')
        elif key in {'INCLUDE','EXPORT'}:need(symbol(value),'unsupported symbol directive')
        elif key=='ALTERNATENAME':need(value.count('=')==1 and all(symbol(x) for x in value.split('=')),'invalid alternate symbol directive')
        else:raise StructureError('unsupported linker directive')

def validate_object(data, *, policy, backend, canaries):
    need(type(data) is bytes,'object must be immutable bytes');need(len(data)<=policy.limits.member_bytes,'object byte bound');canary_check(data,canaries)
    backend.inspect_coff(data)
    big=data[:4]==b'\0\0\xff\xff';head,width=(56,20) if big else (20,18)
    n=struct.unpack_from('<I' if big else '<H',data,44 if big else 2)[0]
    sp,count=struct.unpack_from('<II',data,48 if big else 8);endhead=head+40*n
    extents=[(0,endhead,'headers')];sections=[];relocs=[];primary=set();rawsections=[]
    strings=sp+count*width if sp else 0;slen=struct.unpack_from('<I',data,strings)[0] if sp else 0
    if sp:
        extents.extend([(sp,strings,'symbols'),(strings,strings+slen,'strings')])
        if slen>4:
            need(data[strings+slen-1]==0,'unterminated COFF string table')
            backend.inspect_public_paths(data[strings+4:strings+slen],policy)
    def longname(off):
        need(sp and 4<=off<slen,'invalid long-name offset');return cstring(data,strings+off,strings+slen)[0]
    i=0
    while i<count:
        at=sp+i*width;primary.add(i);name=data[at:at+8]
        if name[:4]==b'\0'*4: name=longname(struct.unpack_from('<I',name,4)[0])
        else:
            if b'\0' in name:need(not any(name[name.index(b'\0'):]),'noncanonical short symbol name')
            name=name.split(b'\0',1)[0]
        sec=struct.unpack_from('<i' if big else '<h',data,at+12)[0];storage,aux=struct.unpack_from('<BB',data,at+width-2)
        need(-2<=sec<=n,'invalid symbol section');need(i+aux<count,'auxiliary symbol overrun')
        need(storage in {2,3,6,101,103,104,105,107},'unsupported COFF symbol storage class')
        if storage==103:need(aux>0,'file symbol missing filename auxiliary')
        # File-symbol auxiliary bytes are an actual filename, not machine code.
        if storage==103:
            raw=data[at+width:at+(aux+1)*width].split(b'\0',1)[0];check_path(raw,policy,backend)
        backend.inspect_public_paths(name,policy)
        i+=aux+1
    for i in range(n):
        at=head+i*40;name=data[at:at+8].rstrip(b'\0')
        if name.startswith(b'/'):
            need(name[1:].isdigit(),'invalid long section name');name=longname(int(name[1:]))
        need(bool(name),'empty section name')
        virtual,addr,size,start,rp,lp,nr,nl,flags=struct.unpack_from('<IIIIIIHHI',data,at+8)
        need(addr==0,'nonzero relocatable section address');need(nl==0 and lp==0,'legacy line tables unsupported')
        if start and size:extents.append((start,start+size,'section'))
        sections.append((name,start,size))
        need(not (flags&0x80 and start and size),'initialized bytes in BSS')
        if flags&0x1000000:
            nr=struct.unpack_from('<I',data,rp)[0];first=1
        else:first=0
        if nr:
            extents.append((rp,rp+nr*10,'relocations'))
            for j in range(first,nr):
                va,si,typ=struct.unpack_from('<IIH',data,rp+j*10)
                need(typ<=16 and si in primary,'invalid relocation type/symbol')
                widths={0:0,1:8,2:4,3:4,4:4,5:4,6:4,7:4,8:4,9:4,10:2,11:4,12:1,13:4,14:4,15:0,16:4}
                need(va+widths[typ]<=max(size,virtual),'relocation outside section')
        backend.inspect_public_paths(name,policy)
        if name==b'.drectve':validate_directives(data[start:start+size],policy,backend)
    occupied=sorted((a,b,k) for a,b,k in extents if b>a);cursor=0
    for a,b,k in occupied:
        bounds(data,a,b-a);need(a>=cursor,'overlapping COFF regions');need(not any(data[cursor:a]),'nonzero unowned COFF gap');cursor=b
    need(cursor==len(data),'trailing COFF bytes')
    commands=debug_sections(data,sections,policy,backend)
    return {'format':'bigobj' if big else 'coff','sha256':hashlib.sha256(data).hexdigest(),'sections':n,'symbols':count,'validated_command_spans':commands,'coverage':'finite CodeView framing + explicit filename/string-ID/command paths; no numeric debug scan'}

def validate_archive(data, *, expected_objects, policy, backend, canaries):
    need(type(data) is bytes,'archive must be immutable bytes');need(len(data)<=policy.limits.member_bytes,'archive byte bound');canary_check(data,canaries)
    need(type(expected_objects) is dict and expected_objects and len(expected_objects)<=policy.limits.members,'trusted bounded expected object map required')
    need(all(type(k) is str and type(v) is str and len(v)==64 and all(c in '0123456789abcdef' for c in v) for k,v in expected_objects.items()),'invalid expected object hashes')
    objects=[];regions=[];backend.inspect_archive(data,named_object_spans=objects,regions=regions)
    normalize=lambda name:name.replace('\\','/')
    normalized={normalize(name):digest for name,digest in expected_objects.items()}
    need(len(normalized)==len(expected_objects),'caller archive-name normalization collision')
    names=[normalize(name) for a,b,name in objects]
    need(len(names)==len(set(names)) and set(names)==set(normalized),'archive identity/multiplicity mismatch')
    for begin,end,name in objects:
        body=data[begin:end];need(hashlib.sha256(body).hexdigest()==normalized[normalize(name)],'archive object hash mismatch')
        validate_object(body,policy=policy,backend=backend,canaries=canaries)
    # All container textual regions retain path checks. Typed numeric fields
    # are already bounded and cross-referenced by the reviewed archive parser.
    for begin,end,kind,index in regions:
        if kind in {'archive_header','archive_symbol_names','archive_longnames'}:backend.inspect_public_paths(data[begin:end],policy)
    return {'format':'coff-archive','objects':len(objects),'sha256':hashlib.sha256(data).hexdigest(),'exact_object_hashes_and_multiplicity':True}
