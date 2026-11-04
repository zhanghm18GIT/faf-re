"""Closed clang-cl argv grammar for the fixed public dependency recipe.
No command execution. Unknown flags stop admission, not an automatic fallback.
This is command admission, not a compiler filesystem sandbox.
"""
import hashlib,json,ntpath,re
class AdmissionError(ValueError):pass
def need(ok,msg):
 if not ok:raise AdmissionError(msg)
# Exact pinned public FFmpeg option list; never a prefix or arbitrary forwarding rule.
FFMPEG_OPTIONS_SOURCE_SHA256 = 'd7264d0a55b01795e59637eee9bc4916b48db68e5a954ba040883194ffbc9911'
FFMPEG_PUBLIC_OPTIONS = frozenset(('/std:c17', '-Wdeclaration-after-statement', '-W3', '-wd4018', '-wd4146', '-wd4244', '-wd4305', '-wd4554', '-Wdisabled-optimization', '-Wpointer-arith', '-Wredundant-decls', '-Wwrite-strings', '-Wtype-limits', '-Wundef', '-Wmissing-prototypes', '-Wstrict-prototypes', '-Wempty-body', '-Wno-parentheses', '-Wno-switch', '-Wno-format-zero-length', '-Wno-pointer-sign', '-Wno-unused-const-variable', '-Wno-bool-operation', '-Wno-char-subscripts', '-O2', '-utf-8'))

def verify_public_option_source(path):
 from pathlib import Path
 p=Path(path)
 need(p.is_file() and not p.is_symlink(),'Public option source missing/link')
 need(hashlib.sha256(p.read_bytes()).hexdigest()==FFMPEG_OPTIONS_SOURCE_SHA256,'Public option source identity mismatch')
 return {'source_sha256':FFMPEG_OPTIONS_SOURCE_SHA256,'exact_option_count':len(FFMPEG_PUBLIC_OPTIONS)}

def norm(value,base):
 value=str(value);need(value and not any(x in value for x in ('\0','\n','\r','@')),'Unsafe argument')
 need(not value.startswith(('\\\\','//')),'UNC/device input forbidden')
 value=ntpath.normpath(value if ntpath.isabs(value) else ntpath.join(base,value))
 drive,tail=ntpath.splitdrive(value);need(re.fullmatch('[A-Za-z]:',drive) and ':' not in tail,'Drive path required; ADS forbidden')
 return ntpath.normcase(value)
def _validate(argv,*,compiler,cwd,source,output,read_roots,write_root,sysroots,_context):
 base=norm(cwd,cwd);need(type(argv)==list and 3<=len(argv)<=4096,'Argv bound')
 need(all(type(x)==str and x and not any(c in x for c in ('\0','\n','\r','@')) for x in argv),'Unsafe argv')
 need(norm(argv[0],base)==norm(compiler,base),'Wrong compiler')
 roots=[norm(x,base).rstrip('\\') for x in read_roots];write=norm(write_root,base).rstrip('\\')
 def readable(x):
  p=norm(x,base);need(any(p==r or p.startswith(r+'\\') for r in roots),'Unapproved input path');return p
 def writable(x):
  p=norm(x,base);need(p.startswith(write+'\\'),'Unapproved output path');return p
 expected_source=readable(source);expected_output=writable(output)
 switches={'-MT','-Z7','--target=x86_64-pc-windows-msvc','-TC','-TP','-std:c++14','-std:c++17','-std:c++20','-std:c++latest','-std:c11','-std:c17','/std:c++14','/std:c11','-Wno-overriding-option','-Wno-c++11-narrowing','/nologo','/c','-c','/TP','/TC','/O1','/O2','/Ob2','/Oi','/Ot','/Oy','/Gy','/Gw','/GS','/GS-','/GR','/GR-','/EHsc','/EHs-c-','/MD','-MD','/MT','/Z7','/bigobj','/W0','/W1','/W2','/W3','/W4','/WX','/WX-','/utf-8','/showIncludes','/permissive-','/fp:precise','/fp:strict','/std:c17','/std:c++17','/std:c++20','/std:c++latest','/Zc:__cplusplus','/Zc:inline','/Zc:preprocessor','/Zc:char8_t-','/Gd','/GF','/RTC-','/FS'}
 forwarded={'-ffp-contract=off','-fno-strict-aliasing','-fwrapv','-fno-delete-null-pointer-checks','-fno-strict-float-cast-overflow','-fno-finite-loops','-fno-strict-return'}
 sources=[];outputs=[];selected=set();i=1;compile_actions=0
 while i<len(argv):
  a=argv[i];low=a.lower();_context['index']=i
  if a=='--':
   need(i+2==len(argv),'Terminal source separator must have exactly one TU')
   sources.append(readable(argv[i+1]));i=len(argv);continue
  if a in switches or a in FFMPEG_PUBLIC_OPTIONS:
   if a in ('/c','-c'):compile_actions+=1
   i+=1;continue
  if re.fullmatch(r'/w[de][0-9]{4,5}',a):i+=1;continue
  if a.startswith('/clang:'):
   f=a[7:];need(f in forwarded or re.fullmatch('-fno-builtin-[a-z0-9]+',f),'Unknown forwarded option');i+=1;continue
  if a.startswith(('/D','-D','/U','-U')):
   body=a[2:]
   if not body:i+=1;need(i<len(argv),'Missing macro');body=argv[i]
   need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:=[^\r\n\x00@]*)?',body),'Invalid macro');i+=1;continue
  matched=False
  for opt in ('/vctoolsdir','/winsdkdir','/winsdkversion'):
   if low==opt or low.startswith(opt+':'):
    if low==opt:i+=1;need(i<len(argv),'Missing sysroot');v=argv[i]
    else:v=a[len(opt)+1:]
    need(opt in sysroots,'Unknown sysroot')
    need(v==sysroots[opt] if opt=='/winsdkversion' else norm(v,base)==norm(sysroots[opt],base),'Wrong fixed sysroot')
    selected.add(opt);matched=True;break
  if matched:i+=1;continue
  for opt in ('/external:I','/imsvc','-imsvc','-isystem','-idirafter','-iquote','-include','/FI','/I','-I','/Fo','/Fd'):
   if a.startswith(opt):
    v=a[len(opt):]
    if not v:
     # LLVM22 clang-cl /Fd is joined-only; its bare form consumes no operand.
     if opt=='/Fd':matched=True;break
     need(opt!='/Fo','Object output requires joined /FoPATH')
     i+=1;need(i<len(argv),'Missing path option');v=argv[i]
     need(not v.startswith(('/','-')),'Option used as path value')
    if opt=='/Fo':outputs.append(writable(v))
    elif opt=='/Fd':writable(v)
    else:readable(v)
    matched=True;break
  if matched:i+=1;continue
  # Absolute drive or relative C/C++ TU only; unknown flags never become paths.
  need(not a.startswith(('/','-')) and a.lower().endswith(('.c','.cc','.cpp','.cxx')),'Unknown argument')
  sources.append(readable(a));i+=1
 need(sources==[expected_source] and outputs==[expected_output],'TU/output identity differs')
 need(selected==set(sysroots),'Missing fixed sysroots')
 need(compile_actions==1,'Exactly one parsed compile-only action required')
 return {'schema':1,'source':expected_source,'output':expected_output,'argv_sha256':hashlib.sha256(json.dumps(argv,separators=(',',':')).encode()).hexdigest()}


def validate(argv,**kwargs):
 """Public entry emits schema-only diagnostics, never raw args/macros/paths."""
 context={'index':-1}
 try:return _validate(argv,_context=context,**kwargs)
 except AdmissionError as exc:
  index=context['index'];token=argv[index] if type(argv)==list and 0<=index<len(argv) and type(argv[index]) is str else ''
  category='other'
  for prefix,label in [('/D','macro_define'),('-D','macro_define'),('/U','macro_undefine'),('-U','macro_undefine'),('/clang:','forwarded'),('-W','diagnostic_option'),('/W','diagnostic_option'),('/wd','diagnostic_option'),('-wd','diagnostic_option'),('/I','include'),('-I','include'),('/Fo','object_output'),('/Fd','debug_output'),('@','response')]:
   if token.startswith(prefix):category=label;break
  reason=str(exc)
  # All reasons originate in this module; preserve only their static identifier.
  rule=re.sub('[^a-z0-9]+','_',reason.lower()).strip('_')
  report={'schema':1,'code':'compiler_argument_rejected','rule':rule,'argument_index':index,'argument_category':category,'argument_bytes':len(token.encode('utf-8')),'argument_sha256':hashlib.sha256(token.encode('utf-8')).hexdigest()}
  if type(argv)==list and all(type(x) is str for x in argv):report['argv_sha256']=hashlib.sha256(json.dumps(argv,separators=(',',':')).encode()).hexdigest()
  raise AdmissionError(json.dumps(report,sort_keys=True,separators=(',',':'))) from None
