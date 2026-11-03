"""Closed clang-cl argv grammar for the fixed public dependency recipe.
No command execution. Unknown flags stop admission, not an automatic fallback.
This is command admission, not a compiler filesystem sandbox.
"""
import hashlib,json,ntpath,re
class AdmissionError(ValueError):pass
def need(ok,msg):
 if not ok:raise AdmissionError(msg)
def norm(value,base):
 value=str(value);need(value and not any(x in value for x in ('\0','\n','\r','@')),'Unsafe argument')
 need(not value.startswith(('\\\\','//')),'UNC/device input forbidden')
 value=ntpath.normpath(value if ntpath.isabs(value) else ntpath.join(base,value))
 drive,tail=ntpath.splitdrive(value);need(re.fullmatch('[A-Za-z]:',drive) and ':' not in tail,'Drive path required; ADS forbidden')
 return ntpath.normcase(value)
def validate(argv,*,compiler,cwd,source,output,read_roots,write_root,sysroots):
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
 sources=[];outputs=[];selected=set();i=1
 while i<len(argv):
  a=argv[i];low=a.lower()
  if a=='--':
   need(i+2==len(argv),'Terminal source separator must have exactly one TU')
   sources.append(readable(argv[i+1]));i=len(argv);continue
  if a in switches:i+=1;continue
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
    if not v:i+=1;need(i<len(argv),'Missing path option');v=argv[i]
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
 need(sum(a in ('/c','-c') for a in argv)==1,'Exactly one compile-only action required')
 return {'schema':1,'source':expected_source,'output':expected_output,'argv_sha256':hashlib.sha256(json.dumps(argv,separators=(',',':')).encode()).hexdigest()}
