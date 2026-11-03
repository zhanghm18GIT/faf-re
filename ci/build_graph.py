"""Read-only generated graph admission. No build or shell execution on import."""
from pathlib import Path, PurePosixPath
import hashlib,json,re

TARGETS=('wxmswu','wx_regex','wx_png','wx_jpeg','wx_tiff','zlib123','ffmpeg_avutil','ffmpeg_swresample','ffmpeg_swscale','ffmpeg_avcodec','ffmpeg_avformat','faf_netlink','faf_netchannel','faf_monocypher','faf_datachannel','faf_usrsctp','faf_mbedtls','faf_juice')
class GraphError(ValueError):pass
def need(ok,msg):
 if not ok:raise GraphError(msg)
def relpath(value):
 p=PurePosixPath(str(value).replace('\\','/'))
 need(not p.is_absolute() and '..' not in p.parts and ':' not in str(p) and '\n' not in str(p) and '\r' not in str(p),'Unsafe generated relative path')
 return p.as_posix()
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def read_json(p):
 need(p.stat().st_size<=16*1024*1024,'Oversized CMake API reply')
 return json.loads(p.read_text(encoding='utf-8'))
def load_targets(build):
 reply=Path(build)/'.cmake/api/v1/reply';indexes=sorted(reply.glob('index-*.json'))
 need(len(indexes)==1,'Expected one fresh CMake API index')
 index=read_json(indexes[0]);entry=index.get('reply',{}).get('codemodel-v2',{})
 need('jsonFile' in entry,'Missing requested codemodel')
 model=read_json(reply/relpath(entry['jsonFile']));configs=model['configurations'];need(len(configs)==1 and configs[0]['name']=='Release','Expected single Release graph')
 by_id={x['id']:x for x in configs[0]['targets']};by_name={x['name']:x for x in by_id.values()}
 need(all(t in by_name for t in TARGETS),'Missing dependency target')
 targets={}
 for name in TARGETS:
  t=read_json(reply/relpath(by_name[name]['jsonFile']));need(t['name']==name and t['type']=='STATIC_LIBRARY','Unexpected dependency target type')
  deps=[by_id[x['id']]['name'] for x in t.get('dependencies',[])]
  need(set(deps)<=set(TARGETS),'Dependency target closes over unreviewed target: '+name)
  artifacts=[relpath(x['path']) for x in t.get('artifacts',[])];need(len(artifacts)==1 and artifacts[0].lower().endswith('.lib'),'Unexpected dependency archive output')
  targets[name]={'artifact':artifacts[0],'depends':sorted(deps),'includes':sorted({x['path'] for g in t.get('compileGroups',[]) for x in g.get('includes',[])})}
 return targets

def select_commands(build,targets,unexpanded,expanded,target_commands):
 """Bind Ninja's own rsp expansion and prove selected-root command closure exact."""
 need(len(unexpanded)<=20000 and len(expanded)<=20000,'Oversized Ninja command database')
 raw={relpath(x['output']):x for x in unexpanded};full={relpath(x['output']):x for x in expanded}
 need(len(raw)==len(unexpanded) and len(full)==len(expanded),'Duplicate Ninja output records')
 archives={x['artifact'] for x in targets.values()};selected={};by_target={t:[] for t in TARGETS}
 for output,e in full.items():
  target=None
  for t in TARGETS:
   if '/CMakeFiles/'+t+'.dir/' in '/'+output:target=t;break
  if output in archives:target=next(t for t,v in targets.items() if v['artifact']==output)
  if target is None:continue
  need(output.lower().endswith(('.obj','.lib')),'Unexpected selected compiler/archive output')
  need(output in raw and e['command'] and raw[output]['command'],'Missing selected command')
  need(Path(e['directory'])==Path(build),'Unexpected command working directory')
  cmd=e['command'];need('\n' not in cmd and '\r' not in cmd,'Multiline selected command')
  need(not re.search(r'(^|\s)(?:/GL\b|-flto\b|/LTCG\b)',cmd,re.I),'Unreviewed LTO in checkpoint')
  need('@' not in cmd,'Ninja command retains an unexpanded response argument')
  selected[output]={'target':target,'file':e['file'],'command':cmd,'raw_command':raw[output]['command']}
  by_target[target].append(output)
 need(archives<=selected.keys() and all(by_target.values()),'Incomplete dependency command/output set')
 actual=target_commands.splitlines();expected=[v['raw_command'] for v in selected.values()]
 need(sorted(actual)==sorted(expected),'Named dependency graph contains unknown or missing command edges')
 public=[{'output':k,'target':v['target'],'command_sha256':hashlib.sha256(v['command'].encode()).hexdigest(),'source':v['file']} for k,v in sorted(selected.items())]
 return {'outputs':sorted(selected),'archives':sorted(archives),'records':public,'identity':digest(public),'command_count':len(actual)}

def clean_plan(text):
 lines=[x.strip() for x in text.splitlines() if x.strip()]
 need(not any(re.match(r'^\[\d+/\d+\]',x) for x in lines),'Dependency reuse would execute work')
 need(any(x=='ninja: no work to do.' for x in lines),'Ninja did not confirm a clean dependency plan')
 need(not any('is dirty' in x or 'Re-running CMake' in x or 'VERIFY_GLOBS' in x for x in lines),'Unexpected dirty/generator state')
 return True

def windows_argv(command):
 """Use the Windows parser for generated Windows compiler commands, never a shell."""
 import ctypes,os
 need(os.name=='nt','Windows command parsing required for actual graph')
 shell=ctypes.WinDLL('shell32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
 shell.CommandLineToArgvW.argtypes=[ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_int)];shell.CommandLineToArgvW.restype=ctypes.POINTER(ctypes.c_wchar_p)
 kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree.restype=ctypes.c_void_p
 count=ctypes.c_int();argv=shell.CommandLineToArgvW(command,ctypes.byref(count));need(bool(argv),'Cannot parse generated command')
 try:return [argv[i] for i in range(count.value)]
 finally:kernel.LocalFree(argv)

def validate_compile_argv(argv,compiler,build,allowed_roots,sysroots):
 """Check input-bearing channels separately from immutable command-byte identity."""
 import ntpath
 norm=lambda p:ntpath.normcase(ntpath.normpath(str(p)))
 base=norm(build);roots=[norm(p).rstrip('\\') for p in allowed_roots]
 def path_ok(value):
  p=norm(value if ntpath.isabs(value) else ntpath.join(base,value))
  need(any(p==r or p.startswith(r+'\\') for r in roots),'Compiler input root is not fingerprinted')
  return p
 need(argv and norm(argv[0])==norm(compiler),'Dependency object compiler is not the pinned clang-cl')
 seen={};includes=[];i=1
 forward={'-ffp-contract=off','-fno-strict-aliasing','-fwrapv','-fno-delete-null-pointer-checks','-fno-strict-float-cast-overflow','-fno-finite-loops','-fno-strict-return'}
 while i<len(argv):
  a=argv[i];low=a.lower()
  need(not any(c in a for c in ['\n','\r','\x00']),'Unsafe command argument')
  need(not low.startswith(('@','--config','-ivfs','-vfsoverlay','-fplugin','-fmodule','/external:env','-xclang','-working-directory','--sysroot','-isysroot','-gcc-toolchain','-stdlib++-isystem')),'Undeclared compiler configuration/input channel')
  if low.startswith('/clang:'):
   x=low[7:];need(x in forward or re.fullmatch('-fno-builtin-[a-z0-9]+',x),'Unreviewed forwarded clang option')
  if low.startswith(('/yu','/yc','/fp:fast')) or (low.startswith('/fp') and not low.startswith('/fp:')):raise GraphError('Unreviewed PCH/fast-math input')
  match=False
  for opt in ['/vctoolsdir','/winsdkdir','/winsdkversion']:
   if low==opt or low.startswith(opt+':'):
    if low==opt:i+=1;need(i<len(argv),'Missing sysroot value');v=argv[i]
    else:v=a[len(opt)+1:]
    need(opt not in seen,'Duplicate sysroot override');seen[opt]=v;match=True;break
  if match:i+=1;continue
  for opt in ['/external:i','/imsvc','-imsvc','-isystem-after','-isystem','-idirafter','-iquote','-include','/fi','/i','-i']:
   # -I is case-sensitive; other lowercase -i prefixes are explicitly enumerated.
   matched=(a.startswith('-I') if opt=='-i' else low.startswith(opt))
   if not matched:continue
   if opt=='-i' and not a.startswith('-I'):continue
   suffix=a[len(opt):]
   if not suffix:i+=1;need(i<len(argv),'Missing include value');suffix=argv[i]
   includes.append(path_ok(suffix));match=True;break
  if not match and low.startswith(('-i','-resource-dir','/external:')):raise GraphError('Unclassified compiler include channel')
  i+=1
 need(set(seen)==set(sysroots),'Missing explicit compiler toolset/SDK selection')
 for k,v in sysroots.items():need(norm(seen[k])==norm(v),'Compiler toolset/SDK selection differs')
 return {'argv_sha256':digest(argv),'include_paths':sorted(set(includes))}
