"""Finalizer gate; validates native-cache readiness, never saves or uploads."""
from pathlib import Path
import argparse,json,os,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import cache_transport as c

def verify(directory,recipe,env):
 d=Path(directory);rpath=c.regular(d/'CACHE_READY.json');c.need(rpath.stat().st_size<=32768,'Oversized ready receipt')
 r=json.loads(rpath.read_text(encoding='utf-8'))
 c.need(set(r)=={'state','size','sha256','publication','cache_access_guarantee','account_quota_headroom','recipe','producer','artifact'},'Ready receipt fields')
 c.expected({'size':r['size'],'sha256':r['sha256']})
 c.need(r['publication']=='not_a_published_artifact' and r['cache_access_guarantee']=='UNKNOWN' and r['account_quota_headroom']=='UNKNOWN','Unverified cache claim')
 c.need(r['state']=='READY_FOR_NATIVE_CACHE_NOT_CONFIRMED_SAVED' and r['recipe']==recipe,'Ready identity mismatch')
 for field,var in [('job_id','APPVEYOR_JOB_ID'),('build_id','APPVEYOR_BUILD_ID'),('provider_commit','APPVEYOR_REPO_COMMIT')]:
  c.need(env.get(var) and r['producer'].get(field)==env[var],'Wrong producer')
 c.need(set(p.name for p in d.iterdir())=={'checkpoint.zip','CACHE_READY.json'},'Unexpected cache handoff content')
 c.need(c.identity(d/'checkpoint.zip')=={'size':r['size'],'sha256':r['sha256']},'Ready bytes mismatch')
 return True
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--directory',required=True);p.add_argument('--recipe',required=True);a=p.parse_args()
 verify(a.directory,a.recipe,os.environ);print('CACHE_FINALIZER_GATE_PASS')
