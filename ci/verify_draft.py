"""Read-only local exact draft verification; never enables an execution path."""
import json
from pathlib import Path
from native_checks import need,verify_files

def main():
    root=Path(__file__).resolve().parent.parent
    frozen=json.loads((root/'ci/DRIVER_FILES.json').read_text())
    need(frozen['status']=='LOCAL_DRAFT_REVIEW_PENDING_AUTHORIZATION','Not an inert draft')
    verify_files(root,frozen['files'])
    actual={p.relative_to(root).as_posix() for p in (root/'ci').rglob('*') if p.is_file()}
    expected={e['path'] for e in frozen['files'] if e['path'].startswith('ci/')}|{'ci/DRIVER_FILES.json'}
    need(actual==expected,'Runtime file set changed')
    a=json.loads((root/'ci/authorization.json').read_text())
    need(a['state']=='DRAFT_NOT_AUTHORIZED' and all(v is False for v in a['grants'].values()),'Draft activated')
    need("throw 'LOCAL_DRAFT_PENDING_FINAL_REVIEW_AND_PARENT_GO'" in (root/'appveyor.yml').read_text(),'Inert YAML gate absent')
    print('PASS: exact inert local AppVeyor draft. No native or CI run implied.')
if __name__=='__main__':main()
