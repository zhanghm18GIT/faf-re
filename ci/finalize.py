"""No network, no build, no installation. Preserve bounded diagnostics after failure."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
from driver import diagnostics


def main():
    out=Path(os.environ['APPVEYOR_BUILD_FOLDER'])/'ci-results'
    out.mkdir(exist_ok=True); logs=out/'raw-logs'; logs.mkdir(exist_ok=True)
    receipt=out/'RECEIPT.json'
    data=json.loads(receipt.read_text()) if receipt.is_file() else {'status':'BLOCKED_BEFORE_DRIVER','native_gates':'NOT_RUN','in_game':'NOT_RUN','replays':'NOT_RUN'}
    if not data.get('product'):
        data['status']='BLOCKED_NO_COMPLETE_PRODUCT'
    ctx=SimpleNamespace(out=out,logs=logs,receipt=data)
    ctx.save=lambda: receipt.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')
    diagnostics(ctx)

if __name__=='__main__': main()
