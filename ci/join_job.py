"""Join the supervisor-owned Windows job BEFORE spawning any actual command."""
import os
import subprocess
import sys
from windows_job import join_named_job
if __name__=='__main__':
    try:
        join_named_job(os.environ['FAF_SUPERVISOR_JOB'])
        if len(sys.argv)<2:raise RuntimeError('Missing contained command')
        raise SystemExit(subprocess.run(sys.argv[1:],check=False).returncode)
    except Exception as exc:
        print('Containment setup failed: '+str(exc));raise SystemExit(125)
