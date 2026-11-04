#!/usr/bin/env python3
"""Inert fixed-source single-job client build. No cache or intermediate export."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import json
import os
import shutil
import time
import driver as core
import staged_driver as shared
import build_capture

need = core.require

class SingleBuild(shared.StagedBuild):
    # Reuse audited acquisition, controlled environment, configuration, source
    # inventory and owned cleanup. Do not dispatch any staged/cache run method.
    remaining = core.Build.remaining

    def __init__(self, here, contract):
        super().__init__(here, contract)
        # Before acquisition, only platform locators and fixed executable roots.
        self.child_env = {k:os.environ[k] for k in ['SYSTEMROOT','WINDIR','COMSPEC'] if k in os.environ}
        paths = [str(Path(sys.executable).parent)]
        if os.environ.get('WINDIR'): paths.append(str(Path(os.environ['WINDIR'])/'System32'))
        git = shutil.which('git.exe')
        if git: paths.append(str(Path(git).parent))
        self.child_env.update(PATH=os.pathsep.join(paths),GIT_TERMINAL_PROMPT='0',GIT_LFS_SKIP_SMUDGE='1',PYTHONDONTWRITEBYTECODE='1')

    def start_workspace(self):
        super().start_workspace()
        self.child_env.update(TEMP=str(self.root/'temp'), TMP=str(self.root/'temp'))

    def validate_contract(self):
        core.Build.validate_contract(self)
        need(self.c.get('mode') == 'single-fixed-public-client-v1', 'Unknown single-job mode')
        need(self.c.get('stage') is None and self.c.get('checkpoint_input') is None,
             'Single job cannot consume or produce a checkpoint')
        need('checkpoint_transport' not in self.c, 'Cache transport forbidden')
        need(self.c.get('max_total_seconds') == 3300 and self.c.get('parallelism') == 2,
             'Single-job resource bounds changed')
        need(self.c.get('build_reserve_seconds') == 390, 'Upload/cleanup minimum reserve changed')
        need(os.environ.get('APPVEYOR_CACHE_SKIP_SAVE', '').lower() == 'true' and
             os.environ.get('APPVEYOR_CACHE_SKIP_RESTORE', '').lower() == 'true', 'Cache must be disabled')
        self.material_selection = shared.validate_material_selection(core.read_json(self.here/shared.MATERIAL_POLICY_FILE))
        self.material_selection_sha = core.sha(self.here/shared.MATERIAL_POLICY_FILE)
        need(self.distribution.get('material_selection_sha256') == self.material_selection_sha and
             self.distribution.get('material_selection_review_status') == 'REVIEWED', 'Material review mismatch')
        need(self.c.get('source_review_status') == 'REVIEWED_FIXED_PRODUCT', 'Fixed source review missing')
        self.recipe = core.read_json(self.here/shared.RECIPE_FILE)
        self.recipe_key = shared.json_hash(self.recipe)
        need(self.recipe_key == self.c['dependency_recipe_sha256'], 'Recipe pin mismatch')
        self.receipt.update(mode=self.c['mode'], cache='DISABLED', completion_guarantee=False,
                            compile_input_admission_scope='dependency commands only; fixed source/tool trust model',
                            budget_policy='3300s aggregate; individual test caps unchanged; 390s minimum build reserve is not a downstream completion prediction')

    def command(self, args, cwd=None, cap=120, env=None, name='command', binary=False,
                permit_failure=False, started_callback=None):
        begin = time.monotonic()
        try:
            if name == 'build':
                limit = min(cap, self.remaining(3300) - self.c['build_reserve_seconds'])
                need(limit > 0, 'No compile window after minimum finalization reserve')
                print('BUILD_BUDGET ' + json.dumps({'seconds': limit, 'minimum_finalization_reserve':390,
                      'tests_and_packaging_fit_not_guaranteed':True}), flush=True)
                log = self.root/'logs/build.txt'
                result = build_capture.run_build([str(x) for x in args], cwd=cwd or self.root,
                    env=env if env is not None else self.child_env, log_path=log, timeout=limit,
                    emit=print, aliases=[(self.root,'<owned-work>'),(self.here.parent,'<configuration>')])
                self.receipt.setdefault('build_capture', {})[name] = result
                self.receipt['ninja_timing_summary'] = build_capture.ninja_summary(self.build/'.ninja_log', [(self.root,'<owned-work>')])
                print('NINJA_TIMING_SUMMARY '+json.dumps(self.receipt['ninja_timing_summary'],sort_keys=True),flush=True)
                need(result['state'] == 'SUCCESS', 'Bounded streamed build did not complete')
                text = log.read_text(encoding='utf-8', errors='replace')
                self.receipt['standalone_effect_scan_link'] = shared.validate_effect_link(text, self.build)
                return text
            return core.Build.command(self, args, cwd, cap, env if env is not None else self.child_env,
                                      name, binary, permit_failure, started_callback)
        except BaseException:
            self.child_uncertain = True
            raise
        finally:
            print('COMMAND_DURATION ' + json.dumps({'name':name,'seconds':round(time.monotonic()-begin,3)}), flush=True)

    def compile_and_test(self):
        core.Build.compile_and_test(self)
        self.phase = 'effect-ctest'
        data = json.loads(self.command([self.ctest,'--test-dir',self.build,'--show-only=json-v1','-R',shared.EFFECT_REGEX], name='effect-discovery-built'))
        shared.single_test(data, 'effect_scan', 'faf_effect_scan_tests.exe')
        junit = self.root/'ctest-effect.xml'
        self.command([self.ctest,'--test-dir',self.build,'-R',shared.EFFECT_REGEX,'--output-on-failure',
                      '--no-tests=error','--timeout','180','--parallel','1','--output-junit',junit], cap=210,name='ctest-effect')
        core.validate_junit(junit, ['effect_scan'])
        self.receipt['ctest_executed'].append('effect_scan')

    def capture_before(self):
        self.owned_baseline = self.owned_identity()
        self.receipt['external_input_scope'] = 'Pinned official tool acquisition and selected UCRT; no whole-SDK cross-job fingerprint needed'
        self.submodule_before = self.submodule_state()

    def submodule_state(self):
        result = {}
        for entry in self.integration['submodule_gitlinks']:
            result[entry['path']] = self.command([self.git,'-C',self.source/entry['path'],
                'status','--porcelain=v1','--untracked-files=all'],name='submodule-worktree-state')
        return result

    def check_after(self):
        self.assert_owned()
        need(self.submodule_state() == self.submodule_before, 'Submodule worktree membership/status changed')

    def upload(self):
        need(not self.child_uncertain, 'Uncertain child forbids upload')
        need(self.receipt.get('owned_cleanup_before_upload') == 'VERIFIED_ONLY_EXACT_ARTIFACT_REMAINS', 'Cleanup gate missing')
        need(sorted(self.receipt.get('ctest_executed', [])) == ['effect_scan','lua_coroutine','math_dump','sim_math'], 'Four CTests required')
        need(self.remaining(390) == 390, 'Upload and final cleanup window unavailable')
        # Provider CLI only gets its service environment; compilers never do.
        self.phase = 'exact-package-upload'
        need(self.receipt.get('ctest_result') == 'PASS', 'Test acceptance missing')
        core.checked_hash(self.artifact, self.receipt['artifact']['sha256'])
        print('PUBLIC_ARTIFACT_PREPARED '+json.dumps({'appveyor':self.receipt['appveyor'],'artifact':self.receipt['artifact']}), flush=True)
        self.command([self.appveyor,'PushArtifact',self.artifact,'-FileName',self.artifact.name],env=dict(os.environ),cap=330,name='upload',started_callback=lambda:setattr(self,'upload_attempted',True))
        self.upload_accepted = True
        self.receipt['state'] = 'UPLOAD_ACCEPTED_RETRIEVAL_NOT_VERIFIED'
        print('PUBLIC_ARTIFACT_RECEIPT '+json.dumps({'appveyor':self.receipt['appveyor'],'artifact':self.receipt['artifact'],'state':self.receipt['state']}),flush=True)

    def run_phase(self, method):
        self.phase = method.__name__
        begin = time.monotonic()
        print('PHASE_START '+json.dumps({'name':self.phase,'elapsed':round(begin-self.started,3)}),flush=True)
        try:
            return method()
        finally:
            row = {'name':method.__name__,'seconds':round(time.monotonic()-begin,3),'elapsed':round(time.monotonic()-self.started,3)}
            self.receipt.setdefault('phase_timings',[]).append(row)
            print('PHASE_END '+json.dumps(row),flush=True)

    def run(self):
        result = 1
        try:
            for method in [self.validate_contract,self.verify_configuration_checkout,self.start_workspace,
                           self.windows_cleanup_fixture,self.tools_and_runtime,self.source_assembly,
                           self.configure,self.capture_before,self.compile_and_test,self.check_after,
                           self.stage_package,self.clean_before_upload,self.upload]:
                self.run_phase(method)
            result = 0
        except Exception as exc:
            capture = self.receipt.get('build_capture', {}).get('build', {})
            print('BUILD_PROGRESS_AT_STOP '+json.dumps({k:capture.get(k) for k in ['state','returncode','last_ninja_status','elapsed_seconds','total_bytes_seen']}),flush=True)
            self.receipt['state'] = 'BLOCKED_UPLOAD_UNCERTAIN' if self.upload_attempted and not self.upload_accepted else 'BLOCKED'
            print('BUILD_BLOCKED '+json.dumps({'state':self.receipt['state'],'phase':self.phase,
                  'reason':build_capture.safe_text(str(exc),[(self.owned_root or '<none>','<owned-work>')]),
                  'upload_attempted':self.upload_attempted}),flush=True)
        finally:
            if self.owned_root:
                if self.child_uncertain:
                    result = 1
                    print('CLEANUP_UNCERTAIN no artifact fallback; ephemeral work retained for provider teardown',flush=True)
                else:
                    try:
                        self.verify_owner(); self.remove_junctions(); self.remove_owned(self.owned_root)
                    except Exception as exc:
                        result = 1
                        print('CLEANUP_INCOMPLETE '+json.dumps({'error_type':type(exc).__name__, 'errno':getattr(exc,'errno',None),'winerror':getattr(exc,'winerror',None)}),flush=True)
            print('FINALIZATION no cache, extra artifact, deployment or retry',flush=True)
        return result

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--contract', type=Path); p.add_argument('--execute', action='store_true')
    p.add_argument('--check-interpreter', action='store_true'); args = p.parse_args()
    if args.check_interpreter: core.validate_interpreter(); return 0
    if not args.execute: print('DRAFT ONLY. No execution requested.'); return 2
    need(args.contract is not None, 'Explicit contract required')
    return SingleBuild(Path(__file__).parent,core.read_json(args.contract)).run()

if __name__ == '__main__': raise SystemExit(main())
