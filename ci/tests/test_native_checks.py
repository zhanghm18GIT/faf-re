import copy
import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import native_checks as n
import driver

class Checks(unittest.TestCase):
    def test_codec_pass(self): n.check_codec(0,'PASS x\n0 failed\n')
    def test_codec_no_device(self):
        with self.assertRaises(n.GateError): n.check_codec(0,'SKIP: no WARP device\n')
    def test_codec_format_skip(self):
        with self.assertRaises(n.GateError): n.check_codec(0,'SKIP: format\n0 failed\n')
    def test_codec_nonzero(self):
        with self.assertRaises(n.GateError): n.check_codec(1,'0 failed\n')
    def test_codec_missing(self):
        with self.assertRaises(n.GateError): n.check_codec(0,'PASS\n')
    def test_codec_ambiguous(self):
        with self.assertRaises(n.GateError): n.check_codec(0,'0 failed\n1 failed\n')
    def test_unsafe_paths(self):
        for s in ['/a','../a','a/../b','C:/a','a\\b','']:
            with self.subTest(s=s),self.assertRaises(n.GateError): n.relative(s)
    def cache(self):
        return {**{x:'OFF' for x in n.OFF},'CMAKE_BUILD_TYPE':'Release','CMAKE_GENERATOR':'Ninja','FAF_PGO_PROFILE':'','FAF_OUTPUT_NAME':'main_x64','FAF_FETCH_DEPENDENCIES':'OFF','FAF_UCRT_LIB_VERSION':'10.0.22000.0'}
    def test_cache(self): n.check_cache(self.cache())
    def test_cache_on(self):
        for key in self.cache():
            with self.subTest(key=key),self.assertRaises(n.GateError): n.check_cache({**self.cache(),key:'wrong'})
    def test_pch_actual_name(self): self.assertIn('FAF_PCH',n.OFF);self.assertNotIn('FAF_ENABLE_PCH',n.OFF)
    def test_build_info(self):
        v='#define FAF_BUILD_SHOWN "a-dirty"\n#define FAF_BUILD_COMMIT "a"\n#define FAF_BUILD_DIRTY 1\n#define FAF_BUILD_ARCH "x64"\n#define FAF_BUILD_CONFIG "Release"\n'
        n.check_build_info(v,'a')
        with self.assertRaises(n.GateError): n.check_build_info(v.replace('DIRTY 1','DIRTY 0'),'a')
    def test_junit(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'j.xml'
            p.write_text('<testsuite>'+''.join('<testcase name="'+s+'"/>' for s in n.CTESTS)+'</testsuite>'); n.check_junit(p)
            p.write_text('<testsuite>'+''.join('<testcase name="'+s+'"><skipped/></testcase>' for s in n.CTESTS)+'</testsuite>')
            with self.assertRaises(n.GateError): n.check_junit(p)
    def test_empty_junit(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'j.xml';p.write_text('<testsuite/>')
            with self.assertRaises(n.GateError): n.check_junit(p)
    def discovery(self):
        e={'sim_math':['/b/tests/faf_sim_math_tests.exe','/s/tests/sim_math/golden.txt'],
           'math_dump':['/b/tests/faf_math_dump.exe','--check','/s/tests/math_dump/golden.txt','--values','/s/tests/math_dump/retail_values.txt'],
           'lua_coroutine':['/b/tests/faf_coroutine_tests.exe'],'effect_scan':['/b/tests/faf_effect_scan_tests.exe'],'image_codec':['/b/tests/faf_image_codec_tests.exe'],'replay_scan':['/b/tests/faf_replay_scan_tests.exe'],'texture_quality':['/b/tests/faf_texture_quality_tests.exe']}
        return {'tests':[{'name':x,'command':e.get(x,[])} for x in n.ALL_CTESTS]}
    def test_discovery(self): self.assertEqual(len(n.check_discovery(self.discovery(),'/s','/b')),8)
    def test_math_cannot_reduce(self):
        d=self.discovery();next(t for t in d['tests'] if t['name']=='math_dump')['command']+=['--iters','131072']
        with self.assertRaises(n.GateError):n.check_discovery(d,'/s','/b')
    def test_missing_discovery(self):
        d=self.discovery(); d['tests'].pop()
        with self.assertRaises(n.GateError): n.check_discovery(d,'/s','/b')
    def test_exact_inputs(self):
        here=Path(__file__).resolve().parents[1];x=json.loads((here/'inputs.json').read_text())
        self.assertEqual(x['candidate_tree'],'ff340b16db5af1cbb76df051a9a7439c1dd08160')
        self.assertEqual(len(x['resources']),10); self.assertEqual(len(x['gitlinks']),5)
        self.assertEqual(n.digest(here/'candidate.patch'),x['patch_sha256'])
        self.assertEqual(len(n.TARGETS),9)

class Diagnostics(unittest.TestCase):
    def test_no_final_oversize(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            ctx=driver.Context(Path(d)); (ctx.logs/'build.log').write_text('abc')
            with patch.object(driver,'DIAGNOSTICS_LIMIT',1),self.assertRaises(n.GateError):driver.diagnostics(ctx)
            self.assertFalse((ctx.out/'diagnostics/diagnostics.zip').exists())
    def test_valid_zip(self):
        import zipfile
        with tempfile.TemporaryDirectory() as d:
            ctx=driver.Context(Path(d));(ctx.logs/'build.log').write_text('useful error')
            p=driver.diagnostics(ctx)
            with zipfile.ZipFile(p) as z:
                self.assertEqual(z.read('logs/build.log'),b'useful error')
                self.assertIn('DIAGNOSTIC_INDEX.json',z.namelist())
