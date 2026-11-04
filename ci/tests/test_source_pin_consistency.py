"""Cross-check runtime literals against captured real Git tree and source bytes.
The fixture is public-source evidence, not generated from the pins being tested.
"""
from pathlib import Path
import ast,base64,hashlib,json,sys,unittest,gzip
CI=Path(__file__).resolve().parents[1];sys.path.insert(0,str(CI))
import driver

def load(name):
    p=CI/name
    return json.loads(gzip.decompress(p.read_bytes())) if name.endswith('.gz') else json.loads(p.read_text())
def git_hash(kind,data):return hashlib.sha1((kind+' '+str(len(data))+'\0').encode()+data).hexdigest()
def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def tree_hash(entries,patches=None):
    dirs={};patches=patches or {};observed={e['path']:e['sha'] for e in entries if e['type']=='tree'}
    for e in entries:
        if e['type']=='tree':continue
        parent,_,name=e['path'].rpartition('/');dirs.setdefault(parent,[]).append((name,e['mode'].lstrip('0'),patches.get(e['path'],e['sha'])))
    paths=set(dirs)
    for path in list(paths):
        while '/' in path:path=path.rsplit('/',1)[0];paths.add(path)
    paths.add('');hashes={}
    for path in sorted(paths,key=lambda p:p.count('/')+(bool(p)),reverse=True):
        rows=list(dirs.get(path,[]))
        for child,digest in hashes.items():
            parent,_,name=child.rpartition('/')
            if child and parent==path:rows.append((name,'40000',digest))
        rows.sort(key=lambda r:(r[0]+('/' if r[1]=='40000' else '')).encode())
        hashes[path]=git_hash('tree',b''.join(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest) for name,mode,digest in rows))
        if not patches and path and path in observed:assert hashes[path]==observed[path],path
    return hashes['']

class SourcePins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e=load('tests/fixtures/source_pin_evidence.json.gz');cls.tree={r['path']:r for r in cls.e['entries']};cls.m=load('integration-manifest.json')
        cls.actual={p:base64.b64decode(r['base64']) for p,r in cls.e['base_files'].items()}
    def test_real_tree_and_composite_reconstruction(self):
        self.assertEqual(driver.BASE,self.e['base']);self.assertEqual(tree_hash(self.e['entries']),driver.BASE_TREE)
        self.assertEqual(self.m['base_tree'],driver.BASE_TREE);self.assertEqual(self.m['base_commit'],driver.BASE)
        replacements={r['path']:r['after_blob'] for r in self.m['changed_files']}
        self.assertEqual(tree_hash(self.e['entries'],replacements),driver.TREE);self.assertEqual(self.m['planned_integrated_tree'],driver.TREE)
    def test_real_source_bytes_are_tree_bound(self):
        for path,data in self.actual.items():
            with self.subTest(path=path):self.assertEqual(git_hash('blob',data),self.tree[path]['sha'])
    def test_all_runtime_golden_literals_against_real_tree_and_bytes(self):
        self.assertEqual(len(driver.GOLDEN_BLOBS),10)
        for path,pin in driver.GOLDEN_BLOBS.items():
            with self.subTest(path=path):
                self.assertEqual(pin,self.tree[path]['sha']);self.assertEqual(pin,git_hash('blob',self.actual[path]))
    def test_old_buildinfo_literal_demonstrably_fails(self):
        actual=git_hash('blob',self.actual['cmake/FafBuildInfo.cmake'])
        self.assertEqual(actual,'f0c43c24596bf792598f080ddc77708d78366294')
        self.assertNotEqual(actual,'5bf0a288b9bda00993158e9b34026670807b2926')
    def test_all_build_sha256_and_integration_pin(self):
        self.assertEqual(hashlib.sha256((CI/'integration-manifest.json').read_bytes()).hexdigest(),driver.INTEGRATION_SHA)
        for path,pin in self.m['build_file_sha256'].items():
            with self.subTest(path=path):self.assertEqual(hashlib.sha256(self.actual[path]).hexdigest(),pin)
    def test_all_hook_patch_gitlink_pins(self):
        for key in ['hook_files','dependency_patch_blobs','submodule_gitlinks']:
            for row in self.m[key]:
                with self.subTest(key=key,path=row['path']):
                    self.assertEqual(row['sha'],self.tree[row['path']]['sha']);self.assertEqual(row['mode'],self.tree[row['path']]['mode'])
    def test_pr_before_after_actual_bytes(self):
        bypath={r['path']:r for r in self.e['changed_files']}
        for row in self.m['changed_files']:
            actual=bypath[row['path']];data=base64.b64decode(actual['base64'])
            self.assertEqual(row['head'],actual['head']);self.assertEqual(row['before_blob'],self.tree[row['path']]['sha'])
            self.assertEqual(row['before_sha256'],hashlib.sha256(self.actual[row['path']]).hexdigest())
            self.assertEqual(row['after_blob'],git_hash('blob',data));self.assertEqual(row['after_sha256'],hashlib.sha256(data).hexdigest())
    def test_all_source_allowlist_entries(self):
        allow=load('public-source-allowlist.json');replace={r['path']:r['after_blob'] for r in self.m['changed_files']}
        self.assertEqual(allow['base'],driver.BASE);self.assertEqual(allow['composite_tree'],driver.TREE)
        for row in allow['files']:
            self.assertEqual(row['git_blob'],replace.get(row['path'],self.tree[row['path']]['sha']),row['path'])
            self.assertEqual(row['mode'],self.tree[row['path']]['mode'])
    def test_dependency_configuration_inputs(self):
        dep=load('dependency-recipe.json')
        for path,pin in dep['configuration_input_blobs'].items():self.assertEqual(pin,self.tree[path]['sha'],path)
        for row in dep['dependency_gitlinks']:self.assertEqual(row['sha'],self.tree[row['path']]['sha'])
        self.assertEqual(load('resume-recipe.json')['base_dependency_recipe'],canonical(dep))
    def test_excluded_source_provenance_is_current(self):
        for row in load('source-material-policy.json')['excluded_product_linux_only_material']:
            self.assertEqual(row['git_blob'],self.tree[row['path']]['sha'],row['path'])
            self.assertEqual(row['bytes'],self.e['tree_sizes'][row['path']])
    def test_external_hardcoded_blob_literals_from_pinned_archives(self):
        literals={node.value for node in ast.walk(ast.parse((CI/'driver.py').read_text())) if isinstance(node,ast.Constant) and isinstance(node.value,str)}
        for row in self.e['external_files']:
            self.assertEqual(git_hash('blob',base64.b64decode(row['base64'])),row['git_blob'])
            self.assertIn(row['git_blob'],literals)
            self.assertEqual(row['gitlink'],self.tree['dependencies/'+row['component']]['sha'])
    def test_contract_distribution_and_recipe_hashchains(self):
        d=load('distribution-review.json');self.assertEqual(d['composite_tree'],driver.TREE)
        self.assertEqual(d['material_selection_sha256'],hashlib.sha256((CI/'source-material-policy.json').read_bytes()).hexdigest())
        self.assertEqual(d['public_source_allowlist_sha256'],hashlib.sha256((CI/'public-source-allowlist.json').read_bytes()).hexdigest())
        for p in CI.glob('execution-*.json'):
            c=json.loads(p.read_text());self.assertEqual(c['dependency_recipe_sha256'],canonical(load('dependency-recipe.json')))
            self.assertEqual(c['distribution_review_sha256'],hashlib.sha256((CI/'distribution-review.json').read_bytes()).hexdigest())
            if 'resume_recipe_sha256' in c:self.assertEqual(c['resume_recipe_sha256'],canonical(load('artifact-recipe.json' if c.get('mode')=='public-artifact-build-resume-v1' else 'resume-recipe.json')))
if __name__=='__main__':unittest.main()
