from pathlib import Path
import hashlib,json
D=Path(__file__).parent
core=(D/'sources/D3D12Core.cpp').read_text()
base=(D/'sources/base-DeviceD3D12.cpp').read_text()
head=(D/'sources/head-DeviceD3D12.cpp').read_text()
expected_blobs = {'base-DeviceD3D12.cpp':'b3ba08d1997ddd37a40daed7577af38ec499f5c5','head-DeviceD3D12.cpp':'16eec18197654c826714c822ae2d94af960bc590','D3D12Core.cpp':'ef24a2a81ef90c2e6249bd7da004b77364fa15bf'}
for name, expected in expected_blobs.items():
 b=(D/'sources'/name).read_bytes()
 assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==expected, name+' changed'
def method(s, signature):
 p=s.index(signature); q=s.index('{',p); depth=1; end=q+1
 while depth:
  depth += (s[end]=='{')-(s[end]=='}'); end+=1
 return s[p:end]
def snap(s):
 p=s.index('    const std::span<const std::uint8_t> constants = parameters.Constants();', s.index('void DeviceD3D12::BindPass'))
 q=s.index('    if (!constants.empty())',p)
 return s[p:q]+method(s[q:], '    if (!constants.empty())')
assert snap(base)==snap(head)
# Fail closed if the ordering assumptions no longer match this revision.
for s,fixed in [(base,False),(head,True)]:
 bind=method(s,'void DeviceD3D12::BindPass')
 assert (bind.index('AllocateTable(effects::kMaxTextureSlots') < bind.index('parameters.Constants()')) == fixed
 assert bind.index('parameters.Constants()') < bind.index('mPass =')
 submit=method(s,'void DeviceD3D12::Submit')
 assert submit.index('++mSubmittedSerial') < submit.index('WaitForSerial') < submit.index('CarryBoundPass()') < submit.index('CollectCompleted()')
 table=method(s,'D3D12_GPU_DESCRIPTOR_HANDLE DeviceD3D12::AllocateTable')
 assert table.index('Submit(true)') < table.index('views.Reset()') < table.index('++mArenaEpoch')
 assert 'views.Reset' not in method(s,'d3d12::UploadAllocation DeviceD3D12::AllocateUpload')
 assert 'mUpload.Retire(completed)' in method(s,'void DeviceD3D12::CollectCompleted')
methods='\n'.join(method(core,s) for s in ['UploadAllocation UploadAllocator::Allocate','void UploadAllocator::Retire','std::uint64_t UploadAllocator::TakeAllocatedBytes','std::uint64_t UploadAllocator::BusyBytes','bool DescriptorArena::Allocate'])
carry=method(head,'bool DeviceD3D12::CarryBoundPass')
table=method(head,'D3D12_GPU_DESCRIPTOR_HANDLE DeviceD3D12::AllocateTable')
upload=method(head,'d3d12::UploadAllocation DeviceD3D12::AllocateUpload')
# Original AllocateUpload has process-static accounting/config. Tests require a fresh
# device per case, so these two declarations become fixture members (same logic).
upload=upload.replace('    static std::uint64_t sinceSubmit = 0U;','')
p=upload.index('    static const std::uint64_t kSubmitAfter = [] {')
q=upload.index('    if (sinceSubmit',p)
upload=upload[:p]+upload[q:]
prefix=(D/'harness.cpp.in').read_text()
for name,code in [('CORE',methods),('CARRY',carry),('TABLE',table),('UPLOAD',upload),('SNAP',snap(head))]:
 prefix=prefix.replace('/*@'+name+'@*/',code)
(D/'generated.cpp').write_text(prefix)
manifest={'head':'41840bd3236ad7dcf8bda9ccd9fc6059d3692cc4','base':'9ed4a96d517fed91c90e48accea1febfea673ce8','files':{str(p.relative_to(D)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (D/'sources').iterdir()},'extraction':'Exact allocator Allocate/Retire/BusyBytes/TakeAllocatedBytes, descriptor Allocate, CarryBoundPass, AllocateTable, snapshot; AllocateUpload static counters/config replaced by per-fixture members.'}
(D/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Source guards PASS; generated.cpp written')
