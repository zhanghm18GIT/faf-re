#!/usr/bin/env python3
"""Emit actual-source D3D9 full-float selection/packing regression for Windows.
No compilation here. Only reads the exact public checkout. Device/classes/Matrix
are test doubles; production structs, selector, helpers and writers stay verbatim.
D3D10 aliases only satisfy unused branch linkage; no D3D10 coverage is claimed.
Native D3DX supplies conversions, not a host approximation.
"""
from pathlib import Path
import argparse, hashlib, re

def function(text, signature):
    start=text.index(signature); brace=text.index('{',start); depth=1; end=brace+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}'); end+=1
    return text[start:end]

def noincludes(text):
    return '\n'.join(l for l in text.splitlines() if not l.startswith('#include') and not l.startswith('#pragma'))

parser=argparse.ArgumentParser()
parser.add_argument('source_root',type=Path)
parser.add_argument('output_cpp',type=Path)
a=parser.parse_args()
s=a.source_root/'src'
policy=(s/'gpg/gal/MeshFormatter.cpp').read_bytes()
if hashlib.sha256(policy).hexdigest() != '3aac870af7d02461377f2d30cd4550aeac228f3d12700b54e934861e63b75aa3':
    raise SystemExit('Unexpected full-float candidate source identity')
d3d=(s/'gpg/gal/backends/d3d9/D3D9Interfaces.cpp').read_text(encoding='utf-8-sig')
pre='#include <cstdint>\n#include <cstddef>\n#include <cstring>\n#include <cassert>\n#include <stdexcept>\n#include <string>\n#include <iostream>\n#include <d3dx9math.h>\n#ifdef NDEBUG\n#error Full-float regression requires active assertions\n#endif\nnamespace msvc8 {using string=std::string;}\nnamespace gpg::gal {\nstruct Matrix {struct Row {float x,y,z,w;}; Row r[4];};\nenum class DeviceApi {Direct3D9,Direct3D10,Direct3D11,Direct3D12,Vulkan};\nstruct DeviceContext {bool mHWBasedInstancing=true; bool mSupportsFloat16=true; DeviceApi mDeviceType=DeviceApi::Direct3D9;};\nstruct Device {DeviceContext context; static Device* GetInstance(){static Device d;return &d;} DeviceContext* GetDeviceContext(){return &context;}};\nstruct Error:std::runtime_error {Error(const std::string&,int,const std::string&s):runtime_error(s){}};\nstruct MeshVertex;\nstruct MeshFormatter {virtual ~MeshFormatter();virtual bool AllowMeshInstancing()=0;};\nbool MeshInstancingEnabled();bool MeshFloat16Enabled();\nstruct HardwareVertexFormatterD3D9:MeshFormatter {bool AllowMeshInstancing() override; std::uint32_t GetVertexStride(std::int32_t,std::int32_t);void WriteFormattedVertex(std::int32_t,void*,const MeshVertex&,std::int32_t);};\nstruct Float16HardwareVertexFormatterD3D9:MeshFormatter {bool AllowMeshInstancing() override; std::uint32_t GetVertexStride(std::int32_t,std::int32_t);void WriteFormattedVertex(std::int32_t,void*,const MeshVertex&,std::int32_t);};\nusing HardwareVertexFormatterD3D10=HardwareVertexFormatterD3D9;\nusing Float16HardwareVertexFormatterD3D10=Float16HardwareVertexFormatterD3D9;\n\n}\n'
funcs=['static void CopyMatrix4x3Rows(', 'static void PackFloat2ToHalf2(', 'static void PackFloat3ToHalf3(', 'bool HardwareVertexFormatterD3D9::AllowMeshInstancing()', 'bool Float16HardwareVertexFormatterD3D9::AllowMeshInstancing()', 'std::uint32_t HardwareVertexFormatterD3D9::GetVertexStride(', 'std::uint32_t Float16HardwareVertexFormatterD3D9::GetVertexStride(', 'void HardwareVertexFormatterD3D9::WriteFormattedVertex(', 'void Float16HardwareVertexFormatterD3D9::WriteFormattedVertex(']
main='\nint main(){using namespace gpg::gal;\nassert(sMeshAllowInstancing==1);assert(sMeshAllowFloat16==0);\nauto& c=Device::GetInstance()->context;\nResetHardwareVertexFormatter();auto*p=GetHardwareVertexFormatter();\nassert((dynamic_cast<Float16HardwareVertexFormatterD3D9*>(p)!=nullptr)==bool(0));\nunsigned count=0;\nfor(int sw=0;sw<2;sw++)for(int inst=0;inst<2;inst++)for(int hw=0;hw<2;hw++)for(int cap=0;cap<2;cap++){\nsMeshAllowFloat16=sw;sMeshAllowInstancing=inst;c.mHWBasedInstancing=hw;c.mSupportsFloat16=cap;ResetHardwareVertexFormatter();p=GetHardwareVertexFormatter();\nassert((p!=nullptr)==bool(inst&&hw));if(p)assert((dynamic_cast<Float16HardwareVertexFormatterD3D9*>(p)!=nullptr)==bool(sw&&cap));count++;}\nsMeshAllowInstancing=1;c.mHWBasedInstancing=true;c.mSupportsFloat16=true;sMeshAllowFloat16=0;ResetHardwareVertexFormatter();auto*full=GetHardwareVertexFormatter();sMeshAllowFloat16=1;assert(GetHardwareVertexFormatter()==full);ResetHardwareVertexFormatter();assert(dynamic_cast<Float16HardwareVertexFormatterD3D9*>(GetHardwareVertexFormatter()));\nHardwareVertexFormatterD3D9 f;Float16HardwareVertexFormatterD3D9 h;\nassert(f.GetVertexStride(0,0)==72&&f.GetVertexStride(1,0)==76);assert(h.GetVertexStride(0,0)==44&&h.GetVertexStride(1,0)==68);\nMeshVertex v{};v.scroll[0]=9.49896908f;v.scroll[1]=9.51095009f;v.shaderTime=7.125f;v.parameter=-2.25f;v.meshColor=.75f;v.color=0x12345678;v.instanceIndex=17;v.bonePaletteBase=19;v.dissolve=21;v.useSecondaryData=1;\nfor(int i=0;i<4;i++)v.transform.r[i]={float(i*4),float(i*4+1),float(i*4+2),float(i*4+3)};\nstruct Guard {std::uint64_t before=0x12345678;HardwareVertexInstance value{};std::uint64_t after=0x87654321;} g;\nf.WriteFormattedVertex(1,&g.value,v,0);assert(g.before==0x12345678&&g.after==0x87654321);\nassert(!std::memcmp(g.value.scroll,v.scroll,8));assert(g.value.shaderTime==v.shaderTime&&g.value.parameter==v.parameter&&g.value.color==v.color&&g.value.meshColor==v.meshColor);assert(g.value.secondaryDataMask==255&&g.value.instanceIndex==17&&g.value.bonePaletteBase==19&&g.value.dissolve==21);\nfor(int i=0;i<4;i++)for(int j=0;j<3;j++)assert(g.value.transform[i][j]==float(i*4+j));\nfloat material[4];std::memcpy(material,reinterpret_cast<char*>(&g.value)+52,16);assert(material[2]==v.scroll[0]&&material[3]==v.scroll[1]);\nFloat16HardwareVertexInstance hv{};h.WriteFormattedVertex(1,&hv,v,0);float a,b;D3DXFloat16To32Array(&a,reinterpret_cast<const D3DXFLOAT16*>(reinterpret_cast<const char*>(&hv)+56),1);D3DXFloat16To32Array(&b,reinterpret_cast<const D3DXFLOAT16*>(reinterpret_cast<const char*>(&hv)+58),1);assert(b-a==0.0078125f);assert(material[3]-material[2]>0.0119f);\nHardwareVertex geo{};v.position[0]=9.49896908f;v.normal[1]=.1234567f;v.texCoord1[1]=9.51095009f;v.boneIndices[3]=3;f.WriteFormattedVertex(0,&geo,v,0);assert(geo.position[0]==v.position[0]&&geo.position[3]==1&&geo.normal[1]==v.normal[1]&&geo.texCoords[3]==v.texCoord1[1]&&geo.boneIndices[3]==3);\nstd::cout<<"PASS actual source: startup default "<<0<<", "<<count<<" selection combinations, cached selection/reset, stride/layout, full instance and geometry writers, TEXCOORD6.zw bytes; half numerical conversion uses native Microsoft D3DX; device/formatter declarations are doubles; D3D9 selector only\\n";\n}\n'
tables=[]
for name in ('kFloat16VertexStrideTableDefault','kFloat16VertexStrideTableCompact'):
    match=re.search(r'constexpr std::uint32_t '+name+r'\[2\]\s*=\s*\{[^}]+\};', d3d)
    if match is None: raise SystemExit('Missing actual stride table '+name)
    tables.append(match[0])
bodies='\n'.join(function(d3d,f) for f in funcs)
read=lambda x:(s/x).read_text(encoding='utf-8-sig')
generated=(pre+noincludes(read('gpg/gal/MeshVertex.h'))+'\n'+noincludes(policy.decode('utf-8-sig'))+
    '\nnamespace gpg::gal {\n'+'\n'.join(tables)+'\n'+bodies+'\n}\n'+noincludes(read('gpg/gal/MeshVertex.cpp'))+main)
a.output_cpp.write_text(generated,encoding='utf-8')
