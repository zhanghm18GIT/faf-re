#!/usr/bin/env python3
"""Generate actual-source policy regression; not an engine/GPU test.

Copies the two real eligibility bodies from each backend, the actual shared
helper bodies, defaults, DeviceApi enum, and complete MeshVertex.cpp (without
includes) into a temporary C++ translation unit. Only device storage, formatter
class declarations and Error are test doubles. No production expressions are
rewritten. Read only the checked-out public source. Compilation is handled by the CI CMake target.
"""
import argparse
from pathlib import Path
import re

def read(root, path):
    return (root / path).read_text(encoding='utf-8-sig')

def body(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

parser = argparse.ArgumentParser()
parser.add_argument('source_root', type=Path)
parser.add_argument('output_cpp', type=Path)
args = parser.parse_args()
root = args.source_root
mesh = read(root, 'src/gpg/gal/MeshFormatter.cpp')
ctx = read(root, 'src/gpg/gal/DeviceContext.hpp')
api = body(ctx, 'enum class DeviceApi') + ';'
cpp = '''#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
namespace msvc8 { using string = std::string; }
namespace gpg::gal {
'''+api+'''
struct DeviceContext { DeviceApi mDeviceType; bool mHWBasedInstancing; bool mSupportsFloat16; };
struct Device {
  DeviceContext context{};
  static Device* GetInstance() { static Device device; return &device; }
  DeviceContext* GetDeviceContext() { return &context; }
};
struct MeshFormatter { virtual ~MeshFormatter() = default; virtual bool AllowMeshInstancing() = 0; };
struct Error : std::runtime_error { Error(msvc8::string, int, msvc8::string s) : std::runtime_error(s) {} };
'''
for name in ('sMeshAllowFloat16', 'sMeshAllowInstancing'):
    cpp += re.search(r'std::uint8_t '+name+r' = [^;]+;', mesh)[0]+'\n'
for name in ('MeshInstancingEnabled', 'MeshFloat16Enabled'):
    cpp += body(mesh, 'bool '+name+'()')+'\n'
for backend in ('D3D9', 'D3D10'):
    source = read(root, f'src/gpg/gal/backends/{backend.lower()}/{backend}Interfaces.cpp')
    for prefix in ('', 'Float16'):
        name = prefix+'HardwareVertexFormatter'+backend
        cpp += f'struct {name} : MeshFormatter {{ bool AllowMeshInstancing() override; }};\n'
        cpp += body(source, 'bool '+name+'::AllowMeshInstancing()')+'\n'
cpp += '}\n'
cpp += re.sub(r'^#include[^\n]*\n', '', read(root, 'src/gpg/gal/MeshVertex.cpp'), flags=re.M)
cpp += r'''
int main() {
  using namespace gpg::gal;
  int failed = 0, cases = 0;
  if (sMeshAllowFloat16 != 1 || sMeshAllowInstancing != 1) {
    std::puts("FAIL: default policy changed"); ++failed;
  }
  const std::uint8_t switches[] = {0, 1, 2, 255};
  auto* ctx = Device::GetInstance()->GetDeviceContext();
  for (auto api : {DeviceApi::Direct3D9, DeviceApi::Direct3D10, DeviceApi::Direct3D11,
                  DeviceApi::Direct3D12, DeviceApi::Vulkan}) {
    ctx->mDeviceType = api;
    MeshFormatter* plain = api == DeviceApi::Direct3D9 ?
      static_cast<MeshFormatter*>(&sHardwareVertexFormatterD3D9) : &sHardwareVertexFormatterD3D10;
    MeshFormatter* half = api == DeviceApi::Direct3D9 ?
      static_cast<MeshFormatter*>(&sFloat16HardwareVertexFormatterD3D9) : &sFloat16HardwareVertexFormatterD3D10;
    for (auto instancing : switches) for (auto float16 : switches)
      for (bool hw : {false, true}) for (bool fp : {false, true}) {
        ++cases;
        sMeshAllowInstancing = instancing; sMeshAllowFloat16 = float16;
        ctx->mHWBasedInstancing = hw; ctx->mSupportsFloat16 = fp;
        const bool wantPlain = instancing != 0 && hw;
        const bool wantHalf = wantPlain && float16 != 0 && fp;
        MeshFormatter* expected = wantHalf ? half : (wantPlain ? plain : nullptr);
        ResetHardwareVertexFormatter();
        bool ok = plain->AllowMeshInstancing() == wantPlain;
        ok &= half->AllowMeshInstancing() == wantHalf;
        ok &= GetHardwareVertexFormatter() == expected;
        ok &= GetHardwareVertexFormatter() == expected;
        if (!ok) {
          ++failed;
          std::printf("FAIL api=%d instancing=%u float16=%u hw=%d fp=%d\n",
                      int(api), instancing, float16, hw, fp);
        }
      }
    // Cache persists until the reset used by mesh_Rebatch.
    sMeshAllowInstancing = sMeshAllowFloat16 = 1;
    ctx->mHWBasedInstancing = ctx->mSupportsFloat16 = true;
    ResetHardwareVertexFormatter();
    if (GetHardwareVertexFormatter() != half) ++failed;
    sMeshAllowFloat16 = 0;
    if (GetHardwareVertexFormatter() != half) ++failed;
    ResetHardwareVertexFormatter();
    if (GetHardwareVertexFormatter() != plain) ++failed;
    sMeshAllowInstancing = 0;
    ResetHardwareVertexFormatter();
    if (GetHardwareVertexFormatter() != nullptr) ++failed;
  }
  std::printf("%d matrix cases; %d failures (including defaults/cache transitions)\n", cases, failed);
  return failed != 0;
}
'''
args.output_cpp.write_text(cpp, encoding='utf-8')
