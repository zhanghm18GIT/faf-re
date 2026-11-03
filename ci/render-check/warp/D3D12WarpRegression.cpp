// Narrow integration regression for DeviceD3D12::BindPass upload lifetime.
// Calls production public APIs, executes DXIL on WARP, reads an offscreen target.
// No altered access control, private layout, game startup, HWND, or game assets.
#include <Windows.h>
#include <d3d12.h>
#include <d3d12sdklayers.h>
#include <dxgi1_4.h>
#include <wrl/client.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawContext.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "gpg/gal/backends/d3d12/DeviceD3D12.h"
#include "gpg/gal/backends/dxgi/DxgiFactory.h"
#include "gpg/gal/effects/EffectRuntime.h"
#include "SyntheticEffect.h"

using Microsoft::WRL::ComPtr;
using namespace gpg::gal;
namespace {
constexpr std::uint64_t kPageBytes = 8ULL << 20;
constexpr unsigned kTablesPerArena = 262144U / effects::kMaxTextureSlots;
constexpr int kSkip = 77;
constexpr int kPoisonObserved = 42;
constexpr std::array<float, 4> kGreen{0, 1, 0, 1};
constexpr std::array<float, 4> kRed{1, 0, 0, 1};
void Require(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}
bool SameLuid(LUID a, LUID b) { return a.LowPart == b.LowPart && a.HighPart == b.HighPart; }
int Skip(const char* reason, HRESULT hr = S_OK) {
    std::printf("SKIP WARP_REGRESSION reason=%s HRESULT=0x%08lX\n", reason, static_cast<unsigned long>(hr));
    return kSkip;
}
struct DeviceLifetime { ~DeviceLifetime() { Device::DestroyInstance(); } };

void SetTarget(DeviceD3D12& device, const boost::shared_ptr<RenderTarget>& target, unsigned size, unsigned color) {
    OutputContext output(target, boost::shared_ptr<DepthStencilTarget>());
    device.ClearTarget(&output);
    D3DVIEWPORT9 viewport{};
    viewport.Width = viewport.Height = size;
    viewport.MaxZ = 1;
    device.SetViewport(&viewport);
    device.Clear(true, false, false, color, 1, 0);
}
void Configure(effects::EffectProgram& program, const boost::shared_ptr<RenderTarget>& white) {
    const auto color = program.FindParameter("TestColor");
    const auto texture = program.FindParameter("TestTexture");
    Require(color >= 0 && texture >= 0, "synthetic effect parameters missing");
    program.Parameters().SetVector(static_cast<unsigned>(color), kGreen.data());
    program.Parameters().SetRenderTarget(static_cast<unsigned>(texture), white);
    Require(program.Parameters().Constants().size() == 16, "synthetic constants must occupy exactly 16 bytes");
    const auto* slot = program.Modern().constants.Find(static_cast<unsigned>(color));
    Require(slot && slot->offset == 0 && slot->size == 16, "TestColor layout mismatch");
    Require(program.Modern().textures.size() == 1, "synthetic sample must use one texture descriptor");
    const auto entries = program.Entries(0, 0);
    Require(entries.vertex >= 0 && entries.pixel >= 0, "synthetic shader entries missing");
    for (const auto entry : {entries.vertex, entries.pixel}) {
        const auto& shader = program.Shader(static_cast<unsigned>(entry));
        if (!shader.succeeded) {
            std::printf("SHADER_FAILURE %s\n", shader.messages.c_str());
            throw std::runtime_error("synthetic shader compilation failed");
        }
    }
}

int Run(const std::string& name) {
    const bool boundary = name == "rollover-boundary";
    const bool validPrior = boundary || name == "same-page-carry";
    const bool rollover = name != "no-rollover" && name != "threshold-only";
    const bool poison = name != "no-poison";
    const bool threshold = name == "threshold-only" || name == "rollover-threshold";
    Require(name == "rollover-invalid" || boundary || name == "same-page-carry" ||
            name == "no-rollover" || name == "no-poison" || threshold, "unknown case");
    // Set before the function-local diagnostic limit is first initialized.
    Require(_putenv_s("FAF_GAL_UPLOAD_SUBMIT_KB", threshold ? "1" : "") == 0, "cannot set upload threshold");
    Require(std::getenv("FAF_GAL_SOLID_PS") == nullptr && std::getenv("FAF_GAL_CLEAR_TEST") == nullptr,
            "external render diagnostic overrides are forbidden");
    Require(std::getenv("FAF_SHADER_CACHE_DIR") != nullptr, "runner must provide an isolated shader-cache directory");

    ComPtr<IDXGIFactory4> factory;
    HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(hr)) return Skip("DXGI_factory_unavailable", hr);
    ComPtr<IDXGIAdapter1> warp;
    hr = factory->EnumWarpAdapter(IID_PPV_ARGS(&warp));
    if (FAILED(hr)) return Skip("EnumWarpAdapter_unavailable", hr);
    DXGI_ADAPTER_DESC1 warpDesc{};
    hr = warp->GetDesc1(&warpDesc);
    if (FAILED(hr)) return Skip("WARP_description_unavailable", hr);
    Require((warpDesc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0, "EnumWarpAdapter did not identify software");

    // Respect production adapter filtering. Never silently use hardware or alter it.
    dxgi::Factory backendFactory;
    hr = backendFactory.Create();
    if (FAILED(hr)) return Skip("backend_DXGI_factory_unavailable", hr);
    backendFactory.EnumerateAdapters(DXGI_FORMAT_B8G8R8A8_UNORM);
    int adapterIndex = -1;
    for (unsigned i = 0; i < backendFactory.Adapters().size(); ++i) {
        const auto& a = backendFactory.Adapters()[i];
        if (a.IsSoftware() && SameLuid(a.desc.AdapterLuid, warpDesc.AdapterLuid)) adapterIndex = static_cast<int>(i);
    }
    if (adapterIndex < 0) return Skip("WARP_not_exposed_by_production_adapter_filter");

    d3d12::Library library;
    if (!library.Load()) return Skip("system_D3D12_unavailable");
    ComPtr<ID3D12Debug> debug;
    const bool debugAvailable = library.getDebugInterface && SUCCEEDED(library.getDebugInterface(IID_PPV_ARGS(&debug)));
    if (debugAvailable) debug->EnableDebugLayer();
    std::printf("DEBUG_LAYER %s\n", debugAvailable ? "enabled" : "unavailable_not_installed");
    ComPtr<ID3D12Device> preflight;
    hr = library.createDevice(warp.Get(), D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&preflight));
    if (FAILED(hr)) return Skip("system_WARP_D3D12_device_unavailable", hr);
    D3D12_FEATURE_DATA_SHADER_MODEL sm{D3D_SHADER_MODEL_6_0};
    hr = preflight->CheckFeatureSupport(D3D12_FEATURE_SHADER_MODEL, &sm, sizeof(sm));
    if (FAILED(hr) || sm.HighestShaderModel < D3D_SHADER_MODEL_6_0) return Skip("system_WARP_lacks_SM6_DXIL", hr);
    preflight.Reset();
    if (!effects::ShaderCompiler::Instance().Available()) {
        std::printf("DXC_DETAIL %s\n", effects::ShaderCompiler::Instance().LoadError().c_str());
        return Skip("pinned_DXC_runtime_unavailable");
    }
    if (!imaging::ImageCodec::Instance()) return Skip("D3DX11_43_or_D3D11_WARP_image_codec_unavailable");

    DeviceLifetime lifetime;
    DeviceContext context(DeviceApi::Direct3D12); // zero heads: no window or swap chain
    context.mAdapter = adapterIndex;
    auto& device = *static_cast<DeviceD3D12*>(Device::Create(&context));
    Require(device.GetDeviceContext()->mDeviceType == DeviceApi::Direct3D12, "wrong backend");
    Require(SameLuid(device.Native()->GetAdapterLuid(), warpDesc.AdapterLuid), "backend did not select verified WARP adapter");
    DeviceRuntimeInfo runtime;
    Require(device.GetRuntimeInfo(runtime), "missing runtime identity");
    std::printf("RUNTIME api=%s adapter=%s vendor=0x%04X device=0x%04X heads=%d\n",
                runtime.api.c_str(), runtime.adapter.c_str(), runtime.vendorId, runtime.deviceId,
                device.GetDeviceContext()->GetHeadCount());
    ComPtr<ID3D12InfoQueue> info;
    if (debugAvailable) Require(SUCCEEDED(device.Native()->QueryInterface(IID_PPV_ARGS(&info))), "debug queue missing");

    const RenderTargetContext whiteContext(1, 1, 2), targetContext(8, 8, 2);
    auto white = device.CreateRenderTarget(&whiteContext);
    auto target = device.CreateRenderTarget(&targetContext);
    SetTarget(device, white, 1, 0xFFFFFFFFU);
    SetTarget(device, target, 8, 0xFFFF00FFU); // magenta distinguishes skipped draw from poisoned red
    auto& nativeTarget = *static_cast<RenderTargetD3D12*>(target.get());
    Require(nativeTarget.Format() == DXGI_FORMAT_B8G8R8A8_UNORM, "unexpected readback format");
    effects::EffectProgram filler("warp_filler.fx", kFillerEffect, effects::ShaderTarget::Dxil);
    effects::EffectProgram previous("warp_previous.fx", kWarpEffect, effects::ShaderTarget::Dxil);
    effects::EffectProgram current("warp_current.fx", kWarpEffect, effects::ShaderTarget::Dxil);
    Configure(previous, white);
    Configure(current, white);
    Require(filler.Parameters().Constants().empty(), "filler must not upload constants");
    Require(filler.Entries(0, 0).vertex < 0, "filler must leave an invalid prior pass");
    const int fillerTexture = filler.FindParameter("FillerTexture");
    Require(fillerTexture >= 0, "filler texture missing");

    const auto initialSerial = device.RecordingSerial();
    // Every genuine BindPass allocates the ordinary 64-descriptor table. No tiny heaps.
    const unsigned fillCount = rollover ? kTablesPerArena - (validPrior ? 1U : 0U) : 2U;
    for (unsigned i = 0; i < fillCount; ++i) {
        filler.Parameters().SetTexture(static_cast<unsigned>(fillerTexture), boost::shared_ptr<Texture>());
        device.BindPass(filler, 0, 0);
    }
    Require(device.RecordingSerial() == initialSerial, "unexpected submission while filling descriptor arena");
    // No uploads happen in Setup, target clearing or these filler passes on the pinned source.
    // An anchor makes page reuse directly observable through the public allocation result.
    const auto anchor = device.AllocateUpload(boundary ? kPageBytes - 512U : (threshold ? 2048U : 256U), 256);
    Require(anchor.offset == 0, "first upload did not start at the fresh page boundary");
    if (validPrior) device.BindPass(previous, 0, 0);
    const auto beforeBind = device.RecordingSerial();
    device.BindPass(current, 0, 0);
    const auto afterBind = device.RecordingSerial();
    const unsigned requiredSubmits = (rollover ? 1U : 0U) + (threshold ? 1U : 0U);
    Require(afterBind == beforeBind + requiredSubmits, "expected rollover/threshold submission did not occur exactly");

    bool anchorReused = false;
    if (poison) {
        const auto overwrite = device.AllocateUpload(kPageBytes, 256);
        // Do not allow this pressure call to hide the bug by carrying current constants.
        Require(device.RecordingSerial() == afterBind, "poison upload unexpectedly submitted before draw");
        anchorReused = overwrite.resource == anchor.resource;
        for (std::uint64_t at = 0; at < kPageBytes; at += sizeof(kRed)) {
            std::memcpy(overwrite.cpu + at, kRed.data(), sizeof(kRed));
        }
    }
    const DrawContext draw(DrawContext::TOPOLOGY_TRIANGLELIST, 3, 0);
    device.DrawPrimitive(&draw);
    std::vector<std::uint8_t> pixels;
    std::uint32_t pitch = 0;
    device.ReadSubresource(nativeTarget.Current().resource, 0, pixels, pitch);
    Require(pitch == 32 && pixels.size() == 256, "unexpected offscreen readback footprint");
    Require(SUCCEEDED(device.Native()->GetDeviceRemovedReason()), "D3D12 device was removed");
    if (info) {
        Require(info->GetNumMessagesDiscardedByMessageCountLimit() == 0, "D3D12 debug messages were discarded");
        unsigned errors = 0, warnings = 0;
        for (UINT64 i = 0; i < info->GetNumStoredMessagesAllowedByRetrievalFilter(); ++i) {
            SIZE_T size = 0;
            Require(SUCCEEDED(info->GetMessage(i, nullptr, &size)) && size >= sizeof(D3D12_MESSAGE),
                    "cannot size D3D12 validation message");
            std::vector<std::uint8_t> buffer(size);
            auto* message = reinterpret_cast<D3D12_MESSAGE*>(buffer.data());
            Require(SUCCEEDED(info->GetMessage(i, message, &size)), "cannot retrieve D3D12 validation message");
            if (message->Severity <= D3D12_MESSAGE_SEVERITY_ERROR) {
                ++errors;
                std::printf("D3D12_ERROR id=%u %s\n", message->ID, message->pDescription);
            } else if (message->Severity == D3D12_MESSAGE_SEVERITY_WARNING) {
                ++warnings;
                std::printf("D3D12_WARNING id=%u %s\n", message->ID, message->pDescription);
            }
        }
        std::printf("DEBUG_MESSAGES errors=%u warnings=%u\n", errors, warnings);
        Require(errors == 0, "D3D12 validation error, not a valid lifetime result");
    }
    bool green = true, red = true;
    // Interior avoids unrelated pixel-centre conventions at viewport edges.
    for (unsigned y = 2; y < 6; ++y) for (unsigned x = 2; x < 6; ++x) {
        const auto* p = &pixels[y * pitch + x * 4];
        green &= p[0] == 0 && p[1] == 255 && p[2] == 0 && p[3] == 255;
        red &= p[0] == 0 && p[1] == 0 && p[2] == 255 && p[3] == 255;
    }
    std::printf("OBSERVATION case=%s bind_serial=%llu->%llu anchor_reused=%d center_bgra=%u,%u,%u,%u\n",
                name.c_str(), static_cast<unsigned long long>(beforeBind), static_cast<unsigned long long>(afterBind),
                anchorReused ? 1 : 0, pixels[3 * pitch + 12], pixels[3 * pitch + 13], pixels[3 * pitch + 14], pixels[3 * pitch + 15]);
    if (green) {
        std::printf("PASS WARP_REGRESSION case=%s sampled_texture_and_constants_intact\n", name.c_str());
        return 0;
    }
    if (red && poison && anchorReused && (name == "rollover-invalid" || boundary)) {
        std::printf("FAIL_EXPECTED_POISON WARP_REGRESSION case=%s retired_upload_page_reused_red_constant\n", name.c_str());
        return kPoisonObserved;
    }
    throw std::runtime_error("unexpected pixel value or missing page-reuse evidence; not the intended baseline failure");
}
} // namespace
int main(int argc, char** argv) {
    try {
        Require(argc == 2, "usage: faf_d3d12_warp_regression CASE");
        return Run(argv[1]);
    } catch (const std::exception& error) {
        std::printf("FAIL WARP_REGRESSION %s\n", error.what());
        return 1;
    } catch (...) {
        std::printf("FAIL WARP_REGRESSION non-standard exception\n");
        return 1;
    }
}
