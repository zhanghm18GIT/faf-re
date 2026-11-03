#pragma once
// Original synthetic test content. No game shaders or assets.
inline constexpr const char* kWarpEffect = R"fx(
float4 TestColor;
texture TestTexture;
sampler TestSampler = sampler_state {
    Texture = <TestTexture>;
    Filter = MIN_MAG_MIP_POINT;
    AddressU = Clamp;
    AddressV = Clamp;
};
float4 TestVS(uint id : SV_VertexID) : SV_Position {
    float2 p = id == 0 ? float2(-1, -1) : (id == 1 ? float2(-1, 3) : float2(3, -1));
    return float4(p, 0.5, 1);
}
float4 TestPS() : SV_Target0 {
    return TestColor * tex2D(TestSampler, float2(0.5, 0.5));
}
technique10 Test {
    pass P {
        SetVertexShader(CompileShader(vs_4_0, TestVS()));
        SetPixelShader(CompileShader(ps_4_0, TestPS()));
    }
}
)fx";
inline constexpr const char* kFillerEffect = R"fx(
texture FillerTexture;
technique10 Filler { pass P { } }
)fx";
