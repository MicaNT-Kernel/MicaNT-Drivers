// ============================================================================
// MicaNT: Prism3D Acceleration & Shading Engine (Direct3D 11/12 Compatible)
// 
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/DirectX-Headers (directx/d3d11*.h, d3d12*.h)
//   - https://github.com/microsoft/DirectXTK (VertexTypes, SimpleMath)
//   - https://github.com/microsoft/win32metadata
//
// Trademark & Nominative Fair Use Notice:
//   Prism3D is an independent, sovereign 3D graphics rendering subsystem
//   designed for MicaNT, named in tribute to Dave Cutler's 1988 DEC PRISM
//   architecture. DirectX, Direct3D, and DXGI are registered trademarks
//   of Microsoft Corporation.
// ============================================================================

#pragma once

#include "prismx.hpp"
#include <vector>
#include <memory>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <atomic>
#include <iostream>

namespace micant::prism3d {

using namespace micant::prismx;

// ============================================================================
// 1. Core Direct3D Enums & Structs
// ============================================================================

enum D3D_FEATURE_LEVEL : uint32_t {
    D3D_FEATURE_LEVEL_9_1  = 0x9100,
    D3D_FEATURE_LEVEL_9_2  = 0x9200,
    D3D_FEATURE_LEVEL_9_3  = 0x9300,
    D3D_FEATURE_LEVEL_10_0 = 0xa000,
    D3D_FEATURE_LEVEL_10_1 = 0xa100,
    D3D_FEATURE_LEVEL_11_0 = 0xb000,
    D3D_FEATURE_LEVEL_11_1 = 0xb100,
    D3D_FEATURE_LEVEL_12_0 = 0xc000,
    D3D_FEATURE_LEVEL_12_1 = 0xc100,
    D3D_FEATURE_LEVEL_12_2 = 0xc200
};

enum D3D_DRIVER_TYPE : uint32_t {
    D3D_DRIVER_TYPE_UNKNOWN   = 0,
    D3D_DRIVER_TYPE_HARDWARE  = 1,
    D3D_DRIVER_TYPE_REFERENCE = 2,
    D3D_DRIVER_TYPE_NULL      = 3,
    D3D_DRIVER_TYPE_SOFTWARE  = 4,
    D3D_DRIVER_TYPE_WARP      = 5
};

enum D3D11_USAGE : uint32_t {
    D3D11_USAGE_DEFAULT   = 0,
    D3D11_USAGE_IMMUTABLE = 1,
    D3D11_USAGE_DYNAMIC   = 2,
    D3D11_USAGE_STAGING   = 3
};

enum D3D11_BIND_FLAG : uint32_t {
    D3D11_BIND_VERTEX_BUFFER    = 0x1,
    D3D11_BIND_INDEX_BUFFER     = 0x2,
    D3D11_BIND_CONSTANT_BUFFER  = 0x4,
    D3D11_BIND_SHADER_RESOURCE  = 0x8,
    D3D11_BIND_STREAM_OUTPUT    = 0x10,
    D3D11_BIND_RENDER_TARGET    = 0x20,
    D3D11_BIND_DEPTH_STENCIL    = 0x40,
    D3D11_BIND_UNORDERED_ACCESS = 0x80
};

enum D3D11_CPU_ACCESS_FLAG : uint32_t {
    D3D11_CPU_ACCESS_WRITE = 0x10000,
    D3D11_CPU_ACCESS_READ  = 0x20000
};

enum D3D11_CLEAR_FLAG : uint32_t {
    D3D11_CLEAR_DEPTH   = 0x1,
    D3D11_CLEAR_STENCIL = 0x2
};

enum D3D_PRIMITIVE_TOPOLOGY : uint32_t {
    D3D_PRIMITIVE_TOPOLOGY_UNDEFINED     = 0,
    D3D_PRIMITIVE_TOPOLOGY_POINTLIST     = 1,
    D3D_PRIMITIVE_TOPOLOGY_LINELIST      = 2,
    D3D_PRIMITIVE_TOPOLOGY_LINESTRIP     = 3,
    D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST  = 4,
    D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP = 5
};

enum D3D11_FILL_MODE : uint32_t {
    D3D11_FILL_WIREFRAME = 2,
    D3D11_FILL_SOLID     = 3
};

enum D3D11_CULL_MODE : uint32_t {
    D3D11_CULL_NONE  = 1,
    D3D11_CULL_FRONT = 2,
    D3D11_CULL_BACK  = 3
};

enum D3D11_COMPARISON_FUNC : uint32_t {
    D3D11_COMPARISON_NEVER         = 1,
    D3D11_COMPARISON_LESS          = 2,
    D3D11_COMPARISON_EQUAL         = 3,
    D3D11_COMPARISON_LESS_EQUAL    = 4,
    D3D11_COMPARISON_GREATER       = 5,
    D3D11_COMPARISON_NOT_EQUAL     = 6,
    D3D11_COMPARISON_GREATER_EQUAL = 7,
    D3D11_COMPARISON_ALWAYS        = 8
};

enum D3D11_MAP : uint32_t {
    D3D11_MAP_READ               = 1,
    D3D11_MAP_WRITE              = 2,
    D3D11_MAP_READ_WRITE         = 3,
    D3D11_MAP_WRITE_DISCARD      = 4,
    D3D11_MAP_WRITE_NO_OVERWRITE = 5
};

struct D3D11_VIEWPORT {
    float TopLeftX;
    float TopLeftY;
    float Width;
    float Height;
    float MinDepth;
    float MaxDepth;
};

struct D3D11_BUFFER_DESC {
    uint32_t ByteWidth;
    D3D11_USAGE Usage;
    uint32_t BindFlags;
    uint32_t CPUAccessFlags;
    uint32_t MiscFlags;
    uint32_t StructureByteStride;
};

struct D3D11_SUBRESOURCE_DATA {
    const void* pSysMem;
    uint32_t SysMemPitch;
    uint32_t SysMemSlicePitch;
};

struct D3D11_INPUT_ELEMENT_DESC {
    const char* SemanticName;
    uint32_t SemanticIndex;
    DXGI_FORMAT Format;
    uint32_t InputSlot;
    uint32_t AlignedByteOffset;
    uint32_t InputSlotClass;
    uint32_t InstanceDataStepRate;
};

struct D3D11_RENDER_TARGET_VIEW_DESC {
    DXGI_FORMAT Format;
    uint32_t ViewDimension;
};

struct D3D11_DEPTH_STENCIL_VIEW_DESC {
    DXGI_FORMAT Format;
    uint32_t ViewDimension;
    uint32_t Flags;
};

struct D3D11_RASTERIZER_DESC {
    D3D11_FILL_MODE FillMode;
    D3D11_CULL_MODE CullMode;
    int32_t FrontCounterClockwise;
    int32_t DepthBias;
    float DepthBiasClamp;
    float SlopeScaledDepthBias;
    int32_t DepthClipEnable;
    int32_t ScissorEnable;
    int32_t MultisampleEnable;
    int32_t AntialiasedLineEnable;
};

struct D3D11_DEPTH_STENCIL_DESC {
    int32_t DepthEnable;
    uint32_t DepthWriteMask;
    D3D11_COMPARISON_FUNC DepthFunc;
    int32_t StencilEnable;
    uint8_t StencilReadMask;
    uint8_t StencilWriteMask;
};

struct D3D11_BLEND_DESC {
    int32_t AlphaToCoverageEnable;
    int32_t IndependentBlendEnable;
    struct {
        int32_t BlendEnable;
        uint32_t SrcBlend;
        uint32_t DestBlend;
        uint32_t BlendOp;
        uint32_t SrcBlendAlpha;
        uint32_t DestBlendAlpha;
        uint32_t BlendOpAlpha;
        uint8_t RenderTargetWriteMask;
    } RenderTarget[8];
};

struct D3D11_TEXTURE2D_DESC {
    uint32_t Width;
    uint32_t Height;
    uint32_t MipLevels;
    uint32_t ArraySize;
    DXGI_FORMAT Format;
    DXGI_SAMPLE_DESC SampleDesc;
    D3D11_USAGE Usage;
    uint32_t BindFlags;
    uint32_t CPUAccessFlags;
    uint32_t MiscFlags;
};

struct D3D11_SHADER_RESOURCE_VIEW_DESC {
    DXGI_FORMAT Format;
    uint32_t ViewDimension;
};

struct D3D11_SAMPLER_DESC {
    uint32_t Filter;
    uint32_t AddressU;
    uint32_t AddressV;
    uint32_t AddressW;
    float MipLODBias;
    uint32_t MaxAnisotropy;
    D3D11_COMPARISON_FUNC ComparisonFunc;
    float BorderColor[4];
    float MinLOD;
    float MaxLOD;
};

struct D3D11_MAPPED_SUBRESOURCE {
    void* pData;
    uint32_t RowPitch;
    uint32_t DepthPitch;
};

// ============================================================================
// 2. Direct3D COM GUIDs
// ============================================================================

static constexpr IID IID_ID3D11DeviceChild = 
    { 0x1841e7c7, 0x4f9b, 0x4afc, { 0xa1, 0x97, 0xe4, 0x60, 0x6e, 0x56, 0x58, 0x61 } };

static constexpr IID IID_ID3D11Resource = 
    { 0xdc8e63f3, 0xd12b, 0x4952, { 0xb4, 0x7b, 0x5e, 0x45, 0x02, 0x6a, 0x86, 0x2d } };

static constexpr IID IID_ID3D11Buffer = 
    { 0x48570b85, 0xd100, 0x4f76, { 0xbd, 0x40, 0xf0, 0x5c, 0xb4, 0xe3, 0xc0, 0x4b } };

static constexpr IID IID_ID3D11Texture2D = 
    { 0x6f15aaf2, 0xd208, 0x4e89, { 0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c } };

static constexpr IID IID_ID3D11View = 
    { 0x839d1236, 0xbb30, 0x4124, { 0xac, 0xb4, 0xa1, 0x49, 0xb6, 0x7e, 0x49, 0x6a } };

static constexpr IID IID_ID3D11RenderTargetView = 
    { 0xdfdba067, 0x0547, 0x44a2, { 0x9e, 0x16, 0x0d, 0x61, 0x99, 0x7e, 0x4f, 0xef } };

static constexpr IID IID_ID3D11DepthStencilView = 
    { 0x9fdac92a, 0x18e6, 0x48c3, { 0xaf, 0xad, 0x28, 0xb9, 0x4f, 0x32, 0x9b, 0xe6 } };

static constexpr IID IID_ID3D11ShaderResourceView = 
    { 0xb0e06bf0, 0x8170, 0x4e84, { 0x8a, 0x2f, 0x92, 0x39, 0x36, 0x5e, 0x34, 0x90 } };

static constexpr IID IID_ID3D11SamplerState = 
    { 0xda6570e1, 0x7e12, 0x46ce, { 0x91, 0x0b, 0xc2, 0xb6, 0x62, 0xa3, 0x1a, 0xb8 } };

static constexpr IID IID_ID3D11RasterizerState = 
    { 0x9bb4ab81, 0xab1c, 0x4d8f, { 0xbe, 0x50, 0x45, 0x27, 0xd4, 0x7e, 0xdc, 0x34 } };

static constexpr IID IID_ID3D11DepthStencilState = 
    { 0x0382349a, 0x4f37, 0x4e0a, { 0xac, 0x2a, 0xea, 0x35, 0x91, 0xb6, 0xb3, 0x26 } };

static constexpr IID IID_ID3D11BlendState = 
    { 0x75b12a66, 0xbb0f, 0x41cb, { 0x97, 0xdb, 0x66, 0x8c, 0xb5, 0xa0, 0xf6, 0x08 } };

static constexpr IID IID_ID3D11VertexShader = 
    { 0x3b301d64, 0xd678, 0x4289, { 0x88, 0x97, 0x22, 0xf8, 0x92, 0x8b, 0x72, 0xf3 } };

static constexpr IID IID_ID3D11PixelShader = 
    { 0xea82e40d, 0x51dc, 0x4333, { 0xac, 0x3d, 0x61, 0xac, 0x30, 0xb3, 0x0c, 0xb7 } };

static constexpr IID IID_ID3D11InputLayout = 
    { 0xe4819772, 0x4303, 0x4f76, { 0x81, 0xe2, 0x40, 0x26, 0x0c, 0xbe, 0x56, 0x41 } };

static constexpr IID IID_ID3D11DeviceContext = 
    { 0xc0bfa96c, 0xe089, 0x44fb, { 0x8e, 0xaf, 0x26, 0xf8, 0x79, 0x61, 0x90, 0xda } };

static constexpr IID IID_ID3D11Device = 
    { 0xdb6f6ddb, 0xac77, 0x4e88, { 0x82, 0x53, 0x81, 0x9d, 0xf9, 0xbb, 0xf1, 0x40 } };

// ============================================================================
// 3. 3D Mathematics & Matrix Engine (DirectXTK SimpleMath Parity)
// ============================================================================

struct Vector3 {
    float x{ 0.0f };
    float y{ 0.0f };
    float z{ 0.0f };

    constexpr bool operator==(const Vector3& o) const noexcept {
        return x == o.x && y == o.y && z == o.z;
    }
};

struct Vector4 {
    float x{ 0.0f };
    float y{ 0.0f };
    float z{ 0.0f };
    float w{ 1.0f };
};

struct Matrix4x4 {
    float m[4][4]{};

    static Matrix4x4 Identity() noexcept {
        Matrix4x4 mat{};
        mat.m[0][0] = 1.0f;
        mat.m[1][1] = 1.0f;
        mat.m[2][2] = 1.0f;
        mat.m[3][3] = 1.0f;
        return mat;
    }

    static Matrix4x4 Translation(float x, float y, float z) noexcept {
        Matrix4x4 mat = Identity();
        mat.m[3][0] = x;
        mat.m[3][1] = y;
        mat.m[3][2] = z;
        return mat;
    }

    static Matrix4x4 RotationX(float rad) noexcept {
        Matrix4x4 mat = Identity();
        float c = std::cos(rad);
        float s = std::sin(rad);
        mat.m[1][1] = c;
        mat.m[1][2] = s;
        mat.m[2][1] = -s;
        mat.m[2][2] = c;
        return mat;
    }

    static Matrix4x4 RotationY(float rad) noexcept {
        Matrix4x4 mat = Identity();
        float c = std::cos(rad);
        float s = std::sin(rad);
        mat.m[0][0] = c;
        mat.m[0][2] = -s;
        mat.m[2][0] = s;
        mat.m[2][2] = c;
        return mat;
    }

    static Matrix4x4 RotationZ(float rad) noexcept {
        Matrix4x4 mat = Identity();
        float c = std::cos(rad);
        float s = std::sin(rad);
        mat.m[0][0] = c;
        mat.m[0][1] = s;
        mat.m[1][0] = -s;
        mat.m[1][1] = c;
        return mat;
    }

    static Matrix4x4 Multiply(const Matrix4x4& a, const Matrix4x4& b) noexcept {
        Matrix4x4 out{};
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                out.m[r][c] = a.m[r][0] * b.m[0][c] +
                              a.m[r][1] * b.m[1][c] +
                              a.m[r][2] * b.m[2][c] +
                              a.m[r][3] * b.m[3][c];
            }
        }
        return out;
    }

    static Matrix4x4 PerspectiveFovLH(float fovY, float aspect, float nearZ, float farZ) noexcept {
        Matrix4x4 mat{};
        float sinFov = std::sin(0.5f * fovY);
        float cosFov = std::cos(0.5f * fovY);
        float height = cosFov / sinFov;
        float width = height / aspect;
        float fRange = farZ / (farZ - nearZ);

        mat.m[0][0] = width;
        mat.m[1][1] = height;
        mat.m[2][2] = fRange;
        mat.m[2][3] = 1.0f;
        mat.m[3][2] = -fRange * nearZ;
        return mat;
    }

    static Matrix4x4 LookAtLH(const Vector3& eye, const Vector3& target, const Vector3& up) noexcept {
        Vector3 zAxis{ target.x - eye.x, target.y - eye.y, target.z - eye.z };
        float zLen = std::sqrt(zAxis.x * zAxis.x + zAxis.y * zAxis.y + zAxis.z * zAxis.z);
        if (zLen > 1e-6f) { zAxis.x /= zLen; zAxis.y /= zLen; zAxis.z /= zLen; }

        Vector3 xAxis{ up.y * zAxis.z - up.z * zAxis.y,
                       up.z * zAxis.x - up.x * zAxis.z,
                       up.x * zAxis.y - up.y * zAxis.x };
        float xLen = std::sqrt(xAxis.x * xAxis.x + xAxis.y * xAxis.y + xAxis.z * xAxis.z);
        if (xLen > 1e-6f) { xAxis.x /= xLen; xAxis.y /= xLen; xAxis.z /= xLen; }

        Vector3 yAxis{ zAxis.y * xAxis.z - zAxis.z * xAxis.y,
                       zAxis.z * xAxis.x - zAxis.x * xAxis.z,
                       zAxis.x * xAxis.y - zAxis.y * xAxis.x };

        Matrix4x4 mat = Identity();
        mat.m[0][0] = xAxis.x; mat.m[0][1] = yAxis.x; mat.m[0][2] = zAxis.x;
        mat.m[1][0] = xAxis.y; mat.m[1][1] = yAxis.y; mat.m[1][2] = zAxis.y;
        mat.m[2][0] = xAxis.z; mat.m[2][1] = yAxis.z; mat.m[2][2] = zAxis.z;
        mat.m[3][0] = -(xAxis.x * eye.x + xAxis.y * eye.y + xAxis.z * eye.z);
        mat.m[3][1] = -(yAxis.x * eye.x + yAxis.y * eye.y + yAxis.z * eye.z);
        mat.m[3][2] = -(zAxis.x * eye.x + zAxis.y * eye.y + zAxis.z * eye.z);
        return mat;
    }

    Vector4 Transform(const Vector4& v) const noexcept {
        return Vector4{
            v.x * m[0][0] + v.y * m[1][0] + v.z * m[2][0] + v.w * m[3][0],
            v.x * m[0][1] + v.y * m[1][1] + v.z * m[2][1] + v.w * m[3][1],
            v.x * m[0][2] + v.y * m[1][2] + v.z * m[2][2] + v.w * m[3][2],
            v.x * m[0][3] + v.y * m[1][3] + v.z * m[2][3] + v.w * m[3][3]
        };
    }
};

// ============================================================================
// 4. Vertex Formats
// ============================================================================

struct VertexPositionColor {
    float x, y, z;
    float r, g, b, a;
};

struct VertexPositionTexture {
    float x, y, z;
    float u, v;
};

struct VertexPositionColorTexture {
    float x, y, z;
    float r, g, b, a;
    float u, v;
};

// ============================================================================
// 5. Interface Declarations
// ============================================================================

class ID3D11Device;
class ID3D11DeviceContext;

class ID3D11DeviceChild : public IUnknown {
public:
    virtual void GetDevice(ID3D11Device** ppDevice) = 0;
};

class ID3D11Resource : public ID3D11DeviceChild {
public:
    virtual void GetType(uint32_t* pResourceDimension) = 0;
};

class ID3D11Buffer : public ID3D11Resource {
public:
    virtual void GetDesc(D3D11_BUFFER_DESC* pDesc) = 0;
};

class ID3D11Texture2D : public ID3D11Resource {
public:
    virtual void GetDesc(D3D11_TEXTURE2D_DESC* pDesc) = 0;
};

class ID3D11View : public ID3D11DeviceChild {
public:
    virtual void GetResource(ID3D11Resource** ppResource) = 0;
};

class ID3D11RenderTargetView : public ID3D11View {
public:
    virtual void GetDesc(D3D11_RENDER_TARGET_VIEW_DESC* pDesc) = 0;
};

class ID3D11DepthStencilView : public ID3D11View {
public:
    virtual void GetDesc(D3D11_DEPTH_STENCIL_VIEW_DESC* pDesc) = 0;
};

class ID3D11ShaderResourceView : public ID3D11View {
public:
    virtual void GetDesc(D3D11_SHADER_RESOURCE_VIEW_DESC* pDesc) = 0;
};

class ID3D11SamplerState : public ID3D11DeviceChild {
public:
    virtual void GetDesc(D3D11_SAMPLER_DESC* pDesc) = 0;
};

class ID3D11RasterizerState : public ID3D11DeviceChild {
public:
    virtual void GetDesc(D3D11_RASTERIZER_DESC* pDesc) = 0;
};

class ID3D11DepthStencilState : public ID3D11DeviceChild {
public:
    virtual void GetDesc(D3D11_DEPTH_STENCIL_DESC* pDesc) = 0;
};

class ID3D11BlendState : public ID3D11DeviceChild {
public:
    virtual void GetDesc(D3D11_BLEND_DESC* pDesc) = 0;
};

class ID3D11VertexShader : public ID3D11DeviceChild {};
class ID3D11PixelShader : public ID3D11DeviceChild {};
class ID3D11InputLayout : public ID3D11DeviceChild {};

class ID3D11DeviceContext : public ID3D11DeviceChild {
public:
    virtual void VSSetConstantBuffers(uint32_t StartSlot, uint32_t NumBuffers, ID3D11Buffer* const* ppConstantBuffers) = 0;
    virtual void PSSetConstantBuffers(uint32_t StartSlot, uint32_t NumBuffers, ID3D11Buffer* const* ppConstantBuffers) = 0;
    virtual void PSSetShader(ID3D11PixelShader* pPixelShader) = 0;
    virtual void VSSetShader(ID3D11VertexShader* pVertexShader) = 0;
    virtual void IASetInputLayout(ID3D11InputLayout* pInputLayout) = 0;
    virtual void IASetVertexBuffers(uint32_t StartSlot, uint32_t NumBuffers, ID3D11Buffer* const* ppVertexBuffers, const uint32_t* pStrides, const uint32_t* pOffsets) = 0;
    virtual void IASetIndexBuffer(ID3D11Buffer* pIndexBuffer, DXGI_FORMAT Format, uint32_t Offset) = 0;
    virtual void IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY Topology) = 0;
    virtual void RSSetViewports(uint32_t NumViewports, const D3D11_VIEWPORT* pViewports) = 0;
    virtual void RSSetState(ID3D11RasterizerState* pRasterizerState) = 0;
    virtual void OMSetRenderTargets(uint32_t NumViews, ID3D11RenderTargetView* const* ppRenderTargetViews, ID3D11DepthStencilView* pDepthStencilView) = 0;
    virtual void OMSetDepthStencilState(ID3D11DepthStencilState* pDepthStencilState, uint32_t StencilRef) = 0;
    virtual void OMSetBlendState(ID3D11BlendState* pBlendState, const float BlendFactor[4], uint32_t SampleMask) = 0;
    virtual void PSSetShaderResources(uint32_t StartSlot, uint32_t NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews) = 0;
    virtual void PSSetSamplers(uint32_t StartSlot, uint32_t NumSamplers, ID3D11SamplerState* const* ppSamplers) = 0;
    virtual void ClearRenderTargetView(ID3D11RenderTargetView* pRenderTargetView, const float ColorRGBA[4]) = 0;
    virtual void ClearDepthStencilView(ID3D11DepthStencilView* pDepthStencilView, uint32_t ClearFlags, float Depth, uint8_t Stencil) = 0;
    virtual void UpdateSubresource(ID3D11Resource* pDstResource, uint32_t DstSubresource, const void* pSrcData, uint32_t SrcRowPitch, uint32_t SrcDepthPitch) = 0;
    virtual int32_t Map(ID3D11Resource* pResource, uint32_t Subresource, D3D11_MAP MapType, uint32_t MapFlags, D3D11_MAPPED_SUBRESOURCE* pMappedResource) = 0;
    virtual void Unmap(ID3D11Resource* pResource, uint32_t Subresource) = 0;
    virtual void Draw(uint32_t VertexCount, uint32_t StartVertexLocation) = 0;
    virtual void DrawIndexed(uint32_t IndexCount, uint32_t StartIndexLocation, int32_t BaseVertexLocation) = 0;
};

class ID3D11Device : public IUnknown {
public:
    virtual int32_t CreateBuffer(const D3D11_BUFFER_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Buffer** ppBuffer) = 0;
    virtual int32_t CreateTexture2D(const D3D11_TEXTURE2D_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Texture2D** ppTexture2D) = 0;
    virtual int32_t CreateRenderTargetView(ID3D11Resource* pResource, const D3D11_RENDER_TARGET_VIEW_DESC* pDesc, ID3D11RenderTargetView** ppRTView) = 0;
    virtual int32_t CreateDepthStencilView(ID3D11Resource* pResource, const D3D11_DEPTH_STENCIL_VIEW_DESC* pDesc, ID3D11DepthStencilView** ppDepthStencilView) = 0;
    virtual int32_t CreateShaderResourceView(ID3D11Resource* pResource, const D3D11_SHADER_RESOURCE_VIEW_DESC* pDesc, ID3D11ShaderResourceView** ppSRView) = 0;
    virtual int32_t CreateSamplerState(const D3D11_SAMPLER_DESC* pSamplerDesc, ID3D11SamplerState** ppSamplerState) = 0;
    virtual int32_t CreateRasterizerState(const D3D11_RASTERIZER_DESC* pRasterizerDesc, ID3D11RasterizerState** ppRasterizerState) = 0;
    virtual int32_t CreateDepthStencilState(const D3D11_DEPTH_STENCIL_DESC* pDepthStencilDesc, ID3D11DepthStencilState** ppDepthStencilState) = 0;
    virtual int32_t CreateBlendState(const D3D11_BLEND_DESC* pBlendStateDesc, ID3D11BlendState** ppBlendState) = 0;
    virtual int32_t CreateInputLayout(const D3D11_INPUT_ELEMENT_DESC* pInputElementDescs, uint32_t NumElements, const void* pShaderBytecode, size_t BytecodeLength, ID3D11InputLayout** ppInputLayout) = 0;
    virtual int32_t CreateVertexShader(const void* pShaderBytecode, size_t BytecodeLength, ID3D11VertexShader** ppVertexShader) = 0;
    virtual int32_t CreatePixelShader(const void* pShaderBytecode, size_t BytecodeLength, ID3D11PixelShader** ppPixelShader) = 0;
    virtual void GetImmediateContext(ID3D11DeviceContext** ppImmediateContext) = 0;
    virtual D3D_FEATURE_LEVEL GetFeatureLevel() = 0;
};

// ============================================================================
// 6. Concrete Implementations
// ============================================================================

class Prism3DBufferImpl : public ID3D11Buffer {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    D3D11_BUFFER_DESC m_desc{};
    std::vector<uint8_t> m_data;

public:
    Prism3DBufferImpl(ID3D11Device* pDevice, const D3D11_BUFFER_DESC& desc, const void* initialData)
        : m_pDevice(pDevice), m_desc(desc) {
        m_data.resize(desc.ByteWidth, 0);
        if (initialData) {
            std::memcpy(m_data.data(), initialData, desc.ByteWidth);
        }
    }

    const uint8_t* GetData() const { return m_data.data(); }
    uint8_t* GetData() { return m_data.data(); }
    size_t GetSize() const { return m_data.size(); }

    void UpdateData(const void* pSrc, size_t size) {
        if (!pSrc) return;
        size_t copyBytes = std::min(size, m_data.size());
        std::memcpy(m_data.data(), pSrc, copyBytes);
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11Resource || riid == IID_ID3D11Buffer) {
            *ppvObject = static_cast<ID3D11Buffer*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    void GetType(uint32_t* pResourceDimension) override {
        if (pResourceDimension) *pResourceDimension = 2; // D3D11_RESOURCE_DIMENSION_BUFFER
    }

    void GetDesc(D3D11_BUFFER_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

class Prism3DTexture2DImpl : public ID3D11Texture2D {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    D3D11_TEXTURE2D_DESC m_desc{};
    std::vector<uint32_t> m_pixels;

public:
    Prism3DTexture2DImpl(ID3D11Device* pDev, const D3D11_TEXTURE2D_DESC& desc, const void* initData)
        : m_pDevice(pDev), m_desc(desc) {
        size_t pixelCount = static_cast<size_t>(desc.Width) * desc.Height;
        m_pixels.resize(pixelCount, 0xFFFFFFFF);
        if (initData) {
            std::memcpy(m_pixels.data(), initData, pixelCount * sizeof(uint32_t));
        }
    }

    const uint32_t* GetPixels() const { return m_pixels.data(); }
    uint32_t* GetPixels() { return m_pixels.data(); }
    uint32_t GetWidth() const { return m_desc.Width; }
    uint32_t GetHeight() const { return m_desc.Height; }

    uint32_t Sample(float u, float v) const {
        if (m_pixels.empty()) return 0xFFFFFFFF;
        u = u - std::floor(u); // Wrap
        v = v - std::floor(v);
        int x = std::clamp(static_cast<int>(u * m_desc.Width), 0, static_cast<int>(m_desc.Width) - 1);
        int y = std::clamp(static_cast<int>(v * m_desc.Height), 0, static_cast<int>(m_desc.Height) - 1);
        return m_pixels[static_cast<size_t>(y) * m_desc.Width + x];
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11Resource || riid == IID_ID3D11Texture2D) {
            *ppvObject = static_cast<ID3D11Texture2D*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    void GetType(uint32_t* pResourceDimension) override {
        if (pResourceDimension) *pResourceDimension = 4; // D3D11_RESOURCE_DIMENSION_TEXTURE2D
    }

    void GetDesc(D3D11_TEXTURE2D_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

class Prism3DShaderResourceViewImpl : public ID3D11ShaderResourceView {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    ID3D11Resource* m_pResource{ nullptr };
    Prism3DTexture2DImpl* m_pTexture{ nullptr };
    D3D11_SHADER_RESOURCE_VIEW_DESC m_desc{};

public:
    Prism3DShaderResourceViewImpl(ID3D11Device* pDev, ID3D11Resource* pRes, const D3D11_SHADER_RESOURCE_VIEW_DESC* pDesc)
        : m_pDevice(pDev), m_pResource(pRes) {
        if (pDesc) m_desc = *pDesc;
        if (pRes) {
            pRes->QueryInterface(IID_ID3D11Texture2D, reinterpret_cast<void**>(&m_pTexture));
            if (m_pTexture) m_pTexture->Release();
        }
    }

    Prism3DTexture2DImpl* GetTexture() const { return m_pTexture; }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11View || riid == IID_ID3D11ShaderResourceView) {
            *ppvObject = static_cast<ID3D11ShaderResourceView*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    void GetResource(ID3D11Resource** ppResource) override {
        if (ppResource) {
            *ppResource = m_pResource;
            if (m_pResource) m_pResource->AddRef();
        }
    }

    void GetDesc(D3D11_SHADER_RESOURCE_VIEW_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

class Prism3DRasterizerStateImpl : public ID3D11RasterizerState {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    D3D11_RASTERIZER_DESC m_desc{};

public:
    Prism3DRasterizerStateImpl(ID3D11Device* pDev, const D3D11_RASTERIZER_DESC& desc)
        : m_pDevice(pDev), m_desc(desc) {}

    const D3D11_RASTERIZER_DESC& GetInternalDesc() const { return m_desc; }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11RasterizerState) {
            *ppvObject = static_cast<ID3D11RasterizerState*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    void GetDesc(D3D11_RASTERIZER_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

class Prism3DDepthStencilStateImpl : public ID3D11DepthStencilState {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    D3D11_DEPTH_STENCIL_DESC m_desc{};

public:
    Prism3DDepthStencilStateImpl(ID3D11Device* pDev, const D3D11_DEPTH_STENCIL_DESC& desc)
        : m_pDevice(pDev), m_desc(desc) {}

    const D3D11_DEPTH_STENCIL_DESC& GetInternalDesc() const { return m_desc; }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11DepthStencilState) {
            *ppvObject = static_cast<ID3D11DepthStencilState*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    void GetDesc(D3D11_DEPTH_STENCIL_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

class Prism3DBlendStateImpl : public ID3D11BlendState {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    D3D11_BLEND_DESC m_desc{};

public:
    Prism3DBlendStateImpl(ID3D11Device* pDev, const D3D11_BLEND_DESC& desc)
        : m_pDevice(pDev), m_desc(desc) {}

    const D3D11_BLEND_DESC& GetInternalDesc() const { return m_desc; }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11BlendState) {
            *ppvObject = static_cast<ID3D11BlendState*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    void GetDesc(D3D11_BLEND_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

class Prism3DSamplerStateImpl : public ID3D11SamplerState {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    D3D11_SAMPLER_DESC m_desc{};

public:
    Prism3DSamplerStateImpl(ID3D11Device* pDev, const D3D11_SAMPLER_DESC& desc)
        : m_pDevice(pDev), m_desc(desc) {}

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11SamplerState) {
            *ppvObject = static_cast<ID3D11SamplerState*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    void GetDesc(D3D11_SAMPLER_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

class Prism3DRenderTargetViewImpl : public ID3D11RenderTargetView {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    ID3D11Resource* m_pResource{ nullptr };
    PrismXSurfaceImpl* m_pSurface{ nullptr };
    D3D11_RENDER_TARGET_VIEW_DESC m_desc{};

public:
    Prism3DRenderTargetViewImpl(ID3D11Device* pDev, ID3D11Resource* pRes, PrismXSurfaceImpl* pSurface, const D3D11_RENDER_TARGET_VIEW_DESC* pDesc)
        : m_pDevice(pDev), m_pResource(pRes), m_pSurface(pSurface) {
        if (pDesc) m_desc = *pDesc;
        else {
            m_desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
            m_desc.ViewDimension = 4;
        }
    }

    PrismXSurfaceImpl* GetSurface() { return m_pSurface; }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11View || riid == IID_ID3D11RenderTargetView) {
            *ppvObject = static_cast<ID3D11RenderTargetView*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    void GetResource(ID3D11Resource** ppResource) override {
        if (ppResource) {
            *ppResource = m_pResource;
            if (m_pResource) m_pResource->AddRef();
        }
    }

    void GetDesc(D3D11_RENDER_TARGET_VIEW_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

class Prism3DDepthStencilViewImpl : public ID3D11DepthStencilView {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    uint32_t m_width{ 0 };
    uint32_t m_height{ 0 };
    std::vector<float> m_depthBuffer;

public:
    Prism3DDepthStencilViewImpl(ID3D11Device* pDev, uint32_t width, uint32_t height)
        : m_pDevice(pDev), m_width(width), m_height(height) {
        m_depthBuffer.resize(static_cast<size_t>(width) * height, 1.0f);
    }

    float* GetDepthData() { return m_depthBuffer.data(); }
    uint32_t GetWidth() const { return m_width; }
    uint32_t GetHeight() const { return m_height; }

    void Clear(float depth) {
        std::fill(m_depthBuffer.begin(), m_depthBuffer.end(), depth);
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11View || riid == IID_ID3D11DepthStencilView) {
            *ppvObject = static_cast<ID3D11DepthStencilView*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    void GetResource(ID3D11Resource** ppResource) override {
        if (ppResource) *ppResource = nullptr;
    }

    void GetDesc(D3D11_DEPTH_STENCIL_VIEW_DESC* pDesc) override {
        if (pDesc) {
            pDesc->Format = DXGI_FORMAT_D32_FLOAT;
            pDesc->ViewDimension = 3;
            pDesc->Flags = 0;
        }
    }
};

class Prism3DVertexShaderImpl : public ID3D11VertexShader {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    std::vector<uint8_t> m_bytecode;

public:
    Prism3DVertexShaderImpl(ID3D11Device* pDev, const void* pBytecode, size_t length)
        : m_pDevice(pDev) {
        if (pBytecode && length > 0) {
            m_bytecode.assign(reinterpret_cast<const uint8_t*>(pBytecode), reinterpret_cast<const uint8_t*>(pBytecode) + length);
        }
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11VertexShader) {
            *ppvObject = static_cast<ID3D11VertexShader*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }
};

class Prism3DPixelShaderImpl : public ID3D11PixelShader {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    std::vector<uint8_t> m_bytecode;

public:
    Prism3DPixelShaderImpl(ID3D11Device* pDev, const void* pBytecode, size_t length)
        : m_pDevice(pDev) {
        if (pBytecode && length > 0) {
            m_bytecode.assign(reinterpret_cast<const uint8_t*>(pBytecode), reinterpret_cast<const uint8_t*>(pBytecode) + length);
        }
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11PixelShader) {
            *ppvObject = static_cast<ID3D11PixelShader*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }
};

class Prism3DInputLayoutImpl : public ID3D11InputLayout {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    std::vector<D3D11_INPUT_ELEMENT_DESC> m_elements;

public:
    Prism3DInputLayoutImpl(ID3D11Device* pDev, const D3D11_INPUT_ELEMENT_DESC* pElements, uint32_t count)
        : m_pDevice(pDev) {
        if (pElements && count > 0) {
            m_elements.assign(pElements, pElements + count);
        }
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11InputLayout) {
            *ppvObject = static_cast<ID3D11InputLayout*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }
};

// ============================================================================
// 7. Prism3D Device Context & Complete Software Reference Rasterizer
// ============================================================================

class Prism3DDeviceContextImpl : public ID3D11DeviceContext {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };

    // Pipeline State
    D3D11_VIEWPORT m_viewport{};
    Prism3DRenderTargetViewImpl* m_currentRTV{ nullptr };
    Prism3DDepthStencilViewImpl* m_currentDSV{ nullptr };
    Prism3DBufferImpl* m_currentVB{ nullptr };
    uint32_t m_currentVBStride{ 0 };
    uint32_t m_currentVBOffset{ 0 };
    Prism3DBufferImpl* m_currentIB{ nullptr };
    DXGI_FORMAT m_currentIBFormat{ DXGI_FORMAT_R16_UINT };
    uint32_t m_currentIBOffset{ 0 };
    D3D_PRIMITIVE_TOPOLOGY m_topology{ D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST };

    ID3D11Buffer* m_vsConstantBuffers[14]{};
    ID3D11Buffer* m_psConstantBuffers[14]{};
    ID3D11ShaderResourceView* m_psShaderResources[8]{};
    ID3D11SamplerState* m_psSamplers[8]{};

    Prism3DRasterizerStateImpl* m_currentRasterizerState{ nullptr };
    Prism3DDepthStencilStateImpl* m_currentDepthStencilState{ nullptr };
    Prism3DBlendStateImpl* m_currentBlendState{ nullptr };

    ID3D11VertexShader* m_currentVS{ nullptr };
    ID3D11PixelShader* m_currentPS{ nullptr };
    ID3D11InputLayout* m_currentLayout{ nullptr };

public:
    Prism3DDeviceContextImpl(ID3D11Device* pDev) : m_pDevice(pDev) {
        m_viewport = { 0.0f, 0.0f, 1920.0f, 1080.0f, 0.0f, 1.0f };
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11DeviceContext) {
            *ppvObject = static_cast<ID3D11DeviceContext*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    void VSSetConstantBuffers(uint32_t StartSlot, uint32_t NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override {
        for (uint32_t i = 0; i < NumBuffers && (StartSlot + i) < 14; ++i) {
            m_vsConstantBuffers[StartSlot + i] = ppConstantBuffers ? ppConstantBuffers[i] : nullptr;
        }
    }

    void PSSetConstantBuffers(uint32_t StartSlot, uint32_t NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override {
        for (uint32_t i = 0; i < NumBuffers && (StartSlot + i) < 14; ++i) {
            m_psConstantBuffers[StartSlot + i] = ppConstantBuffers ? ppConstantBuffers[i] : nullptr;
        }
    }

    void PSSetShader(ID3D11PixelShader* pPixelShader) override { m_currentPS = pPixelShader; }
    void VSSetShader(ID3D11VertexShader* pVertexShader) override { m_currentVS = pVertexShader; }
    void IASetInputLayout(ID3D11InputLayout* pInputLayout) override { m_currentLayout = pInputLayout; }

    void IASetVertexBuffers(uint32_t StartSlot, uint32_t NumBuffers, ID3D11Buffer* const* ppVertexBuffers, const uint32_t* pStrides, const uint32_t* pOffsets) override {
        if (StartSlot == 0 && NumBuffers > 0 && ppVertexBuffers) {
            m_currentVB = static_cast<Prism3DBufferImpl*>(ppVertexBuffers[0]);
            m_currentVBStride = pStrides ? pStrides[0] : sizeof(VertexPositionColor);
            m_currentVBOffset = pOffsets ? pOffsets[0] : 0;
        }
    }

    void IASetIndexBuffer(ID3D11Buffer* pIndexBuffer, DXGI_FORMAT Format, uint32_t Offset) override {
        m_currentIB = static_cast<Prism3DBufferImpl*>(pIndexBuffer);
        m_currentIBFormat = Format;
        m_currentIBOffset = Offset;
    }

    void IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY Topology) override {
        m_topology = Topology;
    }

    void RSSetViewports(uint32_t NumViewports, const D3D11_VIEWPORT* pViewports) override {
        if (NumViewports > 0 && pViewports) {
            m_viewport = pViewports[0];
        }
    }

    void RSSetState(ID3D11RasterizerState* pRasterizerState) override {
        m_currentRasterizerState = static_cast<Prism3DRasterizerStateImpl*>(pRasterizerState);
    }

    void OMSetRenderTargets(uint32_t NumViews, ID3D11RenderTargetView* const* ppRenderTargetViews, ID3D11DepthStencilView* pDepthStencilView) override {
        if (NumViews > 0 && ppRenderTargetViews) {
            m_currentRTV = static_cast<Prism3DRenderTargetViewImpl*>(ppRenderTargetViews[0]);
        } else {
            m_currentRTV = nullptr;
        }
        m_currentDSV = static_cast<Prism3DDepthStencilViewImpl*>(pDepthStencilView);
    }

    void OMSetDepthStencilState(ID3D11DepthStencilState* pDepthStencilState, uint32_t) override {
        m_currentDepthStencilState = static_cast<Prism3DDepthStencilStateImpl*>(pDepthStencilState);
    }

    void OMSetBlendState(ID3D11BlendState* pBlendState, const float[4], uint32_t) override {
        m_currentBlendState = static_cast<Prism3DBlendStateImpl*>(pBlendState);
    }

    void PSSetShaderResources(uint32_t StartSlot, uint32_t NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews) override {
        for (uint32_t i = 0; i < NumViews && (StartSlot + i) < 8; ++i) {
            m_psShaderResources[StartSlot + i] = ppShaderResourceViews ? ppShaderResourceViews[i] : nullptr;
        }
    }

    void PSSetSamplers(uint32_t StartSlot, uint32_t NumSamplers, ID3D11SamplerState* const* ppSamplers) override {
        for (uint32_t i = 0; i < NumSamplers && (StartSlot + i) < 8; ++i) {
            m_psSamplers[StartSlot + i] = ppSamplers ? ppSamplers[i] : nullptr;
        }
    }

    void ClearRenderTargetView(ID3D11RenderTargetView* pRenderTargetView, const float ColorRGBA[4]) override {
        auto* rtv = static_cast<Prism3DRenderTargetViewImpl*>(pRenderTargetView);
        if (!rtv || !rtv->GetSurface()) return;

        auto* surface = rtv->GetSurface();
        uint8_t* pixels = surface->GetRawData();
        size_t size = surface->GetDataSize();

        // 32-bpp BGRA byte packing
        uint8_t b = static_cast<uint8_t>(std::clamp(ColorRGBA[2] * 255.0f, 0.0f, 255.0f));
        uint8_t g = static_cast<uint8_t>(std::clamp(ColorRGBA[1] * 255.0f, 0.0f, 255.0f));
        uint8_t r = static_cast<uint8_t>(std::clamp(ColorRGBA[0] * 255.0f, 0.0f, 255.0f));
        uint8_t a = static_cast<uint8_t>(std::clamp(ColorRGBA[3] * 255.0f, 0.0f, 255.0f));
        uint32_t pixel32 = (a << 24) | (r << 16) | (g << 8) | b;

        uint32_t* p32 = reinterpret_cast<uint32_t*>(pixels);
        size_t count = size / 4;
        for (size_t i = 0; i < count; ++i) {
            p32[i] = pixel32;
        }
    }

    void ClearDepthStencilView(ID3D11DepthStencilView* pDepthStencilView, uint32_t ClearFlags, float Depth, uint8_t) override {
        auto* dsv = static_cast<Prism3DDepthStencilViewImpl*>(pDepthStencilView);
        if (dsv && (ClearFlags & D3D11_CLEAR_DEPTH)) {
            dsv->Clear(Depth);
        }
    }

    void UpdateSubresource(ID3D11Resource* pDstResource, uint32_t, const void* pSrcData, uint32_t, uint32_t) override {
        if (!pDstResource || !pSrcData) return;
        ID3D11Buffer* pBuffer = nullptr;
        if (pDstResource->QueryInterface(IID_ID3D11Buffer, reinterpret_cast<void**>(&pBuffer)) == 0 && pBuffer) {
            auto* b = static_cast<Prism3DBufferImpl*>(pBuffer);
            b->UpdateData(pSrcData, b->GetSize());
            pBuffer->Release();
        }
    }

    int32_t Map(ID3D11Resource* pResource, uint32_t, D3D11_MAP, uint32_t, D3D11_MAPPED_SUBRESOURCE* pMappedResource) override {
        if (!pResource || !pMappedResource) return -1;
        ID3D11Buffer* pBuffer = nullptr;
        if (pResource->QueryInterface(IID_ID3D11Buffer, reinterpret_cast<void**>(&pBuffer)) == 0 && pBuffer) {
            auto* b = static_cast<Prism3DBufferImpl*>(pBuffer);
            pMappedResource->pData = b->GetData();
            pMappedResource->RowPitch = static_cast<uint32_t>(b->GetSize());
            pMappedResource->DepthPitch = static_cast<uint32_t>(b->GetSize());
            pBuffer->Release();
            return 0;
        }
        return -1;
    }

    void Unmap(ID3D11Resource*, uint32_t) override {}

private:
    void DrawLine(int x0, int y0, float z0, int x1, int y1, float z1, uint32_t color, uint32_t* target, float* depth, uint32_t width, uint32_t height) {
        int dx = std::abs(x1 - x0);
        int dy = std::abs(y1 - y0);
        int sx = (x0 < x1) ? 1 : -1;
        int sy = (y0 < y1) ? 1 : -1;
        int err = dx - dy;

        int steps = std::max(dx, dy);
        int stepCount = 0;

        while (true) {
            if (x0 >= 0 && x0 < static_cast<int>(width) && y0 >= 0 && y0 < static_cast<int>(height)) {
                size_t idx = static_cast<size_t>(y0) * width + x0;
                float t = (steps > 0) ? static_cast<float>(stepCount) / static_cast<float>(steps) : 0.0f;
                float z = z0 * (1.0f - t) + z1 * t;
                if (!depth || z <= depth[idx]) {
                    if (depth) depth[idx] = z;
                    target[idx] = color;
                }
            }

            if (x0 == x1 && y0 == y1) break;
            int e2 = 2 * err;
            if (e2 > -dy) {
                err -= dy;
                x0 += sx;
            }
            if (e2 < dx) {
                err += dx;
                y0 += sy;
            }
            stepCount++;
        }
    }

    void RasterizeTriangle(uint32_t i0, uint32_t i1, uint32_t i2) {
        if (!m_currentRTV || !m_currentRTV->GetSurface() || !m_currentVB) return;

        auto* surface = m_currentRTV->GetSurface();
        uint32_t* targetPixels = reinterpret_cast<uint32_t*>(surface->GetRawData());
        uint32_t width = surface->GetWidth();
        uint32_t height = surface->GetHeight();
        float* depthBuffer = m_currentDSV ? m_currentDSV->GetDepthData() : nullptr;

        const uint8_t* vbRaw = m_currentVB->GetData() + m_currentVBOffset;
        uint32_t stride = m_currentVBStride;

        const auto* raw0 = vbRaw + i0 * stride;
        const auto* raw1 = vbRaw + i1 * stride;
        const auto* raw2 = vbRaw + i2 * stride;

        const auto* v0 = reinterpret_cast<const VertexPositionColor*>(raw0);
        const auto* v1 = reinterpret_cast<const VertexPositionColor*>(raw1);
        const auto* v2 = reinterpret_cast<const VertexPositionColor*>(raw2);

        // Check for UV coordinates if stride >= sizeof(VertexPositionColorTexture)
        bool hasUV = (stride >= sizeof(VertexPositionColorTexture));
        float u0 = 0.0f, vCoord0 = 0.0f;
        float u1 = 0.0f, vCoord1 = 0.0f;
        float u2 = 0.0f, vCoord2 = 0.0f;
        if (hasUV) {
            const auto* vct0 = reinterpret_cast<const VertexPositionColorTexture*>(raw0);
            const auto* vct1 = reinterpret_cast<const VertexPositionColorTexture*>(raw1);
            const auto* vct2 = reinterpret_cast<const VertexPositionColorTexture*>(raw2);
            u0 = vct0->u; vCoord0 = vct0->v;
            u1 = vct1->u; vCoord1 = vct1->v;
            u2 = vct2->u; vCoord2 = vct2->v;
        }

        Vector4 pos0{ v0->x, v0->y, v0->z, 1.0f };
        Vector4 pos1{ v1->x, v1->y, v1->z, 1.0f };
        Vector4 pos2{ v2->x, v2->y, v2->z, 1.0f };

        // Vertex Transformation via Constant Buffer (Slot 0, MVP Matrix)
        if (m_vsConstantBuffers[0]) {
            auto* cb = static_cast<Prism3DBufferImpl*>(m_vsConstantBuffers[0]);
            if (cb->GetSize() >= sizeof(Matrix4x4)) {
                const auto* mat = reinterpret_cast<const Matrix4x4*>(cb->GetData());
                pos0 = mat->Transform(pos0);
                pos1 = mat->Transform(pos1);
                pos2 = mat->Transform(pos2);
            }
        }

        // Perspective Divide
        float invW0 = (std::abs(pos0.w) > 1e-6f) ? (1.0f / pos0.w) : 1.0f;
        float invW1 = (std::abs(pos1.w) > 1e-6f) ? (1.0f / pos1.w) : 1.0f;
        float invW2 = (std::abs(pos2.w) > 1e-6f) ? (1.0f / pos2.w) : 1.0f;

        float ndcX0 = pos0.x * invW0, ndcY0 = pos0.y * invW0, ndcZ0 = pos0.z * invW0;
        float ndcX1 = pos1.x * invW1, ndcY1 = pos1.y * invW1, ndcZ1 = pos1.z * invW1;
        float ndcX2 = pos2.x * invW2, ndcY2 = pos2.y * invW2, ndcZ2 = pos2.z * invW2;

        // Viewport Transform to Screen Coordinates
        float sx0 = (ndcX0 + 1.0f) * 0.5f * m_viewport.Width + m_viewport.TopLeftX;
        float sy0 = (1.0f - ndcY0) * 0.5f * m_viewport.Height + m_viewport.TopLeftY;
        float sx1 = (ndcX1 + 1.0f) * 0.5f * m_viewport.Width + m_viewport.TopLeftX;
        float sy1 = (1.0f - ndcY1) * 0.5f * m_viewport.Height + m_viewport.TopLeftY;
        float sx2 = (ndcX2 + 1.0f) * 0.5f * m_viewport.Width + m_viewport.TopLeftX;
        float sy2 = (1.0f - ndcY2) * 0.5f * m_viewport.Height + m_viewport.TopLeftY;

        // Backface Culling (Determinant of 2D projected winding)
        float denom = (sx1 - sx0) * (sy2 - sy0) - (sy1 - sy0) * (sx2 - sx0);
        if (std::abs(denom) < 1e-6f) return; // Degenerate triangle

        D3D11_CULL_MODE cull = D3D11_CULL_NONE;
        bool frontCCW = false;
        if (m_currentRasterizerState) {
            cull = m_currentRasterizerState->GetInternalDesc().CullMode;
            frontCCW = (m_currentRasterizerState->GetInternalDesc().FrontCounterClockwise != 0);
        }

        if (cull != D3D11_CULL_NONE) {
            // In screen coordinates with inverted Y: Clockwise has denom > 0, CCW has denom < 0.
            bool isFrontFacing = frontCCW ? (denom < 0.0f) : (denom > 0.0f);
            if (cull == D3D11_CULL_BACK && !isFrontFacing) return;
            if (cull == D3D11_CULL_FRONT && isFrontFacing) return;
        }

        // Wireframe Rasterizer Mode
        D3D11_FILL_MODE fill = m_currentRasterizerState ? m_currentRasterizerState->GetInternalDesc().FillMode : D3D11_FILL_SOLID;
        if (fill == D3D11_FILL_WIREFRAME) {
            uint32_t wireColor = 0xFF00FF00; // Bright Green wireframe
            DrawLine(static_cast<int>(sx0), static_cast<int>(sy0), ndcZ0,
                     static_cast<int>(sx1), static_cast<int>(sy1), ndcZ1, wireColor, targetPixels, depthBuffer, width, height);
            DrawLine(static_cast<int>(sx1), static_cast<int>(sy1), ndcZ1,
                     static_cast<int>(sx2), static_cast<int>(sy2), ndcZ2, wireColor, targetPixels, depthBuffer, width, height);
            DrawLine(static_cast<int>(sx2), static_cast<int>(sy2), ndcZ2,
                     static_cast<int>(sx0), static_cast<int>(sy0), ndcZ0, wireColor, targetPixels, depthBuffer, width, height);
            return;
        }

        // Solid Barycentric Scan Conversion
        int minX = std::max(0, static_cast<int>(std::floor(std::min({ sx0, sx1, sx2 }))));
        int maxX = std::min(static_cast<int>(width) - 1, static_cast<int>(std::ceil(std::max({ sx0, sx1, sx2 }))));
        int minY = std::max(0, static_cast<int>(std::floor(std::min({ sy0, sy1, sy2 }))));
        int maxY = std::min(static_cast<int>(height) - 1, static_cast<int>(std::ceil(std::max({ sy0, sy1, sy2 }))));

        float invDenom = 1.0f / denom;

        // Texture sampler setup
        Prism3DTexture2DImpl* tex = nullptr;
        if (m_psShaderResources[0]) {
            auto* srv = static_cast<Prism3DShaderResourceViewImpl*>(m_psShaderResources[0]);
            tex = srv->GetTexture();
        }

        bool blendEnabled = m_currentBlendState && m_currentBlendState->GetInternalDesc().RenderTarget[0].BlendEnable;

        for (int y = minY; y <= maxY; ++y) {
            float py = static_cast<float>(y) + 0.5f;
            for (int x = minX; x <= maxX; ++x) {
                float px = static_cast<float>(x) + 0.5f;

                float w0 = ((sx1 - px) * (sy2 - py) - (sy1 - py) * (sx2 - px)) * invDenom;
                float w1 = ((sx2 - px) * (sy0 - py) - (sy2 - py) * (sx0 - px)) * invDenom;
                float w2 = 1.0f - w0 - w1;

                if (w0 >= 0.0f && w1 >= 0.0f && w2 >= 0.0f) {
                    size_t pixelIndex = static_cast<size_t>(y) * width + x;

                    // Interpolate depth
                    float z = w0 * ndcZ0 + w1 * ndcZ1 + w2 * ndcZ2;
                    if (depthBuffer) {
                        if (z > depthBuffer[pixelIndex]) continue;
                        depthBuffer[pixelIndex] = z;
                    }

                    // Gouraud color interpolation
                    float r = w0 * v0->r + w1 * v1->r + w2 * v2->r;
                    float g = w0 * v0->g + w1 * v1->g + w2 * v2->g;
                    float b = w0 * v0->b + w1 * v1->b + w2 * v2->b;
                    float a = w0 * v0->a + w1 * v1->a + w2 * v2->a;

                    // Texture modulation if UVs & texture present
                    if (hasUV && tex) {
                        float u = w0 * u0 + w1 * u1 + w2 * u2;
                        float vC = w0 * vCoord0 + w1 * vCoord1 + w2 * vCoord2;
                        uint32_t texel = tex->Sample(u, vC);
                        float tr = ((texel >> 16) & 0xFF) / 255.0f;
                        float tg = ((texel >> 8) & 0xFF) / 255.0f;
                        float tb = (texel & 0xFF) / 255.0f;
                        float ta = ((texel >> 24) & 0xFF) / 255.0f;
                        r *= tr; g *= tg; b *= tb; a *= ta;
                    }

                    uint8_t uR = static_cast<uint8_t>(std::clamp(r * 255.0f, 0.0f, 255.0f));
                    uint8_t uG = static_cast<uint8_t>(std::clamp(g * 255.0f, 0.0f, 255.0f));
                    uint8_t uB = static_cast<uint8_t>(std::clamp(b * 255.0f, 0.0f, 255.0f));
                    uint8_t uA = static_cast<uint8_t>(std::clamp(a * 255.0f, 0.0f, 255.0f));

                    if (blendEnabled && uA < 255) {
                        uint32_t dst = targetPixels[pixelIndex];
                        uint8_t dstB = dst & 0xFF;
                        uint8_t dstG = (dst >> 8) & 0xFF;
                        uint8_t dstR = (dst >> 16) & 0xFF;
                        float alpha = uA / 255.0f;
                        float invA = 1.0f - alpha;
                        uR = static_cast<uint8_t>(uR * alpha + dstR * invA);
                        uG = static_cast<uint8_t>(uG * alpha + dstG * invA);
                        uB = static_cast<uint8_t>(uB * alpha + dstB * invA);
                        uA = 255;
                    }

                    targetPixels[pixelIndex] = (uA << 24) | (uR << 16) | (uG << 8) | uB;
                }
            }
        }
    }

public:
    void Draw(uint32_t VertexCount, uint32_t StartVertexLocation) override {
        if (m_topology == D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST) {
            uint32_t numTriangles = VertexCount / 3;
            for (uint32_t t = 0; t < numTriangles; ++t) {
                uint32_t vIdx = StartVertexLocation + t * 3;
                RasterizeTriangle(vIdx, vIdx + 1, vIdx + 2);
            }
        }
    }

    void DrawIndexed(uint32_t IndexCount, uint32_t StartIndexLocation, int32_t BaseVertexLocation) override {
        if (!m_currentIB) return;
        const uint8_t* ibRaw = m_currentIB->GetData() + m_currentIBOffset;

        if (m_topology == D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST) {
            uint32_t numTriangles = IndexCount / 3;
            for (uint32_t t = 0; t < numTriangles; ++t) {
                uint32_t i0, i1, i2;
                if (m_currentIBFormat == DXGI_FORMAT_R16_UINT) {
                    const uint16_t* indices = reinterpret_cast<const uint16_t*>(ibRaw);
                    i0 = indices[StartIndexLocation + t * 3 + 0] + BaseVertexLocation;
                    i1 = indices[StartIndexLocation + t * 3 + 1] + BaseVertexLocation;
                    i2 = indices[StartIndexLocation + t * 3 + 2] + BaseVertexLocation;
                } else {
                    const uint32_t* indices = reinterpret_cast<const uint32_t*>(ibRaw);
                    i0 = indices[StartIndexLocation + t * 3 + 0] + BaseVertexLocation;
                    i1 = indices[StartIndexLocation + t * 3 + 1] + BaseVertexLocation;
                    i2 = indices[StartIndexLocation + t * 3 + 2] + BaseVertexLocation;
                }
                RasterizeTriangle(i0, i1, i2);
            }
        }
    }
};

// ============================================================================
// 8. Prism3D Device Concrete Implementation
// ============================================================================

class Prism3DDeviceImpl : public ID3D11Device {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    D3D_FEATURE_LEVEL m_featureLevel{ D3D_FEATURE_LEVEL_11_0 };
    Prism3DDeviceContextImpl* m_pImmediateContext{ nullptr };

public:
    Prism3DDeviceImpl(D3D_FEATURE_LEVEL level = D3D_FEATURE_LEVEL_11_0) : m_featureLevel(level) {
        m_pImmediateContext = new Prism3DDeviceContextImpl(this);
    }

    ~Prism3DDeviceImpl() override {
        if (m_pImmediateContext) {
            m_pImmediateContext->Release();
        }
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11Device) {
            *ppvObject = static_cast<ID3D11Device*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    int32_t CreateBuffer(const D3D11_BUFFER_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Buffer** ppBuffer) override {
        if (!pDesc || !ppBuffer) return -1;
        const void* initMem = pInitialData ? pInitialData->pSysMem : nullptr;
        *ppBuffer = new Prism3DBufferImpl(this, *pDesc, initMem);
        return 0;
    }

    int32_t CreateTexture2D(const D3D11_TEXTURE2D_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Texture2D** ppTexture2D) override {
        if (!pDesc || !ppTexture2D) return -1;
        const void* initMem = pInitialData ? pInitialData->pSysMem : nullptr;
        *ppTexture2D = new Prism3DTexture2DImpl(this, *pDesc, initMem);
        return 0;
    }

    int32_t CreateRenderTargetView(ID3D11Resource* pResource, const D3D11_RENDER_TARGET_VIEW_DESC* pDesc, ID3D11RenderTargetView** ppRTView) override {
        if (!pResource || !ppRTView) return -1;

        PrismXSurfaceImpl* surface = nullptr;
        pResource->QueryInterface(IID_IDXGISurface, reinterpret_cast<void**>(&surface));
        if (surface) surface->Release();

        *ppRTView = new Prism3DRenderTargetViewImpl(this, pResource, surface, pDesc);
        return 0;
    }

    int32_t CreateDepthStencilView(ID3D11Resource*, const D3D11_DEPTH_STENCIL_VIEW_DESC*, ID3D11DepthStencilView** ppDepthStencilView) override {
        if (!ppDepthStencilView) return -1;
        *ppDepthStencilView = new Prism3DDepthStencilViewImpl(this, 1920, 1080);
        return 0;
    }

    int32_t CreateShaderResourceView(ID3D11Resource* pResource, const D3D11_SHADER_RESOURCE_VIEW_DESC* pDesc, ID3D11ShaderResourceView** ppSRView) override {
        if (!pResource || !ppSRView) return -1;
        *ppSRView = new Prism3DShaderResourceViewImpl(this, pResource, pDesc);
        return 0;
    }

    int32_t CreateSamplerState(const D3D11_SAMPLER_DESC* pSamplerDesc, ID3D11SamplerState** ppSamplerState) override {
        if (!pSamplerDesc || !ppSamplerState) return -1;
        *ppSamplerState = new Prism3DSamplerStateImpl(this, *pSamplerDesc);
        return 0;
    }

    int32_t CreateRasterizerState(const D3D11_RASTERIZER_DESC* pRasterizerDesc, ID3D11RasterizerState** ppRasterizerState) override {
        if (!pRasterizerDesc || !ppRasterizerState) return -1;
        *ppRasterizerState = new Prism3DRasterizerStateImpl(this, *pRasterizerDesc);
        return 0;
    }

    int32_t CreateDepthStencilState(const D3D11_DEPTH_STENCIL_DESC* pDepthStencilDesc, ID3D11DepthStencilState** ppDepthStencilState) override {
        if (!pDepthStencilDesc || !ppDepthStencilState) return -1;
        *ppDepthStencilState = new Prism3DDepthStencilStateImpl(this, *pDepthStencilDesc);
        return 0;
    }

    int32_t CreateBlendState(const D3D11_BLEND_DESC* pBlendStateDesc, ID3D11BlendState** ppBlendState) override {
        if (!pBlendStateDesc || !ppBlendState) return -1;
        *ppBlendState = new Prism3DBlendStateImpl(this, *pBlendStateDesc);
        return 0;
    }

    int32_t CreateInputLayout(const D3D11_INPUT_ELEMENT_DESC* pInputElementDescs, uint32_t NumElements, const void*, size_t, ID3D11InputLayout** ppInputLayout) override {
        if (!ppInputLayout) return -1;
        *ppInputLayout = new Prism3DInputLayoutImpl(this, pInputElementDescs, NumElements);
        return 0;
    }

    int32_t CreateVertexShader(const void* pShaderBytecode, size_t BytecodeLength, ID3D11VertexShader** ppVertexShader) override {
        if (!ppVertexShader) return -1;
        *ppVertexShader = new Prism3DVertexShaderImpl(this, pShaderBytecode, BytecodeLength);
        return 0;
    }

    int32_t CreatePixelShader(const void* pShaderBytecode, size_t BytecodeLength, ID3D11PixelShader** ppPixelShader) override {
        if (!ppPixelShader) return -1;
        *ppPixelShader = new Prism3DPixelShaderImpl(this, pShaderBytecode, BytecodeLength);
        return 0;
    }

    void GetImmediateContext(ID3D11DeviceContext** ppImmediateContext) override {
        if (ppImmediateContext && m_pImmediateContext) {
            *ppImmediateContext = m_pImmediateContext;
            m_pImmediateContext->AddRef();
        }
    }

    D3D_FEATURE_LEVEL GetFeatureLevel() override {
        return m_featureLevel;
    }
};

// ============================================================================
// 9. Exported APIs (d3d11.dll / d3d12.dll parity)
// ============================================================================

inline int32_t D3D11CreateDevice(
    IDXGIAdapter* pAdapter,
    D3D_DRIVER_TYPE DriverType,
    void* Software,
    uint32_t Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    uint32_t FeatureLevels,
    uint32_t SDKVersion,
    ID3D11Device** ppDevice,
    D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext
) {
    (void)pAdapter; (void)DriverType; (void)Software; (void)Flags; (void)SDKVersion;
    D3D_FEATURE_LEVEL selectedLevel = D3D_FEATURE_LEVEL_11_0;
    if (pFeatureLevels && FeatureLevels > 0) {
        selectedLevel = pFeatureLevels[0];
    }

    auto* device = new Prism3DDeviceImpl(selectedLevel);
    if (ppDevice) {
        *ppDevice = device;
        (*ppDevice)->AddRef();
    }
    if (pFeatureLevel) {
        *pFeatureLevel = selectedLevel;
    }
    if (ppImmediateContext) {
        device->GetImmediateContext(ppImmediateContext);
    }
    device->Release();
    return 0; // S_OK
}

inline int32_t D3D11CreateDeviceAndSwapChain(
    IDXGIAdapter* pAdapter,
    D3D_DRIVER_TYPE DriverType,
    void* Software,
    uint32_t Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    uint32_t FeatureLevels,
    uint32_t SDKVersion,
    const DXGI_SWAP_CHAIN_DESC* pSwapChainDesc,
    IDXGISwapChain** ppSwapChain,
    ID3D11Device** ppDevice,
    D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext
) {
    int32_t hr = D3D11CreateDevice(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
    if (hr != 0) return hr;

    if (pSwapChainDesc && ppSwapChain) {
        IDXGIFactory1* factory = nullptr;
        CreateDXGIFactory1(IID_IDXGIFactory1, reinterpret_cast<void**>(&factory));
        if (factory) {
            DXGI_SWAP_CHAIN_DESC descCopy = *pSwapChainDesc;
            factory->CreateSwapChain(*ppDevice, &descCopy, ppSwapChain);
            factory->Release();
        }
    }
    return 0; // S_OK
}

} // namespace micant::prism3d
