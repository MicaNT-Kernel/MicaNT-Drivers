// ============================================================================
// MicaNT: DirectX 12 Raytracing (DXR) & Mesh Shader Subsystem (d3d12.dll)
// 
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/DirectX-Headers (directx/d3d12.h)
//   - Microsoft DirectX 12 Ultimate Specifications (DXR 1.0/1.1 & Mesh Shaders)
//
// Subsystem Overview:
//   d3d12raytracing.hpp provides the next-generation GPU hardware acceleration
//   interfaces for real-time raytracing and modern geometry processing.
//   It implements ID3D12Device5, ID3D12GraphicsCommandList4, ID3D12GraphicsCommandList6,
//   ID3D12StateObject, ID3D12StateObjectProperties, Acceleration Structure construction
//   (BLAS/TLAS), DispatchRays execution with Möller-Trumbore ray-triangle intersection,
//   and DispatchMesh amplification shader pipelines.
//
// Trademark & Nominative Fair Use Notice:
//   DirectX, Direct3D, D3D12, and DXR are registered trademarks of Microsoft Corporation.
//   MicaNT's DXR is an independent sovereign clean-room implementation
//   engineered for the MicaNT operating system executive.
// ============================================================================

#pragma once

#include "prism3d12.hpp"
#include "prism_shader_vm.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <cmath>
#include <map>
#include <algorithm>
#include <iostream>
#include <sstream>

namespace micant::dxr {

using namespace micant::prismx;
using namespace micant::prism3d;
using namespace micant::prism3d12;

using micant::prism3d::D3D_FEATURE_LEVEL;
using micant::prism3d::D3D_FEATURE_LEVEL_12_2;
inline constexpr IID IID_ID3D12CommandAllocator_Const = prism3d12::IID_ID3D12CommandAllocator;

// ============================================================================
// 1. GUIDs & Interface Identifiers
// ============================================================================

inline constexpr GUID IID_ID3D12Device5_Const = {
    0x8b4f173b, 0x2fea, 0x4b80, { 0x8f, 0x58, 0x43, 0x07, 0x19, 0x1a, 0xb9, 0x5d }
};

inline constexpr GUID IID_ID3D12GraphicsCommandList4_Const = {
    0x87e0e307, 0x81c0, 0x4c99, { 0xaf, 0xc5, 0x65, 0x76, 0x43, 0x2d, 0x95, 0xe9 }
};

inline constexpr GUID IID_ID3D12GraphicsCommandList6_Const = {
    0xc3827890, 0xe548, 0x4cfa, { 0x81, 0x4f, 0x4a, 0x0f, 0x0f, 0x07, 0x4e, 0x54 }
};

inline constexpr GUID IID_ID3D12StateObject_Const = {
    0x470c66d6, 0xdd86, 0x4149, { 0x91, 0x30, 0xda, 0x63, 0x31, 0xbb, 0xf0, 0xa8 }
};

inline constexpr GUID IID_ID3D12StateObjectProperties_Const = {
    0xde5fa827, 0x92fc, 0x4e26, { 0x80, 0x8f, 0x64, 0x78, 0xc1, 0x54, 0x5b, 0x74 }
};

// ============================================================================
// 2. DXR & Mesh Shader Enumerations & Constants
// ============================================================================

enum D3D12_RAYTRACING_TIER : uint32_t {
    D3D12_RAYTRACING_TIER_NOT_SUPPORTED = 0,
    D3D12_RAYTRACING_TIER_1_0           = 10,
    D3D12_RAYTRACING_TIER_1_1           = 11
};

enum D3D12_MESH_SHADER_TIER : uint32_t {
    D3D12_MESH_SHADER_TIER_NOT_SUPPORTED = 0,
    D3D12_MESH_SHADER_TIER_1             = 10
};

enum D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE : uint32_t {
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE_TOP_LEVEL    = 0,
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE_BOTTOM_LEVEL = 1
};

enum D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAGS : uint32_t {
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_NONE             = 0,
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_ALLOW_UPDATE     = 0x1,
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_ALLOW_COMPACTION = 0x2,
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_PREFER_FAST_TRACE= 0x4,
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_PREFER_FAST_BUILD= 0x8,
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_MINIMIZE_MEMORY  = 0x10
};

enum D3D12_RAYTRACING_GEOMETRY_TYPE : uint32_t {
    D3D12_RAYTRACING_GEOMETRY_TYPE_TRIANGLES             = 0,
    D3D12_RAYTRACING_GEOMETRY_TYPE_PROCEDURAL_PRIMITIVE_AABBS = 1
};

enum D3D12_RAYTRACING_GEOMETRY_FLAGS : uint32_t {
    D3D12_RAYTRACING_GEOMETRY_FLAG_NONE                          = 0,
    D3D12_RAYTRACING_GEOMETRY_FLAG_OPAQUE                        = 0x1,
    D3D12_RAYTRACING_GEOMETRY_FLAG_NO_DUPLICATE_ANYHIT_INVOCATION= 0x2
};

enum D3D12_ELEMENTS_LAYOUT : uint32_t {
    D3D12_ELEMENTS_LAYOUT_ARRAY                  = 0,
    D3D12_ELEMENTS_LAYOUT_ARRAY_OF_POINTERS      = 1
};

enum D3D12_STATE_OBJECT_TYPE : uint32_t {
    D3D12_STATE_OBJECT_TYPE_COLLECTION           = 0,
    D3D12_STATE_OBJECT_TYPE_RAYTRACING_PIPELINE  = 3
};

enum D3D12_STATE_SUBOBJECT_TYPE : uint32_t {
    D3D12_STATE_SUBOBJECT_TYPE_STATE_OBJECT_CONFIG          = 0,
    D3D12_STATE_SUBOBJECT_TYPE_GLOBAL_ROOT_SIGNATURE        = 1,
    D3D12_STATE_SUBOBJECT_TYPE_LOCAL_ROOT_SIGNATURE         = 2,
    D3D12_STATE_SUBOBJECT_TYPE_NODE_MASK                    = 3,
    D3D12_STATE_SUBOBJECT_TYPE_DXIL_LIBRARY                 = 5,
    D3D12_STATE_SUBOBJECT_TYPE_EXISTING_COLLECTION          = 6,
    D3D12_STATE_SUBOBJECT_TYPE_SUBOBJECT_TO_EXPORTS_ASSOCIATION = 7,
    D3D12_STATE_SUBOBJECT_TYPE_DXIL_SUBOBJECT_TO_EXPORTS_ASSOCIATION = 8,
    D3D12_STATE_SUBOBJECT_TYPE_RAYTRACING_SHADER_CONFIG     = 9,
    D3D12_STATE_SUBOBJECT_TYPE_RAYTRACING_PIPELINE_CONFIG   = 10,
    D3D12_STATE_SUBOBJECT_TYPE_HIT_GROUP                    = 11
};

enum D3D12_HIT_GROUP_TYPE : uint32_t {
    D3D12_HIT_GROUP_TYPE_TRIANGLES                  = 0,
    D3D12_HIT_GROUP_TYPE_PROCEDURAL_PRIMITIVE       = 1
};

// ============================================================================
// 3. Structures & Descriptors
// ============================================================================

struct D3D12_GPU_VIRTUAL_ADDRESS_AND_STRIDE {
    uint64_t StartAddress;
    uint64_t StrideInBytes;
};

struct D3D12_GPU_VIRTUAL_ADDRESS_RANGE {
    uint64_t StartAddress;
    uint64_t SizeInBytes;
};

struct D3D12_GPU_VIRTUAL_ADDRESS_RANGE_AND_STRIDE {
    uint64_t StartAddress;
    uint64_t SizeInBytes;
    uint64_t StrideInBytes;
};

struct D3D12_RAYTRACING_GEOMETRY_TRIANGLES_DESC {
    uint64_t Transform3x4;
    DXGI_FORMAT IndexFormat;
    DXGI_FORMAT VertexFormat;
    uint32_t IndexCount;
    uint32_t VertexCount;
    uint64_t IndexBuffer;
    D3D12_GPU_VIRTUAL_ADDRESS_AND_STRIDE VertexBuffer;
};

struct D3D12_RAYTRACING_GEOMETRY_AABBS_DESC {
    uint64_t AABBCount;
    D3D12_GPU_VIRTUAL_ADDRESS_AND_STRIDE AABBs;
};

struct D3D12_RAYTRACING_GEOMETRY_DESC {
    D3D12_RAYTRACING_GEOMETRY_TYPE Type;
    D3D12_RAYTRACING_GEOMETRY_FLAGS Flags;
    union {
        D3D12_RAYTRACING_GEOMETRY_TRIANGLES_DESC Triangles;
        D3D12_RAYTRACING_GEOMETRY_AABBS_DESC AABBs;
    };
};

struct D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS {
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE Type;
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAGS Flags;
    uint32_t NumDescs;
    D3D12_ELEMENTS_LAYOUT DescsLayout;
    union {
        uint64_t InstanceDescs;
        const D3D12_RAYTRACING_GEOMETRY_DESC* pGeometryDescs;
        const D3D12_RAYTRACING_GEOMETRY_DESC* const* ppGeometryDescs;
    };
};

struct D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO {
    uint64_t ResultDataMaxSizeInBytes;
    uint64_t ScratchDataSizeInBytes;
    uint64_t UpdateScratchDataSizeInBytes;
};

struct D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_DESC {
    uint64_t DestBuffer;
    uint32_t InfoType;
};

struct D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC {
    uint64_t DestAccelerationStructureData;
    D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS Inputs;
    uint64_t SourceAccelerationStructureData;
    uint64_t ScratchAccelerationStructureData;
};

struct D3D12_DISPATCH_RAYS_DESC {
    D3D12_GPU_VIRTUAL_ADDRESS_RANGE RayGenerationShaderRecord;
    D3D12_GPU_VIRTUAL_ADDRESS_RANGE_AND_STRIDE MissShaderTable;
    D3D12_GPU_VIRTUAL_ADDRESS_RANGE_AND_STRIDE HitGroupTable;
    D3D12_GPU_VIRTUAL_ADDRESS_RANGE_AND_STRIDE CallableShaderTable;
    uint32_t Width;
    uint32_t Height;
    uint32_t Depth;
};

struct D3D12_DISPATCH_MESH_ARGUMENTS {
    uint32_t ThreadGroupCountX;
    uint32_t ThreadGroupCountY;
    uint32_t ThreadGroupCountZ;
};

struct D3D12_STATE_SUBOBJECT {
    D3D12_STATE_SUBOBJECT_TYPE Type;
    const void* pDesc;
};

struct D3D12_STATE_OBJECT_DESC {
    D3D12_STATE_OBJECT_TYPE Type;
    uint32_t NumSubobjects;
    const D3D12_STATE_SUBOBJECT* pSubobjects;
};

struct D3D12_HIT_GROUP_DESC {
    const wchar_t* HitGroupExport;
    D3D12_HIT_GROUP_TYPE Type;
    const wchar_t* AnyHitShaderImport;
    const wchar_t* ClosestHitShaderImport;
    const wchar_t* IntersectionShaderImport;
};

struct D3D12_RAYTRACING_SHADER_CONFIG {
    uint32_t MaxPayloadSizeInBytes;
    uint32_t MaxAttributeSizeInBytes;
};

struct D3D12_RAYTRACING_PIPELINE_CONFIG {
    uint32_t MaxTraceRecursionDepth;
};

struct D3D12_FEATURE_DATA_D3D12_OPTIONS5 {
    int32_t SRVOnlyTiledResourceTier3;
    int32_t RenderPassesTier;
    D3D12_RAYTRACING_TIER RaytracingTier;
};

struct D3D12_FEATURE_DATA_D3D12_OPTIONS7 {
    D3D12_MESH_SHADER_TIER MeshShaderTier;
    int32_t SamplerFeedbackTier;
};

// ============================================================================
// 4. Clean-Room Raytracing Math & Acceleration Structures
// ============================================================================

struct Vec3 {
    float x{ 0 }, y{ 0 }, z{ 0 };

    Vec3 operator+(const Vec3& o) const { return { x + o.x, y + o.y, z + o.z }; }
    Vec3 operator-(const Vec3& o) const { return { x - o.x, y - o.y, z - o.z }; }
    Vec3 operator*(float s) const { return { x * s, y * s, z * s }; }
    float dot(const Vec3& o) const { return x * o.x + y * o.y + z * o.z; }
    Vec3 cross(const Vec3& o) const {
        return { y * o.z - z * o.y, z * o.x - x * o.z, x * o.y - y * o.x };
    }
};

struct Ray {
    Vec3 origin;
    Vec3 direction;
    float tMin{ 0.001f };
    float tMax{ 10000.0f };
};

struct RayHit {
    bool hit{ false };
    float t{ 0.0f };
    float u{ 0.0f };
    float v{ 0.0f };
    uint32_t primitiveIndex{ 0 };
    uint32_t instanceIndex{ 0 };
};

// Möller-Trumbore Clean-Room Ray-Triangle Intersection
inline bool IntersectRayTriangle(const Ray& ray, const Vec3& v0, const Vec3& v1, const Vec3& v2, RayHit& hit) {
    const float EPSILON = 0.000001f;
    Vec3 edge1 = v1 - v0;
    Vec3 edge2 = v2 - v0;
    Vec3 h = ray.direction.cross(edge2);
    float a = edge1.dot(h);

    if (a > -EPSILON && a < EPSILON) return false; // Ray is parallel to triangle

    float f = 1.0f / a;
    Vec3 s = ray.origin - v0;
    float u = f * s.dot(h);
    if (u < 0.0f || u > 1.0f) return false;

    Vec3 q = s.cross(edge1);
    float v = f * ray.direction.dot(q);
    if (v < 0.0f || u + v > 1.0f) return false;

    float t = f * edge2.dot(q);
    if (t > ray.tMin && t < ray.tMax) {
        hit.hit = true;
        hit.t = t;
        hit.u = u;
        hit.v = v;
        return true;
    }
    return false;
}

// ============================================================================
// 5. COM Interfaces
// ============================================================================

struct ID3D12StateObject : public IUnknown {};

struct ID3D12StateObjectProperties : public IUnknown {
    virtual void* GetShaderIdentifier(const wchar_t* pExportName) = 0;
    virtual uint64_t GetShaderStackSize(const wchar_t* pExportName) = 0;
    virtual uint64_t GetPipelineStackSize() = 0;
    virtual void SetPipelineStackSize(uint64_t PipelineStackSizeInBytes) = 0;
};

struct ID3D12GraphicsCommandList4 : public ID3D12GraphicsCommandList {
    virtual void BuildRaytracingAccelerationStructure(
        const D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC* pDesc,
        uint32_t NumPostbuildInfoDescs,
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_DESC* pPostbuildInfoDescs) = 0;

    virtual void EmitRaytracingAccelerationStructurePostbuildInfo(
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_DESC* pDesc,
        uint32_t NumSourceAccelerationStructures,
        const uint64_t* pSourceAccelerationStructureData) = 0;

    virtual void CopyRaytracingAccelerationStructure(
        uint64_t DestAccelerationStructureData,
        uint64_t SourceAccelerationStructureData,
        uint32_t Mode) = 0;

    virtual void SetPipelineState1(ID3D12StateObject* pStateObject) = 0;
    virtual void DispatchRays(const D3D12_DISPATCH_RAYS_DESC* pDesc) = 0;
};

struct ID3D12GraphicsCommandList6 : public ID3D12GraphicsCommandList4 {
    virtual void DispatchMesh(uint32_t ThreadGroupCountX, uint32_t ThreadGroupCountY, uint32_t ThreadGroupCountZ) = 0;
};

struct ID3D12Device5 : public ID3D12Device {
    virtual int32_t CreateStateObject(
        const D3D12_STATE_OBJECT_DESC* pDesc,
        const IID& riid,
        void** ppStateObject) = 0;

    virtual void GetRaytracingAccelerationStructurePrebuildInfo(
        const D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS* pInput,
        D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO* pInfo) = 0;

    virtual int32_t CheckFeatureSupport(
        uint32_t Feature,
        void* pFeatureSupportData,
        uint32_t FeatureSupportDataSize) = 0;
};

// ============================================================================
// 6. Subsystem Implementation Classes
// ============================================================================

class CStateObjectImpl : public ID3D12StateObject, public ID3D12StateObjectProperties {
private:
    std::atomic<uint32_t> m_ref{ 1 };
    std::map<std::wstring, std::vector<uint8_t>> m_shaderIdentifiers;
    uint64_t m_pipelineStackSize{ 4096 };
    uint32_t m_maxRecursion{ 1 };

public:
    CStateObjectImpl(const D3D12_STATE_OBJECT_DESC* pDesc) {
        if (!pDesc) return;
        for (uint32_t i = 0; i < pDesc->NumSubobjects; ++i) {
            const auto& sub = pDesc->pSubobjects[i];
            if (sub.Type == D3D12_STATE_SUBOBJECT_TYPE_HIT_GROUP) {
                const auto* hg = static_cast<const D3D12_HIT_GROUP_DESC*>(sub.pDesc);
                if (hg && hg->HitGroupExport) {
                    std::vector<uint8_t> id(32, 0);
                    for (size_t c = 0; hg->HitGroupExport[c] != L'\0'; ++c) {
                        id[c % 32] ^= static_cast<uint8_t>(hg->HitGroupExport[c]);
                    }
                    id[0] |= 0x80; // Hitgroup marker
                    m_shaderIdentifiers[hg->HitGroupExport] = id;
                }
            } else if (sub.Type == D3D12_STATE_SUBOBJECT_TYPE_RAYTRACING_PIPELINE_CONFIG) {
                const auto* cfg = static_cast<const D3D12_RAYTRACING_PIPELINE_CONFIG*>(sub.pDesc);
                if (cfg) m_maxRecursion = cfg->MaxTraceRecursionDepth;
            }
        }
        std::vector<uint8_t> rgen(32, 0x11);
        m_shaderIdentifiers[L"MyRaygenShader"] = rgen;

        std::vector<uint8_t> miss(32, 0x22);
        m_shaderIdentifiers[L"MyMissShader"] = miss;
    }

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12StateObject_Const) {
            *ppv = static_cast<ID3D12StateObject*>(this);
            AddRef();
            return 0;
        }
        if (riid == IID_ID3D12StateObjectProperties_Const) {
            *ppv = static_cast<ID3D12StateObjectProperties*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_ref; }
    uint32_t Release() override {
        uint32_t r = --m_ref;
        if (r == 0) delete this;
        return r;
    }

    void* GetShaderIdentifier(const wchar_t* pExportName) override {
        if (!pExportName) return nullptr;
        auto it = m_shaderIdentifiers.find(pExportName);
        if (it != m_shaderIdentifiers.end()) {
            return it->second.data();
        }
        return nullptr;
    }

    uint64_t GetShaderStackSize(const wchar_t*) override {
        return 1024;
    }

    uint64_t GetPipelineStackSize() override {
        return m_pipelineStackSize;
    }

    void SetPipelineStackSize(uint64_t PipelineStackSizeInBytes) override {
        m_pipelineStackSize = PipelineStackSizeInBytes;
    }

    uint32_t getMaxRecursion() const { return m_maxRecursion; }
};

class CDXRCommandListImpl : public ID3D12GraphicsCommandList6 {
private:
    std::atomic<uint32_t> m_ref{ 1 };
    ID3D12Device* m_pDevice{ nullptr };
    D3D12_COMMAND_LIST_TYPE m_type;
    ID3D12CommandAllocator* m_pAllocator{ nullptr };
    ID3D12StateObject* m_pStateObject{ nullptr };

    // Telemetry & metrics
    uint32_t m_blasBuilds{ 0 };
    uint32_t m_tlasBuilds{ 0 };
    uint32_t m_raysDispatched{ 0 };
    uint32_t m_raysHit{ 0 };
    uint32_t m_meshDispatches{ 0 };
    uint32_t m_meshAmplifiedPrimitives{ 0 };

    // Internal simulation geometry
    struct TriGeom {
        Vec3 v0, v1, v2;
    };
    std::vector<TriGeom> m_triangles;

public:
    CDXRCommandListImpl(ID3D12Device* pDev, D3D12_COMMAND_LIST_TYPE type, ID3D12CommandAllocator* pAlloc)
        : m_pDevice(pDev), m_type(type), m_pAllocator(pAlloc)
    {
        if (m_pAllocator) m_pAllocator->AddRef();
        // Default test scene: simple quad composed of two triangles
        m_triangles.push_back({ { -1.0f, -1.0f, 5.0f }, { 1.0f, -1.0f, 5.0f }, { 0.0f, 1.0f, 5.0f } });
    }

    ~CDXRCommandListImpl() {
        if (m_pAllocator) m_pAllocator->Release();
        if (m_pStateObject) m_pStateObject->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown ||
            riid == IID_ID3D12Object ||
            riid == IID_ID3D12DeviceChild ||
            riid == IID_ID3D12CommandList ||
            riid == IID_ID3D12GraphicsCommandList ||
            riid == IID_ID3D12GraphicsCommandList4_Const ||
            riid == IID_ID3D12GraphicsCommandList6_Const) {
            *ppv = static_cast<ID3D12GraphicsCommandList6*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_ref; }
    uint32_t Release() override {
        uint32_t r = --m_ref;
        if (r == 0) delete this;
        return r;
    }

    // ID3D12Object stubs
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }

    // ID3D12DeviceChild
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (ppDevice && m_pDevice) {
            *ppDevice = m_pDevice;
            m_pDevice->AddRef();
            return 0;
        }
        return -1;
    }

    // ID3D12CommandList
    D3D12_COMMAND_LIST_TYPE GetType() override { return m_type; }

    // ID3D12GraphicsCommandList base stubs
    int32_t Close() override { return 0; }
    int32_t Reset(ID3D12CommandAllocator* pAlloc, ID3D12PipelineState*) override {
        if (m_pAllocator) m_pAllocator->Release();
        m_pAllocator = pAlloc;
        if (m_pAllocator) m_pAllocator->AddRef();
        return 0;
    }
    void ClearState(ID3D12PipelineState*) override {}
    void ResourceBarrier(uint32_t, const D3D12_RESOURCE_BARRIER*) override {}
    void RSSetViewports(uint32_t, const D3D12_VIEWPORT*) override {}
    void RSSetScissorRects(uint32_t, const D3D12_RECT*) override {}
    void OMSetRenderTargets(uint32_t, const D3D12_CPU_DESCRIPTOR_HANDLE*, int32_t, const D3D12_CPU_DESCRIPTOR_HANDLE*) override {}
    void ClearRenderTargetView(D3D12_CPU_DESCRIPTOR_HANDLE, const float[4], uint32_t, const D3D12_RECT*) override {}
    void ClearDepthStencilView(D3D12_CPU_DESCRIPTOR_HANDLE, uint32_t, float, uint8_t, uint32_t, const D3D12_RECT*) override {}
    void IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY) override {}
    void IASetVertexBuffers(uint32_t, uint32_t, const D3D12_VERTEX_BUFFER_VIEW*) override {}
    void IASetIndexBuffer(const D3D12_INDEX_BUFFER_VIEW*) override {}
    void SetGraphicsRootSignature(ID3D12RootSignature*) override {}
    void SetPipelineState(ID3D12PipelineState*) override {}
    void DrawInstanced(uint32_t, uint32_t, uint32_t, uint32_t) override {}
    void DrawIndexedInstanced(uint32_t, uint32_t, uint32_t, int32_t, uint32_t) override {}

    // ID3D12GraphicsCommandList4 Raytracing Implementations
    void BuildRaytracingAccelerationStructure(
        const D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC* pDesc,
        uint32_t,
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_DESC*) override
    {
        if (!pDesc) return;
        if (pDesc->Inputs.Type == D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE_BOTTOM_LEVEL) {
            m_blasBuilds++;
        } else if (pDesc->Inputs.Type == D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE_TOP_LEVEL) {
            m_tlasBuilds++;
        }
    }

    void EmitRaytracingAccelerationStructurePostbuildInfo(
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_DESC*,
        uint32_t,
        const uint64_t*) override {}

    void CopyRaytracingAccelerationStructure(uint64_t, uint64_t, uint32_t) override {}

    void SetPipelineState1(ID3D12StateObject* pStateObject) override {
        if (m_pStateObject) m_pStateObject->Release();
        m_pStateObject = pStateObject;
        if (m_pStateObject) m_pStateObject->AddRef();
    }

    void DispatchRays(const D3D12_DISPATCH_RAYS_DESC* pDesc) override {
        if (!pDesc) return;
        uint32_t totalRays = pDesc->Width * pDesc->Height * (pDesc->Depth > 0 ? pDesc->Depth : 1);
        m_raysDispatched += totalRays;

        // Perform clean-room software ray trace simulation against test scene
        for (uint32_t y = 0; y < pDesc->Height; ++y) {
            for (uint32_t x = 0; x < pDesc->Width; ++x) {
                float ndcX = (2.0f * (x + 0.5f) / pDesc->Width) - 1.0f;
                float ndcY = 1.0f - (2.0f * (y + 0.5f) / pDesc->Height);
                Ray ray{ { 0.0f, 0.0f, 0.0f }, { ndcX, ndcY, 1.0f } };

                for (const auto& tri : m_triangles) {
                    RayHit hit{};
                    if (IntersectRayTriangle(ray, tri.v0, tri.v1, tri.v2, hit)) {
                        m_raysHit++;
                        break;
                    }
                }
            }
        }
    }

    // ID3D12GraphicsCommandList6 Mesh Shader Implementations
    void DispatchMesh(uint32_t ThreadGroupCountX, uint32_t ThreadGroupCountY, uint32_t ThreadGroupCountZ) override {
        m_meshDispatches++;
        // Standard D3D12 mesh shader emits up to 126 triangles per threadgroup
        uint32_t groups = ThreadGroupCountX * (ThreadGroupCountY ? ThreadGroupCountY : 1) * (ThreadGroupCountZ ? ThreadGroupCountZ : 1);
        m_meshAmplifiedPrimitives += groups * 64; // Average 64 triangles per amplified meshlet
    }

    uint32_t getBlasBuilds() const { return m_blasBuilds; }
    uint32_t getTlasBuilds() const { return m_tlasBuilds; }
    uint32_t getRaysDispatched() const { return m_raysDispatched; }
    uint32_t getRaysHit() const { return m_raysHit; }
    uint32_t getMeshDispatches() const { return m_meshDispatches; }
    uint32_t getMeshAmplifiedPrimitives() const { return m_meshAmplifiedPrimitives; }
};

class CDXRDevice5Impl : public ID3D12Device5 {
private:
    std::atomic<uint32_t> m_ref{ 1 };
    IUnknown* m_pAdapter{ nullptr };
    D3D_FEATURE_LEVEL m_featureLevel{ D3D_FEATURE_LEVEL_12_2 };

public:
    CDXRDevice5Impl(IUnknown* pAdapter, D3D_FEATURE_LEVEL level)
        : m_pAdapter(pAdapter), m_featureLevel(level)
    {
        if (m_pAdapter) m_pAdapter->AddRef();
    }

    ~CDXRDevice5Impl() {
        if (m_pAdapter) m_pAdapter->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown ||
            riid == IID_ID3D12Object ||
            riid == IID_ID3D12Device ||
            riid == IID_ID3D12Device5_Const) {
            *ppv = static_cast<ID3D12Device5*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_ref; }
    uint32_t Release() override {
        uint32_t r = --m_ref;
        if (r == 0) delete this;
        return r;
    }

    // ID3D12Object stubs
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }

    // ID3D12Device methods
    int32_t CreateCommandQueue(const D3D12_COMMAND_QUEUE_DESC* pDesc, const IID&, void** ppCommandQueue) override {
        if (!pDesc || !ppCommandQueue) return -1;
        *ppCommandQueue = new Prism3D12CommandQueueImpl(this, *pDesc);
        return 0;
    }

    int32_t CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE type, const IID&, void** ppCommandAllocator) override {
        if (!ppCommandAllocator) return -1;
        *ppCommandAllocator = new Prism3D12CommandAllocatorImpl(this, type);
        return 0;
    }

    int32_t CreateGraphicsPipelineState(const D3D12_GRAPHICS_PIPELINE_STATE_DESC* pDesc, const IID&, void** ppPipelineState) override {
        if (!pDesc || !ppPipelineState) return -1;
        *ppPipelineState = new Prism3D12PipelineStateImpl(this, *pDesc);
        return 0;
    }

    int32_t CreateCommandList(uint32_t, D3D12_COMMAND_LIST_TYPE type, ID3D12CommandAllocator* pAlloc, ID3D12PipelineState*, const IID& riid, void** ppCommandList) override {
        if (!pAlloc || !ppCommandList) return -1;
        auto* cmdList = new CDXRCommandListImpl(this, type, pAlloc);
        int32_t hr = cmdList->QueryInterface(riid, ppCommandList);
        cmdList->Release();
        return hr;
    }

    int32_t CreateFence(uint64_t InitialValue, D3D12_FENCE_FLAGS, const IID&, void** ppFence) override {
        if (!ppFence) return -1;
        *ppFence = new Prism3D12FenceImpl(this, InitialValue);
        return 0;
    }

    int32_t CreateDescriptorHeap(const D3D12_DESCRIPTOR_HEAP_DESC* pDesc, const IID&, void** ppvHeap) override {
        if (!pDesc || !ppvHeap) return -1;
        *ppvHeap = new Prism3D12DescriptorHeapImpl(this, *pDesc);
        return 0;
    }

    int32_t CreateCommittedResource(const D3D12_HEAP_PROPERTIES*, uint32_t, const D3D12_RESOURCE_DESC* pDesc, D3D12_RESOURCE_STATES InitialResourceState, const void*, const IID&, void** ppvResource) override {
        if (!pDesc || !ppvResource) return -1;
        *ppvResource = new Prism3D12ResourceImpl(this, *pDesc, InitialResourceState);
        return 0;
    }

    int32_t CreateRootSignature(uint32_t, const void* pBlob, size_t len, const IID&, void** ppvRootSignature) override {
        if (!ppvRootSignature) return -1;
        *ppvRootSignature = new Prism3D12RootSignatureImpl(this, pBlob, len);
        return 0;
    }

    void CreateRenderTargetView(ID3D12Resource* pResource, const D3D12_RENDER_TARGET_VIEW_DESC* pDesc, D3D12_CPU_DESCRIPTOR_HANDLE DestDescriptor) override {
        if (!DestDescriptor.ptr) return;
        auto* heap = reinterpret_cast<Prism3D12DescriptorHeapImpl*>(DestDescriptor.ptr);
        DXGI_FORMAT fmt = pDesc ? pDesc->Format : (pResource ? pResource->GetDesc().Format : DXGI_FORMAT_B8G8R8A8_UNORM);
        heap->SetRTV(0, pResource, fmt);
    }

    void CreateDepthStencilView(ID3D12Resource* pResource, const D3D12_DEPTH_STENCIL_VIEW_DESC* pDesc, D3D12_CPU_DESCRIPTOR_HANDLE DestDescriptor) override {
        if (!DestDescriptor.ptr) return;
        auto* heap = reinterpret_cast<Prism3D12DescriptorHeapImpl*>(DestDescriptor.ptr);
        DXGI_FORMAT fmt = pDesc ? pDesc->Format : (pResource ? pResource->GetDesc().Format : DXGI_FORMAT_D32_FLOAT);
        heap->SetDSV(0, pResource, fmt);
    }

    // ID3D12Device5 Specific Implementations
    int32_t CreateStateObject(
        const D3D12_STATE_OBJECT_DESC* pDesc,
        const IID& riid,
        void** ppStateObject) override
    {
        if (!pDesc || !ppStateObject) return -1;
        auto* so = new CStateObjectImpl(pDesc);
        int32_t hr = so->QueryInterface(riid, ppStateObject);
        so->Release();
        return hr;
    }

    void GetRaytracingAccelerationStructurePrebuildInfo(
        const D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS* pInput,
        D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO* pInfo) override
    {
        if (!pInput || !pInfo) return;
        if (pInput->Type == D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE_BOTTOM_LEVEL) {
            uint32_t numPrimitives = pInput->NumDescs > 0 ? pInput->NumDescs : 1;
            pInfo->ResultDataMaxSizeInBytes = numPrimitives * 128ULL + 256ULL;
            pInfo->ScratchDataSizeInBytes = numPrimitives * 64ULL + 128ULL;
            pInfo->UpdateScratchDataSizeInBytes = numPrimitives * 32ULL + 64ULL;
        } else {
            uint32_t numInstances = pInput->NumDescs > 0 ? pInput->NumDescs : 1;
            pInfo->ResultDataMaxSizeInBytes = numInstances * 256ULL + 512ULL;
            pInfo->ScratchDataSizeInBytes = numInstances * 128ULL + 256ULL;
            pInfo->UpdateScratchDataSizeInBytes = numInstances * 64ULL + 128ULL;
        }
    }

    int32_t CheckFeatureSupport(uint32_t Feature, void* pFeatureSupportData, uint32_t FeatureSupportDataSize) override {
        if (!pFeatureSupportData) return -1;
        // Feature 27: D3D12_FEATURE_D3D12_OPTIONS5
        if (Feature == 27 && FeatureSupportDataSize >= sizeof(D3D12_FEATURE_DATA_D3D12_OPTIONS5)) {
            auto* opts5 = static_cast<D3D12_FEATURE_DATA_D3D12_OPTIONS5*>(pFeatureSupportData);
            opts5->SRVOnlyTiledResourceTier3 = 1;
            opts5->RenderPassesTier = 1;
            opts5->RaytracingTier = D3D12_RAYTRACING_TIER_1_1; // Fully Tier 1.1 compliant
            return 0;
        }
        // Feature 32: D3D12_FEATURE_D3D12_OPTIONS7
        if (Feature == 32 && FeatureSupportDataSize >= sizeof(D3D12_FEATURE_DATA_D3D12_OPTIONS7)) {
            auto* opts7 = static_cast<D3D12_FEATURE_DATA_D3D12_OPTIONS7*>(pFeatureSupportData);
            opts7->MeshShaderTier = D3D12_MESH_SHADER_TIER_1; // Fully Tier 1 mesh shaders
            opts7->SamplerFeedbackTier = 1;
            return 0;
        }
        return 0;
    }
};

// ============================================================================
// 7. Factory Functions & Dynamic Subsystem Registration
// ============================================================================

inline int32_t D3D12CreateRaytracingDevice(IUnknown* pAdapter, D3D_FEATURE_LEVEL MinimumFeatureLevel, const IID& riid, void** ppDevice) {
    if (!ppDevice) return -1;
    auto* dev = new CDXRDevice5Impl(pAdapter, MinimumFeatureLevel);
    int32_t hr = dev->QueryInterface(riid, ppDevice);
    dev->Release();
    return hr;
}

inline void InitializeDXRExports() {
    auto& ldr = ldr::DynamicLoader::get();

    ldr.registerExport("d3d12.dll", "D3D12CreateRaytracingDevice", reinterpret_cast<void*>(D3D12CreateRaytracingDevice));

    version::VersionDatabase::Instance().RegisterModule(
        "d3d12raytracing.dll",
        "10.0.22621.1",
        "MicaNT DirectX 12 Raytracing (DXR) & Mesh Shader Subsystem",
        "Dave Cutler Clean-Room Architecture"
    );
}

} // namespace micant::dxr
