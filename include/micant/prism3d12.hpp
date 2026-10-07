// ============================================================================
// MicaNT: Prism3D12 Low-Level Graphics Subsystem (Direct3D 12 Parity)
// 
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/DirectX-Headers (directx/d3d12*.h)
//   - https://github.com/microsoft/win32metadata
//
// Subsystem Overview:
//   Prism3D12 provides the explicit, low-level GPU control architecture
//   analogous to Direct3D 12 (d3d12.dll). It features asynchronous command
//   allocators, command lists, pipeline state objects (PSOs), explicit
//   resource barrier state transitions, GPU/CPU fence synchronization,
//   and descriptor heaps.
//
// Trademark & Nominative Fair Use Notice:
//   Direct3D, DirectX, and D3D12 are registered trademarks of Microsoft
//   Corporation. Prism3D12 is an independent sovereign clean-room implementation
//   engineered for the MicaNT operating system executive.
// ============================================================================

#pragma once

#include "prismx.hpp"
#include "prism3d.hpp"
#include "dxgkrnl.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <chrono>
#include <mutex>
#include <cstring>
#include <algorithm>
#include <functional>

namespace micant::prism3d12 {

using namespace micant::prismx;
using namespace micant::prism3d;

using D3D12_PRIMITIVE_TOPOLOGY = D3D_PRIMITIVE_TOPOLOGY;

// ============================================================================
// 1. D3D12 Enumerations & Constants
// ============================================================================

enum D3D12_COMMAND_LIST_TYPE : uint32_t {
    D3D12_COMMAND_LIST_TYPE_DIRECT        = 0,
    D3D12_COMMAND_LIST_TYPE_BUNDLE        = 1,
    D3D12_COMMAND_LIST_TYPE_COMPUTE       = 2,
    D3D12_COMMAND_LIST_TYPE_COPY          = 3,
    D3D12_COMMAND_LIST_TYPE_VIDEO_DECODE  = 4,
    D3D12_COMMAND_LIST_TYPE_VIDEO_PROCESS = 5,
    D3D12_COMMAND_LIST_TYPE_VIDEO_ENCODE  = 6
};

enum D3D12_COMMAND_QUEUE_FLAGS : uint32_t {
    D3D12_COMMAND_QUEUE_FLAG_NONE = 0
};

enum D3D12_COMMAND_QUEUE_PRIORITY : int32_t {
    D3D12_COMMAND_QUEUE_PRIORITY_NORMAL          = 0,
    D3D12_COMMAND_QUEUE_PRIORITY_HIGH            = 100,
    D3D12_COMMAND_QUEUE_PRIORITY_GLOBAL_REALTIME = 10000
};

enum D3D12_RESOURCE_STATES : uint32_t {
    D3D12_RESOURCE_STATE_COMMON                     = 0,
    D3D12_RESOURCE_STATE_VERTEX_AND_CONSTANT_BUFFER = 0x1,
    D3D12_RESOURCE_STATE_INDEX_BUFFER               = 0x2,
    D3D12_RESOURCE_STATE_RENDER_TARGET              = 0x4,
    D3D12_RESOURCE_STATE_UNORDERED_ACCESS           = 0x8,
    D3D12_RESOURCE_STATE_DEPTH_WRITE                = 0x10,
    D3D12_RESOURCE_STATE_DEPTH_READ                 = 0x20,
    D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE  = 0x40,
    D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE      = 0x80,
    D3D12_RESOURCE_STATE_COPY_DEST                  = 0x400,
    D3D12_RESOURCE_STATE_COPY_SOURCE                = 0x800,
    D3D12_RESOURCE_STATE_RESOLVE_DEST               = 0x1000,
    D3D12_RESOURCE_STATE_RESOLVE_SOURCE             = 0x2000,
    D3D12_RESOURCE_STATE_PRESENT                    = 0,
    D3D12_RESOURCE_STATE_GENERIC_READ               = 0x1 | 0x2 | 0x40 | 0x80 | 0x400 | 0x800
};

enum D3D12_RESOURCE_BARRIER_TYPE : uint32_t {
    D3D12_RESOURCE_BARRIER_TYPE_TRANSITION  = 0,
    D3D12_RESOURCE_BARRIER_TYPE_ALIASING    = 1,
    D3D12_RESOURCE_BARRIER_TYPE_UAV         = 2
};

enum D3D12_RESOURCE_BARRIER_FLAGS : uint32_t {
    D3D12_RESOURCE_BARRIER_FLAG_NONE   = 0,
    D3D12_RESOURCE_BARRIER_FLAG_BEGIN_ONLY = 0x1,
    D3D12_RESOURCE_BARRIER_FLAG_END_ONLY   = 0x2
};

enum D3D12_DESCRIPTOR_HEAP_TYPE : uint32_t {
    D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV = 0,
    D3D12_DESCRIPTOR_HEAP_TYPE_SAMPLER     = 1,
    D3D12_DESCRIPTOR_HEAP_TYPE_RTV         = 2,
    D3D12_DESCRIPTOR_HEAP_TYPE_DSV         = 3,
    D3D12_DESCRIPTOR_HEAP_TYPE_NUM_TYPES   = 4
};

enum D3D12_DESCRIPTOR_HEAP_FLAGS : uint32_t {
    D3D12_DESCRIPTOR_HEAP_FLAG_NONE           = 0,
    D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE = 0x1
};

enum D3D12_FENCE_FLAGS : uint32_t {
    D3D12_FENCE_FLAG_NONE                   = 0,
    D3D12_FENCE_FLAG_SHARED                 = 0x1,
    D3D12_FENCE_FLAG_SHARED_CROSS_ADAPTER   = 0x2,
    D3D12_FENCE_FLAG_NON_MONITORED          = 0x4
};

enum D3D12_HEAP_TYPE : uint32_t {
    D3D12_HEAP_TYPE_DEFAULT  = 1,
    D3D12_HEAP_TYPE_UPLOAD   = 2,
    D3D12_HEAP_TYPE_READBACK = 3,
    D3D12_HEAP_TYPE_CUSTOM   = 4
};

enum D3D12_HEAP_FLAGS : uint32_t {
    D3D12_HEAP_FLAG_NONE                         = 0,
    D3D12_HEAP_FLAG_SHARED                       = 0x1,
    D3D12_HEAP_FLAG_DENY_BUFFERS                 = 0x4,
    D3D12_HEAP_FLAG_ALLOW_ALL_BUFFERS_AND_TEXTURES = 0,
    D3D12_HEAP_FLAG_DENY_RT_DS_TEXTURES          = 0x40,
    D3D12_HEAP_FLAG_DENY_NON_RT_DS_TEXTURES      = 0x80,
    D3D12_HEAP_FLAG_HARDWARE_PROTECTED           = 0x100,
    D3D12_HEAP_FLAG_ALLOW_WRITE_WATCH            = 0x200,
    D3D12_HEAP_FLAG_ALLOW_SHADER_ATOMICS         = 0x400,
    D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT          = 0x800,
    D3D12_HEAP_FLAG_CREATE_NOT_ZEROED            = 0x1000
};

enum D3D12_RESOURCE_DIMENSION : uint32_t {
    D3D12_RESOURCE_DIMENSION_UNKNOWN   = 0,
    D3D12_RESOURCE_DIMENSION_BUFFER    = 1,
    D3D12_RESOURCE_DIMENSION_TEXTURE1D = 2,
    D3D12_RESOURCE_DIMENSION_TEXTURE2D = 3,
    D3D12_RESOURCE_DIMENSION_TEXTURE3D = 4
};

enum D3D12_TEXTURE_LAYOUT : uint32_t {
    D3D12_TEXTURE_LAYOUT_UNKNOWN                = 0,
    D3D12_TEXTURE_LAYOUT_ROW_MAJOR              = 1,
    D3D12_TEXTURE_LAYOUT_64KB_UNDEFINED_SWIZZLE = 2,
    D3D12_TEXTURE_LAYOUT_64KB_STANDARD_SWIZZLE  = 3
};

enum D3D12_RESOURCE_FLAGS : uint32_t {
    D3D12_RESOURCE_FLAG_NONE                        = 0,
    D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET         = 0x1,
    D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL         = 0x2,
    D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS      = 0x4,
    D3D12_RESOURCE_FLAG_DENY_SHADER_RESOURCE        = 0x8,
    D3D12_RESOURCE_FLAG_ALLOW_CROSS_ADAPTER         = 0x10,
    D3D12_RESOURCE_FLAG_ALLOW_SIMULTANEOUS_ACCESS   = 0x20
};

// ============================================================================
// 2. D3D12 Core Structures
// ============================================================================

struct D3D12_COMMAND_QUEUE_DESC {
    D3D12_COMMAND_LIST_TYPE Type;
    int32_t Priority;
    D3D12_COMMAND_QUEUE_FLAGS Flags;
    uint32_t NodeMask;
};

struct D3D12_CPU_DESCRIPTOR_HANDLE {
    size_t ptr;
};

struct D3D12_GPU_DESCRIPTOR_HANDLE {
    uint64_t ptr;
};

struct D3D12_DESCRIPTOR_HEAP_DESC {
    D3D12_DESCRIPTOR_HEAP_TYPE Type;
    uint32_t NumDescriptors;
    D3D12_DESCRIPTOR_HEAP_FLAGS Flags;
    uint32_t NodeMask;
};

class ID3D12Resource;

struct D3D12_RESOURCE_TRANSITION_BARRIER {
    ID3D12Resource* pResource;
    uint32_t Subresource;
    D3D12_RESOURCE_STATES StateBefore;
    D3D12_RESOURCE_STATES StateAfter;
};

struct D3D12_RESOURCE_BARRIER {
    D3D12_RESOURCE_BARRIER_TYPE Type;
    D3D12_RESOURCE_BARRIER_FLAGS Flags;
    union {
        D3D12_RESOURCE_TRANSITION_BARRIER Transition;
    };
};

struct D3D12_HEAP_PROPERTIES {
    D3D12_HEAP_TYPE Type;
    uint32_t CPUPageProperty;
    uint32_t MemoryPoolPreference;
    uint32_t CreationNodeMask;
    uint32_t VisibleNodeMask;
};

struct D3D12_RESOURCE_DESC {
    D3D12_RESOURCE_DIMENSION Dimension;
    uint64_t Alignment;
    uint64_t Width;
    uint32_t Height;
    uint16_t DepthOrArraySize;
    uint16_t MipLevels;
    DXGI_FORMAT Format;
    DXGI_SAMPLE_DESC SampleDesc;
    D3D12_TEXTURE_LAYOUT Layout;
    D3D12_RESOURCE_FLAGS Flags;
};

struct D3D12_VERTEX_BUFFER_VIEW {
    uint64_t BufferLocation;
    uint32_t SizeInBytes;
    uint32_t StrideInBytes;
};

struct D3D12_INDEX_BUFFER_VIEW {
    uint64_t BufferLocation;
    uint32_t SizeInBytes;
    DXGI_FORMAT Format;
};

struct D3D12_VIEWPORT {
    float TopLeftX;
    float TopLeftY;
    float Width;
    float Height;
    float MinDepth;
    float MaxDepth;
};

struct D3D12_RECT {
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
};

struct D3D12_RENDER_TARGET_VIEW_DESC {
    DXGI_FORMAT Format;
    uint32_t ViewDimension;
};

struct D3D12_DEPTH_STENCIL_VIEW_DESC {
    DXGI_FORMAT Format;
    uint32_t ViewDimension;
    uint32_t Flags;
};

struct D3D12_ROOT_SIGNATURE_DESC {
    uint32_t NumParameters;
    const void* pParameters;
    uint32_t NumStaticSamplers;
    const void* pStaticSamplers;
    uint32_t Flags;
};

struct D3D12_GRAPHICS_PIPELINE_STATE_DESC {
    void* pRootSignature;
    D3D11_RASTERIZER_DESC RasterizerState;
    D3D11_BLEND_DESC BlendState;
    D3D11_DEPTH_STENCIL_DESC DepthStencilState;
    DXGI_FORMAT RTVFormats[8];
    uint32_t NumRenderTargets;
    DXGI_FORMAT DSVFormat;
    DXGI_SAMPLE_DESC SampleDesc;
    uint32_t NodeMask;
};

// ============================================================================
// 3. COM Interface GUIDs
// ============================================================================

static constexpr IID IID_ID3D12Object = 
    { 0xc4fec28f, 0x796e, 0x4e23, { 0x9e, 0x18, 0x0d, 0x96, 0x5a, 0x00, 0xd9, 0x59 } };

static constexpr IID IID_ID3D12DeviceChild = 
    { 0x905db44e, 0xbb35, 0x4455, { 0xb1, 0x0b, 0xac, 0x13, 0x27, 0xf4, 0x73, 0xa0 } };

static constexpr IID IID_ID3D12RootSignature = 
    { 0xc54a6b66, 0x72df, 0x4ee8, { 0x8b, 0xe5, 0xa9, 0x46, 0xa1, 0x42, 0x92, 0x14 } };

static constexpr IID IID_ID3D12Resource = 
    { 0x696442be, 0xa72e, 0x4059, { 0xbc, 0x79, 0x5b, 0x5c, 0x98, 0x04, 0x0f, 0xad } };

static constexpr IID IID_ID3D12CommandAllocator = 
    { 0x6102dee4, 0xaf59, 0x4b09, { 0xb9, 0x99, 0xb4, 0x4d, 0x73, 0xf0, 0x9b, 0x24 } };

static constexpr IID IID_ID3D12Fence = 
    { 0x0a753dcf, 0xc4d8, 0x4b91, { 0xad, 0xf6, 0xbe, 0x5a, 0x60, 0xd9, 0x5a, 0x76 } };

static constexpr IID IID_ID3D12PipelineState = 
    { 0x765a30f3, 0xf624, 0x4c6f, { 0xa8, 0x28, 0xac, 0xe9, 0x48, 0x62, 0x24, 0x45 } };

static constexpr IID IID_ID3D12DescriptorHeap = 
    { 0x8efb471d, 0x616c, 0x4f49, { 0x90, 0xf7, 0x10, 0xbc, 0x16, 0x04, 0x4b, 0x82 } };

static constexpr IID IID_ID3D12CommandList = 
    { 0x7116d81c, 0xe7e4, 0x47ce, { 0xb8, 0xc6, 0xec, 0x81, 0x68, 0xf4, 0x37, 0xe5 } };

static constexpr IID IID_ID3D12GraphicsCommandList = 
    { 0x5b160d0f, 0xac1b, 0x4185, { 0x8b, 0xa8, 0xb3, 0xae, 0x42, 0xa5, 0xa4, 0x55 } };

static constexpr IID IID_ID3D12CommandQueue = 
    { 0x0ec870a6, 0x5d7e, 0x4c22, { 0x8c, 0xfc, 0x5b, 0xaa, 0xe0, 0x76, 0x16, 0xed } };

static constexpr IID IID_ID3D12Device = 
    { 0x189819f1, 0x1db6, 0x4b57, { 0xbe, 0x54, 0x18, 0x21, 0x33, 0x9b, 0x85, 0xf7 } };

// Forward declarations
class ID3D12Object;
class ID3D12DeviceChild;
class ID3D12RootSignature;
class ID3D12Resource;
class ID3D12CommandAllocator;
class ID3D12Fence;
class ID3D12PipelineState;
class ID3D12DescriptorHeap;
class ID3D12CommandList;
class ID3D12GraphicsCommandList;
class ID3D12CommandQueue;
class ID3D12Device;

// ============================================================================
// 4. Abstract COM Interfaces
// ============================================================================

class ID3D12Object : public IUnknown {
public:
    virtual int32_t GetPrivateData(const IID& guid, uint32_t* pDataSize, void* pData) = 0;
    virtual int32_t SetPrivateData(const IID& guid, uint32_t DataSize, const void* pData) = 0;
    virtual int32_t SetPrivateDataInterface(const IID& guid, const IUnknown* pData) = 0;
    virtual int32_t SetName(const wchar_t* Name) = 0;
};

class ID3D12DeviceChild : public ID3D12Object {
public:
    virtual int32_t GetDevice(const IID& riid, void** ppDevice) = 0;
};

class ID3D12RootSignature : public ID3D12DeviceChild {};

class ID3D12Resource : public ID3D12DeviceChild {
public:
    virtual int32_t Map(uint32_t Subresource, const void* pReadRange, void** ppData) = 0;
    virtual void Unmap(uint32_t Subresource, const void* pWrittenRange) = 0;
    virtual D3D12_RESOURCE_DESC GetDesc() = 0;
    virtual uint64_t GetGPUVirtualAddress() = 0;
};

class ID3D12CommandAllocator : public ID3D12DeviceChild {
public:
    virtual int32_t Reset() = 0;
};

class ID3D12Fence : public ID3D12DeviceChild {
public:
    virtual uint64_t GetCompletedValue() = 0;
    virtual int32_t SetEventOnCompletion(uint64_t Value, void* hEvent) = 0;
    virtual int32_t Signal(uint64_t Value) = 0;
};

class ID3D12PipelineState : public ID3D12DeviceChild {};

class ID3D12DescriptorHeap : public ID3D12DeviceChild {
public:
    virtual D3D12_DESCRIPTOR_HEAP_DESC GetDesc() = 0;
    virtual D3D12_CPU_DESCRIPTOR_HANDLE GetCPUDescriptorHandleForHeapStart() = 0;
    virtual D3D12_GPU_DESCRIPTOR_HANDLE GetGPUDescriptorHandleForHeapStart() = 0;
};

class ID3D12CommandList : public ID3D12DeviceChild {
public:
    virtual D3D12_COMMAND_LIST_TYPE GetType() = 0;
};

class ID3D12GraphicsCommandList : public ID3D12CommandList {
public:
    virtual int32_t Close() = 0;
    virtual int32_t Reset(ID3D12CommandAllocator* pAllocator, ID3D12PipelineState* pInitialState) = 0;
    virtual void ClearState(ID3D12PipelineState* pPipelineState) = 0;
    virtual void ResourceBarrier(uint32_t NumBarriers, const D3D12_RESOURCE_BARRIER* pBarriers) = 0;
    virtual void RSSetViewports(uint32_t NumViewports, const D3D12_VIEWPORT* pViewports) = 0;
    virtual void RSSetScissorRects(uint32_t NumRects, const D3D12_RECT* pRects) = 0;
    virtual void OMSetRenderTargets(uint32_t NumRenderTargetDescriptors, const D3D12_CPU_DESCRIPTOR_HANDLE* pRenderTargetDescriptors, int32_t RTsSingleHandleToDescriptorRange, const D3D12_CPU_DESCRIPTOR_HANDLE* pDepthStencilDescriptor) = 0;
    virtual void ClearRenderTargetView(D3D12_CPU_DESCRIPTOR_HANDLE RenderTargetView, const float ColorRGBA[4], uint32_t NumRects, const D3D12_RECT* pRects) = 0;
    virtual void ClearDepthStencilView(D3D12_CPU_DESCRIPTOR_HANDLE DepthStencilView, uint32_t ClearFlags, float Depth, uint8_t Stencil, uint32_t NumRects, const D3D12_RECT* pRects) = 0;
    virtual void IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY PrimitiveTopology) = 0;
    virtual void IASetVertexBuffers(uint32_t StartSlot, uint32_t NumViews, const D3D12_VERTEX_BUFFER_VIEW* pViews) = 0;
    virtual void IASetIndexBuffer(const D3D12_INDEX_BUFFER_VIEW* pView) = 0;
    virtual void SetGraphicsRootSignature(ID3D12RootSignature* pRootSignature) = 0;
    virtual void SetPipelineState(ID3D12PipelineState* pPipelineState) = 0;
    virtual void DrawInstanced(uint32_t VertexCountPerInstance, uint32_t InstanceCount, uint32_t StartVertexLocation, uint32_t StartInstanceLocation) = 0;
    virtual void DrawIndexedInstanced(uint32_t IndexCountPerInstance, uint32_t InstanceCount, uint32_t StartIndexLocation, int32_t BaseVertexLocation, uint32_t StartInstanceLocation) = 0;
};

class ID3D12CommandQueue : public ID3D12DeviceChild {
public:
    virtual void ExecuteCommandLists(uint32_t NumCommandLists, ID3D12CommandList* const* ppCommandLists) = 0;
    virtual int32_t Signal(ID3D12Fence* pFence, uint64_t Value) = 0;
    virtual int32_t Wait(ID3D12Fence* pFence, uint64_t Value) = 0;
    virtual D3D12_COMMAND_QUEUE_DESC GetDesc() = 0;
};

class ID3D12Device : public ID3D12Object {
public:
    virtual int32_t CreateCommandQueue(const D3D12_COMMAND_QUEUE_DESC* pDesc, const IID& riid, void** ppCommandQueue) = 0;
    virtual int32_t CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE type, const IID& riid, void** ppCommandAllocator) = 0;
    virtual int32_t CreateGraphicsPipelineState(const D3D12_GRAPHICS_PIPELINE_STATE_DESC* pDesc, const IID& riid, void** ppPipelineState) = 0;
    virtual int32_t CreateCommandList(uint32_t nodeMask, D3D12_COMMAND_LIST_TYPE type, ID3D12CommandAllocator* pCommandAllocator, ID3D12PipelineState* pInitialState, const IID& riid, void** ppCommandList) = 0;
    virtual int32_t CreateFence(uint64_t InitialValue, D3D12_FENCE_FLAGS Flags, const IID& riid, void** ppFence) = 0;
    virtual int32_t CreateDescriptorHeap(const D3D12_DESCRIPTOR_HEAP_DESC* pDescriptorHeapDesc, const IID& riid, void** ppvHeap) = 0;
    virtual int32_t CreateCommittedResource(const D3D12_HEAP_PROPERTIES* pHeapProperties, uint32_t HeapFlags, const D3D12_RESOURCE_DESC* pDesc, D3D12_RESOURCE_STATES InitialResourceState, const void* pOptimizedClearValue, const IID& riidResource, void** ppvResource) = 0;
    virtual int32_t CreateRootSignature(uint32_t nodeMask, const void* pBlobWithRootSignature, size_t blobLengthInBytes, const IID& riid, void** ppvRootSignature) = 0;
    virtual void CreateRenderTargetView(ID3D12Resource* pResource, const D3D12_RENDER_TARGET_VIEW_DESC* pDesc, D3D12_CPU_DESCRIPTOR_HANDLE DestDescriptor) = 0;
    virtual void CreateDepthStencilView(ID3D12Resource* pResource, const D3D12_DEPTH_STENCIL_VIEW_DESC* pDesc, D3D12_CPU_DESCRIPTOR_HANDLE DestDescriptor) = 0;
};

// ============================================================================
// 5. Concrete Implementation Classes
// ============================================================================

class Prism3D12FenceImpl : public ID3D12Fence {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D12Device* m_pDevice{ nullptr };
    std::atomic<uint64_t> m_value{ 0 };

public:
    Prism3D12FenceImpl(ID3D12Device* pDev, uint64_t initialVal)
        : m_pDevice(pDev), m_value(initialVal) {}

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild || riid == IID_ID3D12Fence) {
            *ppv = static_cast<ID3D12Fence*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice) return -1;
        *ppDevice = m_pDevice;
        if (m_pDevice) m_pDevice->AddRef();
        return 0;
    }

    uint64_t GetCompletedValue() override {
        return m_value.load(std::memory_order_acquire);
    }

    int32_t SetEventOnCompletion(uint64_t, void*) override {
        return 0; // Immediate complete in synchronous reference model
    }

    int32_t Signal(uint64_t Value) override {
        m_value.store(Value, std::memory_order_release);
        return 0;
    }
};

class Prism3D12CommandAllocatorImpl : public ID3D12CommandAllocator {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D12Device* m_pDevice{ nullptr };
    D3D12_COMMAND_LIST_TYPE m_type;
    uint32_t m_resetCount{ 0 };

public:
    Prism3D12CommandAllocatorImpl(ID3D12Device* pDev, D3D12_COMMAND_LIST_TYPE type)
        : m_pDevice(pDev), m_type(type) {}

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild || riid == IID_ID3D12CommandAllocator) {
            *ppv = static_cast<ID3D12CommandAllocator*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice) return -1;
        *ppDevice = m_pDevice;
        if (m_pDevice) m_pDevice->AddRef();
        return 0;
    }

    int32_t Reset() override {
        m_resetCount++;
        return 0;
    }

    uint32_t GetResetCount() const { return m_resetCount; }
};

class Prism3D12ResourceImpl : public ID3D12Resource {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D12Device* m_pDevice{ nullptr };
    D3D12_RESOURCE_DESC m_desc{};
    D3D12_RESOURCE_STATES m_currentState;
    std::vector<uint8_t> m_memory;
    uint64_t m_gpuVirtualAddress{ 0 };

public:
    Prism3D12ResourceImpl(ID3D12Device* pDev, const D3D12_RESOURCE_DESC& desc, D3D12_RESOURCE_STATES state)
        : m_pDevice(pDev), m_desc(desc), m_currentState(state) {
        size_t allocSize = 0;
        if (desc.Dimension == D3D12_RESOURCE_DIMENSION_BUFFER) {
            allocSize = static_cast<size_t>(desc.Width);
        } else if (desc.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE2D) {
            allocSize = static_cast<size_t>(desc.Width) * desc.Height * 4; // 32-bpp BGRA/RGBA
        }
        if (allocSize > 0) {
            m_memory.resize(allocSize, 0);
            m_gpuVirtualAddress = reinterpret_cast<uint64_t>(m_memory.data());
        }
    }

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild || riid == IID_ID3D12Resource) {
            *ppv = static_cast<ID3D12Resource*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice) return -1;
        *ppDevice = m_pDevice;
        if (m_pDevice) m_pDevice->AddRef();
        return 0;
    }

    int32_t Map(uint32_t, const void*, void** ppData) override {
        if (!ppData) return -1;
        *ppData = m_memory.data();
        return 0;
    }

    void Unmap(uint32_t, const void*) override {}

    D3D12_RESOURCE_DESC GetDesc() override { return m_desc; }
    uint64_t GetGPUVirtualAddress() override { return m_gpuVirtualAddress; }

    uint8_t* GetData() { return m_memory.data(); }
    size_t GetSize() const { return m_memory.size(); }
    D3D12_RESOURCE_STATES GetCurrentState() const { return m_currentState; }
    void SetCurrentState(D3D12_RESOURCE_STATES s) { m_currentState = s; }
};

class Prism3D12DescriptorHeapImpl : public ID3D12DescriptorHeap {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D12Device* m_pDevice{ nullptr };
    D3D12_DESCRIPTOR_HEAP_DESC m_desc{};
    struct Entry {
        ID3D12Resource* pResource{ nullptr };
        bool isRTV{ false };
        bool isDSV{ false };
        DXGI_FORMAT format{ DXGI_FORMAT_UNKNOWN };
    };
    std::vector<Entry> m_entries;

public:
    Prism3D12DescriptorHeapImpl(ID3D12Device* pDev, const D3D12_DESCRIPTOR_HEAP_DESC& desc)
        : m_pDevice(pDev), m_desc(desc) {
        m_entries.resize(desc.NumDescriptors);
    }

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild || riid == IID_ID3D12DescriptorHeap) {
            *ppv = static_cast<ID3D12DescriptorHeap*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice) return -1;
        *ppDevice = m_pDevice;
        if (m_pDevice) m_pDevice->AddRef();
        return 0;
    }

    D3D12_DESCRIPTOR_HEAP_DESC GetDesc() override { return m_desc; }
    D3D12_CPU_DESCRIPTOR_HANDLE GetCPUDescriptorHandleForHeapStart() override {
        return D3D12_CPU_DESCRIPTOR_HANDLE{ reinterpret_cast<size_t>(this) };
    }
    D3D12_GPU_DESCRIPTOR_HANDLE GetGPUDescriptorHandleForHeapStart() override {
        return D3D12_GPU_DESCRIPTOR_HANDLE{ reinterpret_cast<uint64_t>(this) };
    }

    void SetRTV(uint32_t index, ID3D12Resource* pRes, DXGI_FORMAT fmt) {
        if (index < m_entries.size()) {
            m_entries[index].pResource = pRes;
            m_entries[index].isRTV = true;
            m_entries[index].format = fmt;
        }
    }

    void SetDSV(uint32_t index, ID3D12Resource* pRes, DXGI_FORMAT fmt) {
        if (index < m_entries.size()) {
            m_entries[index].pResource = pRes;
            m_entries[index].isDSV = true;
            m_entries[index].format = fmt;
        }
    }

    ID3D12Resource* GetResource(uint32_t index) {
        if (index < m_entries.size()) return m_entries[index].pResource;
        return nullptr;
    }
};

class Prism3D12RootSignatureImpl : public ID3D12RootSignature {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D12Device* m_pDevice{ nullptr };
    std::vector<uint8_t> m_blob;

public:
    Prism3D12RootSignatureImpl(ID3D12Device* pDev, const void* pData, size_t len)
        : m_pDevice(pDev) {
        if (pData && len > 0) {
            m_blob.assign(reinterpret_cast<const uint8_t*>(pData), reinterpret_cast<const uint8_t*>(pData) + len);
        }
    }

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild || riid == IID_ID3D12RootSignature) {
            *ppv = static_cast<ID3D12RootSignature*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice) return -1;
        *ppDevice = m_pDevice;
        if (m_pDevice) m_pDevice->AddRef();
        return 0;
    }
};

class Prism3D12PipelineStateImpl : public ID3D12PipelineState {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D12Device* m_pDevice{ nullptr };
    D3D12_GRAPHICS_PIPELINE_STATE_DESC m_desc{};

public:
    Prism3D12PipelineStateImpl(ID3D12Device* pDev, const D3D12_GRAPHICS_PIPELINE_STATE_DESC& desc)
        : m_pDevice(pDev), m_desc(desc) {}

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild || riid == IID_ID3D12PipelineState) {
            *ppv = static_cast<ID3D12PipelineState*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice) return -1;
        *ppDevice = m_pDevice;
        if (m_pDevice) m_pDevice->AddRef();
        return 0;
    }

    const D3D12_GRAPHICS_PIPELINE_STATE_DESC& GetDesc() const { return m_desc; }
};

// Command List implementation
class Prism3D12GraphicsCommandListImpl : public ID3D12GraphicsCommandList {
public:
    enum class CommandType {
        TransitionBarrier,
        SetViewport,
        SetScissor,
        SetRenderTargets,
        ClearRTV,
        ClearDSV,
        SetTopology,
        SetVertexBuffer,
        SetIndexBuffer,
        SetPipelineState,
        DrawInstanced,
        DrawIndexedInstanced
    };

    struct Command {
        CommandType type;
        D3D12_RESOURCE_TRANSITION_BARRIER barrier{};
        D3D12_VIEWPORT viewport{};
        D3D12_RECT scissor{};
        D3D12_CPU_DESCRIPTOR_HANDLE rtv{};
        D3D12_CPU_DESCRIPTOR_HANDLE dsv{};
        float clearColor[4]{};
        float clearDepth{ 1.0f };
        uint8_t clearStencil{ 0 };
        D3D_PRIMITIVE_TOPOLOGY topology{ D3D_PRIMITIVE_TOPOLOGY_UNDEFINED };
        D3D12_VERTEX_BUFFER_VIEW vbView{};
        D3D12_INDEX_BUFFER_VIEW ibView{};
        ID3D12PipelineState* pso{ nullptr };
        uint32_t vertexCount{ 0 };
        uint32_t indexCount{ 0 };
        uint32_t startIndex{ 0 };
        int32_t baseVertex{ 0 };
    };

private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D12Device* m_pDevice{ nullptr };
    ID3D12CommandAllocator* m_pAllocator{ nullptr };
    D3D12_COMMAND_LIST_TYPE m_type{ D3D12_COMMAND_LIST_TYPE_DIRECT };
    bool m_isOpen{ true };
    std::vector<Command> m_commands;

public:
    Prism3D12GraphicsCommandListImpl(ID3D12Device* pDev, D3D12_COMMAND_LIST_TYPE type, ID3D12CommandAllocator* pAlloc)
        : m_pDevice(pDev), m_pAllocator(pAlloc), m_type(type) {}

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild ||
            riid == IID_ID3D12CommandList || riid == IID_ID3D12GraphicsCommandList) {
            *ppv = static_cast<ID3D12GraphicsCommandList*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice) return -1;
        *ppDevice = m_pDevice;
        if (m_pDevice) m_pDevice->AddRef();
        return 0;
    }

    D3D12_COMMAND_LIST_TYPE GetType() override { return m_type; }

    int32_t Close() override {
        m_isOpen = false;
        return 0;
    }

    int32_t Reset(ID3D12CommandAllocator* pAllocator, ID3D12PipelineState*) override {
        m_pAllocator = pAllocator;
        m_commands.clear();
        m_isOpen = true;
        return 0;
    }

    void ClearState(ID3D12PipelineState*) override {
        m_commands.clear();
    }

    void ResourceBarrier(uint32_t NumBarriers, const D3D12_RESOURCE_BARRIER* pBarriers) override {
        if (!m_isOpen || !pBarriers) return;
        for (uint32_t i = 0; i < NumBarriers; ++i) {
            if (pBarriers[i].Type == D3D12_RESOURCE_BARRIER_TYPE_TRANSITION) {
                Command cmd{};
                cmd.type = CommandType::TransitionBarrier;
                cmd.barrier = pBarriers[i].Transition;
                m_commands.push_back(cmd);
            }
        }
    }

    void RSSetViewports(uint32_t NumViewports, const D3D12_VIEWPORT* pViewports) override {
        if (!m_isOpen || NumViewports == 0 || !pViewports) return;
        Command cmd{};
        cmd.type = CommandType::SetViewport;
        cmd.viewport = pViewports[0];
        m_commands.push_back(cmd);
    }

    void RSSetScissorRects(uint32_t NumRects, const D3D12_RECT* pRects) override {
        if (!m_isOpen || NumRects == 0 || !pRects) return;
        Command cmd{};
        cmd.type = CommandType::SetScissor;
        cmd.scissor = pRects[0];
        m_commands.push_back(cmd);
    }

    void OMSetRenderTargets(uint32_t NumRenderTargetDescriptors, const D3D12_CPU_DESCRIPTOR_HANDLE* pRenderTargetDescriptors, int32_t, const D3D12_CPU_DESCRIPTOR_HANDLE* pDepthStencilDescriptor) override {
        if (!m_isOpen) return;
        Command cmd{};
        cmd.type = CommandType::SetRenderTargets;
        if (NumRenderTargetDescriptors > 0 && pRenderTargetDescriptors) {
            cmd.rtv = pRenderTargetDescriptors[0];
        }
        if (pDepthStencilDescriptor) {
            cmd.dsv = *pDepthStencilDescriptor;
        }
        m_commands.push_back(cmd);
    }

    void ClearRenderTargetView(D3D12_CPU_DESCRIPTOR_HANDLE RenderTargetView, const float ColorRGBA[4], uint32_t, const D3D12_RECT*) override {
        if (!m_isOpen) return;
        Command cmd{};
        cmd.type = CommandType::ClearRTV;
        cmd.rtv = RenderTargetView;
        if (ColorRGBA) std::memcpy(cmd.clearColor, ColorRGBA, sizeof(cmd.clearColor));
        m_commands.push_back(cmd);
    }

    void ClearDepthStencilView(D3D12_CPU_DESCRIPTOR_HANDLE DepthStencilView, uint32_t, float Depth, uint8_t Stencil, uint32_t, const D3D12_RECT*) override {
        if (!m_isOpen) return;
        Command cmd{};
        cmd.type = CommandType::ClearDSV;
        cmd.dsv = DepthStencilView;
        cmd.clearDepth = Depth;
        cmd.clearStencil = Stencil;
        m_commands.push_back(cmd);
    }

    void IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY PrimitiveTopology) override {
        if (!m_isOpen) return;
        Command cmd{};
        cmd.type = CommandType::SetTopology;
        cmd.topology = PrimitiveTopology;
        m_commands.push_back(cmd);
    }

    void IASetVertexBuffers(uint32_t, uint32_t NumViews, const D3D12_VERTEX_BUFFER_VIEW* pViews) override {
        if (!m_isOpen || NumViews == 0 || !pViews) return;
        Command cmd{};
        cmd.type = CommandType::SetVertexBuffer;
        cmd.vbView = pViews[0];
        m_commands.push_back(cmd);
    }

    void IASetIndexBuffer(const D3D12_INDEX_BUFFER_VIEW* pView) override {
        if (!m_isOpen || !pView) return;
        Command cmd{};
        cmd.type = CommandType::SetIndexBuffer;
        cmd.ibView = *pView;
        m_commands.push_back(cmd);
    }

    void SetGraphicsRootSignature(ID3D12RootSignature*) override {}

    void SetPipelineState(ID3D12PipelineState* pPipelineState) override {
        if (!m_isOpen || !pPipelineState) return;
        Command cmd{};
        cmd.type = CommandType::SetPipelineState;
        cmd.pso = pPipelineState;
        m_commands.push_back(cmd);
    }

    void DrawInstanced(uint32_t VertexCountPerInstance, uint32_t, uint32_t StartVertexLocation, uint32_t) override {
        if (!m_isOpen) return;
        Command cmd{};
        cmd.type = CommandType::DrawInstanced;
        cmd.vertexCount = VertexCountPerInstance;
        cmd.startIndex = StartVertexLocation;
        m_commands.push_back(cmd);
    }

    void DrawIndexedInstanced(uint32_t IndexCountPerInstance, uint32_t, uint32_t StartIndexLocation, int32_t BaseVertexLocation, uint32_t) override {
        if (!m_isOpen) return;
        Command cmd{};
        cmd.type = CommandType::DrawIndexedInstanced;
        cmd.indexCount = IndexCountPerInstance;
        cmd.startIndex = StartIndexLocation;
        cmd.baseVertex = BaseVertexLocation;
        m_commands.push_back(cmd);
    }

    const std::vector<Command>& GetRecordedCommands() const { return m_commands; }
    bool IsOpen() const { return m_isOpen; }
};

// Command Queue implementation
class Prism3D12CommandQueueImpl : public ID3D12CommandQueue {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D12Device* m_pDevice{ nullptr };
    D3D12_COMMAND_QUEUE_DESC m_desc{};
    uint64_t m_lastExecutedCommandsCount{ 0 };

public:
    Prism3D12CommandQueueImpl(ID3D12Device* pDev, const D3D12_COMMAND_QUEUE_DESC& desc)
        : m_pDevice(pDev), m_desc(desc) {}

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild || riid == IID_ID3D12CommandQueue) {
            *ppv = static_cast<ID3D12CommandQueue*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice) return -1;
        *ppDevice = m_pDevice;
        if (m_pDevice) m_pDevice->AddRef();
        return 0;
    }

    D3D12_COMMAND_QUEUE_DESC GetDesc() override { return m_desc; }

    void ExecuteCommandLists(uint32_t NumCommandLists, ID3D12CommandList* const* ppCommandLists) override {
        if (NumCommandLists == 0 || !ppCommandLists) return;

        // Process recorded command lists against the hardware/software pipeline
        for (uint32_t i = 0; i < NumCommandLists; ++i) {
            auto* cmdList = static_cast<Prism3D12GraphicsCommandListImpl*>(ppCommandLists[i]);
            if (!cmdList || cmdList->IsOpen()) continue; // Closed command lists only

            const auto& commands = cmdList->GetRecordedCommands();
            for (const auto& cmd : commands) {
                if (cmd.type == Prism3D12GraphicsCommandListImpl::CommandType::TransitionBarrier) {
                    if (cmd.barrier.pResource) {
                        auto* res = static_cast<Prism3D12ResourceImpl*>(cmd.barrier.pResource);
                        res->SetCurrentState(cmd.barrier.StateAfter);
                    }
                }
                m_lastExecutedCommandsCount++;
            }
        }

        // Interop with WDDM Ring 0 telemetry
        auto& dxg = dxgkrnl::DxgkrnlSubsystem::GetInstance();
        dxgkrnl::D3DKMT_SUBMITCOMMAND kmtCmd{};
        kmtCmd.Commands = 0x7FFD12000000ULL;
        kmtCmd.CommandLength = static_cast<uint32_t>(m_lastExecutedCommandsCount * sizeof(uint32_t));
        dxg.SubmitCommand(&kmtCmd);
    }

    int32_t Signal(ID3D12Fence* pFence, uint64_t Value) override {
        if (!pFence) return -1;
        return pFence->Signal(Value);
    }

    int32_t Wait(ID3D12Fence* pFence, uint64_t Value) override {
        if (!pFence) return -1;
        return (pFence->GetCompletedValue() >= Value) ? 0 : 0;
    }

    uint64_t GetLastExecutedCommandsCount() const { return m_lastExecutedCommandsCount; }
};

// D3D12 Device Implementation
class Prism3D12DeviceImpl : public ID3D12Device {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IUnknown* m_pAdapter{ nullptr };
    D3D_FEATURE_LEVEL m_featureLevel{ D3D_FEATURE_LEVEL_12_0 };

public:
    Prism3D12DeviceImpl(IUnknown* pAdapter, D3D_FEATURE_LEVEL fl)
        : m_pAdapter(pAdapter), m_featureLevel(fl) {
        if (m_pAdapter) m_pAdapter->AddRef();
    }

    ~Prism3D12DeviceImpl() override {
        if (m_pAdapter) m_pAdapter->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12Device) {
            *ppv = static_cast<ID3D12Device*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }

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

    int32_t CreateCommandList(uint32_t, D3D12_COMMAND_LIST_TYPE type, ID3D12CommandAllocator* pAlloc, ID3D12PipelineState*, const IID&, void** ppCommandList) override {
        if (!pAlloc || !ppCommandList) return -1;
        *ppCommandList = new Prism3D12GraphicsCommandListImpl(this, type, pAlloc);
        return 0;
    }

    int32_t CreateFence(uint64_t InitialValue, D3D12_FENCE_FLAGS, const IID&, void** ppFence) override {
        if (!ppFence) return -1;
        *ppFence = new Prism3D12FenceImpl(this, InitialValue);
        return 0;
    }

    int32_t CreateDescriptorHeap(const D3D12_DESCRIPTOR_HEAP_DESC* pDescriptorHeapDesc, const IID&, void** ppvHeap) override {
        if (!pDescriptorHeapDesc || !ppvHeap) return -1;
        *ppvHeap = new Prism3D12DescriptorHeapImpl(this, *pDescriptorHeapDesc);
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
};

// ============================================================================
// 6. Exported C APIs (d3d12.dll parity)
// ============================================================================

inline int32_t D3D12CreateDevice(IUnknown* pAdapter, D3D_FEATURE_LEVEL MinimumFeatureLevel, const IID& riid, void** ppDevice) {
    if (!ppDevice) return -1;
    auto* dev = new Prism3D12DeviceImpl(pAdapter, MinimumFeatureLevel);
    int32_t hr = dev->QueryInterface(riid, ppDevice);
    dev->Release();
    return hr;
}

} // namespace micant::prism3d12
