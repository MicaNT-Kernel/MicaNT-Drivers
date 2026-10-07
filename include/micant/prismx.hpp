// ============================================================================
// MicaNT: PrismX Presentation & Display Infrastructure (DXGI Compatible)
// 
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/DirectX-Headers (directx/dxgi*.h)
//   - https://github.com/microsoft/win32metadata
//
// Trademark & Nominative Fair Use Notice:
//   PrismX is an independent, sovereign graphics presentation subsystem
//   designed for MicaNT, named in tribute to Dave Cutler's 1988 DEC PRISM
//   architecture. DirectX, Direct3D, and DXGI are registered trademarks
//   of Microsoft Corporation.
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <atomic>
#include <functional>

namespace micant::prismx {

// ============================================================================
// 1. Standard COM Types & GUIDs
// ============================================================================

struct RECT {
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
};

struct POINT {
    int32_t x;
    int32_t y;
};

// Standard DXGI Formats (subset matching DirectX-Headers dxgiformat.h)
enum DXGI_FORMAT : uint32_t {
    DXGI_FORMAT_UNKNOWN                    = 0,
    DXGI_FORMAT_R32G32B32A32_TYPELESS       = 1,
    DXGI_FORMAT_R32G32B32A32_FLOAT          = 2,
    DXGI_FORMAT_R32G32B32_FLOAT             = 6,
    DXGI_FORMAT_R16G16B16A16_FLOAT          = 10,
    DXGI_FORMAT_R16G16B16A16_UNORM          = 11,
    DXGI_FORMAT_R32G32_FLOAT                = 16,
    DXGI_FORMAT_D32_FLOAT                   = 40,
    DXGI_FORMAT_R32_FLOAT                   = 41,
    DXGI_FORMAT_D24_UNORM_S8_UINT           = 45,
    DXGI_FORMAT_R8G8B8A8_TYPELESS           = 27,
    DXGI_FORMAT_R8G8B8A8_UNORM              = 28,
    DXGI_FORMAT_R8G8B8A8_UNORM_SRGB         = 29,
    DXGI_FORMAT_R8G8B8A8_UINT               = 30,
    DXGI_FORMAT_R8G8B8A8_SNORM              = 31,
    DXGI_FORMAT_R16_UINT                    = 57,
    DXGI_FORMAT_R32_UINT                    = 42,
    DXGI_FORMAT_B8G8R8A8_UNORM              = 87,
    DXGI_FORMAT_B8G8R8X8_UNORM              = 88,
    DXGI_FORMAT_B8G8R8A8_UNORM_SRGB         = 91,
    DXGI_FORMAT_R10G10B10A2_UNORM           = 24,
    DXGI_FORMAT_AYUV                        = 100,
    DXGI_FORMAT_NV12                        = 103,
    DXGI_FORMAT_P010                        = 104,
    DXGI_FORMAT_YUY2                        = 107
};

enum DXGI_COLOR_SPACE_TYPE : uint32_t {
    DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709           = 0,
    DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709           = 1,
    DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P709         = 2,
    DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P2020        = 3,
    DXGI_COLOR_SPACE_RESERVED                         = 4,
    DXGI_COLOR_SPACE_YCBCR_FULL_G22_NONE_P709_X601    = 5,
    DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P601       = 6,
    DXGI_COLOR_SPACE_YCBCR_FULL_G22_LEFT_P601         = 7,
    DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709       = 8,
    DXGI_COLOR_SPACE_YCBCR_FULL_G22_LEFT_P709         = 9,
    DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P2020      = 10,
    DXGI_COLOR_SPACE_YCBCR_FULL_G22_LEFT_P2020        = 11,
    DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020        = 12,
    DXGI_COLOR_SPACE_YCBCR_STUDIO_G2084_LEFT_P2020    = 13,
    DXGI_COLOR_SPACE_RGB_STUDIO_G2084_NONE_P2020       = 14,
    DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_TOPLEFT_P2020   = 15,
    DXGI_COLOR_SPACE_YCBCR_STUDIO_G2084_TOPLEFT_P2020 = 16,
    DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P2020          = 17,
    DXGI_COLOR_SPACE_CUSTOM                           = 0xFFFFFFFF
};

enum DXGI_MODE_SCANLINE_ORDER : uint32_t {
    DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED        = 0,
    DXGI_MODE_SCANLINE_ORDER_PROGRESSIVE        = 1,
    DXGI_MODE_SCANLINE_ORDER_UPPER_FIELD_FIRST  = 2,
    DXGI_MODE_SCANLINE_ORDER_LOWER_FIELD_FIRST  = 3
};

enum DXGI_MODE_SCALING : uint32_t {
    DXGI_MODE_SCALING_UNSPECIFIED   = 0,
    DXGI_MODE_SCALING_CENTERED      = 1,
    DXGI_MODE_SCALING_STRETCHED     = 2
};

struct DXGI_RATIONAL {
    uint32_t Numerator;
    uint32_t Denominator;
};

struct DXGI_MODE_DESC {
    uint32_t Width;
    uint32_t Height;
    DXGI_RATIONAL RefreshRate;
    DXGI_FORMAT Format;
    DXGI_MODE_SCANLINE_ORDER ScanlineOrdering;
    DXGI_MODE_SCALING Scaling;
};

struct DXGI_SAMPLE_DESC {
    uint32_t Count;
    uint32_t Quality;
};

enum DXGI_SWAP_EFFECT : uint32_t {
    DXGI_SWAP_EFFECT_DISCARD         = 0,
    DXGI_SWAP_EFFECT_SEQUENTIAL      = 1,
    DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL = 3,
    DXGI_SWAP_EFFECT_FLIP_DISCARD    = 4
};

enum DXGI_SWAP_CHAIN_FLAG : uint32_t {
    DXGI_SWAP_CHAIN_FLAG_NONPREROTATED                          = 1,
    DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH                      = 2,
    DXGI_SWAP_CHAIN_FLAG_GDI_COMPATIBLE                         = 4,
    DXGI_SWAP_CHAIN_FLAG_RESTRICTED_CONTENT                     = 8,
    DXGI_SWAP_CHAIN_FLAG_RESTRICT_SHARED_RESOURCE_DRIVER        = 16,
    DXGI_SWAP_CHAIN_FLAG_DISPLAY_ONLY                           = 32,
    DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT          = 64,
    DXGI_SWAP_CHAIN_FLAG_FOREGROUND_LAYER                       = 128,
    DXGI_SWAP_CHAIN_FLAG_FULLSCREEN_VIDEO                       = 256,
    DXGI_SWAP_CHAIN_FLAG_HW_PROTECTED                           = 512,
    DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING                          = 2048
};

enum DXGI_USAGE : uint32_t {
    DXGI_USAGE_SHADER_INPUT         = 1 << (0 + 4),
    DXGI_USAGE_RENDER_TARGET_OUTPUT = 1 << (1 + 4),
    DXGI_USAGE_BACK_BUFFER          = 1 << (2 + 4),
    DXGI_USAGE_SHARED               = 1 << (3 + 4),
    DXGI_USAGE_READ_ONLY            = 1 << (4 + 4),
    DXGI_USAGE_DISCARD_ON_PRESENT   = 1 << (5 + 4),
    DXGI_USAGE_UNORDERED_ACCESS     = 1 << (6 + 4)
};

struct DXGI_SWAP_CHAIN_DESC {
    DXGI_MODE_DESC BufferDesc;
    DXGI_SAMPLE_DESC SampleDesc;
    uint32_t BufferUsage;
    uint32_t BufferCount;
    void* OutputWindow; // HWND
    int32_t Windowed;   // BOOL
    DXGI_SWAP_EFFECT SwapEffect;
    uint32_t Flags;
};

struct DXGI_ADAPTER_DESC {
    wchar_t Description[128];
    uint32_t VendorId;
    uint32_t DeviceId;
    uint32_t SubSysId;
    uint32_t Revision;
    size_t DedicatedVideoMemory;
    size_t DedicatedSystemMemory;
    size_t SharedSystemMemory;
    LUID AdapterLuid;
};

struct DXGI_ADAPTER_DESC1 {
    wchar_t Description[128];
    uint32_t VendorId;
    uint32_t DeviceId;
    uint32_t SubSysId;
    uint32_t Revision;
    size_t DedicatedVideoMemory;
    size_t DedicatedSystemMemory;
    size_t SharedSystemMemory;
    LUID AdapterLuid;
    uint32_t Flags;
};

struct DXGI_OUTPUT_DESC {
    wchar_t DeviceName[32];
    RECT DesktopCoordinates;
    int32_t AttachedToDesktop;
    uint32_t Rotation;
    void* Monitor; // HMONITOR
};

struct DXGI_FRAME_STATISTICS {
    uint32_t PresentCount;
    uint32_t PresentRefreshCount;
    uint32_t SyncRefreshCount;
    int64_t SyncQPCTime;
    int64_t SyncGPUTime;
};

// ============================================================================
// 2. COM Interface GUIDs
// ============================================================================

using IID = micant::GUID;
using GUID = micant::GUID;

static constexpr IID IID_IUnknown = 
    { 0x00000000, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

static constexpr IID IID_IDXGIObject = 
    { 0xaec22fb8, 0x76f3, 0x4639, { 0x9b, 0xe0, 0x28, 0xeb, 0x43, 0xa6, 0x7a, 0x2e } };

static constexpr IID IID_IDXGIDeviceSubObject = 
    { 0x3d3e0379, 0xd9de, 0x4d58, { 0xbb, 0x6c, 0x18, 0xd4, 0x19, 0x92, 0x9f, 0x6a } };

static constexpr IID IID_IDXGIResource = 
    { 0x035f3ab4, 0x482e, 0x4e50, { 0xb4, 0x1f, 0x8a, 0x7f, 0x8b, 0xd8, 0x96, 0x0b } };

static constexpr IID IID_IDXGISurface = 
    { 0xcafcb56c, 0x6ac3, 0x4889, { 0xbf, 0x47, 0x9e, 0x23, 0xbb, 0xd2, 0x60, 0xec } };

static constexpr IID IID_IDXGIAdapter = 
    { 0x2411e7e1, 0x12ac, 0x4ccf, { 0xbd, 0x14, 0x97, 0x98, 0xe8, 0x53, 0x4d, 0x00 } };

static constexpr IID IID_IDXGIAdapter1 = 
    { 0x29038f61, 0x3839, 0x4626, { 0x91, 0xfd, 0x08, 0x68, 0x79, 0x01, 0x1a, 0x05 } };

static constexpr IID IID_IDXGIOutput = 
    { 0xae02eedb, 0xc735, 0x4690, { 0x8d, 0x52, 0x5a, 0x8d, 0xc2, 0x02, 0x13, 0xaa } };

static constexpr IID IID_IDXGISwapChain = 
    { 0x310d36a0, 0xd0e7, 0x4c40, { 0x90, 0x97, 0x62, 0xe0, 0x39, 0x04, 0xbe, 0x4e } };

static constexpr IID IID_IDXGIFactory = 
    { 0x7b716634, 0x20c7, 0x44ae, { 0xb5, 0x1a, 0x97, 0x43, 0x25, 0x6e, 0x29, 0x78 } };

static constexpr IID IID_IDXGIFactory1 = 
    { 0x770aae78, 0xf26f, 0x4dba, { 0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87 } };

// Forward declarations of COM interfaces
class IUnknown;
class IDXGIObject;
class IDXGIDeviceSubObject;
class IDXGIResource;
class IDXGISurface;
class IDXGIAdapter;
class IDXGIAdapter1;
class IDXGIOutput;
class IDXGISwapChain;
class IDXGIFactory;
class IDXGIFactory1;

// ============================================================================
// 3. COM Interface Base Declarations
// ============================================================================

class IUnknown {
public:
    virtual int32_t QueryInterface(const IID& riid, void** ppvObject) = 0;
    virtual uint32_t AddRef() = 0;
    virtual uint32_t Release() = 0;
    virtual ~IUnknown() = default;
};

class IDXGIObject : public IUnknown {
public:
    virtual int32_t SetPrivateData(const IID& Name, uint32_t DataSize, const void* pData) = 0;
    virtual int32_t SetPrivateDataInterface(const IID& Name, const IUnknown* pUnknown) = 0;
    virtual int32_t GetPrivateData(const IID& Name, uint32_t* pDataSize, void* pData) = 0;
    virtual int32_t GetParent(const IID& riid, void** ppParent) = 0;
};

class IDXGISurface : public IDXGIObject {
public:
    virtual int32_t GetDesc(DXGI_MODE_DESC* pDesc) = 0;
    virtual int32_t Map(void** ppSurfaceData, uint32_t* pPitch) = 0;
    virtual int32_t Unmap() = 0;
};

class IDXGIOutput : public IDXGIObject {
public:
    virtual int32_t GetDesc(DXGI_OUTPUT_DESC* pDesc) = 0;
    virtual int32_t GetDisplayModeList(DXGI_FORMAT EnumFormat, uint32_t Flags, uint32_t* pNumModes, DXGI_MODE_DESC* pDesc) = 0;
    virtual int32_t FindClosestMatchingMode(const DXGI_MODE_DESC* pModeToMatch, DXGI_MODE_DESC* pClosestMatch, IUnknown* pConcernedDevice) = 0;
    virtual int32_t WaitForVBlank() = 0;
    virtual int32_t TakeOwnership(IUnknown* pDevice, int32_t Exclusive) = 0;
    virtual void ReleaseOwnership() = 0;
};

class IDXGIAdapter : public IDXGIObject {
public:
    virtual int32_t EnumOutputs(uint32_t Output, IDXGIOutput** ppOutput) = 0;
    virtual int32_t GetDesc(DXGI_ADAPTER_DESC* pDesc) = 0;
    virtual int32_t CheckInterfaceSupport(const IID& InterfaceName, int64_t* pUMDVersion) = 0;
};

class IDXGIAdapter1 : public IDXGIAdapter {
public:
    virtual int32_t GetDesc1(DXGI_ADAPTER_DESC1* pDesc) = 0;
};

class IDXGISwapChain : public IDXGIObject {
public:
    virtual int32_t Present(uint32_t SyncInterval, uint32_t Flags) = 0;
    virtual int32_t GetBuffer(uint32_t Buffer, const IID& riid, void** ppSurface) = 0;
    virtual int32_t SetFullscreenState(int32_t Fullscreen, IDXGIOutput* pTarget) = 0;
    virtual int32_t GetFullscreenState(int32_t* pFullscreen, IDXGIOutput** ppTarget) = 0;
    virtual int32_t GetDesc(DXGI_SWAP_CHAIN_DESC* pDesc) = 0;
    virtual int32_t ResizeBuffers(uint32_t BufferCount, uint32_t Width, uint32_t Height, DXGI_FORMAT NewFormat, uint32_t SwapChainFlags) = 0;
    virtual int32_t ResizeTarget(const DXGI_MODE_DESC* pNewTargetParameters) = 0;
    virtual int32_t GetContainingOutput(IDXGIOutput** ppOutput) = 0;
    virtual int32_t GetFrameStatistics(DXGI_FRAME_STATISTICS* pStats) = 0;
    virtual int32_t GetLastPresentCount(uint32_t* pLastPresentCount) = 0;
};

class IDXGIFactory : public IDXGIObject {
public:
    virtual int32_t EnumAdapters(uint32_t Adapter, IDXGIAdapter** ppAdapter) = 0;
    virtual int32_t MakeWindowAssociation(void* WindowHandle, uint32_t Flags) = 0;
    virtual int32_t GetWindowAssociation(void** pWindowHandle) = 0;
    virtual int32_t CreateSwapChain(IUnknown* pDevice, DXGI_SWAP_CHAIN_DESC* pDesc, IDXGISwapChain** ppSwapChain) = 0;
    virtual int32_t CreateSoftwareAdapter(void* Module, IDXGIAdapter** ppAdapter) = 0;
};

class IDXGIFactory1 : public IDXGIFactory {
public:
    virtual int32_t EnumAdapters1(uint32_t Adapter, IDXGIAdapter1** ppAdapter) = 0;
    virtual int32_t IsCurrent() = 0;
};

// ============================================================================
// 4. PrismX Concrete Implementation Classes
// ============================================================================

// Memory Back-Buffer Surface for SwapChains
class PrismXSurfaceImpl : public IDXGISurface {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    DXGI_MODE_DESC m_desc{};
    std::vector<uint8_t> m_pixelData;
    uint32_t m_pitch{ 0 };
    bool m_isMapped{ false };

public:
    PrismXSurfaceImpl(uint32_t width, uint32_t height, DXGI_FORMAT format) {
        m_desc.Width = width;
        m_desc.Height = height;
        m_desc.Format = format;
        m_desc.RefreshRate = { 60, 1 };
        m_desc.ScanlineOrdering = DXGI_MODE_SCANLINE_ORDER_PROGRESSIVE;
        m_desc.Scaling = DXGI_MODE_SCALING_UNSPECIFIED;

        // Calculate pitch (32-bpp BGRA = 4 bytes per pixel)
        m_pitch = width * 4;
        m_pixelData.resize(static_cast<size_t>(m_pitch) * height, 0);
    }

    uint8_t* GetRawData() { return m_pixelData.data(); }
    size_t GetDataSize() const { return m_pixelData.size(); }
    uint32_t GetWidth() const { return m_desc.Width; }
    uint32_t GetHeight() const { return m_desc.Height; }
    uint32_t GetPitch() const { return m_pitch; }

    // IUnknown
    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_IDXGIObject || riid == IID_IDXGISurface) {
            *ppvObject = static_cast<IDXGISurface*>(this);
            AddRef();
            return 0; // S_OK
        }
        *ppvObject = nullptr;
        return -2147467262; // E_NOINTERFACE (0x80004002)
    }

    uint32_t AddRef() override {
        return ++m_refCount;
    }

    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    // IDXGIObject
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t GetParent(const IID&, void**) override { return 0; }

    // IDXGISurface
    int32_t GetDesc(DXGI_MODE_DESC* pDesc) override {
        if (!pDesc) return -1;
        *pDesc = m_desc;
        return 0;
    }

    int32_t Map(void** ppSurfaceData, uint32_t* pPitch) override {
        if (!ppSurfaceData || !pPitch) return -1;
        *ppSurfaceData = m_pixelData.data();
        *pPitch = m_pitch;
        m_isMapped = true;
        return 0;
    }

    int32_t Unmap() override {
        m_isMapped = false;
        return 0;
    }
};

// Display Output Monitor
class PrismXOutputImpl : public IDXGIOutput {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    DXGI_OUTPUT_DESC m_desc{};

public:
    PrismXOutputImpl(const std::wstring& name, int32_t width, int32_t height) {
        std::memset(&m_desc, 0, sizeof(m_desc));
        std::wcsncpy(m_desc.DeviceName, name.c_str(), 31);
        m_desc.DesktopCoordinates = { 0, 0, width, height };
        m_desc.AttachedToDesktop = 1;
        m_desc.Rotation = 0;
        m_desc.Monitor = reinterpret_cast<void*>(0x10001);
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_IDXGIObject || riid == IID_IDXGIOutput) {
            *ppvObject = static_cast<IDXGIOutput*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262; // E_NOINTERFACE
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t GetParent(const IID&, void**) override { return 0; }

    int32_t GetDesc(DXGI_OUTPUT_DESC* pDesc) override {
        if (!pDesc) return -1;
        *pDesc = m_desc;
        return 0;
    }

    int32_t GetDisplayModeList(DXGI_FORMAT, uint32_t, uint32_t* pNumModes, DXGI_MODE_DESC* pDesc) override {
        if (!pNumModes) return -1;
        if (!pDesc) {
            *pNumModes = 3;
            return 0;
        }
        // Return 3 standard modes: 1920x1080, 1280x720, 1024x768
        pDesc[0] = { 1920, 1080, { 60, 1 }, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_MODE_SCANLINE_ORDER_PROGRESSIVE, DXGI_MODE_SCALING_UNSPECIFIED };
        pDesc[1] = { 1280, 720, { 60, 1 }, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_MODE_SCANLINE_ORDER_PROGRESSIVE, DXGI_MODE_SCALING_UNSPECIFIED };
        pDesc[2] = { 1024, 768, { 60, 1 }, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_MODE_SCANLINE_ORDER_PROGRESSIVE, DXGI_MODE_SCALING_UNSPECIFIED };
        *pNumModes = 3;
        return 0;
    }

    int32_t FindClosestMatchingMode(const DXGI_MODE_DESC* pModeToMatch, DXGI_MODE_DESC* pClosestMatch, IUnknown*) override {
        if (!pModeToMatch || !pClosestMatch) return -1;
        *pClosestMatch = *pModeToMatch;
        return 0;
    }

    int32_t WaitForVBlank() override {
        return 0; // Immediate VBlank acknowledgement
    }

    int32_t TakeOwnership(IUnknown*, int32_t) override { return 0; }
    void ReleaseOwnership() override {}
};

// Graphics Adapter (Physical / Virtual GPU)
class PrismXAdapterImpl : public IDXGIAdapter1 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    DXGI_ADAPTER_DESC1 m_desc{};
    std::vector<IDXGIOutput*> m_outputs;

public:
    PrismXAdapterImpl(const std::wstring& name, uint32_t vendorId, uint32_t deviceId, size_t vramBytes, bool isSoftware = false) {
        std::memset(&m_desc, 0, sizeof(m_desc));
        std::wcsncpy(m_desc.Description, name.c_str(), 127);
        m_desc.VendorId = vendorId;
        m_desc.DeviceId = deviceId;
        m_desc.SubSysId = 0x0001;
        m_desc.Revision = 0x01;
        m_desc.DedicatedVideoMemory = vramBytes;
        m_desc.DedicatedSystemMemory = 256 * 1024 * 1024; // 256MB
        m_desc.SharedSystemMemory = 1024 * 1024 * 1024;   // 1GB
        m_desc.AdapterLuid = { 0x00000001, 0x00000000 };
        m_desc.Flags = isSoftware ? 2 /* DXGI_ADAPTER_FLAG_SOFTWARE */ : 0;

        // Default connected display
        m_outputs.push_back(new PrismXOutputImpl(L"\\\\.\\DISPLAY1", 1920, 1080));
    }

    ~PrismXAdapterImpl() override {
        for (auto* out : m_outputs) {
            out->Release();
        }
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_IDXGIObject || riid == IID_IDXGIAdapter || riid == IID_IDXGIAdapter1) {
            *ppvObject = static_cast<IDXGIAdapter1*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262; // E_NOINTERFACE
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t GetParent(const IID&, void**) override { return 0; }

    int32_t EnumOutputs(uint32_t Output, IDXGIOutput** ppOutput) override {
        if (!ppOutput) return -1;
        if (Output >= m_outputs.size()) return -2005270526; // DXGI_ERROR_NOT_FOUND (0x887A0002)
        *ppOutput = m_outputs[Output];
        (*ppOutput)->AddRef();
        return 0;
    }

    int32_t GetDesc(DXGI_ADAPTER_DESC* pDesc) override {
        if (!pDesc) return -1;
        std::wcsncpy(pDesc->Description, m_desc.Description, 128);
        pDesc->VendorId = m_desc.VendorId;
        pDesc->DeviceId = m_desc.DeviceId;
        pDesc->SubSysId = m_desc.SubSysId;
        pDesc->Revision = m_desc.Revision;
        pDesc->DedicatedVideoMemory = m_desc.DedicatedVideoMemory;
        pDesc->DedicatedSystemMemory = m_desc.DedicatedSystemMemory;
        pDesc->SharedSystemMemory = m_desc.SharedSystemMemory;
        pDesc->AdapterLuid = m_desc.AdapterLuid;
        return 0;
    }

    int32_t GetDesc1(DXGI_ADAPTER_DESC1* pDesc) override {
        if (!pDesc) return -1;
        *pDesc = m_desc;
        return 0;
    }

    int32_t CheckInterfaceSupport(const IID&, int64_t* pUMDVersion) override {
        if (pUMDVersion) *pUMDVersion = 0x00010000;
        return 0;
    }
};

// Presentation SwapChain
class PrismXSwapChainImpl : public IDXGISwapChain {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    DXGI_SWAP_CHAIN_DESC m_desc{};
    std::vector<PrismXSurfaceImpl*> m_backBuffers;
    uint32_t m_currentBackBuffer{ 0 };
    uint32_t m_presentCount{ 0 };
    int32_t m_isFullscreen{ 0 };
    std::function<void(const uint8_t*, uint32_t, uint32_t, uint32_t)> m_presentCallback;

public:
    PrismXSwapChainImpl(const DXGI_SWAP_CHAIN_DESC& desc, std::function<void(const uint8_t*, uint32_t, uint32_t, uint32_t)> callback = nullptr)
        : m_desc(desc), m_presentCallback(callback) {
        uint32_t bufferCount = (desc.BufferCount == 0) ? 1 : desc.BufferCount;
        for (uint32_t i = 0; i < bufferCount; ++i) {
            m_backBuffers.push_back(new PrismXSurfaceImpl(desc.BufferDesc.Width, desc.BufferDesc.Height, desc.BufferDesc.Format));
        }
    }

    ~PrismXSwapChainImpl() override {
        for (auto* buf : m_backBuffers) {
            buf->Release();
        }
    }

    PrismXSurfaceImpl* GetActiveBackBuffer() {
        if (m_backBuffers.empty()) return nullptr;
        return m_backBuffers[m_currentBackBuffer];
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_IDXGIObject || riid == IID_IDXGISwapChain) {
            *ppvObject = static_cast<IDXGISwapChain*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262; // E_NOINTERFACE
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t GetParent(const IID&, void**) override { return 0; }

    using WindowPresenterFn = void(*)(void* hwnd, const uint8_t* pData, uint32_t width, uint32_t height, uint32_t pitch);

    static WindowPresenterFn& GetGlobalWindowPresenter() noexcept {
        static WindowPresenterFn s_presenter = nullptr;
        return s_presenter;
    }

    static void SetGlobalWindowPresenter(WindowPresenterFn fn) noexcept {
        GetGlobalWindowPresenter() = fn;
    }

    int32_t Present(uint32_t /*SyncInterval*/, uint32_t /*Flags*/) override {
        if (m_backBuffers.empty()) return -1;

        auto* currentBuffer = m_backBuffers[m_currentBackBuffer];
        m_presentCount++;

        // 1. Dispatch frame to presenter callback (e.g. UEFI GOP blitter or Conhost)
        if (m_presentCallback && currentBuffer) {
            m_presentCallback(currentBuffer->GetRawData(),
                              currentBuffer->GetWidth(),
                              currentBuffer->GetHeight(),
                              currentBuffer->GetPitch());
        }

        // 2. Dispatch to registered Window Manager if OutputWindow (HWND) is bound
        if (m_desc.OutputWindow && currentBuffer) {
            auto wp = GetGlobalWindowPresenter();
            if (wp) {
                wp(m_desc.OutputWindow,
                   currentBuffer->GetRawData(),
                   currentBuffer->GetWidth(),
                   currentBuffer->GetHeight(),
                   currentBuffer->GetPitch());
            }
        }

        // Advance swapchain buffer index for flip models
        if (m_desc.SwapEffect == DXGI_SWAP_EFFECT_FLIP_DISCARD ||
            m_desc.SwapEffect == DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL) {
            m_currentBackBuffer = (m_currentBackBuffer + 1) % static_cast<uint32_t>(m_backBuffers.size());
        }
        return 0; // S_OK
    }

    int32_t GetBuffer(uint32_t Buffer, const IID& riid, void** ppSurface) override {
        if (!ppSurface) return -1;
        if (Buffer >= m_backBuffers.size()) return -2005270526; // DXGI_ERROR_NOT_FOUND
        return m_backBuffers[Buffer]->QueryInterface(riid, ppSurface);
    }

    int32_t SetFullscreenState(int32_t Fullscreen, IDXGIOutput*) override {
        m_isFullscreen = Fullscreen;
        return 0;
    }

    int32_t GetFullscreenState(int32_t* pFullscreen, IDXGIOutput** ppTarget) override {
        if (pFullscreen) *pFullscreen = m_isFullscreen;
        if (ppTarget) *ppTarget = nullptr;
        return 0;
    }

    int32_t GetDesc(DXGI_SWAP_CHAIN_DESC* pDesc) override {
        if (!pDesc) return -1;
        *pDesc = m_desc;
        return 0;
    }

    int32_t ResizeBuffers(uint32_t BufferCount, uint32_t Width, uint32_t Height, DXGI_FORMAT NewFormat, uint32_t SwapChainFlags) override {
        for (auto* buf : m_backBuffers) {
            buf->Release();
        }
        m_backBuffers.clear();

        m_desc.BufferCount = (BufferCount == 0) ? m_desc.BufferCount : BufferCount;
        m_desc.BufferDesc.Width = (Width == 0) ? m_desc.BufferDesc.Width : Width;
        m_desc.BufferDesc.Height = (Height == 0) ? m_desc.BufferDesc.Height : Height;
        if (NewFormat != DXGI_FORMAT_UNKNOWN) m_desc.BufferDesc.Format = NewFormat;
        m_desc.Flags = SwapChainFlags;

        for (uint32_t i = 0; i < m_desc.BufferCount; ++i) {
            m_backBuffers.push_back(new PrismXSurfaceImpl(m_desc.BufferDesc.Width, m_desc.BufferDesc.Height, m_desc.BufferDesc.Format));
        }
        m_currentBackBuffer = 0;
        return 0;
    }

    int32_t ResizeTarget(const DXGI_MODE_DESC* pNewTargetParameters) override {
        if (!pNewTargetParameters) return -1;
        m_desc.BufferDesc = *pNewTargetParameters;
        return 0;
    }

    int32_t GetContainingOutput(IDXGIOutput** ppOutput) override {
        if (!ppOutput) return -1;
        *ppOutput = new PrismXOutputImpl(L"\\\\.\\DISPLAY1", m_desc.BufferDesc.Width, m_desc.BufferDesc.Height);
        return 0;
    }

    int32_t GetFrameStatistics(DXGI_FRAME_STATISTICS* pStats) override {
        if (!pStats) return -1;
        pStats->PresentCount = m_presentCount;
        pStats->PresentRefreshCount = m_presentCount;
        pStats->SyncRefreshCount = m_presentCount;
        pStats->SyncQPCTime = m_presentCount * 16666; // ~60fps (16.6ms)
        pStats->SyncGPUTime = m_presentCount * 16666;
        return 0;
    }

    int32_t GetLastPresentCount(uint32_t* pLastPresentCount) override {
        if (!pLastPresentCount) return -1;
        *pLastPresentCount = m_presentCount;
        return 0;
    }
};

// DXGI Factory
class PrismXFactoryImpl : public IDXGIFactory1 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<IDXGIAdapter1*> m_adapters;
    void* m_associatedWindow{ nullptr };

public:
    PrismXFactoryImpl() {
        // Adapter 0: PrismX Hardware Discrete GPU (e.g. VirtIO-GPU / Native PCIe)
        m_adapters.push_back(new PrismXAdapterImpl(L"PrismX DEC PRISM-64 Advanced Graphics Accelerator", 0x1414 /* MS/Mica */, 0x0088, 4ULL * 1024 * 1024 * 1024 /* 4GB VRAM */, false));
        // Adapter 1: PrismX Warp Reference Software Rasterizer
        m_adapters.push_back(new PrismXAdapterImpl(L"PrismX High-Precision Software Rasterizer (Warp/CPU)", 0x1414, 0x0089, 512ULL * 1024 * 1024 /* 512MB */, true));
    }

    ~PrismXFactoryImpl() override {
        for (auto* adp : m_adapters) {
            adp->Release();
        }
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_IDXGIObject || riid == IID_IDXGIFactory || riid == IID_IDXGIFactory1) {
            *ppvObject = static_cast<IDXGIFactory1*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262; // E_NOINTERFACE
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t GetParent(const IID&, void**) override { return 0; }

    int32_t EnumAdapters(uint32_t Adapter, IDXGIAdapter** ppAdapter) override {
        if (!ppAdapter) return -1;
        if (Adapter >= m_adapters.size()) return -2005270526; // DXGI_ERROR_NOT_FOUND
        *ppAdapter = m_adapters[Adapter];
        (*ppAdapter)->AddRef();
        return 0;
    }

    int32_t EnumAdapters1(uint32_t Adapter, IDXGIAdapter1** ppAdapter) override {
        if (!ppAdapter) return -1;
        if (Adapter >= m_adapters.size()) return -2005270526; // DXGI_ERROR_NOT_FOUND
        *ppAdapter = m_adapters[Adapter];
        (*ppAdapter)->AddRef();
        return 0;
    }

    int32_t MakeWindowAssociation(void* WindowHandle, uint32_t) override {
        m_associatedWindow = WindowHandle;
        return 0;
    }

    int32_t GetWindowAssociation(void** pWindowHandle) override {
        if (!pWindowHandle) return -1;
        *pWindowHandle = m_associatedWindow;
        return 0;
    }

    int32_t CreateSwapChain(IUnknown*, DXGI_SWAP_CHAIN_DESC* pDesc, IDXGISwapChain** ppSwapChain) override {
        if (!pDesc || !ppSwapChain) return -1;
        *ppSwapChain = new PrismXSwapChainImpl(*pDesc);
        return 0;
    }

    int32_t CreateSoftwareAdapter(void*, IDXGIAdapter** ppAdapter) override {
        if (!ppAdapter) return -1;
        *ppAdapter = new PrismXAdapterImpl(L"PrismX Custom User-Mode Software Adapter", 0x1414, 0x0090, 256 * 1024 * 1024, true);
        return 0;
    }

    int32_t IsCurrent() override {
        return 1; // TRUE
    }
};

// ============================================================================
// 5. Standard Exported C API Functions (dxgi.dll parity)
// ============================================================================

inline int32_t CreateDXGIFactory(const IID& riid, void** ppFactory) {
    if (!ppFactory) return -1;
    auto* factory = new PrismXFactoryImpl();
    int32_t hr = factory->QueryInterface(riid, ppFactory);
    factory->Release();
    return hr;
}

inline int32_t CreateDXGIFactory1(const IID& riid, void** ppFactory) {
    return CreateDXGIFactory(riid, ppFactory);
}

} // namespace micant::prismx
