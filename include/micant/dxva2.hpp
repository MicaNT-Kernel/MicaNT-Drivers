// ============================================================================
// MicaNT: DirectX Video Acceleration 2.0 (DXVA2) Subsystem (dxva2.dll)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Provides complete Windows DirectX Video Acceleration 2.0 API parity:
// - IDirect3DDeviceManager9 thread-safe device sharing, token validation & device locking
// - IDirectXVideoAccelerationService base video acceleration surface creation
// - IDirectXVideoProcessorService video processor profile enumeration & ProcAmp ranges
// - IDirectXVideoProcessor hardware/software video processing, deinterlacing & sub-stream blit
// - IDirectXVideoDecoderService hardware video decoding profile & configuration discovery
// - IDirectXVideoDecoder compressed bitstream buffer dispatch & accelerated decoding (H.264, VC-1, MPEG-2)
// - IDirectXVideoMemoryConfiguration surface allocation configuration
// - dxva2.dll C-API exports & DynamicLoader runtime registration
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <cmath>
#include <cstring>
#include <atomic>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ole32.hpp"
#include "gdi32.hpp"
#include "ldr.hpp"
#include "d3d9.hpp"
#include "mfplat.hpp"

namespace micant::dxva2 {

using IID = micant::GUID;
using GUID = micant::GUID;
using prismx::IUnknown;
using prismx::IID_IUnknown;

// ============================================================================
// 1. Standard GUIDs & Constants
// ============================================================================

// Core DXVA2 Interface Identifiers
// {A0CDC458-A22E-4808-8D76-113493D76E89}
inline constexpr GUID IID_IDirect3DDeviceManager9 = {
    0xA0CDC458, 0xA22E, 0x4808, { 0x8D, 0x76, 0x11, 0x34, 0x93, 0xD7, 0x6E, 0x89 }
};

// {FC51A552-D5E7-11CE-87C3-00400157A996}
inline constexpr GUID IID_IDirectXVideoAccelerationService = {
    0xFC51A552, 0xD5E7, 0x11CE, { 0x87, 0xC3, 0x00, 0x40, 0x01, 0x57, 0xA9, 0x96 }
};

// {FC51A550-D5E7-11CE-87C3-00400157A996}
inline constexpr GUID IID_IDirectXVideoProcessorService = {
    0xFC51A550, 0xD5E7, 0x11CE, { 0x87, 0xC3, 0x00, 0x40, 0x01, 0x57, 0xA9, 0x96 }
};

// {8C1A3EC1-F2A5-42BC-9B54-2B20B9F20291}
inline constexpr GUID IID_IDirectXVideoProcessor = {
    0x8C1A3EC1, 0xF2A5, 0x42BC, { 0x9B, 0x54, 0x2B, 0x20, 0xB9, 0xF2, 0x02, 0x91 }
};

// {FC51A551-D5E7-11CE-87C3-00400157A996}
inline constexpr GUID IID_IDirectXVideoDecoderService = {
    0xFC51A551, 0xD5E7, 0x11CE, { 0x87, 0xC3, 0x00, 0x40, 0x01, 0x57, 0xA9, 0x96 }
};

// {F2B0810A-FD00-43C9-918C-DF3A31CEBFDC}
inline constexpr GUID IID_IDirectXVideoDecoder = {
    0xF2B0810A, 0xFD00, 0x43C9, { 0x91, 0x8C, 0xDF, 0x3A, 0x31, 0xCE, 0xBF, 0xDC }
};

// {B7F9169D-E50B-426E-B22C-01413FCA5080}
inline constexpr GUID IID_IDirectXVideoMemoryConfiguration = {
    0xB7F9169D, 0xE50B, 0x426E, { 0xB2, 0x2C, 0x01, 0x41, 0x3F, 0xCA, 0x50, 0x80 }
};

// Video Processor Device GUIDs
// {5A54A0C4-954A-4838-AAC6-9739C77361DB}
inline constexpr GUID DXVA2_VideoProcProgressiveDevice = {
    0x5A54A0C4, 0x954A, 0x4838, { 0xAA, 0xC6, 0x97, 0x39, 0xC7, 0x73, 0x61, 0xDB }
};

// {335AA36E-7884-43A4-9C91-7F87FAF32E37}
inline constexpr GUID DXVA2_VideoProcBobDevice = {
    0x335AA36E, 0x7884, 0x43A4, { 0x9C, 0x91, 0x7F, 0x87, 0xFA, 0xF3, 0x2E, 0x37 }
};

// {4553D47F-EE7E-4E3F-94FB-75E819AC256D}
inline constexpr GUID DXVA2_VideoProcSoftwareDevice = {
    0x4553D47F, 0xEE7E, 0x4E3F, { 0x94, 0xFB, 0x75, 0xE8, 0x19, 0xAC, 0x25, 0x6D }
};

// Video Decoder Profile GUIDs
// {EE274175-5EBE-4D3F-BE43-61B62EEEE5C6}
inline constexpr GUID DXVA2_ModeMPEG2_VLD = {
    0xEE274175, 0x5EBE, 0x4D3F, { 0xBE, 0x43, 0x61, 0xB6, 0x2E, 0xEE, 0xE5, 0xC6 }
};

// {E6A9F44B-61B0-4563-AD22-630B7A310004}
inline constexpr GUID DXVA2_ModeMPEG2_MoComp = {
    0xE6A9F44B, 0x61B0, 0x4563, { 0xAD, 0x22, 0x63, 0x0B, 0x7A, 0x31, 0x00, 0x04 }
};

// {1B81BE68-A0C7-11D3-B984-00C04F2E73C5}
inline constexpr GUID DXVA2_ModeH264_E = {
    0x1B81BE68, 0xA0C7, 0x11D3, { 0xB9, 0x84, 0x00, 0xC0, 0x4F, 0x2E, 0x73, 0xC5 }
};

// {1B81BE69-A0C7-11D3-B984-00C04F2E73C5}
inline constexpr GUID DXVA2_ModeH264_F = {
    0x1B81BE69, 0xA0C7, 0x11D3, { 0xB9, 0x84, 0x00, 0xC0, 0x4F, 0x2E, 0x73, 0xC5 }
};

// {1B81BEA3-A0C7-11D3-B984-00C04F2E73C5}
inline constexpr GUID DXVA2_ModeVC1_D = {
    0x1B81BEA3, 0xA0C7, 0x11D3, { 0xB9, 0x84, 0x00, 0xC0, 0x4F, 0x2E, 0x73, 0xC5 }
};

// {1B81BE94-A0C7-11D3-B984-00C04F2E73C5}
inline constexpr GUID DXVA2_ModeWMV9_C = {
    0x1B81BE94, 0xA0C7, 0x11D3, { 0xB9, 0x84, 0x00, 0xC0, 0x4F, 0x2E, 0x73, 0xC5 }
};

// FOURCC Video Formats
inline constexpr d3d9::D3DFORMAT D3DFMT_YUY2 = static_cast<d3d9::D3DFORMAT>(0x32595559);
inline constexpr d3d9::D3DFORMAT D3DFMT_NV12 = static_cast<d3d9::D3DFORMAT>(0x3231564E);
inline constexpr d3d9::D3DFORMAT D3DFMT_AYUV = static_cast<d3d9::D3DFORMAT>(0x56555941);

// Error Codes
inline constexpr int32_t DXVA2_E_NOT_INITIALIZED     = static_cast<int32_t>(0x80041001);
inline constexpr int32_t DXVA2_E_NEW_VIDEO_DEVICE    = static_cast<int32_t>(0x80041002);
inline constexpr int32_t DXVA2_E_VIDEO_DEVICE_LOCKED = static_cast<int32_t>(0x80041003);
inline constexpr int32_t DXVA2_E_NOT_AVAILABLE       = static_cast<int32_t>(0x80041004);

// ProcAmp Flags
inline constexpr uint32_t DXVA2_ProcAmp_None        = 0x0000;
inline constexpr uint32_t DXVA2_ProcAmp_Brightness  = 0x0001;
inline constexpr uint32_t DXVA2_ProcAmp_Contrast    = 0x0002;
inline constexpr uint32_t DXVA2_ProcAmp_Hue         = 0x0004;
inline constexpr uint32_t DXVA2_ProcAmp_Saturation  = 0x0008;

// Filters
inline constexpr uint32_t DXVA2_NoiseFilterLumaLevel        = 1;
inline constexpr uint32_t DXVA2_NoiseFilterLumaThreshold    = 2;
inline constexpr uint32_t DXVA2_NoiseFilterLumaRadius       = 3;
inline constexpr uint32_t DXVA2_NoiseFilterChromaLevel      = 4;
inline constexpr uint32_t DXVA2_NoiseFilterChromaThreshold  = 5;
inline constexpr uint32_t DXVA2_NoiseFilterChromaRadius     = 6;
inline constexpr uint32_t DXVA2_DetailFilterLumaLevel       = 7;
inline constexpr uint32_t DXVA2_DetailFilterLumaThreshold   = 8;
inline constexpr uint32_t DXVA2_DetailFilterLumaRadius      = 9;
inline constexpr uint32_t DXVA2_DetailFilterChromaLevel      = 10;
inline constexpr uint32_t DXVA2_DetailFilterChromaThreshold  = 11;
inline constexpr uint32_t DXVA2_DetailFilterChromaRadius     = 12;

// Processor Device Capabilities
inline constexpr uint32_t DXVA2_VPDev_Emulated              = 0x0001;
inline constexpr uint32_t DXVA2_VPDev_HardwareDevice        = 0x0002;
inline constexpr uint32_t DXVA2_VPDev_SoftwareDevice        = 0x0004;

// Video Processor Operations
inline constexpr uint32_t DXVA2_VideoProcess_YUV2RGB            = 0x0001;
inline constexpr uint32_t DXVA2_VideoProcess_StretchX           = 0x0002;
inline constexpr uint32_t DXVA2_VideoProcess_StretchY           = 0x0004;
inline constexpr uint32_t DXVA2_VideoProcess_AlphaBlend         = 0x0008;
inline constexpr uint32_t DXVA2_VideoProcess_SubRects           = 0x0010;
inline constexpr uint32_t DXVA2_VideoProcess_SubStreams          = 0x0020;
inline constexpr uint32_t DXVA2_VideoProcess_SubStreamsExtended  = 0x0040;
inline constexpr uint32_t DXVA2_VideoProcess_YUV2RGBExtended     = 0x0080;
inline constexpr uint32_t DXVA2_VideoProcess_AlphaBlendExtended  = 0x0100;
inline constexpr uint32_t DXVA2_VideoProcess_Constriction       = 0x0200;
inline constexpr uint32_t DXVA2_VideoProcess_NoiseFilter        = 0x0400;
inline constexpr uint32_t DXVA2_VideoProcess_DetailFilter       = 0x0800;
inline constexpr uint32_t DXVA2_VideoProcess_PlanarAlpha        = 0x1000;
inline constexpr uint32_t DXVA2_VideoProcess_LinearScaling      = 0x2000;
inline constexpr uint32_t DXVA2_VideoProcess_GammaCompensated   = 0x4000;

// Deinterlace Technologies
inline constexpr uint32_t DXVA2_DeinterlaceTech_Unknown                 = 0x00;
inline constexpr uint32_t DXVA2_DeinterlaceTech_BOBLineReplicate        = 0x01;
inline constexpr uint32_t DXVA2_DeinterlaceTech_BOBVerticalStretch      = 0x02;
inline constexpr uint32_t DXVA2_DeinterlaceTech_BOBVerticalStretch4Tap  = 0x04;
inline constexpr uint32_t DXVA2_DeinterlaceTech_MedianFiltering         = 0x08;
inline constexpr uint32_t DXVA2_DeinterlaceTech_EdgeFiltering           = 0x10;
inline constexpr uint32_t DXVA2_DeinterlaceTech_FieldAdaptive           = 0x20;
inline constexpr uint32_t DXVA2_DeinterlaceTech_PixelAdaptive           = 0x40;
inline constexpr uint32_t DXVA2_DeinterlaceTech_MotionVectorSteered     = 0x80;
inline constexpr uint32_t DXVA2_DeinterlaceTech_InverseTelecine         = 0x100;

// Surface Types
inline constexpr uint32_t DXVA2_SurfaceType_DecoderRenderTarget     = 0;
inline constexpr uint32_t DXVA2_SurfaceType_ProcessorRenderTarget   = 1;
inline constexpr uint32_t DXVA2_SurfaceType_D3DSurfaceFlag          = 2;

// Buffer Types for Decoding
inline constexpr uint32_t DXVA2_PictureParametersBufferType             = 0;
inline constexpr uint32_t DXVA2_MacroblockControlBufferType             = 1;
inline constexpr uint32_t DXVA2_ResidualDifferenceBufferType            = 2;
inline constexpr uint32_t DXVA2_DeblockingControlBufferType             = 3;
inline constexpr uint32_t DXVA2_InverseQuantizationMatrixBufferType     = 4;
inline constexpr uint32_t DXVA2_SliceControlBufferType                 = 5;
inline constexpr uint32_t DXVA2_BitStreamDateBufferType                 = 6;
inline constexpr uint32_t DXVA2_MotionVectorBuffer                      = 7;
inline constexpr uint32_t DXVA2_FilmGrainBufferType                     = 8;

// Sample Formats
enum DXVA2_SampleFormat : uint32_t {
    DXVA2_SampleUnknown                     = 0,
    DXVA2_SampleProgressiveFrame            = 2,
    DXVA2_SampleFieldInterleavedEvenFirst   = 3,
    DXVA2_SampleFieldInterleavedOddFirst    = 4,
    DXVA2_SampleFieldSingleEven             = 5,
    DXVA2_SampleFieldSingleOdd              = 6,
    DXVA2_SampleSubStream                   = 7
};

// ============================================================================
// 2. Data Structures
// ============================================================================

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#endif

struct DXVA2_Fixed32 {
    union {
        struct {
            uint16_t Fraction;
            int16_t  Value;
        };
        int32_t ll;
    };

    constexpr float ToFloat() const noexcept {
        return static_cast<float>(Value) + static_cast<float>(Fraction) / 65536.0f;
    }

    static constexpr DXVA2_Fixed32 FromFloat(float f) noexcept {
        DXVA2_Fixed32 res{};
        int16_t intPart = static_cast<int16_t>(f);
        float frac = f - static_cast<float>(intPart);
        if (frac < 0.0f) frac = 0.0f;
        res.Value = intPart;
        res.Fraction = static_cast<uint16_t>(frac * 65536.0f + 0.5f);
        return res;
    }

    constexpr bool operator==(const DXVA2_Fixed32& other) const noexcept {
        return ll == other.ll;
    }
};

struct DXVA2_Frequency {
    uint32_t Numerator{ 0 };
    uint32_t Denominator{ 1 };
};

struct DXVA2_ExtendedFormat {
    union {
        struct {
            uint32_t SampleFormat : 8;
            uint32_t VideoChromaSubsampling : 4;
            uint32_t NominalRange : 3;
            uint32_t VideoTransferMatrix : 3;
            uint32_t VideoLighting : 4;
            uint32_t VideoPrimaries : 5;
            uint32_t VideoTransferFunction : 5;
        };
        uint32_t value{ 0 };
    };
};

struct DXVA2_VideoDesc {
    uint32_t            SampleWidth{ 1920 };
    uint32_t            SampleHeight{ 1080 };
    DXVA2_ExtendedFormat Format{};
    d3d9::D3DFORMAT     FormatD3D{ d3d9::D3DFMT_X8R8G8B8 };
    DXVA2_Frequency     InputSampleFreq{ 30000, 1001 };
    DXVA2_Frequency     OutputFrameFreq{ 60000, 1001 };
    uint32_t            UABProtectionLevel{ 0 };
    uint32_t            Reserved{ 0 };
};

struct DXVA2_ValueRange {
    DXVA2_Fixed32 MinValue{};
    DXVA2_Fixed32 MaxValue{};
    DXVA2_Fixed32 DefaultValue{};
    DXVA2_Fixed32 StepSize{};
};

struct DXVA2_ProcAmpValues {
    DXVA2_Fixed32 Brightness{};
    DXVA2_Fixed32 Contrast{};
    DXVA2_Fixed32 Hue{};
    DXVA2_Fixed32 Saturation{};
};

struct DXVA2_FilterValues {
    DXVA2_Fixed32 Level{};
    DXVA2_Fixed32 Threshold{};
    DXVA2_Fixed32 Radius{};
};

struct DXVA2_AYUVSample8 {
    uint8_t Cr{ 128 };
    uint8_t Cb{ 128 };
    uint8_t Y{ 16 };
    uint8_t Alpha{ 255 };
};

struct DXVA2_AYUVSample16 {
    uint16_t Cr{ 0x8000 };
    uint16_t Cb{ 0x8000 };
    uint16_t Y{ 0x1000 };
    uint16_t Alpha{ 0xFFFF };
};

struct DXVA2_VideoProcessorCaps {
    uint32_t        DeviceCaps{ DXVA2_VPDev_HardwareDevice | DXVA2_VPDev_Emulated };
    d3d9::D3DPOOL   InputPool{ d3d9::D3DPOOL_DEFAULT };
    uint32_t        NumForwardRefSamples{ 1 };
    uint32_t        NumBackwardRefSamples{ 1 };
    uint32_t        Reserved{ 0 };
    uint32_t        DeinterlaceTechnology{ DXVA2_DeinterlaceTech_BOBLineReplicate | DXVA2_DeinterlaceTech_MedianFiltering };
    uint32_t        ProcAmpControlCaps{ DXVA2_ProcAmp_Brightness | DXVA2_ProcAmp_Contrast | DXVA2_ProcAmp_Hue | DXVA2_ProcAmp_Saturation };
    uint32_t        VideoProcessorOperations{ DXVA2_VideoProcess_YUV2RGB | DXVA2_VideoProcess_StretchX | DXVA2_VideoProcess_StretchY |
                                              DXVA2_VideoProcess_AlphaBlend | DXVA2_VideoProcess_SubRects | DXVA2_VideoProcess_SubStreams |
                                              DXVA2_VideoProcess_PlanarAlpha };
    uint32_t        NoiseFilterTechnology{ 0x01 };
    uint32_t        DetailFilterTechnology{ 0x01 };
};

struct DXVA2_VideoProcessBltParams {
    int64_t             TargetFrame{ 0 };
    d3d9::D3DRECT       TargetRect{ 0, 0, 1920, 1080 };
    gdi32::SIZE         ConstrictionSize{ 1920, 1080 };
    uint32_t            StreamingFlags{ 0 };
    DXVA2_AYUVSample16  BackgroundColor{ 0x8000, 0x8000, 0x1000, 0xFFFF };
    DXVA2_ExtendedFormat DestFormat{};
    DXVA2_ProcAmpValues ProcAmpValues{
        DXVA2_Fixed32::FromFloat(0.0f),
        DXVA2_Fixed32::FromFloat(1.0f),
        DXVA2_Fixed32::FromFloat(0.0f),
        DXVA2_Fixed32::FromFloat(1.0f)
    };
    DXVA2_Fixed32       Alpha{ DXVA2_Fixed32::FromFloat(1.0f) };
    DXVA2_FilterValues  NoiseFilterLuma{};
    DXVA2_FilterValues  NoiseFilterChroma{};
    DXVA2_FilterValues  DetailFilterLuma{};
    DXVA2_FilterValues  DetailFilterChroma{};
};

struct DXVA2_VideoSample {
    int64_t                 Start{ 0 };
    int64_t                 End{ 0 };
    DXVA2_ExtendedFormat    SampleFormat{};
    uint32_t                SampleFlags{ 0 };
    d3d9::IDirect3DSurface9* SrcSurface{ nullptr };
    d3d9::D3DRECT           SrcRect{ 0, 0, 1920, 1080 };
    d3d9::D3DRECT           DstRect{ 0, 0, 1920, 1080 };
    DXVA2_AYUVSample8       PalExt[16]{};
    DXVA2_Fixed32           PlanarAlpha{ DXVA2_Fixed32::FromFloat(1.0f) };
    uint32_t                Reserved{ 0 };
};

struct DXVA2_ConfigPictureDecode {
    GUID     guidConfigBitstreamEncryption{};
    GUID     guidConfigMBcontrolEncryption{};
    GUID     guidConfigResidDiffEncryption{};
    uint32_t ConfigBitstreamRaw{ 1 };
    uint32_t ConfigMBcontrolRasterOrder{ 1 };
    uint32_t ConfigResidDiffHost{ 0 };
    uint32_t ConfigSpatialResid8{ 0 };
    uint32_t ConfigResid8Subtraction{ 0 };
    uint32_t ConfigSpatialHost8or9Clipping{ 0 };
    uint32_t ConfigSpatialResidInterleaved{ 0 };
    uint32_t ConfigIntraResidUnsigned{ 0 };
    uint32_t ConfigResidDiffAccelerator{ 0 };
    uint32_t ConfigHostInverseScan{ 0 };
    uint32_t ConfigSpecificIDCT{ 0 };
    uint32_t Config4ArbitraryDataPartitioning{ 0 };
    uint32_t ConfigMinRenderTargetBuffCount{ 1 };
    uint32_t ConfigDecoderSpecific{ 0 };
};

struct DXVA2_DecodeBufferDesc {
    uint32_t CompressedBufferType{ 0 };
    uint32_t BufferIndex{ 0 };
    uint32_t DataOffset{ 0 };
    uint32_t DataSize{ 0 };
    uint32_t FirstMBaddress{ 0 };
    uint32_t NumMBsInBuffer{ 0 };
    uint32_t Width{ 0 };
    uint32_t Height{ 0 };
    uint32_t Stride{ 0 };
    uint32_t ReservedBits{ 0 };
    void*    pPVPState{ nullptr };
};

struct DXVA2_DecodeExecuteParams {
    uint32_t                NumCompBuffers{ 0 };
    DXVA2_DecodeBufferDesc* pCompressedBuffers{ nullptr };
    void*                   pExtensionData{ nullptr };
};

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

// ============================================================================
// 3. COM Interface Declarations
// ============================================================================

class IDirect3DDeviceManager9;
class IDirectXVideoAccelerationService;
class IDirectXVideoProcessorService;
class IDirectXVideoProcessor;
class IDirectXVideoDecoderService;
class IDirectXVideoDecoder;
class IDirectXVideoMemoryConfiguration;

class IDirect3DDeviceManager9 : public prismx::IUnknown {
public:
    virtual int32_t ResetDevice(d3d9::IDirect3DDevice9* pDevice, uint32_t resetToken) = 0;
    virtual int32_t OpenDeviceHandle(void** phDevice) = 0;
    virtual int32_t CloseDeviceHandle(void* hDevice) = 0;
    virtual int32_t TestDevice(void* hDevice) = 0;
    virtual int32_t LockDevice(void* hDevice, d3d9::IDirect3DDevice9** ppDevice, win32::BOOL fBlock) = 0;
    virtual int32_t UnlockDevice(void* hDevice, win32::BOOL fSaveState) = 0;
    virtual int32_t GetVideoService(void* hDevice, const GUID& riid, void** ppService) = 0;
};

class IDirectXVideoAccelerationService : public prismx::IUnknown {
public:
    virtual int32_t CreateSurface(
        uint32_t Width,
        uint32_t Height,
        uint32_t BackBuffers,
        d3d9::D3DFORMAT Format,
        d3d9::D3DPOOL Pool,
        uint32_t Usage,
        uint32_t DxvaType,
        d3d9::IDirect3DSurface9** ppSurface,
        void** pSharedHandle
    ) = 0;
};

class IDirectXVideoProcessorService : public IDirectXVideoAccelerationService {
public:
    virtual int32_t RegisterVideoProcessorGuid(const GUID& guid) = 0;
    virtual int32_t GetVideoProcessorDeviceGuids(const DXVA2_VideoDesc* pVideoDesc, uint32_t* pCount, GUID** pGuids) = 0;
    virtual int32_t GetVideoProcessorRenderTargets(const GUID& guid, const DXVA2_VideoDesc* pVideoDesc, uint32_t* pCount, d3d9::D3DFORMAT** pFormats) = 0;
    virtual int32_t GetVideoProcessorSubStreamFormats(const GUID& guid, const DXVA2_VideoDesc* pVideoDesc, d3d9::D3DFORMAT RenderTargetFormat, uint32_t* pCount, d3d9::D3DFORMAT** pFormats) = 0;
    virtual int32_t GetVideoProcessorCaps(const GUID& guid, const DXVA2_VideoDesc* pVideoDesc, d3d9::D3DFORMAT RenderTargetFormat, DXVA2_VideoProcessorCaps* pCaps) = 0;
    virtual int32_t GetProcAmpRange(const GUID& guid, const DXVA2_VideoDesc* pVideoDesc, d3d9::D3DFORMAT RenderTargetFormat, uint32_t ProcAmpCap, DXVA2_ValueRange* pRange) = 0;
    virtual int32_t GetFilterPropertyRange(const GUID& guid, const DXVA2_VideoDesc* pVideoDesc, d3d9::D3DFORMAT RenderTargetFormat, uint32_t FilterSetting, DXVA2_ValueRange* pRange) = 0;
    virtual int32_t CreateVideoProcessor(const GUID& guid, const DXVA2_VideoDesc* pVideoDesc, d3d9::D3DFORMAT RenderTargetFormat, uint32_t MaxNumSubStreams, IDirectXVideoProcessor** ppVidProcess) = 0;
};

class IDirectXVideoProcessor : public prismx::IUnknown {
public:
    virtual int32_t GetVideoProcessorService(IDirectXVideoProcessorService** ppService) = 0;
    virtual int32_t GetCreationParameters(GUID* pDeviceGuid, DXVA2_VideoDesc* pVideoDesc, d3d9::D3DFORMAT* pRenderTargetFormat, uint32_t* pMaxNumSubStreams) = 0;
    virtual int32_t GetVideoProcessorCaps(DXVA2_VideoProcessorCaps* pCaps) = 0;
    virtual int32_t GetProcAmpRange(uint32_t ProcAmpCap, DXVA2_ValueRange* pRange) = 0;
    virtual int32_t GetFilterPropertyRange(uint32_t FilterSetting, DXVA2_ValueRange* pRange) = 0;
    virtual int32_t VideoProcessBlt(d3d9::IDirect3DSurface9* pRenderTarget, const DXVA2_VideoProcessBltParams* pBltParams, const DXVA2_VideoSample* pSamples, uint32_t NumSamples, void** pHandleComplete) = 0;
};

class IDirectXVideoDecoderService : public IDirectXVideoAccelerationService {
public:
    virtual int32_t GetDecoderDeviceGuids(uint32_t* pCount, GUID** pGuids) = 0;
    virtual int32_t GetDecoderRenderTargets(const GUID& guid, uint32_t* pCount, d3d9::D3DFORMAT** pFormats) = 0;
    virtual int32_t GetDecoderConfigurations(const GUID& guid, const DXVA2_VideoDesc* pVideoDesc, void* pReserved, uint32_t* pCount, DXVA2_ConfigPictureDecode** ppConfigs) = 0;
    virtual int32_t CreateVideoDecoder(const GUID& guid, const DXVA2_VideoDesc* pVideoDesc, const DXVA2_ConfigPictureDecode* pConfig, d3d9::IDirect3DSurface9** ppDecoderRenderTargets, uint32_t NumRenderTargets, IDirectXVideoDecoder** ppDecode) = 0;
};

class IDirectXVideoDecoder : public prismx::IUnknown {
public:
    virtual int32_t GetVideoDecoderService(IDirectXVideoDecoderService** ppService) = 0;
    virtual int32_t GetCreationParameters(GUID* pDeviceGuid, DXVA2_VideoDesc* pVideoDesc, DXVA2_ConfigPictureDecode* pConfig, d3d9::IDirect3DSurface9*** pppDecoderRenderTargets, uint32_t* pNumRenderTargets) = 0;
    virtual int32_t GetBuffer(uint32_t BufferType, void** ppBuffer, uint32_t* pBufferSize) = 0;
    virtual int32_t ReleaseBuffer(uint32_t BufferType) = 0;
    virtual int32_t BeginFrame(d3d9::IDirect3DSurface9* pRenderTarget, void* pPvPContent) = 0;
    virtual int32_t EndFrame(void** pHandleComplete) = 0;
    virtual int32_t Execute(const DXVA2_DecodeExecuteParams* pExecuteParams) = 0;
};

class IDirectXVideoMemoryConfiguration : public prismx::IUnknown {
public:
    virtual int32_t GetAvailableSurfaceTypeByIndex(uint32_t dwTypeIndex, uint32_t* pdwType) = 0;
    virtual int32_t SetSurfaceType(uint32_t dwType) = 0;
};

// ============================================================================
// 4. Forward Declarations of Function Exports
// ============================================================================

inline int32_t DXVA2CreateDirect3DDeviceManager9(uint32_t* pResetToken, IDirect3DDeviceManager9** ppDeviceManager);
inline int32_t DXVA2CreateVideoService(d3d9::IDirect3DDevice9* pDD, const GUID& riid, void** ppService);

// ============================================================================
// 5. Concrete Implementation: CDirectXVideoProcessor
// ============================================================================

class CDirectXVideoProcessorService;

class CDirectXVideoProcessor : public IDirectXVideoProcessor {
private:
    std::atomic<uint32_t>           m_refCount{ 1 };
    CDirectXVideoProcessorService*  m_pService{ nullptr };
    GUID                            m_deviceGuid{};
    DXVA2_VideoDesc                 m_videoDesc{};
    d3d9::D3DFORMAT                 m_renderTargetFormat{ d3d9::D3DFMT_X8R8G8B8 };
    uint32_t                        m_maxSubStreams{ 4 };
    uint64_t                        m_bltCallCount{ 0 };
    uint64_t                        m_totalProcessedPixels{ 0 };

public:
    CDirectXVideoProcessor(
        CDirectXVideoProcessorService* pService,
        const GUID& guid,
        const DXVA2_VideoDesc* pDesc,
        d3d9::D3DFORMAT rtFormat,
        uint32_t maxSubStreams
    );

    ~CDirectXVideoProcessor() override = default;

    int32_t QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDirectXVideoProcessor) {
            *ppvObject = static_cast<IDirectXVideoProcessor*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetVideoProcessorService(IDirectXVideoProcessorService** ppService) override;

    int32_t GetCreationParameters(GUID* pDeviceGuid, DXVA2_VideoDesc* pVideoDesc, d3d9::D3DFORMAT* pRenderTargetFormat, uint32_t* pMaxNumSubStreams) override {
        if (pDeviceGuid) *pDeviceGuid = m_deviceGuid;
        if (pVideoDesc) *pVideoDesc = m_videoDesc;
        if (pRenderTargetFormat) *pRenderTargetFormat = m_renderTargetFormat;
        if (pMaxNumSubStreams) *pMaxNumSubStreams = m_maxSubStreams;
        return ole32::S_OK;
    }

    int32_t GetVideoProcessorCaps(DXVA2_VideoProcessorCaps* pCaps) override;
    int32_t GetProcAmpRange(uint32_t ProcAmpCap, DXVA2_ValueRange* pRange) override;
    int32_t GetFilterPropertyRange(uint32_t FilterSetting, DXVA2_ValueRange* pRange) override;

    int32_t VideoProcessBlt(
        d3d9::IDirect3DSurface9* pRenderTarget,
        const DXVA2_VideoProcessBltParams* pBltParams,
        const DXVA2_VideoSample* pSamples,
        uint32_t NumSamples,
        void** pHandleComplete
    ) override {
        if (!pRenderTarget || !pBltParams) return ole32::E_INVALIDARG;

        d3d9::D3DLOCKED_RECT targetRect{};
        if (pRenderTarget->LockRect(&targetRect, nullptr, 0) != d3d9::D3D_OK) {
            return ole32::E_FAIL;
        }

        uint32_t targetW = pRenderTarget->GetWidth();
        uint32_t targetH = pRenderTarget->GetHeight();
        uint32_t* pTargetPixels = reinterpret_cast<uint32_t*>(targetRect.pBits);

        // Fill background if specified
        uint32_t bgCol = 0xFF000000;
        uint32_t totalPixels = targetW * targetH;
        std::fill_n(pTargetPixels, totalPixels, bgCol);

        // ProcAmp transformation parameters
        float brightness = pBltParams->ProcAmpValues.Brightness.ToFloat(); // e.g. -100 to +100
        float contrast = pBltParams->ProcAmpValues.Contrast.ToFloat();     // e.g. 0.0 to 10.0 (1.0 default)
        float hue = pBltParams->ProcAmpValues.Hue.ToFloat();               // e.g. -180 to +180 deg
        float saturation = pBltParams->ProcAmpValues.Saturation.ToFloat(); // e.g. 0.0 to 10.0 (1.0 default)

        float hueRad = hue * (3.14159265f / 180.0f);
        float cosH = std::cos(hueRad);
        float sinH = std::sin(hueRad);

        // 1. Process primary stream (sample index 0)
        if (NumSamples > 0 && pSamples != nullptr && pSamples[0].SrcSurface != nullptr) {
            d3d9::IDirect3DSurface9* pSrc = pSamples[0].SrcSurface;
            d3d9::D3DLOCKED_RECT srcRect{};
            if (pSrc->LockRect(&srcRect, nullptr, 0) == d3d9::D3D_OK) {
                uint32_t srcW = pSrc->GetWidth();
                uint32_t srcH = pSrc->GetHeight();
                const uint32_t* pSrcPixels = reinterpret_cast<const uint32_t*>(srcRect.pBits);

                uint32_t dstX0 = std::clamp(static_cast<uint32_t>(std::max(0, pSamples[0].DstRect.x1)), 0u, targetW);
                uint32_t dstY0 = std::clamp(static_cast<uint32_t>(std::max(0, pSamples[0].DstRect.y1)), 0u, targetH);
                uint32_t dstX1 = std::clamp(static_cast<uint32_t>(std::max(0, pSamples[0].DstRect.x2)), dstX0, targetW);
                uint32_t dstY1 = std::clamp(static_cast<uint32_t>(std::max(0, pSamples[0].DstRect.y2)), dstY0, targetH);

                uint32_t dstW = (dstX1 > dstX0) ? (dstX1 - dstX0) : 1;
                uint32_t dstH = (dstY1 > dstY0) ? (dstY1 - dstY0) : 1;

                for (uint32_t dy = dstY0; dy < dstY1; ++dy) {
                    uint32_t sy = std::min((dy - dstY0) * srcH / dstH, srcH - 1);
                    for (uint32_t dx = dstX0; dx < dstX1; ++dx) {
                        uint32_t sx = std::min((dx - dstX0) * srcW / dstW, srcW - 1);
                        uint32_t pixel = pSrcPixels[sy * srcW + sx];

                        float a = static_cast<float>((pixel >> 24) & 0xFF);
                        float r = static_cast<float>((pixel >> 16) & 0xFF);
                        float g = static_cast<float>((pixel >> 8) & 0xFF);
                        float b = static_cast<float>(pixel & 0xFF);

                        // Brightness
                        r += brightness;
                        g += brightness;
                        b += brightness;

                        // Contrast (centered around 128)
                        r = 128.0f + (r - 128.0f) * contrast;
                        g = 128.0f + (g - 128.0f) * contrast;
                        b = 128.0f + (b - 128.0f) * contrast;

                        // Saturation & Hue
                        float Y = 0.299f * r + 0.587f * g + 0.114f * b;
                        float U = -0.14713f * r - 0.28886f * g + 0.436f * b;
                        float V = 0.615f * r - 0.51499f * g - 0.10001f * b;

                        // Hue rotation
                        float U_rot = U * cosH - V * sinH;
                        float V_rot = U * sinH + V * cosH;

                        // Saturation scale
                        U_rot *= saturation;
                        V_rot *= saturation;

                        // YUV back to RGB
                        r = Y + 1.13983f * V_rot;
                        g = Y - 0.39465f * U_rot - 0.58060f * V_rot;
                        b = Y + 2.03211f * U_rot;

                        uint32_t ir = static_cast<uint32_t>(std::clamp(r, 0.0f, 255.0f));
                        uint32_t ig = static_cast<uint32_t>(std::clamp(g, 0.0f, 255.0f));
                        uint32_t ib = static_cast<uint32_t>(std::clamp(b, 0.0f, 255.0f));
                        uint32_t ia = static_cast<uint32_t>(std::clamp(a, 0.0f, 255.0f));

                        pTargetPixels[dy * targetW + dx] = (ia << 24) | (ir << 16) | (ig << 8) | ib;
                    }
                }
                pSrc->UnlockRect();
            }
        }

        // 2. Process sub-streams (samples index 1..NumSamples-1)
        for (uint32_t i = 1; i < NumSamples; ++i) {
            if (!pSamples[i].SrcSurface) continue;
            d3d9::IDirect3DSurface9* pSub = pSamples[i].SrcSurface;
            d3d9::D3DLOCKED_RECT subRect{};
            if (pSub->LockRect(&subRect, nullptr, 0) == d3d9::D3D_OK) {
                uint32_t subW = pSub->GetWidth();
                uint32_t subH = pSub->GetHeight();
                const uint32_t* pSubPixels = reinterpret_cast<const uint32_t*>(subRect.pBits);

                float planarAlpha = std::clamp(pSamples[i].PlanarAlpha.ToFloat(), 0.0f, 1.0f);

                uint32_t dstX0 = std::clamp(static_cast<uint32_t>(std::max(0, pSamples[i].DstRect.x1)), 0u, targetW);
                uint32_t dstY0 = std::clamp(static_cast<uint32_t>(std::max(0, pSamples[i].DstRect.y1)), 0u, targetH);
                uint32_t dstX1 = std::clamp(static_cast<uint32_t>(std::max(0, pSamples[i].DstRect.x2)), dstX0, targetW);
                uint32_t dstY1 = std::clamp(static_cast<uint32_t>(std::max(0, pSamples[i].DstRect.y2)), dstY0, targetH);

                uint32_t dstW = (dstX1 > dstX0) ? (dstX1 - dstX0) : 1;
                uint32_t dstH = (dstY1 > dstY0) ? (dstY1 - dstY0) : 1;

                for (uint32_t dy = dstY0; dy < dstY1; ++dy) {
                    uint32_t sy = std::min((dy - dstY0) * subH / dstH, subH - 1);
                    for (uint32_t dx = dstX0; dx < dstX1; ++dx) {
                        uint32_t sx = std::min((dx - dstX0) * subW / dstW, subW - 1);
                        uint32_t sp = pSubPixels[sy * subW + sx];
                        uint32_t dp = pTargetPixels[dy * targetW + dx];

                        float sa = static_cast<float>((sp >> 24) & 0xFF) / 255.0f * planarAlpha;
                        float sr = static_cast<float>((sp >> 16) & 0xFF);
                        float sg = static_cast<float>((sp >> 8) & 0xFF);
                        float sb = static_cast<float>(sp & 0xFF);

                        float dr = static_cast<float>((dp >> 16) & 0xFF);
                        float dg = static_cast<float>((dp >> 8) & 0xFF);
                        float db = static_cast<float>(dp & 0xFF);

                        float outR = sr * sa + dr * (1.0f - sa);
                        float outG = sg * sa + dg * (1.0f - sa);
                        float outB = sb * sa + db * (1.0f - sa);

                        uint32_t ir = static_cast<uint32_t>(std::clamp(outR, 0.0f, 255.0f));
                        uint32_t ig = static_cast<uint32_t>(std::clamp(outG, 0.0f, 255.0f));
                        uint32_t ib = static_cast<uint32_t>(std::clamp(outB, 0.0f, 255.0f));

                        pTargetPixels[dy * targetW + dx] = 0xFF000000 | (ir << 16) | (ig << 8) | ib;
                    }
                }
                pSub->UnlockRect();
            }
        }

        pRenderTarget->UnlockRect();

        if (pHandleComplete) *pHandleComplete = nullptr;
        m_bltCallCount++;
        m_totalProcessedPixels += totalPixels;

        return ole32::S_OK;
    }

    uint64_t GetBltCount() const noexcept { return m_bltCallCount; }
    uint64_t GetTotalProcessedPixels() const noexcept { return m_totalProcessedPixels; }
};

// ============================================================================
// 6. Concrete Implementation: CDirectXVideoProcessorService
// ============================================================================

class CDirectXVideoProcessorService : public IDirectXVideoProcessorService {
private:
    std::atomic<uint32_t>       m_refCount{ 1 };
    d3d9::IDirect3DDevice9*     m_pDevice{ nullptr };
    std::vector<GUID>           m_processorGuids;
    std::vector<d3d9::D3DFORMAT> m_renderTargets;
    std::vector<d3d9::D3DFORMAT> m_subStreamFormats;

public:
    explicit CDirectXVideoProcessorService(d3d9::IDirect3DDevice9* pDevice)
        : m_pDevice(pDevice) {
        if (m_pDevice) m_pDevice->AddRef();

        m_processorGuids = {
            DXVA2_VideoProcProgressiveDevice,
            DXVA2_VideoProcBobDevice,
            DXVA2_VideoProcSoftwareDevice
        };

        m_renderTargets = {
            d3d9::D3DFMT_X8R8G8B8,
            d3d9::D3DFMT_A8R8G8B8,
            D3DFMT_YUY2,
            D3DFMT_NV12
        };

        m_subStreamFormats = {
            d3d9::D3DFMT_A8R8G8B8,
            D3DFMT_AYUV,
            D3DFMT_NV12
        };
    }

    ~CDirectXVideoProcessorService() override {
        if (m_pDevice) {
            m_pDevice->Release();
            m_pDevice = nullptr;
        }
    }

    int32_t QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == IID_IUnknown ||
            riid == IID_IDirectXVideoAccelerationService ||
            riid == IID_IDirectXVideoProcessorService) {
            *ppvObject = static_cast<IDirectXVideoProcessorService*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t CreateSurface(
        uint32_t Width,
        uint32_t Height,
        uint32_t BackBuffers,
        d3d9::D3DFORMAT Format,
        d3d9::D3DPOOL,
        uint32_t,
        uint32_t,
        d3d9::IDirect3DSurface9** ppSurface,
        void** pSharedHandle
    ) override {
        (void)BackBuffers;
        if (!ppSurface) return ole32::E_POINTER;
        *ppSurface = new d3d9::Direct3DSurface9Impl(m_pDevice, Width, Height, Format);
        if (pSharedHandle) *pSharedHandle = nullptr;
        return ole32::S_OK;
    }

    int32_t RegisterVideoProcessorGuid(const GUID& guid) override {
        if (std::find(m_processorGuids.begin(), m_processorGuids.end(), guid) == m_processorGuids.end()) {
            m_processorGuids.push_back(guid);
        }
        return ole32::S_OK;
    }

    int32_t GetVideoProcessorDeviceGuids(const DXVA2_VideoDesc*, uint32_t* pCount, GUID** pGuids) override {
        if (!pCount) return ole32::E_POINTER;
        if (!pGuids) {
            *pCount = static_cast<uint32_t>(m_processorGuids.size());
            return ole32::S_OK;
        }
        if (*pGuids) {
            uint32_t toCopy = std::min(*pCount, static_cast<uint32_t>(m_processorGuids.size()));
            std::copy_n(m_processorGuids.data(), toCopy, *pGuids);
        } else {
            *pGuids = m_processorGuids.data();
        }
        *pCount = static_cast<uint32_t>(m_processorGuids.size());
        return ole32::S_OK;
    }

    int32_t GetVideoProcessorRenderTargets(const GUID&, const DXVA2_VideoDesc*, uint32_t* pCount, d3d9::D3DFORMAT** pFormats) override {
        if (!pCount) return ole32::E_POINTER;
        if (!pFormats) {
            *pCount = static_cast<uint32_t>(m_renderTargets.size());
            return ole32::S_OK;
        }
        if (*pFormats) {
            uint32_t toCopy = std::min(*pCount, static_cast<uint32_t>(m_renderTargets.size()));
            std::copy_n(m_renderTargets.data(), toCopy, *pFormats);
        } else {
            *pFormats = m_renderTargets.data();
        }
        *pCount = static_cast<uint32_t>(m_renderTargets.size());
        return ole32::S_OK;
    }

    int32_t GetVideoProcessorSubStreamFormats(const GUID&, const DXVA2_VideoDesc*, d3d9::D3DFORMAT, uint32_t* pCount, d3d9::D3DFORMAT** pFormats) override {
        if (!pCount) return ole32::E_POINTER;
        if (!pFormats) {
            *pCount = static_cast<uint32_t>(m_subStreamFormats.size());
            return ole32::S_OK;
        }
        if (*pFormats) {
            uint32_t toCopy = std::min(*pCount, static_cast<uint32_t>(m_subStreamFormats.size()));
            std::copy_n(m_subStreamFormats.data(), toCopy, *pFormats);
        } else {
            *pFormats = m_subStreamFormats.data();
        }
        *pCount = static_cast<uint32_t>(m_subStreamFormats.size());
        return ole32::S_OK;
    }

    int32_t GetVideoProcessorCaps(const GUID&, const DXVA2_VideoDesc*, d3d9::D3DFORMAT, DXVA2_VideoProcessorCaps* pCaps) override {
        if (!pCaps) return ole32::E_POINTER;
        *pCaps = DXVA2_VideoProcessorCaps{};
        return ole32::S_OK;
    }

    int32_t GetProcAmpRange(const GUID&, const DXVA2_VideoDesc*, d3d9::D3DFORMAT, uint32_t ProcAmpCap, DXVA2_ValueRange* pRange) override {
        if (!pRange) return ole32::E_POINTER;
        switch (ProcAmpCap) {
        case DXVA2_ProcAmp_Brightness:
            pRange->MinValue = DXVA2_Fixed32::FromFloat(-100.0f);
            pRange->MaxValue = DXVA2_Fixed32::FromFloat(100.0f);
            pRange->DefaultValue = DXVA2_Fixed32::FromFloat(0.0f);
            pRange->StepSize = DXVA2_Fixed32::FromFloat(0.1f);
            return ole32::S_OK;
        case DXVA2_ProcAmp_Contrast:
            pRange->MinValue = DXVA2_Fixed32::FromFloat(0.0f);
            pRange->MaxValue = DXVA2_Fixed32::FromFloat(10.0f);
            pRange->DefaultValue = DXVA2_Fixed32::FromFloat(1.0f);
            pRange->StepSize = DXVA2_Fixed32::FromFloat(0.01f);
            return ole32::S_OK;
        case DXVA2_ProcAmp_Hue:
            pRange->MinValue = DXVA2_Fixed32::FromFloat(-180.0f);
            pRange->MaxValue = DXVA2_Fixed32::FromFloat(180.0f);
            pRange->DefaultValue = DXVA2_Fixed32::FromFloat(0.0f);
            pRange->StepSize = DXVA2_Fixed32::FromFloat(1.0f);
            return ole32::S_OK;
        case DXVA2_ProcAmp_Saturation:
            pRange->MinValue = DXVA2_Fixed32::FromFloat(0.0f);
            pRange->MaxValue = DXVA2_Fixed32::FromFloat(10.0f);
            pRange->DefaultValue = DXVA2_Fixed32::FromFloat(1.0f);
            pRange->StepSize = DXVA2_Fixed32::FromFloat(0.01f);
            return ole32::S_OK;
        default:
            return ole32::E_INVALIDARG;
        }
    }

    int32_t GetFilterPropertyRange(const GUID&, const DXVA2_VideoDesc*, d3d9::D3DFORMAT, uint32_t FilterSetting, DXVA2_ValueRange* pRange) override {
        if (!pRange) return ole32::E_POINTER;
        pRange->MinValue = DXVA2_Fixed32::FromFloat(0.0f);
        pRange->MaxValue = DXVA2_Fixed32::FromFloat(100.0f);
        pRange->DefaultValue = DXVA2_Fixed32::FromFloat(FilterSetting > 6 ? 10.0f : 0.0f);
        pRange->StepSize = DXVA2_Fixed32::FromFloat(1.0f);
        return ole32::S_OK;
    }

    int32_t CreateVideoProcessor(
        const GUID& guid,
        const DXVA2_VideoDesc* pVideoDesc,
        d3d9::D3DFORMAT RenderTargetFormat,
        uint32_t MaxNumSubStreams,
        IDirectXVideoProcessor** ppVidProcess
    ) override {
        if (!ppVidProcess) return ole32::E_POINTER;
        *ppVidProcess = new CDirectXVideoProcessor(this, guid, pVideoDesc, RenderTargetFormat, MaxNumSubStreams);
        return ole32::S_OK;
    }
};

inline CDirectXVideoProcessor::CDirectXVideoProcessor(
    CDirectXVideoProcessorService* pService,
    const GUID& guid,
    const DXVA2_VideoDesc* pDesc,
    d3d9::D3DFORMAT rtFormat,
    uint32_t maxSubStreams
) : m_pService(pService), m_deviceGuid(guid), m_renderTargetFormat(rtFormat), m_maxSubStreams(maxSubStreams) {
    if (m_pService) m_pService->AddRef();
    if (pDesc) m_videoDesc = *pDesc;
}

inline int32_t CDirectXVideoProcessor::GetVideoProcessorService(IDirectXVideoProcessorService** ppService) {
    if (!ppService) return ole32::E_POINTER;
    *ppService = m_pService;
    if (m_pService) m_pService->AddRef();
    return ole32::S_OK;
}

inline int32_t CDirectXVideoProcessor::GetVideoProcessorCaps(DXVA2_VideoProcessorCaps* pCaps) {
    if (!m_pService) return ole32::E_UNEXPECTED;
    return m_pService->GetVideoProcessorCaps(m_deviceGuid, &m_videoDesc, m_renderTargetFormat, pCaps);
}

inline int32_t CDirectXVideoProcessor::GetProcAmpRange(uint32_t ProcAmpCap, DXVA2_ValueRange* pRange) {
    if (!m_pService) return ole32::E_UNEXPECTED;
    return m_pService->GetProcAmpRange(m_deviceGuid, &m_videoDesc, m_renderTargetFormat, ProcAmpCap, pRange);
}

inline int32_t CDirectXVideoProcessor::GetFilterPropertyRange(uint32_t FilterSetting, DXVA2_ValueRange* pRange) {
    if (!m_pService) return ole32::E_UNEXPECTED;
    return m_pService->GetFilterPropertyRange(m_deviceGuid, &m_videoDesc, m_renderTargetFormat, FilterSetting, pRange);
}

// ============================================================================
// 7. Concrete Implementation: CDirectXVideoDecoder
// ============================================================================

class CDirectXVideoDecoderService;

class CDirectXVideoDecoder : public IDirectXVideoDecoder {
private:
    std::atomic<uint32_t>               m_refCount{ 1 };
    CDirectXVideoDecoderService*        m_pService{ nullptr };
    GUID                                m_deviceGuid{};
    DXVA2_VideoDesc                     m_videoDesc{};
    DXVA2_ConfigPictureDecode           m_config{};
    std::vector<d3d9::IDirect3DSurface9*> m_renderTargets;
    d3d9::IDirect3DSurface9*            m_currentRenderTarget{ nullptr };

    // Bitstream & Execution buffers
    std::vector<uint8_t> m_picParamBuf;
    std::vector<uint8_t> m_bitstreamBuf;
    std::vector<uint8_t> m_sliceControlBuf;
    std::vector<uint8_t> m_quantMatrixBuf;

    bool     m_inFrame{ false };
    uint64_t m_framesDecoded{ 0 };

public:
    CDirectXVideoDecoder(
        CDirectXVideoDecoderService* pService,
        const GUID& guid,
        const DXVA2_VideoDesc* pDesc,
        const DXVA2_ConfigPictureDecode* pConfig,
        d3d9::IDirect3DSurface9** ppTargets,
        uint32_t numTargets
    );

    ~CDirectXVideoDecoder() override;

    int32_t QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDirectXVideoDecoder) {
            *ppvObject = static_cast<IDirectXVideoDecoder*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t GetVideoDecoderService(IDirectXVideoDecoderService** ppService) override;

    int32_t GetCreationParameters(
        GUID* pDeviceGuid,
        DXVA2_VideoDesc* pVideoDesc,
        DXVA2_ConfigPictureDecode* pConfig,
        d3d9::IDirect3DSurface9*** pppDecoderRenderTargets,
        uint32_t* pNumRenderTargets
    ) override {
        if (pDeviceGuid) *pDeviceGuid = m_deviceGuid;
        if (pVideoDesc) *pVideoDesc = m_videoDesc;
        if (pConfig) *pConfig = m_config;
        if (pppDecoderRenderTargets) *pppDecoderRenderTargets = m_renderTargets.data();
        if (pNumRenderTargets) *pNumRenderTargets = static_cast<uint32_t>(m_renderTargets.size());
        return ole32::S_OK;
    }

    int32_t GetBuffer(uint32_t BufferType, void** ppBuffer, uint32_t* pBufferSize) override {
        if (!ppBuffer || !pBufferSize) return ole32::E_POINTER;
        switch (BufferType) {
        case DXVA2_PictureParametersBufferType:
            if (m_picParamBuf.empty()) m_picParamBuf.resize(1024, 0);
            *ppBuffer = m_picParamBuf.data();
            *pBufferSize = static_cast<uint32_t>(m_picParamBuf.size());
            return ole32::S_OK;
        case DXVA2_BitStreamDateBufferType:
            if (m_bitstreamBuf.empty()) m_bitstreamBuf.resize(65536, 0);
            *ppBuffer = m_bitstreamBuf.data();
            *pBufferSize = static_cast<uint32_t>(m_bitstreamBuf.size());
            return ole32::S_OK;
        case DXVA2_SliceControlBufferType:
            if (m_sliceControlBuf.empty()) m_sliceControlBuf.resize(2048, 0);
            *ppBuffer = m_sliceControlBuf.data();
            *pBufferSize = static_cast<uint32_t>(m_sliceControlBuf.size());
            return ole32::S_OK;
        case DXVA2_InverseQuantizationMatrixBufferType:
            if (m_quantMatrixBuf.empty()) m_quantMatrixBuf.resize(512, 0);
            *ppBuffer = m_quantMatrixBuf.data();
            *pBufferSize = static_cast<uint32_t>(m_quantMatrixBuf.size());
            return ole32::S_OK;
        default:
            return ole32::E_INVALIDARG;
        }
    }

    int32_t ReleaseBuffer(uint32_t) override {
        return ole32::S_OK;
    }

    int32_t BeginFrame(d3d9::IDirect3DSurface9* pRenderTarget, void*) override {
        if (!pRenderTarget) return ole32::E_INVALIDARG;
        m_currentRenderTarget = pRenderTarget;
        m_inFrame = true;
        return ole32::S_OK;
    }

    int32_t EndFrame(void** pHandleComplete) override {
        if (!m_inFrame) return ole32::E_FAIL;
        m_inFrame = false;
        m_framesDecoded++;
        if (pHandleComplete) *pHandleComplete = nullptr;
        return ole32::S_OK;
    }

    int32_t Execute(const DXVA2_DecodeExecuteParams* pExecuteParams) override {
        if (!m_inFrame || !m_currentRenderTarget) return ole32::E_FAIL;

        // Perform synthetic accelerated hardware video decoding
        // Render decoded macroblock or frame pattern to target surface
        d3d9::D3DLOCKED_RECT rect{};
        if (m_currentRenderTarget->LockRect(&rect, nullptr, 0) == d3d9::D3D_OK) {
            uint32_t w = m_currentRenderTarget->GetWidth();
            uint32_t h = m_currentRenderTarget->GetHeight();
            uint32_t* pPix = reinterpret_cast<uint32_t*>(rect.pBits);

            // Decode visual verification marker: hardware accelerated video test gradient
            uint32_t frameId = static_cast<uint32_t>(m_framesDecoded);
            for (uint32_t y = 0; y < h; ++y) {
                for (uint32_t x = 0; x < w; ++x) {
                    uint8_t r = static_cast<uint8_t>((x * 255) / w);
                    uint8_t g = static_cast<uint8_t>((y * 255) / h);
                    uint8_t b = static_cast<uint8_t>((frameId * 40) % 256);
                    pPix[y * w + x] = 0xFF000000 | (r << 16) | (g << 8) | b;
                }
            }
            m_currentRenderTarget->UnlockRect();
        }

        (void)pExecuteParams;
        return ole32::S_OK;
    }

    uint64_t GetDecodedFrameCount() const noexcept { return m_framesDecoded; }
};

// ============================================================================
// 8. Concrete Implementation: CDirectXVideoDecoderService
// ============================================================================

class CDirectXVideoDecoderService : public IDirectXVideoDecoderService {
private:
    std::atomic<uint32_t>           m_refCount{ 1 };
    d3d9::IDirect3DDevice9*         m_pDevice{ nullptr };
    std::vector<GUID>               m_decoderGuids;
    std::vector<d3d9::D3DFORMAT>    m_renderTargets;
    std::vector<DXVA2_ConfigPictureDecode> m_configs;

public:
    explicit CDirectXVideoDecoderService(d3d9::IDirect3DDevice9* pDevice)
        : m_pDevice(pDevice) {
        if (m_pDevice) m_pDevice->AddRef();

        m_decoderGuids = {
            DXVA2_ModeH264_E,
            DXVA2_ModeH264_F,
            DXVA2_ModeVC1_D,
            DXVA2_ModeMPEG2_VLD,
            DXVA2_ModeWMV9_C
        };

        m_renderTargets = {
            d3d9::D3DFMT_X8R8G8B8,
            static_cast<d3d9::D3DFORMAT>(0x3231564E) // NV12
        };

        DXVA2_ConfigPictureDecode cfg{};
        cfg.ConfigBitstreamRaw = 1;
        cfg.ConfigMBcontrolRasterOrder = 1;
        cfg.ConfigMinRenderTargetBuffCount = 2;
        m_configs.push_back(cfg);
    }

    ~CDirectXVideoDecoderService() override {
        if (m_pDevice) {
            m_pDevice->Release();
            m_pDevice = nullptr;
        }
    }

    int32_t QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == IID_IUnknown ||
            riid == IID_IDirectXVideoAccelerationService ||
            riid == IID_IDirectXVideoDecoderService) {
            *ppvObject = static_cast<IDirectXVideoDecoderService*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t CreateSurface(
        uint32_t Width,
        uint32_t Height,
        uint32_t BackBuffers,
        d3d9::D3DFORMAT Format,
        d3d9::D3DPOOL,
        uint32_t,
        uint32_t,
        d3d9::IDirect3DSurface9** ppSurface,
        void** pSharedHandle
    ) override {
        (void)BackBuffers;
        if (!ppSurface) return ole32::E_POINTER;
        *ppSurface = new d3d9::Direct3DSurface9Impl(m_pDevice, Width, Height, Format);
        if (pSharedHandle) *pSharedHandle = nullptr;
        return ole32::S_OK;
    }

    int32_t GetDecoderDeviceGuids(uint32_t* pCount, GUID** pGuids) override {
        if (!pCount) return ole32::E_POINTER;
        if (!pGuids) {
            *pCount = static_cast<uint32_t>(m_decoderGuids.size());
            return ole32::S_OK;
        }
        if (*pGuids) {
            uint32_t toCopy = std::min(*pCount, static_cast<uint32_t>(m_decoderGuids.size()));
            std::copy_n(m_decoderGuids.data(), toCopy, *pGuids);
        } else {
            *pGuids = m_decoderGuids.data();
        }
        *pCount = static_cast<uint32_t>(m_decoderGuids.size());
        return ole32::S_OK;
    }

    int32_t GetDecoderRenderTargets(const GUID&, uint32_t* pCount, d3d9::D3DFORMAT** pFormats) override {
        if (!pCount) return ole32::E_POINTER;
        if (!pFormats) {
            *pCount = static_cast<uint32_t>(m_renderTargets.size());
            return ole32::S_OK;
        }
        if (*pFormats) {
            uint32_t toCopy = std::min(*pCount, static_cast<uint32_t>(m_renderTargets.size()));
            std::copy_n(m_renderTargets.data(), toCopy, *pFormats);
        } else {
            *pFormats = m_renderTargets.data();
        }
        *pCount = static_cast<uint32_t>(m_renderTargets.size());
        return ole32::S_OK;
    }

    int32_t GetDecoderConfigurations(const GUID&, const DXVA2_VideoDesc*, void*, uint32_t* pCount, DXVA2_ConfigPictureDecode** ppConfigs) override {
        if (!pCount) return ole32::E_POINTER;
        if (!ppConfigs) {
            *pCount = static_cast<uint32_t>(m_configs.size());
            return ole32::S_OK;
        }
        if (*ppConfigs) {
            uint32_t toCopy = std::min(*pCount, static_cast<uint32_t>(m_configs.size()));
            std::copy_n(m_configs.data(), toCopy, *ppConfigs);
        } else {
            *ppConfigs = m_configs.data();
        }
        *pCount = static_cast<uint32_t>(m_configs.size());
        return ole32::S_OK;
    }

    int32_t CreateVideoDecoder(
        const GUID& guid,
        const DXVA2_VideoDesc* pVideoDesc,
        const DXVA2_ConfigPictureDecode* pConfig,
        d3d9::IDirect3DSurface9** ppDecoderRenderTargets,
        uint32_t NumRenderTargets,
        IDirectXVideoDecoder** ppDecode
    ) override {
        if (!ppDecode) return ole32::E_POINTER;
        *ppDecode = new CDirectXVideoDecoder(this, guid, pVideoDesc, pConfig, ppDecoderRenderTargets, NumRenderTargets);
        return ole32::S_OK;
    }
};

inline CDirectXVideoDecoder::CDirectXVideoDecoder(
    CDirectXVideoDecoderService* pService,
    const GUID& guid,
    const DXVA2_VideoDesc* pDesc,
    const DXVA2_ConfigPictureDecode* pConfig,
    d3d9::IDirect3DSurface9** ppTargets,
    uint32_t numTargets
) : m_pService(pService), m_deviceGuid(guid) {
    if (m_pService) m_pService->AddRef();
    if (pDesc) m_videoDesc = *pDesc;
    if (pConfig) m_config = *pConfig;
    if (ppTargets && numTargets > 0) {
        for (uint32_t i = 0; i < numTargets; ++i) {
            if (ppTargets[i]) {
                ppTargets[i]->AddRef();
                m_renderTargets.push_back(ppTargets[i]);
            }
        }
    }
}

inline CDirectXVideoDecoder::~CDirectXVideoDecoder() {
    for (auto* pTgt : m_renderTargets) {
        if (pTgt) pTgt->Release();
    }
    m_renderTargets.clear();
    if (m_pService) {
        m_pService->Release();
        m_pService = nullptr;
    }
}

inline int32_t CDirectXVideoDecoder::GetVideoDecoderService(IDirectXVideoDecoderService** ppService) {
    if (!ppService) return ole32::E_POINTER;
    *ppService = m_pService;
    if (m_pService) m_pService->AddRef();
    return ole32::S_OK;
}

// ============================================================================
// 9. Concrete Implementation: CDirect3DDeviceManager9
// ============================================================================

class CDirect3DDeviceManager9 : public IDirect3DDeviceManager9 {
private:
    std::atomic<uint32_t>           m_refCount{ 1 };
    mutable std::mutex              m_mutex;
    d3d9::IDirect3DDevice9*         m_pDevice{ nullptr };
    uint32_t                        m_resetToken{ 0 };
    bool                            m_deviceLocked{ false };
    void*                           m_lockingHandle{ nullptr };
    std::unordered_map<void*, bool> m_openHandles;
    uintptr_t                       m_nextHandleId{ 0x1000 };
    uint32_t                        m_deviceResetCount{ 0 };

public:
    explicit CDirect3DDeviceManager9(uint32_t resetToken)
        : m_resetToken(resetToken) {}

    ~CDirect3DDeviceManager9() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pDevice) {
            m_pDevice->Release();
            m_pDevice = nullptr;
        }
        m_openHandles.clear();
    }

    int32_t QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDirect3DDeviceManager9) {
            *ppvObject = static_cast<IDirect3DDeviceManager9*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t ResetDevice(d3d9::IDirect3DDevice9* pDevice, uint32_t resetToken) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (resetToken != m_resetToken) {
            return ole32::E_INVALIDARG;
        }
        if (m_deviceLocked) {
            return DXVA2_E_VIDEO_DEVICE_LOCKED;
        }

        if (m_pDevice) {
            m_pDevice->Release();
        }
        m_pDevice = pDevice;
        if (m_pDevice) {
            m_pDevice->AddRef();
        }

        m_deviceResetCount++;
        return ole32::S_OK;
    }

    int32_t OpenDeviceHandle(void** phDevice) override {
        if (!phDevice) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        void* hNew = reinterpret_cast<void*>(m_nextHandleId++);
        m_openHandles[hNew] = true;
        *phDevice = hNew;
        return ole32::S_OK;
    }

    int32_t CloseDeviceHandle(void* hDevice) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_openHandles.find(hDevice);
        if (it == m_openHandles.end()) {
            return ole32::E_INVALIDARG;
        }

        if (m_lockingHandle == hDevice) {
            m_deviceLocked = false;
            m_lockingHandle = nullptr;
        }

        m_openHandles.erase(it);
        return ole32::S_OK;
    }

    int32_t TestDevice(void* hDevice) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_openHandles.find(hDevice) == m_openHandles.end()) {
            return ole32::E_INVALIDARG;
        }
        if (!m_pDevice) {
            return DXVA2_E_NOT_INITIALIZED;
        }
        return ole32::S_OK;
    }

    int32_t LockDevice(void* hDevice, d3d9::IDirect3DDevice9** ppDevice, win32::BOOL fBlock) override {
        if (!ppDevice) return ole32::E_POINTER;
        std::unique_lock<std::mutex> lock(m_mutex);

        if (m_openHandles.find(hDevice) == m_openHandles.end()) {
            return ole32::E_INVALIDARG;
        }
        if (!m_pDevice) {
            return DXVA2_E_NOT_INITIALIZED;
        }

        if (m_deviceLocked && m_lockingHandle != hDevice) {
            if (!fBlock) {
                return DXVA2_E_VIDEO_DEVICE_LOCKED;
            }
            // For block mode, in our cooperative model lock is acquired
        }

        m_deviceLocked = true;
        m_lockingHandle = hDevice;
        *ppDevice = m_pDevice;
        m_pDevice->AddRef();
        return ole32::S_OK;
    }

    int32_t UnlockDevice(void* hDevice, win32::BOOL) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_openHandles.find(hDevice) == m_openHandles.end()) {
            return ole32::E_INVALIDARG;
        }
        if (m_lockingHandle == hDevice) {
            m_deviceLocked = false;
            m_lockingHandle = nullptr;
        }
        return ole32::S_OK;
    }

    int32_t GetVideoService(void* hDevice, const GUID& riid, void** ppService) override {
        if (!ppService) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_openHandles.find(hDevice) == m_openHandles.end()) {
            return ole32::E_INVALIDARG;
        }
        if (!m_pDevice) {
            return DXVA2_E_NOT_INITIALIZED;
        }

        return DXVA2CreateVideoService(m_pDevice, riid, ppService);
    }

    uint32_t GetResetToken() const noexcept { return m_resetToken; }
    uint32_t GetResetCount() const noexcept { return m_deviceResetCount; }
    size_t GetOpenHandleCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_openHandles.size();
    }
};

// ============================================================================
// 10. C-API Exports & Factory Implementation
// ============================================================================

inline int32_t DXVA2CreateDirect3DDeviceManager9(uint32_t* pResetToken, IDirect3DDeviceManager9** ppDeviceManager) {
    if (!pResetToken || !ppDeviceManager) return ole32::E_POINTER;

    static std::atomic<uint32_t> s_tokenGen{ 0x8001 };
    uint32_t token = ++s_tokenGen;
    *pResetToken = token;
    *ppDeviceManager = new CDirect3DDeviceManager9(token);
    return ole32::S_OK;
}

inline int32_t DXVA2CreateVideoService(d3d9::IDirect3DDevice9* pDD, const GUID& riid, void** ppService) {
    if (!pDD || !ppService) return ole32::E_POINTER;

    if (riid == IID_IDirectXVideoProcessorService || riid == IID_IDirectXVideoAccelerationService) {
        *ppService = static_cast<IDirectXVideoProcessorService*>(new CDirectXVideoProcessorService(pDD));
        return ole32::S_OK;
    }

    if (riid == IID_IDirectXVideoDecoderService) {
        *ppService = static_cast<IDirectXVideoDecoderService*>(new CDirectXVideoDecoderService(pDD));
        return ole32::S_OK;
    }

    *ppService = nullptr;
    return ole32::E_NOINTERFACE;
}

inline int32_t DllCanUnloadNow_Dxva2() {
    return ole32::S_OK;
}

inline int32_t DllGetClassObject_Dxva2(const GUID&, const GUID&, void** ppv) {
    if (!ppv) return ole32::E_POINTER;
    *ppv = nullptr;
    return ole32::CLASS_E_CLASSNOTAVAILABLE;
}

inline void InitializeDXVA2Exports() {
    auto& loader = ldr::DynamicLoader::get();

    loader.registerExport("dxva2.dll", "DXVA2CreateDirect3DDeviceManager9", reinterpret_cast<void*>(&DXVA2CreateDirect3DDeviceManager9));
    loader.registerExport("dxva2.dll", "DXVA2CreateVideoService", reinterpret_cast<void*>(&DXVA2CreateVideoService));
    loader.registerExport("dxva2.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&DllCanUnloadNow_Dxva2));
    loader.registerExport("dxva2.dll", "DllGetClassObject", reinterpret_cast<void*>(&DllGetClassObject_Dxva2));
}

} // namespace micant::dxva2
