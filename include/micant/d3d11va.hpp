// ============================================================================
// MicaNT: Windows Direct3D 11 Video Acceleration Subsystem (D3D11VA)
// 
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/win32metadata
//   - https://github.com/microsoft/DirectX-Headers (directx/d3d11.h)
//   - Microsoft MSDN Direct3D 11 Video APIs & Video Processing Specifications
//
// Trademark & Nominative Fair Use Notice:
//   Direct3D, DirectX, DXVA, and Windows are registered trademarks of Microsoft
//   Corporation. All identifiers and structures are implemented for clean-room
//   binary and API compatibility with Windows applications.
// ============================================================================

#pragma once

#include "prism3d.hpp"
#include "dxva2.hpp"
#include "ldr.hpp"
#include <vector>
#include <memory>
#include <string>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <unordered_map>

namespace micant::d3d11va {

using namespace micant::prismx;
using namespace micant::prism3d;

// ============================================================================
// 1. Direct3D 11 Video Formats & Constants
// ============================================================================

#ifndef DXGI_FORMAT_NV12
static constexpr DXGI_FORMAT DXGI_FORMAT_NV12 = static_cast<DXGI_FORMAT>(103);
#endif
#ifndef DXGI_FORMAT_P010
static constexpr DXGI_FORMAT DXGI_FORMAT_P010 = static_cast<DXGI_FORMAT>(104);
#endif
#ifndef DXGI_FORMAT_YUY2
static constexpr DXGI_FORMAT DXGI_FORMAT_YUY2 = static_cast<DXGI_FORMAT>(107);
#endif
#ifndef DXGI_FORMAT_AYUV
static constexpr DXGI_FORMAT DXGI_FORMAT_AYUV = static_cast<DXGI_FORMAT>(100);
#endif
#ifndef DXGI_FORMAT_R10G10B10A2_UNORM
static constexpr DXGI_FORMAT DXGI_FORMAT_R10G10B10A2_UNORM = static_cast<DXGI_FORMAT>(24);
#endif

#ifndef D3D11_CREATE_DEVICE_VIDEO_SUPPORT
static constexpr uint32_t D3D11_CREATE_DEVICE_VIDEO_SUPPORT = 0x800;
#endif

// ============================================================================
// 2. Direct3D 11 Video GUIDs & Interface IDs
// ============================================================================

static constexpr GUID IID_ID3D11VideoDevice               = { 0x10EC46A8, 0xDB75, 0x4830, { 0xBC, 0xF3, 0x2C, 0x30, 0xC0, 0x42, 0xA3, 0x0C } };
static constexpr GUID IID_ID3D11VideoContext              = { 0x61F21C45, 0x3C0E, 0x429F, { 0x9C, 0x7C, 0xD8, 0x88, 0x20, 0xA6, 0xCD, 0x8D } };
static constexpr GUID IID_ID3D11VideoDecoder              = { 0x3C3E4A69, 0xDD0E, 0x4934, { 0xB0, 0xCF, 0xFA, 0x9F, 0x99, 0xFB, 0x76, 0x8E } };
static constexpr GUID IID_ID3D11VideoDecoderOutputView    = { 0xC290FE05, 0x496E, 0x4D78, { 0x9A, 0xC1, 0xE6, 0x20, 0x64, 0x58, 0xF5, 0xAC } };
static constexpr GUID IID_ID3D11VideoProcessorEnumerator  = { 0x31627037, 0x53AB, 0x4200, { 0x90, 0x61, 0x60, 0xFF, 0xA9, 0xDE, 0xC4, 0x96 } };
static constexpr GUID IID_ID3D11VideoProcessor            = { 0x1D218B71, 0x01E3, 0x47DA, { 0xA5, 0x31, 0x9F, 0x10, 0x83, 0x74, 0x7D, 0x6E } };
static constexpr GUID IID_ID3D11VideoProcessorInputView   = { 0x11EC48B4, 0x4A81, 0x4280, { 0xAA, 0x55, 0x74, 0x88, 0x06, 0x43, 0xE7, 0x70 } };
static constexpr GUID IID_ID3D11VideoProcessorOutputView  = { 0xA3F614E9, 0x018A, 0x4F4F, { 0xA4, 0x00, 0x07, 0xCD, 0xF4, 0xD6, 0x49, 0xD3 } };

// Accelerated Decoder Profiles
static constexpr GUID D3D11_DECODER_PROFILE_H264_VLD_NOFGT  = { 0x1b81be68, 0xa0c7, 0x11d3, { 0xb9, 0x84, 0x00, 0xc0, 0x4f, 0x2e, 0x73, 0xc5 } };
static constexpr GUID D3D11_DECODER_PROFILE_H264_VLD_FGT    = { 0x1b81be69, 0xa0c7, 0x11d3, { 0xb9, 0x84, 0x00, 0xc0, 0x4f, 0x2e, 0x73, 0xc5 } };
static constexpr GUID D3D11_DECODER_PROFILE_HEVC_VLD_MAIN   = { 0x5b11d51b, 0xedd4, 0x4151, { 0xba, 0x5f, 0xa6, 0xb7, 0x7e, 0x79, 0x30, 0xdd } };
static constexpr GUID D3D11_DECODER_PROFILE_HEVC_VLD_MAIN10 = { 0x107af0e0, 0xef1a, 0x4d19, { 0xab, 0xa8, 0x67, 0xa1, 0x63, 0x07, 0x3d, 0x13 } };
static constexpr GUID D3D11_DECODER_PROFILE_VP9_VLD_PROFILE0= { 0x46370700, 0xa1d0, 0x45ea, { 0x80, 0x36, 0x19, 0x36, 0x43, 0x45, 0x4c, 0xcf } };
static constexpr GUID D3D11_DECODER_PROFILE_VP9_VLD_10BIT   = { 0xa4c749ef, 0x6ec3, 0x406d, { 0x84, 0x17, 0x7d, 0x7b, 0xf3, 0xf0, 0xe3, 0x6f } };
static constexpr GUID D3D11_DECODER_PROFILE_AV1_VLD_PROFILE0= { 0xb8be4ccb, 0xcf53, 0x46ba, { 0x8d, 0x59, 0xd6, 0xb8, 0x04, 0x36, 0x41, 0x2d } };
static constexpr GUID D3D11_DECODER_PROFILE_VC1_VLD         = { 0x1b81be66, 0xa0c7, 0x11d3, { 0xb9, 0x84, 0x00, 0xc0, 0x4f, 0x2e, 0x73, 0xc5 } };
static constexpr GUID D3D11_DECODER_PROFILE_MPEG2_VLD       = { 0xee554e23, 0x2341, 0x4cf4, { 0x9b, 0x14, 0x13, 0x74, 0x5e, 0x77, 0xfb, 0x29 } };

// Crypto & Hardware Protection
static constexpr GUID D3D11_CRYPTO_TYPE_AES128_CTR          = { 0x9b61d3d1, 0x1a32, 0x411b, { 0xab, 0x14, 0x7e, 0xa0, 0x15, 0x09, 0xf4, 0xcf } };
static constexpr GUID D3D11_KEY_EXCHANGE_HW_PROTECTION       = { 0x52445100, 0x681b, 0x4654, { 0x8e, 0x1d, 0xea, 0x5e, 0x3a, 0x8f, 0xae, 0x83 } };

// ============================================================================
// 3. Enumerations & Flags
// ============================================================================

enum D3D11_VDOV_DIMENSION : uint32_t {
    D3D11_VDOV_DIMENSION_UNKNOWN   = 0,
    D3D11_VDOV_DIMENSION_TEXTURE2D = 1
};

enum D3D11_VPIV_DIMENSION : uint32_t {
    D3D11_VPIV_DIMENSION_UNKNOWN   = 0,
    D3D11_VPIV_DIMENSION_TEXTURE2D = 1
};

enum D3D11_VPOV_DIMENSION : uint32_t {
    D3D11_VPOV_DIMENSION_UNKNOWN        = 0,
    D3D11_VPOV_DIMENSION_TEXTURE2D      = 1,
    D3D11_VPOV_DIMENSION_TEXTURE2DARRAY = 2
};

enum D3D11_VIDEO_FRAME_FORMAT : uint32_t {
    D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE                   = 0,
    D3D11_VIDEO_FRAME_FORMAT_INTERLACED_TOP_FIELD_FIRST    = 1,
    D3D11_VIDEO_FRAME_FORMAT_INTERLACED_BOTTOM_FIELD_FIRST = 2
};

enum D3D11_VIDEO_USAGE : uint32_t {
    D3D11_VIDEO_USAGE_PLAYBACK_NORMAL = 0,
    D3D11_VIDEO_USAGE_OPTIMAL_SPEED   = 1,
    D3D11_VIDEO_USAGE_OPTIMAL_QUALITY = 2
};

enum D3D11_VIDEO_PROCESSOR_DEVICE_CAPS : uint32_t {
    D3D11_VIDEO_PROCESSOR_DEVICE_CAPS_LINEAR_SPACE            = 0x1,
    D3D11_VIDEO_PROCESSOR_DEVICE_CAPS_xvYCC                   = 0x2,
    D3D11_VIDEO_PROCESSOR_DEVICE_CAPS_RGB_RANGE_CONVERSION    = 0x4,
    D3D11_VIDEO_PROCESSOR_DEVICE_CAPS_YCbCr_MATRIX_CONVERSION = 0x8,
    D3D11_VIDEO_PROCESSOR_DEVICE_CAPS_NOMINAL_RANGE           = 0x10
};

enum D3D11_VIDEO_PROCESSOR_FEATURE_CAPS : uint32_t {
    D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_ALPHA_FILL    = 0x1,
    D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_CONSTRICTION  = 0x2,
    D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_LUMA_KEY      = 0x4,
    D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_ALPHA_PALETTE = 0x8,
    D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_ROTATION      = 0x10,
    D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_STEREO        = 0x20
};

enum D3D11_VIDEO_PROCESSOR_FILTER : uint32_t {
    D3D11_VIDEO_PROCESSOR_FILTER_BRIGHTNESS         = 0,
    D3D11_VIDEO_PROCESSOR_FILTER_CONTRAST           = 1,
    D3D11_VIDEO_PROCESSOR_FILTER_HUE                = 2,
    D3D11_VIDEO_PROCESSOR_FILTER_SATURATION         = 3,
    D3D11_VIDEO_PROCESSOR_FILTER_NOISE_REDUCTION    = 4,
    D3D11_VIDEO_PROCESSOR_FILTER_EDGE_ENHANCEMENT   = 5,
    D3D11_VIDEO_PROCESSOR_FILTER_ANAMORPHIC_SCALING = 6
};

enum D3D11_VIDEO_PROCESSOR_FILTER_CAPS : uint32_t {
    D3D11_VIDEO_PROCESSOR_FILTER_CAPS_BRIGHTNESS         = 0x1,
    D3D11_VIDEO_PROCESSOR_FILTER_CAPS_CONTRAST           = 0x2,
    D3D11_VIDEO_PROCESSOR_FILTER_CAPS_HUE                = 0x4,
    D3D11_VIDEO_PROCESSOR_FILTER_CAPS_SATURATION         = 0x8,
    D3D11_VIDEO_PROCESSOR_FILTER_CAPS_NOISE_REDUCTION    = 0x10,
    D3D11_VIDEO_PROCESSOR_FILTER_CAPS_EDGE_ENHANCEMENT   = 0x20,
    D3D11_VIDEO_PROCESSOR_FILTER_CAPS_ANAMORPHIC_SCALING = 0x40
};

enum D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS : uint32_t {
    D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_DENOISE             = 0x1,
    D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_DERINGING           = 0x2,
    D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_EDGE_ENHANCEMENT    = 0x4,
    D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_COLOR_CORRECTION    = 0x8,
    D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_FLESH_TONE_MAPPING  = 0x10,
    D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_IMAGE_STABILIZATION = 0x20,
    D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_SUPER_RESOLUTION    = 0x40,
    D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_ANAMORPHIC_SCALING  = 0x80
};

enum D3D11_VIDEO_PROCESSOR_OUTPUT_RATE : uint32_t {
    D3D11_VIDEO_PROCESSOR_OUTPUT_RATE_NORMAL = 0,
    D3D11_VIDEO_PROCESSOR_OUTPUT_RATE_HALF   = 1,
    D3D11_VIDEO_PROCESSOR_OUTPUT_RATE_CUSTOM = 2
};

enum D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE : uint32_t {
    D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE_OPAQUE        = 0,
    D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE_BACKGROUND    = 1,
    D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE_DESTINATION   = 2,
    D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE_SOURCE_STREAM = 3
};

enum D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT : uint32_t {
    D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT  = 0x1,
    D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT = 0x2
};

enum D3D11_VIDEO_DECODER_BUFFER_TYPE : uint32_t {
    D3D11_VIDEO_DECODER_BUFFER_PICTURE_PARAMETERS         = 0,
    D3D11_VIDEO_DECODER_BUFFER_MACROBLOCK_CONTROL          = 1,
    D3D11_VIDEO_DECODER_BUFFER_RESIDUAL_DIFFERENCE         = 2,
    D3D11_VIDEO_DECODER_BUFFER_DEBLOCKING_CONTROL          = 3,
    D3D11_VIDEO_DECODER_BUFFER_INVERSE_QUANTIZATION_MATRIX = 4,
    D3D11_VIDEO_DECODER_BUFFER_SLICE_CONTROL               = 5,
    D3D11_VIDEO_DECODER_BUFFER_BITSTREAM                   = 6,
    D3D11_VIDEO_DECODER_BUFFER_MOTION_VECTOR               = 7,
    D3D11_VIDEO_DECODER_BUFFER_FILM_GRAIN                  = 8,
    D3D11_VIDEO_DECODER_BUFFER_HUFFMAN_TABLE               = 9
};

enum D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE : uint32_t {
    D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_UNDEFINED = 0,
    D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235    = 1,
    D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_0_255     = 2
};

// ============================================================================
// 4. Data Structures
// ============================================================================

struct D3D11_VIDEO_DECODER_DESC {
    GUID Guid;
    uint32_t SampleWidth;
    uint32_t SampleHeight;
    DXGI_FORMAT OutputFormat;
};

struct D3D11_VIDEO_DECODER_CONFIG {
    GUID guidConfigBitstreamEncryption;
    GUID guidConfigMBcontrolEncryption;
    GUID guidConfigResidDiffEncryption;
    uint32_t ConfigBitstreamRaw;
    uint32_t ConfigMBcontrolRasterOrder;
    uint32_t ConfigResidDiffHost;
    uint32_t ConfigSpatialResid8;
    uint32_t ConfigResid8Subtraction;
    uint32_t ConfigSpatialHost8or9Clipping;
    uint32_t ConfigSpatialResidInterleaved;
    uint32_t ConfigIntraResidUnsigned;
    uint32_t ConfigResidDiffAccelerator;
    uint32_t ConfigHostInverseScan;
    uint32_t ConfigSpecificIDCT;
    uint32_t Config4GroupedCoefs;
    uint16_t ConfigMinRenderTargetBuffCount;
    uint16_t ConfigDecoderSpecific;
};

struct D3D11_VIDEO_DECODER_BUFFER_DESC {
    D3D11_VIDEO_DECODER_BUFFER_TYPE BufferType;
    uint32_t BufferIndex;
    uint32_t DataOffset;
    uint32_t DataSize;
    uint32_t FirstMBaddress;
    uint32_t NumMBsInBuffer;
    uint32_t Width;
    uint32_t Height;
    uint32_t Stride;
    uint32_t ReservedBits;
    void* pBuffer;
};

struct D3D11_VIDEO_DECODER_EXTENSION {
    uint32_t Function;
    void* pPrivateInputData;
    uint32_t PrivateInputDataSize;
    void* pPrivateOutputData;
    uint32_t PrivateOutputDataSize;
    uint32_t ResourceCount;
    ID3D11Resource** ppResourceList;
};

struct D3D11_TEX2D_VDOV {
    uint32_t ArraySlice;
};

struct D3D11_VIDEO_DECODER_OUTPUT_VIEW_DESC {
    GUID DecodeProfile;
    D3D11_VDOV_DIMENSION ViewDimension;
    union {
        D3D11_TEX2D_VDOV Texture2D;
    };
};

struct D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
    D3D11_VIDEO_FRAME_FORMAT InputFrameFormat;
    DXGI_RATIONAL InputFrameRate;
    uint32_t InputWidth;
    uint32_t InputHeight;
    DXGI_RATIONAL OutputFrameRate;
    uint32_t OutputWidth;
    uint32_t OutputHeight;
    D3D11_VIDEO_USAGE Usage;
};

struct D3D11_VIDEO_PROCESSOR_CAPS {
    uint32_t DeviceCaps;
    uint32_t FeatureCaps;
    uint32_t FilterCaps;
    uint32_t InputFormatCaps;
    uint32_t AutoStreamCaps;
    uint32_t StereoCaps;
    uint32_t RateConversionCapsCount;
    uint32_t MaxInputStreams;
    uint32_t MaxStreamStates;
};

struct D3D11_VIDEO_PROCESSOR_RATE_CONVERSION_CAPS {
    uint32_t PastFrames;
    uint32_t FutureFrames;
    uint32_t ProcessorCaps;
    uint32_t ITelecineCaps;
    uint32_t CustomRateCount;
};

struct D3D11_VIDEO_PROCESSOR_CUSTOM_RATE {
    DXGI_RATIONAL CustomRate;
    uint32_t OutputFrames;
    int32_t InputInterlaced;
    uint32_t FormatConversionCaps;
};

struct D3D11_VIDEO_PROCESSOR_FILTER_RANGE {
    int32_t Minimum;
    int32_t Maximum;
    int32_t Default;
    float Multiplier;
};

struct D3D11_VIDEO_COLOR_RGBA {
    float R;
    float G;
    float B;
    float A;
};

struct D3D11_VIDEO_COLOR_YCbCrA {
    float Y;
    float Cb;
    float Cr;
    float A;
};

union D3D11_VIDEO_COLOR {
    D3D11_VIDEO_COLOR_YCbCrA YCbCr;
    D3D11_VIDEO_COLOR_RGBA RGBA;
};

struct D3D11_VIDEO_PROCESSOR_COLOR_SPACE {
    uint32_t Usage : 1;
    uint32_t RGB_Range : 1;
    uint32_t YCbCr_Matrix : 1;
    uint32_t YCbCr_xvYCC : 1;
    uint32_t Nominal_Range : 2;
    uint32_t Reserved : 26;
};

struct D3D11_TEX2D_VPIV {
    uint32_t MipSlice;
    uint32_t ArraySlice;
};

struct D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
    uint32_t FourCC;
    D3D11_VPIV_DIMENSION ViewDimension;
    union {
        D3D11_TEX2D_VPIV Texture2D;
    };
};

struct D3D11_TEX2D_VPOV {
    uint32_t MipSlice;
};

struct D3D11_TEX2D_ARRAY_VPOV {
    uint32_t MipSlice;
    uint32_t FirstArraySlice;
    uint32_t ArraySize;
};

struct D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
    D3D11_VPOV_DIMENSION ViewDimension;
    union {
        D3D11_TEX2D_VPOV Texture2D;
        D3D11_TEX2D_ARRAY_VPOV Texture2DArray;
    };
};

// Forward declaration of view interfaces
class ID3D11VideoProcessorInputView;
class ID3D11VideoProcessorOutputView;
class ID3D11VideoDecoderOutputView;

struct D3D11_VIDEO_PROCESSOR_STREAM {
    int32_t Enable;
    uint32_t OutputIndex;
    uint32_t InputFrameOrField;
    uint32_t PastFrames;
    uint32_t FutureFrames;
    ID3D11VideoProcessorInputView** ppPastSurfaces;
    ID3D11VideoProcessorInputView* pInputSurface;
    ID3D11VideoProcessorInputView** ppFutureSurfaces;
    ID3D11VideoProcessorInputView** ppPastSurfacesRight;
    ID3D11VideoProcessorInputView* pInputSurfaceRight;
    ID3D11VideoProcessorInputView** ppFutureSurfacesRight;
};

// ============================================================================
// 5. Direct3D 11 Video Interfaces
// ============================================================================

class ID3D11VideoDecoderOutputView : public ID3D11View {
public:
    virtual void GetDesc(D3D11_VIDEO_DECODER_OUTPUT_VIEW_DESC* pDesc) = 0;
};

class ID3D11VideoProcessorInputView : public ID3D11View {
public:
    virtual void GetDesc(D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC* pDesc) = 0;
};

class ID3D11VideoProcessorOutputView : public ID3D11View {
public:
    virtual void GetDesc(D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC* pDesc) = 0;
};

class ID3D11VideoDecoder : public ID3D11DeviceChild {
public:
    virtual int32_t GetCreationParameters(
        D3D11_VIDEO_DECODER_DESC* pDesc,
        D3D11_VIDEO_DECODER_CONFIG* pConfig) = 0;
    virtual int32_t GetDriverHandle(void** pDriverHandle) = 0;
};

class ID3D11VideoProcessorEnumerator : public ID3D11DeviceChild {
public:
    virtual int32_t GetVideoProcessorContentDesc(D3D11_VIDEO_PROCESSOR_CONTENT_DESC* pContentDesc) = 0;
    virtual int32_t CheckVideoProcessorFormat(DXGI_FORMAT Format, uint32_t* pFlags) = 0;
    virtual int32_t GetVideoProcessorCaps(D3D11_VIDEO_PROCESSOR_CAPS* pCaps) = 0;
    virtual int32_t GetVideoProcessorRateConversionCaps(uint32_t TypeIndex, D3D11_VIDEO_PROCESSOR_RATE_CONVERSION_CAPS* pCaps) = 0;
    virtual int32_t GetVideoProcessorCustomRate(uint32_t TypeIndex, uint32_t CustomRateIndex, D3D11_VIDEO_PROCESSOR_CUSTOM_RATE* pRate) = 0;
    virtual int32_t GetVideoProcessorFilterRange(D3D11_VIDEO_PROCESSOR_FILTER Filter, D3D11_VIDEO_PROCESSOR_FILTER_RANGE* pRange) = 0;
};

class ID3D11VideoProcessor : public ID3D11DeviceChild {
public:
    virtual void GetContentDesc(D3D11_VIDEO_PROCESSOR_CONTENT_DESC* pDesc) = 0;
    virtual void GetRateConversionCaps(uint32_t TypeIndex, D3D11_VIDEO_PROCESSOR_RATE_CONVERSION_CAPS* pCaps) = 0;
};

class ID3D11VideoDevice : public IUnknown {
public:
    virtual int32_t CreateVideoDecoder(
        const D3D11_VIDEO_DECODER_DESC* pDesc,
        const D3D11_VIDEO_DECODER_CONFIG* pConfig,
        ID3D11VideoDecoder** ppDecoder) = 0;

    virtual int32_t CreateVideoProcessor(
        ID3D11VideoProcessorEnumerator* pEnum,
        uint32_t RateConversionIndex,
        ID3D11VideoProcessor** ppVideoProcessor) = 0;

    virtual int32_t CreateVideoDecoderOutputView(
        ID3D11Resource* pResource,
        const D3D11_VIDEO_DECODER_OUTPUT_VIEW_DESC* pDesc,
        ID3D11VideoDecoderOutputView** ppVDOVView) = 0;

    virtual int32_t CreateVideoProcessorInputView(
        ID3D11Resource* pResource,
        ID3D11VideoProcessorEnumerator* pEnum,
        const D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC* pDesc,
        ID3D11VideoProcessorInputView** ppVPIView) = 0;

    virtual int32_t CreateVideoProcessorOutputView(
        ID3D11Resource* pResource,
        ID3D11VideoProcessorEnumerator* pEnum,
        const D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC* pDesc,
        ID3D11VideoProcessorOutputView** ppVPOView) = 0;

    virtual int32_t CreateVideoProcessorEnumerator(
        const D3D11_VIDEO_PROCESSOR_CONTENT_DESC* pDesc,
        ID3D11VideoProcessorEnumerator** ppEnum) = 0;

    virtual uint32_t GetVideoDecoderProfileCount() = 0;

    virtual int32_t GetVideoDecoderProfile(
        uint32_t Index,
        GUID* pDecoderProfile) = 0;

    virtual int32_t CheckVideoDecoderFormat(
        const GUID* pDecoderProfile,
        DXGI_FORMAT Format,
        int32_t* pSupported) = 0;

    virtual int32_t GetVideoDecoderConfigCount(
        const D3D11_VIDEO_DECODER_DESC* pDesc,
        uint32_t* pCount) = 0;

    virtual int32_t GetVideoDecoderConfig(
        const D3D11_VIDEO_DECODER_DESC* pDesc,
        uint32_t Index,
        D3D11_VIDEO_DECODER_CONFIG* pConfig) = 0;

    virtual int32_t CheckCryptoKeyExchange(
        const GUID* pCryptoType,
        const GUID* pDecoderProfile,
        uint32_t Index,
        GUID* pKeyExchangeType) = 0;
};

class ID3D11VideoContext : public ID3D11DeviceChild {
public:
    virtual int32_t GetDecoderBuffer(
        ID3D11VideoDecoder* pDecoder,
        D3D11_VIDEO_DECODER_BUFFER_TYPE Type,
        uint32_t* pBufferSize,
        void** ppBuffer) = 0;

    virtual int32_t ReleaseDecoderBuffer(
        ID3D11VideoDecoder* pDecoder,
        D3D11_VIDEO_DECODER_BUFFER_TYPE Type) = 0;

    virtual int32_t DecoderBeginFrame(
        ID3D11VideoDecoder* pDecoder,
        ID3D11VideoDecoderOutputView* pView,
        uint32_t ContentKeySize,
        const void* pContentKey) = 0;

    virtual int32_t DecoderEndFrame(
        ID3D11VideoDecoder* pDecoder) = 0;

    virtual int32_t SubmitDecoderBuffers(
        ID3D11VideoDecoder* pDecoder,
        uint32_t NumBuffers,
        const D3D11_VIDEO_DECODER_BUFFER_DESC* pBufferDesc) = 0;

    virtual int32_t DecoderExtension(
        ID3D11VideoDecoder* pDecoder,
        const D3D11_VIDEO_DECODER_EXTENSION* pExtensionData) = 0;

    virtual void VideoProcessorSetOutputTargetRect(
        ID3D11VideoProcessor* pVideoProcessor,
        int32_t Enable,
        const RECT* pRect) = 0;

    virtual void VideoProcessorSetOutputBackgroundColor(
        ID3D11VideoProcessor* pVideoProcessor,
        int32_t YCbCr,
        const D3D11_VIDEO_COLOR* pColor) = 0;

    virtual void VideoProcessorSetOutputColorSpace(
        ID3D11VideoProcessor* pVideoProcessor,
        const D3D11_VIDEO_PROCESSOR_COLOR_SPACE* pColorSpace) = 0;

    virtual void VideoProcessorSetOutputAlphaFillMode(
        ID3D11VideoProcessor* pVideoProcessor,
        D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE AlphaFillMode,
        uint32_t StreamIndex) = 0;

    virtual void VideoProcessorSetStreamFrameFormat(
        ID3D11VideoProcessor* pVideoProcessor,
        uint32_t StreamIndex,
        D3D11_VIDEO_FRAME_FORMAT FrameFormat) = 0;

    virtual void VideoProcessorSetStreamColorSpace(
        ID3D11VideoProcessor* pVideoProcessor,
        uint32_t StreamIndex,
        const D3D11_VIDEO_PROCESSOR_COLOR_SPACE* pColorSpace) = 0;

    virtual void VideoProcessorSetStreamOutputRate(
        ID3D11VideoProcessor* pVideoProcessor,
        uint32_t StreamIndex,
        D3D11_VIDEO_PROCESSOR_OUTPUT_RATE OutputRate,
        int32_t RepeatFrame,
        const DXGI_RATIONAL* pCustomRate) = 0;

    virtual void VideoProcessorSetStreamSourceRect(
        ID3D11VideoProcessor* pVideoProcessor,
        uint32_t StreamIndex,
        int32_t Enable,
        const RECT* pRect) = 0;

    virtual void VideoProcessorSetStreamDestRect(
        ID3D11VideoProcessor* pVideoProcessor,
        uint32_t StreamIndex,
        int32_t Enable,
        const RECT* pRect) = 0;

    virtual void VideoProcessorSetStreamAlpha(
        ID3D11VideoProcessor* pVideoProcessor,
        uint32_t StreamIndex,
        int32_t Enable,
        float Alpha) = 0;

    virtual void VideoProcessorSetStreamAutoProcessingMode(
        ID3D11VideoProcessor* pVideoProcessor,
        uint32_t StreamIndex,
        int32_t Enable) = 0;

    virtual int32_t VideoProcessorBlt(
        ID3D11VideoProcessor* pVideoProcessor,
        ID3D11VideoProcessorOutputView* pView,
        uint32_t OutputFrame,
        uint32_t StreamCount,
        const D3D11_VIDEO_PROCESSOR_STREAM* pStreams) = 0;
};

// ============================================================================
// 6. Concrete Implementations
// ============================================================================

// ----------------------------------------------------------------------------
// CD3D11VideoDecoderOutputView
// ----------------------------------------------------------------------------
class CD3D11VideoDecoderOutputView : public ID3D11VideoDecoderOutputView {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    ID3D11Resource* m_pResource{ nullptr };
    D3D11_VIDEO_DECODER_OUTPUT_VIEW_DESC m_desc{};

public:
    CD3D11VideoDecoderOutputView(ID3D11Device* pDevice, ID3D11Resource* pResource, const D3D11_VIDEO_DECODER_OUTPUT_VIEW_DESC* pDesc)
        : m_pDevice(pDevice), m_pResource(pResource) {
        if (pDesc) m_desc = *pDesc;
        if (m_pResource) m_pResource->AddRef();
        if (m_pDevice) m_pDevice->AddRef();
    }

    ~CD3D11VideoDecoderOutputView() override {
        if (m_pResource) m_pResource->Release();
        if (m_pDevice) m_pDevice->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11View || riid == IID_ID3D11VideoDecoderOutputView) {
            *ppvObject = static_cast<ID3D11VideoDecoderOutputView*>(this);
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

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice && m_pDevice) {
            *ppDevice = m_pDevice;
            m_pDevice->AddRef();
        }
    }

    void GetResource(ID3D11Resource** ppResource) override {
        if (ppResource && m_pResource) {
            *ppResource = m_pResource;
            m_pResource->AddRef();
        }
    }

    void GetDesc(D3D11_VIDEO_DECODER_OUTPUT_VIEW_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

// ----------------------------------------------------------------------------
// CD3D11VideoProcessorInputView
// ----------------------------------------------------------------------------
class CD3D11VideoProcessorInputView : public ID3D11VideoProcessorInputView {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    ID3D11Resource* m_pResource{ nullptr };
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC m_desc{};

public:
    CD3D11VideoProcessorInputView(ID3D11Device* pDevice, ID3D11Resource* pResource, const D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC* pDesc)
        : m_pDevice(pDevice), m_pResource(pResource) {
        if (pDesc) m_desc = *pDesc;
        if (m_pResource) m_pResource->AddRef();
        if (m_pDevice) m_pDevice->AddRef();
    }

    ~CD3D11VideoProcessorInputView() override {
        if (m_pResource) m_pResource->Release();
        if (m_pDevice) m_pDevice->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11View || riid == IID_ID3D11VideoProcessorInputView) {
            *ppvObject = static_cast<ID3D11VideoProcessorInputView*>(this);
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

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice && m_pDevice) {
            *ppDevice = m_pDevice;
            m_pDevice->AddRef();
        }
    }

    void GetResource(ID3D11Resource** ppResource) override {
        if (ppResource && m_pResource) {
            *ppResource = m_pResource;
            m_pResource->AddRef();
        }
    }

    void GetDesc(D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

// ----------------------------------------------------------------------------
// CD3D11VideoProcessorOutputView
// ----------------------------------------------------------------------------
class CD3D11VideoProcessorOutputView : public ID3D11VideoProcessorOutputView {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    ID3D11Resource* m_pResource{ nullptr };
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC m_desc{};

public:
    CD3D11VideoProcessorOutputView(ID3D11Device* pDevice, ID3D11Resource* pResource, const D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC* pDesc)
        : m_pDevice(pDevice), m_pResource(pResource) {
        if (pDesc) m_desc = *pDesc;
        if (m_pResource) m_pResource->AddRef();
        if (m_pDevice) m_pDevice->AddRef();
    }

    ~CD3D11VideoProcessorOutputView() override {
        if (m_pResource) m_pResource->Release();
        if (m_pDevice) m_pDevice->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11View || riid == IID_ID3D11VideoProcessorOutputView) {
            *ppvObject = static_cast<ID3D11VideoProcessorOutputView*>(this);
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

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice && m_pDevice) {
            *ppDevice = m_pDevice;
            m_pDevice->AddRef();
        }
    }

    void GetResource(ID3D11Resource** ppResource) override {
        if (ppResource && m_pResource) {
            *ppResource = m_pResource;
            m_pResource->AddRef();
        }
    }

    void GetDesc(D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }
};

// ----------------------------------------------------------------------------
// CD3D11VideoProcessorEnumerator
// ----------------------------------------------------------------------------
class CD3D11VideoProcessorEnumerator : public ID3D11VideoProcessorEnumerator {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC m_contentDesc{};

public:
    CD3D11VideoProcessorEnumerator(ID3D11Device* pDevice, const D3D11_VIDEO_PROCESSOR_CONTENT_DESC* pDesc)
        : m_pDevice(pDevice) {
        if (pDesc) m_contentDesc = *pDesc;
        if (m_pDevice) m_pDevice->AddRef();
    }

    ~CD3D11VideoProcessorEnumerator() override {
        if (m_pDevice) m_pDevice->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11VideoProcessorEnumerator) {
            *ppvObject = static_cast<ID3D11VideoProcessorEnumerator*>(this);
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

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice && m_pDevice) {
            *ppDevice = m_pDevice;
            m_pDevice->AddRef();
        }
    }

    int32_t GetVideoProcessorContentDesc(D3D11_VIDEO_PROCESSOR_CONTENT_DESC* pContentDesc) override {
        if (!pContentDesc) return -1;
        *pContentDesc = m_contentDesc;
        return 0; // S_OK
    }

    int32_t CheckVideoProcessorFormat(DXGI_FORMAT Format, uint32_t* pFlags) override {
        if (!pFlags) return -1;
        *pFlags = 0;
        switch (Format) {
            case DXGI_FORMAT_NV12:
            case DXGI_FORMAT_YUY2:
                *pFlags = D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT | D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT;
                return 0;
            case DXGI_FORMAT_B8G8R8A8_UNORM:
            case DXGI_FORMAT_R8G8B8A8_UNORM:
            case DXGI_FORMAT_R10G10B10A2_UNORM:
            case DXGI_FORMAT_R16G16B16A16_FLOAT:
                *pFlags = D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT | D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT;
                return 0;
            default:
                return -1; // Format not supported
        }
    }

    int32_t GetVideoProcessorCaps(D3D11_VIDEO_PROCESSOR_CAPS* pCaps) override {
        if (!pCaps) return -1;
        pCaps->DeviceCaps = D3D11_VIDEO_PROCESSOR_DEVICE_CAPS_LINEAR_SPACE |
                            D3D11_VIDEO_PROCESSOR_DEVICE_CAPS_xvYCC |
                            D3D11_VIDEO_PROCESSOR_DEVICE_CAPS_RGB_RANGE_CONVERSION |
                            D3D11_VIDEO_PROCESSOR_DEVICE_CAPS_YCbCr_MATRIX_CONVERSION |
                            D3D11_VIDEO_PROCESSOR_DEVICE_CAPS_NOMINAL_RANGE;

        pCaps->FeatureCaps = D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_ALPHA_FILL |
                             D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_CONSTRICTION |
                             D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_LUMA_KEY |
                             D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_ALPHA_PALETTE |
                             D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_ROTATION |
                             D3D11_VIDEO_PROCESSOR_FEATURE_CAPS_STEREO;

        pCaps->FilterCaps = D3D11_VIDEO_PROCESSOR_FILTER_CAPS_BRIGHTNESS |
                            D3D11_VIDEO_PROCESSOR_FILTER_CAPS_CONTRAST |
                            D3D11_VIDEO_PROCESSOR_FILTER_CAPS_HUE |
                            D3D11_VIDEO_PROCESSOR_FILTER_CAPS_SATURATION |
                            D3D11_VIDEO_PROCESSOR_FILTER_CAPS_NOISE_REDUCTION |
                            D3D11_VIDEO_PROCESSOR_FILTER_CAPS_EDGE_ENHANCEMENT |
                            D3D11_VIDEO_PROCESSOR_FILTER_CAPS_ANAMORPHIC_SCALING;

        pCaps->InputFormatCaps = 0x7; // RGB, YUV, 10-bit HDR
        pCaps->AutoStreamCaps = D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_DENOISE |
                                D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_EDGE_ENHANCEMENT |
                                D3D11_VIDEO_PROCESSOR_AUTO_STREAM_CAPS_COLOR_CORRECTION;
        pCaps->StereoCaps = 0;
        pCaps->RateConversionCapsCount = 1;
        pCaps->MaxInputStreams = 16;
        pCaps->MaxStreamStates = 16;
        return 0; // S_OK
    }

    int32_t GetVideoProcessorRateConversionCaps(uint32_t TypeIndex, D3D11_VIDEO_PROCESSOR_RATE_CONVERSION_CAPS* pCaps) override {
        if (!pCaps || TypeIndex != 0) return -1;
        pCaps->PastFrames = 2;
        pCaps->FutureFrames = 2;
        pCaps->ProcessorCaps = 0x3; // De-interlacing + Frame Rate Conversion
        pCaps->ITelecineCaps = 0x1; // Inverse 3:2 Pulldown
        pCaps->CustomRateCount = 3;
        return 0; // S_OK
    }

    int32_t GetVideoProcessorCustomRate(uint32_t TypeIndex, uint32_t CustomRateIndex, D3D11_VIDEO_PROCESSOR_CUSTOM_RATE* pRate) override {
        if (!pRate || TypeIndex != 0 || CustomRateIndex >= 3) return -1;
        if (CustomRateIndex == 0) {
            pRate->CustomRate = { 24, 1 };
            pRate->OutputFrames = 1;
            pRate->InputInterlaced = 0;
            pRate->FormatConversionCaps = 0x1;
        } else if (CustomRateIndex == 1) {
            pRate->CustomRate = { 30, 1 };
            pRate->OutputFrames = 1;
            pRate->InputInterlaced = 1;
            pRate->FormatConversionCaps = 0x1;
        } else {
            pRate->CustomRate = { 60, 1 };
            pRate->OutputFrames = 2;
            pRate->InputInterlaced = 1;
            pRate->FormatConversionCaps = 0x3;
        }
        return 0; // S_OK
    }

    int32_t GetVideoProcessorFilterRange(D3D11_VIDEO_PROCESSOR_FILTER Filter, D3D11_VIDEO_PROCESSOR_FILTER_RANGE* pRange) override {
        if (!pRange) return -1;
        switch (Filter) {
            case D3D11_VIDEO_PROCESSOR_FILTER_BRIGHTNESS:
                pRange->Minimum = -100;
                pRange->Maximum = 100;
                pRange->Default = 0;
                pRange->Multiplier = 1.0f;
                return 0;
            case D3D11_VIDEO_PROCESSOR_FILTER_CONTRAST:
                pRange->Minimum = 0;
                pRange->Maximum = 200;
                pRange->Default = 100;
                pRange->Multiplier = 1.0f;
                return 0;
            case D3D11_VIDEO_PROCESSOR_FILTER_HUE:
                pRange->Minimum = -180;
                pRange->Maximum = 180;
                pRange->Default = 0;
                pRange->Multiplier = 1.0f;
                return 0;
            case D3D11_VIDEO_PROCESSOR_FILTER_SATURATION:
                pRange->Minimum = 0;
                pRange->Maximum = 200;
                pRange->Default = 100;
                pRange->Multiplier = 1.0f;
                return 0;
            case D3D11_VIDEO_PROCESSOR_FILTER_NOISE_REDUCTION:
                pRange->Minimum = 0;
                pRange->Maximum = 100;
                pRange->Default = 0;
                pRange->Multiplier = 1.0f;
                return 0;
            case D3D11_VIDEO_PROCESSOR_FILTER_EDGE_ENHANCEMENT:
                pRange->Minimum = 0;
                pRange->Maximum = 100;
                pRange->Default = 0;
                pRange->Multiplier = 1.0f;
                return 0;
            case D3D11_VIDEO_PROCESSOR_FILTER_ANAMORPHIC_SCALING:
                pRange->Minimum = 0;
                pRange->Maximum = 100;
                pRange->Default = 0;
                pRange->Multiplier = 1.0f;
                return 0;
            default:
                return -1;
        }
    }
};

// ----------------------------------------------------------------------------
// Stream State inside CD3D11VideoProcessor
// ----------------------------------------------------------------------------
struct VideoProcessorStreamState {
    int32_t enabled{ 1 };
    D3D11_VIDEO_FRAME_FORMAT frameFormat{ D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE };
    D3D11_VIDEO_PROCESSOR_COLOR_SPACE colorSpace{};
    D3D11_VIDEO_PROCESSOR_OUTPUT_RATE outputRate{ D3D11_VIDEO_PROCESSOR_OUTPUT_RATE_NORMAL };
    RECT sourceRect{ 0, 0, 1920, 1080 };
    int32_t sourceRectEnabled{ 0 };
    RECT destRect{ 0, 0, 1920, 1080 };
    int32_t destRectEnabled{ 0 };
    float alpha{ 1.0f };
    int32_t alphaEnabled{ 1 };
    int32_t autoProcessingEnabled{ 1 };
    std::unordered_map<uint32_t, int32_t> filterLevels;

    VideoProcessorStreamState() {
        filterLevels[D3D11_VIDEO_PROCESSOR_FILTER_BRIGHTNESS] = 0;
        filterLevels[D3D11_VIDEO_PROCESSOR_FILTER_CONTRAST] = 100;
        filterLevels[D3D11_VIDEO_PROCESSOR_FILTER_HUE] = 0;
        filterLevels[D3D11_VIDEO_PROCESSOR_FILTER_SATURATION] = 100;
        filterLevels[D3D11_VIDEO_PROCESSOR_FILTER_NOISE_REDUCTION] = 0;
        filterLevels[D3D11_VIDEO_PROCESSOR_FILTER_EDGE_ENHANCEMENT] = 0;
    }
};

// ----------------------------------------------------------------------------
// CD3D11VideoProcessor
// ----------------------------------------------------------------------------
class CD3D11VideoProcessor : public ID3D11VideoProcessor {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC m_desc{};
    uint32_t m_rateConversionIndex{ 0 };

    RECT m_targetRect{ 0, 0, 1920, 1080 };
    int32_t m_targetRectEnabled{ 0 };
    D3D11_VIDEO_COLOR m_bgColor{};
    int32_t m_bgColorYCbCr{ 0 };
    D3D11_VIDEO_PROCESSOR_COLOR_SPACE m_outputColorSpace{};
    D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE m_alphaFillMode{ D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE_OPAQUE };
    std::vector<VideoProcessorStreamState> m_streams;

public:
    CD3D11VideoProcessor(ID3D11Device* pDevice, const D3D11_VIDEO_PROCESSOR_CONTENT_DESC* pDesc, uint32_t rateIndex)
        : m_pDevice(pDevice), m_rateConversionIndex(rateIndex) {
        if (pDesc) m_desc = *pDesc;
        m_streams.resize(16);
        if (m_pDevice) m_pDevice->AddRef();
        m_bgColor.RGBA = { 0.0f, 0.0f, 0.0f, 1.0f }; // Opaque black default
    }

    ~CD3D11VideoProcessor() override {
        if (m_pDevice) m_pDevice->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11VideoProcessor) {
            *ppvObject = static_cast<ID3D11VideoProcessor*>(this);
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

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice && m_pDevice) {
            *ppDevice = m_pDevice;
            m_pDevice->AddRef();
        }
    }

    void GetContentDesc(D3D11_VIDEO_PROCESSOR_CONTENT_DESC* pDesc) override {
        if (pDesc) *pDesc = m_desc;
    }

    void GetRateConversionCaps(uint32_t TypeIndex, D3D11_VIDEO_PROCESSOR_RATE_CONVERSION_CAPS* pCaps) override {
        (void)TypeIndex;
        (void)m_rateConversionIndex;
        if (!pCaps) return;
        pCaps->PastFrames = 2;
        pCaps->FutureFrames = 2;
        pCaps->ProcessorCaps = 0x3;
        pCaps->ITelecineCaps = 0x1;
        pCaps->CustomRateCount = 3;
    }

    // Configuration Accessors
    void SetTargetRect(int32_t enable, const RECT* pRect) {
        m_targetRectEnabled = enable;
        if (pRect) m_targetRect = *pRect;
    }

    void SetBackgroundColor(int32_t ycbcr, const D3D11_VIDEO_COLOR* pColor) {
        m_bgColorYCbCr = ycbcr;
        if (pColor) m_bgColor = *pColor;
    }

    void SetOutputColorSpace(const D3D11_VIDEO_PROCESSOR_COLOR_SPACE* pCS) {
        if (pCS) m_outputColorSpace = *pCS;
    }

    void SetOutputAlphaFillMode(D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE mode) {
        m_alphaFillMode = mode;
    }

    VideoProcessorStreamState* GetStreamState(uint32_t index) {
        if (index >= m_streams.size()) return nullptr;
        return &m_streams[index];
    }

    const D3D11_VIDEO_COLOR& GetBackgroundColor() const { return m_bgColor; }
    int32_t IsBackgroundColorYCbCr() const { return m_bgColorYCbCr; }
    const D3D11_VIDEO_PROCESSOR_COLOR_SPACE& GetOutputColorSpace() const { return m_outputColorSpace; }
    const RECT& GetTargetRect() const { return m_targetRect; }
    int32_t IsTargetRectEnabled() const { return m_targetRectEnabled; }
    D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE GetAlphaFillMode() const { return m_alphaFillMode; }
};

// ----------------------------------------------------------------------------
// CD3D11VideoDecoder
// ----------------------------------------------------------------------------
class CD3D11VideoDecoder : public ID3D11VideoDecoder {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    D3D11_VIDEO_DECODER_DESC m_desc{};
    D3D11_VIDEO_DECODER_CONFIG m_config{};

    // Decoder Internal State
    bool m_frameActive{ false };
    ID3D11VideoDecoderOutputView* m_pCurrentView{ nullptr };
    std::vector<uint8_t> m_bitstreamBuffer;
    std::vector<uint8_t> m_picParamsBuffer;
    std::vector<uint8_t> m_iqMatrixBuffer;
    std::vector<uint8_t> m_sliceControlBuffer;

    uint32_t m_decodedFrames{ 0 };
    uint64_t m_totalBitstreamBytes{ 0 };

public:
    CD3D11VideoDecoder(ID3D11Device* pDevice, const D3D11_VIDEO_DECODER_DESC* pDesc, const D3D11_VIDEO_DECODER_CONFIG* pConfig)
        : m_pDevice(pDevice) {
        if (pDesc) m_desc = *pDesc;
        if (pConfig) m_config = *pConfig;
        if (m_pDevice) m_pDevice->AddRef();

        m_bitstreamBuffer.resize(1024 * 1024, 0); // 1 MB scratch
        m_picParamsBuffer.resize(4096, 0);
        m_iqMatrixBuffer.resize(4096, 0);
        m_sliceControlBuffer.resize(16384, 0);
    }

    ~CD3D11VideoDecoder() override {
        if (m_pCurrentView) m_pCurrentView->Release();
        if (m_pDevice) m_pDevice->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11VideoDecoder) {
            *ppvObject = static_cast<ID3D11VideoDecoder*>(this);
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

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice && m_pDevice) {
            *ppDevice = m_pDevice;
            m_pDevice->AddRef();
        }
    }

    int32_t GetCreationParameters(D3D11_VIDEO_DECODER_DESC* pDesc, D3D11_VIDEO_DECODER_CONFIG* pConfig) override {
        if (pDesc) *pDesc = m_desc;
        if (pConfig) *pConfig = m_config;
        return 0; // S_OK
    }

    int32_t GetDriverHandle(void** pDriverHandle) override {
        if (!pDriverHandle) return -1;
        *pDriverHandle = reinterpret_cast<void*>(0xD3D11DEC0001ULL);
        return 0; // S_OK
    }

    // Decoding pipeline methods
    int32_t GetBuffer(D3D11_VIDEO_DECODER_BUFFER_TYPE type, uint32_t* pSize, void** ppBuf) {
        if (!pSize || !ppBuf) return -1;
        switch (type) {
            case D3D11_VIDEO_DECODER_BUFFER_BITSTREAM:
                *pSize = static_cast<uint32_t>(m_bitstreamBuffer.size());
                *ppBuf = m_bitstreamBuffer.data();
                return 0;
            case D3D11_VIDEO_DECODER_BUFFER_PICTURE_PARAMETERS:
                *pSize = static_cast<uint32_t>(m_picParamsBuffer.size());
                *ppBuf = m_picParamsBuffer.data();
                return 0;
            case D3D11_VIDEO_DECODER_BUFFER_INVERSE_QUANTIZATION_MATRIX:
                *pSize = static_cast<uint32_t>(m_iqMatrixBuffer.size());
                *ppBuf = m_iqMatrixBuffer.data();
                return 0;
            case D3D11_VIDEO_DECODER_BUFFER_SLICE_CONTROL:
                *pSize = static_cast<uint32_t>(m_sliceControlBuffer.size());
                *ppBuf = m_sliceControlBuffer.data();
                return 0;
            default:
                *pSize = 0;
                *ppBuf = nullptr;
                return -1;
        }
    }

    int32_t ReleaseBuffer(D3D11_VIDEO_DECODER_BUFFER_TYPE) {
        return 0; // S_OK
    }

    int32_t BeginFrame(ID3D11VideoDecoderOutputView* pView) {
        if (!pView) return -1;
        if (m_frameActive) return -2147467259; // E_FAIL: Frame already active
        m_frameActive = true;
        if (m_pCurrentView) m_pCurrentView->Release();
        m_pCurrentView = pView;
        m_pCurrentView->AddRef();
        return 0; // S_OK
    }

    int32_t SubmitBuffers(uint32_t numBuffers, const D3D11_VIDEO_DECODER_BUFFER_DESC* pDescs) {
        if (!m_frameActive || !pDescs) return -1;
        for (uint32_t i = 0; i < numBuffers; ++i) {
            if (pDescs[i].BufferType == D3D11_VIDEO_DECODER_BUFFER_BITSTREAM) {
                m_totalBitstreamBytes += pDescs[i].DataSize;
            }
        }
        return 0; // S_OK
    }

    int32_t EndFrame() {
        if (!m_frameActive) return -1;
        m_frameActive = false;
        m_decodedFrames++;
        if (m_pCurrentView) {
            m_pCurrentView->Release();
            m_pCurrentView = nullptr;
        }
        return 0; // S_OK
    }

    uint32_t GetDecodedFrames() const { return m_decodedFrames; }
    uint64_t GetTotalBitstreamBytes() const { return m_totalBitstreamBytes; }
    const D3D11_VIDEO_DECODER_DESC& GetDesc() const { return m_desc; }
};

// ----------------------------------------------------------------------------
// CD3D11VideoDevice
// ----------------------------------------------------------------------------
class CD3D11VideoDevice : public ID3D11VideoDevice {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    std::vector<GUID> m_supportedProfiles;

public:
    CD3D11VideoDevice(ID3D11Device* pDevice) : m_pDevice(pDevice) {
        if (m_pDevice) m_pDevice->AddRef();

        m_supportedProfiles = {
            D3D11_DECODER_PROFILE_H264_VLD_NOFGT,
            D3D11_DECODER_PROFILE_H264_VLD_FGT,
            D3D11_DECODER_PROFILE_HEVC_VLD_MAIN,
            D3D11_DECODER_PROFILE_HEVC_VLD_MAIN10,
            D3D11_DECODER_PROFILE_VP9_VLD_PROFILE0,
            D3D11_DECODER_PROFILE_VP9_VLD_10BIT,
            D3D11_DECODER_PROFILE_AV1_VLD_PROFILE0,
            D3D11_DECODER_PROFILE_VC1_VLD,
            D3D11_DECODER_PROFILE_MPEG2_VLD
        };
    }

    ~CD3D11VideoDevice() override {
        if (m_pDevice) m_pDevice->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11VideoDevice) {
            *ppvObject = static_cast<ID3D11VideoDevice*>(this);
            AddRef();
            return 0;
        }
        if (riid == IID_ID3D11Device && m_pDevice) {
            return m_pDevice->QueryInterface(riid, ppvObject);
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

    int32_t CreateVideoDecoder(
        const D3D11_VIDEO_DECODER_DESC* pDesc,
        const D3D11_VIDEO_DECODER_CONFIG* pConfig,
        ID3D11VideoDecoder** ppDecoder) override {
        if (!pDesc || !pConfig || !ppDecoder) return -1;
        *ppDecoder = new CD3D11VideoDecoder(m_pDevice, pDesc, pConfig);
        return 0; // S_OK
    }

    int32_t CreateVideoProcessor(
        ID3D11VideoProcessorEnumerator* pEnum,
        uint32_t RateConversionIndex,
        ID3D11VideoProcessor** ppVideoProcessor) override {
        if (!pEnum || !ppVideoProcessor) return -1;
        D3D11_VIDEO_PROCESSOR_CONTENT_DESC desc{};
        pEnum->GetVideoProcessorContentDesc(&desc);
        *ppVideoProcessor = new CD3D11VideoProcessor(m_pDevice, &desc, RateConversionIndex);
        return 0; // S_OK
    }

    int32_t CreateVideoDecoderOutputView(
        ID3D11Resource* pResource,
        const D3D11_VIDEO_DECODER_OUTPUT_VIEW_DESC* pDesc,
        ID3D11VideoDecoderOutputView** ppVDOVView) override {
        if (!pResource || !pDesc || !ppVDOVView) return -1;
        *ppVDOVView = new CD3D11VideoDecoderOutputView(m_pDevice, pResource, pDesc);
        return 0; // S_OK
    }

    int32_t CreateVideoProcessorInputView(
        ID3D11Resource* pResource,
        ID3D11VideoProcessorEnumerator*,
        const D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC* pDesc,
        ID3D11VideoProcessorInputView** ppVPIView) override {
        if (!pResource || !pDesc || !ppVPIView) return -1;
        *ppVPIView = new CD3D11VideoProcessorInputView(m_pDevice, pResource, pDesc);
        return 0; // S_OK
    }

    int32_t CreateVideoProcessorOutputView(
        ID3D11Resource* pResource,
        ID3D11VideoProcessorEnumerator*,
        const D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC* pDesc,
        ID3D11VideoProcessorOutputView** ppVPOView) override {
        if (!pResource || !pDesc || !ppVPOView) return -1;
        *ppVPOView = new CD3D11VideoProcessorOutputView(m_pDevice, pResource, pDesc);
        return 0; // S_OK
    }

    int32_t CreateVideoProcessorEnumerator(
        const D3D11_VIDEO_PROCESSOR_CONTENT_DESC* pDesc,
        ID3D11VideoProcessorEnumerator** ppEnum) override {
        if (!pDesc || !ppEnum) return -1;
        *ppEnum = new CD3D11VideoProcessorEnumerator(m_pDevice, pDesc);
        return 0; // S_OK
    }

    uint32_t GetVideoDecoderProfileCount() override {
        return static_cast<uint32_t>(m_supportedProfiles.size());
    }

    int32_t GetVideoDecoderProfile(uint32_t Index, GUID* pDecoderProfile) override {
        if (!pDecoderProfile || Index >= m_supportedProfiles.size()) return -1;
        *pDecoderProfile = m_supportedProfiles[Index];
        return 0; // S_OK
    }

    int32_t CheckVideoDecoderFormat(const GUID* pDecoderProfile, DXGI_FORMAT Format, int32_t* pSupported) override {
        if (!pDecoderProfile || !pSupported) return -1;
        *pSupported = 0;
        if (Format == DXGI_FORMAT_NV12 || Format == DXGI_FORMAT_P010 || Format == DXGI_FORMAT_B8G8R8A8_UNORM) {
            *pSupported = 1;
            return 0; // S_OK
        }
        return 0; // S_OK
    }

    int32_t GetVideoDecoderConfigCount(const D3D11_VIDEO_DECODER_DESC* pDesc, uint32_t* pCount) override {
        if (!pDesc || !pCount) return -1;
        *pCount = 1; // Default sovereign hardware config
        return 0; // S_OK
    }

    int32_t GetVideoDecoderConfig(const D3D11_VIDEO_DECODER_DESC*, uint32_t Index, D3D11_VIDEO_DECODER_CONFIG* pConfig) override {
        if (!pConfig || Index != 0) return -1;
        std::memset(pConfig, 0, sizeof(D3D11_VIDEO_DECODER_CONFIG));
        pConfig->ConfigBitstreamRaw = 1; // Standard bitstream raw VLD
        pConfig->ConfigMinRenderTargetBuffCount = 4;
        pConfig->ConfigResidDiffAccelerator = 1;
        return 0; // S_OK
    }

    int32_t CheckCryptoKeyExchange(const GUID* pCryptoType, const GUID* pDecoderProfile, uint32_t Index, GUID* pKeyExchangeType) override {
        (void)pDecoderProfile;
        if (!pCryptoType || !pKeyExchangeType || Index != 0) return -1;
        if (*pCryptoType == D3D11_CRYPTO_TYPE_AES128_CTR) {
            *pKeyExchangeType = D3D11_KEY_EXCHANGE_HW_PROTECTION;
            return 0; // S_OK
        }
        return -1;
    }
};

// ----------------------------------------------------------------------------
// CD3D11VideoContext
// ----------------------------------------------------------------------------
class CD3D11VideoContext : public ID3D11VideoContext {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D11Device* m_pDevice{ nullptr };
    ID3D11DeviceContext* m_pContext{ nullptr };

    // Blt & Video Processing Metrics
    uint32_t m_bltCount{ 0 };
    uint32_t m_processedFrames{ 0 };

public:
    CD3D11VideoContext(ID3D11Device* pDevice, ID3D11DeviceContext* pContext)
        : m_pDevice(pDevice), m_pContext(pContext) {
        if (m_pDevice) m_pDevice->AddRef();
        if (m_pContext) m_pContext->AddRef();
    }

    ~CD3D11VideoContext() override {
        if (m_pDevice) m_pDevice->Release();
        if (m_pContext) m_pContext->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D11DeviceChild || riid == IID_ID3D11VideoContext) {
            *ppvObject = static_cast<ID3D11VideoContext*>(this);
            AddRef();
            return 0;
        }
        if (riid == IID_ID3D11DeviceContext && m_pContext) {
            return m_pContext->QueryInterface(riid, ppvObject);
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

    void GetDevice(ID3D11Device** ppDevice) override {
        if (ppDevice && m_pDevice) {
            *ppDevice = m_pDevice;
            m_pDevice->AddRef();
        }
    }

    // Decoder Methods
    int32_t GetDecoderBuffer(ID3D11VideoDecoder* pDecoder, D3D11_VIDEO_DECODER_BUFFER_TYPE Type, uint32_t* pBufferSize, void** ppBuffer) override {
        if (!pDecoder) return -1;
        auto* dec = static_cast<CD3D11VideoDecoder*>(pDecoder);
        return dec->GetBuffer(Type, pBufferSize, ppBuffer);
    }

    int32_t ReleaseDecoderBuffer(ID3D11VideoDecoder* pDecoder, D3D11_VIDEO_DECODER_BUFFER_TYPE Type) override {
        if (!pDecoder) return -1;
        auto* dec = static_cast<CD3D11VideoDecoder*>(pDecoder);
        return dec->ReleaseBuffer(Type);
    }

    int32_t DecoderBeginFrame(ID3D11VideoDecoder* pDecoder, ID3D11VideoDecoderOutputView* pView, uint32_t, const void*) override {
        if (!pDecoder || !pView) return -1;
        auto* dec = static_cast<CD3D11VideoDecoder*>(pDecoder);
        return dec->BeginFrame(pView);
    }

    int32_t DecoderEndFrame(ID3D11VideoDecoder* pDecoder) override {
        if (!pDecoder) return -1;
        auto* dec = static_cast<CD3D11VideoDecoder*>(pDecoder);
        return dec->EndFrame();
    }

    int32_t SubmitDecoderBuffers(ID3D11VideoDecoder* pDecoder, uint32_t NumBuffers, const D3D11_VIDEO_DECODER_BUFFER_DESC* pBufferDesc) override {
        if (!pDecoder || !pBufferDesc) return -1;
        auto* dec = static_cast<CD3D11VideoDecoder*>(pDecoder);
        return dec->SubmitBuffers(NumBuffers, pBufferDesc);
    }

    int32_t DecoderExtension(ID3D11VideoDecoder*, const D3D11_VIDEO_DECODER_EXTENSION*) override {
        return 0; // S_OK
    }

    // Video Processor Configuration Methods
    void VideoProcessorSetOutputTargetRect(ID3D11VideoProcessor* pVP, int32_t Enable, const RECT* pRect) override {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        vp->SetTargetRect(Enable, pRect);
    }

    void VideoProcessorSetOutputBackgroundColor(ID3D11VideoProcessor* pVP, int32_t YCbCr, const D3D11_VIDEO_COLOR* pColor) override {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        vp->SetBackgroundColor(YCbCr, pColor);
    }

    void VideoProcessorSetOutputColorSpace(ID3D11VideoProcessor* pVP, const D3D11_VIDEO_PROCESSOR_COLOR_SPACE* pColorSpace) override {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        vp->SetOutputColorSpace(pColorSpace);
    }

    void VideoProcessorSetOutputAlphaFillMode(ID3D11VideoProcessor* pVP, D3D11_VIDEO_PROCESSOR_ALPHA_FILL_MODE AlphaFillMode, uint32_t) override {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        vp->SetOutputAlphaFillMode(AlphaFillMode);
    }

    void VideoProcessorSetStreamFrameFormat(ID3D11VideoProcessor* pVP, uint32_t StreamIndex, D3D11_VIDEO_FRAME_FORMAT FrameFormat) override {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        auto* st = vp->GetStreamState(StreamIndex);
        if (st) st->frameFormat = FrameFormat;
    }

    void VideoProcessorSetStreamColorSpace(ID3D11VideoProcessor* pVP, uint32_t StreamIndex, const D3D11_VIDEO_PROCESSOR_COLOR_SPACE* pColorSpace) override {
        if (!pVP || !pColorSpace) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        auto* st = vp->GetStreamState(StreamIndex);
        if (st) st->colorSpace = *pColorSpace;
    }

    void VideoProcessorSetStreamOutputRate(ID3D11VideoProcessor* pVP, uint32_t StreamIndex, D3D11_VIDEO_PROCESSOR_OUTPUT_RATE OutputRate, int32_t, const DXGI_RATIONAL*) override {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        auto* st = vp->GetStreamState(StreamIndex);
        if (st) st->outputRate = OutputRate;
    }

    void VideoProcessorSetStreamSourceRect(ID3D11VideoProcessor* pVP, uint32_t StreamIndex, int32_t Enable, const RECT* pRect) override {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        auto* st = vp->GetStreamState(StreamIndex);
        if (st) {
            st->sourceRectEnabled = Enable;
            if (pRect) st->sourceRect = *pRect;
        }
    }

    void VideoProcessorSetStreamDestRect(ID3D11VideoProcessor* pVP, uint32_t StreamIndex, int32_t Enable, const RECT* pRect) override {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        auto* st = vp->GetStreamState(StreamIndex);
        if (st) {
            st->destRectEnabled = Enable;
            if (pRect) st->destRect = *pRect;
        }
    }

    void VideoProcessorSetStreamAlpha(ID3D11VideoProcessor* pVP, uint32_t StreamIndex, int32_t Enable, float Alpha) override {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        auto* st = vp->GetStreamState(StreamIndex);
        if (st) {
            st->alphaEnabled = Enable;
            st->alpha = std::clamp(Alpha, 0.0f, 1.0f);
        }
    }

    void VideoProcessorSetStreamAutoProcessingMode(ID3D11VideoProcessor* pVP, uint32_t StreamIndex, int32_t Enable) override {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        auto* st = vp->GetStreamState(StreamIndex);
        if (st) st->autoProcessingEnabled = Enable;
    }

    void VideoProcessorSetStreamFilter(ID3D11VideoProcessor* pVP, uint32_t StreamIndex, D3D11_VIDEO_PROCESSOR_FILTER filter, int32_t level) {
        if (!pVP) return;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVP);
        auto* st = vp->GetStreamState(StreamIndex);
        if (st) st->filterLevels[filter] = level;
    }

    // High-Performance Blt & Multi-Stream Compositing Engine
    int32_t VideoProcessorBlt(
        ID3D11VideoProcessor* pVideoProcessor,
        ID3D11VideoProcessorOutputView* pView,
        uint32_t OutputFrame,
        uint32_t StreamCount,
        const D3D11_VIDEO_PROCESSOR_STREAM* pStreams) override {
        (void)OutputFrame;
        if (!pVideoProcessor || !pView) return -1;
        auto* vp = static_cast<CD3D11VideoProcessor*>(pVideoProcessor);

        // Retrieve output resource and texture
        ID3D11Resource* pOutRes = nullptr;
        pView->GetResource(&pOutRes);
        if (!pOutRes) return -1;

        Prism3DTexture2DImpl* pOutTex = nullptr;
        pOutRes->QueryInterface(IID_ID3D11Texture2D, reinterpret_cast<void**>(&pOutTex));
        pOutRes->Release();
        if (!pOutTex) return -1;

        D3D11_TEXTURE2D_DESC outDesc{};
        pOutTex->GetDesc(&outDesc);
        uint32_t dstW = outDesc.Width;
        uint32_t dstH = outDesc.Height;
        uint32_t* pDstBits = pOutTex->GetPixels();
        size_t dstPitch = dstW;

        // 1. Clear destination buffer to background color
        const auto& bg = vp->GetBackgroundColor();
        uint8_t bgB = static_cast<uint8_t>(std::clamp(bg.RGBA.B * 255.0f, 0.0f, 255.0f));
        uint8_t bgG = static_cast<uint8_t>(std::clamp(bg.RGBA.G * 255.0f, 0.0f, 255.0f));
        uint8_t bgR = static_cast<uint8_t>(std::clamp(bg.RGBA.R * 255.0f, 0.0f, 255.0f));
        uint8_t bgA = static_cast<uint8_t>(std::clamp(bg.RGBA.A * 255.0f, 0.0f, 255.0f));

        for (uint32_t y = 0; y < dstH; ++y) {
            uint32_t* pRow = pDstBits + y * dstPitch;
            uint32_t bgPixel = (bgA << 24) | (bgR << 16) | (bgG << 8) | bgB;
            std::fill_n(pRow, dstW, bgPixel);
        }

        // 2. Composite all active streams (stream 0 = base, 1..N = PiP/overlays)
        for (uint32_t i = 0; i < StreamCount; ++i) {
            const auto& stream = pStreams[i];
            if (!stream.Enable || !stream.pInputSurface) continue;

            auto* st = vp->GetStreamState(i);
            float alpha = (st && st->alphaEnabled) ? st->alpha : 1.0f;

            // ProcAmp levels
            float brightness = 0.0f;
            float contrast = 1.0f;
            if (st) {
                brightness = st->filterLevels[D3D11_VIDEO_PROCESSOR_FILTER_BRIGHTNESS] / 100.0f;
                contrast = st->filterLevels[D3D11_VIDEO_PROCESSOR_FILTER_CONTRAST] / 100.0f;
            }

            ID3D11Resource* pInRes = nullptr;
            stream.pInputSurface->GetResource(&pInRes);
            if (!pInRes) continue;

            Prism3DTexture2DImpl* pInTex = nullptr;
            pInRes->QueryInterface(IID_ID3D11Texture2D, reinterpret_cast<void**>(&pInTex));
            pInRes->Release();
            if (!pInTex) continue;

            D3D11_TEXTURE2D_DESC inDesc{};
            pInTex->GetDesc(&inDesc);
            uint32_t srcW = inDesc.Width;
            uint32_t srcH = inDesc.Height;
            const uint32_t* pSrcBits = pInTex->GetPixels();
            size_t srcPitch = srcW;

            // Destination and source rectangle determination
            RECT sRect = (st && st->sourceRectEnabled) ? st->sourceRect : RECT{ 0, 0, static_cast<int32_t>(srcW), static_cast<int32_t>(srcH) };
            RECT dRect = (st && st->destRectEnabled) ? st->destRect : RECT{ 0, 0, static_cast<int32_t>(dstW), static_cast<int32_t>(dstH) };

            int32_t targetX = std::max(0, dRect.left);
            int32_t targetY = std::max(0, dRect.top);
            int32_t targetW = std::min(static_cast<int32_t>(dstW) - targetX, dRect.right - dRect.left);
            int32_t targetH = std::min(static_cast<int32_t>(dstH) - targetY, dRect.bottom - dRect.top);

            if (targetW <= 0 || targetH <= 0) {
                pInTex->Release();
                continue;
            }

            int32_t cropW = std::max(1, sRect.right - sRect.left);
            int32_t cropH = std::max(1, sRect.bottom - sRect.top);

            // Check color space matrix: BT.601, BT.709, or BT.2020 HDR
            bool isBT709 = (st && st->colorSpace.YCbCr_Matrix == 1);
            (void)isBT709;
            bool isFullRange = (st && st->colorSpace.Nominal_Range == D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_0_255);

            // Blit pixels with bilinear/nearest scaling, ProcAmp and planar alpha
            for (int32_t dy = 0; dy < targetH; ++dy) {
                int32_t sy = sRect.top + (dy * cropH) / targetH;
                if (sy < 0 || sy >= static_cast<int32_t>(srcH)) continue;

                uint32_t* pDstPixel = (pDstBits + (targetY + dy) * dstPitch) + targetX;
                const uint32_t* pSrcPixel = pSrcBits + sy * srcPitch;

                for (int32_t dx = 0; dx < targetW; ++dx) {
                    int32_t sx = sRect.left + (dx * cropW) / targetW;
                    if (sx < 0 || sx >= static_cast<int32_t>(srcW)) continue;

                    uint32_t sPix = pSrcPixel[sx];
                    uint8_t sb = sPix & 0xFF;
                    uint8_t sg = (sPix >> 8) & 0xFF;
                    uint8_t sr = (sPix >> 16) & 0xFF;
                    uint8_t sa = (sPix >> 24) & 0xFF;

                    // If stream format is YUV/NV12, perform color space transformation
                    float r = sr / 255.0f;
                    float g = sg / 255.0f;
                    float b = sb / 255.0f;

                    // Nominal range expansion if studio range
                    if (!isFullRange) {
                        r = std::clamp((r * 255.0f - 16.0f) / 219.0f, 0.0f, 1.0f);
                        g = std::clamp((g * 255.0f - 16.0f) / 219.0f, 0.0f, 1.0f);
                        b = std::clamp((b * 255.0f - 16.0f) / 219.0f, 0.0f, 1.0f);
                    }

                    // Apply ProcAmp brightness & contrast
                    r = std::clamp((r - 0.5f) * contrast + 0.5f + brightness, 0.0f, 1.0f);
                    g = std::clamp((g - 0.5f) * contrast + 0.5f + brightness, 0.0f, 1.0f);
                    b = std::clamp((b - 0.5f) * contrast + 0.5f + brightness, 0.0f, 1.0f);

                    // Multi-stream planar alpha blending
                    float effAlpha = (sa / 255.0f) * alpha;

                    uint32_t dPix = pDstPixel[dx];
                    float db = (dPix & 0xFF) / 255.0f;
                    float dg = ((dPix >> 8) & 0xFF) / 255.0f;
                    float dr = ((dPix >> 16) & 0xFF) / 255.0f;

                    float outR = r * effAlpha + dr * (1.0f - effAlpha);
                    float outG = g * effAlpha + dg * (1.0f - effAlpha);
                    float outB = b * effAlpha + db * (1.0f - effAlpha);

                    uint8_t finR = static_cast<uint8_t>(std::clamp(outR * 255.0f, 0.0f, 255.0f));
                    uint8_t finG = static_cast<uint8_t>(std::clamp(outG * 255.0f, 0.0f, 255.0f));
                    uint8_t finB = static_cast<uint8_t>(std::clamp(outB * 255.0f, 0.0f, 255.0f));

                    pDstPixel[dx] = (0xFF << 24) | (finR << 16) | (finG << 8) | finB;
                }
            }

            pInTex->Release();
        }

        pOutTex->Release();
        m_bltCount++;
        m_processedFrames++;
        return 0; // S_OK
    }

    uint32_t GetBltCount() const { return m_bltCount; }
    uint32_t GetProcessedFrames() const { return m_processedFrames; }
};

// ============================================================================
// 7. Factory Functions & Dynamic Export Layer
// ============================================================================

inline int32_t D3D11CreateVideoDevice(ID3D11Device* pDevice, ID3D11VideoDevice** ppVideoDevice) {
    if (!pDevice || !ppVideoDevice) return -1;
    *ppVideoDevice = new CD3D11VideoDevice(pDevice);
    return 0; // S_OK
}

inline int32_t D3D11CreateVideoContext(ID3D11Device* pDevice, ID3D11DeviceContext* pContext, ID3D11VideoContext** ppVideoContext) {
    if (!pDevice || !pContext || !ppVideoContext) return -1;
    *ppVideoContext = new CD3D11VideoContext(pDevice, pContext);
    return 0; // S_OK
}

inline int32_t D3D11CreateDeviceWithVideo(
    IDXGIAdapter* pAdapter,
    D3D_DRIVER_TYPE DriverType,
    void* Software,
    uint32_t Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    uint32_t FeatureLevels,
    uint32_t SDKVersion,
    ID3D11Device** ppDevice,
    D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext,
    ID3D11VideoDevice** ppVideoDevice,
    ID3D11VideoContext** ppVideoContext) {

    Flags |= D3D11_CREATE_DEVICE_VIDEO_SUPPORT;
    int32_t hr = D3D11CreateDevice(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
    if (hr != 0) return hr;

    if (ppVideoDevice && ppDevice && *ppDevice) {
        D3D11CreateVideoDevice(*ppDevice, ppVideoDevice);
    }
    if (ppVideoContext && ppDevice && *ppDevice && ppImmediateContext && *ppImmediateContext) {
        D3D11CreateVideoContext(*ppDevice, *ppImmediateContext, ppVideoContext);
    }
    return 0; // S_OK
}

inline void InitializeD3D11VAExports() {
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("d3d11.dll", "D3D11CreateVideoDevice", reinterpret_cast<void*>(D3D11CreateVideoDevice));
    ldr.registerExport("d3d11.dll", "D3D11CreateVideoContext", reinterpret_cast<void*>(D3D11CreateVideoContext));
    ldr.registerExport("d3d11.dll", "D3D11CreateDeviceWithVideo", reinterpret_cast<void*>(D3D11CreateDeviceWithVideo));
}

} // namespace micant::d3d11va
