// ============================================================================
// MicaNT: Windows Direct3D 12 Video Decode & Processing API (D3D12 Video)
// 
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/DirectX-Headers (directx/d3d12video.h)
//   - https://github.com/microsoft/win32metadata
//   - Microsoft MSDN Direct3D 12 Video APIs & Video Processing Specifications
//
// Subsystem Overview:
//   D3D12 Video provides the low-level, command-list-driven video decode,
//   encode, and video processing architecture for modern Windows NT. Unlike
//   earlier immediate-mode APIs, operations are recorded into dedicated
//   ID3D12VideoDecodeCommandList and ID3D12VideoProcessCommandList objects,
//   executing asynchronously on dedicated GPU video queues.
//
// Trademark & Nominative Fair Use Notice:
//   Direct3D, DirectX, and D3D12 are registered trademarks of Microsoft
//   Corporation. All identifiers and structures are implemented for clean-room
//   binary and API compatibility with Windows applications.
// ============================================================================

#pragma once

#include "prismx.hpp"
#include "prism3d.hpp"
#include "prism3d12.hpp"
#include "ldr.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <unordered_map>

namespace micant::d3d12video {

using namespace micant::prismx;
using namespace micant::prism3d;
using namespace micant::prism3d12;

// ============================================================================
// 1. Direct3D 12 Video Formats & Color Spaces
// ============================================================================

using prismx::DXGI_FORMAT;
using prismx::DXGI_COLOR_SPACE_TYPE;
using prismx::DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;
using prismx::DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709;
using prismx::DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P709;
using prismx::DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P2020;
using prismx::DXGI_COLOR_SPACE_RESERVED;
using prismx::DXGI_COLOR_SPACE_YCBCR_FULL_G22_NONE_P709_X601;
using prismx::DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P601;
using prismx::DXGI_COLOR_SPACE_YCBCR_FULL_G22_LEFT_P601;
using prismx::DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709;
using prismx::DXGI_COLOR_SPACE_YCBCR_FULL_G22_LEFT_P709;
using prismx::DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P2020;
using prismx::DXGI_COLOR_SPACE_YCBCR_FULL_G22_LEFT_P2020;
using prismx::DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020;
using prismx::DXGI_COLOR_SPACE_YCBCR_STUDIO_G2084_LEFT_P2020;
using prismx::DXGI_COLOR_SPACE_RGB_STUDIO_G2084_NONE_P2020;
using prismx::DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_TOPLEFT_P2020;
using prismx::DXGI_COLOR_SPACE_YCBCR_STUDIO_G2084_TOPLEFT_P2020;
using prismx::DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P2020;
using prismx::DXGI_COLOR_SPACE_CUSTOM;

// ============================================================================
// 2. Direct3D 12 Video GUIDs
// ============================================================================

inline constexpr IID IID_ID3D12Pageable = {
    0x63EE58FB, 0x1268, 0x4835, { 0x86, 0xDA, 0xF0, 0x08, 0xCE, 0x10, 0x3C, 0x58 }
};

inline constexpr IID IID_ID3D12VideoDecoder = {
    0xC59B6BE9, 0x4D30, 0x4961, { 0xA9, 0xFE, 0xA0, 0x59, 0xDC, 0x22, 0x90, 0x64 }
};

inline constexpr IID IID_ID3D12VideoDecoderHeap = {
    0x0946B2EE, 0x0EBF, 0x4C42, { 0xBB, 0xCE, 0x30, 0x02, 0x77, 0x9D, 0x40, 0x34 }
};

inline constexpr IID IID_ID3D12VideoProcessor = {
    0x304FDB32, 0xBEDE, 0x410A, { 0x85, 0x45, 0x94, 0x3A, 0xC6, 0xA4, 0x61, 0x38 }
};

inline constexpr IID IID_ID3D12VideoDecodeCommandList = {
    0x3B605372, 0x2B48, 0x4FEB, { 0x9B, 0x05, 0x34, 0x3A, 0x11, 0x38, 0x4D, 0x82 }
};

inline constexpr IID IID_ID3D12VideoProcessCommandList = {
    0xAE4B69D0, 0xADCD, 0x4458, { 0xBE, 0x50, 0xE6, 0x30, 0x72, 0xD8, 0x88, 0x96 }
};

inline constexpr IID IID_ID3D12VideoDevice = {
    0x1F364CDB, 0xF2B4, 0x4360, { 0xBF, 0x43, 0xE8, 0x37, 0x23, 0xD4, 0x29, 0xF0 }
};

inline constexpr IID IID_ID3D12VideoDevice1 = {
    0x980F2197, 0x0B0B, 0x4813, { 0xB1, 0x14, 0x19, 0x15, 0x9F, 0x9C, 0x62, 0x3C }
};

// Standard Video Decode Profile GUIDs
inline constexpr GUID D3D12_VIDEO_DECODE_PROFILE_H264 = {
    0x1B81BE68, 0xA0C7, 0x11D3, { 0xB9, 0x84, 0x00, 0xC0, 0x4F, 0x2E, 0x73, 0xC5 }
};

inline constexpr GUID D3D12_VIDEO_DECODE_PROFILE_HEVC_MAIN = {
    0x5B11D51B, 0x2F4C, 0x4452, { 0xBC, 0xC4, 0x09, 0xF2, 0xA1, 0x16, 0x0C, 0xC0 }
};

inline constexpr GUID D3D12_VIDEO_DECODE_PROFILE_HEVC_MAIN10 = {
    0x107AF0E0, 0xEF1A, 0x4D19, { 0xAB, 0xA8, 0x67, 0xA1, 0x63, 0x07, 0x3D, 0x13 }
};

inline constexpr GUID D3D12_VIDEO_DECODE_PROFILE_VP9 = {
    0x463707F8, 0xA1D0, 0x4585, { 0x87, 0x6D, 0x83, 0xAA, 0x6D, 0x60, 0xB8, 0x9E }
};

inline constexpr GUID D3D12_VIDEO_DECODE_PROFILE_VP9_10BIT = {
    0xA4C749EF, 0x6EC3, 0x406A, { 0x84, 0x44, 0xC7, 0x27, 0xBF, 0x72, 0xBE, 0x13 }
};

inline constexpr GUID D3D12_VIDEO_DECODE_PROFILE_AV1_PROFILE0 = {
    0xB8BE4CCB, 0xCF53, 0x46BA, { 0x8D, 0x59, 0xD6, 0xB8, 0x04, 0x36, 0xD6, 0xCB }
};

inline constexpr GUID D3D12_VIDEO_DECODE_PROFILE_AV1_PROFILE1 = {
    0x6936FF4C, 0x45F1, 0x411A, { 0xB4, 0xBD, 0x84, 0x50, 0x6B, 0xF2, 0xDB, 0x59 }
};

inline constexpr GUID D3D12_VIDEO_DECODE_PROFILE_AV1_PROFILE2 = {
    0xC25204F2, 0x5C89, 0x4960, { 0x91, 0x33, 0xF1, 0xB0, 0xCB, 0x7F, 0x42, 0x04 }
};

inline constexpr GUID D3D12_VIDEO_DECODE_PROFILE_MPEG2 = {
    0xEE27417F, 0x5E28, 0x4E65, { 0xBE, 0xEA, 0x1D, 0x26, 0xB5, 0x08, 0xAD, 0xC9 }
};

inline constexpr GUID D3D12_VIDEO_DECODE_PROFILE_VC1 = {
    0x1B81BEA3, 0xA0C7, 0x11D3, { 0xB9, 0x84, 0x00, 0xC0, 0x4F, 0x2E, 0x73, 0xC5 }
};

// ============================================================================
// 3. Direct3D 12 Video Enumerations
// ============================================================================

enum D3D12_FEATURE_VIDEO : uint32_t {
    D3D12_FEATURE_VIDEO_DECODE_SUPPORT             = 0,
    D3D12_FEATURE_VIDEO_DECODE_PROFILES            = 1,
    D3D12_FEATURE_VIDEO_DECODE_FORMATS             = 2,
    D3D12_FEATURE_VIDEO_DECODE_CONVERSION_SUPPORT  = 3,
    D3D12_FEATURE_VIDEO_PROCESS_SUPPORT            = 4,
    D3D12_FEATURE_VIDEO_PROCESS_MAX_INPUT_STREAMS  = 5,
    D3D12_FEATURE_VIDEO_PROCESS_REFERENCE_INFO     = 6,
    D3D12_FEATURE_VIDEO_DECODER_HEAP_SIZE          = 7,
    D3D12_FEATURE_VIDEO_PROCESSOR_SIZE             = 8,
    D3D12_FEATURE_VIDEO_DECODE_PROFILE_COUNT       = 9,
    D3D12_FEATURE_VIDEO_DECODE_FORMAT_COUNT        = 10,
    D3D12_FEATURE_VIDEO_ARCHITECTURE               = 11
};

enum D3D12_VIDEO_DECODE_TIER : uint32_t {
    D3D12_VIDEO_DECODE_TIER_NOT_SUPPORTED = 0,
    D3D12_VIDEO_DECODE_TIER_1             = 1,
    D3D12_VIDEO_DECODE_TIER_2             = 2,
    D3D12_VIDEO_DECODE_TIER_3             = 3
};

enum D3D12_VIDEO_DECODE_SUPPORT_FLAGS : uint32_t {
    D3D12_VIDEO_DECODE_SUPPORT_FLAG_NONE       = 0,
    D3D12_VIDEO_DECODE_SUPPORT_FLAG_SUPPORTED  = 0x1
};

enum D3D12_VIDEO_DECODE_CONFIGURATION_FLAGS : uint32_t {
    D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_NONE                                      = 0,
    D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_HEIGHT_ALIGNMENT_MULTIPLE_OF_32            = 0x1,
    D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_POST_PROCESSING_SUPPORTED                  = 0x2,
    D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_REFERENCE_ONLY_ALLOCATIONS_REQUIRED       = 0x4,
    D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_ALLOW_RESOLUTION_CHANGE_ON_NON_KEY_FRAME  = 0x8
};

enum D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE : uint32_t {
    D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE_NONE        = 0,
    D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE_FIELD_BASED = 1
};

enum D3D12_BITSTREAM_ENCRYPTION_TYPE : uint32_t {
    D3D12_BITSTREAM_ENCRYPTION_TYPE_NONE = 0,
    D3D12_BITSTREAM_ENCRYPTION_TYPE_CENC = 1,
    D3D12_BITSTREAM_ENCRYPTION_TYPE_CBCS = 2
};

enum D3D12_VIDEO_DECODE_ARGUMENT_TYPE : uint32_t {
    D3D12_VIDEO_DECODE_ARGUMENT_TYPE_PICTURE_PARAMETERS         = 0,
    D3D12_VIDEO_DECODE_ARGUMENT_TYPE_INVERSE_QUANTIZATION_MATRIX = 1,
    D3D12_VIDEO_DECODE_ARGUMENT_TYPE_SLICE_CONTROL              = 2,
    D3D12_VIDEO_DECODE_ARGUMENT_TYPE_MAX_VALID                  = 3
};

enum D3D12_VIDEO_DECODE_STATUS : uint32_t {
    D3D12_VIDEO_DECODE_STATUS_OK             = 0,
    D3D12_VIDEO_DECODE_STATUS_CONTINUE       = 1,
    D3D12_VIDEO_DECODE_STATUS_RESTART        = 2,
    D3D12_VIDEO_DECODE_STATUS_RATE_EXCEEDED  = 3
};

enum D3D12_VIDEO_PROCESS_FEATURE_FLAGS : uint32_t {
    D3D12_VIDEO_PROCESS_FEATURE_FLAG_NONE               = 0,
    D3D12_VIDEO_PROCESS_FEATURE_FLAG_ALPHA_FILL         = 0x1,
    D3D12_VIDEO_PROCESS_FEATURE_FLAG_LUMA_KEY           = 0x2,
    D3D12_VIDEO_PROCESS_FEATURE_FLAG_STEREO             = 0x4,
    D3D12_VIDEO_PROCESS_FEATURE_FLAG_ROTATION           = 0x8,
    D3D12_VIDEO_PROCESS_FEATURE_FLAG_FLIP               = 0x10,
    D3D12_VIDEO_PROCESS_FEATURE_FLAG_ALPHA_BLENDING     = 0x20,
    D3D12_VIDEO_PROCESS_FEATURE_FLAG_PIXEL_ASPECT_RATIO = 0x40
};

enum D3D12_VIDEO_PROCESS_DEINTERLACE_FLAGS : uint32_t {
    D3D12_VIDEO_PROCESS_DEINTERLACE_FLAG_NONE   = 0,
    D3D12_VIDEO_PROCESS_DEINTERLACE_FLAG_BOB    = 0x1,
    D3D12_VIDEO_PROCESS_DEINTERLACE_FLAG_CUSTOM = 0x80000000
};

enum D3D12_VIDEO_PROCESS_FILTER : uint32_t {
    D3D12_VIDEO_PROCESS_FILTER_BRIGHTNESS          = 0,
    D3D12_VIDEO_PROCESS_FILTER_CONTRAST            = 1,
    D3D12_VIDEO_PROCESS_FILTER_HUE                 = 2,
    D3D12_VIDEO_PROCESS_FILTER_SATURATION          = 3,
    D3D12_VIDEO_PROCESS_FILTER_NOISE_REDUCTION     = 4,
    D3D12_VIDEO_PROCESS_FILTER_EDGE_ENHANCEMENT    = 5,
    D3D12_VIDEO_PROCESS_FILTER_ANAMORPHIC_SCALING  = 6,
    D3D12_VIDEO_PROCESS_FILTER_STEREO_ADJUSTMENT   = 7
};

enum D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE : uint32_t {
    D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE_OPAQUE        = 0,
    D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE_BACKGROUND    = 1,
    D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE_DESTINATION   = 2,
    D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE_SOURCE_STREAM = 3
};

enum D3D12_VIDEO_PROCESS_ORIENTATION : uint32_t {
    D3D12_VIDEO_PROCESS_ORIENTATION_DEFAULT                         = 0,
    D3D12_VIDEO_PROCESS_ORIENTATION_FLIP_HORIZONTAL                 = 1,
    D3D12_VIDEO_PROCESS_ORIENTATION_CLOCKWISE_90                    = 2,
    D3D12_VIDEO_PROCESS_ORIENTATION_CLOCKWISE_90_FLIP_HORIZONTAL   = 3,
    D3D12_VIDEO_PROCESS_ORIENTATION_CLOCKWISE_180                   = 4,
    D3D12_VIDEO_PROCESS_ORIENTATION_FLIP_VERTICAL                   = 5,
    D3D12_VIDEO_PROCESS_ORIENTATION_CLOCKWISE_270                   = 6,
    D3D12_VIDEO_PROCESS_ORIENTATION_CLOCKWISE_270_FLIP_HORIZONTAL   = 7
};

enum D3D12_VIDEO_FIELD_TYPE : uint32_t {
    D3D12_VIDEO_FIELD_TYPE_NONE    = 0,
    D3D12_VIDEO_FIELD_TYPE_FIELD1  = 1,
    D3D12_VIDEO_FIELD_TYPE_FIELD2  = 2
};

// ============================================================================
// 4. Direct3D 12 Video Structures
// ============================================================================

struct D3D12_VIDEO_DECODE_CONFIGURATION {
    GUID DecodeProfile{};
    D3D12_BITSTREAM_ENCRYPTION_TYPE BitstreamEncryption{D3D12_BITSTREAM_ENCRYPTION_TYPE_NONE};
    D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE InterlaceType{D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE_NONE};
};

struct D3D12_VIDEO_DECODER_DESC {
    uint32_t NodeMask{0};
    D3D12_VIDEO_DECODE_CONFIGURATION Configuration{};
};

struct D3D12_VIDEO_DECODER_HEAP_DESC {
    uint32_t NodeMask{0};
    D3D12_VIDEO_DECODE_CONFIGURATION Configuration{};
    uint32_t DecodeWidth{1920};
    uint32_t DecodeHeight{1080};
    DXGI_FORMAT Format{DXGI_FORMAT_NV12};
    DXGI_RATIONAL FrameRate{ 30, 1 };
    uint32_t BitRate{ 10000000 };
    uint32_t MaxDecodePictureBufferCount{ 16 };
};

struct D3D12_VIDEO_DECODE_FRAME_ARGUMENT {
    D3D12_VIDEO_DECODE_ARGUMENT_TYPE Type{static_cast<D3D12_VIDEO_DECODE_ARGUMENT_TYPE>(0)};
    uint32_t Size{0};
    void* pData{nullptr};
};

struct D3D12_VIDEO_DECODE_REFERENCE_FRAMES {
    uint32_t NumTexture2Ds{0};
    ID3D12Resource** ppTexture2Ds{nullptr};
    uint32_t* pSubresources{nullptr};
};

struct D3D12_VIDEO_DECODE_COMPRESSED_BITSTREAM {
    ID3D12Resource* pBuffer{nullptr};
    uint64_t Offset{0};
    uint64_t Size{0};
};

struct D3D12_VIDEO_DECODE_CONVERSION_ARGUMENTS {
    int32_t Enable{0};
    ID3D12Resource* pReferenceTexture2D{nullptr};
    uint32_t ReferenceSubresource{0};
    DXGI_COLOR_SPACE_TYPE OutputColorSpace{DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709};
};

// Forward declaration of ID3D12VideoDecoderHeap
class ID3D12VideoDecoderHeap;

struct D3D12_VIDEO_DECODE_INPUT_STREAM_ARGUMENTS {
    uint32_t NumFrameArguments{0};
    D3D12_VIDEO_DECODE_FRAME_ARGUMENT FrameArguments[10]{};
    D3D12_VIDEO_DECODE_REFERENCE_FRAMES ReferenceFrames{};
    D3D12_VIDEO_DECODE_COMPRESSED_BITSTREAM CompressedBitstream{};
    ID3D12VideoDecoderHeap* pHeap{nullptr};
};

struct D3D12_VIDEO_DECODE_OUTPUT_STREAM_ARGUMENTS {
    ID3D12Resource* pOutputTexture2D{nullptr};
    uint32_t OutputSubresource{0};
    D3D12_VIDEO_DECODE_CONVERSION_ARGUMENTS ConversionArguments{};
};

struct D3D12_VIDEO_PROCESS_FILTER_RANGE {
    int32_t Minimum{ -100 };
    int32_t Maximum{ 100 };
    int32_t Default{ 0 };
    float Multiplier{ 1.0f };
};

struct D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC {
    DXGI_FORMAT Format{DXGI_FORMAT_NV12};
    DXGI_COLOR_SPACE_TYPE ColorSpace{DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709};
    DXGI_RATIONAL SourceAspectRatio{ 1, 1 };
    DXGI_RATIONAL DestinationAspectRatio{ 1, 1 };
    DXGI_RATIONAL FrameRate{ 30, 1 };
    RECT SourceRect{ 0, 0, 1920, 1080 };
    RECT DestinationRect{ 0, 0, 1920, 1080 };
    D3D12_VIDEO_PROCESS_ORIENTATION Orientation{D3D12_VIDEO_PROCESS_ORIENTATION_DEFAULT};
    D3D12_VIDEO_PROCESS_DEINTERLACE_FLAGS DeinterlaceFlags{D3D12_VIDEO_PROCESS_DEINTERLACE_FLAG_BOB};
    D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE AlphaFillMode{D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE_OPAQUE};
};

struct D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC {
    DXGI_FORMAT Format{DXGI_FORMAT_B8G8R8A8_UNORM};
    DXGI_COLOR_SPACE_TYPE ColorSpace{DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709};
    D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE AlphaFillMode{D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE_OPAQUE};
    uint32_t BackgroundColor[4]{ 0, 0, 0, 255 }; // RGBA
    DXGI_RATIONAL FrameRate{ 60, 1 };
    int32_t EnableStereo{ 0 };
};

struct D3D12_VIDEO_PROCESS_INPUT_STREAM_ARGUMENTS {
    ID3D12Resource* pInputTexture2D{nullptr};
    uint32_t InputSubresource{0};
    RECT SourceRect{};
    RECT DestinationRect{};
    float Alpha{ 1.0f };
    int32_t FilterLevels[8]{ 0 };
};

struct D3D12_VIDEO_PROCESS_OUTPUT_STREAM_ARGUMENTS {
    ID3D12Resource* pOutputTexture2D{nullptr};
    uint32_t OutputSubresource{0};
    RECT TargetRect{};
};

// Feature Queries
struct D3D12_FEATURE_DATA_VIDEO_DECODE_SUPPORT {
    uint32_t NodeIndex{0};
    D3D12_VIDEO_DECODE_CONFIGURATION Configuration{};
    uint32_t Width{1920};
    uint32_t Height{1080};
    DXGI_FORMAT DecodeFormat{DXGI_FORMAT_NV12};
    DXGI_RATIONAL FrameRate{ 30, 1 };
    uint32_t BitRate{ 10000000 };
    D3D12_VIDEO_DECODE_SUPPORT_FLAGS SupportFlags{D3D12_VIDEO_DECODE_SUPPORT_FLAG_NONE};
    D3D12_VIDEO_DECODE_CONFIGURATION_FLAGS ConfigurationFlags{D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_NONE};
    D3D12_VIDEO_DECODE_TIER DecodeTier{D3D12_VIDEO_DECODE_TIER_NOT_SUPPORTED};
};

struct D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILE_COUNT {
    uint32_t NodeIndex{0};
    uint32_t ProfileCount{0};
};

struct D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILES {
    uint32_t NodeIndex{0};
    uint32_t ProfileCount{0};
    GUID* pProfiles{nullptr};
};

struct D3D12_FEATURE_DATA_VIDEO_DECODE_FORMAT_COUNT {
    uint32_t NodeIndex{0};
    D3D12_VIDEO_DECODE_CONFIGURATION Configuration{};
    uint32_t FormatCount{0};
};

struct D3D12_FEATURE_DATA_VIDEO_DECODE_FORMATS {
    uint32_t NodeIndex{0};
    D3D12_VIDEO_DECODE_CONFIGURATION Configuration{};
    uint32_t FormatCount{0};
    DXGI_FORMAT* pOutputFormats{nullptr};
};

struct D3D12_FEATURE_DATA_VIDEO_PROCESS_SUPPORT {
    uint32_t NodeIndex{0};
    D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC InputDesc{};
    D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC OutputDesc{};
    D3D12_VIDEO_PROCESS_FEATURE_FLAGS FeatureFlags{D3D12_VIDEO_PROCESS_FEATURE_FLAG_NONE};
    D3D12_VIDEO_PROCESS_DEINTERLACE_FLAGS DeinterlaceFlags{D3D12_VIDEO_PROCESS_DEINTERLACE_FLAG_NONE};
    D3D12_VIDEO_PROCESS_FILTER_RANGE FilterRanges[8]{};
};

// ============================================================================
// 5. Core Direct3D 12 Video COM Interfaces
// ============================================================================

class ID3D12Pageable : public ID3D12DeviceChild {};

class ID3D12VideoDecoder : public ID3D12Pageable {
public:
    virtual D3D12_VIDEO_DECODER_DESC GetDesc() = 0;
};

class ID3D12VideoDecoderHeap : public ID3D12Pageable {
public:
    virtual D3D12_VIDEO_DECODER_HEAP_DESC GetDesc() = 0;
};

class ID3D12VideoProcessor : public ID3D12DeviceChild {
public:
    virtual uint32_t GetNodeMask() = 0;
    virtual uint32_t GetNumInputStreamDescs() = 0;
    virtual D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC GetInputStreamDesc(uint32_t TypeIndex) = 0;
    virtual D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC GetOutputStreamDesc() = 0;
};

class ID3D12VideoDecodeCommandList : public ID3D12CommandList {
public:
    virtual int32_t Close() = 0;
    virtual int32_t Reset(ID3D12CommandAllocator* pAllocator) = 0;
    virtual void Clear() = 0;
    virtual void DecodeFrame(
        ID3D12VideoDecoder* pDecoder,
        const D3D12_VIDEO_DECODE_OUTPUT_STREAM_ARGUMENTS* pOutputArguments,
        const D3D12_VIDEO_DECODE_INPUT_STREAM_ARGUMENTS* pInputArguments
    ) = 0;
    virtual void ResourceBarrier(
        uint32_t NumBarriers,
        const D3D12_RESOURCE_BARRIER* pBarriers
    ) = 0;
};

class ID3D12VideoProcessCommandList : public ID3D12CommandList {
public:
    virtual int32_t Close() = 0;
    virtual int32_t Reset(ID3D12CommandAllocator* pAllocator) = 0;
    virtual void Clear() = 0;
    virtual void ProcessFrames(
        ID3D12VideoProcessor* pVideoProcessor,
        const D3D12_VIDEO_PROCESS_OUTPUT_STREAM_ARGUMENTS* pOutputArguments,
        uint32_t NumInputStreams,
        const D3D12_VIDEO_PROCESS_INPUT_STREAM_ARGUMENTS* pInputArguments
    ) = 0;
    virtual void ResourceBarrier(
        uint32_t NumBarriers,
        const D3D12_RESOURCE_BARRIER* pBarriers
    ) = 0;
};

class ID3D12VideoDevice : public IUnknown {
public:
    virtual int32_t CheckFeatureSupport(
        D3D12_FEATURE_VIDEO Feature,
        void* pFeatureSupportData,
        uint32_t FeatureSupportDataSize
    ) = 0;

    virtual int32_t CreateVideoDecoder(
        const D3D12_VIDEO_DECODER_DESC* pDesc,
        const IID& riid,
        void** ppVideoDecoder
    ) = 0;

    virtual int32_t CreateVideoDecoderHeap(
        const D3D12_VIDEO_DECODER_HEAP_DESC* pDesc,
        const IID& riid,
        void** ppVideoDecoderHeap
    ) = 0;

    virtual int32_t CreateVideoProcessor(
        uint32_t NodeMask,
        const D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC* pOutputStreamDesc,
        uint32_t NumInputStreamDescs,
        const D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC* pInputStreamDescs,
        const IID& riid,
        void** ppVideoProcessor
    ) = 0;
};

class ID3D12VideoDevice1 : public ID3D12VideoDevice {
public:
    virtual int32_t CreateVideoDecodeCommandList(
        uint32_t NodeMask,
        ID3D12CommandAllocator* pCommandAllocator,
        const IID& riid,
        void** ppCommandList
    ) = 0;

    virtual int32_t CreateVideoProcessCommandList(
        uint32_t NodeMask,
        ID3D12CommandAllocator* pCommandAllocator,
        const IID& riid,
        void** ppCommandList
    ) = 0;
};

// ============================================================================
// 6. Clean-Room Concrete Emulation Implementation
// ============================================================================

/**
 * @brief Concrete implementation of ID3D12VideoDecoder.
 */
class CVideoDecoder final : public ID3D12VideoDecoder {
private:
    std::atomic<uint32_t> m_refCount{1};
    ID3D12Device* m_pDevice{nullptr};
    D3D12_VIDEO_DECODER_DESC m_desc{};
    uint64_t m_decodedFramesCount{0};

public:
    CVideoDecoder(ID3D12Device* pDevice, const D3D12_VIDEO_DECODER_DESC& desc)
        : m_pDevice(pDevice), m_desc(desc) {
        if (m_pDevice) m_pDevice->AddRef();
    }

    ~CVideoDecoder() override {
        if (m_pDevice) m_pDevice->Release();
    }

    // IUnknown
    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild ||
            riid == IID_ID3D12Pageable || riid == IID_ID3D12VideoDecoder) {
            *ppv = static_cast<ID3D12VideoDecoder*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262; // E_NOINTERFACE
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    // ID3D12Object / ID3D12DeviceChild
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice || !m_pDevice) return -1;
        *ppDevice = m_pDevice;
        m_pDevice->AddRef();
        return 0;
    }

    // ID3D12VideoDecoder
    D3D12_VIDEO_DECODER_DESC GetDesc() override { return m_desc; }
    
    void RecordDecodedFrame() noexcept { ++m_decodedFramesCount; }
    [[nodiscard]] uint64_t GetDecodedFramesCount() const noexcept { return m_decodedFramesCount; }
};

/**
 * @brief Concrete implementation of ID3D12VideoDecoderHeap.
 */
class CVideoDecoderHeap final : public ID3D12VideoDecoderHeap {
private:
    std::atomic<uint32_t> m_refCount{1};
    ID3D12Device* m_pDevice{nullptr};
    D3D12_VIDEO_DECODER_HEAP_DESC m_desc{};
    size_t m_allocationSizeBytes{0};

public:
    CVideoDecoderHeap(ID3D12Device* pDevice, const D3D12_VIDEO_DECODER_HEAP_DESC& desc)
        : m_pDevice(pDevice), m_desc(desc) {
        if (m_pDevice) m_pDevice->AddRef();
        // Calculate memory allocation based on picture buffers and resolution
        size_t bpp = (desc.Format == DXGI_FORMAT_P010) ? 2 : 1;
        size_t lumaSize = static_cast<size_t>(desc.DecodeWidth) * desc.DecodeHeight * bpp;
        size_t chromaSize = lumaSize / 2;
        size_t frameSize = lumaSize + chromaSize;
        m_allocationSizeBytes = frameSize * desc.MaxDecodePictureBufferCount + (4 * 1024 * 1024); // 4MB scratch
    }

    ~CVideoDecoderHeap() override {
        if (m_pDevice) m_pDevice->Release();
    }

    // IUnknown
    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild ||
            riid == IID_ID3D12Pageable || riid == IID_ID3D12VideoDecoderHeap) {
            *ppv = static_cast<ID3D12VideoDecoderHeap*>(this);
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

    // ID3D12Object / ID3D12DeviceChild
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice || !m_pDevice) return -1;
        *ppDevice = m_pDevice;
        m_pDevice->AddRef();
        return 0;
    }

    // ID3D12VideoDecoderHeap
    D3D12_VIDEO_DECODER_HEAP_DESC GetDesc() override { return m_desc; }
    [[nodiscard]] size_t GetAllocationSizeBytes() const noexcept { return m_allocationSizeBytes; }
};

/**
 * @brief Concrete implementation of ID3D12VideoProcessor.
 */
class CVideoProcessor final : public ID3D12VideoProcessor {
private:
    std::atomic<uint32_t> m_refCount{1};
    ID3D12Device* m_pDevice{nullptr};
    uint32_t m_nodeMask{0};
    D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC m_outputDesc{};
    std::vector<D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC> m_inputDescs;

public:
    CVideoProcessor(
        ID3D12Device* pDevice,
        uint32_t nodeMask,
        const D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC& outputDesc,
        const std::vector<D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC>& inputDescs
    ) : m_pDevice(pDevice), m_nodeMask(nodeMask), m_outputDesc(outputDesc), m_inputDescs(inputDescs) {
        if (m_pDevice) m_pDevice->AddRef();
    }

    ~CVideoProcessor() override {
        if (m_pDevice) m_pDevice->Release();
    }

    // IUnknown
    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild ||
            riid == IID_ID3D12VideoProcessor) {
            *ppv = static_cast<ID3D12VideoProcessor*>(this);
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

    // ID3D12Object / ID3D12DeviceChild
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice || !m_pDevice) return -1;
        *ppDevice = m_pDevice;
        m_pDevice->AddRef();
        return 0;
    }

    // ID3D12VideoProcessor
    uint32_t GetNodeMask() override { return m_nodeMask; }
    uint32_t GetNumInputStreamDescs() override { return static_cast<uint32_t>(m_inputDescs.size()); }
    D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC GetInputStreamDesc(uint32_t TypeIndex) override {
        if (TypeIndex < m_inputDescs.size()) return m_inputDescs[TypeIndex];
        return D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC{};
    }
    D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC GetOutputStreamDesc() override { return m_outputDesc; }
};

/**
 * @brief Concrete implementation of ID3D12VideoDecodeCommandList.
 */
class CVideoDecodeCommandList final : public ID3D12VideoDecodeCommandList {
private:
    std::atomic<uint32_t> m_refCount{1};
    ID3D12Device* m_pDevice{nullptr};
    ID3D12CommandAllocator* m_pAllocator{nullptr};
    bool m_isClosed{false};
    uint32_t m_recordedDecodes{0};
    uint64_t m_processedBitstreamBytes{0};

public:
    CVideoDecodeCommandList(ID3D12Device* pDevice, ID3D12CommandAllocator* pAllocator)
        : m_pDevice(pDevice), m_pAllocator(pAllocator) {
        if (m_pDevice) m_pDevice->AddRef();
        if (m_pAllocator) m_pAllocator->AddRef();
    }

    ~CVideoDecodeCommandList() override {
        if (m_pAllocator) m_pAllocator->Release();
        if (m_pDevice) m_pDevice->Release();
    }

    // IUnknown
    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild ||
            riid == IID_ID3D12CommandList || riid == IID_ID3D12VideoDecodeCommandList) {
            *ppv = static_cast<ID3D12VideoDecodeCommandList*>(this);
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

    // ID3D12Object / ID3D12DeviceChild
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice || !m_pDevice) return -1;
        *ppDevice = m_pDevice;
        m_pDevice->AddRef();
        return 0;
    }

    // ID3D12CommandList
    D3D12_COMMAND_LIST_TYPE GetType() override {
        return static_cast<D3D12_COMMAND_LIST_TYPE>(4); // D3D12_COMMAND_LIST_TYPE_VIDEO_DECODE
    }

    // ID3D12VideoDecodeCommandList
    int32_t Close() override {
        m_isClosed = true;
        return 0;
    }

    int32_t Reset(ID3D12CommandAllocator* pAllocator) override {
        if (!pAllocator) return -1;
        if (m_pAllocator) m_pAllocator->Release();
        m_pAllocator = pAllocator;
        m_pAllocator->AddRef();
        m_isClosed = false;
        m_recordedDecodes = 0;
        m_processedBitstreamBytes = 0;
        return 0;
    }

    void Clear() override {
        m_recordedDecodes = 0;
        m_processedBitstreamBytes = 0;
    }

    void DecodeFrame(
        ID3D12VideoDecoder* pDecoder,
        const D3D12_VIDEO_DECODE_OUTPUT_STREAM_ARGUMENTS* pOutputArguments,
        const D3D12_VIDEO_DECODE_INPUT_STREAM_ARGUMENTS* pInputArguments
    ) override {
        if (!pDecoder || !pOutputArguments || !pInputArguments) return;
        m_recordedDecodes++;
        m_processedBitstreamBytes += pInputArguments->CompressedBitstream.Size;

        auto* decoderImpl = dynamic_cast<CVideoDecoder*>(pDecoder);
        if (decoderImpl) {
            decoderImpl->RecordDecodedFrame();
        }
    }

    void ResourceBarrier(
        uint32_t,
        const D3D12_RESOURCE_BARRIER*
    ) override {
        // Track barrier transitions in recording state
    }

    [[nodiscard]] bool IsClosed() const noexcept { return m_isClosed; }
    [[nodiscard]] uint32_t GetRecordedDecodes() const noexcept { return m_recordedDecodes; }
    [[nodiscard]] uint64_t GetProcessedBitstreamBytes() const noexcept { return m_processedBitstreamBytes; }
};

/**
 * @brief Concrete implementation of ID3D12VideoProcessCommandList.
 */
class CVideoProcessCommandList final : public ID3D12VideoProcessCommandList {
private:
    std::atomic<uint32_t> m_refCount{1};
    ID3D12Device* m_pDevice{nullptr};
    ID3D12CommandAllocator* m_pAllocator{nullptr};
    bool m_isClosed{false};
    uint32_t m_recordedProcesses{0};

public:
    CVideoProcessCommandList(ID3D12Device* pDevice, ID3D12CommandAllocator* pAllocator)
        : m_pDevice(pDevice), m_pAllocator(pAllocator) {
        if (m_pDevice) m_pDevice->AddRef();
        if (m_pAllocator) m_pAllocator->AddRef();
    }

    ~CVideoProcessCommandList() override {
        if (m_pAllocator) m_pAllocator->Release();
        if (m_pDevice) m_pDevice->Release();
    }

    // IUnknown
    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12Object || riid == IID_ID3D12DeviceChild ||
            riid == IID_ID3D12CommandList || riid == IID_ID3D12VideoProcessCommandList) {
            *ppv = static_cast<ID3D12VideoProcessCommandList*>(this);
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

    // ID3D12Object / ID3D12DeviceChild
    int32_t GetPrivateData(const IID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const IID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const IID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }
    int32_t GetDevice(const IID&, void** ppDevice) override {
        if (!ppDevice || !m_pDevice) return -1;
        *ppDevice = m_pDevice;
        m_pDevice->AddRef();
        return 0;
    }

    // ID3D12CommandList
    D3D12_COMMAND_LIST_TYPE GetType() override {
        return static_cast<D3D12_COMMAND_LIST_TYPE>(5); // D3D12_COMMAND_LIST_TYPE_VIDEO_PROCESS
    }

    // ID3D12VideoProcessCommandList
    int32_t Close() override {
        m_isClosed = true;
        return 0;
    }

    int32_t Reset(ID3D12CommandAllocator* pAllocator) override {
        if (!pAllocator) return -1;
        if (m_pAllocator) m_pAllocator->Release();
        m_pAllocator = pAllocator;
        m_pAllocator->AddRef();
        m_isClosed = false;
        m_recordedProcesses = 0;
        return 0;
    }

    void Clear() override {
        m_recordedProcesses = 0;
    }

    void ProcessFrames(
        ID3D12VideoProcessor* pVideoProcessor,
        const D3D12_VIDEO_PROCESS_OUTPUT_STREAM_ARGUMENTS* pOutputArguments,
        uint32_t NumInputStreams,
        const D3D12_VIDEO_PROCESS_INPUT_STREAM_ARGUMENTS* pInputArguments
    ) override {
        if (!pVideoProcessor || !pOutputArguments || NumInputStreams == 0 || !pInputArguments) return;
        m_recordedProcesses++;
    }

    void ResourceBarrier(
        uint32_t,
        const D3D12_RESOURCE_BARRIER*
    ) override {}

    [[nodiscard]] bool IsClosed() const noexcept { return m_isClosed; }
    [[nodiscard]] uint32_t GetRecordedProcesses() const noexcept { return m_recordedProcesses; }
};

/**
 * @brief Concrete implementation of ID3D12VideoDevice & ID3D12VideoDevice1.
 */
class CVideoDevice final : public ID3D12VideoDevice1 {
private:
    std::atomic<uint32_t> m_refCount{1};
    ID3D12Device* m_pDevice{nullptr};
    std::vector<GUID> m_supportedProfiles;
    std::vector<DXGI_FORMAT> m_supportedFormats;

public:
    explicit CVideoDevice(ID3D12Device* pDevice)
        : m_pDevice(pDevice) {
        if (m_pDevice) m_pDevice->AddRef();

        // Register Sovereign hardware accelerated decode profiles
        m_supportedProfiles = {
            D3D12_VIDEO_DECODE_PROFILE_H264,
            D3D12_VIDEO_DECODE_PROFILE_HEVC_MAIN,
            D3D12_VIDEO_DECODE_PROFILE_HEVC_MAIN10,
            D3D12_VIDEO_DECODE_PROFILE_VP9,
            D3D12_VIDEO_DECODE_PROFILE_VP9_10BIT,
            D3D12_VIDEO_DECODE_PROFILE_AV1_PROFILE0,
            D3D12_VIDEO_DECODE_PROFILE_MPEG2,
            D3D12_VIDEO_DECODE_PROFILE_VC1
        };

        // Standard Video Color & Texture Formats
        m_supportedFormats = {
            DXGI_FORMAT_NV12,
            DXGI_FORMAT_P010,
            DXGI_FORMAT_YUY2,
            DXGI_FORMAT_AYUV,
            DXGI_FORMAT_B8G8R8A8_UNORM,
            DXGI_FORMAT_R8G8B8A8_UNORM,
            DXGI_FORMAT_R10G10B10A2_UNORM
        };
    }

    ~CVideoDevice() override {
        if (m_pDevice) m_pDevice->Release();
    }

    // IUnknown
    int32_t QueryInterface(const IID& riid, void** ppv) override {
        if (!ppv) return -1;
        if (riid == IID_IUnknown || riid == IID_ID3D12VideoDevice || riid == IID_ID3D12VideoDevice1) {
            *ppv = static_cast<ID3D12VideoDevice1*>(this);
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

    // ID3D12VideoDevice
    int32_t CheckFeatureSupport(
        D3D12_FEATURE_VIDEO Feature,
        void* pFeatureSupportData,
        uint32_t FeatureSupportDataSize
    ) override {
        if (!pFeatureSupportData) return -1;

        switch (Feature) {
            case D3D12_FEATURE_VIDEO_DECODE_PROFILE_COUNT: {
                if (FeatureSupportDataSize < sizeof(D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILE_COUNT)) return -1;
                auto* data = static_cast<D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILE_COUNT*>(pFeatureSupportData);
                data->ProfileCount = static_cast<uint32_t>(m_supportedProfiles.size());
                return 0;
            }

            case D3D12_FEATURE_VIDEO_DECODE_PROFILES: {
                if (FeatureSupportDataSize < sizeof(D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILES)) return -1;
                auto* data = static_cast<D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILES*>(pFeatureSupportData);
                uint32_t count = std::min(data->ProfileCount, static_cast<uint32_t>(m_supportedProfiles.size()));
                for (uint32_t i = 0; i < count; ++i) {
                    data->pProfiles[i] = m_supportedProfiles[i];
                }
                return 0;
            }

            case D3D12_FEATURE_VIDEO_DECODE_SUPPORT: {
                if (FeatureSupportDataSize < sizeof(D3D12_FEATURE_DATA_VIDEO_DECODE_SUPPORT)) return -1;
                auto* data = static_cast<D3D12_FEATURE_DATA_VIDEO_DECODE_SUPPORT*>(pFeatureSupportData);
                
                // Validate if profile is in supported list
                bool profileOk = false;
                for (const auto& prof : m_supportedProfiles) {
                    if (prof == data->Configuration.DecodeProfile) {
                        profileOk = true;
                        break;
                    }
                }

                if (profileOk && data->Width <= 7680 && data->Height <= 4320) { // Up to 8K
                    data->SupportFlags = D3D12_VIDEO_DECODE_SUPPORT_FLAG_SUPPORTED;
                    data->ConfigurationFlags = static_cast<D3D12_VIDEO_DECODE_CONFIGURATION_FLAGS>(
                        D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_HEIGHT_ALIGNMENT_MULTIPLE_OF_32 |
                        D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_POST_PROCESSING_SUPPORTED
                    );
                    data->DecodeTier = D3D12_VIDEO_DECODE_TIER_3; // Full independent hardware video queue
                } else {
                    data->SupportFlags = D3D12_VIDEO_DECODE_SUPPORT_FLAG_NONE;
                    data->DecodeTier = D3D12_VIDEO_DECODE_TIER_NOT_SUPPORTED;
                }
                return 0;
            }

            case D3D12_FEATURE_VIDEO_DECODE_FORMAT_COUNT: {
                if (FeatureSupportDataSize < sizeof(D3D12_FEATURE_DATA_VIDEO_DECODE_FORMAT_COUNT)) return -1;
                auto* data = static_cast<D3D12_FEATURE_DATA_VIDEO_DECODE_FORMAT_COUNT*>(pFeatureSupportData);
                data->FormatCount = static_cast<uint32_t>(m_supportedFormats.size());
                return 0;
            }

            case D3D12_FEATURE_VIDEO_DECODE_FORMATS: {
                if (FeatureSupportDataSize < sizeof(D3D12_FEATURE_DATA_VIDEO_DECODE_FORMATS)) return -1;
                auto* data = static_cast<D3D12_FEATURE_DATA_VIDEO_DECODE_FORMATS*>(pFeatureSupportData);
                uint32_t count = std::min(data->FormatCount, static_cast<uint32_t>(m_supportedFormats.size()));
                for (uint32_t i = 0; i < count; ++i) {
                    data->pOutputFormats[i] = m_supportedFormats[i];
                }
                return 0;
            }

            case D3D12_FEATURE_VIDEO_PROCESS_SUPPORT: {
                if (FeatureSupportDataSize < sizeof(D3D12_FEATURE_DATA_VIDEO_PROCESS_SUPPORT)) return -1;
                auto* data = static_cast<D3D12_FEATURE_DATA_VIDEO_PROCESS_SUPPORT*>(pFeatureSupportData);
                data->FeatureFlags = static_cast<D3D12_VIDEO_PROCESS_FEATURE_FLAGS>(
                    D3D12_VIDEO_PROCESS_FEATURE_FLAG_ALPHA_FILL |
                    D3D12_VIDEO_PROCESS_FEATURE_FLAG_ALPHA_BLENDING |
                    D3D12_VIDEO_PROCESS_FEATURE_FLAG_ROTATION |
                    D3D12_VIDEO_PROCESS_FEATURE_FLAG_FLIP |
                    D3D12_VIDEO_PROCESS_FEATURE_FLAG_PIXEL_ASPECT_RATIO
                );
                data->DeinterlaceFlags = D3D12_VIDEO_PROCESS_DEINTERLACE_FLAG_BOB;
                
                // Configure standard filter ranges
                for (int i = 0; i < 8; ++i) {
                    data->FilterRanges[i].Minimum = -100;
                    data->FilterRanges[i].Maximum = 100;
                    data->FilterRanges[i].Default = 0;
                    data->FilterRanges[i].Multiplier = 1.0f;
                }
                return 0;
            }

            default:
                return -1;
        }
    }

    int32_t CreateVideoDecoder(
        const D3D12_VIDEO_DECODER_DESC* pDesc,
        const IID& riid,
        void** ppVideoDecoder
    ) override {
        if (!pDesc || !ppVideoDecoder) return -1;
        auto* decoder = new CVideoDecoder(m_pDevice, *pDesc);
        int32_t hr = decoder->QueryInterface(riid, ppVideoDecoder);
        decoder->Release();
        return hr;
    }

    int32_t CreateVideoDecoderHeap(
        const D3D12_VIDEO_DECODER_HEAP_DESC* pDesc,
        const IID& riid,
        void** ppVideoDecoderHeap
    ) override {
        if (!pDesc || !ppVideoDecoderHeap) return -1;
        auto* heap = new CVideoDecoderHeap(m_pDevice, *pDesc);
        int32_t hr = heap->QueryInterface(riid, ppVideoDecoderHeap);
        heap->Release();
        return hr;
    }

    int32_t CreateVideoProcessor(
        uint32_t NodeMask,
        const D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC* pOutputStreamDesc,
        uint32_t NumInputStreamDescs,
        const D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC* pInputStreamDescs,
        const IID& riid,
        void** ppVideoProcessor
    ) override {
        if (!pOutputStreamDesc || !ppVideoProcessor) return -1;
        std::vector<D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC> inputs;
        if (pInputStreamDescs && NumInputStreamDescs > 0) {
            inputs.assign(pInputStreamDescs, pInputStreamDescs + NumInputStreamDescs);
        }

        auto* proc = new CVideoProcessor(m_pDevice, NodeMask, *pOutputStreamDesc, inputs);
        int32_t hr = proc->QueryInterface(riid, ppVideoProcessor);
        proc->Release();
        return hr;
    }

    // ID3D12VideoDevice1
    int32_t CreateVideoDecodeCommandList(
        uint32_t,
        ID3D12CommandAllocator* pCommandAllocator,
        const IID& riid,
        void** ppCommandList
    ) override {
        if (!pCommandAllocator || !ppCommandList) return -1;
        auto* cmdList = new CVideoDecodeCommandList(m_pDevice, pCommandAllocator);
        int32_t hr = cmdList->QueryInterface(riid, ppCommandList);
        cmdList->Release();
        return hr;
    }

    int32_t CreateVideoProcessCommandList(
        uint32_t,
        ID3D12CommandAllocator* pCommandAllocator,
        const IID& riid,
        void** ppCommandList
    ) override {
        if (!pCommandAllocator || !ppCommandList) return -1;
        auto* cmdList = new CVideoProcessCommandList(m_pDevice, pCommandAllocator);
        int32_t hr = cmdList->QueryInterface(riid, ppCommandList);
        cmdList->Release();
        return hr;
    }
};

/**
 * @brief Clean-room factory function to create a D3D12 Video Device from an ID3D12Device.
 */
inline int32_t D3D12CreateVideoDevice(
    ID3D12Device* pDevice,
    const IID& riid,
    void** ppVideoDevice
) {
    if (!pDevice || !ppVideoDevice) return -1;
    auto* videoDev = new CVideoDevice(pDevice);
    int32_t hr = videoDev->QueryInterface(riid, ppVideoDevice);
    videoDev->Release();
    return hr;
}

inline void InitializeD3D12VideoExports() {
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("d3d12.dll", "D3D12CreateVideoDevice", reinterpret_cast<void*>(&D3D12CreateVideoDevice));
    ldr.registerExport("d3d12video.dll", "D3D12CreateVideoDevice", reinterpret_cast<void*>(&D3D12CreateVideoDevice));
}

} // namespace micant::d3d12video
