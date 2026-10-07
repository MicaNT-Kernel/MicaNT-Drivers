#pragma once

/**
 * @file mfplat.hpp
 * @brief Clean-Room Windows Media Foundation Platform & Pipeline Architecture
 *        (mfplat.dll / mf.dll / mfreadwrite.dll).
 *
 * Implements Microsoft Media Foundation core platform, attribute stores, memory buffers,
 * media samples, byte streams, async work queues, event queues, Media Foundation Transforms (MFT),
 * Source Reader, Sink Writer, and Media Session topology architecture.
 *
 * Referenced exclusively from Microsoft's MIT-licensed win32metadata / Media Foundation specifications.
 * 100% clean-room engineering. Zero proprietary, leaked, or decompiled code.
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <chrono>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ole32.hpp"
#include "ldr.hpp"

namespace micant::mf {

// ============================================================================
// 1. Media Foundation Basic Types, Enums & GUIDs
// ============================================================================

constexpr uint32_t MF_SDK_VERSION   = 0x0002;
constexpr uint32_t MF_API_VERSION   = 0x0070;
constexpr uint32_t MF_VERSION       = (MF_SDK_VERSION << 16) | MF_API_VERSION;

constexpr uint32_t MFSTARTUP_NOSOCKET = 0x1;
constexpr uint32_t MFSTARTUP_FULL     = 0x0;

using LONGLONG = int64_t;
using MFTIME   = int64_t;

struct PROPVARIANT;

enum MF_ATTRIBUTE_TYPE {
    MF_ATTRIBUTE_UINT32     = 19,
    MF_ATTRIBUTE_UINT64     = 21,
    MF_ATTRIBUTE_DOUBLE     = 5,
    MF_ATTRIBUTE_GUID       = 72,
    MF_ATTRIBUTE_STRING     = 31,
    MF_ATTRIBUTE_BLOB       = 65,
    MF_ATTRIBUTE_IUNKNOWN   = 13
};

enum MF_ATTRIBUTES_MATCH_TYPE {
    MF_ATTRIBUTES_MATCH_OUR_ITEMS       = 0,
    MF_ATTRIBUTES_MATCH_OTHERS_ITEMS    = 1,
    MF_ATTRIBUTES_MATCH_INTERSECTION    = 2,
    MF_ATTRIBUTES_MATCH_SMALLER         = 3,
    MF_ATTRIBUTES_MATCH_ALL             = 4
};

enum MediaEventType {
    MEUnknown                   = 0,
    MEError                     = 1,
    MEExtendedType              = 2,
    MENonFatalError             = 3,
    MESessionTopologySet        = 101,
    MESessionTopologiesCleared  = 102,
    MESessionStarted            = 103,
    MESessionPaused             = 104,
    MESessionStopped            = 105,
    MESessionClosed             = 106,
    MESessionEnded              = 107,
    MESessionRateChanged        = 108,
    MESessionScrubSampleComplete = 109,
    MESessionCapabilitiesChanged = 110,
    MESessionTopologyStatus     = 111,
    MESessionNotifyPresentationTime = 112,
    MENewPresentation           = 113,
    MELicenseAcquisitionStart   = 114,
    MELicenseAcquisitionCompleted = 115,
    MEIndividualizationStart    = 116,
    MEIndividualizationCompleted = 117,
    MEEnclosureStart            = 118,
    MEEnclosureCompleted        = 119,
    MESourceStarted             = 120,
    MEStreamStarted             = 121,
    MESourceSeeked              = 122,
    MEStreamSeeked              = 123,
    MENewStream                 = 124,
    MEUpdatedStream             = 125,
    MESourceStopped             = 126,
    MEStreamStopped             = 127,
    MESourcePaused              = 128,
    MEStreamPaused              = 129,
    MEEndOfPresentation         = 130,
    MEEndOfStream               = 131,
    MEMediaSample               = 132,
    MEStreamTick                = 133,
    METransformHaveOutput       = 201,
    METransformNeedInput        = 202,
    METransformDrainComplete    = 203,
    METransformMarker           = 204
};

enum MFT_MESSAGE_TYPE {
    MFT_MESSAGE_COMMAND_FLUSH           = 0x00000000,
    MFT_MESSAGE_COMMAND_DRAIN           = 0x00000001,
    MFT_MESSAGE_SET_D3D_MANAGER         = 0x00000002,
    MFT_MESSAGE_DROP_SAMPLES            = 0x00000003,
    MFT_MESSAGE_COMMAND_TICK            = 0x00000004,
    MFT_MESSAGE_NOTIFY_BEGIN_STREAMING  = 0x10000000,
    MFT_MESSAGE_NOTIFY_END_STREAMING    = 0x10000001,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM    = 0x10000002,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM  = 0x10000003
};

enum MF_TOPOLOGY_TYPE {
    MF_TOPOLOGY_OUTPUT_NODE         = 0,
    MF_TOPOLOGY_SOURCESTREAM_NODE   = 1,
    MF_TOPOLOGY_TRANSFORM_NODE      = 2,
    MF_TOPOLOGY_TEE_NODE            = 3
};

enum MF_SOURCE_READER_FLAG {
    MF_SOURCE_READERF_ERROR                     = 0x00000001,
    MF_SOURCE_READERF_ENDOFSTREAM               = 0x00000002,
    MF_SOURCE_READERF_NEWSTREAM                 = 0x00000004,
    MF_SOURCE_READERF_NATIVEMEDIATYPETRUNCATED  = 0x00000008,
    MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED   = 0x00000010,
    MF_SOURCE_READERF_STREAMTICK                = 0x00000100,
    MF_SOURCE_READERF_ALLEFFECTSREMOVED         = 0x00000200
};

enum MF_FILE_ACCESS_MODE {
    MF_ACCESSMODE_READ      = 1,
    MF_ACCESSMODE_WRITE     = 2,
    MF_ACCESSMODE_READWRITE = 3
};

enum MF_FILE_OPEN_MODE {
    MF_OPENMODE_FAIL_IF_NOT_EXIST   = 0,
    MF_OPENMODE_FAIL_IF_EXIST       = 1,
    MF_OPENMODE_RESET_IF_EXIST      = 2,
    MF_OPENMODE_APPEND_IF_EXIST     = 3,
    MF_OPENMODE_DELETE_IF_EXIST     = 4
};

enum MF_FILE_FLAGS {
    MF_FILEFLAGS_NONE           = 0x00000000,
};

// Media Foundation Error Codes
inline constexpr int32_t MF_E_PLATFORM_NOT_INITIALIZED = static_cast<int32_t>(0xC00D36B0L);
inline constexpr int32_t MF_E_BUFFERTOOSMALL           = static_cast<int32_t>(0xC00D36B1L);
inline constexpr int32_t MF_E_INVALIDREQUEST           = static_cast<int32_t>(0xC00D36B2L);
inline constexpr int32_t MF_E_INVALIDSTREAMNUMBER      = static_cast<int32_t>(0xC00D36B3L);
inline constexpr int32_t MF_E_INVALIDMEDIATYPE         = static_cast<int32_t>(0xC00D36B4L);
inline constexpr int32_t MF_E_NOTACCEPTING             = static_cast<int32_t>(0xC00D36B5L);
inline constexpr int32_t MF_E_NOT_INITIALIZED          = static_cast<int32_t>(0xC00D36B6L);
inline constexpr int32_t MF_E_UNSUPPORTED_REPRESENTATION = static_cast<int32_t>(0xC00D36B7L);
inline constexpr int32_t MF_E_NO_MORE_TYPES            = static_cast<int32_t>(0xC00D36B9L);
inline constexpr int32_t MF_E_TRANSFORM_CANNOT_CHANGE_MEDIATYPE_WHILE_PROCESSING = static_cast<int32_t>(0xC00D36BDL);
inline constexpr int32_t MF_E_TRANSFORM_TYPE_NOT_SET   = static_cast<int32_t>(0xC00D36BEL);
inline constexpr int32_t MF_E_TRANSFORM_NEED_MORE_INPUT = static_cast<int32_t>(0xC00D36BFL);
inline constexpr int32_t MF_E_TRANSFORM_STREAM_CHANGE  = static_cast<int32_t>(0xC00D36D2L);

struct GuidLess {
    bool operator()(const GUID& a, const GUID& b) const noexcept {
        if (a.Data1 != b.Data1) return a.Data1 < b.Data1;
        if (a.Data2 != b.Data2) return a.Data2 < b.Data2;
        if (a.Data3 != b.Data3) return a.Data3 < b.Data3;
        return std::memcmp(a.Data4, b.Data4, sizeof(a.Data4)) < 0;
    }
};

// GUID Constants
// Major Types
inline constexpr GUID MFMediaType_Audio =
    { 0x73647561, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFMediaType_Video =
    { 0x73646976, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };

// Audio Subtypes
inline constexpr GUID MFAudioFormat_PCM =
    { 0x00000001, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFAudioFormat_Float =
    { 0x00000003, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFAudioFormat_AAC =
    { 0x00001610, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFAudioFormat_MP3 =
    { 0x00000055, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };

// Video Subtypes
inline constexpr GUID MFVideoFormat_RGB32 =
    { 0x00000016, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFVideoFormat_ARGB32 =
    { 0x00000015, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFVideoFormat_NV12 =
    { 0x3231564E, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFVideoFormat_YUY2 =
    { 0x32595559, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFVideoFormat_H264 =
    { 0x34363248, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFVideoFormat_HEVC =
    { 0x43564548, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };

// Attribute Keys
inline constexpr GUID MF_MT_MAJOR_TYPE =
    { 0x48EBA18E, 0xF8C9, 0x4687, { 0xBF, 0x11, 0x0A, 0x74, 0xC9, 0xF9, 0x6A, 0x8F } };
inline constexpr GUID MF_MT_SUBTYPE =
    { 0xF7E34C9A, 0x42E8, 0x4714, { 0xB7, 0x4B, 0xCB, 0x29, 0xD7, 0x2C, 0x35, 0xE5 } };
inline constexpr GUID MF_MT_ALL_SAMPLES_INDEPENDENT =
    { 0xC9173739, 0x5E56, 0x461C, { 0xB7, 0x13, 0x46, 0xFB, 0x99, 0x5C, 0xB9, 0x5F } };
inline constexpr GUID MF_MT_FIXED_SIZE_SAMPLES =
    { 0x3A0F010B, 0x1923, 0x470F, { 0x83, 0x77, 0xFE, 0x5F, 0x89, 0xAC, 0x8E, 0xDF } };
inline constexpr GUID MF_MT_SAMPLE_SIZE =
    { 0xDADADADF, 0x52FC, 0x4757, { 0x9E, 0xFE, 0x89, 0xB7, 0x6D, 0x1D, 0x0C, 0xEB } };
inline constexpr GUID MF_MT_AUDIO_NUM_CHANNELS =
    { 0x372215F1, 0x02DB, 0x4F4E, { 0xAC, 0x65, 0xBF, 0x0E, 0x62, 0x60, 0xAC, 0x63 } };
inline constexpr GUID MF_MT_AUDIO_SAMPLES_PER_SECOND =
    { 0x5FAEEAE7, 0x0290, 0x4C31, { 0x9E, 0x88, 0xC6, 0xF1, 0x22, 0x97, 0x76, 0xD8 } };
inline constexpr GUID MF_MT_AUDIO_BLOCK_ALIGNMENT =
    { 0x322DE3E4, 0x821D, 0x47E9, { 0x86, 0x1E, 0x07, 0x4B, 0x69, 0x3B, 0x69, 0x30 } };
inline constexpr GUID MF_MT_AUDIO_AVG_BYTES_PER_SECOND =
    { 0x1AAB75C8, 0xCFEF, 0x451C, { 0xAB, 0x95, 0xAC, 0x03, 0x4B, 0x8E, 0x17, 0x31 } };
inline constexpr GUID MF_MT_AUDIO_BITS_PER_SAMPLE =
    { 0xF2DEB57F, 0x4009, 0x4297, { 0x81, 0x33, 0x3D, 0xF3, 0x41, 0x32, 0xC7, 0x63 } };
inline constexpr GUID MF_MT_FRAME_SIZE =
    { 0x1652C33D, 0xD6B2, 0x4012, { 0xB8, 0x34, 0x72, 0x03, 0x08, 0x49, 0xA3, 0x7D } };
inline constexpr GUID MF_MT_FRAME_RATE =
    { 0xC456AC37, 0x5CD0, 0x4493, { 0x81, 0x7C, 0x7D, 0x3E, 0x4A, 0x46, 0xEC, 0xBE } };
inline constexpr GUID MF_MT_PIXEL_ASPECT_RATIO =
    { 0xC637645F, 0x8D08, 0x4CE5, { 0xBE, 0xAC, 0x69, 0x34, 0x4D, 0xE6, 0x6D, 0x60 } };
inline constexpr GUID MF_MT_INTERLACE_MODE =
    { 0xE2724BB8, 0xE676, 0x4806, { 0xB4, 0xB2, 0xA8, 0xD6, 0xEF, 0xB4, 0x4C, 0xCE } };

// Transform Categories
inline constexpr GUID MFT_CATEGORY_VIDEO_DECODER =
    { 0xD6C020DE, 0xDB66, 0x4D49, { 0x80, 0x9E, 0xD1, 0x39, 0x42, 0xE3, 0x14, 0xA8 } };
inline constexpr GUID MFT_CATEGORY_VIDEO_ENCODER =
    { 0xF79EAC7D, 0xE545, 0x4387, { 0xBD, 0xEE, 0xD6, 0x47, 0xD7, 0xBD, 0xE4, 0x2A } };
inline constexpr GUID MFT_CATEGORY_AUDIO_DECODER =
    { 0x9EA37439, 0x9991, 0x4E63, { 0x88, 0x8A, 0x00, 0xD9, 0x5D, 0x60, 0xCE, 0xEB } };
inline constexpr GUID MFT_CATEGORY_AUDIO_ENCODER =
    { 0x91C64EF0, 0x59C4, 0x4AB8, { 0x95, 0x4E, 0xDC, 0xBC, 0x8D, 0x87, 0x73, 0xEC } };
inline constexpr GUID MFT_CATEGORY_VIDEO_EFFECT =
    { 0x12E17521, 0x1156, 0x4B92, { 0x94, 0x29, 0x30, 0x45, 0x11, 0x65, 0x94, 0xE8 } };
inline constexpr GUID MFT_CATEGORY_AUDIO_EFFECT =
    { 0x11064C48, 0x3648, 0x4ED0, { 0x93, 0x2E, 0x05, 0xCE, 0x8A, 0xC8, 0x11, 0x61 } };

// Built-in Transform CLSIDs
inline constexpr GUID CLSID_CMSH264DecoderMFT =
    { 0x62CE7E72, 0x4C71, 0x4D20, { 0xB1, 0x5D, 0x25, 0x0E, 0x49, 0xD9, 0xE8, 0xD5 } };
inline constexpr GUID CLSID_CMSAACDecMFT =
    { 0x32D16CED, 0x4173, 0x4A74, { 0x88, 0x40, 0xC4, 0xE0, 0x70, 0x76, 0x4C, 0x11 } };
inline constexpr GUID CLSID_CColorConvertDMO =
    { 0x98230571, 0x0087, 0x4204, { 0xB0, 0x20, 0x32, 0x82, 0x53, 0x8E, 0x57, 0xD3 } };
inline constexpr GUID CLSID_CResamplerMediaObject =
    { 0xF447FF64, 0x1A6E, 0x4802, { 0xBE, 0x55, 0x0B, 0xC2, 0xC1, 0xA3, 0x05, 0xC3 } };

// Forward declarations
struct IMFAttributes;
struct IMFMediaBuffer;
struct IMFSample;
struct IMFMediaType;
struct IMFByteStream;
struct IMFAsyncResult;
struct IMFAsyncCallback;
struct IMFMediaEvent;
struct IMFMediaEventQueue;
struct IMFTransform;
struct IMFSourceReader;
struct IMFSinkWriter;
struct IMFMediaSession;
struct IMFTopology;
struct IMFTopologyNode;

// ============================================================================
// 2. Interfaces
// ============================================================================

struct IMFAttributes : public ole32::IUnknown {
    virtual int32_t __stdcall GetItem(const GUID& guidKey, void* pValue) = 0;
    virtual int32_t __stdcall GetItemType(const GUID& guidKey, MF_ATTRIBUTE_TYPE* pType) = 0;
    virtual int32_t __stdcall CompareItem(const GUID& guidKey, const void* Value, int32_t* pbResult) = 0;
    virtual int32_t __stdcall Compare(IMFAttributes* pTheirs, MF_ATTRIBUTES_MATCH_TYPE MatchType, int32_t* pbResult) = 0;
    virtual int32_t __stdcall GetUINT32(const GUID& guidKey, uint32_t* punValue) = 0;
    virtual int32_t __stdcall GetUINT64(const GUID& guidKey, uint64_t* punValue) = 0;
    virtual int32_t __stdcall GetDouble(const GUID& guidKey, double* pfValue) = 0;
    virtual int32_t __stdcall GetGUID(const GUID& guidKey, GUID* pguidValue) = 0;
    virtual int32_t __stdcall GetStringLength(const GUID& guidKey, uint32_t* pcchLength) = 0;
    virtual int32_t __stdcall GetString(const GUID& guidKey, wchar_t* pwszValue, uint32_t cchBufSize, uint32_t* pcchLength) = 0;
    virtual int32_t __stdcall GetAllocatedString(const GUID& guidKey, wchar_t** ppwszValue, uint32_t* pcchLength) = 0;
    virtual int32_t __stdcall GetBlobSize(const GUID& guidKey, uint32_t* pcbBlobSize) = 0;
    virtual int32_t __stdcall GetBlob(const GUID& guidKey, uint8_t* pBuf, uint32_t cbBufSize, uint32_t* pcbBlobSize) = 0;
    virtual int32_t __stdcall GetAllocatedBlob(const GUID& guidKey, uint8_t** ppBuf, uint32_t* pcbSize) = 0;
    virtual int32_t __stdcall GetUnknown(const GUID& guidKey, const GUID& riid, void** ppv) = 0;
    virtual int32_t __stdcall SetItem(const GUID& guidKey, const void* Value) = 0;
    virtual int32_t __stdcall DeleteItem(const GUID& guidKey) = 0;
    virtual int32_t __stdcall DeleteAllItems() = 0;
    virtual int32_t __stdcall SetUINT32(const GUID& guidKey, uint32_t unValue) = 0;
    virtual int32_t __stdcall SetUINT64(const GUID& guidKey, uint64_t unValue) = 0;
    virtual int32_t __stdcall SetDouble(const GUID& guidKey, double fValue) = 0;
    virtual int32_t __stdcall SetGUID(const GUID& guidKey, const GUID& guidValue) = 0;
    virtual int32_t __stdcall SetString(const GUID& guidKey, const wchar_t* wszValue) = 0;
    virtual int32_t __stdcall SetBlob(const GUID& guidKey, const uint8_t* pBuf, uint32_t cbBufSize) = 0;
    virtual int32_t __stdcall SetUnknown(const GUID& guidKey, ole32::IUnknown* pUnknown) = 0;
    virtual int32_t __stdcall LockStore() = 0;
    virtual int32_t __stdcall UnlockStore() = 0;
    virtual int32_t __stdcall GetCount(uint32_t* pcItems) = 0;
    virtual int32_t __stdcall GetItemByIndex(uint32_t unIndex, GUID* pguidKey, void* pValue) = 0;
    virtual int32_t __stdcall CopyAllItems(IMFAttributes* pDest) = 0;
};

struct IMFMediaBuffer : public ole32::IUnknown {
    virtual int32_t __stdcall Lock(uint8_t** ppbBuffer, uint32_t* pcbMaxLength, uint32_t* pcbCurrentLength) = 0;
    virtual int32_t __stdcall Unlock() = 0;
    virtual int32_t __stdcall GetCurrentLength(uint32_t* pcbCurrentLength) = 0;
    virtual int32_t __stdcall SetCurrentLength(uint32_t cbCurrentLength) = 0;
    virtual int32_t __stdcall GetMaxLength(uint32_t* pcbMaxLength) = 0;
};

struct IMFSample : public IMFAttributes {
    virtual int32_t __stdcall GetSampleFlags(uint32_t* pdwSampleFlags) = 0;
    virtual int32_t __stdcall SetSampleFlags(uint32_t dwSampleFlags) = 0;
    virtual int32_t __stdcall GetSampleTime(LONGLONG* phnsSampleTime) = 0;
    virtual int32_t __stdcall SetSampleTime(LONGLONG hnsSampleTime) = 0;
    virtual int32_t __stdcall GetSampleDuration(LONGLONG* phnsSampleDuration) = 0;
    virtual int32_t __stdcall SetSampleDuration(LONGLONG hnsSampleDuration) = 0;
    virtual int32_t __stdcall GetBufferCount(uint32_t* pdwBufferCount) = 0;
    virtual int32_t __stdcall GetBufferByIndex(uint32_t dwIndex, IMFMediaBuffer** ppBuffer) = 0;
    virtual int32_t __stdcall ConvertToContiguousBuffer(IMFMediaBuffer** ppBuffer) = 0;
    virtual int32_t __stdcall AddBuffer(IMFMediaBuffer* pBuffer) = 0;
    virtual int32_t __stdcall RemoveBufferByIndex(uint32_t dwIndex) = 0;
    virtual int32_t __stdcall RemoveAllBuffers() = 0;
    virtual int32_t __stdcall GetTotalLength(uint32_t* pcbTotalLength) = 0;
    virtual int32_t __stdcall CopyToBuffer(IMFMediaBuffer* pBuffer) = 0;
};

struct IMFMediaType : public IMFAttributes {
    virtual int32_t __stdcall GetMajorType(GUID* pguidMajorType) = 0;
    virtual int32_t __stdcall IsCompressedFormat(int32_t* pfCompressed) = 0;
    virtual int32_t __stdcall IsEqual(IMFMediaType* pIMediaType, uint32_t* pdwFlags) = 0;
    virtual int32_t __stdcall GetRepresentation(GUID guidRepresentation, void** ppvRepresentation) = 0;
    virtual int32_t __stdcall FreeRepresentation(GUID guidRepresentation, void* pvRepresentation) = 0;
};

struct IMFByteStream : public ole32::IUnknown {
    virtual int32_t __stdcall GetCapabilities(uint32_t* pdwCapabilities) = 0;
    virtual int32_t __stdcall GetLength(uint64_t* pqwLength) = 0;
    virtual int32_t __stdcall SetLength(uint64_t qwLength) = 0;
    virtual int32_t __stdcall GetCurrentPosition(uint64_t* pqwPosition) = 0;
    virtual int32_t __stdcall SetCurrentPosition(uint64_t qwPosition) = 0;
    virtual int32_t __stdcall IsEndOfStream(int32_t* pfEndOfStream) = 0;
    virtual int32_t __stdcall Read(uint8_t* pb, uint32_t cb, uint32_t* pcbRead) = 0;
    virtual int32_t __stdcall BeginRead(uint8_t* pb, uint32_t cb, IMFAsyncCallback* pCallback, ole32::IUnknown* punkState) = 0;
    virtual int32_t __stdcall EndRead(IMFAsyncResult* pResult, uint32_t* pcbRead) = 0;
    virtual int32_t __stdcall Write(const uint8_t* pb, uint32_t cb, uint32_t* pcbWritten) = 0;
    virtual int32_t __stdcall BeginWrite(const uint8_t* pb, uint32_t cb, IMFAsyncCallback* pCallback, ole32::IUnknown* punkState) = 0;
    virtual int32_t __stdcall EndWrite(IMFAsyncResult* pResult, uint32_t* pcbWritten) = 0;
    virtual int32_t __stdcall Seek(uint32_t SeekOrigin, int64_t llSeekOffset, uint32_t dwSeekFlags, uint64_t* pqwCurrentPosition) = 0;
    virtual int32_t __stdcall Flush() = 0;
    virtual int32_t __stdcall Close() = 0;
};

struct IMFAsyncResult : public ole32::IUnknown {
    virtual int32_t __stdcall GetState(ole32::IUnknown** ppunkState) = 0;
    virtual int32_t __stdcall GetStatus() = 0;
    virtual int32_t __stdcall SetStatus(int32_t hrStatus) = 0;
    virtual int32_t __stdcall GetObject(ole32::IUnknown** ppObject) = 0;
    virtual ole32::IUnknown* __stdcall GetStateNoAddRef() = 0;
};

struct IMFAsyncCallback : public ole32::IUnknown {
    virtual int32_t __stdcall GetParameters(uint32_t* pdwFlags, uint32_t* pdwQueue) = 0;
    virtual int32_t __stdcall Invoke(IMFAsyncResult* pResult) = 0;
};

struct IMFMediaEvent : public IMFAttributes {
    virtual int32_t __stdcall GetType(MediaEventType* pmet) = 0;
    virtual int32_t __stdcall GetExtendedType(GUID* pguidExtendedType) = 0;
    virtual int32_t __stdcall GetStatus(int32_t* phrStatus) = 0;
    virtual int32_t __stdcall GetValue(void* pvValue) = 0;
};

struct IMFMediaEventQueue : public ole32::IUnknown {
    virtual int32_t __stdcall GetEvent(uint32_t dwFlags, IMFMediaEvent** ppEvent) = 0;
    virtual int32_t __stdcall BeginGetEvent(IMFAsyncCallback* pCallback, ole32::IUnknown* punkState) = 0;
    virtual int32_t __stdcall EndGetEvent(IMFAsyncResult* pResult, IMFMediaEvent** ppEvent) = 0;
    virtual int32_t __stdcall QueueEvent(IMFMediaEvent* pEvent) = 0;
    virtual int32_t __stdcall QueueEventParamVar(MediaEventType met, const GUID& guidExtendedType, int32_t hrStatus, const void* pvValue) = 0;
    virtual int32_t __stdcall QueueEventParamUnk(MediaEventType met, const GUID& guidExtendedType, int32_t hrStatus, ole32::IUnknown* pUnk) = 0;
    virtual int32_t __stdcall Shutdown() = 0;
};

struct MFT_INPUT_STREAM_INFO {
    int64_t hnsMaxLatency;
    uint32_t dwFlags;
    uint32_t cbSize;
    uint32_t cbMaxLookahead;
    uint32_t cbAlignment;
};

struct MFT_OUTPUT_STREAM_INFO {
    uint32_t dwFlags;
    uint32_t cbSize;
    uint32_t cbAlignment;
};

struct MFT_OUTPUT_DATA_BUFFER {
    uint32_t dwStreamID;
    IMFSample* pSample;
    uint32_t dwStatus;
    IMFMediaEvent* pEvents;
};

struct IMFTransform : public ole32::IUnknown {
    virtual int32_t __stdcall GetStreamLimits(uint32_t* pdwInputMinimum, uint32_t* pdwInputMaximum, uint32_t* pdwOutputMinimum, uint32_t* pdwOutputMaximum) = 0;
    virtual int32_t __stdcall GetStreamCount(uint32_t* pcInputStreams, uint32_t* pcOutputStreams) = 0;
    virtual int32_t __stdcall GetStreamIDs(uint32_t dwInputIDArraySize, uint32_t* pdwInputIDs, uint32_t dwOutputIDArraySize, uint32_t* pdwOutputIDs) = 0;
    virtual int32_t __stdcall GetInputStreamInfo(uint32_t dwInputStreamID, MFT_INPUT_STREAM_INFO* pStreamInfo) = 0;
    virtual int32_t __stdcall GetOutputStreamInfo(uint32_t dwOutputStreamID, MFT_OUTPUT_STREAM_INFO* pStreamInfo) = 0;
    virtual int32_t __stdcall GetAttributes(IMFAttributes** pAttributes) = 0;
    virtual int32_t __stdcall GetInputStreamAttributes(uint32_t dwInputStreamID, IMFAttributes** pAttributes) = 0;
    virtual int32_t __stdcall GetOutputStreamAttributes(uint32_t dwOutputStreamID, IMFAttributes** pAttributes) = 0;
    virtual int32_t __stdcall DeleteInputStream(uint32_t dwStreamID) = 0;
    virtual int32_t __stdcall AddInputStreams(uint32_t cStreams, uint32_t* adwStreamIDs) = 0;
    virtual int32_t __stdcall GetInputAvailableType(uint32_t dwInputStreamID, uint32_t dwTypeIndex, IMFMediaType** ppType) = 0;
    virtual int32_t __stdcall GetOutputAvailableType(uint32_t dwOutputStreamID, uint32_t dwTypeIndex, IMFMediaType** ppType) = 0;
    virtual int32_t __stdcall SetInputType(uint32_t dwInputStreamID, IMFMediaType* pType, uint32_t dwFlags) = 0;
    virtual int32_t __stdcall SetOutputType(uint32_t dwOutputStreamID, IMFMediaType* pType, uint32_t dwFlags) = 0;
    virtual int32_t __stdcall GetInputCurrentType(uint32_t dwInputStreamID, IMFMediaType** ppType) = 0;
    virtual int32_t __stdcall GetOutputCurrentType(uint32_t dwOutputStreamID, IMFMediaType** ppType) = 0;
    virtual int32_t __stdcall GetInputStatus(uint32_t dwInputStreamID, uint32_t* pdwFlags) = 0;
    virtual int32_t __stdcall GetOutputStatus(uint32_t* pdwFlags) = 0;
    virtual int32_t __stdcall SetOutputBounds(LONGLONG hnsLowerBound, LONGLONG hnsUpperBound) = 0;
    virtual int32_t __stdcall ProcessEvent(uint32_t dwInputStreamID, IMFMediaEvent* pEvent) = 0;
    virtual int32_t __stdcall ProcessMessage(MFT_MESSAGE_TYPE eMessage, uint64_t ulParam) = 0;
    virtual int32_t __stdcall ProcessInput(uint32_t dwInputStreamID, IMFSample* pSample, uint32_t dwFlags) = 0;
    virtual int32_t __stdcall ProcessOutput(uint32_t dwFlags, uint32_t cOutputBufferCount, MFT_OUTPUT_DATA_BUFFER* pOutputSamples, uint32_t* pdwStatus) = 0;
};

struct IMFSourceReader : public ole32::IUnknown {
    virtual int32_t __stdcall GetStreamSelection(uint32_t dwStreamIndex, int32_t* pfSelected) = 0;
    virtual int32_t __stdcall SetStreamSelection(uint32_t dwStreamIndex, int32_t fSelected) = 0;
    virtual int32_t __stdcall GetNativeMediaType(uint32_t dwStreamIndex, uint32_t dwMediaTypeIndex, IMFMediaType** ppMediaType) = 0;
    virtual int32_t __stdcall GetCurrentMediaType(uint32_t dwStreamIndex, IMFMediaType** ppMediaType) = 0;
    virtual int32_t __stdcall SetCurrentMediaType(uint32_t dwStreamIndex, uint32_t* pdwReserved, IMFMediaType* pMediaType) = 0;
    virtual int32_t __stdcall SetStreamPosition(const GUID& guidTimeFormat, const void* varPosition) = 0;
    virtual int32_t __stdcall ReadSample(uint32_t dwStreamIndex, uint32_t dwControlFlags, uint32_t* pdwActualStreamIndex, uint32_t* pdwStreamFlags, LONGLONG* pllTimestamp, IMFSample** ppSample) = 0;
    virtual int32_t __stdcall Flush(uint32_t dwStreamIndex) = 0;
    virtual int32_t __stdcall GetServiceForStream(uint32_t dwStreamIndex, const GUID& guidService, const GUID& riid, void** ppvObject) = 0;
    virtual int32_t __stdcall GetPresentationAttribute(uint32_t dwStreamIndex, const GUID& guidAttribute, void* pvarAttribute) = 0;
};

struct IMFSinkWriter : public ole32::IUnknown {
    virtual int32_t __stdcall AddStream(IMFMediaType* pTargetMediaType, uint32_t* pdwStreamIndex) = 0;
    virtual int32_t __stdcall SetInputMediaType(uint32_t dwStreamIndex, IMFMediaType* pInputMediaType, IMFAttributes* pEncodingParameters) = 0;
    virtual int32_t __stdcall BeginWriting() = 0;
    virtual int32_t __stdcall WriteSample(uint32_t dwStreamIndex, IMFSample* pSample) = 0;
    virtual int32_t __stdcall SendStreamTick(uint32_t dwStreamIndex, LONGLONG llTimestamp) = 0;
    virtual int32_t __stdcall PlaceMarker(uint32_t dwStreamIndex, void* pvContext) = 0;
    virtual int32_t __stdcall NotifyEndOfSegment(uint32_t dwStreamIndex) = 0;
    virtual int32_t __stdcall Flush(uint32_t dwStreamIndex) = 0;
    virtual int32_t __stdcall Finalize() = 0;
    virtual int32_t __stdcall GetServiceForStream(uint32_t dwStreamIndex, const GUID& guidService, const GUID& riid, void** ppvObject) = 0;
};

struct IMFTopologyNode : public IMFAttributes {
    virtual int32_t __stdcall SetObject(ole32::IUnknown* pObject) = 0;
    virtual int32_t __stdcall GetObject(ole32::IUnknown** ppObject) = 0;
    virtual int32_t __stdcall GetNodeType(MF_TOPOLOGY_TYPE* pType) = 0;
    virtual int32_t __stdcall GetTopoNodeID(uint64_t* pID) = 0;
    virtual int32_t __stdcall SetTopoNodeID(uint64_t ullTopoNodeID) = 0;
    virtual int32_t __stdcall ConnectOutput(uint32_t dwOutputIndex, IMFTopologyNode* pDownstreamNode, uint32_t dwInputIndexOnDownstreamNode) = 0;
    virtual int32_t __stdcall DisconnectOutput(uint32_t dwOutputIndex) = 0;
    virtual int32_t __stdcall GetOutput(uint32_t dwOutputIndex, IMFTopologyNode** ppDownstreamNode, uint32_t* pdwInputIndexOnDownstreamNode) = 0;
    virtual int32_t __stdcall GetOutputCount(uint32_t* pdwOutputCount) = 0;
    virtual int32_t __stdcall GetInput(uint32_t dwInputIndex, IMFTopologyNode** ppUpstreamNode, uint32_t* pdwOutputIndexOnUpstreamNode) = 0;
    virtual int32_t __stdcall GetInputCount(uint32_t* pdwInputCount) = 0;
};

struct IMFTopology : public IMFAttributes {
    virtual int32_t __stdcall GetTopologyID(uint64_t* pID) = 0;
    virtual int32_t __stdcall AddNode(IMFTopologyNode* pNode) = 0;
    virtual int32_t __stdcall RemoveNode(IMFTopologyNode* pNode) = 0;
    virtual int32_t __stdcall GetNodeCount(uint16_t* pwNodes) = 0;
    virtual int32_t __stdcall GetNode(uint16_t wIndex, IMFTopologyNode** ppNode) = 0;
    virtual int32_t __stdcall Clear() = 0;
    virtual int32_t __stdcall CloneFrom(IMFTopology* pTopology) = 0;
    virtual int32_t __stdcall GetNodeByID(uint64_t ullTopoNodeID, IMFTopologyNode** ppNode) = 0;
    virtual int32_t __stdcall GetSourceNodeCollection(void** ppCollection) = 0;
    virtual int32_t __stdcall GetOutputNodeCollection(void** ppCollection) = 0;
};

struct IMFMediaSession : public IMFMediaEventQueue {
    virtual int32_t __stdcall SetTopology(uint32_t dwSetTopologyFlags, IMFTopology* pTopology) = 0;
    virtual int32_t __stdcall ClearTopologies() = 0;
    virtual int32_t __stdcall Start(const GUID* pguidTimeFormat, const void* pvarStartPosition) = 0;
    virtual int32_t __stdcall Pause() = 0;
    virtual int32_t __stdcall Stop() = 0;
    virtual int32_t __stdcall Close() = 0;
    virtual int32_t __stdcall GetClock(ole32::IUnknown** ppClock) = 0;
    virtual int32_t __stdcall GetSessionCapabilities(uint32_t* pdwCaps) = 0;
    virtual int32_t __stdcall GetFullTopology(uint32_t dwGetFullTopologyFlags, uint64_t TopoId, IMFTopology** ppFullTopology) = 0;
};

// ============================================================================
// 3. Concrete Implementations
// ============================================================================

// Attribute Value Container
struct AttributeVal {
    MF_ATTRIBUTE_TYPE type = MF_ATTRIBUTE_UINT32;
    uint32_t u32 = 0;
    uint64_t u64 = 0;
    double dbl = 0.0;
    GUID guid{};
    std::wstring str;
    std::vector<uint8_t> blob;
    ole32::IUnknown* punk = nullptr;

    ~AttributeVal() {
        if (punk) {
            punk->Release();
            punk = nullptr;
        }
    }

    AttributeVal() = default;

    AttributeVal(const AttributeVal& o) {
        copyFrom(o);
    }

    AttributeVal& operator=(const AttributeVal& o) {
        if (this != &o) {
            if (punk) punk->Release();
            copyFrom(o);
        }
        return *this;
    }

private:
    void copyFrom(const AttributeVal& o) {
        type = o.type;
        u32 = o.u32;
        u64 = o.u64;
        dbl = o.dbl;
        guid = o.guid;
        str = o.str;
        blob = o.blob;
        punk = o.punk;
        if (punk) punk->AddRef();
    }
};

class CAttributes : public IMFAttributes {
protected:
    uint32_t m_refCount{ 1 };
    mutable std::mutex m_mutex;
    std::map<GUID, AttributeVal, GuidLess> m_items;

public:
    CAttributes() = default;
    virtual ~CAttributes() = default;

    // IUnknown
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFAttributes_Local =
            { 0x2CD2D928, 0x0776, 0x4E86, { 0x82, 0x24, 0xE0, 0x2C, 0x0E, 0x58, 0x9C, 0x41 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFAttributes_Local) {
            *ppvObject = static_cast<IMFAttributes*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return ++m_refCount;
    }

    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFAttributes
    int32_t __stdcall GetItem(const GUID& guidKey, void*) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_items.find(guidKey) == m_items.end()) return ole32::E_FAIL;
        return ole32::S_OK;
    }

    int32_t __stdcall GetItemType(const GUID& guidKey, MF_ATTRIBUTE_TYPE* pType) override {
        if (!pType) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_items.find(guidKey);
        if (it == m_items.end()) return ole32::E_FAIL;
        *pType = it->second.type;
        return ole32::S_OK;
    }

    int32_t __stdcall CompareItem(const GUID&, const void*, int32_t* pbResult) override {
        if (!pbResult) return ole32::E_POINTER;
        *pbResult = 1;
        return ole32::S_OK;
    }

    int32_t __stdcall Compare(IMFAttributes*, MF_ATTRIBUTES_MATCH_TYPE, int32_t* pbResult) override {
        if (!pbResult) return ole32::E_POINTER;
        *pbResult = 1;
        return ole32::S_OK;
    }

    int32_t __stdcall GetUINT32(const GUID& guidKey, uint32_t* punValue) override {
        if (!punValue) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_items.find(guidKey);
        if (it == m_items.end() || it->second.type != MF_ATTRIBUTE_UINT32) return ole32::E_FAIL;
        *punValue = it->second.u32;
        return ole32::S_OK;
    }

    int32_t __stdcall GetUINT64(const GUID& guidKey, uint64_t* punValue) override {
        if (!punValue) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_items.find(guidKey);
        if (it == m_items.end() || it->second.type != MF_ATTRIBUTE_UINT64) return ole32::E_FAIL;
        *punValue = it->second.u64;
        return ole32::S_OK;
    }

    int32_t __stdcall GetDouble(const GUID& guidKey, double* pfValue) override {
        if (!pfValue) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_items.find(guidKey);
        if (it == m_items.end() || it->second.type != MF_ATTRIBUTE_DOUBLE) return ole32::E_FAIL;
        *pfValue = it->second.dbl;
        return ole32::S_OK;
    }

    int32_t __stdcall GetGUID(const GUID& guidKey, GUID* pguidValue) override {
        if (!pguidValue) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_items.find(guidKey);
        if (it == m_items.end() || it->second.type != MF_ATTRIBUTE_GUID) return ole32::E_FAIL;
        *pguidValue = it->second.guid;
        return ole32::S_OK;
    }

    int32_t __stdcall GetStringLength(const GUID& guidKey, uint32_t* pcchLength) override {
        if (!pcchLength) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_items.find(guidKey);
        if (it == m_items.end() || it->second.type != MF_ATTRIBUTE_STRING) return ole32::E_FAIL;
        *pcchLength = static_cast<uint32_t>(it->second.str.size());
        return ole32::S_OK;
    }

    int32_t __stdcall GetString(const GUID& guidKey, wchar_t* pwszValue, uint32_t cchBufSize, uint32_t* pcchLength) override {
        if (!pwszValue || cchBufSize == 0) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_items.find(guidKey);
        if (it == m_items.end() || it->second.type != MF_ATTRIBUTE_STRING) return ole32::E_FAIL;
        uint32_t len = static_cast<uint32_t>(it->second.str.size());
        if (pcchLength) *pcchLength = len;
        uint32_t copyLen = std::min(len, cchBufSize - 1);
        std::wmemcpy(pwszValue, it->second.str.data(), copyLen);
        pwszValue[copyLen] = L'\0';
        return ole32::S_OK;
    }

    int32_t __stdcall GetAllocatedString(const GUID&, wchar_t**, uint32_t*) override {
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall GetBlobSize(const GUID& guidKey, uint32_t* pcbBlobSize) override {
        if (!pcbBlobSize) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_items.find(guidKey);
        if (it == m_items.end() || it->second.type != MF_ATTRIBUTE_BLOB) return ole32::E_FAIL;
        *pcbBlobSize = static_cast<uint32_t>(it->second.blob.size());
        return ole32::S_OK;
    }

    int32_t __stdcall GetBlob(const GUID& guidKey, uint8_t* pBuf, uint32_t cbBufSize, uint32_t* pcbBlobSize) override {
        if (!pBuf || cbBufSize == 0) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_items.find(guidKey);
        if (it == m_items.end() || it->second.type != MF_ATTRIBUTE_BLOB) return ole32::E_FAIL;
        uint32_t sz = static_cast<uint32_t>(it->second.blob.size());
        if (pcbBlobSize) *pcbBlobSize = sz;
        uint32_t copySz = std::min(sz, cbBufSize);
        std::memcpy(pBuf, it->second.blob.data(), copySz);
        return ole32::S_OK;
    }

    int32_t __stdcall GetAllocatedBlob(const GUID&, uint8_t**, uint32_t*) override {
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall GetUnknown(const GUID& guidKey, const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_items.find(guidKey);
        if (it == m_items.end() || it->second.type != MF_ATTRIBUTE_IUNKNOWN || !it->second.punk) return ole32::E_FAIL;
        return it->second.punk->QueryInterface(riid, ppv);
    }

    int32_t __stdcall SetItem(const GUID&, const void*) override {
        return ole32::S_OK;
    }

    int32_t __stdcall DeleteItem(const GUID& guidKey) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_items.erase(guidKey);
        return ole32::S_OK;
    }

    int32_t __stdcall DeleteAllItems() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_items.clear();
        return ole32::S_OK;
    }

    int32_t __stdcall SetUINT32(const GUID& guidKey, uint32_t unValue) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        AttributeVal val;
        val.type = MF_ATTRIBUTE_UINT32;
        val.u32 = unValue;
        m_items[guidKey] = val;
        return ole32::S_OK;
    }

    int32_t __stdcall SetUINT64(const GUID& guidKey, uint64_t unValue) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        AttributeVal val;
        val.type = MF_ATTRIBUTE_UINT64;
        val.u64 = unValue;
        m_items[guidKey] = val;
        return ole32::S_OK;
    }

    int32_t __stdcall SetDouble(const GUID& guidKey, double fValue) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        AttributeVal val;
        val.type = MF_ATTRIBUTE_DOUBLE;
        val.dbl = fValue;
        m_items[guidKey] = val;
        return ole32::S_OK;
    }

    int32_t __stdcall SetGUID(const GUID& guidKey, const GUID& guidValue) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        AttributeVal val;
        val.type = MF_ATTRIBUTE_GUID;
        val.guid = guidValue;
        m_items[guidKey] = val;
        return ole32::S_OK;
    }

    int32_t __stdcall SetString(const GUID& guidKey, const wchar_t* wszValue) override {
        if (!wszValue) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        AttributeVal val;
        val.type = MF_ATTRIBUTE_STRING;
        val.str = wszValue;
        m_items[guidKey] = val;
        return ole32::S_OK;
    }

    int32_t __stdcall SetBlob(const GUID& guidKey, const uint8_t* pBuf, uint32_t cbBufSize) override {
        if (!pBuf && cbBufSize > 0) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        AttributeVal val;
        val.type = MF_ATTRIBUTE_BLOB;
        if (pBuf && cbBufSize > 0) {
            val.blob.assign(pBuf, pBuf + cbBufSize);
        }
        m_items[guidKey] = val;
        return ole32::S_OK;
    }

    int32_t __stdcall SetUnknown(const GUID& guidKey, ole32::IUnknown* pUnknown) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        AttributeVal val;
        val.type = MF_ATTRIBUTE_IUNKNOWN;
        val.punk = pUnknown;
        if (pUnknown) pUnknown->AddRef();
        m_items[guidKey] = val;
        return ole32::S_OK;
    }

    int32_t __stdcall LockStore() override { return ole32::S_OK; }
    int32_t __stdcall UnlockStore() override { return ole32::S_OK; }

    int32_t __stdcall GetCount(uint32_t* pcItems) override {
        if (!pcItems) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pcItems = static_cast<uint32_t>(m_items.size());
        return ole32::S_OK;
    }

    int32_t __stdcall GetItemByIndex(uint32_t, GUID*, void*) override {
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall CopyAllItems(IMFAttributes* pDest) override {
        if (!pDest) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& [k, v] : m_items) {
            switch (v.type) {
                case MF_ATTRIBUTE_UINT32: pDest->SetUINT32(k, v.u32); break;
                case MF_ATTRIBUTE_UINT64: pDest->SetUINT64(k, v.u64); break;
                case MF_ATTRIBUTE_DOUBLE: pDest->SetDouble(k, v.dbl); break;
                case MF_ATTRIBUTE_GUID:   pDest->SetGUID(k, v.guid); break;
                case MF_ATTRIBUTE_STRING: pDest->SetString(k, v.str.c_str()); break;
                case MF_ATTRIBUTE_BLOB:   pDest->SetBlob(k, v.blob.data(), static_cast<uint32_t>(v.blob.size())); break;
                case MF_ATTRIBUTE_IUNKNOWN: pDest->SetUnknown(k, v.punk); break;
            }
        }
        return ole32::S_OK;
    }
};

// Media Buffer Implementation
class CMediaBuffer : public IMFMediaBuffer {
    uint32_t m_refCount{ 1 };
    mutable std::mutex m_mutex;
    std::vector<uint8_t> m_buffer;
    uint32_t m_maxLength{ 0 };
    uint32_t m_currentLength{ 0 };
    bool m_locked{ false };

public:
    explicit CMediaBuffer(uint32_t maxLength)
        : m_buffer(maxLength, 0), m_maxLength(maxLength), m_currentLength(0) {}

    // IUnknown
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFMediaBuffer_Local =
            { 0x045FA593, 0x8799, 0x42B8, { 0xBC, 0x8D, 0x89, 0x68, 0xC6, 0x45, 0x35, 0x07 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFMediaBuffer_Local) {
            *ppvObject = static_cast<IMFMediaBuffer*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFMediaBuffer
    int32_t __stdcall Lock(uint8_t** ppbBuffer, uint32_t* pcbMaxLength, uint32_t* pcbCurrentLength) override {
        if (!ppbBuffer) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_locked = true;
        *ppbBuffer = m_buffer.data();
        if (pcbMaxLength) *pcbMaxLength = m_maxLength;
        if (pcbCurrentLength) *pcbCurrentLength = m_currentLength;
        return ole32::S_OK;
    }

    int32_t __stdcall Unlock() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_locked = false;
        return ole32::S_OK;
    }

    int32_t __stdcall GetCurrentLength(uint32_t* pcbCurrentLength) override {
        if (!pcbCurrentLength) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pcbCurrentLength = m_currentLength;
        return ole32::S_OK;
    }

    int32_t __stdcall SetCurrentLength(uint32_t cbCurrentLength) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (cbCurrentLength > m_maxLength) return ole32::E_INVALIDARG;
        m_currentLength = cbCurrentLength;
        return ole32::S_OK;
    }

    int32_t __stdcall GetMaxLength(uint32_t* pcbMaxLength) override {
        if (!pcbMaxLength) return ole32::E_POINTER;
        *pcbMaxLength = m_maxLength;
        return ole32::S_OK;
    }
};

// Media Sample Implementation
class CSample : public CAttributes, public IMFSample {
    uint32_t m_flags{ 0 };
    LONGLONG m_sampleTime{ 0 };
    LONGLONG m_sampleDuration{ 0 };
    std::vector<IMFMediaBuffer*> m_buffers;

public:
    CSample() = default;
    ~CSample() override {
        for (auto* b : m_buffers) {
            if (b) b->Release();
        }
        m_buffers.clear();
    }

    // IUnknown
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFSample_Local =
            { 0xC40A0074, 0xB93A, 0x4D80, { 0xAE, 0x8C, 0x5A, 0x1C, 0x63, 0x4F, 0x58, 0xE4 } };
        static const GUID IID_IMFAttributes_Local =
            { 0x2CD2D928, 0x0776, 0x4E86, { 0x82, 0x24, 0xE0, 0x2C, 0x0E, 0x58, 0x9C, 0x41 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFSample_Local) {
            *ppvObject = static_cast<IMFSample*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMFAttributes_Local) {
            *ppvObject = static_cast<IMFAttributes*>(static_cast<IMFSample*>(this));
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFAttributes delegation
    int32_t __stdcall GetItem(const GUID& k, void* v) override { return CAttributes::GetItem(k, v); }
    int32_t __stdcall GetItemType(const GUID& k, MF_ATTRIBUTE_TYPE* t) override { return CAttributes::GetItemType(k, t); }
    int32_t __stdcall CompareItem(const GUID& k, const void* v, int32_t* r) override { return CAttributes::CompareItem(k, v, r); }
    int32_t __stdcall Compare(IMFAttributes* t, MF_ATTRIBUTES_MATCH_TYPE m, int32_t* r) override { return CAttributes::Compare(t, m, r); }
    int32_t __stdcall GetUINT32(const GUID& k, uint32_t* v) override { return CAttributes::GetUINT32(k, v); }
    int32_t __stdcall GetUINT64(const GUID& k, uint64_t* v) override { return CAttributes::GetUINT64(k, v); }
    int32_t __stdcall GetDouble(const GUID& k, double* v) override { return CAttributes::GetDouble(k, v); }
    int32_t __stdcall GetGUID(const GUID& k, GUID* v) override { return CAttributes::GetGUID(k, v); }
    int32_t __stdcall GetStringLength(const GUID& k, uint32_t* l) override { return CAttributes::GetStringLength(k, l); }
    int32_t __stdcall GetString(const GUID& k, wchar_t* b, uint32_t s, uint32_t* l) override { return CAttributes::GetString(k, b, s, l); }
    int32_t __stdcall GetAllocatedString(const GUID& k, wchar_t** b, uint32_t* l) override { return CAttributes::GetAllocatedString(k, b, l); }
    int32_t __stdcall GetBlobSize(const GUID& k, uint32_t* s) override { return CAttributes::GetBlobSize(k, s); }
    int32_t __stdcall GetBlob(const GUID& k, uint8_t* b, uint32_t s, uint32_t* bs) override { return CAttributes::GetBlob(k, b, s, bs); }
    int32_t __stdcall GetAllocatedBlob(const GUID& k, uint8_t** b, uint32_t* s) override { return CAttributes::GetAllocatedBlob(k, b, s); }
    int32_t __stdcall GetUnknown(const GUID& k, const GUID& r, void** p) override { return CAttributes::GetUnknown(k, r, p); }
    int32_t __stdcall SetItem(const GUID& k, const void* v) override { return CAttributes::SetItem(k, v); }
    int32_t __stdcall DeleteItem(const GUID& k) override { return CAttributes::DeleteItem(k); }
    int32_t __stdcall DeleteAllItems() override { return CAttributes::DeleteAllItems(); }
    int32_t __stdcall SetUINT32(const GUID& k, uint32_t v) override { return CAttributes::SetUINT32(k, v); }
    int32_t __stdcall SetUINT64(const GUID& k, uint64_t v) override { return CAttributes::SetUINT64(k, v); }
    int32_t __stdcall SetDouble(const GUID& k, double v) override { return CAttributes::SetDouble(k, v); }
    int32_t __stdcall SetGUID(const GUID& k, const GUID& v) override { return CAttributes::SetGUID(k, v); }
    int32_t __stdcall SetString(const GUID& k, const wchar_t* v) override { return CAttributes::SetString(k, v); }
    int32_t __stdcall SetBlob(const GUID& k, const uint8_t* b, uint32_t s) override { return CAttributes::SetBlob(k, b, s); }
    int32_t __stdcall SetUnknown(const GUID& k, ole32::IUnknown* p) override { return CAttributes::SetUnknown(k, p); }
    int32_t __stdcall LockStore() override { return CAttributes::LockStore(); }
    int32_t __stdcall UnlockStore() override { return CAttributes::UnlockStore(); }
    int32_t __stdcall GetCount(uint32_t* c) override { return CAttributes::GetCount(c); }
    int32_t __stdcall GetItemByIndex(uint32_t i, GUID* g, void* v) override { return CAttributes::GetItemByIndex(i, g, v); }
    int32_t __stdcall CopyAllItems(IMFAttributes* d) override { return CAttributes::CopyAllItems(d); }

    // IMFSample
    int32_t __stdcall GetSampleFlags(uint32_t* pdwSampleFlags) override {
        if (!pdwSampleFlags) return ole32::E_POINTER;
        *pdwSampleFlags = m_flags;
        return ole32::S_OK;
    }

    int32_t __stdcall SetSampleFlags(uint32_t dwSampleFlags) override {
        m_flags = dwSampleFlags;
        return ole32::S_OK;
    }

    int32_t __stdcall GetSampleTime(LONGLONG* phnsSampleTime) override {
        if (!phnsSampleTime) return ole32::E_POINTER;
        *phnsSampleTime = m_sampleTime;
        return ole32::S_OK;
    }

    int32_t __stdcall SetSampleTime(LONGLONG hnsSampleTime) override {
        m_sampleTime = hnsSampleTime;
        return ole32::S_OK;
    }

    int32_t __stdcall GetSampleDuration(LONGLONG* phnsSampleDuration) override {
        if (!phnsSampleDuration) return ole32::E_POINTER;
        *phnsSampleDuration = m_sampleDuration;
        return ole32::S_OK;
    }

    int32_t __stdcall SetSampleDuration(LONGLONG hnsSampleDuration) override {
        m_sampleDuration = hnsSampleDuration;
        return ole32::S_OK;
    }

    int32_t __stdcall GetBufferCount(uint32_t* pdwBufferCount) override {
        if (!pdwBufferCount) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pdwBufferCount = static_cast<uint32_t>(m_buffers.size());
        return ole32::S_OK;
    }

    int32_t __stdcall GetBufferByIndex(uint32_t dwIndex, IMFMediaBuffer** ppBuffer) override {
        if (!ppBuffer) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwIndex >= m_buffers.size()) return ole32::E_INVALIDARG;
        *ppBuffer = m_buffers[dwIndex];
        (*ppBuffer)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall ConvertToContiguousBuffer(IMFMediaBuffer** ppBuffer) override {
        if (!ppBuffer) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_buffers.empty()) return ole32::E_FAIL;
        if (m_buffers.size() == 1) {
            *ppBuffer = m_buffers[0];
            (*ppBuffer)->AddRef();
            return ole32::S_OK;
        }

        uint32_t totalLen = 0;
        for (auto* b : m_buffers) {
            uint32_t len = 0;
            b->GetCurrentLength(&len);
            totalLen += len;
        }

        auto* newBuf = new CMediaBuffer(totalLen);
        uint8_t* destPtr = nullptr;
        newBuf->Lock(&destPtr, nullptr, nullptr);
        uint32_t offset = 0;
        for (auto* b : m_buffers) {
            uint8_t* src = nullptr;
            uint32_t len = 0;
            b->Lock(&src, nullptr, &len);
            if (src && len > 0) {
                std::memcpy(destPtr + offset, src, len);
                offset += len;
            }
            b->Unlock();
        }
        newBuf->Unlock();
        newBuf->SetCurrentLength(totalLen);
        *ppBuffer = newBuf;
        return ole32::S_OK;
    }

    int32_t __stdcall AddBuffer(IMFMediaBuffer* pBuffer) override {
        if (!pBuffer) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        pBuffer->AddRef();
        m_buffers.push_back(pBuffer);
        return ole32::S_OK;
    }

    int32_t __stdcall RemoveBufferByIndex(uint32_t dwIndex) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwIndex >= m_buffers.size()) return ole32::E_INVALIDARG;
        m_buffers[dwIndex]->Release();
        m_buffers.erase(m_buffers.begin() + dwIndex);
        return ole32::S_OK;
    }

    int32_t __stdcall RemoveAllBuffers() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto* b : m_buffers) b->Release();
        m_buffers.clear();
        return ole32::S_OK;
    }

    int32_t __stdcall GetTotalLength(uint32_t* pcbTotalLength) override {
        if (!pcbTotalLength) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t tot = 0;
        for (auto* b : m_buffers) {
            uint32_t l = 0;
            b->GetCurrentLength(&l);
            tot += l;
        }
        *pcbTotalLength = tot;
        return ole32::S_OK;
    }

    int32_t __stdcall CopyToBuffer(IMFMediaBuffer* pBuffer) override {
        if (!pBuffer) return ole32::E_POINTER;
        uint8_t* dest = nullptr;
        uint32_t destMax = 0;
        pBuffer->Lock(&dest, &destMax, nullptr);
        uint32_t totWritten = 0;
        for (auto* b : m_buffers) {
            uint8_t* src = nullptr;
            uint32_t srcLen = 0;
            b->Lock(&src, nullptr, &srcLen);
            if (src && srcLen > 0 && totWritten + srcLen <= destMax) {
                std::memcpy(dest + totWritten, src, srcLen);
                totWritten += srcLen;
            }
            b->Unlock();
        }
        pBuffer->Unlock();
        pBuffer->SetCurrentLength(totWritten);
        return ole32::S_OK;
    }
};

// Media Type Implementation
class CMediaType : public CAttributes, public IMFMediaType {
public:
    CMediaType() = default;

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFMediaType_Local =
            { 0x44AE0FA8, 0xEA31, 0x4109, { 0x8D, 0x2E, 0xBE, 0x1E, 0x6B, 0x15, 0xCA, 0x21 } };
        static const GUID IID_IMFAttributes_Local =
            { 0x2CD2D928, 0x0776, 0x4E86, { 0x82, 0x24, 0xE0, 0x2C, 0x0E, 0x58, 0x9C, 0x41 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFMediaType_Local) {
            *ppvObject = static_cast<IMFMediaType*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMFAttributes_Local) {
            *ppvObject = static_cast<IMFAttributes*>(static_cast<IMFMediaType*>(this));
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFAttributes delegation
    int32_t __stdcall GetItem(const GUID& k, void* v) override { return CAttributes::GetItem(k, v); }
    int32_t __stdcall GetItemType(const GUID& k, MF_ATTRIBUTE_TYPE* t) override { return CAttributes::GetItemType(k, t); }
    int32_t __stdcall CompareItem(const GUID& k, const void* v, int32_t* r) override { return CAttributes::CompareItem(k, v, r); }
    int32_t __stdcall Compare(IMFAttributes* t, MF_ATTRIBUTES_MATCH_TYPE m, int32_t* r) override { return CAttributes::Compare(t, m, r); }
    int32_t __stdcall GetUINT32(const GUID& k, uint32_t* v) override { return CAttributes::GetUINT32(k, v); }
    int32_t __stdcall GetUINT64(const GUID& k, uint64_t* v) override { return CAttributes::GetUINT64(k, v); }
    int32_t __stdcall GetDouble(const GUID& k, double* v) override { return CAttributes::GetDouble(k, v); }
    int32_t __stdcall GetGUID(const GUID& k, GUID* v) override { return CAttributes::GetGUID(k, v); }
    int32_t __stdcall GetStringLength(const GUID& k, uint32_t* l) override { return CAttributes::GetStringLength(k, l); }
    int32_t __stdcall GetString(const GUID& k, wchar_t* b, uint32_t s, uint32_t* l) override { return CAttributes::GetString(k, b, s, l); }
    int32_t __stdcall GetAllocatedString(const GUID& k, wchar_t** b, uint32_t* l) override { return CAttributes::GetAllocatedString(k, b, l); }
    int32_t __stdcall GetBlobSize(const GUID& k, uint32_t* s) override { return CAttributes::GetBlobSize(k, s); }
    int32_t __stdcall GetBlob(const GUID& k, uint8_t* b, uint32_t s, uint32_t* bs) override { return CAttributes::GetBlob(k, b, s, bs); }
    int32_t __stdcall GetAllocatedBlob(const GUID& k, uint8_t** b, uint32_t* s) override { return CAttributes::GetAllocatedBlob(k, b, s); }
    int32_t __stdcall GetUnknown(const GUID& k, const GUID& r, void** p) override { return CAttributes::GetUnknown(k, r, p); }
    int32_t __stdcall SetItem(const GUID& k, const void* v) override { return CAttributes::SetItem(k, v); }
    int32_t __stdcall DeleteItem(const GUID& k) override { return CAttributes::DeleteItem(k); }
    int32_t __stdcall DeleteAllItems() override { return CAttributes::DeleteAllItems(); }
    int32_t __stdcall SetUINT32(const GUID& k, uint32_t v) override { return CAttributes::SetUINT32(k, v); }
    int32_t __stdcall SetUINT64(const GUID& k, uint64_t v) override { return CAttributes::SetUINT64(k, v); }
    int32_t __stdcall SetDouble(const GUID& k, double v) override { return CAttributes::SetDouble(k, v); }
    int32_t __stdcall SetGUID(const GUID& k, const GUID& v) override { return CAttributes::SetGUID(k, v); }
    int32_t __stdcall SetString(const GUID& k, const wchar_t* v) override { return CAttributes::SetString(k, v); }
    int32_t __stdcall SetBlob(const GUID& k, const uint8_t* b, uint32_t s) override { return CAttributes::SetBlob(k, b, s); }
    int32_t __stdcall SetUnknown(const GUID& k, ole32::IUnknown* p) override { return CAttributes::SetUnknown(k, p); }
    int32_t __stdcall LockStore() override { return CAttributes::LockStore(); }
    int32_t __stdcall UnlockStore() override { return CAttributes::UnlockStore(); }
    int32_t __stdcall GetCount(uint32_t* c) override { return CAttributes::GetCount(c); }
    int32_t __stdcall GetItemByIndex(uint32_t i, GUID* g, void* v) override { return CAttributes::GetItemByIndex(i, g, v); }
    int32_t __stdcall CopyAllItems(IMFAttributes* d) override { return CAttributes::CopyAllItems(d); }

    // IMFMediaType
    int32_t __stdcall GetMajorType(GUID* pguidMajorType) override {
        return GetGUID(MF_MT_MAJOR_TYPE, pguidMajorType);
    }

    int32_t __stdcall IsCompressedFormat(int32_t* pfCompressed) override {
        if (!pfCompressed) return ole32::E_POINTER;
        GUID sub{};
        if (GetGUID(MF_MT_SUBTYPE, &sub) != ole32::S_OK) return ole32::E_FAIL;
        *pfCompressed = (sub == MFAudioFormat_PCM || sub == MFVideoFormat_RGB32 || sub == MFVideoFormat_NV12) ? 0 : 1;
        return ole32::S_OK;
    }

    int32_t __stdcall IsEqual(IMFMediaType* pIMediaType, uint32_t* pdwFlags) override {
        if (!pIMediaType) return ole32::E_POINTER;
        if (pdwFlags) *pdwFlags = 0;
        GUID myMajor{}, theirMajor{};
        GetMajorType(&myMajor);
        pIMediaType->GetMajorType(&theirMajor);
        if (myMajor != theirMajor) return ole32::S_FALSE;
        GUID mySub{}, theirSub{};
        GetGUID(MF_MT_SUBTYPE, &mySub);
        pIMediaType->GetGUID(MF_MT_SUBTYPE, &theirSub);
        return (mySub == theirSub) ? ole32::S_OK : ole32::S_FALSE;
    }

    int32_t __stdcall GetRepresentation(GUID, void**) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall FreeRepresentation(GUID, void*) override { return ole32::E_NOTIMPL; }
};

// Byte Stream Implementation
class CMemoryByteStream : public IMFByteStream {
    uint32_t m_refCount{ 1 };
    mutable std::mutex m_mutex;
    std::vector<uint8_t> m_data;
    uint64_t m_pos{ 0 };

public:
    CMemoryByteStream() = default;
    explicit CMemoryByteStream(std::vector<uint8_t> data) : m_data(std::move(data)) {}

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFByteStream_Local =
            { 0xAD4C1B00, 0x4BF7, 0x422F, { 0x91, 0x75, 0x75, 0x66, 0x93, 0xD9, 0x13, 0x0D } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFByteStream_Local) {
            *ppvObject = static_cast<IMFByteStream*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFByteStream
    int32_t __stdcall GetCapabilities(uint32_t* pdwCapabilities) override {
        if (!pdwCapabilities) return ole32::E_POINTER;
        *pdwCapabilities = 0x00000007; // CanRead, CanWrite, CanSeek
        return ole32::S_OK;
    }

    int32_t __stdcall GetLength(uint64_t* pqwLength) override {
        if (!pqwLength) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pqwLength = m_data.size();
        return ole32::S_OK;
    }

    int32_t __stdcall SetLength(uint64_t qwLength) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_data.resize(static_cast<size_t>(qwLength));
        return ole32::S_OK;
    }

    int32_t __stdcall GetCurrentPosition(uint64_t* pqwPosition) override {
        if (!pqwPosition) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pqwPosition = m_pos;
        return ole32::S_OK;
    }

    int32_t __stdcall SetCurrentPosition(uint64_t qwPosition) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pos = std::min(qwPosition, static_cast<uint64_t>(m_data.size()));
        return ole32::S_OK;
    }

    int32_t __stdcall IsEndOfStream(int32_t* pfEndOfStream) override {
        if (!pfEndOfStream) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pfEndOfStream = (m_pos >= m_data.size()) ? 1 : 0;
        return ole32::S_OK;
    }

    int32_t __stdcall Read(uint8_t* pb, uint32_t cb, uint32_t* pcbRead) override {
        if (!pb) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t available = static_cast<uint32_t>((m_pos < m_data.size()) ? (m_data.size() - m_pos) : 0);
        uint32_t toRead = std::min(cb, available);
        if (toRead > 0) {
            std::memcpy(pb, m_data.data() + m_pos, toRead);
            m_pos += toRead;
        }
        if (pcbRead) *pcbRead = toRead;
        return ole32::S_OK;
    }

    int32_t __stdcall BeginRead(uint8_t*, uint32_t, IMFAsyncCallback*, ole32::IUnknown*) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall EndRead(IMFAsyncResult*, uint32_t*) override { return ole32::E_NOTIMPL; }

    int32_t __stdcall Write(const uint8_t* pb, uint32_t cb, uint32_t* pcbWritten) override {
        if (!pb) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pos + cb > m_data.size()) {
            m_data.resize(static_cast<size_t>(m_pos + cb));
        }
        std::memcpy(m_data.data() + m_pos, pb, cb);
        m_pos += cb;
        if (pcbWritten) *pcbWritten = cb;
        return ole32::S_OK;
    }

    int32_t __stdcall BeginWrite(const uint8_t*, uint32_t, IMFAsyncCallback*, ole32::IUnknown*) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall EndWrite(IMFAsyncResult*, uint32_t*) override { return ole32::E_NOTIMPL; }

    int32_t __stdcall Seek(uint32_t SeekOrigin, int64_t llSeekOffset, uint32_t, uint64_t* pqwCurrentPosition) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        int64_t target = 0;
        if (SeekOrigin == 0) { // SEEK_SET
            target = llSeekOffset;
        } else if (SeekOrigin == 1) { // SEEK_CUR
            target = static_cast<int64_t>(m_pos) + llSeekOffset;
        } else if (SeekOrigin == 2) { // SEEK_END
            target = static_cast<int64_t>(m_data.size()) + llSeekOffset;
        }
        if (target < 0) target = 0;
        m_pos = std::min(static_cast<uint64_t>(target), static_cast<uint64_t>(m_data.size()));
        if (pqwCurrentPosition) *pqwCurrentPosition = m_pos;
        return ole32::S_OK;
    }

    int32_t __stdcall Flush() override { return ole32::S_OK; }
    int32_t __stdcall Close() override { return ole32::S_OK; }
};

// Async Result Implementation
class CAsyncResult : public IMFAsyncResult {
    uint32_t m_refCount{ 1 };
    ole32::IUnknown* m_punkObject{ nullptr };
    IMFAsyncCallback* m_pCallback{ nullptr };
    ole32::IUnknown* m_punkState{ nullptr };
    int32_t m_status{ ole32::S_OK };

public:
    CAsyncResult(ole32::IUnknown* punkObject, IMFAsyncCallback* pCallback, ole32::IUnknown* punkState)
        : m_punkObject(punkObject), m_pCallback(pCallback), m_punkState(punkState) {
        if (m_punkObject) m_punkObject->AddRef();
        if (m_pCallback) m_pCallback->AddRef();
        if (m_punkState) m_punkState->AddRef();
    }

    ~CAsyncResult() override {
        if (m_punkObject) m_punkObject->Release();
        if (m_pCallback) m_pCallback->Release();
        if (m_punkState) m_punkState->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFAsyncResult_Local =
            { 0xAC6B210C, 0xAC40, 0x4C51, { 0xA8, 0x81, 0xD2, 0xD3, 0x03, 0xA7, 0x75, 0x91 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFAsyncResult_Local) {
            *ppvObject = static_cast<IMFAsyncResult*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall GetState(ole32::IUnknown** ppunkState) override {
        if (!ppunkState) return ole32::E_POINTER;
        *ppunkState = m_punkState;
        if (*ppunkState) (*ppunkState)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetStatus() override { return m_status; }
    int32_t __stdcall SetStatus(int32_t hrStatus) override {
        m_status = hrStatus;
        return ole32::S_OK;
    }

    int32_t __stdcall GetObject(ole32::IUnknown** ppObject) override {
        if (!ppObject) return ole32::E_POINTER;
        *ppObject = m_punkObject;
        if (*ppObject) (*ppObject)->AddRef();
        return ole32::S_OK;
    }

    ole32::IUnknown* __stdcall GetStateNoAddRef() override {
        return m_punkState;
    }

    IMFAsyncCallback* GetCallback() const { return m_pCallback; }
};

// Media Event Implementation
class CMediaEvent : public CAttributes, public IMFMediaEvent {
    MediaEventType m_met{ MEUnknown };
    GUID m_extendedType{};
    int32_t m_status{ ole32::S_OK };

public:
    CMediaEvent(MediaEventType met, const GUID& ext, int32_t hr)
        : m_met(met), m_extendedType(ext), m_status(hr) {}

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFMediaEvent_Local =
            { 0xDF5943F4, 0xCAEE, 0x45F6, { 0xB1, 0xD6, 0xE3, 0x4E, 0x3F, 0x32, 0x67, 0xE7 } };
        static const GUID IID_IMFAttributes_Local =
            { 0x2CD2D928, 0x0776, 0x4E86, { 0x82, 0x24, 0xE0, 0x2C, 0x0E, 0x58, 0x9C, 0x41 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFMediaEvent_Local) {
            *ppvObject = static_cast<IMFMediaEvent*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMFAttributes_Local) {
            *ppvObject = static_cast<IMFAttributes*>(static_cast<IMFMediaEvent*>(this));
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFAttributes delegation
    int32_t __stdcall GetItem(const GUID& k, void* v) override { return CAttributes::GetItem(k, v); }
    int32_t __stdcall GetItemType(const GUID& k, MF_ATTRIBUTE_TYPE* t) override { return CAttributes::GetItemType(k, t); }
    int32_t __stdcall CompareItem(const GUID& k, const void* v, int32_t* r) override { return CAttributes::CompareItem(k, v, r); }
    int32_t __stdcall Compare(IMFAttributes* t, MF_ATTRIBUTES_MATCH_TYPE m, int32_t* r) override { return CAttributes::Compare(t, m, r); }
    int32_t __stdcall GetUINT32(const GUID& k, uint32_t* v) override { return CAttributes::GetUINT32(k, v); }
    int32_t __stdcall GetUINT64(const GUID& k, uint64_t* v) override { return CAttributes::GetUINT64(k, v); }
    int32_t __stdcall GetDouble(const GUID& k, double* v) override { return CAttributes::GetDouble(k, v); }
    int32_t __stdcall GetGUID(const GUID& k, GUID* v) override { return CAttributes::GetGUID(k, v); }
    int32_t __stdcall GetStringLength(const GUID& k, uint32_t* l) override { return CAttributes::GetStringLength(k, l); }
    int32_t __stdcall GetString(const GUID& k, wchar_t* b, uint32_t s, uint32_t* l) override { return CAttributes::GetString(k, b, s, l); }
    int32_t __stdcall GetAllocatedString(const GUID& k, wchar_t** b, uint32_t* l) override { return CAttributes::GetAllocatedString(k, b, l); }
    int32_t __stdcall GetBlobSize(const GUID& k, uint32_t* s) override { return CAttributes::GetBlobSize(k, s); }
    int32_t __stdcall GetBlob(const GUID& k, uint8_t* b, uint32_t s, uint32_t* bs) override { return CAttributes::GetBlob(k, b, s, bs); }
    int32_t __stdcall GetAllocatedBlob(const GUID& k, uint8_t** b, uint32_t* s) override { return CAttributes::GetAllocatedBlob(k, b, s); }
    int32_t __stdcall GetUnknown(const GUID& k, const GUID& r, void** p) override { return CAttributes::GetUnknown(k, r, p); }
    int32_t __stdcall SetItem(const GUID& k, const void* v) override { return CAttributes::SetItem(k, v); }
    int32_t __stdcall DeleteItem(const GUID& k) override { return CAttributes::DeleteItem(k); }
    int32_t __stdcall DeleteAllItems() override { return CAttributes::DeleteAllItems(); }
    int32_t __stdcall SetUINT32(const GUID& k, uint32_t v) override { return CAttributes::SetUINT32(k, v); }
    int32_t __stdcall SetUINT64(const GUID& k, uint64_t v) override { return CAttributes::SetUINT64(k, v); }
    int32_t __stdcall SetDouble(const GUID& k, double v) override { return CAttributes::SetDouble(k, v); }
    int32_t __stdcall SetGUID(const GUID& k, const GUID& v) override { return CAttributes::SetGUID(k, v); }
    int32_t __stdcall SetString(const GUID& k, const wchar_t* v) override { return CAttributes::SetString(k, v); }
    int32_t __stdcall SetBlob(const GUID& k, const uint8_t* b, uint32_t s) override { return CAttributes::SetBlob(k, b, s); }
    int32_t __stdcall SetUnknown(const GUID& k, ole32::IUnknown* p) override { return CAttributes::SetUnknown(k, p); }
    int32_t __stdcall LockStore() override { return CAttributes::LockStore(); }
    int32_t __stdcall UnlockStore() override { return CAttributes::UnlockStore(); }
    int32_t __stdcall GetCount(uint32_t* c) override { return CAttributes::GetCount(c); }
    int32_t __stdcall GetItemByIndex(uint32_t i, GUID* g, void* v) override { return CAttributes::GetItemByIndex(i, g, v); }
    int32_t __stdcall CopyAllItems(IMFAttributes* d) override { return CAttributes::CopyAllItems(d); }

    // IMFMediaEvent
    int32_t __stdcall GetType(MediaEventType* pmet) override {
        if (!pmet) return ole32::E_POINTER;
        *pmet = m_met;
        return ole32::S_OK;
    }

    int32_t __stdcall GetExtendedType(GUID* pguidExtendedType) override {
        if (!pguidExtendedType) return ole32::E_POINTER;
        *pguidExtendedType = m_extendedType;
        return ole32::S_OK;
    }

    int32_t __stdcall GetStatus(int32_t* phrStatus) override {
        if (!phrStatus) return ole32::E_POINTER;
        *phrStatus = m_status;
        return ole32::S_OK;
    }

    int32_t __stdcall GetValue(void*) override {
        return ole32::S_OK;
    }
};

// Media Event Queue Implementation
class CMediaEventQueue : public IMFMediaEventQueue {
    uint32_t m_refCount{ 1 };
    mutable std::mutex m_mutex;
    std::vector<IMFMediaEvent*> m_events;
    bool m_shutdown{ false };

public:
    CMediaEventQueue() = default;
    ~CMediaEventQueue() override {
        Shutdown();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFMediaEventQueue_Local =
            { 0x36F846FC, 0x2256, 0x48B6, { 0xB5, 0x8E, 0xE2, 0xB6, 0x38, 0x31, 0x65, 0x81 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFMediaEventQueue_Local) {
            *ppvObject = static_cast<IMFMediaEventQueue*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFMediaEventQueue
    int32_t __stdcall GetEvent(uint32_t, IMFMediaEvent** ppEvent) override {
        if (!ppEvent) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_shutdown) return ole32::E_FAIL;
        if (m_events.empty()) return ole32::E_FAIL;
        *ppEvent = m_events.front();
        m_events.erase(m_events.begin());
        return ole32::S_OK;
    }

    int32_t __stdcall BeginGetEvent(IMFAsyncCallback*, ole32::IUnknown*) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall EndGetEvent(IMFAsyncResult*, IMFMediaEvent**) override { return ole32::E_NOTIMPL; }

    int32_t __stdcall QueueEvent(IMFMediaEvent* pEvent) override {
        if (!pEvent) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_shutdown) return ole32::E_FAIL;
        pEvent->AddRef();
        m_events.push_back(pEvent);
        return ole32::S_OK;
    }

    int32_t __stdcall QueueEventParamVar(MediaEventType met, const GUID& guidExtendedType, int32_t hrStatus, const void*) override {
        auto* ev = new CMediaEvent(met, guidExtendedType, hrStatus);
        int32_t hr = QueueEvent(ev);
        ev->Release();
        return hr;
    }

    int32_t __stdcall QueueEventParamUnk(MediaEventType met, const GUID& guidExtendedType, int32_t hrStatus, ole32::IUnknown* pUnk) override {
        auto* ev = new CMediaEvent(met, guidExtendedType, hrStatus);
        if (pUnk) ev->SetUnknown(GUID{}, pUnk);
        int32_t hr = QueueEvent(ev);
        ev->Release();
        return hr;
    }

    int32_t __stdcall Shutdown() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
        for (auto* ev : m_events) ev->Release();
        m_events.clear();
        return ole32::S_OK;
    }
};

// Base Media Transform (MFT) Implementation
class CBaseTransform : public IMFTransform {
protected:
    uint32_t m_refCount{ 1 };
    std::string m_name;
    GUID m_clsid{};
    GUID m_category{};
    IMFMediaType* m_inputType{ nullptr };
    IMFMediaType* m_outputType{ nullptr };
    std::vector<IMFSample*> m_queuedSamples;
    mutable std::mutex m_mutex;

public:
    CBaseTransform(std::string name, GUID clsid, GUID cat)
        : m_name(std::move(name)), m_clsid(clsid), m_category(cat) {}

    ~CBaseTransform() override {
        if (m_inputType) m_inputType->Release();
        if (m_outputType) m_outputType->Release();
        for (auto* s : m_queuedSamples) s->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFTransform_Local =
            { 0xBFEE914F, 0x0333, 0x4F08, { 0x8C, 0xE6, 0x5F, 0x7D, 0x0E, 0x07, 0x65, 0xBC } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFTransform_Local) {
            *ppvObject = static_cast<IMFTransform*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    const std::string& GetName() const { return m_name; }
    const GUID& GetClsid() const { return m_clsid; }
    const GUID& GetCategory() const { return m_category; }

    int32_t __stdcall GetStreamLimits(uint32_t* pdwInputMinimum, uint32_t* pdwInputMaximum, uint32_t* pdwOutputMinimum, uint32_t* pdwOutputMaximum) override {
        if (pdwInputMinimum) *pdwInputMinimum = 1;
        if (pdwInputMaximum) *pdwInputMaximum = 1;
        if (pdwOutputMinimum) *pdwOutputMinimum = 1;
        if (pdwOutputMaximum) *pdwOutputMaximum = 1;
        return ole32::S_OK;
    }

    int32_t __stdcall GetStreamCount(uint32_t* pcInputStreams, uint32_t* pcOutputStreams) override {
        if (pcInputStreams) *pcInputStreams = 1;
        if (pcOutputStreams) *pcOutputStreams = 1;
        return ole32::S_OK;
    }

    int32_t __stdcall GetStreamIDs(uint32_t, uint32_t* pdwInputIDs, uint32_t, uint32_t* pdwOutputIDs) override {
        if (pdwInputIDs) pdwInputIDs[0] = 0;
        if (pdwOutputIDs) pdwOutputIDs[0] = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall GetInputStreamInfo(uint32_t, MFT_INPUT_STREAM_INFO* pStreamInfo) override {
        if (!pStreamInfo) return ole32::E_POINTER;
        pStreamInfo->cbSize = 4096;
        pStreamInfo->cbAlignment = 1;
        pStreamInfo->cbMaxLookahead = 0;
        pStreamInfo->dwFlags = 0;
        pStreamInfo->hnsMaxLatency = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputStreamInfo(uint32_t, MFT_OUTPUT_STREAM_INFO* pStreamInfo) override {
        if (!pStreamInfo) return ole32::E_POINTER;
        pStreamInfo->cbSize = 4096;
        pStreamInfo->cbAlignment = 1;
        pStreamInfo->dwFlags = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall GetAttributes(IMFAttributes** pAttributes) override {
        if (!pAttributes) return ole32::E_POINTER;
        *pAttributes = new CAttributes();
        return ole32::S_OK;
    }

    int32_t __stdcall GetInputStreamAttributes(uint32_t, IMFAttributes** pAttributes) override { return GetAttributes(pAttributes); }
    int32_t __stdcall GetOutputStreamAttributes(uint32_t, IMFAttributes** pAttributes) override { return GetAttributes(pAttributes); }
    int32_t __stdcall DeleteInputStream(uint32_t) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall AddInputStreams(uint32_t, uint32_t*) override { return ole32::E_NOTIMPL; }

    int32_t __stdcall GetInputAvailableType(uint32_t, uint32_t, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        *ppType = nullptr;
        return MF_E_NO_MORE_TYPES;
    }

    int32_t __stdcall GetOutputAvailableType(uint32_t, uint32_t, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        *ppType = nullptr;
        return MF_E_NO_MORE_TYPES;
    }

    int32_t __stdcall SetInputType(uint32_t, IMFMediaType* pType, uint32_t) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_inputType) m_inputType->Release();
        m_inputType = pType;
        if (m_inputType) m_inputType->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall SetOutputType(uint32_t, IMFMediaType* pType, uint32_t) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_outputType) m_outputType->Release();
        m_outputType = pType;
        if (m_outputType) m_outputType->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetInputCurrentType(uint32_t, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_inputType) return ole32::E_FAIL;
        *ppType = m_inputType;
        (*ppType)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputCurrentType(uint32_t, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_outputType) return ole32::E_FAIL;
        *ppType = m_outputType;
        (*ppType)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetInputStatus(uint32_t, uint32_t* pdwFlags) override {
        if (!pdwFlags) return ole32::E_POINTER;
        *pdwFlags = 0x00000001; // MFT_INPUT_STATUS_ACCEPT_DATA
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputStatus(uint32_t* pdwFlags) override {
        if (!pdwFlags) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pdwFlags = m_queuedSamples.empty() ? 0 : 0x00000001;
        return ole32::S_OK;
    }

    int32_t __stdcall SetOutputBounds(LONGLONG, LONGLONG) override { return ole32::S_OK; }
    int32_t __stdcall ProcessEvent(uint32_t, IMFMediaEvent*) override { return ole32::S_OK; }

    int32_t __stdcall ProcessMessage(MFT_MESSAGE_TYPE eMessage, uint64_t) override {
        if (eMessage == MFT_MESSAGE_COMMAND_FLUSH) {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto* s : m_queuedSamples) s->Release();
            m_queuedSamples.clear();
        }
        return ole32::S_OK;
    }

    int32_t __stdcall ProcessInput(uint32_t, IMFSample* pSample, uint32_t) override {
        if (!pSample) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        pSample->AddRef();
        m_queuedSamples.push_back(pSample);
        return ole32::S_OK;
    }

    int32_t __stdcall ProcessOutput(uint32_t, uint32_t cOutputBufferCount, MFT_OUTPUT_DATA_BUFFER* pOutputSamples, uint32_t* pdwStatus) override {
        if (!pOutputSamples || cOutputBufferCount == 0) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queuedSamples.empty()) return ole32::E_FAIL;

        auto* inSample = m_queuedSamples.front();
        m_queuedSamples.erase(m_queuedSamples.begin());

        if (pOutputSamples[0].pSample) {
            inSample->CopyToBuffer(nullptr); // Transcoding mock
            LONGLONG t = 0, d = 0;
            inSample->GetSampleTime(&t);
            inSample->GetSampleDuration(&d);
            pOutputSamples[0].pSample->SetSampleTime(t);
            pOutputSamples[0].pSample->SetSampleDuration(d);
        } else {
            pOutputSamples[0].pSample = inSample;
            inSample->AddRef();
        }

        inSample->Release();
        if (pdwStatus) *pdwStatus = 0;
        return ole32::S_OK;
    }
};

// Specialized Transforms
class CH264DecoderMFT : public CBaseTransform {
public:
    CH264DecoderMFT()
        : CBaseTransform("Microsoft H.264 Video Decoder MFT", CLSID_CMSH264DecoderMFT, MFT_CATEGORY_VIDEO_DECODER) {}

    int32_t __stdcall GetInputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        if (dwTypeIndex != 0) return ole32::E_FAIL;
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        mt->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
        *ppType = mt;
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        if (dwTypeIndex > 1) return ole32::E_FAIL;
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        mt->SetGUID(MF_MT_SUBTYPE, (dwTypeIndex == 0) ? MFVideoFormat_NV12 : MFVideoFormat_RGB32);
        *ppType = mt;
        return ole32::S_OK;
    }
};

class CAACDecoderMFT : public CBaseTransform {
public:
    CAACDecoderMFT()
        : CBaseTransform("Microsoft AAC Audio Decoder MFT", CLSID_CMSAACDecMFT, MFT_CATEGORY_AUDIO_DECODER) {}

    int32_t __stdcall GetInputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        if (dwTypeIndex != 0) return ole32::E_FAIL;
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        mt->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_AAC);
        *ppType = mt;
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        if (dwTypeIndex != 0) return ole32::E_FAIL;
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        mt->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_PCM);
        *ppType = mt;
        return ole32::S_OK;
    }
};

class CColorConvertMFT : public CBaseTransform {
public:
    CColorConvertMFT()
        : CBaseTransform("Color Converter DMO/MFT", CLSID_CColorConvertDMO, MFT_CATEGORY_VIDEO_EFFECT) {}

    int32_t __stdcall GetInputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        if (dwTypeIndex != 0) return ole32::E_FAIL;
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        mt->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
        *ppType = mt;
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        if (dwTypeIndex != 0) return ole32::E_FAIL;
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        mt->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);
        *ppType = mt;
        return ole32::S_OK;
    }
};

class CAudioResamplerMFT : public CBaseTransform {
public:
    CAudioResamplerMFT()
        : CBaseTransform("Audio Resampler MFT", CLSID_CResamplerMediaObject, MFT_CATEGORY_AUDIO_EFFECT) {}

    int32_t __stdcall GetInputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        if (dwTypeIndex != 0) return ole32::E_FAIL;
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        mt->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_PCM);
        *ppType = mt;
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        if (dwTypeIndex != 0) return ole32::E_FAIL;
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        mt->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_PCM);
        *ppType = mt;
        return ole32::S_OK;
    }
};

// ============================================================================
// 4. Source Reader & Sink Writer Architecture
// ============================================================================

class CSourceReader : public IMFSourceReader {
    uint32_t m_refCount{ 1 };
    std::wstring m_url;
    IMFByteStream* m_pByteStream{ nullptr };
    std::vector<IMFMediaType*> m_streams;
    uint32_t m_sampleIndex{ 0 };

public:
    explicit CSourceReader(std::wstring url, IMFByteStream* pStream = nullptr)
        : m_url(std::move(url)), m_pByteStream(pStream) {
        if (m_pByteStream) m_pByteStream->AddRef();
        initDefaultStreams();
    }

    ~CSourceReader() override {
        if (m_pByteStream) m_pByteStream->Release();
        for (auto* s : m_streams) s->Release();
    }

    void initDefaultStreams() {
        // Stream 0: Video (H.264 / 1080p / 30fps)
        auto* vType = new CMediaType();
        vType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        vType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
        vType->SetUINT64(MF_MT_FRAME_SIZE, (static_cast<uint64_t>(1920) << 32) | 1080);
        vType->SetUINT64(MF_MT_FRAME_RATE, (static_cast<uint64_t>(30) << 32) | 1);
        m_streams.push_back(vType);

        // Stream 1: Audio (AAC / 48kHz / Stereo)
        auto* aType = new CMediaType();
        aType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        aType->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_AAC);
        aType->SetUINT32(MF_MT_AUDIO_NUM_CHANNELS, 2);
        aType->SetUINT32(MF_MT_AUDIO_SAMPLES_PER_SECOND, 48000);
        aType->SetUINT32(MF_MT_AUDIO_BITS_PER_SAMPLE, 16);
        m_streams.push_back(aType);
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFSourceReader_Local =
            { 0x70AE66F2, 0xC809, 0x4E4F, { 0x89, 0x15, 0xBD, 0xCB, 0x40, 0x40, 0x41, 0x0C } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFSourceReader_Local) {
            *ppvObject = static_cast<IMFSourceReader*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFSourceReader
    int32_t __stdcall GetStreamSelection(uint32_t dwStreamIndex, int32_t* pfSelected) override {
        if (!pfSelected) return ole32::E_POINTER;
        *pfSelected = (dwStreamIndex < m_streams.size()) ? 1 : 0;
        return ole32::S_OK;
    }

    int32_t __stdcall SetStreamSelection(uint32_t, int32_t) override { return ole32::S_OK; }

    int32_t __stdcall GetNativeMediaType(uint32_t dwStreamIndex, uint32_t, IMFMediaType** ppMediaType) override {
        if (!ppMediaType) return ole32::E_POINTER;
        if (dwStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;
        *ppMediaType = m_streams[dwStreamIndex];
        (*ppMediaType)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetCurrentMediaType(uint32_t dwStreamIndex, IMFMediaType** ppMediaType) override {
        return GetNativeMediaType(dwStreamIndex, 0, ppMediaType);
    }

    int32_t __stdcall SetCurrentMediaType(uint32_t, uint32_t*, IMFMediaType*) override { return ole32::S_OK; }
    int32_t __stdcall SetStreamPosition(const GUID&, const void*) override { return ole32::S_OK; }

    int32_t __stdcall ReadSample(
        uint32_t dwStreamIndex,
        uint32_t,
        uint32_t* pdwActualStreamIndex,
        uint32_t* pdwStreamFlags,
        LONGLONG* pllTimestamp,
        IMFSample** ppSample) override
    {
        if (!ppSample || !pdwStreamFlags || !pllTimestamp) return ole32::E_POINTER;
        if (pdwActualStreamIndex) *pdwActualStreamIndex = dwStreamIndex;

        if (m_sampleIndex >= 100) {
            *pdwStreamFlags = MF_SOURCE_READERF_ENDOFSTREAM;
            *ppSample = nullptr;
            return ole32::S_OK;
        }

        *pdwStreamFlags = 0;
        LONGLONG frameDuration = 333333; // 33.3ms for 30fps video in 100-ns units
        *pllTimestamp = m_sampleIndex * frameDuration;

        auto* sample = new CSample();
        sample->SetSampleTime(*pllTimestamp);
        sample->SetSampleDuration(frameDuration);

        // Generate synthetic buffer (1024 bytes)
        auto* buf = new CMediaBuffer(1024);
        uint8_t* pData = nullptr;
        buf->Lock(&pData, nullptr, nullptr);
        std::memset(pData, static_cast<uint8_t>(m_sampleIndex & 0xFF), 1024);
        buf->Unlock();
        buf->SetCurrentLength(1024);

        sample->AddBuffer(buf);
        buf->Release();

        *ppSample = sample;
        m_sampleIndex++;
        return ole32::S_OK;
    }

    int32_t __stdcall Flush(uint32_t) override {
        m_sampleIndex = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall GetServiceForStream(uint32_t, const GUID&, const GUID&, void**) override {
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall GetPresentationAttribute(uint32_t, const GUID&, void*) override {
        return ole32::E_NOTIMPL;
    }
};

class CSinkWriter : public IMFSinkWriter {
    uint32_t m_refCount{ 1 };
    std::wstring m_url;
    std::vector<IMFMediaType*> m_streams;
    uint32_t m_samplesWritten{ 0 };
    uint64_t m_bytesWritten{ 0 };
    bool m_writing{ false };
    bool m_finalized{ false };

public:
    explicit CSinkWriter(std::wstring url) : m_url(std::move(url)) {}

    ~CSinkWriter() override {
        for (auto* s : m_streams) s->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFSinkWriter_Local =
            { 0x3137F1CD, 0xFE5C, 0x4009, { 0xA5, 0x80, 0xF4, 0x4B, 0x7C, 0xE0, 0x19, 0x13 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFSinkWriter_Local) {
            *ppvObject = static_cast<IMFSinkWriter*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFSinkWriter
    int32_t __stdcall AddStream(IMFMediaType* pTargetMediaType, uint32_t* pdwStreamIndex) override {
        if (!pTargetMediaType || !pdwStreamIndex) return ole32::E_POINTER;
        if (m_writing) return ole32::E_FAIL;
        pTargetMediaType->AddRef();
        m_streams.push_back(pTargetMediaType);
        *pdwStreamIndex = static_cast<uint32_t>(m_streams.size() - 1);
        return ole32::S_OK;
    }

    int32_t __stdcall SetInputMediaType(uint32_t dwStreamIndex, IMFMediaType*, IMFAttributes*) override {
        if (dwStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;
        return ole32::S_OK;
    }

    int32_t __stdcall BeginWriting() override {
        m_writing = true;
        return ole32::S_OK;
    }

    int32_t __stdcall WriteSample(uint32_t dwStreamIndex, IMFSample* pSample) override {
        if (!pSample) return ole32::E_POINTER;
        if (!m_writing || m_finalized) return ole32::E_FAIL;
        if (dwStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;

        uint32_t totalLen = 0;
        pSample->GetTotalLength(&totalLen);
        m_bytesWritten += totalLen;
        m_samplesWritten++;
        return ole32::S_OK;
    }

    int32_t __stdcall SendStreamTick(uint32_t, LONGLONG) override { return ole32::S_OK; }
    int32_t __stdcall PlaceMarker(uint32_t, void*) override { return ole32::S_OK; }
    int32_t __stdcall NotifyEndOfSegment(uint32_t) override { return ole32::S_OK; }
    int32_t __stdcall Flush(uint32_t) override { return ole32::S_OK; }

    int32_t __stdcall Finalize() override {
        m_finalized = true;
        return ole32::S_OK;
    }

    int32_t __stdcall GetServiceForStream(uint32_t, const GUID&, const GUID&, void**) override {
        return ole32::E_NOTIMPL;
    }

    uint32_t GetSamplesWritten() const { return m_samplesWritten; }
    uint64_t GetBytesWritten() const { return m_bytesWritten; }
};

// ============================================================================
// 5. Media Session & Topology Architecture
// ============================================================================

class CTopologyNode : public CAttributes, public IMFTopologyNode {
    MF_TOPOLOGY_TYPE m_type{ MF_TOPOLOGY_TRANSFORM_NODE };
    uint64_t m_nodeId{ 0 };
    ole32::IUnknown* m_pObject{ nullptr };
    std::vector<std::pair<IMFTopologyNode*, uint32_t>> m_outputs;
    std::vector<std::pair<IMFTopologyNode*, uint32_t>> m_inputs;

public:
    explicit CTopologyNode(MF_TOPOLOGY_TYPE type) : m_type(type) {}

    ~CTopologyNode() override {
        if (m_pObject) m_pObject->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFTopologyNode_Local =
            { 0x83015D31, 0xE743, 0x4262, { 0xA0, 0x1B, 0x42, 0xBB, 0x34, 0x78, 0x78, 0x85 } };
        static const GUID IID_IMFAttributes_Local =
            { 0x2CD2D928, 0x0776, 0x4E86, { 0x82, 0x24, 0xE0, 0x2C, 0x0E, 0x58, 0x9C, 0x41 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFTopologyNode_Local) {
            *ppvObject = static_cast<IMFTopologyNode*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMFAttributes_Local) {
            *ppvObject = static_cast<IMFAttributes*>(static_cast<IMFTopologyNode*>(this));
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFAttributes delegation
    int32_t __stdcall GetItem(const GUID& k, void* v) override { return CAttributes::GetItem(k, v); }
    int32_t __stdcall GetItemType(const GUID& k, MF_ATTRIBUTE_TYPE* t) override { return CAttributes::GetItemType(k, t); }
    int32_t __stdcall CompareItem(const GUID& k, const void* v, int32_t* r) override { return CAttributes::CompareItem(k, v, r); }
    int32_t __stdcall Compare(IMFAttributes* t, MF_ATTRIBUTES_MATCH_TYPE m, int32_t* r) override { return CAttributes::Compare(t, m, r); }
    int32_t __stdcall GetUINT32(const GUID& k, uint32_t* v) override { return CAttributes::GetUINT32(k, v); }
    int32_t __stdcall GetUINT64(const GUID& k, uint64_t* v) override { return CAttributes::GetUINT64(k, v); }
    int32_t __stdcall GetDouble(const GUID& k, double* v) override { return CAttributes::GetDouble(k, v); }
    int32_t __stdcall GetGUID(const GUID& k, GUID* v) override { return CAttributes::GetGUID(k, v); }
    int32_t __stdcall GetStringLength(const GUID& k, uint32_t* l) override { return CAttributes::GetStringLength(k, l); }
    int32_t __stdcall GetString(const GUID& k, wchar_t* b, uint32_t s, uint32_t* l) override { return CAttributes::GetString(k, b, s, l); }
    int32_t __stdcall GetAllocatedString(const GUID& k, wchar_t** b, uint32_t* l) override { return CAttributes::GetAllocatedString(k, b, l); }
    int32_t __stdcall GetBlobSize(const GUID& k, uint32_t* s) override { return CAttributes::GetBlobSize(k, s); }
    int32_t __stdcall GetBlob(const GUID& k, uint8_t* b, uint32_t s, uint32_t* bs) override { return CAttributes::GetBlob(k, b, s, bs); }
    int32_t __stdcall GetAllocatedBlob(const GUID& k, uint8_t** b, uint32_t* s) override { return CAttributes::GetAllocatedBlob(k, b, s); }
    int32_t __stdcall GetUnknown(const GUID& k, const GUID& r, void** p) override { return CAttributes::GetUnknown(k, r, p); }
    int32_t __stdcall SetItem(const GUID& k, const void* v) override { return CAttributes::SetItem(k, v); }
    int32_t __stdcall DeleteItem(const GUID& k) override { return CAttributes::DeleteItem(k); }
    int32_t __stdcall DeleteAllItems() override { return CAttributes::DeleteAllItems(); }
    int32_t __stdcall SetUINT32(const GUID& k, uint32_t v) override { return CAttributes::SetUINT32(k, v); }
    int32_t __stdcall SetUINT64(const GUID& k, uint64_t v) override { return CAttributes::SetUINT64(k, v); }
    int32_t __stdcall SetDouble(const GUID& k, double v) override { return CAttributes::SetDouble(k, v); }
    int32_t __stdcall SetGUID(const GUID& k, const GUID& v) override { return CAttributes::SetGUID(k, v); }
    int32_t __stdcall SetString(const GUID& k, const wchar_t* v) override { return CAttributes::SetString(k, v); }
    int32_t __stdcall SetBlob(const GUID& k, const uint8_t* b, uint32_t s) override { return CAttributes::SetBlob(k, b, s); }
    int32_t __stdcall SetUnknown(const GUID& k, ole32::IUnknown* p) override { return CAttributes::SetUnknown(k, p); }
    int32_t __stdcall LockStore() override { return CAttributes::LockStore(); }
    int32_t __stdcall UnlockStore() override { return CAttributes::UnlockStore(); }
    int32_t __stdcall GetCount(uint32_t* c) override { return CAttributes::GetCount(c); }
    int32_t __stdcall GetItemByIndex(uint32_t i, GUID* g, void* v) override { return CAttributes::GetItemByIndex(i, g, v); }
    int32_t __stdcall CopyAllItems(IMFAttributes* d) override { return CAttributes::CopyAllItems(d); }

    // IMFTopologyNode
    int32_t __stdcall SetObject(ole32::IUnknown* pObject) override {
        if (m_pObject) m_pObject->Release();
        m_pObject = pObject;
        if (m_pObject) m_pObject->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetObject(ole32::IUnknown** ppObject) override {
        if (!ppObject) return ole32::E_POINTER;
        *ppObject = m_pObject;
        if (*ppObject) (*ppObject)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetNodeType(MF_TOPOLOGY_TYPE* pType) override {
        if (!pType) return ole32::E_POINTER;
        *pType = m_type;
        return ole32::S_OK;
    }

    int32_t __stdcall GetTopoNodeID(uint64_t* pID) override {
        if (!pID) return ole32::E_POINTER;
        *pID = m_nodeId;
        return ole32::S_OK;
    }

    int32_t __stdcall SetTopoNodeID(uint64_t ullTopoNodeID) override {
        m_nodeId = ullTopoNodeID;
        return ole32::S_OK;
    }

    int32_t __stdcall ConnectOutput(uint32_t dwOutputIndex, IMFTopologyNode* pDownstreamNode, uint32_t dwInputIndexOnDownstreamNode) override {
        if (!pDownstreamNode) return ole32::E_POINTER;
        if (dwOutputIndex >= m_outputs.size()) m_outputs.resize(dwOutputIndex + 1);
        m_outputs[dwOutputIndex] = { pDownstreamNode, dwInputIndexOnDownstreamNode };
        auto* pDown = dynamic_cast<CTopologyNode*>(pDownstreamNode);
        if (pDown) {
            if (dwInputIndexOnDownstreamNode >= pDown->m_inputs.size()) {
                pDown->m_inputs.resize(dwInputIndexOnDownstreamNode + 1);
            }
            pDown->m_inputs[dwInputIndexOnDownstreamNode] = { this, dwOutputIndex };
        }
        return ole32::S_OK;
    }

    int32_t __stdcall DisconnectOutput(uint32_t dwOutputIndex) override {
        if (dwOutputIndex < m_outputs.size()) {
            auto* pDownstream = m_outputs[dwOutputIndex].first;
            uint32_t downInput = m_outputs[dwOutputIndex].second;
            m_outputs[dwOutputIndex] = { nullptr, 0 };
            if (pDownstream) {
                auto* pDown = dynamic_cast<CTopologyNode*>(pDownstream);
                if (pDown && downInput < pDown->m_inputs.size() && pDown->m_inputs[downInput].first == this) {
                    pDown->m_inputs[downInput] = { nullptr, 0 };
                }
            }
        }
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutput(uint32_t dwOutputIndex, IMFTopologyNode** ppDownstreamNode, uint32_t* pdwInputIndexOnDownstreamNode) override {
        if (!ppDownstreamNode) return ole32::E_POINTER;
        if (dwOutputIndex >= m_outputs.size() || !m_outputs[dwOutputIndex].first) return ole32::E_FAIL;
        *ppDownstreamNode = m_outputs[dwOutputIndex].first;
        (*ppDownstreamNode)->AddRef();
        if (pdwInputIndexOnDownstreamNode) *pdwInputIndexOnDownstreamNode = m_outputs[dwOutputIndex].second;
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputCount(uint32_t* pdwOutputCount) override {
        if (!pdwOutputCount) return ole32::E_POINTER;
        *pdwOutputCount = static_cast<uint32_t>(m_outputs.size());
        return ole32::S_OK;
    }

    int32_t __stdcall GetInput(uint32_t dwInputIndex, IMFTopologyNode** ppUpstreamNode, uint32_t* pdwOutputIndexOnUpstreamNode) override {
        if (!ppUpstreamNode) return ole32::E_POINTER;
        if (dwInputIndex >= m_inputs.size() || !m_inputs[dwInputIndex].first) return ole32::E_FAIL;
        *ppUpstreamNode = m_inputs[dwInputIndex].first;
        (*ppUpstreamNode)->AddRef();
        if (pdwOutputIndexOnUpstreamNode) *pdwOutputIndexOnUpstreamNode = m_inputs[dwInputIndex].second;
        return ole32::S_OK;
    }

    int32_t __stdcall GetInputCount(uint32_t* pdwInputCount) override {
        if (!pdwInputCount) return ole32::E_POINTER;
        *pdwInputCount = static_cast<uint32_t>(m_inputs.size());
        return ole32::S_OK;
    }
};

class CTopology : public CAttributes, public IMFTopology {
    uint64_t m_topoId{ 1 };
    std::vector<IMFTopologyNode*> m_nodes;

public:
    CTopology() = default;
    ~CTopology() override {
        Clear();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFTopology_Local =
            { 0x83015D30, 0xE743, 0x4262, { 0xA0, 0x1B, 0x42, 0xBB, 0x34, 0x78, 0x78, 0x85 } };
        static const GUID IID_IMFAttributes_Local =
            { 0x2CD2D928, 0x0776, 0x4E86, { 0x82, 0x24, 0xE0, 0x2C, 0x0E, 0x58, 0x9C, 0x41 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFTopology_Local) {
            *ppvObject = static_cast<IMFTopology*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMFAttributes_Local) {
            *ppvObject = static_cast<IMFAttributes*>(static_cast<IMFTopology*>(this));
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFAttributes delegation
    int32_t __stdcall GetItem(const GUID& k, void* v) override { return CAttributes::GetItem(k, v); }
    int32_t __stdcall GetItemType(const GUID& k, MF_ATTRIBUTE_TYPE* t) override { return CAttributes::GetItemType(k, t); }
    int32_t __stdcall CompareItem(const GUID& k, const void* v, int32_t* r) override { return CAttributes::CompareItem(k, v, r); }
    int32_t __stdcall Compare(IMFAttributes* t, MF_ATTRIBUTES_MATCH_TYPE m, int32_t* r) override { return CAttributes::Compare(t, m, r); }
    int32_t __stdcall GetUINT32(const GUID& k, uint32_t* v) override { return CAttributes::GetUINT32(k, v); }
    int32_t __stdcall GetUINT64(const GUID& k, uint64_t* v) override { return CAttributes::GetUINT64(k, v); }
    int32_t __stdcall GetDouble(const GUID& k, double* v) override { return CAttributes::GetDouble(k, v); }
    int32_t __stdcall GetGUID(const GUID& k, GUID* v) override { return CAttributes::GetGUID(k, v); }
    int32_t __stdcall GetStringLength(const GUID& k, uint32_t* l) override { return CAttributes::GetStringLength(k, l); }
    int32_t __stdcall GetString(const GUID& k, wchar_t* b, uint32_t s, uint32_t* l) override { return CAttributes::GetString(k, b, s, l); }
    int32_t __stdcall GetAllocatedString(const GUID& k, wchar_t** b, uint32_t* l) override { return CAttributes::GetAllocatedString(k, b, l); }
    int32_t __stdcall GetBlobSize(const GUID& k, uint32_t* s) override { return CAttributes::GetBlobSize(k, s); }
    int32_t __stdcall GetBlob(const GUID& k, uint8_t* b, uint32_t s, uint32_t* bs) override { return CAttributes::GetBlob(k, b, s, bs); }
    int32_t __stdcall GetAllocatedBlob(const GUID& k, uint8_t** b, uint32_t* s) override { return CAttributes::GetAllocatedBlob(k, b, s); }
    int32_t __stdcall GetUnknown(const GUID& k, const GUID& r, void** p) override { return CAttributes::GetUnknown(k, r, p); }
    int32_t __stdcall SetItem(const GUID& k, const void* v) override { return CAttributes::SetItem(k, v); }
    int32_t __stdcall DeleteItem(const GUID& k) override { return CAttributes::DeleteItem(k); }
    int32_t __stdcall DeleteAllItems() override { return CAttributes::DeleteAllItems(); }
    int32_t __stdcall SetUINT32(const GUID& k, uint32_t v) override { return CAttributes::SetUINT32(k, v); }
    int32_t __stdcall SetUINT64(const GUID& k, uint64_t v) override { return CAttributes::SetUINT64(k, v); }
    int32_t __stdcall SetDouble(const GUID& k, double v) override { return CAttributes::SetDouble(k, v); }
    int32_t __stdcall SetGUID(const GUID& k, const GUID& v) override { return CAttributes::SetGUID(k, v); }
    int32_t __stdcall SetString(const GUID& k, const wchar_t* v) override { return CAttributes::SetString(k, v); }
    int32_t __stdcall SetBlob(const GUID& k, const uint8_t* b, uint32_t s) override { return CAttributes::SetBlob(k, b, s); }
    int32_t __stdcall SetUnknown(const GUID& k, ole32::IUnknown* p) override { return CAttributes::SetUnknown(k, p); }
    int32_t __stdcall LockStore() override { return CAttributes::LockStore(); }
    int32_t __stdcall UnlockStore() override { return CAttributes::UnlockStore(); }
    int32_t __stdcall GetCount(uint32_t* c) override { return CAttributes::GetCount(c); }
    int32_t __stdcall GetItemByIndex(uint32_t i, GUID* g, void* v) override { return CAttributes::GetItemByIndex(i, g, v); }
    int32_t __stdcall CopyAllItems(IMFAttributes* d) override { return CAttributes::CopyAllItems(d); }

    // IMFTopology
    int32_t __stdcall GetTopologyID(uint64_t* pID) override {
        if (!pID) return ole32::E_POINTER;
        *pID = m_topoId;
        return ole32::S_OK;
    }

    int32_t __stdcall AddNode(IMFTopologyNode* pNode) override {
        if (!pNode) return ole32::E_POINTER;
        pNode->AddRef();
        m_nodes.push_back(pNode);
        return ole32::S_OK;
    }

    int32_t __stdcall RemoveNode(IMFTopologyNode* pNode) override {
        auto it = std::find(m_nodes.begin(), m_nodes.end(), pNode);
        if (it != m_nodes.end()) {
            (*it)->Release();
            m_nodes.erase(it);
            return ole32::S_OK;
        }
        return ole32::E_FAIL;
    }

    int32_t __stdcall GetNodeCount(uint16_t* pwNodes) override {
        if (!pwNodes) return ole32::E_POINTER;
        *pwNodes = static_cast<uint16_t>(m_nodes.size());
        return ole32::S_OK;
    }

    int32_t __stdcall GetNode(uint16_t wIndex, IMFTopologyNode** ppNode) override {
        if (!ppNode) return ole32::E_POINTER;
        if (wIndex >= m_nodes.size()) return ole32::E_INVALIDARG;
        *ppNode = m_nodes[wIndex];
        (*ppNode)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall Clear() override {
        for (auto* n : m_nodes) n->Release();
        m_nodes.clear();
        return ole32::S_OK;
    }

    int32_t __stdcall CloneFrom(IMFTopology* pTopology) override {
        if (!pTopology) return ole32::E_POINTER;
        Clear();
        pTopology->CopyAllItems(static_cast<IMFTopology*>(this));
        pTopology->GetTopologyID(&m_topoId);
        uint16_t nodeCount = 0;
        pTopology->GetNodeCount(&nodeCount);
        std::map<IMFTopologyNode*, IMFTopologyNode*> oldToNew;
        for (uint16_t i = 0; i < nodeCount; ++i) {
            IMFTopologyNode* pOldNode = nullptr;
            if (pTopology->GetNode(i, &pOldNode) == ole32::S_OK && pOldNode) {
                MF_TOPOLOGY_TYPE nType{};
                pOldNode->GetNodeType(&nType);
                auto* pNewNode = new CTopologyNode(nType);
                pOldNode->CopyAllItems(static_cast<IMFTopologyNode*>(pNewNode));
                uint64_t nId = 0;
                pOldNode->GetTopoNodeID(&nId);
                pNewNode->SetTopoNodeID(nId);
                ole32::IUnknown* pObj = nullptr;
                if (pOldNode->GetObject(&pObj) == ole32::S_OK && pObj) {
                    pNewNode->SetObject(pObj);
                    pObj->Release();
                }
                AddNode(pNewNode);
                oldToNew[pOldNode] = pNewNode;
                pNewNode->Release(); // AddNode added a ref
                pOldNode->Release();
            }
        }
        for (uint16_t i = 0; i < nodeCount; ++i) {
            IMFTopologyNode* pOldNode = nullptr;
            if (pTopology->GetNode(i, &pOldNode) == ole32::S_OK && pOldNode) {
                auto itNew = oldToNew.find(pOldNode);
                if (itNew != oldToNew.end()) {
                    auto* pNewNode = itNew->second;
                    uint32_t outCount = 0;
                    pOldNode->GetOutputCount(&outCount);
                    for (uint32_t o = 0; o < outCount; ++o) {
                        IMFTopologyNode* pOldDownstream = nullptr;
                        uint32_t downInputIdx = 0;
                        if (pOldNode->GetOutput(o, &pOldDownstream, &downInputIdx) == ole32::S_OK && pOldDownstream) {
                            auto itDown = oldToNew.find(pOldDownstream);
                            if (itDown != oldToNew.end()) {
                                pNewNode->ConnectOutput(o, itDown->second, downInputIdx);
                            }
                            pOldDownstream->Release();
                        }
                    }
                }
                pOldNode->Release();
            }
        }
        return ole32::S_OK;
    }

    int32_t __stdcall GetNodeByID(uint64_t ullTopoNodeID, IMFTopologyNode** ppNode) override {
        if (!ppNode) return ole32::E_POINTER;
        for (auto* n : m_nodes) {
            uint64_t nid = 0;
            n->GetTopoNodeID(&nid);
            if (nid == ullTopoNodeID) {
                *ppNode = n;
                (*ppNode)->AddRef();
                return ole32::S_OK;
            }
        }
        return ole32::E_FAIL;
    }

    int32_t __stdcall GetSourceNodeCollection(void**) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall GetOutputNodeCollection(void**) override { return ole32::E_NOTIMPL; }
};

class CMediaSession : public IMFMediaSession {
    uint32_t m_refCount{ 1 };
    IMFMediaEventQueue* m_pEventQueue{ nullptr };
    IMFTopology* m_pTopology{ nullptr };
    bool m_running{ false };
    bool m_closed{ false };

public:
    CMediaSession() {
        m_pEventQueue = new CMediaEventQueue();
    }

    ~CMediaSession() override {
        Close();
        if (m_pTopology) m_pTopology->Release();
        if (m_pEventQueue) m_pEventQueue->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        static const GUID IID_IMFMediaSession_Local =
            { 0x90377834, 0x21D0, 0x4035, { 0x90, 0x2C, 0xF5, 0xF5, 0x70, 0x9C, 0xD0, 0x00 } };
        static const GUID IID_IMFMediaEventQueue_Local =
            { 0x36F846FC, 0x2256, 0x48B6, { 0xB5, 0x8E, 0xE2, 0xB6, 0x38, 0x31, 0x65, 0x81 } };
        if (riid == ole32::IID_IUnknown || riid == IID_IMFMediaSession_Local || riid == IID_IMFMediaEventQueue_Local) {
            *ppvObject = static_cast<IMFMediaSession*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // IMFMediaEventQueue delegation
    int32_t __stdcall GetEvent(uint32_t flags, IMFMediaEvent** ppEvent) override { return m_pEventQueue->GetEvent(flags, ppEvent); }
    int32_t __stdcall BeginGetEvent(IMFAsyncCallback* cb, ole32::IUnknown* unk) override { return m_pEventQueue->BeginGetEvent(cb, unk); }
    int32_t __stdcall EndGetEvent(IMFAsyncResult* res, IMFMediaEvent** ppEvent) override { return m_pEventQueue->EndGetEvent(res, ppEvent); }
    int32_t __stdcall QueueEvent(IMFMediaEvent* ev) override { return m_pEventQueue->QueueEvent(ev); }
    int32_t __stdcall QueueEventParamVar(MediaEventType m, const GUID& g, int32_t h, const void* v) override { return m_pEventQueue->QueueEventParamVar(m, g, h, v); }
    int32_t __stdcall QueueEventParamUnk(MediaEventType m, const GUID& g, int32_t h, ole32::IUnknown* u) override { return m_pEventQueue->QueueEventParamUnk(m, g, h, u); }
    int32_t __stdcall Shutdown() override { return m_pEventQueue->Shutdown(); }

    // IMFMediaSession
    int32_t __stdcall SetTopology(uint32_t, IMFTopology* pTopology) override {
        if (!pTopology) return ole32::E_POINTER;
        if (m_pTopology) m_pTopology->Release();
        m_pTopology = pTopology;
        m_pTopology->AddRef();
        QueueEventParamVar(MESessionTopologySet, GUID{}, ole32::S_OK, nullptr);
        return ole32::S_OK;
    }

    int32_t __stdcall ClearTopologies() override {
        if (m_pTopology) {
            m_pTopology->Release();
            m_pTopology = nullptr;
        }
        QueueEventParamVar(MESessionTopologiesCleared, GUID{}, ole32::S_OK, nullptr);
        return ole32::S_OK;
    }

    int32_t __stdcall Start(const GUID*, const void*) override {
        m_running = true;
        QueueEventParamVar(MESessionStarted, GUID{}, ole32::S_OK, nullptr);
        return ole32::S_OK;
    }

    int32_t __stdcall Pause() override {
        m_running = false;
        QueueEventParamVar(MESessionPaused, GUID{}, ole32::S_OK, nullptr);
        return ole32::S_OK;
    }

    int32_t __stdcall Stop() override {
        m_running = false;
        QueueEventParamVar(MESessionStopped, GUID{}, ole32::S_OK, nullptr);
        return ole32::S_OK;
    }

    int32_t __stdcall Close() override {
        if (!m_closed) {
            m_running = false;
            m_closed = true;
            QueueEventParamVar(MESessionClosed, GUID{}, ole32::S_OK, nullptr);
        }
        return ole32::S_OK;
    }

    int32_t __stdcall GetClock(ole32::IUnknown**) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall GetSessionCapabilities(uint32_t* pdwCaps) override {
        if (!pdwCaps) return ole32::E_POINTER;
        *pdwCaps = 0x00000007; // CanSeek, CanPause, CanScrub
        return ole32::S_OK;
    }

    int32_t __stdcall GetFullTopology(uint32_t, uint64_t, IMFTopology** ppFullTopology) override {
        if (!ppFullTopology) return ole32::E_POINTER;
        if (!m_pTopology) return ole32::E_FAIL;
        *ppFullTopology = m_pTopology;
        (*ppFullTopology)->AddRef();
        return ole32::S_OK;
    }

    bool IsRunning() const { return m_running; }
    bool IsClosed() const { return m_closed; }
};

// ============================================================================
// 6. Media Foundation Platform Registry & Factory APIs
// ============================================================================

class MediaFoundationPlatform {
    bool m_initialized{ false };
    std::mutex m_mutex;
    std::map<GUID, std::shared_ptr<CBaseTransform>, GuidLess> m_registeredTransforms;
    uint32_t m_nextWorkQueueId{ 1 };

    MediaFoundationPlatform() {
        // Register default codecs
        registerBuiltinTransform(std::make_shared<CH264DecoderMFT>());
        registerBuiltinTransform(std::make_shared<CAACDecoderMFT>());
        registerBuiltinTransform(std::make_shared<CColorConvertMFT>());
        registerBuiltinTransform(std::make_shared<CAudioResamplerMFT>());
    }

public:
    static MediaFoundationPlatform& get() {
        static MediaFoundationPlatform s_instance;
        return s_instance;
    }

    void registerBuiltinTransform(std::shared_ptr<CBaseTransform> t) {
        m_registeredTransforms[t->GetClsid()] = t;
    }

    int32_t startup(uint32_t dwVersion, uint32_t) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwVersion != MF_VERSION && dwVersion != 0x00020070 && dwVersion != 0x00010070) {
            // Permit minor variances for compatibility
        }
        m_initialized = true;
        return ole32::S_OK;
    }

    int32_t shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_initialized = false;
        return ole32::S_OK;
    }

    bool isInitialized() const { return m_initialized; }

    uint32_t allocateWorkQueue() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_nextWorkQueueId++;
    }

    void unlockWorkQueue(uint32_t) {
        // Work queue released
    }

    const std::map<GUID, std::shared_ptr<CBaseTransform>, GuidLess>& getTransforms() const {
        return m_registeredTransforms;
    }
};

// ============================================================================
// 7. C Entry Points (mfplat.dll, mf.dll, mfreadwrite.dll)
// ============================================================================

// mfplat.dll
inline int32_t __stdcall MFStartup(uint32_t dwVersion, uint32_t dwFlags) {
    return MediaFoundationPlatform::get().startup(dwVersion, dwFlags);
}

inline int32_t __stdcall MFShutdown() {
    return MediaFoundationPlatform::get().shutdown();
}

inline int32_t __stdcall MFCreateAttributes(IMFAttributes** ppMFAttributes, uint32_t) {
    if (!ppMFAttributes) return ole32::E_POINTER;
    *ppMFAttributes = new CAttributes();
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateMemoryBuffer(uint32_t cbMaxLength, IMFMediaBuffer** ppBuffer) {
    if (!ppBuffer) return ole32::E_POINTER;
    *ppBuffer = new CMediaBuffer(cbMaxLength);
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateSample(IMFSample** ppSample) {
    if (!ppSample) return ole32::E_POINTER;
    *ppSample = new CSample();
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateMediaType(IMFMediaType** ppMFType) {
    if (!ppMFType) return ole32::E_POINTER;
    *ppMFType = new CMediaType();
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateAsyncResult(
    ole32::IUnknown* punkObject,
    IMFAsyncCallback* pCallback,
    ole32::IUnknown* punkState,
    IMFAsyncResult** ppOut)
{
    if (!ppOut) return ole32::E_POINTER;
    *ppOut = new CAsyncResult(punkObject, pCallback, punkState);
    return ole32::S_OK;
}

inline int32_t __stdcall MFInvokeCallback(IMFAsyncResult* pResult) {
    if (!pResult) return ole32::E_POINTER;
    auto* ar = dynamic_cast<CAsyncResult*>(pResult);
    if (ar && ar->GetCallback()) {
        return ar->GetCallback()->Invoke(pResult);
    }
    return ole32::S_OK;
}

inline int32_t __stdcall MFAllocateWorkQueue(uint32_t* pdwWorkQueueId) {
    if (!pdwWorkQueueId) return ole32::E_POINTER;
    *pdwWorkQueueId = MediaFoundationPlatform::get().allocateWorkQueue();
    return ole32::S_OK;
}

inline int32_t __stdcall MFUnlockWorkQueue(uint32_t dwWorkQueueId) {
    MediaFoundationPlatform::get().unlockWorkQueue(dwWorkQueueId);
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateEventQueue(IMFMediaEventQueue** ppQueue) {
    if (!ppQueue) return ole32::E_POINTER;
    *ppQueue = new CMediaEventQueue();
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateFile(
    MF_FILE_ACCESS_MODE,
    MF_FILE_OPEN_MODE,
    MF_FILE_FLAGS,
    const wchar_t*,
    IMFByteStream** ppByteStream)
{
    if (!ppByteStream) return ole32::E_POINTER;
    *ppByteStream = new CMemoryByteStream();
    return ole32::S_OK;
}

inline int32_t __stdcall MFTRegister(
    GUID clsidMFT,
    GUID guidCategory,
    const wchar_t* pszName,
    uint32_t,
    uint32_t,
    const void*,
    uint32_t,
    const void*,
    IMFAttributes*)
{
    std::string name;
    if (pszName) {
        while (*pszName) name.push_back(static_cast<char>(*pszName++));
    } else {
        name = "Custom MFT";
    }
    auto t = std::make_shared<CBaseTransform>(name, clsidMFT, guidCategory);
    MediaFoundationPlatform::get().registerBuiltinTransform(t);
    return ole32::S_OK;
}

inline int32_t __stdcall MFTEnumEx(
    GUID guidCategory,
    uint32_t,
    const void*,
    const void*,
    IMFTransform*** pppMFTs,
    uint32_t* pnumMFTs)
{
    if (!pppMFTs || !pnumMFTs) return ole32::E_POINTER;
    const auto& tfms = MediaFoundationPlatform::get().getTransforms();
    std::vector<IMFTransform*> matched;
    for (const auto& [_, t] : tfms) {
        if (t->GetCategory() == guidCategory || guidCategory == GUID{}) {
            t->AddRef();
            matched.push_back(t.get());
        }
    }
    *pnumMFTs = static_cast<uint32_t>(matched.size());
    if (*pnumMFTs > 0) {
        auto** arr = new IMFTransform* [*pnumMFTs];
        for (size_t i = 0; i < matched.size(); ++i) arr[i] = matched[i];
        *pppMFTs = arr;
    } else {
        *pppMFTs = nullptr;
    }
    return ole32::S_OK;
}

// mfreadwrite.dll
inline int32_t __stdcall MFCreateSourceReaderFromURL(
    const wchar_t* pwszURL,
    IMFAttributes*,
    IMFSourceReader** ppSourceReader)
{
    if (!ppSourceReader) return ole32::E_POINTER;
    *ppSourceReader = new CSourceReader(pwszURL ? pwszURL : L"media.mp4");
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateSourceReaderFromByteStream(
    IMFByteStream* pByteStream,
    IMFAttributes*,
    IMFSourceReader** ppSourceReader)
{
    if (!ppSourceReader || !pByteStream) return ole32::E_POINTER;
    *ppSourceReader = new CSourceReader(L"stream", pByteStream);
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateSinkWriterFromURL(
    const wchar_t* pwszOutputURL,
    IMFByteStream*,
    IMFAttributes*,
    IMFSinkWriter** ppSinkWriter)
{
    if (!ppSinkWriter) return ole32::E_POINTER;
    *ppSinkWriter = new CSinkWriter(pwszOutputURL ? pwszOutputURL : L"output.mp4");
    return ole32::S_OK;
}

// mf.dll
inline int32_t __stdcall MFCreateTopology(IMFTopology** ppTopology) {
    if (!ppTopology) return ole32::E_POINTER;
    *ppTopology = new CTopology();
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateTopologyNode(MF_TOPOLOGY_TYPE NodeType, IMFTopologyNode** ppNode) {
    if (!ppNode) return ole32::E_POINTER;
    *ppNode = new CTopologyNode(NodeType);
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateMediaSession(IMFAttributes*, IMFMediaSession** ppSession) {
    if (!ppSession) return ole32::E_POINTER;
    *ppSession = new CMediaSession();
    return ole32::S_OK;
}

// ============================================================================
// 8. Dynamic Module Export Registration
// ============================================================================

inline void InitializeMediaFoundationExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // mfplat.dll
    ldr.registerExport("mfplat.dll", "MFStartup", reinterpret_cast<void*>(&MFStartup));
    ldr.registerExport("mfplat.dll", "MFShutdown", reinterpret_cast<void*>(&MFShutdown));
    ldr.registerExport("mfplat.dll", "MFCreateAttributes", reinterpret_cast<void*>(&MFCreateAttributes));
    ldr.registerExport("mfplat.dll", "MFCreateMemoryBuffer", reinterpret_cast<void*>(&MFCreateMemoryBuffer));
    ldr.registerExport("mfplat.dll", "MFCreateSample", reinterpret_cast<void*>(&MFCreateSample));
    ldr.registerExport("mfplat.dll", "MFCreateMediaType", reinterpret_cast<void*>(&MFCreateMediaType));
    ldr.registerExport("mfplat.dll", "MFCreateAsyncResult", reinterpret_cast<void*>(&MFCreateAsyncResult));
    ldr.registerExport("mfplat.dll", "MFInvokeCallback", reinterpret_cast<void*>(&MFInvokeCallback));
    ldr.registerExport("mfplat.dll", "MFAllocateWorkQueue", reinterpret_cast<void*>(&MFAllocateWorkQueue));
    ldr.registerExport("mfplat.dll", "MFUnlockWorkQueue", reinterpret_cast<void*>(&MFUnlockWorkQueue));
    ldr.registerExport("mfplat.dll", "MFCreateEventQueue", reinterpret_cast<void*>(&MFCreateEventQueue));
    ldr.registerExport("mfplat.dll", "MFCreateFile", reinterpret_cast<void*>(&MFCreateFile));
    ldr.registerExport("mfplat.dll", "MFTRegister", reinterpret_cast<void*>(&MFTRegister));
    ldr.registerExport("mfplat.dll", "MFTEnumEx", reinterpret_cast<void*>(&MFTEnumEx));

    // mfreadwrite.dll
    ldr.registerExport("mfreadwrite.dll", "MFCreateSourceReaderFromURL", reinterpret_cast<void*>(&MFCreateSourceReaderFromURL));
    ldr.registerExport("mfreadwrite.dll", "MFCreateSourceReaderFromByteStream", reinterpret_cast<void*>(&MFCreateSourceReaderFromByteStream));
    ldr.registerExport("mfreadwrite.dll", "MFCreateSinkWriterFromURL", reinterpret_cast<void*>(&MFCreateSinkWriterFromURL));

    // mf.dll
    ldr.registerExport("mf.dll", "MFCreateTopology", reinterpret_cast<void*>(&MFCreateTopology));
    ldr.registerExport("mf.dll", "MFCreateTopologyNode", reinterpret_cast<void*>(&MFCreateTopologyNode));
    ldr.registerExport("mf.dll", "MFCreateMediaSession", reinterpret_cast<void*>(&MFCreateMediaSession));
}

} // namespace micant::mf
