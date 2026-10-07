#pragma once

#include <micant/ntdef.hpp>
#include <micant/ole32.hpp>
#include <micant/oleaut32.hpp>
#include <micant/ldr.hpp>
#include <micant/version.hpp>

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <cstring>
#include <algorithm>
#include <functional>

namespace micant::dshow {

// ============================================================================
// 1. DirectShow Constants, Enums & HRESULT Codes
// ============================================================================

using REFERENCE_TIME = int64_t;
using LONGLONG = int64_t;

enum PIN_DIRECTION {
    PINDIR_INPUT  = 0,
    PINDIR_OUTPUT = 1
};

enum FILTER_STATE {
    State_Stopped = 0,
    State_Paused  = 1,
    State_Running = 2
};

// Event Notification Codes
inline constexpr int32_t EC_COMPLETE               = 0x0001;
inline constexpr int32_t EC_USERABORT              = 0x0002;
inline constexpr int32_t EC_ERRORABORT             = 0x0003;
inline constexpr int32_t EC_TIME                   = 0x0004;
inline constexpr int32_t EC_REPAINT                = 0x0005;
inline constexpr int32_t EC_STREAM_ERROR_STOPPED   = 0x0006;
inline constexpr int32_t EC_STREAM_ERROR_STILLPLAYING = 0x0007;
inline constexpr int32_t EC_ERROR_STILLPLAYING     = 0x0008;
inline constexpr int32_t EC_PALETTE_CHANGED        = 0x0009;
inline constexpr int32_t EC_VIDEO_SIZE_CHANGED     = 0x000A;
inline constexpr int32_t EC_QUALITY_CHANGE         = 0x000B;
inline constexpr int32_t EC_SHUTTING_DOWN          = 0x000C;
inline constexpr int32_t EC_CLOCK_CHANGED          = 0x000D;
inline constexpr int32_t EC_PAUSED                 = 0x000E;
inline constexpr int32_t EC_OPENING_FILE           = 0x0010;
inline constexpr int32_t EC_BUFFERING_DATA         = 0x0011;

// DirectShow Error & Success Codes
inline constexpr int32_t VFW_S_STATE_INTERMEDIATE  = static_cast<int32_t>(0x00040237);
inline constexpr int32_t VFW_E_NOT_CONNECTED       = static_cast<int32_t>(0x80040209);
inline constexpr int32_t VFW_E_CANNOT_CONNECT      = static_cast<int32_t>(0x80040217);
inline constexpr int32_t VFW_E_CANNOT_RENDER       = static_cast<int32_t>(0x80040218);
inline constexpr int32_t VFW_E_NO_TYPES            = static_cast<int32_t>(0x8004022B);
inline constexpr int32_t VFW_E_NO_ACCEPTABLE_TYPES = static_cast<int32_t>(0x80040207);
inline constexpr int32_t VFW_E_NOT_STOPPED         = static_cast<int32_t>(0x80040224);
inline constexpr int32_t VFW_E_NOT_PAUSED          = static_cast<int32_t>(0x80040225);
inline constexpr int32_t VFW_E_NOT_RUNNING         = static_cast<int32_t>(0x80040226);
inline constexpr int32_t VFW_E_ALREADY_CONNECTED   = static_cast<int32_t>(0x80040204);
inline constexpr int32_t VFW_E_TYPE_NOT_ACCEPTED   = static_cast<int32_t>(0x8004022A);
inline constexpr int32_t VFW_E_SAMPLE_REJECTED     = static_cast<int32_t>(0x8004022B);
inline constexpr int32_t VFW_E_WRONG_STATE         = static_cast<int32_t>(0x80040227);

// ============================================================================
// 2. GUID Definitions (DirectShow & Quartz)
// ============================================================================

// Interface IIDs
inline constexpr GUID IID_IPersist =
    { 0x0000010c, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
inline constexpr GUID IID_IBaseFilter =
    { 0x56A86895, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IMediaFilter =
    { 0x56A86899, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IPin =
    { 0x56A86891, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IEnumPins =
    { 0x56A86892, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IEnumFilters =
    { 0x56A86893, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IPropertyBag =
    { 0x55272A00, 0x42CB, 0x11CE, { 0x81, 0x35, 0x00, 0xAA, 0x00, 0x4B, 0xB8, 0x51 } };
inline constexpr GUID IID_IEnumMediaTypes =
    { 0x89C31040, 0x846B, 0x11CE, { 0x97, 0xD3, 0x00, 0xAA, 0x00, 0x55, 0x59, 0x5A } };
inline constexpr GUID IID_IFilterGraph =
    { 0x56A8689F, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IFilterGraph2 =
    { 0x36B73882, 0xC2C8, 0x11CF, { 0x8B, 0x46, 0x00, 0x80, 0x5F, 0x6C, 0xEF, 0x60 } };
inline constexpr GUID IID_IGraphBuilder =
    { 0x56A868A9, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IMediaControl =
    { 0x56A868B1, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IMediaEvent =
    { 0x56A868B6, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IMediaEventEx =
    { 0x56A868C0, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IMediaSeeking =
    { 0x36B73880, 0xC2C8, 0x11CF, { 0x8B, 0x46, 0x00, 0x80, 0x5F, 0x6C, 0xEF, 0x60 } };
inline constexpr GUID IID_IBasicAudio =
    { 0x56A868B3, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IBasicVideo =
    { 0x56A868B5, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IVideoWindow =
    { 0x56A868B4, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_ISampleGrabber =
    { 0x6B652FFF, 0x11FE, 0x4FCE, { 0x92, 0xAD, 0x02, 0x66, 0xB5, 0xD7, 0xC7, 0x8F } };
inline constexpr GUID IID_ISampleGrabberCB =
    { 0x0579154A, 0x2B53, 0x4994, { 0xB0, 0xD0, 0xE7, 0x73, 0x14, 0x8E, 0xFF, 0x85 } };
inline constexpr GUID IID_ICreateDevEnum =
    { 0x29840822, 0x5B84, 0x11D0, { 0xBD, 0x3B, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } };
inline constexpr GUID IID_IReferenceClock =
    { 0x56A86897, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IMemInputPin =
    { 0x56A8689D, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IMediaSample =
    { 0x56A8689A, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID IID_IMemAllocator =
    { 0x56A8689C, 0x0AD4, 0x11CE, { 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };

// CLSIDs
inline constexpr GUID CLSID_FilterGraph =
    { 0xE436EBB3, 0x524F, 0x11CE, { 0x9F, 0x53, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID CLSID_SystemDeviceEnum =
    { 0x62BE5D10, 0x60EB, 0x11D0, { 0xBD, 0x3B, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } };
inline constexpr GUID CLSID_AsyncReader =
    { 0xE436EBB5, 0x524F, 0x11CE, { 0x9F, 0x53, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID CLSID_AVIDec =
    { 0xCF498640, 0xCD5A, 0x11CE, { 0x96, 0xE3, 0x00, 0xAA, 0x00, 0x4C, 0x73, 0x59 } };
inline constexpr GUID CLSID_Colour =
    { 0x1643E180, 0x67F5, 0x11CE, { 0xA8, 0x1C, 0x00, 0xAA, 0x00, 0x2F, 0xEA, 0xB5 } };
inline constexpr GUID CLSID_VideoRenderer =
    { 0x6BC1BFA8, 0x06F6, 0x11D0, { 0x9B, 0x23, 0x00, 0xA0, 0xC9, 0x03, 0x97, 0x7F } };
inline constexpr GUID CLSID_DSoundRender =
    { 0x79376820, 0x07D0, 0x11CF, { 0xA2, 0x4D, 0x00, 0x20, 0xAF, 0xD7, 0x97, 0x67 } };
inline constexpr GUID CLSID_NullRenderer =
    { 0xC1F400A0, 0x3F08, 0x11D3, { 0x9F, 0x0B, 0x00, 0x60, 0x08, 0x03, 0x9E, 0x37 } };
inline constexpr GUID CLSID_SampleGrabber =
    { 0xC1F400A4, 0x3F08, 0x11D3, { 0x9F, 0x0B, 0x00, 0x60, 0x08, 0x03, 0x9E, 0x37 } };

// Categories
inline constexpr GUID CLSID_VideoInputDeviceCategory =
    { 0x860BB310, 0x5D01, 0x11D0, { 0xBD, 0x3B, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } };
inline constexpr GUID CLSID_AudioInputDeviceCategory =
    { 0x33D9A762, 0x90C8, 0x11D0, { 0xBD, 0x43, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } };
inline constexpr GUID CLSID_AudioRendererCategory =
    { 0xE0F158E1, 0xCB04, 0x11D0, { 0xBD, 0x4E, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } };
inline constexpr GUID CLSID_LegacyAmFilterCategory =
    { 0x083863F1, 0x70DE, 0x11D0, { 0xBD, 0x40, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } };

// Major Types
inline constexpr GUID MEDIATYPE_Video =
    { 0x73646976, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MEDIATYPE_Audio =
    { 0x73647561, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MEDIATYPE_Stream =
    { 0xE436EB83, 0x524F, 0x11CE, { 0x9F, 0x53, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };

// Subtypes
inline constexpr GUID MEDIASUBTYPE_RGB24 =
    { 0xE436EB7D, 0x524F, 0x11CE, { 0x9F, 0x53, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID MEDIASUBTYPE_RGB32 =
    { 0xE436EB7E, 0x524F, 0x11CE, { 0x9F, 0x53, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID MEDIASUBTYPE_PCM =
    { 0x00000001, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MEDIASUBTYPE_AVI =
    { 0xE436EB88, 0x524F, 0x11CE, { 0x9F, 0x53, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70 } };
inline constexpr GUID MEDIASUBTYPE_H264 =
    { 0x34363248, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };

// Format Types
inline constexpr GUID FORMAT_None =
    { 0x0F6417D6, 0xC318, 0x11D0, { 0xA4, 0x3F, 0x00, 0xA0, 0xC9, 0x22, 0x31, 0x96 } };
inline constexpr GUID FORMAT_VideoInfo =
    { 0x05589F80, 0xC356, 0x11CE, { 0xBF, 0x01, 0x00, 0xAA, 0x00, 0x55, 0x59, 0x5A } };
inline constexpr GUID FORMAT_WaveFormatEx =
    { 0x05589F81, 0xC356, 0x11CE, { 0xBF, 0x01, 0x00, 0xAA, 0x00, 0x55, 0x59, 0x5A } };

// Time Formats
inline constexpr GUID TIME_FORMAT_MEDIA_TIME =
    { 0x7B785570, 0x8C82, 0x11CF, { 0xBC, 0x0C, 0x00, 0xAA, 0x00, 0xAC, 0x74, 0xF6 } };
inline constexpr GUID TIME_FORMAT_FRAME =
    { 0x7B785571, 0x8C82, 0x11CF, { 0xBC, 0x0C, 0x00, 0xAA, 0x00, 0xAC, 0x74, 0xF6 } };

// ============================================================================
// 3. Media Structures
// ============================================================================

struct AM_MEDIA_TYPE {
    GUID majortype{ GUID{} };
    GUID subtype{ GUID{} };
    int32_t bFixedSizeSamples{ 1 };
    int32_t bTemporalCompression{ 0 };
    uint32_t lSampleSize{ 1 };
    GUID formattype{ FORMAT_None };
    ole32::IUnknown* pUnk{ nullptr };
    uint32_t cbFormat{ 0 };
    uint8_t* pbFormat{ nullptr };
};

struct VIDEOINFOHEADER {
    struct {
        int32_t left;
        int32_t top;
        int32_t right;
        int32_t bottom;
    } rcSource;
    struct {
        int32_t left;
        int32_t top;
        int32_t right;
        int32_t bottom;
    } rcTarget;
    uint32_t dwBitRate;
    uint32_t dwBitErrorRate;
    REFERENCE_TIME AvgTimePerFrame;
    struct {
        uint32_t biSize;
        int32_t  biWidth;
        int32_t  biHeight;
        uint16_t biPlanes;
        uint16_t biBitCount;
        uint32_t biCompression;
        uint32_t biSizeImage;
        int32_t  biXPelsPerMeter;
        int32_t  biYPelsPerMeter;
        uint32_t biClrUsed;
        uint32_t biClrImportant;
    } bmiHeader;
};

struct WAVEFORMATEX {
    uint16_t wFormatTag;
    uint16_t nChannels;
    uint32_t nSamplesPerSec;
    uint32_t nAvgBytesPerSec;
    uint16_t nBlockAlign;
    uint16_t wBitsPerSample;
    uint16_t cbSize;
};

// Forward Declarations
class IBaseFilter;
class IFilterGraph;
class IPin;

struct PIN_INFO {
    IBaseFilter* pFilter{ nullptr };
    PIN_DIRECTION dir{ PINDIR_INPUT };
    wchar_t achName[128]{};
};

struct FILTER_INFO {
    wchar_t achName[128]{};
    IFilterGraph* pGraph{ nullptr };
};

// ============================================================================
// 4. Core DirectShow COM Interfaces
// ============================================================================

class IReferenceClock : public ole32::IUnknown {
public:
    virtual int32_t __stdcall GetTime(REFERENCE_TIME* pTime) = 0;
    virtual int32_t __stdcall AdviseTime(REFERENCE_TIME baseTime, REFERENCE_TIME streamTime, uintptr_t hEvent, uintptr_t* pdwAdviseCookie) = 0;
    virtual int32_t __stdcall AdvisePeriodic(REFERENCE_TIME startTime, REFERENCE_TIME periodTime, uintptr_t hSemaphore, uintptr_t* pdwAdviseCookie) = 0;
    virtual int32_t __stdcall Unadvise(uintptr_t dwAdviseCookie) = 0;
};

class IMediaSample : public ole32::IUnknown {
public:
    virtual int32_t __stdcall GetPointer(uint8_t** ppBuffer) = 0;
    virtual int32_t __stdcall GetSize() = 0;
    virtual int32_t __stdcall GetTime(REFERENCE_TIME* pTimeStart, REFERENCE_TIME* pTimeEnd) = 0;
    virtual int32_t __stdcall SetTime(REFERENCE_TIME* pTimeStart, REFERENCE_TIME* pTimeEnd) = 0;
    virtual int32_t __stdcall IsSyncPoint() = 0;
    virtual int32_t __stdcall SetSyncPoint(int32_t bIsSyncPoint) = 0;
    virtual int32_t __stdcall IsPreroll() = 0;
    virtual int32_t __stdcall SetPreroll(int32_t bIsPreroll) = 0;
    virtual int32_t __stdcall GetActualDataLength() = 0;
    virtual int32_t __stdcall SetActualDataLength(int32_t length) = 0;
    virtual int32_t __stdcall GetMediaType(AM_MEDIA_TYPE** ppMediaType) = 0;
    virtual int32_t __stdcall SetMediaType(AM_MEDIA_TYPE* pMediaType) = 0;
    virtual int32_t __stdcall IsDiscontinuity() = 0;
    virtual int32_t __stdcall SetDiscontinuity(int32_t bDiscontinuity) = 0;
    virtual int32_t __stdcall GetMediaTime(LONGLONG* pTimeStart, LONGLONG* pTimeEnd) = 0;
    virtual int32_t __stdcall SetMediaTime(LONGLONG* pTimeStart, LONGLONG* pTimeEnd) = 0;
};

class IMemAllocator : public ole32::IUnknown {
public:
    struct ALLOCATOR_PROPERTIES {
        int32_t cBuffers;
        int32_t cbBuffer;
        int32_t cbAlign;
        int32_t cbPrefix;
    };
    virtual int32_t __stdcall SetProperties(ALLOCATOR_PROPERTIES* pRequest, ALLOCATOR_PROPERTIES* pActual) = 0;
    virtual int32_t __stdcall GetProperties(ALLOCATOR_PROPERTIES* pProps) = 0;
    virtual int32_t __stdcall Commit() = 0;
    virtual int32_t __stdcall Decommit() = 0;
    virtual int32_t __stdcall GetBuffer(IMediaSample** ppBuffer, REFERENCE_TIME* pStartTime, REFERENCE_TIME* pEndTime, uint32_t dwFlags) = 0;
    virtual int32_t __stdcall ReleaseBuffer(IMediaSample* pBuffer) = 0;
};

class IMemInputPin : public ole32::IUnknown {
public:
    virtual int32_t __stdcall GetAllocator(IMemAllocator** ppAllocator) = 0;
    virtual int32_t __stdcall NotifyAllocator(IMemAllocator* pAllocator, int32_t bReadOnly) = 0;
    virtual int32_t __stdcall GetAllocatorRequirements(IMemAllocator::ALLOCATOR_PROPERTIES* pProps) = 0;
    virtual int32_t __stdcall Receive(IMediaSample* pSample) = 0;
    virtual int32_t __stdcall ReceiveMultiple(IMediaSample** pSamples, int32_t nSamples, int32_t* nSamplesProcessed) = 0;
    virtual int32_t __stdcall ReceiveCanBlock() = 0;
};

class IEnumMediaTypes : public ole32::IUnknown {
public:
    virtual int32_t __stdcall Next(uint32_t cMediaTypes, AM_MEDIA_TYPE** ppMediaTypes, uint32_t* pcFetched) = 0;
    virtual int32_t __stdcall Skip(uint32_t cMediaTypes) = 0;
    virtual int32_t __stdcall Reset() = 0;
    virtual int32_t __stdcall Clone(IEnumMediaTypes** ppEnum) = 0;
};

class IEnumPins : public ole32::IUnknown {
public:
    virtual int32_t __stdcall Next(uint32_t cPins, IPin** ppPins, uint32_t* pcFetched) = 0;
    virtual int32_t __stdcall Skip(uint32_t cPins) = 0;
    virtual int32_t __stdcall Reset() = 0;
    virtual int32_t __stdcall Clone(IEnumPins** ppEnum) = 0;
};

class IPin : public ole32::IUnknown {
public:
    virtual int32_t __stdcall Connect(IPin* pReceivePin, const AM_MEDIA_TYPE* pmt) = 0;
    virtual int32_t __stdcall ReceiveConnection(IPin* pConnector, const AM_MEDIA_TYPE* pmt) = 0;
    virtual int32_t __stdcall Disconnect() = 0;
    virtual int32_t __stdcall ConnectedTo(IPin** ppPin) = 0;
    virtual int32_t __stdcall ConnectionMediaType(AM_MEDIA_TYPE* pmt) = 0;
    virtual int32_t __stdcall QueryPinInfo(PIN_INFO* pInfo) = 0;
    virtual int32_t __stdcall QueryDirection(PIN_DIRECTION* pPinDir) = 0;
    virtual int32_t __stdcall QueryId(wchar_t** Id) = 0;
    virtual int32_t __stdcall QueryAccept(const AM_MEDIA_TYPE* pmt) = 0;
    virtual int32_t __stdcall EnumMediaTypes(IEnumMediaTypes** ppEnum) = 0;
    virtual int32_t __stdcall QueryInternalConnections(IPin** apPin, uint32_t* nPin) = 0;
    virtual int32_t __stdcall EndOfStream() = 0;
    virtual int32_t __stdcall BeginFlush() = 0;
    virtual int32_t __stdcall EndFlush() = 0;
    virtual int32_t __stdcall NewSegment(REFERENCE_TIME tStart, REFERENCE_TIME tStop, double dRate) = 0;
};

class IPersist : public ole32::IUnknown {
public:
    virtual int32_t __stdcall GetClassID(GUID* pClassID) = 0;
};

class IMediaFilter : public IPersist {
public:
    virtual int32_t __stdcall Stop() = 0;
    virtual int32_t __stdcall Pause() = 0;
    virtual int32_t __stdcall Run(REFERENCE_TIME tStart) = 0;
    virtual int32_t __stdcall GetState(uint32_t dwMilliSecsTimeout, FILTER_STATE* State) = 0;
    virtual int32_t __stdcall SetSyncSource(IReferenceClock* pClock) = 0;
    virtual int32_t __stdcall GetSyncSource(IReferenceClock** pClock) = 0;
};

class IBaseFilter : public IMediaFilter {
public:
    virtual int32_t __stdcall EnumPins(IEnumPins** ppEnum) = 0;
    virtual int32_t __stdcall FindPin(const wchar_t* Id, IPin** ppPin) = 0;
    virtual int32_t __stdcall QueryFilterInfo(FILTER_INFO* pInfo) = 0;
    virtual int32_t __stdcall JoinFilterGraph(IFilterGraph* pGraph, const wchar_t* pName) = 0;
    virtual int32_t __stdcall QueryVendorInfo(wchar_t** pVendorInfo) = 0;
};

class IEnumFilters : public ole32::IUnknown {
public:
    virtual int32_t __stdcall Next(uint32_t cFilters, IBaseFilter** ppFilters, uint32_t* pcFetched) = 0;
    virtual int32_t __stdcall Skip(uint32_t cFilters) = 0;
    virtual int32_t __stdcall Reset() = 0;
    virtual int32_t __stdcall Clone(IEnumFilters** ppEnum) = 0;
};

class IFilterGraph : public ole32::IUnknown {
public:
    virtual int32_t __stdcall AddFilter(IBaseFilter* pFilter, const wchar_t* pName) = 0;
    virtual int32_t __stdcall RemoveFilter(IBaseFilter* pFilter) = 0;
    virtual int32_t __stdcall EnumFilters(IEnumFilters** ppEnum) = 0;
    virtual int32_t __stdcall FindFilterByName(const wchar_t* pName, IBaseFilter** ppFilter) = 0;
    virtual int32_t __stdcall ConnectDirect(IPin* ppinOut, IPin* ppinIn, const AM_MEDIA_TYPE* pmt) = 0;
    virtual int32_t __stdcall Reconnect(IPin* ppin) = 0;
    virtual int32_t __stdcall Disconnect(IPin* ppin) = 0;
    virtual int32_t __stdcall SetDefaultSyncSource() = 0;
};

class IFilterGraph2 : public IFilterGraph {
public:
    virtual int32_t __stdcall ReconnectEx(IPin* ppin, const AM_MEDIA_TYPE* pmt) = 0;
    virtual int32_t __stdcall RenderEx(IPin* pPinOut, uint32_t dwFlags, uint32_t* pvContext) = 0;
};

class IGraphBuilder : public IFilterGraph2 {
public:
    virtual int32_t __stdcall Connect(IPin* ppinOut, IPin* ppinIn) = 0;
    virtual int32_t __stdcall Render(IPin* ppinOut) = 0;
    virtual int32_t __stdcall RenderFile(const wchar_t* lpcwstrFile, const wchar_t* lpcwstrPlayList) = 0;
    virtual int32_t __stdcall AddSourceFilter(const wchar_t* lpcwstrFileName, const wchar_t* lpcwstrFilterName, IBaseFilter** ppFilter) = 0;
    virtual int32_t __stdcall SetLogFile(uintptr_t hFile) = 0;
    virtual int32_t __stdcall Abort() = 0;
    virtual int32_t __stdcall ShouldOperationContinue() = 0;
};

class IMediaControl : public ole32::IDispatch {
public:
    virtual int32_t __stdcall Run() = 0;
    virtual int32_t __stdcall Pause() = 0;
    virtual int32_t __stdcall Stop() = 0;
    virtual int32_t __stdcall GetState(int32_t msTimeout, FILTER_STATE* pfs) = 0;
    virtual int32_t __stdcall RenderFile(const wchar_t* strFilename) = 0;
    virtual int32_t __stdcall AddSourceFilter(const wchar_t* strFilename, IDispatch** ppUnk) = 0;
    virtual int32_t __stdcall GetFilterGraph(IDispatch** ppUnk) = 0;
    virtual int32_t __stdcall GetRegFilterCollection(IDispatch** ppUnk) = 0;
    virtual int32_t __stdcall StopWhenReady() = 0;
};

class IMediaEvent : public ole32::IDispatch {
public:
    virtual int32_t __stdcall GetEventHandle(uintptr_t* hEvent) = 0;
    virtual int32_t __stdcall GetEvent(int32_t* lEventCode, intptr_t* lParam1, intptr_t* lParam2, int32_t msTimeout) = 0;
    virtual int32_t __stdcall WaitForCompletion(int32_t msTimeout, int32_t* pEvCode) = 0;
    virtual int32_t __stdcall CancelDefaultHandling(int32_t lEvCode) = 0;
    virtual int32_t __stdcall RestoreDefaultHandling(int32_t lEvCode) = 0;
    virtual int32_t __stdcall FreeEventParams(int32_t lEvCode, intptr_t lParam1, intptr_t lParam2) = 0;
};

class IMediaEventEx : public IMediaEvent {
public:
    virtual int32_t __stdcall SetNotifyWindow(win32::HWND hwnd, uint32_t lMsg, intptr_t lInstanceData) = 0;
    virtual int32_t __stdcall SetNotifyFlags(int32_t lNoNotifyFlags) = 0;
};

class IMediaSeeking : public ole32::IUnknown {
public:
    virtual int32_t __stdcall GetCapabilities(uint32_t* pCapabilities) = 0;
    virtual int32_t __stdcall CheckCapabilities(uint32_t* pCapabilities) = 0;
    virtual int32_t __stdcall IsFormatSupported(const GUID* pFormat) = 0;
    virtual int32_t __stdcall QueryPreferredFormat(GUID* pFormat) = 0;
    virtual int32_t __stdcall GetTimeFormat(GUID* pFormat) = 0;
    virtual int32_t __stdcall IsUsingTimeFormat(const GUID* pFormat) = 0;
    virtual int32_t __stdcall SetTimeFormat(const GUID* pFormat) = 0;
    virtual int32_t __stdcall GetDuration(LONGLONG* pDuration) = 0;
    virtual int32_t __stdcall GetStopPosition(LONGLONG* pStopPosition) = 0;
    virtual int32_t __stdcall GetCurrentPosition(LONGLONG* pCurrentPosition) = 0;
    virtual int32_t __stdcall ConvertTimeFormat(LONGLONG* pTarget, const GUID* pTargetFormat, LONGLONG Source, const GUID* pSourceFormat) = 0;
    virtual int32_t __stdcall SetPositions(LONGLONG* pCurrent, uint32_t dwCurrentFlags, LONGLONG* pStop, uint32_t dwStopFlags) = 0;
    virtual int32_t __stdcall GetPositions(LONGLONG* pCurrent, LONGLONG* pStop) = 0;
    virtual int32_t __stdcall GetAvailable(LONGLONG* pEarliest, LONGLONG* pLatest) = 0;
    virtual int32_t __stdcall SetRate(double dRate) = 0;
    virtual int32_t __stdcall GetRate(double* pdRate) = 0;
    virtual int32_t __stdcall GetPreroll(LONGLONG* pllPreroll) = 0;
};

class IBasicAudio : public ole32::IDispatch {
public:
    virtual int32_t __stdcall put_Volume(int32_t lVolume) = 0;
    virtual int32_t __stdcall get_Volume(int32_t* plVolume) = 0;
    virtual int32_t __stdcall put_Balance(int32_t lBalance) = 0;
    virtual int32_t __stdcall get_Balance(int32_t* plBalance) = 0;
};

class IBasicVideo : public ole32::IDispatch {
public:
    virtual int32_t __stdcall get_AvgTimePerFrame(double* pAvgTimePerFrame) = 0;
    virtual int32_t __stdcall get_BitRate(int32_t* pBitRate) = 0;
    virtual int32_t __stdcall get_BitErrorRate(int32_t* pBitErrorRate) = 0;
    virtual int32_t __stdcall get_VideoWidth(int32_t* pVideoWidth) = 0;
    virtual int32_t __stdcall get_VideoHeight(int32_t* pVideoHeight) = 0;
    virtual int32_t __stdcall put_SourceLeft(int32_t SourceLeft) = 0;
    virtual int32_t __stdcall get_SourceLeft(int32_t* pSourceLeft) = 0;
    virtual int32_t __stdcall put_SourceWidth(int32_t SourceWidth) = 0;
    virtual int32_t __stdcall get_SourceWidth(int32_t* pSourceWidth) = 0;
    virtual int32_t __stdcall put_SourceTop(int32_t SourceTop) = 0;
    virtual int32_t __stdcall get_SourceTop(int32_t* pSourceTop) = 0;
    virtual int32_t __stdcall put_SourceHeight(int32_t SourceHeight) = 0;
    virtual int32_t __stdcall get_SourceHeight(int32_t* pSourceHeight) = 0;
    virtual int32_t __stdcall put_DestinationLeft(int32_t DestinationLeft) = 0;
    virtual int32_t __stdcall get_DestinationLeft(int32_t* pDestinationLeft) = 0;
    virtual int32_t __stdcall put_DestinationWidth(int32_t DestinationWidth) = 0;
    virtual int32_t __stdcall get_DestinationWidth(int32_t* pDestinationWidth) = 0;
    virtual int32_t __stdcall put_DestinationTop(int32_t DestinationTop) = 0;
    virtual int32_t __stdcall get_DestinationTop(int32_t* pDestinationTop) = 0;
    virtual int32_t __stdcall put_DestinationHeight(int32_t DestinationHeight) = 0;
    virtual int32_t __stdcall get_DestinationHeight(int32_t* pDestinationHeight) = 0;
    virtual int32_t __stdcall GetCurrentImage(int32_t* pBufferSize, int32_t* pDIBImage) = 0;
};

class IVideoWindow : public ole32::IDispatch {
public:
    virtual int32_t __stdcall put_Caption(const wchar_t* strCaption) = 0;
    virtual int32_t __stdcall get_Caption(wchar_t** strCaption) = 0;
    virtual int32_t __stdcall put_WindowStyle(int32_t WindowStyle) = 0;
    virtual int32_t __stdcall get_WindowStyle(int32_t* pWindowStyle) = 0;
    virtual int32_t __stdcall put_AutoShow(int32_t AutoShow) = 0;
    virtual int32_t __stdcall get_AutoShow(int32_t* pAutoShow) = 0;
    virtual int32_t __stdcall put_WindowState(int32_t WindowState) = 0;
    virtual int32_t __stdcall get_WindowState(int32_t* pWindowState) = 0;
    virtual int32_t __stdcall put_Owner(uintptr_t Owner) = 0;
    virtual int32_t __stdcall get_Owner(uintptr_t* Owner) = 0;
    virtual int32_t __stdcall put_MessageDrain(uintptr_t Drain) = 0;
    virtual int32_t __stdcall get_MessageDrain(uintptr_t* Drain) = 0;
    virtual int32_t __stdcall put_Visible(int32_t Visible) = 0;
    virtual int32_t __stdcall get_Visible(int32_t* pVisible) = 0;
    virtual int32_t __stdcall SetWindowPosition(int32_t Left, int32_t Top, int32_t Width, int32_t Height) = 0;
    virtual int32_t __stdcall GetWindowPosition(int32_t* pLeft, int32_t* pTop, int32_t* pWidth, int32_t* pHeight) = 0;
};

class ISampleGrabberCB : public ole32::IUnknown {
public:
    virtual int32_t __stdcall SampleCB(double SampleTime, IMediaSample* pSample) = 0;
    virtual int32_t __stdcall BufferCB(double SampleTime, uint8_t* pBuffer, int32_t BufferLen) = 0;
};

class ISampleGrabber : public ole32::IUnknown {
public:
    virtual int32_t __stdcall SetOneShot(int32_t OneShot) = 0;
    virtual int32_t __stdcall SetMediaType(const AM_MEDIA_TYPE* pType) = 0;
    virtual int32_t __stdcall GetConnectedMediaType(AM_MEDIA_TYPE* pType) = 0;
    virtual int32_t __stdcall SetBufferSamples(int32_t BufferThem) = 0;
    virtual int32_t __stdcall GetCurrentBuffer(int32_t* pBufferSize, int32_t* pBuffer) = 0;
    virtual int32_t __stdcall GetCurrentConsole(void** ppConsole) = 0;
    virtual int32_t __stdcall SetCallback(ISampleGrabberCB* pCallback, int32_t WhichMethodToCallback) = 0;
};

class IMoniker : public ole32::IUnknown {
public:
    virtual int32_t __stdcall BindToObject(void* pbc, IMoniker* pmkToLeft, const GUID& riidResult, void** ppvResult) = 0;
    virtual int32_t __stdcall BindToStorage(void* pbc, IMoniker* pmkToLeft, const GUID& riid, void** ppvObj) = 0;
};

class IEnumMoniker : public ole32::IUnknown {
public:
    virtual int32_t __stdcall Next(uint32_t celt, IMoniker** rgelt, uint32_t* pceltFetched) = 0;
    virtual int32_t __stdcall Skip(uint32_t celt) = 0;
    virtual int32_t __stdcall Reset() = 0;
    virtual int32_t __stdcall Clone(IEnumMoniker** ppenum) = 0;
};

class ICreateDevEnum : public ole32::IUnknown {
public:
    virtual int32_t __stdcall CreateClassEnumerator(const GUID& clsidDeviceClass, IEnumMoniker** ppEnumMoniker, uint32_t dwFlags) = 0;
};

// ============================================================================
// 5. Concrete Implementations: MediaSample, Pins, BaseFilter
// ============================================================================

class CMediaSample : public IMediaSample {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<uint8_t> m_buffer;
    int32_t m_actualLength{ 0 };
    REFERENCE_TIME m_timeStart{ 0 };
    REFERENCE_TIME m_timeEnd{ 0 };
    int32_t m_isSync{ 1 };
    int32_t m_isPreroll{ 0 };
    int32_t m_isDiscont{ 0 };
    LONGLONG m_mediaStart{ 0 };
    LONGLONG m_mediaEnd{ 0 };
    AM_MEDIA_TYPE m_mediaType{};
    bool m_hasMediaType{ false };
    mutable std::mutex m_mutex;

public:
    explicit CMediaSample(int32_t size = 4096)
        : m_buffer(static_cast<size_t>(size), 0), m_actualLength(size) {}

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMediaSample) {
            *ppvObject = static_cast<IMediaSample*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall GetPointer(uint8_t** ppBuffer) override {
        if (!ppBuffer) return ole32::E_POINTER;
        *ppBuffer = m_buffer.data();
        return ole32::S_OK;
    }

    int32_t __stdcall GetSize() override { return static_cast<int32_t>(m_buffer.size()); }

    int32_t __stdcall GetTime(REFERENCE_TIME* pTimeStart, REFERENCE_TIME* pTimeEnd) override {
        if (pTimeStart) *pTimeStart = m_timeStart;
        if (pTimeEnd) *pTimeEnd = m_timeEnd;
        return ole32::S_OK;
    }

    int32_t __stdcall SetTime(REFERENCE_TIME* pTimeStart, REFERENCE_TIME* pTimeEnd) override {
        if (pTimeStart) m_timeStart = *pTimeStart;
        if (pTimeEnd) m_timeEnd = *pTimeEnd;
        return ole32::S_OK;
    }

    int32_t __stdcall IsSyncPoint() override { return m_isSync ? ole32::S_OK : ole32::S_FALSE; }
    int32_t __stdcall SetSyncPoint(int32_t bIsSyncPoint) override { m_isSync = bIsSyncPoint; return ole32::S_OK; }
    int32_t __stdcall IsPreroll() override { return m_isPreroll ? ole32::S_OK : ole32::S_FALSE; }
    int32_t __stdcall SetPreroll(int32_t bIsPreroll) override { m_isPreroll = bIsPreroll; return ole32::S_OK; }
    int32_t __stdcall GetActualDataLength() override { return m_actualLength; }
    int32_t __stdcall SetActualDataLength(int32_t length) override { m_actualLength = length; return ole32::S_OK; }

    int32_t __stdcall GetMediaType(AM_MEDIA_TYPE** ppMediaType) override {
        if (!ppMediaType) return ole32::E_POINTER;
        if (!m_hasMediaType) {
            *ppMediaType = nullptr;
            return ole32::S_FALSE;
        }
        *ppMediaType = new AM_MEDIA_TYPE(m_mediaType);
        return ole32::S_OK;
    }

    int32_t __stdcall SetMediaType(AM_MEDIA_TYPE* pMediaType) override {
        if (pMediaType) {
            m_mediaType = *pMediaType;
            m_hasMediaType = true;
        } else {
            m_hasMediaType = false;
        }
        return ole32::S_OK;
    }

    int32_t __stdcall IsDiscontinuity() override { return m_isDiscont ? ole32::S_OK : ole32::S_FALSE; }
    int32_t __stdcall SetDiscontinuity(int32_t bDiscontinuity) override { m_isDiscont = bDiscontinuity; return ole32::S_OK; }

    int32_t __stdcall GetMediaTime(LONGLONG* pTimeStart, LONGLONG* pTimeEnd) override {
        if (pTimeStart) *pTimeStart = m_mediaStart;
        if (pTimeEnd) *pTimeEnd = m_mediaEnd;
        return ole32::S_OK;
    }

    int32_t __stdcall SetMediaTime(LONGLONG* pTimeStart, LONGLONG* pTimeEnd) override {
        if (pTimeStart) m_mediaStart = *pTimeStart;
        if (pTimeEnd) m_mediaEnd = *pTimeEnd;
        return ole32::S_OK;
    }
};

class CEnumMediaTypes : public IEnumMediaTypes {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<AM_MEDIA_TYPE> m_types;
    size_t m_index{ 0 };

public:
    explicit CEnumMediaTypes(std::vector<AM_MEDIA_TYPE> types)
        : m_types(std::move(types)) {}

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IEnumMediaTypes) {
            *ppvObject = static_cast<IEnumMediaTypes*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall Next(uint32_t cMediaTypes, AM_MEDIA_TYPE** ppMediaTypes, uint32_t* pcFetched) override {
        if (!ppMediaTypes) return ole32::E_POINTER;
        uint32_t fetched = 0;
        while (m_index < m_types.size() && fetched < cMediaTypes) {
            ppMediaTypes[fetched] = new AM_MEDIA_TYPE(m_types[m_index++]);
            fetched++;
        }
        if (pcFetched) *pcFetched = fetched;
        return (fetched == cMediaTypes) ? ole32::S_OK : ole32::S_FALSE;
    }

    int32_t __stdcall Skip(uint32_t cMediaTypes) override {
        m_index = std::min(m_index + cMediaTypes, m_types.size());
        return ole32::S_OK;
    }

    int32_t __stdcall Reset() override {
        m_index = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall Clone(IEnumMediaTypes** ppEnum) override {
        if (!ppEnum) return ole32::E_POINTER;
        *ppEnum = new CEnumMediaTypes(m_types);
        return ole32::S_OK;
    }
};

class CPin : public IPin, public IMemInputPin {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_name;
    IBaseFilter* m_pFilter{ nullptr };
    PIN_DIRECTION m_direction{ PINDIR_INPUT };
    IPin* m_connectedPin{ nullptr };
    AM_MEDIA_TYPE m_connectionType{};
    std::vector<AM_MEDIA_TYPE> m_supportedTypes;
    mutable std::mutex m_mutex;

public:
    CPin(std::wstring name, IBaseFilter* pFilter, PIN_DIRECTION dir, std::vector<AM_MEDIA_TYPE> supportedTypes = {})
        : m_name(std::move(name)), m_pFilter(pFilter), m_direction(dir), m_supportedTypes(std::move(supportedTypes)) {}

    CPin(std::wstring name, PIN_DIRECTION dir, IBaseFilter* pFilter = nullptr, std::vector<AM_MEDIA_TYPE> supportedTypes = {})
        : m_name(std::move(name)), m_pFilter(pFilter), m_direction(dir), m_supportedTypes(std::move(supportedTypes)) {}

    ~CPin() override {
        Disconnect();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IPin) {
            *ppvObject = static_cast<IPin*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMemInputPin && m_direction == PINDIR_INPUT) {
            *ppvObject = static_cast<IMemInputPin*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IPin Implementation
    int32_t __stdcall Connect(IPin* pReceivePin, const AM_MEDIA_TYPE* pmt) override {
        if (!pReceivePin) return ole32::E_POINTER;
        AM_MEDIA_TYPE mtToUse{};
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_connectedPin) return VFW_E_ALREADY_CONNECTED;

            if (pmt) {
                mtToUse = *pmt;
            } else if (!m_supportedTypes.empty()) {
                mtToUse = m_supportedTypes[0];
            }
        }

        int32_t hr = pReceivePin->ReceiveConnection(this, &mtToUse);
        if (hr == ole32::S_OK) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_connectedPin = pReceivePin;
            m_connectedPin->AddRef();
            m_connectionType = mtToUse;
        }
        return hr;
    }

    int32_t __stdcall ReceiveConnection(IPin* pConnector, const AM_MEDIA_TYPE* pmt) override {
        if (!pConnector || !pmt) return ole32::E_POINTER;
        if (QueryAccept(pmt) != ole32::S_OK) {
            return VFW_E_TYPE_NOT_ACCEPTED;
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_connectedPin) return VFW_E_ALREADY_CONNECTED;

        m_connectedPin = pConnector;
        m_connectedPin->AddRef();
        m_connectionType = *pmt;
        return ole32::S_OK;
    }

    int32_t __stdcall Disconnect() override {
        IPin* pOld = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_connectedPin) {
                pOld = m_connectedPin;
                m_connectedPin = nullptr;
            }
        }
        if (pOld) {
            pOld->Disconnect();
            pOld->Release();
        }
        return ole32::S_OK;
    }

    int32_t __stdcall ConnectedTo(IPin** ppPin) override {
        if (!ppPin) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_connectedPin) {
            *ppPin = nullptr;
            return VFW_E_NOT_CONNECTED;
        }
        *ppPin = m_connectedPin;
        (*ppPin)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall ConnectionMediaType(AM_MEDIA_TYPE* pmt) override {
        if (!pmt) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_connectedPin) return VFW_E_NOT_CONNECTED;
        *pmt = m_connectionType;
        return ole32::S_OK;
    }

    int32_t __stdcall QueryPinInfo(PIN_INFO* pInfo) override {
        if (!pInfo) return ole32::E_POINTER;
        pInfo->pFilter = m_pFilter;
        if (pInfo->pFilter) pInfo->pFilter->AddRef();
        pInfo->dir = m_direction;
        wcsncpy(pInfo->achName, m_name.c_str(), 127);
        pInfo->achName[127] = L'\0';
        return ole32::S_OK;
    }

    int32_t __stdcall QueryDirection(PIN_DIRECTION* pPinDir) override {
        if (!pPinDir) return ole32::E_POINTER;
        *pPinDir = m_direction;
        return ole32::S_OK;
    }

    int32_t __stdcall QueryId(wchar_t** Id) override {
        if (!Id) return ole32::E_POINTER;
        size_t len = m_name.size() + 1;
        *Id = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len * sizeof(wchar_t)));
        if (!*Id) return ole32::E_OUTOFMEMORY;
        std::memcpy(*Id, m_name.c_str(), len * sizeof(wchar_t));
        return ole32::S_OK;
    }

    int32_t __stdcall QueryAccept(const AM_MEDIA_TYPE* pmt) override {
        if (!pmt) return ole32::E_POINTER;
        if (m_supportedTypes.empty()) return ole32::S_OK;
        for (const auto& t : m_supportedTypes) {
            if (t.majortype == pmt->majortype &&
                (t.subtype == pmt->subtype || t.subtype == GUID{})) {
                return ole32::S_OK;
            }
        }
        return ole32::S_FALSE;
    }

    int32_t __stdcall EnumMediaTypes(IEnumMediaTypes** ppEnum) override {
        if (!ppEnum) return ole32::E_POINTER;
        *ppEnum = new CEnumMediaTypes(m_supportedTypes);
        return ole32::S_OK;
    }

    int32_t __stdcall QueryInternalConnections(IPin** apPin, uint32_t* nPin) override {
        if (nPin) *nPin = 0;
        (void)apPin;
        return ole32::S_OK;
    }

    int32_t __stdcall EndOfStream() override { return ole32::S_OK; }
    int32_t __stdcall BeginFlush() override { return ole32::S_OK; }
    int32_t __stdcall EndFlush() override { return ole32::S_OK; }
    int32_t __stdcall NewSegment(REFERENCE_TIME, REFERENCE_TIME, double) override { return ole32::S_OK; }

    // IMemInputPin Implementation
    int32_t __stdcall GetAllocator(IMemAllocator** ppAllocator) override {
        if (!ppAllocator) return ole32::E_POINTER;
        *ppAllocator = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall NotifyAllocator(IMemAllocator*, int32_t) override { return ole32::S_OK; }
    int32_t __stdcall GetAllocatorRequirements(IMemAllocator::ALLOCATOR_PROPERTIES*) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall Receive(IMediaSample*) override { return ole32::S_OK; }
    int32_t __stdcall ReceiveMultiple(IMediaSample**, int32_t n, int32_t* pProc) override {
        if (pProc) *pProc = n;
        return ole32::S_OK;
    }
    int32_t __stdcall ReceiveCanBlock() override { return ole32::S_OK; }
};

class CEnumPins : public IEnumPins {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<IPin*> m_pins;
    size_t m_index{ 0 };

public:
    explicit CEnumPins(std::vector<IPin*> pins)
        : m_pins(std::move(pins)) {
        for (auto* p : m_pins) if (p) p->AddRef();
    }

    ~CEnumPins() override {
        for (auto* p : m_pins) if (p) p->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IEnumPins) {
            *ppvObject = static_cast<IEnumPins*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall Next(uint32_t cPins, IPin** ppPins, uint32_t* pcFetched) override {
        if (!ppPins) return ole32::E_POINTER;
        uint32_t fetched = 0;
        while (m_index < m_pins.size() && fetched < cPins) {
            ppPins[fetched] = m_pins[m_index++];
            ppPins[fetched]->AddRef();
            fetched++;
        }
        if (pcFetched) *pcFetched = fetched;
        return (fetched == cPins) ? ole32::S_OK : ole32::S_FALSE;
    }

    int32_t __stdcall Skip(uint32_t cPins) override {
        m_index = std::min(m_index + cPins, m_pins.size());
        return ole32::S_OK;
    }

    int32_t __stdcall Reset() override {
        m_index = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall Clone(IEnumPins** ppEnum) override {
        if (!ppEnum) return ole32::E_POINTER;
        *ppEnum = new CEnumPins(m_pins);
        return ole32::S_OK;
    }
};

class CEnumFilters : public IEnumFilters {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<IBaseFilter*> m_filters;
    size_t m_index{ 0 };

public:
    explicit CEnumFilters(std::vector<IBaseFilter*> filters)
        : m_filters(std::move(filters)) {
        for (auto* f : m_filters) if (f) f->AddRef();
    }

    ~CEnumFilters() override {
        for (auto* f : m_filters) if (f) f->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IEnumFilters) {
            *ppvObject = static_cast<IEnumFilters*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall Next(uint32_t cFilters, IBaseFilter** ppFilters, uint32_t* pcFetched) override {
        if (!ppFilters) return ole32::E_POINTER;
        uint32_t fetched = 0;
        while (m_index < m_filters.size() && fetched < cFilters) {
            ppFilters[fetched] = m_filters[m_index++];
            ppFilters[fetched]->AddRef();
            fetched++;
        }
        if (pcFetched) *pcFetched = fetched;
        return (fetched == cFilters) ? ole32::S_OK : ole32::S_FALSE;
    }

    int32_t __stdcall Skip(uint32_t cFilters) override {
        m_index = std::min(m_index + cFilters, m_filters.size());
        return ole32::S_OK;
    }

    int32_t __stdcall Reset() override {
        m_index = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall Clone(IEnumFilters** ppEnum) override {
        if (!ppEnum) return ole32::E_POINTER;
        *ppEnum = new CEnumFilters(m_filters);
        return ole32::S_OK;
    }
};

class CBaseFilter : public IBaseFilter {
protected:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_name;
    GUID m_clsid{ GUID{} };
    IFilterGraph* m_pGraph{ nullptr };
    FILTER_STATE m_state{ State_Stopped };
    IReferenceClock* m_pClock{ nullptr };
    std::vector<IPin*> m_pins;
    mutable std::mutex m_mutex;

public:
    CBaseFilter(std::wstring name, GUID clsid)
        : m_name(std::move(name)), m_clsid(clsid) {}

    ~CBaseFilter() override {
        for (auto* p : m_pins) if (p) p->Release();
        if (m_pClock) m_pClock->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IPersist || riid == IID_IMediaFilter || riid == IID_IBaseFilter) {
            *ppvObject = static_cast<IBaseFilter*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall GetClassID(GUID* pClassID) override {
        if (!pClassID) return ole32::E_POINTER;
        *pClassID = m_clsid;
        return ole32::S_OK;
    }

    const std::wstring& GetName() const { return m_name; }
    const GUID& GetClsid() const { return m_clsid; }

    void AddPin(IPin* pPin) {
        if (pPin) {
            pPin->AddRef();
            m_pins.push_back(pPin);
        }
    }

    // IMediaFilter
    int32_t __stdcall Stop() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = State_Stopped;
        return ole32::S_OK;
    }

    int32_t __stdcall Pause() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = State_Paused;
        return ole32::S_OK;
    }

    int32_t __stdcall Run(REFERENCE_TIME) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = State_Running;
        return ole32::S_OK;
    }

    int32_t __stdcall GetState(uint32_t, FILTER_STATE* State) override {
        if (!State) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *State = m_state;
        return ole32::S_OK;
    }

    int32_t __stdcall SetSyncSource(IReferenceClock* pClock) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pClock) m_pClock->Release();
        m_pClock = pClock;
        if (m_pClock) m_pClock->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetSyncSource(IReferenceClock** pClock) override {
        if (!pClock) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pClock = m_pClock;
        if (*pClock) (*pClock)->AddRef();
        return ole32::S_OK;
    }

    // IBaseFilter
    int32_t __stdcall EnumPins(IEnumPins** ppEnum) override {
        if (!ppEnum) return ole32::E_POINTER;
        *ppEnum = new CEnumPins(m_pins);
        return ole32::S_OK;
    }

    int32_t __stdcall FindPin(const wchar_t* Id, IPin** ppPin) override {
        if (!Id || !ppPin) return ole32::E_POINTER;
        *ppPin = nullptr;
        for (auto* p : m_pins) {
            PIN_INFO info{};
            p->QueryPinInfo(&info);
            if (info.pFilter) info.pFilter->Release();
            if (wcscmp(info.achName, Id) == 0) {
                *ppPin = p;
                (*ppPin)->AddRef();
                return ole32::S_OK;
            }
        }
        return ole32::E_FAIL;
    }

    int32_t __stdcall QueryFilterInfo(FILTER_INFO* pInfo) override {
        if (!pInfo) return ole32::E_POINTER;
        wcsncpy(pInfo->achName, m_name.c_str(), 127);
        pInfo->achName[127] = L'\0';
        pInfo->pGraph = m_pGraph;
        if (pInfo->pGraph) pInfo->pGraph->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall JoinFilterGraph(IFilterGraph* pGraph, const wchar_t* pName) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pGraph = pGraph;
        if (pName) m_name = pName;
        return ole32::S_OK;
    }

    int32_t __stdcall QueryVendorInfo(wchar_t** pVendorInfo) override {
        if (!pVendorInfo) return ole32::E_POINTER;
        const wchar_t vendor[] = L"MicaNT Project";
        size_t bytes = sizeof(vendor);
        *pVendorInfo = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(bytes));
        if (!*pVendorInfo) return ole32::E_OUTOFMEMORY;
        std::memcpy(*pVendorInfo, vendor, bytes);
        return ole32::S_OK;
    }
};

// ============================================================================
// 6. Built-in Filters
// ============================================================================

// 6.1 Async File Reader Filter (Source)
class CAsyncFileReaderFilter : public CBaseFilter {
private:
    std::wstring m_filePath;

public:
    explicit CAsyncFileReaderFilter(std::wstring filePath = L"")
        : CBaseFilter(L"Async File Reader", CLSID_AsyncReader), m_filePath(std::move(filePath)) {
        AM_MEDIA_TYPE mtStream{};
        mtStream.majortype = MEDIATYPE_Stream;
        mtStream.subtype = MEDIASUBTYPE_AVI;
        auto* outPin = new CPin(L"Output", this, PINDIR_OUTPUT, { mtStream });
        AddPin(outPin);
        outPin->Release();
    }

    void SetFilePath(std::wstring path) { m_filePath = std::move(path); }
    const std::wstring& GetFilePath() const { return m_filePath; }
};

// 6.2 AVI/Video Decoder Filter (Transform)
class CAVIDecoderFilter : public CBaseFilter {
public:
    CAVIDecoderFilter()
        : CBaseFilter(L"AVI Decompressor", CLSID_AVIDec) {
        AM_MEDIA_TYPE inStream{};
        inStream.majortype = MEDIATYPE_Stream;
        inStream.subtype = MEDIASUBTYPE_AVI;

        AM_MEDIA_TYPE inVideo{};
        inVideo.majortype = MEDIATYPE_Video;
        inVideo.subtype = MEDIASUBTYPE_H264;

        auto* inPin = new CPin(L"XForm In", this, PINDIR_INPUT, { inStream, inVideo });
        AddPin(inPin);
        inPin->Release();

        AM_MEDIA_TYPE outType{};
        outType.majortype = MEDIATYPE_Video;
        outType.subtype = MEDIASUBTYPE_RGB32;
        auto* outPin = new CPin(L"XForm Out", this, PINDIR_OUTPUT, { outType });
        AddPin(outPin);
        outPin->Release();
    }
};

// 6.3 Color Converter Filter (Transform)
class CColorConverterFilter : public CBaseFilter {
public:
    CColorConverterFilter()
        : CBaseFilter(L"Color Space Converter", CLSID_Colour) {
        AM_MEDIA_TYPE inType{};
        inType.majortype = MEDIATYPE_Video;
        inType.subtype = MEDIASUBTYPE_RGB24;
        auto* inPin = new CPin(L"XForm In", this, PINDIR_INPUT, { inType });
        AddPin(inPin);
        inPin->Release();

        AM_MEDIA_TYPE outType{};
        outType.majortype = MEDIATYPE_Video;
        outType.subtype = MEDIASUBTYPE_RGB32;
        auto* outPin = new CPin(L"XForm Out", this, PINDIR_OUTPUT, { outType });
        AddPin(outPin);
        outPin->Release();
    }
};

// 6.4 DirectSound Audio Renderer (Sink)
class CDefaultDirectSoundRenderer : public CBaseFilter {
public:
    CDefaultDirectSoundRenderer()
        : CBaseFilter(L"Default DirectSound Device", CLSID_DSoundRender) {
        AM_MEDIA_TYPE inType{};
        inType.majortype = MEDIATYPE_Audio;
        inType.subtype = MEDIASUBTYPE_PCM;
        auto* inPin = new CPin(L"Audio Input pin (rendered)", this, PINDIR_INPUT, { inType });
        AddPin(inPin);
        inPin->Release();
    }
};

// 6.5 Video Renderer Filter (Sink)
class CVideoRendererFilter : public CBaseFilter {
public:
    CVideoRendererFilter()
        : CBaseFilter(L"Video Renderer", CLSID_VideoRenderer) {
        AM_MEDIA_TYPE inType{};
        inType.majortype = MEDIATYPE_Video;
        inType.subtype = MEDIASUBTYPE_RGB32;
        auto* inPin = new CPin(L"Input", this, PINDIR_INPUT, { inType });
        AddPin(inPin);
        inPin->Release();
    }
};

// 6.6 Null Renderer Filter (Sink)
class CNullRendererFilter : public CBaseFilter {
public:
    CNullRendererFilter()
        : CBaseFilter(L"Null Renderer", CLSID_NullRenderer) {
        AM_MEDIA_TYPE anyType{};
        auto* inPin = new CPin(L"In", this, PINDIR_INPUT, { anyType });
        AddPin(inPin);
        inPin->Release();
    }
};

// 6.7 Sample Grabber Filter (qedit.dll)
class CSampleGrabberFilter : public CBaseFilter, public ISampleGrabber {
private:
    int32_t m_oneShot{ 0 };
    int32_t m_bufferSamples{ 1 };
    AM_MEDIA_TYPE m_grabberMediaType{};
    std::vector<uint8_t> m_lastSampleBuffer;
    ISampleGrabberCB* m_pCallback{ nullptr };
    int32_t m_callbackMethod{ 0 };

public:
    CSampleGrabberFilter()
        : CBaseFilter(L"SampleGrabber", CLSID_SampleGrabber) {
        m_lastSampleBuffer.resize(1024, 0xAA);
        AM_MEDIA_TYPE anyType{};
        anyType.majortype = MEDIATYPE_Video;
        anyType.subtype = MEDIASUBTYPE_RGB32;
        auto* inPin = new CPin(L"Input", this, PINDIR_INPUT, { anyType });
        auto* outPin = new CPin(L"Output", this, PINDIR_OUTPUT, { anyType });
        AddPin(inPin);
        AddPin(outPin);
        inPin->Release();
        outPin->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMediaFilter || riid == IID_IBaseFilter) {
            *ppvObject = static_cast<IBaseFilter*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_ISampleGrabber) {
            *ppvObject = static_cast<ISampleGrabber*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return CBaseFilter::AddRef(); }
    uint32_t __stdcall Release() override { return CBaseFilter::Release(); }

    // ISampleGrabber Implementation
    int32_t __stdcall SetOneShot(int32_t OneShot) override {
        m_oneShot = OneShot;
        return ole32::S_OK;
    }

    int32_t __stdcall SetMediaType(const AM_MEDIA_TYPE* pType) override {
        if (!pType) return ole32::E_POINTER;
        m_grabberMediaType = *pType;
        return ole32::S_OK;
    }

    int32_t __stdcall GetConnectedMediaType(AM_MEDIA_TYPE* pType) override {
        if (!pType) return ole32::E_POINTER;
        *pType = m_grabberMediaType;
        return ole32::S_OK;
    }

    int32_t __stdcall SetBufferSamples(int32_t BufferThem) override {
        m_bufferSamples = BufferThem;
        return ole32::S_OK;
    }

    int32_t __stdcall GetCurrentBuffer(int32_t* pBufferSize, int32_t* pBuffer) override {
        if (!pBufferSize) return ole32::E_POINTER;
        if (!pBuffer) {
            *pBufferSize = static_cast<int32_t>(m_lastSampleBuffer.size());
            return ole32::S_OK;
        }
        int32_t copyLen = std::min(*pBufferSize, static_cast<int32_t>(m_lastSampleBuffer.size()));
        std::memcpy(pBuffer, m_lastSampleBuffer.data(), static_cast<size_t>(copyLen));
        *pBufferSize = copyLen;
        return ole32::S_OK;
    }

    int32_t __stdcall GetCurrentConsole(void** ppConsole) override {
        if (ppConsole) *ppConsole = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall SetCallback(ISampleGrabberCB* pCallback, int32_t WhichMethodToCallback) override {
        m_pCallback = pCallback;
        m_callbackMethod = WhichMethodToCallback;
        return ole32::S_OK;
    }
};

// ============================================================================
// 7. Filter Graph Manager (quartz.dll)
// ============================================================================

class CFilterGraphManager : public IGraphBuilder,
                            public IMediaControl,
                            public IMediaEventEx,
                            public IMediaSeeking,
                            public IBasicAudio,
                            public IBasicVideo,
                            public IVideoWindow {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<IBaseFilter*> m_filters;
    FILTER_STATE m_state{ State_Stopped };
    mutable std::mutex m_mutex;

    // Media Seeking properties
    LONGLONG m_duration{ 100000000 }; // 10 seconds in 100ns units
    LONGLONG m_currentPos{ 0 };
    double m_rate{ 1.0 };

    // Audio properties
    int32_t m_volume{ 0 };
    int32_t m_balance{ 0 };

    // Video properties
    int32_t m_videoWidth{ 1920 };
    int32_t m_videoHeight{ 1080 };

    // Window properties
    std::wstring m_caption{ L"ActiveMovie Window" };
    int32_t m_visible{ 1 };
    win32::HWND m_notifyHwnd{ nullptr };
    uint32_t m_notifyMsg{ 0 };

    // Event queue
    struct EventEntry {
        int32_t code;
        intptr_t p1;
        intptr_t p2;
    };
    std::vector<EventEntry> m_events;

public:
    CFilterGraphManager() = default;

    ~CFilterGraphManager() override {
        for (auto* f : m_filters) if (f) f->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IFilterGraph || riid == IID_IFilterGraph2 || riid == IID_IGraphBuilder) {
            *ppvObject = static_cast<IGraphBuilder*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMediaControl) {
            *ppvObject = static_cast<IMediaControl*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMediaEvent || riid == IID_IMediaEventEx) {
            *ppvObject = static_cast<IMediaEventEx*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMediaSeeking) {
            *ppvObject = static_cast<IMediaSeeking*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IBasicAudio) {
            *ppvObject = static_cast<IBasicAudio*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IBasicVideo) {
            *ppvObject = static_cast<IBasicVideo*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IVideoWindow) {
            *ppvObject = static_cast<IVideoWindow*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IDispatch stub implementation for IMediaControl / IMediaEvent
    int32_t __stdcall GetTypeInfoCount(uint32_t* pctinfo) override { if (pctinfo) *pctinfo = 0; return ole32::S_OK; }
    int32_t __stdcall GetTypeInfo(uint32_t, ole32::LCID, ole32::ITypeInfo**) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall GetIDsOfNames(ole32::REFIID, ole32::LPOLESTR*, uint32_t, ole32::LCID, ole32::DISPID*) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall Invoke(ole32::DISPID, ole32::REFIID, ole32::LCID, uint16_t, ole32::DISPPARAMS*, ole32::VARIANT*, ole32::EXCEPINFO*, uint32_t*) override { return ole32::E_NOTIMPL; }

    // IFilterGraph
    int32_t __stdcall AddFilter(IBaseFilter* pFilter, const wchar_t* pName) override {
        if (!pFilter) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        pFilter->AddRef();
        pFilter->JoinFilterGraph(this, pName);
        m_filters.push_back(pFilter);
        return ole32::S_OK;
    }

    int32_t __stdcall RemoveFilter(IBaseFilter* pFilter) override {
        if (!pFilter) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find(m_filters.begin(), m_filters.end(), pFilter);
        if (it != m_filters.end()) {
            (*it)->JoinFilterGraph(nullptr, nullptr);
            (*it)->Release();
            m_filters.erase(it);
            return ole32::S_OK;
        }
        return ole32::E_FAIL;
    }

    int32_t __stdcall EnumFilters(IEnumFilters** ppEnum) override {
        if (!ppEnum) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *ppEnum = new CEnumFilters(m_filters);
        return ole32::S_OK;
    }

    int32_t __stdcall FindFilterByName(const wchar_t* pName, IBaseFilter** ppFilter) override {
        if (!pName || !ppFilter) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *ppFilter = nullptr;
        for (auto* f : m_filters) {
            FILTER_INFO info{};
            f->QueryFilterInfo(&info);
            if (info.pGraph) info.pGraph->Release();
            if (wcscmp(info.achName, pName) == 0) {
                *ppFilter = f;
                (*ppFilter)->AddRef();
                return ole32::S_OK;
            }
        }
        return ole32::E_FAIL;
    }

    int32_t __stdcall ConnectDirect(IPin* ppinOut, IPin* ppinIn, const AM_MEDIA_TYPE* pmt) override {
        if (!ppinOut || !ppinIn) return ole32::E_POINTER;
        return ppinOut->Connect(ppinIn, pmt);
    }

    int32_t __stdcall Reconnect(IPin* ppin) override {
        if (!ppin) return ole32::E_POINTER;
        IPin* other = nullptr;
        if (ppin->ConnectedTo(&other) == ole32::S_OK) {
            AM_MEDIA_TYPE mt{};
            ppin->ConnectionMediaType(&mt);
            ppin->Disconnect();
            int32_t hr = ppin->Connect(other, &mt);
            other->Release();
            return hr;
        }
        return ole32::S_OK;
    }

    int32_t __stdcall Disconnect(IPin* ppin) override {
        if (!ppin) return ole32::E_POINTER;
        return ppin->Disconnect();
    }

    int32_t __stdcall SetDefaultSyncSource() override { return ole32::S_OK; }

    // IFilterGraph2
    int32_t __stdcall ReconnectEx(IPin* ppin, const AM_MEDIA_TYPE* pmt) override {
        if (!ppin) return ole32::E_POINTER;
        IPin* other = nullptr;
        if (ppin->ConnectedTo(&other) == ole32::S_OK) {
            ppin->Disconnect();
            int32_t hr = ppin->Connect(other, pmt);
            other->Release();
            return hr;
        }
        return ole32::S_OK;
    }

    int32_t __stdcall RenderEx(IPin* pPinOut, uint32_t, uint32_t*) override {
        return Render(pPinOut);
    }

    // IGraphBuilder
    int32_t __stdcall Connect(IPin* ppinOut, IPin* ppinIn) override {
        if (!ppinOut || !ppinIn) return ole32::E_POINTER;
        // Direct connect attempt
        int32_t hr = ConnectDirect(ppinOut, ppinIn, nullptr);
        if (hr == ole32::S_OK) return hr;

        // Intelligent connect: Try inserting standard transform filters
        auto* aviDec = new CAVIDecoderFilter();
        AddFilter(aviDec, L"AVI Decompressor");
        IEnumPins* pDecPins = nullptr;
        aviDec->EnumPins(&pDecPins);
        IPin* decIn = nullptr;
        IPin* decOut = nullptr;
        uint32_t fetched = 0;
        if (pDecPins) {
            pDecPins->Next(1, &decIn, &fetched);
            pDecPins->Next(1, &decOut, &fetched);
            pDecPins->Release();
        }

        if (decIn && decOut) {
            hr = ConnectDirect(ppinOut, decIn, nullptr);
            if (hr == ole32::S_OK) {
                hr = ConnectDirect(decOut, ppinIn, nullptr);
                if (hr == ole32::S_OK) {
                    decIn->Release();
                    decOut->Release();
                    aviDec->Release();
                    return ole32::S_OK;
                }
            }
        }
        if (decIn) decIn->Release();
        if (decOut) decOut->Release();
        RemoveFilter(aviDec);
        aviDec->Release();

        return VFW_E_CANNOT_CONNECT;
    }

    int32_t __stdcall Render(IPin* ppinOut) override {
        if (!ppinOut) return ole32::E_POINTER;
        PIN_DIRECTION dir{};
        ppinOut->QueryDirection(&dir);
        if (dir != PINDIR_OUTPUT) return ole32::E_INVALIDARG;

        IEnumMediaTypes* pEnum = nullptr;
        ppinOut->EnumMediaTypes(&pEnum);
        AM_MEDIA_TYPE* pmt = nullptr;
        uint32_t fetched = 0;
        GUID majorType = MEDIATYPE_Video;
        if (pEnum) {
            if (pEnum->Next(1, &pmt, &fetched) == ole32::S_OK && pmt) {
                majorType = pmt->majortype;
                delete pmt;
            }
            pEnum->Release();
        }

        if (majorType == MEDIATYPE_Audio) {
            auto* pAudio = new CDefaultDirectSoundRenderer();
            AddFilter(pAudio, L"Default DirectSound Device");
            IEnumPins* pPins = nullptr;
            pAudio->EnumPins(&pPins);
            IPin* pIn = nullptr;
            if (pPins) {
                pPins->Next(1, &pIn, &fetched);
                pPins->Release();
            }
            int32_t hr = Connect(ppinOut, pIn);
            if (pIn) pIn->Release();
            pAudio->Release();
            return hr;
        } else {
            auto* pVideo = new CVideoRendererFilter();
            AddFilter(pVideo, L"Video Renderer");
            IEnumPins* pPins = nullptr;
            pVideo->EnumPins(&pPins);
            IPin* pIn = nullptr;
            if (pPins) {
                pPins->Next(1, &pIn, &fetched);
                pPins->Release();
            }
            int32_t hr = Connect(ppinOut, pIn);
            if (pIn) pIn->Release();
            pVideo->Release();
            return hr;
        }
    }

    int32_t __stdcall RenderFile(const wchar_t* lpcwstrFile, const wchar_t*) override {
        if (!lpcwstrFile) return ole32::E_POINTER;
        IBaseFilter* pSrc = nullptr;
        int32_t hr = AddSourceFilter(lpcwstrFile, L"Source Filter", &pSrc);
        if (hr != ole32::S_OK || !pSrc) return hr;

        IEnumPins* pPins = nullptr;
        pSrc->EnumPins(&pPins);
        IPin* pOut = nullptr;
        uint32_t fetched = 0;
        if (pPins) {
            while (pPins->Next(1, &pOut, &fetched) == ole32::S_OK && pOut) {
                Render(pOut);
                pOut->Release();
            }
            pPins->Release();
        }
        pSrc->Release();
        return ole32::S_OK;
    }

    int32_t __stdcall AddSourceFilter(const wchar_t* lpcwstrFileName, const wchar_t* lpcwstrFilterName, IBaseFilter** ppFilter) override {
        if (!lpcwstrFileName || !ppFilter) return ole32::E_POINTER;
        auto* src = new CAsyncFileReaderFilter(lpcwstrFileName);
        const wchar_t* name = lpcwstrFilterName ? lpcwstrFilterName : L"Source Filter";
        AddFilter(src, name);
        *ppFilter = src;
        (*ppFilter)->AddRef();
        src->Release();
        return ole32::S_OK;
    }

    int32_t __stdcall SetLogFile(uintptr_t) override { return ole32::S_OK; }
    int32_t __stdcall Abort() override { return ole32::S_OK; }
    int32_t __stdcall ShouldOperationContinue() override { return ole32::S_OK; }

    // IMediaControl
    int32_t __stdcall Run() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = State_Running;
        for (auto* f : m_filters) f->Run(0);
        m_events.push_back({ EC_COMPLETE, 0, 0 });
        return ole32::S_OK;
    }

    int32_t __stdcall Pause() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = State_Paused;
        for (auto* f : m_filters) f->Pause();
        m_events.push_back({ EC_PAUSED, 0, 0 });
        return ole32::S_OK;
    }

    int32_t __stdcall Stop() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = State_Stopped;
        for (auto* f : m_filters) f->Stop();
        return ole32::S_OK;
    }

    int32_t __stdcall GetState(int32_t, FILTER_STATE* pfs) override {
        if (!pfs) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pfs = m_state;
        return ole32::S_OK;
    }

    int32_t __stdcall RenderFile(const wchar_t* strFilename) override {
        return RenderFile(strFilename, nullptr);
    }

    int32_t __stdcall AddSourceFilter(const wchar_t* strFilename, IDispatch** ppUnk) override {
        if (!ppUnk) return ole32::E_POINTER;
        IBaseFilter* pFilter = nullptr;
        int32_t hr = AddSourceFilter(strFilename, nullptr, &pFilter);
        if (hr == ole32::S_OK && pFilter) {
            *ppUnk = reinterpret_cast<IDispatch*>(pFilter);
        }
        return hr;
    }

    int32_t __stdcall GetFilterGraph(IDispatch** ppUnk) override {
        if (!ppUnk) return ole32::E_POINTER;
        *ppUnk = static_cast<ole32::IDispatch*>(static_cast<IMediaControl*>(this));
        AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetRegFilterCollection(IDispatch** ppUnk) override {
        if (ppUnk) *ppUnk = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall StopWhenReady() override { return Stop(); }

    // IMediaEvent / IMediaEventEx
    int32_t __stdcall GetEventHandle(uintptr_t* hEvent) override {
        if (hEvent) *hEvent = 0x1337;
        return ole32::S_OK;
    }

    int32_t __stdcall GetEvent(int32_t* lEventCode, intptr_t* lParam1, intptr_t* lParam2, int32_t) override {
        if (!lEventCode || !lParam1 || !lParam2) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_events.empty()) return ole32::E_FAIL;
        auto ev = m_events.front();
        m_events.erase(m_events.begin());
        *lEventCode = ev.code;
        *lParam1 = ev.p1;
        *lParam2 = ev.p2;
        return ole32::S_OK;
    }

    int32_t __stdcall WaitForCompletion(int32_t, int32_t* pEvCode) override {
        if (pEvCode) *pEvCode = EC_COMPLETE;
        return ole32::S_OK;
    }

    int32_t __stdcall CancelDefaultHandling(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall RestoreDefaultHandling(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall FreeEventParams(int32_t, intptr_t, intptr_t) override { return ole32::S_OK; }

    int32_t __stdcall SetNotifyWindow(win32::HWND hwnd, uint32_t lMsg, intptr_t) override {
        m_notifyHwnd = hwnd;
        m_notifyMsg = lMsg;
        return ole32::S_OK;
    }

    int32_t __stdcall SetNotifyFlags(int32_t) override { return ole32::S_OK; }

    // IMediaSeeking
    int32_t __stdcall GetCapabilities(uint32_t* pCaps) override {
        if (pCaps) *pCaps = 0x0000000F; // CanSeekAbsolute | CanSeekForwards | CanSeekBackwards | CanGetDuration
        return ole32::S_OK;
    }

    int32_t __stdcall CheckCapabilities(uint32_t* pCaps) override {
        if (pCaps) *pCaps = (*pCaps & 0x0000000F);
        return ole32::S_OK;
    }

    int32_t __stdcall IsFormatSupported(const GUID* pFormat) override {
        if (pFormat && *pFormat == TIME_FORMAT_MEDIA_TIME) return ole32::S_OK;
        return ole32::S_FALSE;
    }

    int32_t __stdcall QueryPreferredFormat(GUID* pFormat) override {
        if (pFormat) *pFormat = TIME_FORMAT_MEDIA_TIME;
        return ole32::S_OK;
    }

    int32_t __stdcall GetTimeFormat(GUID* pFormat) override {
        if (pFormat) *pFormat = TIME_FORMAT_MEDIA_TIME;
        return ole32::S_OK;
    }

    int32_t __stdcall IsUsingTimeFormat(const GUID* pFormat) override {
        if (pFormat && *pFormat == TIME_FORMAT_MEDIA_TIME) return ole32::S_OK;
        return ole32::S_FALSE;
    }

    int32_t __stdcall SetTimeFormat(const GUID*) override { return ole32::S_OK; }
    int32_t __stdcall GetDuration(LONGLONG* pDuration) override {
        if (pDuration) *pDuration = m_duration;
        return ole32::S_OK;
    }

    int32_t __stdcall GetStopPosition(LONGLONG* pStopPosition) override {
        if (pStopPosition) *pStopPosition = m_duration;
        return ole32::S_OK;
    }

    int32_t __stdcall GetCurrentPosition(LONGLONG* pCurrentPosition) override {
        if (pCurrentPosition) *pCurrentPosition = m_currentPos;
        return ole32::S_OK;
    }

    int32_t __stdcall ConvertTimeFormat(LONGLONG* pTarget, const GUID*, LONGLONG Source, const GUID*) override {
        if (pTarget) *pTarget = Source;
        return ole32::S_OK;
    }

    int32_t __stdcall SetPositions(LONGLONG* pCurrent, uint32_t, LONGLONG* pStop, uint32_t) override {
        if (pCurrent) m_currentPos = *pCurrent;
        if (pStop) m_duration = *pStop;
        return ole32::S_OK;
    }

    int32_t __stdcall GetPositions(LONGLONG* pCurrent, LONGLONG* pStop) override {
        if (pCurrent) *pCurrent = m_currentPos;
        if (pStop) *pStop = m_duration;
        return ole32::S_OK;
    }

    int32_t __stdcall GetAvailable(LONGLONG* pEarliest, LONGLONG* pLatest) override {
        if (pEarliest) *pEarliest = 0;
        if (pLatest) *pLatest = m_duration;
        return ole32::S_OK;
    }

    int32_t __stdcall SetRate(double dRate) override { m_rate = dRate; return ole32::S_OK; }
    int32_t __stdcall GetRate(double* pdRate) override { if (pdRate) *pdRate = m_rate; return ole32::S_OK; }
    int32_t __stdcall GetPreroll(LONGLONG* pllPreroll) override { if (pllPreroll) *pllPreroll = 0; return ole32::S_OK; }

    // IBasicAudio
    int32_t __stdcall put_Volume(int32_t lVolume) override { m_volume = lVolume; return ole32::S_OK; }
    int32_t __stdcall get_Volume(int32_t* plVolume) override { if (plVolume) *plVolume = m_volume; return ole32::S_OK; }
    int32_t __stdcall put_Balance(int32_t lBalance) override { m_balance = lBalance; return ole32::S_OK; }
    int32_t __stdcall get_Balance(int32_t* plBalance) override { if (plBalance) *plBalance = m_balance; return ole32::S_OK; }

    // IBasicVideo
    int32_t __stdcall get_AvgTimePerFrame(double* pAvg) override { if (pAvg) *pAvg = 0.033333; return ole32::S_OK; }
    int32_t __stdcall get_BitRate(int32_t* pRate) override { if (pRate) *pRate = 5000000; return ole32::S_OK; }
    int32_t __stdcall get_BitErrorRate(int32_t* pRate) override { if (pRate) *pRate = 0; return ole32::S_OK; }
    int32_t __stdcall get_VideoWidth(int32_t* pW) override { if (pW) *pW = m_videoWidth; return ole32::S_OK; }
    int32_t __stdcall get_VideoHeight(int32_t* pH) override { if (pH) *pH = m_videoHeight; return ole32::S_OK; }
    int32_t __stdcall put_SourceLeft(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_SourceLeft(int32_t* pL) override { if (pL) *pL = 0; return ole32::S_OK; }
    int32_t __stdcall put_SourceWidth(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_SourceWidth(int32_t* pW) override { if (pW) *pW = m_videoWidth; return ole32::S_OK; }
    int32_t __stdcall put_SourceTop(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_SourceTop(int32_t* pT) override { if (pT) *pT = 0; return ole32::S_OK; }
    int32_t __stdcall put_SourceHeight(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_SourceHeight(int32_t* pH) override { if (pH) *pH = m_videoHeight; return ole32::S_OK; }
    int32_t __stdcall put_DestinationLeft(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_DestinationLeft(int32_t* pL) override { if (pL) *pL = 0; return ole32::S_OK; }
    int32_t __stdcall put_DestinationWidth(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_DestinationWidth(int32_t* pW) override { if (pW) *pW = m_videoWidth; return ole32::S_OK; }
    int32_t __stdcall put_DestinationTop(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_DestinationTop(int32_t* pT) override { if (pT) *pT = 0; return ole32::S_OK; }
    int32_t __stdcall put_DestinationHeight(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_DestinationHeight(int32_t* pH) override { if (pH) *pH = m_videoHeight; return ole32::S_OK; }
    int32_t __stdcall GetCurrentImage(int32_t* pBufferSize, int32_t* pDIB) override {
        if (!pBufferSize) return ole32::E_POINTER;
        int32_t req = m_videoWidth * m_videoHeight * 4;
        if (!pDIB) {
            *pBufferSize = req;
            return ole32::S_OK;
        }
        std::memset(pDIB, 0x55, static_cast<size_t>(std::min(*pBufferSize, req)));
        return ole32::S_OK;
    }

    // IVideoWindow
    int32_t __stdcall put_Caption(const wchar_t* strCaption) override {
        if (strCaption) m_caption = strCaption;
        return ole32::S_OK;
    }

    int32_t __stdcall get_Caption(wchar_t** strCaption) override {
        if (!strCaption) return ole32::E_POINTER;
        size_t len = (m_caption.size() + 1) * sizeof(wchar_t);
        *strCaption = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
        if (!*strCaption) return ole32::E_OUTOFMEMORY;
        std::memcpy(*strCaption, m_caption.c_str(), len);
        return ole32::S_OK;
    }

    int32_t __stdcall put_WindowStyle(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_WindowStyle(int32_t* pStyle) override { if (pStyle) *pStyle = 0x14CF0000; return ole32::S_OK; }
    int32_t __stdcall put_AutoShow(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_AutoShow(int32_t* pAS) override { if (pAS) *pAS = 1; return ole32::S_OK; }
    int32_t __stdcall put_WindowState(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall get_WindowState(int32_t* pWS) override { if (pWS) *pWS = 1; return ole32::S_OK; }
    int32_t __stdcall put_Owner(uintptr_t) override { return ole32::S_OK; }
    int32_t __stdcall get_Owner(uintptr_t* pOwner) override { if (pOwner) *pOwner = 0; return ole32::S_OK; }
    int32_t __stdcall put_MessageDrain(uintptr_t) override { return ole32::S_OK; }
    int32_t __stdcall get_MessageDrain(uintptr_t* pDrain) override { if (pDrain) *pDrain = 0; return ole32::S_OK; }
    int32_t __stdcall put_Visible(int32_t Visible) override { m_visible = Visible; return ole32::S_OK; }
    int32_t __stdcall get_Visible(int32_t* pVisible) override { if (pVisible) *pVisible = m_visible; return ole32::S_OK; }
    int32_t __stdcall SetWindowPosition(int32_t, int32_t, int32_t, int32_t) override { return ole32::S_OK; }
    int32_t __stdcall GetWindowPosition(int32_t* pL, int32_t* pT, int32_t* pW, int32_t* pH) override {
        if (pL) *pL = 100;
        if (pT) *pT = 100;
        if (pW) *pW = m_videoWidth;
        if (pH) *pH = m_videoHeight;
        return ole32::S_OK;
    }
};

// ============================================================================
// 8. Device Enumerator (devenum.dll)
// ============================================================================

class CDeviceMoniker : public IMoniker {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_friendlyName;
    GUID m_clsid{};

public:
    CDeviceMoniker(std::wstring name, GUID clsid)
        : m_friendlyName(std::move(name)), m_clsid(clsid) {}

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IPropertyBag) {
            *ppvObject = static_cast<IMoniker*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    const std::wstring& GetFriendlyName() const { return m_friendlyName; }
    const GUID& GetClsid() const { return m_clsid; }

    int32_t __stdcall BindToObject(void*, IMoniker*, const GUID& riid, void** ppvResult) override {
        if (!ppvResult) return ole32::E_POINTER;
        auto* filter = new CBaseFilter(m_friendlyName, m_clsid);
        int32_t hr = filter->QueryInterface(riid, ppvResult);
        filter->Release();
        return hr;
    }

    int32_t __stdcall BindToStorage(void*, IMoniker*, const GUID&, void** ppvObj) override {
        if (!ppvObj) return ole32::E_POINTER;
        *ppvObj = nullptr;
        return ole32::S_OK;
    }
};

class CEnumMoniker : public IEnumMoniker {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<IMoniker*> m_monikers;
    size_t m_index{ 0 };

public:
    explicit CEnumMoniker(std::vector<IMoniker*> monikers)
        : m_monikers(std::move(monikers)) {
        for (auto* m : m_monikers) if (m) m->AddRef();
    }

    ~CEnumMoniker() override {
        for (auto* m : m_monikers) if (m) m->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown) {
            *ppvObject = static_cast<IEnumMoniker*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall Next(uint32_t celt, IMoniker** rgelt, uint32_t* pceltFetched) override {
        if (!rgelt) return ole32::E_POINTER;
        uint32_t fetched = 0;
        while (m_index < m_monikers.size() && fetched < celt) {
            rgelt[fetched] = m_monikers[m_index++];
            rgelt[fetched]->AddRef();
            fetched++;
        }
        if (pceltFetched) *pceltFetched = fetched;
        return (fetched == celt) ? ole32::S_OK : ole32::S_FALSE;
    }

    int32_t __stdcall Skip(uint32_t celt) override {
        m_index = std::min(m_index + celt, m_monikers.size());
        return ole32::S_OK;
    }

    int32_t __stdcall Reset() override {
        m_index = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall Clone(IEnumMoniker** ppenum) override {
        if (!ppenum) return ole32::E_POINTER;
        *ppenum = new CEnumMoniker(m_monikers);
        return ole32::S_OK;
    }
};

class CDeviceEnumerator : public ICreateDevEnum {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::unordered_map<std::string, std::vector<std::pair<std::wstring, GUID>>> m_devices;

public:
    CDeviceEnumerator() {
        // Pre-seed sovereign hardware capture devices
        m_devices[ole32::ComRuntime::GuidToString(CLSID_VideoInputDeviceCategory)] = {
            { L"MicaNT Titan HD Camera", { 0x860BB311, 0x5D01, 0x11D0, { 0xBD, 0x3B, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } } },
            { L"MicaNT Virtual WebCam 1080p", { 0x860BB312, 0x5D01, 0x11D0, { 0xBD, 0x3B, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } } }
        };
        m_devices[ole32::ComRuntime::GuidToString(CLSID_AudioInputDeviceCategory)] = {
            { L"MicaNT Studio Mic Array", { 0x33D9A763, 0x90C8, 0x11D0, { 0xBD, 0x43, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } } },
            { L"MicaNT Bluetooth Hands-Free Mic", { 0x33D9A764, 0x90C8, 0x11D0, { 0xBD, 0x43, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } } }
        };
        m_devices[ole32::ComRuntime::GuidToString(CLSID_AudioRendererCategory)] = {
            { L"Default DirectSound Device", CLSID_DSoundRender },
            { L"MicaNT High Definition Audio", { 0xE0F158E2, 0xCB04, 0x11D0, { 0xBD, 0x4E, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86 } } }
        };
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ICreateDevEnum) {
            *ppvObject = static_cast<ICreateDevEnum*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall CreateClassEnumerator(const GUID& clsidDeviceClass, IEnumMoniker** ppEnumMoniker, uint32_t) override {
        if (!ppEnumMoniker) return ole32::E_POINTER;
        std::string key = ole32::ComRuntime::GuidToString(clsidDeviceClass);
        auto it = m_devices.find(key);
        if (it == m_devices.end() || it->second.empty()) {
            *ppEnumMoniker = nullptr;
            return ole32::S_FALSE;
        }

        std::vector<IMoniker*> list;
        for (const auto& dev : it->second) {
            list.push_back(new CDeviceMoniker(dev.first, dev.second));
        }
        *ppEnumMoniker = new CEnumMoniker(list);
        for (auto* m : list) m->Release();
        return ole32::S_OK;
    }
};

// ============================================================================
// 9. Class Factories & Dynamic Loader Exports
// ============================================================================

template <typename T>
class CSimpleClassFactory : public ole32::IClassFactory {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == ole32::IID_IClassFactory) {
            *ppvObject = static_cast<ole32::IClassFactory*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall CreateInstance(ole32::IUnknown* pUnkOuter, const GUID& riid, void** ppvObject) override {
        if (pUnkOuter) return ole32::CLASS_E_NOAGGREGATION;
        auto* instance = new T();
        int32_t hr = instance->QueryInterface(riid, ppvObject);
        instance->Release();
        return hr;
    }

    int32_t __stdcall LockServer(int32_t) override { return ole32::S_OK; }
};

// Dynamic Loader C-API Exports
inline uint32_t __stdcall AMGetErrorTextA(int32_t hr, char* pbuffer, uint32_t max) {
    if (!pbuffer || max == 0) return 0;
    std::string msg;
    switch (hr) {
        case ole32::S_OK: msg = "Operation succeeded"; break;
        case VFW_E_NOT_CONNECTED: msg = "The operation cannot be performed because the pins are not connected"; break;
        case VFW_E_CANNOT_CONNECT: msg = "No combination of intermediate filters could be found to make the connection"; break;
        case VFW_E_CANNOT_RENDER: msg = "No combination of filters could be found to render the stream"; break;
        default: msg = "DirectShow Error 0x" + std::to_string(static_cast<uint32_t>(hr)); break;
    }
    uint32_t copyLen = std::min(max - 1, static_cast<uint32_t>(msg.size()));
    std::memcpy(pbuffer, msg.c_str(), copyLen);
    pbuffer[copyLen] = '\0';
    return copyLen;
}

inline uint32_t __stdcall AMGetErrorTextW(int32_t hr, wchar_t* pbuffer, uint32_t max) {
    if (!pbuffer || max == 0) return 0;
    std::wstring msg;
    switch (hr) {
        case ole32::S_OK: msg = L"Operation succeeded"; break;
        case VFW_E_NOT_CONNECTED: msg = L"The operation cannot be performed because the pins are not connected"; break;
        case VFW_E_CANNOT_CONNECT: msg = L"No combination of intermediate filters could be found to make the connection"; break;
        case VFW_E_CANNOT_RENDER: msg = L"No combination of filters could be found to render the stream"; break;
        default: msg = L"DirectShow Error"; break;
    }
    uint32_t copyLen = std::min(max - 1, static_cast<uint32_t>(msg.size()));
    std::memcpy(pbuffer, msg.c_str(), copyLen * sizeof(wchar_t));
    pbuffer[copyLen] = L'\0';
    return copyLen;
}

inline int32_t __stdcall DllCanUnloadNow() {
    return ole32::S_OK;
}

inline void InitializeDirectShowExports() {
    auto& loader = ldr::DynamicLoader::get();

    // quartz.dll exports
    loader.registerExport("quartz.dll", "AMGetErrorTextA", reinterpret_cast<void*>(&AMGetErrorTextA));
    loader.registerExport("quartz.dll", "AMGetErrorTextW", reinterpret_cast<void*>(&AMGetErrorTextW));
    loader.registerExport("quartz.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&DllCanUnloadNow));

    // devenum.dll exports
    loader.registerExport("devenum.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&DllCanUnloadNow));

    // qedit.dll exports
    loader.registerExport("qedit.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&DllCanUnloadNow));

    // Register COM Class Factories in ComRuntime
    auto& com = ole32::ComRuntime::get();
    uint32_t regCookie = 0;
    auto* fgFact = new CSimpleClassFactory<CFilterGraphManager>();
    com.RegisterClassObject(CLSID_FilterGraph, fgFact, 1, 1, &regCookie);
    fgFact->Release();

    auto* devFact = new CSimpleClassFactory<CDeviceEnumerator>();
    com.RegisterClassObject(CLSID_SystemDeviceEnum, devFact, 1, 1, &regCookie);
    devFact->Release();

    auto* sgFact = new CSimpleClassFactory<CSampleGrabberFilter>();
    com.RegisterClassObject(CLSID_SampleGrabber, sgFact, 1, 1, &regCookie);
    sgFact->Release();

    auto* arFact = new CSimpleClassFactory<CAsyncFileReaderFilter>();
    com.RegisterClassObject(CLSID_AsyncReader, arFact, 1, 1, &regCookie);
    arFact->Release();

    auto* vrFact = new CSimpleClassFactory<CVideoRendererFilter>();
    com.RegisterClassObject(CLSID_VideoRenderer, vrFact, 1, 1, &regCookie);
    vrFact->Release();

    auto* dsFact = new CSimpleClassFactory<CDefaultDirectSoundRenderer>();
    com.RegisterClassObject(CLSID_DSoundRender, dsFact, 1, 1, &regCookie);
    dsFact->Release();
}

} // namespace micant::dshow
