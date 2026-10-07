// ============================================================================
// MicaNT: Windows Audio Session API (WASAPI) & Core Audio Engine Subsystem
// (mmdevapi.dll & audiosrv.dll)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Compatible with Microsoft win32metadata Core Audio & WASAPI specifications.
//
// Implements:
// - Multimedia Device Enumerator: IMMDeviceEnumerator, IMMDevice,
//   IMMDeviceCollection, IMMEndpoint, IMMNotificationClient.
// - Windows Property Store: IPropertyStore, PROPERTYKEY, PROPVARIANT,
//   standard audio endpoint properties (PKEY_Device_FriendlyName,
//   PKEY_AudioEndpoint_FormFactor, PKEY_AudioEngine_DeviceFormat).
// - Audio Client Engine (WASAPI): IAudioClient, IAudioClient2, IAudioClient3,
//   shared and exclusive streams, latency calculation, format negotiation.
// - Audio Render & Capture Clients: IAudioRenderClient (GetBuffer, ReleaseBuffer),
//   IAudioCaptureClient, event-driven buffer signaling.
// - Audio Clock & Volume Controls: IAudioClock (sample accurate positioning),
//   ISimpleAudioVolume, IAudioEndpointVolume (scalar & dB stepping, mute).
// - Core Audio Service (audiosrv.dll) SCM integration and dynamic DLL exports.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <map>
#include <algorithm>
#include <sstream>
#include <cmath>
#include <cwchar>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "prismaudio.hpp"
#include "ole32.hpp"
#include "scm.hpp"
#include "ldr.hpp"

namespace micant::wasapi {

// ============================================================================
// 1. Core Audio Types, Enums & Constants
// ============================================================================

using REFERENCE_TIME = int64_t;

enum EDataFlow : uint32_t {
    eRender               = 0,
    eCapture              = 1,
    eAll                  = 2,
    EDataFlow_enum_count  = 3
};

enum ERole : uint32_t {
    eConsole              = 0,
    eMultimedia           = 1,
    eCommunications       = 2,
    ERole_enum_count      = 3
};

enum EndpointFormFactor : uint32_t {
    RemoteNetworkDevice        = 0,
    Speakers                   = 1,
    LineLevel                  = 2,
    Headphones                 = 3,
    Microphone                 = 4,
    Headset                    = 5,
    Handset                    = 6,
    UnknownDigitalPassthrough  = 7,
    SPDIF                      = 8,
    DigitalAudioDisplayDevice  = 9,
    UnknownFormFactor          = 10
};

enum AUDCLNT_SHAREMODE : uint32_t {
    AUDCLNT_SHAREMODE_SHARED    = 0,
    AUDCLNT_SHAREMODE_EXCLUSIVE = 1
};

// Device State Bitmasks
inline constexpr uint32_t DEVICE_STATE_ACTIVE     = 0x00000001;
inline constexpr uint32_t DEVICE_STATE_DISABLED   = 0x00000002;
inline constexpr uint32_t DEVICE_STATE_NOTPRESENT = 0x00000004;
inline constexpr uint32_t DEVICE_STATE_UNPLUGGED   = 0x00000008;
inline constexpr uint32_t DEVICE_STATEMASK_ALL    = 0x0000000F;

// Storage Access Modes
inline constexpr uint32_t STGM_READ      = 0x00000000;
inline constexpr uint32_t STGM_WRITE     = 0x00000001;
inline constexpr uint32_t STGM_READWRITE = 0x00000002;

// Audio Client Stream Flags
inline constexpr uint32_t AUDCLNT_STREAMFLAGS_CROSSPROCESS    = 0x00010000;
inline constexpr uint32_t AUDCLNT_STREAMFLAGS_LOOPBACK        = 0x00020000;
inline constexpr uint32_t AUDCLNT_STREAMFLAGS_EVENTCALLBACK   = 0x00040000;
inline constexpr uint32_t AUDCLNT_STREAMFLAGS_NOPERSIST       = 0x00080000;
inline constexpr uint32_t AUDCLNT_STREAMFLAGS_RATEADJUST      = 0x00100000;
inline constexpr uint32_t AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM  = 0x80000000;

// Audio Client Buffer Flags
inline constexpr uint32_t AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY = 0x1;
inline constexpr uint32_t AUDCLNT_BUFFERFLAGS_SILENT             = 0x2;
inline constexpr uint32_t AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR    = 0x4;

// Audio Client Status / Error HRESULTs
inline constexpr ole32::HRESULT AUDCLNT_E_NOT_INITIALIZED            = static_cast<ole32::HRESULT>(0x88890001);
inline constexpr ole32::HRESULT AUDCLNT_E_ALREADY_INITIALIZED        = static_cast<ole32::HRESULT>(0x88890002);
inline constexpr ole32::HRESULT AUDCLNT_E_WRONG_ENDPOINT_TYPE        = static_cast<ole32::HRESULT>(0x88890003);
inline constexpr ole32::HRESULT AUDCLNT_E_DEVICE_INVALIDATED         = static_cast<ole32::HRESULT>(0x88890004);
inline constexpr ole32::HRESULT AUDCLNT_E_NOT_STOPPED                = static_cast<ole32::HRESULT>(0x88890005);
inline constexpr ole32::HRESULT AUDCLNT_E_BUFFER_TOO_LARGE           = static_cast<ole32::HRESULT>(0x88890006);
inline constexpr ole32::HRESULT AUDCLNT_E_OUT_OF_ORDER               = static_cast<ole32::HRESULT>(0x88890007);
inline constexpr ole32::HRESULT AUDCLNT_E_UNSUPPORTED_FORMAT         = static_cast<ole32::HRESULT>(0x88890008);
inline constexpr ole32::HRESULT AUDCLNT_E_INVALID_SIZE               = static_cast<ole32::HRESULT>(0x88890009);
inline constexpr ole32::HRESULT AUDCLNT_E_DEVICE_IN_USE              = static_cast<ole32::HRESULT>(0x8889000A);
inline constexpr ole32::HRESULT AUDCLNT_E_BUFFER_OPERATION_PENDING   = static_cast<ole32::HRESULT>(0x8889000B);
inline constexpr ole32::HRESULT AUDCLNT_E_THREAD_NOT_REGISTERED      = static_cast<ole32::HRESULT>(0x8889000C);
inline constexpr ole32::HRESULT AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED = static_cast<ole32::HRESULT>(0x8889000E);
inline constexpr ole32::HRESULT AUDCLNT_E_ENDPOINT_CREATE_FAILED     = static_cast<ole32::HRESULT>(0x8889000F);
inline constexpr ole32::HRESULT AUDCLNT_E_SERVICE_NOT_RUNNING        = static_cast<ole32::HRESULT>(0x88890010);
inline constexpr ole32::HRESULT AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED   = static_cast<ole32::HRESULT>(0x88890011);
inline constexpr ole32::HRESULT AUDCLNT_E_EXCLUSIVE_MODE_ONLY        = static_cast<ole32::HRESULT>(0x88890012);
inline constexpr ole32::HRESULT AUDCLNT_E_BUFDURATION_PERIOD_NOT_EQUAL = static_cast<ole32::HRESULT>(0x88890013);
inline constexpr ole32::HRESULT AUDCLNT_E_EVENTHANDLE_NOT_SET        = static_cast<ole32::HRESULT>(0x88890014);
inline constexpr ole32::HRESULT AUDCLNT_E_INCORRECT_BUFFER_SIZE      = static_cast<ole32::HRESULT>(0x88890015);
inline constexpr ole32::HRESULT AUDCLNT_E_BUFFER_SIZE_ERROR          = static_cast<ole32::HRESULT>(0x88890016);
inline constexpr ole32::HRESULT AUDCLNT_E_CPUUSAGE_EXCEEDED          = static_cast<ole32::HRESULT>(0x88890017);
inline constexpr ole32::HRESULT AUDCLNT_E_BUFFER_ERROR               = static_cast<ole32::HRESULT>(0x88890018);
inline constexpr ole32::HRESULT AUDCLNT_E_BUFFER_SIZE_NOT_ALIGNED    = static_cast<ole32::HRESULT>(0x88890019);
inline constexpr ole32::HRESULT AUDCLNT_E_PROPERTY_NOT_FOUND         = static_cast<ole32::HRESULT>(0x8889001A);
inline constexpr ole32::HRESULT AUDCLNT_S_BUFFER_EMPTY               = static_cast<ole32::HRESULT>(0x08890001);
inline constexpr ole32::HRESULT AUDCLNT_S_THREAD_ALREADY_REGISTERED  = static_cast<ole32::HRESULT>(0x08890002);
inline constexpr ole32::HRESULT AUDCLNT_S_POSITION_STALLED           = static_cast<ole32::HRESULT>(0x08890003);

// ============================================================================
// 2. Property Store & Property Key Types
// ============================================================================

struct PROPERTYKEY {
    GUID fmtid{};
    uint32_t pid{0};

    bool operator==(const PROPERTYKEY& other) const noexcept {
        return fmtid == other.fmtid && pid == other.pid;
    }

    bool operator<(const PROPERTYKEY& other) const noexcept {
        if (fmtid.Data1 != other.fmtid.Data1) return fmtid.Data1 < other.fmtid.Data1;
        if (fmtid.Data2 != other.fmtid.Data2) return fmtid.Data2 < other.fmtid.Data2;
        if (fmtid.Data3 != other.fmtid.Data3) return fmtid.Data3 < other.fmtid.Data3;
        for (int i = 0; i < 8; ++i) {
            if (fmtid.Data4[i] != other.fmtid.Data4[i]) return fmtid.Data4[i] < other.fmtid.Data4[i];
        }
        return pid < other.pid;
    }
};

inline constexpr uint16_t VT_BLOB = 65;
inline constexpr uint16_t VT_CLSID = 72;

struct PROPVARIANT {
    uint16_t vt{0};
    uint16_t wReserved1{0};
    uint16_t wReserved2{0};
    uint16_t wReserved3{0};
    union {
        int8_t   cVal;
        uint8_t  bVal;
        int16_t  iVal;
        uint16_t uiVal;
        int32_t  lVal;
        uint32_t ulVal;
        int64_t  hVal;
        uint64_t uhVal;
        float    fltVal;
        double   dblVal;
        int16_t  boolVal;
        wchar_t* pwszVal;
        char*    pszVal;
        void*    punkVal;
        GUID*    puuid;
        struct {
            uint32_t cbSize;
            uint8_t* pBlobData;
        } blob;
    };
};

inline void PropVariantInit(PROPVARIANT* pvar) noexcept {
    if (pvar) std::memset(pvar, 0, sizeof(PROPVARIANT));
}

inline ole32::HRESULT PropVariantClear(PROPVARIANT* pvar) noexcept {
    if (!pvar) return ole32::S_OK;
    if (pvar->vt == ole32::VT_LPWSTR && pvar->pwszVal) {
        ole32::CoTaskMemFree(pvar->pwszVal);
    } else if (pvar->vt == ole32::VT_LPSTR && pvar->pszVal) {
        ole32::CoTaskMemFree(pvar->pszVal);
    } else if (pvar->vt == VT_BLOB && pvar->blob.pBlobData) {
        ole32::CoTaskMemFree(pvar->blob.pBlobData);
    } else if (pvar->vt == VT_CLSID && pvar->puuid) {
        ole32::CoTaskMemFree(pvar->puuid);
    }
    std::memset(pvar, 0, sizeof(PROPVARIANT));
    return ole32::S_OK;
}

inline ole32::HRESULT PropVariantCopy(PROPVARIANT* pvarDest, const PROPVARIANT* pvarSrc) noexcept {
    if (!pvarDest || !pvarSrc) return ole32::E_POINTER;
    PropVariantClear(pvarDest);
    pvarDest->vt = pvarSrc->vt;
    if (pvarSrc->vt == ole32::VT_LPWSTR && pvarSrc->pwszVal) {
        size_t len = std::wcslen(pvarSrc->pwszVal);
        pvarDest->pwszVal = static_cast<wchar_t*>(ole32::CoTaskMemAlloc((len + 1) * sizeof(wchar_t)));
        if (pvarDest->pwszVal) {
            std::wcscpy(pvarDest->pwszVal, pvarSrc->pwszVal);
        }
    } else if (pvarSrc->vt == ole32::VT_LPSTR && pvarSrc->pszVal) {
        size_t len = std::strlen(pvarSrc->pszVal);
        pvarDest->pszVal = static_cast<char*>(ole32::CoTaskMemAlloc(len + 1));
        if (pvarDest->pszVal) {
            std::strcpy(pvarDest->pszVal, pvarSrc->pszVal);
        }
    } else if (pvarSrc->vt == VT_BLOB && pvarSrc->blob.pBlobData) {
        pvarDest->blob.cbSize = pvarSrc->blob.cbSize;
        pvarDest->blob.pBlobData = static_cast<uint8_t*>(ole32::CoTaskMemAlloc(pvarSrc->blob.cbSize));
        if (pvarDest->blob.pBlobData) {
            std::memcpy(pvarDest->blob.pBlobData, pvarSrc->blob.pBlobData, pvarSrc->blob.cbSize);
        }
    } else if (pvarSrc->vt == VT_CLSID && pvarSrc->puuid) {
        pvarDest->puuid = static_cast<GUID*>(ole32::CoTaskMemAlloc(sizeof(GUID)));
        if (pvarDest->puuid) {
            *pvarDest->puuid = *pvarSrc->puuid;
        }
    } else {
        std::memcpy(pvarDest, pvarSrc, sizeof(PROPVARIANT));
    }
    return ole32::S_OK;
}

// Standard Property Keys
inline const PROPERTYKEY PKEY_Device_FriendlyName = {
    { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 14
};

inline const PROPERTYKEY PKEY_Device_DeviceDesc = {
    { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 2
};

inline const PROPERTYKEY PKEY_AudioEndpoint_FormFactor = {
    { 0x1da5d803, 0xd492, 0x4edd, { 0x8c, 0x23, 0xe0, 0xc0, 0xff, 0xee, 0x7f, 0x0e } }, 0
};

inline const PROPERTYKEY PKEY_AudioEndpoint_ControlPanelGrouping = {
    { 0x1da5d803, 0xd492, 0x4edd, { 0x8c, 0x23, 0xe0, 0xc0, 0xff, 0xee, 0x7f, 0x0e } }, 1
};

inline const PROPERTYKEY PKEY_AudioEngine_DeviceFormat = {
    { 0xf19f064d, 0x082c, 0x4e27, { 0xbc, 0x73, 0x68, 0x82, 0xa1, 0xbb, 0x8e, 0x4c } }, 0
};

// ============================================================================
// 3. Core Audio GUIDs
// ============================================================================

inline const GUID CLSID_MMDeviceEnumerator = {
    0xbcde0395, 0xe52f, 0x467c, { 0x8e, 0x3d, 0xc4, 0x57, 0x92, 0x91, 0x69, 0x2e }
};

inline const GUID IID_IMMDeviceEnumerator = {
    0xa95664d2, 0x9614, 0x4f35, { 0xa7, 0x46, 0xde, 0x8d, 0xb6, 0x36, 0x17, 0xe6 }
};

inline const GUID IID_IMMDevice = {
    0xd666063f, 0x1587, 0x4e43, { 0x81, 0xf1, 0xb9, 0x48, 0xe8, 0x07, 0x36, 0x3f }
};

inline const GUID IID_IMMDeviceCollection = {
    0x0bd7a1be, 0x7a1a, 0x44db, { 0xa9, 0x83, 0x45, 0x4b, 0x45, 0x4b, 0x36, 0x4a }
};

inline const GUID IID_IMMEndpoint = {
    0x1be09788, 0x6894, 0x4089, { 0x85, 0x86, 0x0a, 0x16, 0x7b, 0x70, 0x03, 0x0a }
};

inline const GUID IID_IMMNotificationClient = {
    0x7991283b, 0x0170, 0x4140, { 0x81, 0x27, 0xd0, 0x0d, 0x1a, 0xf3, 0x68, 0xc4 }
};

inline const GUID IID_IPropertyStore = {
    0x886d8eeb, 0x8cf2, 0x4446, { 0x8d, 0x02, 0xcd, 0xba, 0x1d, 0xbd, 0xcf, 0x99 }
};

inline const GUID IID_IAudioClient = {
    0x1cb9ad4c, 0xdbfa, 0x4c32, { 0xb1, 0x78, 0xc2, 0xf5, 0x68, 0xa7, 0x03, 0xb2 }
};

inline const GUID IID_IAudioClient2 = {
    0x726778cd, 0x1b24, 0x46d4, { 0xae, 0xfa, 0x21, 0xa5, 0xe2, 0x69, 0x9f, 0x12 }
};

inline const GUID IID_IAudioClient3 = {
    0x7ed4ee07, 0x8e67, 0x4cd4, { 0x8c, 0x1a, 0x2b, 0x7a, 0x56, 0x25, 0xc0, 0x0e }
};

inline const GUID IID_IAudioRenderClient = {
    0xf294ac80, 0x3186, 0x42db, { 0xa2, 0xb0, 0xab, 0x80, 0x30, 0x95, 0x33, 0xd3 }
};

inline const GUID IID_IAudioCaptureClient = {
    0xc8adbd64, 0xe71e, 0x48a0, { 0xa4, 0xde, 0x18, 0x5c, 0x30, 0x59, 0x40, 0xf9 }
};

inline const GUID IID_IAudioClock = {
    0xcd63314f, 0x3fba, 0x4a1b, { 0x81, 0x2c, 0xef, 0x96, 0x35, 0x87, 0x28, 0xe7 }
};

inline const GUID IID_ISimpleAudioVolume = {
    0x87ce5498, 0x68d6, 0x44e5, { 0x92, 0x15, 0x6d, 0xa4, 0x7e, 0xf8, 0x83, 0xd8 }
};

inline const GUID IID_IAudioEndpointVolume = {
    0x5bc648ba, 0x3801, 0x4945, { 0x80, 0x98, 0xcd, 0x0e, 0x04, 0x02, 0xc3, 0x46 }
};

inline const GUID IID_IAudioSessionManager = {
    0xbfa971f1, 0x4d5e, 0x40bb, { 0x93, 0x5e, 0x96, 0x70, 0x39, 0xbf, 0xbe, 0xe4 }
};

// ============================================================================
// 4. Base Core Audio COM Interface Declarations
// ============================================================================

class IPropertyStore : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall GetCount(uint32_t* cProps) = 0;
    virtual ole32::HRESULT __stdcall GetAt(uint32_t iProp, PROPERTYKEY* pkey) = 0;
    virtual ole32::HRESULT __stdcall GetValue(const PROPERTYKEY& key, PROPVARIANT* pv) = 0;
    virtual ole32::HRESULT __stdcall SetValue(const PROPERTYKEY& key, const PROPVARIANT& propvar) = 0;
    virtual ole32::HRESULT __stdcall Commit() = 0;
};

class IMMNotificationClient : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall OnDeviceStateChanged(const wchar_t* pwstrDeviceId, uint32_t dwNewState) = 0;
    virtual ole32::HRESULT __stdcall OnDeviceAdded(const wchar_t* pwstrDeviceId) = 0;
    virtual ole32::HRESULT __stdcall OnDeviceRemoved(const wchar_t* pwstrDeviceId) = 0;
    virtual ole32::HRESULT __stdcall OnDefaultDeviceChanged(EDataFlow flow, ERole role, const wchar_t* pwstrDefaultDeviceId) = 0;
    virtual ole32::HRESULT __stdcall OnPropertyValueChanged(const wchar_t* pwstrDeviceId, const PROPERTYKEY key) = 0;
};

class IMMEndpoint : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall GetDataFlow(EDataFlow* pDataFlow) = 0;
};

class IMMDevice : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall Activate(ole32::REFIID iid, uint32_t dwClsCtx, PROPVARIANT* pActivationParams, void** ppInterface) = 0;
    virtual ole32::HRESULT __stdcall OpenPropertyStore(uint32_t stgmAccess, IPropertyStore** ppProperties) = 0;
    virtual ole32::HRESULT __stdcall GetId(wchar_t** ppstrId) = 0;
    virtual ole32::HRESULT __stdcall GetState(uint32_t* pdwState) = 0;
};

class IMMDeviceCollection : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall GetCount(uint32_t* pcDevices) = 0;
    virtual ole32::HRESULT __stdcall Item(uint32_t nDevice, IMMDevice** ppDevice) = 0;
};

class IMMDeviceEnumerator : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall EnumAudioEndpoints(EDataFlow dataFlow, uint32_t dwStateMask, IMMDeviceCollection** ppDevices) = 0;
    virtual ole32::HRESULT __stdcall GetDefaultAudioEndpoint(EDataFlow dataFlow, ERole role, IMMDevice** ppEndpoint) = 0;
    virtual ole32::HRESULT __stdcall GetDevice(const wchar_t* pwstrId, IMMDevice** ppDevice) = 0;
    virtual ole32::HRESULT __stdcall RegisterEndpointNotificationCallback(IMMNotificationClient* pClient) = 0;
    virtual ole32::HRESULT __stdcall UnregisterEndpointNotificationCallback(IMMNotificationClient* pClient) = 0;
};

class IAudioClient : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall Initialize(
        AUDCLNT_SHAREMODE ShareMode,
        uint32_t StreamFlags,
        REFERENCE_TIME hnsBufferDuration,
        REFERENCE_TIME hnsPeriodicity,
        const audio::WAVEFORMATEX* pFormat,
        const GUID* AudioSessionGuid
    ) = 0;
    virtual ole32::HRESULT __stdcall GetBufferSize(uint32_t* pNumBufferFrames) = 0;
    virtual ole32::HRESULT __stdcall GetStreamLatency(REFERENCE_TIME* phnsLatency) = 0;
    virtual ole32::HRESULT __stdcall GetCurrentPadding(uint32_t* pNumPaddingFrames) = 0;
    virtual ole32::HRESULT __stdcall IsFormatSupported(
        AUDCLNT_SHAREMODE ShareMode,
        const audio::WAVEFORMATEX* pFormat,
        audio::WAVEFORMATEX** ppClosestMatch
    ) = 0;
    virtual ole32::HRESULT __stdcall GetMixFormat(audio::WAVEFORMATEX** ppDeviceFormat) = 0;
    virtual ole32::HRESULT __stdcall GetDevicePeriod(
        REFERENCE_TIME* phnsDefaultDevicePeriod,
        REFERENCE_TIME* phnsMinimumDevicePeriod
    ) = 0;
    virtual ole32::HRESULT __stdcall Start() = 0;
    virtual ole32::HRESULT __stdcall Stop() = 0;
    virtual ole32::HRESULT __stdcall Reset() = 0;
    virtual ole32::HRESULT __stdcall SetEventHandle(win32::HANDLE eventHandle) = 0;
    virtual ole32::HRESULT __stdcall GetService(ole32::REFIID riid, void** ppv) = 0;
};

struct AudioClientProperties {
    uint32_t cbSize{sizeof(AudioClientProperties)};
    int32_t  bIsOffload{0};
    uint32_t eCategory{0};
    uint32_t Options{0};
};

class IAudioClient2 : public IAudioClient {
public:
    virtual ole32::HRESULT __stdcall IsOffloadCapable(uint32_t Category, int32_t* pbOfOffloadCapable) = 0;
    virtual ole32::HRESULT __stdcall SetClientProperties(const AudioClientProperties* pProperties) = 0;
    virtual ole32::HRESULT __stdcall GetBufferSizeLimits(
        const audio::WAVEFORMATEX* pFormat,
        int32_t bEventDriven,
        REFERENCE_TIME* phnsMinBufferDuration,
        REFERENCE_TIME* phnsMaxBufferDuration
    ) = 0;
};

class IAudioClient3 : public IAudioClient2 {
public:
    virtual ole32::HRESULT __stdcall GetSharedModeEnginePeriod(
        const audio::WAVEFORMATEX* pFormat,
        uint32_t* pDefaultPeriodInFrames,
        uint32_t* pFundamentalPeriodInFrames,
        uint32_t* pMinPeriodInFrames,
        uint32_t* pMaxPeriodInFrames
    ) = 0;
    virtual ole32::HRESULT __stdcall GetCurrentSharedModeEnginePeriod(
        audio::WAVEFORMATEX** ppFormat,
        uint32_t* pCurrentPeriodInFrames
    ) = 0;
    virtual ole32::HRESULT __stdcall InitializeSharedAudioStream(
        uint32_t StreamFlags,
        uint32_t PeriodInFrames,
        const audio::WAVEFORMATEX* pFormat,
        const GUID* AudioSessionGuid
    ) = 0;
};

class IAudioRenderClient : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall GetBuffer(uint32_t NumFramesRequested, uint8_t** ppData) = 0;
    virtual ole32::HRESULT __stdcall ReleaseBuffer(uint32_t NumFramesWritten, uint32_t dwFlags) = 0;
};

class IAudioCaptureClient : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall GetBuffer(
        uint8_t** ppData,
        uint32_t* pNumFramesToRead,
        uint32_t* pdwFlags,
        uint64_t* pu64DevicePosition,
        uint64_t* pu64QPCPosition
    ) = 0;
    virtual ole32::HRESULT __stdcall ReleaseBuffer(uint32_t NumFramesRead) = 0;
    virtual ole32::HRESULT __stdcall GetNextPacketSize(uint32_t* pNumFramesInNextPacket) = 0;
};

class IAudioClock : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall GetFrequency(uint64_t* pu64Frequency) = 0;
    virtual ole32::HRESULT __stdcall GetPosition(uint64_t* pu64Position, uint64_t* pu64QPCPosition) = 0;
    virtual ole32::HRESULT __stdcall GetCharacteristics(uint32_t* pdwCharacteristics) = 0;
};

class ISimpleAudioVolume : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall SetMasterVolume(float fLevel, const GUID* EventContext) = 0;
    virtual ole32::HRESULT __stdcall GetMasterVolume(float* pfLevel) = 0;
    virtual ole32::HRESULT __stdcall SetMute(win32::BOOL bMute, const GUID* EventContext) = 0;
    virtual ole32::HRESULT __stdcall GetMute(win32::BOOL* pbMute) = 0;
};

class IAudioEndpointVolumeCallback : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall OnNotify(void* pNotify) = 0;
};

class IAudioEndpointVolume : public ole32::IUnknown {
public:
    virtual ole32::HRESULT __stdcall RegisterControlChangeNotify(IAudioEndpointVolumeCallback* pNotify) = 0;
    virtual ole32::HRESULT __stdcall UnregisterControlChangeNotify(IAudioEndpointVolumeCallback* pNotify) = 0;
    virtual ole32::HRESULT __stdcall GetChannelCount(uint32_t* pnChannelCount) = 0;
    virtual ole32::HRESULT __stdcall SetMasterVolumeLevel(float fLevelDB, const GUID* pguidEventContext) = 0;
    virtual ole32::HRESULT __stdcall SetMasterVolumeLevelScalar(float fLevel, const GUID* pguidEventContext) = 0;
    virtual ole32::HRESULT __stdcall GetMasterVolumeLevel(float* pfLevelDB) = 0;
    virtual ole32::HRESULT __stdcall GetMasterVolumeLevelScalar(float* pfLevel) = 0;
    virtual ole32::HRESULT __stdcall SetChannelVolumeLevel(uint32_t nChannel, float fLevelDB, const GUID* pguidEventContext) = 0;
    virtual ole32::HRESULT __stdcall SetChannelVolumeLevelScalar(uint32_t nChannel, float fLevel, const GUID* pguidEventContext) = 0;
    virtual ole32::HRESULT __stdcall GetChannelVolumeLevel(uint32_t nChannel, float* pfLevelDB) = 0;
    virtual ole32::HRESULT __stdcall GetChannelVolumeLevelScalar(uint32_t nChannel, float* pfLevel) = 0;
    virtual ole32::HRESULT __stdcall SetMute(win32::BOOL bMute, const GUID* pguidEventContext) = 0;
    virtual ole32::HRESULT __stdcall GetMute(win32::BOOL* pbMute) = 0;
    virtual ole32::HRESULT __stdcall GetVolumeStepInfo(uint32_t* pnStep, uint32_t* pnStepCount) = 0;
    virtual ole32::HRESULT __stdcall VolumeStepUp(const GUID* pguidEventContext) = 0;
    virtual ole32::HRESULT __stdcall VolumeStepDown(const GUID* pguidEventContext) = 0;
    virtual ole32::HRESULT __stdcall QueryHardwareSupport(uint32_t* pdwHardwareSupportMask) = 0;
    virtual ole32::HRESULT __stdcall GetVolumeRange(float* pflVolumeMindB, float* pflVolumeMaxdB, float* pflVolumeIncrementdB) = 0;
};

// ============================================================================
// 5. Concrete Core Audio Implementation
// ============================================================================

class PropertyStoreImpl : public IPropertyStore {
private:
    std::atomic<uint32_t> m_refCount{1};
    std::map<PROPERTYKEY, PROPVARIANT> m_properties;
    mutable std::mutex m_mutex;

public:
    PropertyStoreImpl() = default;
    ~PropertyStoreImpl() override {
        for (auto& [key, val] : m_properties) {
            PropVariantClear(&val);
        }
    }

    ole32::HRESULT __stdcall QueryInterface(ole32::REFIID riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IPropertyStore) {
            *ppvObject = static_cast<IPropertyStore*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t c = m_refCount.fetch_sub(1) - 1;
        if (c == 0) delete this;
        return c;
    }

    ole32::HRESULT __stdcall GetCount(uint32_t* cProps) override {
        if (!cProps) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *cProps = static_cast<uint32_t>(m_properties.size());
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetAt(uint32_t iProp, PROPERTYKEY* pkey) override {
        if (!pkey) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (iProp >= m_properties.size()) return ole32::E_INVALIDARG;
        auto it = m_properties.begin();
        std::advance(it, iProp);
        *pkey = it->first;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetValue(const PROPERTYKEY& key, PROPVARIANT* pv) override {
        if (!pv) return ole32::E_POINTER;
        PropVariantInit(pv);
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_properties.find(key);
        if (it == m_properties.end()) {
            pv->vt = ole32::VT_EMPTY;
            return ole32::S_OK;
        }
        return PropVariantCopy(pv, &it->second);
    }

    ole32::HRESULT __stdcall SetValue(const PROPERTYKEY& key, const PROPVARIANT& propvar) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_properties.find(key);
        if (it != m_properties.end()) {
            PropVariantClear(&it->second);
        }
        PROPVARIANT copy{};
        PropVariantCopy(&copy, &propvar);
        m_properties[key] = copy;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall Commit() override {
        return ole32::S_OK;
    }
};

class AudioClientImpl : public IAudioClient3,
                        public IAudioRenderClient,
                        public IAudioCaptureClient,
                        public IAudioClock,
                        public ISimpleAudioVolume,
                        public IAudioEndpointVolume {
private:
    std::atomic<uint32_t> m_refCount{1};
    EDataFlow m_dataFlow{eRender};
    AUDCLNT_SHAREMODE m_shareMode{AUDCLNT_SHAREMODE_SHARED};
    uint32_t m_streamFlags{0};
    REFERENCE_TIME m_bufferDurationHns{1000000}; // 100ms default
    REFERENCE_TIME m_periodicityHns{100000};     // 10ms default
    audio::WAVEFORMATEX m_format{};
    bool m_isInitialized{false};
    bool m_isRunning{false};

    // Frame Buffer
    uint32_t m_bufferFrameCapacity{4800}; // e.g. 100ms at 48kHz
    uint32_t m_bytesPerFrame{4};
    std::vector<uint8_t> m_ringBuffer;
    uint32_t m_paddingFrames{0};
    uint32_t m_writeFrameIndex{0};
    uint32_t m_readFrameIndex{0};

    // Timing & Clock
    uint64_t m_samplesPlayed{0};
    uint64_t m_frequency{48000};
    win32::HANDLE m_eventHandle{nullptr};

    // Volume & Mute
    float m_masterVolume{1.0f};
    bool  m_isMuted{false};
    std::vector<float> m_channelVolumes{1.0f, 1.0f};

    mutable std::mutex m_mutex;

public:
    AudioClientImpl(EDataFlow flow) : m_dataFlow(flow) {
        m_format.wFormatTag = audio::WAVE_FORMAT_PCM;
        m_format.nChannels = 2;
        m_format.nSamplesPerSec = 48000;
        m_format.wBitsPerSample = 16;
        m_format.nBlockAlign = 4;
        m_format.nAvgBytesPerSec = 192000;
        m_format.cbSize = 0;
        m_bytesPerFrame = m_format.nBlockAlign;
    }

    ole32::HRESULT __stdcall QueryInterface(ole32::REFIID riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IAudioClient || riid == IID_IAudioClient2 || riid == IID_IAudioClient3) {
            *ppvObject = static_cast<IAudioClient3*>(this);
            AddRef();
            return ole32::S_OK;
        } else if (riid == IID_IAudioRenderClient && m_dataFlow != eCapture) {
            *ppvObject = static_cast<IAudioRenderClient*>(this);
            AddRef();
            return ole32::S_OK;
        } else if (riid == IID_IAudioCaptureClient && m_dataFlow != eRender) {
            *ppvObject = static_cast<IAudioCaptureClient*>(this);
            AddRef();
            return ole32::S_OK;
        } else if (riid == IID_IAudioClock) {
            *ppvObject = static_cast<IAudioClock*>(this);
            AddRef();
            return ole32::S_OK;
        } else if (riid == IID_ISimpleAudioVolume) {
            *ppvObject = static_cast<ISimpleAudioVolume*>(this);
            AddRef();
            return ole32::S_OK;
        } else if (riid == IID_IAudioEndpointVolume) {
            *ppvObject = static_cast<IAudioEndpointVolume*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t c = m_refCount.fetch_sub(1) - 1;
        if (c == 0) delete this;
        return c;
    }

    // ------------------------------------------------------------------------
    // IAudioClient
    // ------------------------------------------------------------------------
    ole32::HRESULT __stdcall Initialize(
        AUDCLNT_SHAREMODE ShareMode,
        uint32_t StreamFlags,
        REFERENCE_TIME hnsBufferDuration,
        REFERENCE_TIME hnsPeriodicity,
        const audio::WAVEFORMATEX* pFormat,
        const GUID* /*AudioSessionGuid*/
    ) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_isInitialized) return AUDCLNT_E_ALREADY_INITIALIZED;
        if (!pFormat) return ole32::E_POINTER;

        m_shareMode = ShareMode;
        m_streamFlags = StreamFlags;
        m_bufferDurationHns = hnsBufferDuration > 0 ? hnsBufferDuration : 1000000; // 100ms default
        m_periodicityHns = hnsPeriodicity > 0 ? hnsPeriodicity : 100000;         // 10ms default
        m_format = *pFormat;
        m_bytesPerFrame = (m_format.nChannels * m_format.wBitsPerSample) / 8;
        if (m_bytesPerFrame == 0) m_bytesPerFrame = 4;

        // Calculate frame capacity from buffer duration (hns: 100ns units -> 10,000,000 hns = 1 sec)
        m_bufferFrameCapacity = static_cast<uint32_t>((m_bufferDurationHns * m_format.nSamplesPerSec) / 10000000ULL);
        if (m_bufferFrameCapacity < 480) m_bufferFrameCapacity = 480;

        m_ringBuffer.resize(static_cast<size_t>(m_bufferFrameCapacity) * m_bytesPerFrame, 0);
        m_paddingFrames = 0;
        m_writeFrameIndex = 0;
        m_readFrameIndex = 0;
        m_frequency = m_format.nSamplesPerSec;
        m_samplesPlayed = 0;

        m_channelVolumes.assign(m_format.nChannels, 1.0f);
        m_isInitialized = true;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetBufferSize(uint32_t* pNumBufferFrames) override {
        if (!pNumBufferFrames) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;
        *pNumBufferFrames = m_bufferFrameCapacity;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetStreamLatency(REFERENCE_TIME* phnsLatency) override {
        if (!phnsLatency) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;
        // Hardware + engine latency: typically 10ms (100,000 hns)
        *phnsLatency = m_periodicityHns > 0 ? m_periodicityHns : 100000;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetCurrentPadding(uint32_t* pNumPaddingFrames) override {
        if (!pNumPaddingFrames) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;
        *pNumPaddingFrames = m_paddingFrames;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall IsFormatSupported(
        AUDCLNT_SHAREMODE /*ShareMode*/,
        const audio::WAVEFORMATEX* pFormat,
        audio::WAVEFORMATEX** ppClosestMatch
    ) override {
        if (!pFormat) return ole32::E_POINTER;
        if (pFormat->wFormatTag == audio::WAVE_FORMAT_PCM || pFormat->wFormatTag == audio::WAVE_FORMAT_IEEE_FLOAT) {
            if (pFormat->nChannels >= 1 && pFormat->nChannels <= 8 &&
                pFormat->nSamplesPerSec >= 8000 && pFormat->nSamplesPerSec <= 192000) {
                return ole32::S_OK;
            }
        }
        if (ppClosestMatch) {
            auto* match = static_cast<audio::WAVEFORMATEX*>(ole32::CoTaskMemAlloc(sizeof(audio::WAVEFORMATEX)));
            if (match) {
                *match = m_format;
                *ppClosestMatch = match;
            }
            return ole32::S_FALSE;
        }
        return AUDCLNT_E_UNSUPPORTED_FORMAT;
    }

    ole32::HRESULT __stdcall GetMixFormat(audio::WAVEFORMATEX** ppDeviceFormat) override {
        if (!ppDeviceFormat) return ole32::E_POINTER;
        auto* fmt = static_cast<audio::WAVEFORMATEX*>(ole32::CoTaskMemAlloc(sizeof(audio::WAVEFORMATEX)));
        if (!fmt) return ole32::E_OUTOFMEMORY;
        fmt->wFormatTag = audio::WAVE_FORMAT_PCM;
        fmt->nChannels = 2;
        fmt->nSamplesPerSec = 48000;
        fmt->wBitsPerSample = 16;
        fmt->nBlockAlign = 4;
        fmt->nAvgBytesPerSec = 192000;
        fmt->cbSize = 0;
        *ppDeviceFormat = fmt;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetDevicePeriod(
        REFERENCE_TIME* phnsDefaultDevicePeriod,
        REFERENCE_TIME* phnsMinimumDevicePeriod
    ) override {
        if (!phnsDefaultDevicePeriod && !phnsMinimumDevicePeriod) return ole32::E_POINTER;
        if (phnsDefaultDevicePeriod) *phnsDefaultDevicePeriod = 100000; // 10ms
        if (phnsMinimumDevicePeriod) *phnsMinimumDevicePeriod = 30000;  // 3ms
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall Start() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;
        m_isRunning = true;
        if (m_eventHandle && (m_streamFlags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK)) {
            kernel32::SetEvent(m_eventHandle);
        }
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall Stop() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;
        m_isRunning = false;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall Reset() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;
        if (m_isRunning) return AUDCLNT_E_NOT_STOPPED;
        m_paddingFrames = 0;
        m_writeFrameIndex = 0;
        m_readFrameIndex = 0;
        std::fill(m_ringBuffer.begin(), m_ringBuffer.end(), 0);
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall SetEventHandle(win32::HANDLE eventHandle) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;
        if (!(m_streamFlags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK)) return AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED;
        m_eventHandle = eventHandle;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetService(ole32::REFIID riid, void** ppv) override {
        return QueryInterface(riid, ppv);
    }

    // ------------------------------------------------------------------------
    // IAudioClient2
    // ------------------------------------------------------------------------
    ole32::HRESULT __stdcall IsOffloadCapable(uint32_t /*Category*/, int32_t* pbOfOffloadCapable) override {
        if (!pbOfOffloadCapable) return ole32::E_POINTER;
        *pbOfOffloadCapable = 1;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall SetClientProperties(const AudioClientProperties* /*pProperties*/) override {
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetBufferSizeLimits(
        const audio::WAVEFORMATEX* /*pFormat*/,
        int32_t /*bEventDriven*/,
        REFERENCE_TIME* phnsMinBufferDuration,
        REFERENCE_TIME* phnsMaxBufferDuration
    ) override {
        if (phnsMinBufferDuration) *phnsMinBufferDuration = 30000;   // 3ms
        if (phnsMaxBufferDuration) *phnsMaxBufferDuration = 20000000;// 2 seconds
        return ole32::S_OK;
    }

    // ------------------------------------------------------------------------
    // IAudioClient3
    // ------------------------------------------------------------------------
    ole32::HRESULT __stdcall GetSharedModeEnginePeriod(
        const audio::WAVEFORMATEX* /*pFormat*/,
        uint32_t* pDefaultPeriodInFrames,
        uint32_t* pFundamentalPeriodInFrames,
        uint32_t* pMinPeriodInFrames,
        uint32_t* pMaxPeriodInFrames
    ) override {
        if (pDefaultPeriodInFrames) *pDefaultPeriodInFrames = 480;       // 10ms at 48kHz
        if (pFundamentalPeriodInFrames) *pFundamentalPeriodInFrames = 48;// 1ms
        if (pMinPeriodInFrames) *pMinPeriodInFrames = 144;              // 3ms
        if (pMaxPeriodInFrames) *pMaxPeriodInFrames = 4800;             // 100ms
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetCurrentSharedModeEnginePeriod(
        audio::WAVEFORMATEX** ppFormat,
        uint32_t* pCurrentPeriodInFrames
    ) override {
        if (pCurrentPeriodInFrames) *pCurrentPeriodInFrames = 480;
        if (ppFormat) return GetMixFormat(ppFormat);
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall InitializeSharedAudioStream(
        uint32_t StreamFlags,
        uint32_t PeriodInFrames,
        const audio::WAVEFORMATEX* pFormat,
        const GUID* AudioSessionGuid
    ) override {
        REFERENCE_TIME dur = static_cast<REFERENCE_TIME>(PeriodInFrames * 10000000ULL / (pFormat ? pFormat->nSamplesPerSec : 48000));
        return Initialize(AUDCLNT_SHAREMODE_SHARED, StreamFlags, dur * 4, dur, pFormat, AudioSessionGuid);
    }

    // ------------------------------------------------------------------------
    // IAudioRenderClient
    // ------------------------------------------------------------------------
    ole32::HRESULT __stdcall GetBuffer(uint32_t NumFramesRequested, uint8_t** ppData) override {
        if (!ppData) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;
        if (NumFramesRequested > (m_bufferFrameCapacity - m_paddingFrames)) {
            return AUDCLNT_E_BUFFER_TOO_LARGE;
        }

        size_t byteOffset = static_cast<size_t>(m_writeFrameIndex) * m_bytesPerFrame;
        if (byteOffset + (static_cast<size_t>(NumFramesRequested) * m_bytesPerFrame) > m_ringBuffer.size()) {
            // Wrap around ring buffer
            m_writeFrameIndex = 0;
            byteOffset = 0;
        }

        *ppData = m_ringBuffer.data() + byteOffset;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall ReleaseBuffer(uint32_t NumFramesWritten, uint32_t dwFlags) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;
        if (NumFramesWritten > (m_bufferFrameCapacity - m_paddingFrames)) {
            return AUDCLNT_E_INVALID_SIZE;
        }

        if (dwFlags & AUDCLNT_BUFFERFLAGS_SILENT) {
            size_t byteOffset = static_cast<size_t>(m_writeFrameIndex) * m_bytesPerFrame;
            size_t byteLen = static_cast<size_t>(NumFramesWritten) * m_bytesPerFrame;
            if (byteOffset + byteLen <= m_ringBuffer.size()) {
                std::memset(m_ringBuffer.data() + byteOffset, 0, byteLen);
            }
        }

        m_paddingFrames += NumFramesWritten;
        m_writeFrameIndex = (m_writeFrameIndex + NumFramesWritten) % m_bufferFrameCapacity;
        m_samplesPlayed += NumFramesWritten;

        // If event-driven, notify client for next buffer
        if (m_eventHandle && (m_streamFlags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK)) {
            kernel32::SetEvent(m_eventHandle);
        }
        return ole32::S_OK;
    }

    // ------------------------------------------------------------------------
    // IAudioCaptureClient
    // ------------------------------------------------------------------------
    ole32::HRESULT __stdcall GetBuffer(
        uint8_t** ppData,
        uint32_t* pNumFramesToRead,
        uint32_t* pdwFlags,
        uint64_t* pu64DevicePosition,
        uint64_t* pu64QPCPosition
    ) override {
        if (!ppData || !pNumFramesToRead || !pdwFlags) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;

        if (m_paddingFrames == 0) {
            *ppData = nullptr;
            *pNumFramesToRead = 0;
            *pdwFlags = AUDCLNT_BUFFERFLAGS_SILENT;
            return AUDCLNT_S_BUFFER_EMPTY;
        }

        *pNumFramesToRead = std::min(m_paddingFrames, uint32_t(480));
        size_t byteOffset = static_cast<size_t>(m_readFrameIndex) * m_bytesPerFrame;
        *ppData = m_ringBuffer.data() + byteOffset;
        *pdwFlags = 0;
        if (pu64DevicePosition) *pu64DevicePosition = m_samplesPlayed;
        if (pu64QPCPosition) *pu64QPCPosition = kernel32::GetTickCount64() * 10000ULL;

        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall ReleaseBuffer(uint32_t NumFramesRead) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return AUDCLNT_E_NOT_INITIALIZED;
        if (NumFramesRead > m_paddingFrames) return AUDCLNT_E_INVALID_SIZE;

        m_paddingFrames -= NumFramesRead;
        m_readFrameIndex = (m_readFrameIndex + NumFramesRead) % m_bufferFrameCapacity;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetNextPacketSize(uint32_t* pNumFramesInNextPacket) override {
        if (!pNumFramesInNextPacket) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pNumFramesInNextPacket = std::min(m_paddingFrames, uint32_t(480));
        return ole32::S_OK;
    }

    // ------------------------------------------------------------------------
    // IAudioClock
    // ------------------------------------------------------------------------
    ole32::HRESULT __stdcall GetFrequency(uint64_t* pu64Frequency) override {
        if (!pu64Frequency) return ole32::E_POINTER;
        *pu64Frequency = m_frequency;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetPosition(uint64_t* pu64Position, uint64_t* pu64QPCPosition) override {
        if (!pu64Position) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pu64Position = m_samplesPlayed;
        if (pu64QPCPosition) *pu64QPCPosition = kernel32::GetTickCount64() * 10000ULL;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetCharacteristics(uint32_t* pdwCharacteristics) override {
        if (!pdwCharacteristics) return ole32::E_POINTER;
        *pdwCharacteristics = 0x1; // AUDIOCLOCK_CHARACTERISTIC_FIXED_FREQ
        return ole32::S_OK;
    }

    // ------------------------------------------------------------------------
    // ISimpleAudioVolume
    // ------------------------------------------------------------------------
    ole32::HRESULT __stdcall SetMasterVolume(float fLevel, const GUID* /*EventContext*/) override {
        if (fLevel < 0.0f || fLevel > 1.0f) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_masterVolume = fLevel;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetMasterVolume(float* pfLevel) override {
        if (!pfLevel) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pfLevel = m_masterVolume;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall SetMute(win32::BOOL bMute, const GUID* /*EventContext*/) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_isMuted = (bMute != 0);
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetMute(win32::BOOL* pbMute) override {
        if (!pbMute) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbMute = m_isMuted ? 1 : 0;
        return ole32::S_OK;
    }

    // ------------------------------------------------------------------------
    // IAudioEndpointVolume
    // ------------------------------------------------------------------------
    ole32::HRESULT __stdcall RegisterControlChangeNotify(IAudioEndpointVolumeCallback* /*pNotify*/) override {
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall UnregisterControlChangeNotify(IAudioEndpointVolumeCallback* /*pNotify*/) override {
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetChannelCount(uint32_t* pnChannelCount) override {
        if (!pnChannelCount) return ole32::E_POINTER;
        *pnChannelCount = static_cast<uint32_t>(m_channelVolumes.size());
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall SetMasterVolumeLevel(float fLevelDB, const GUID* pguidEventContext) override {
        // dB [-96.0f .. 0.0f] to scalar [0.0 .. 1.0]
        float scalar = std::clamp(std::pow(10.0f, fLevelDB / 20.0f), 0.0f, 1.0f);
        return SetMasterVolume(scalar, pguidEventContext);
    }

    ole32::HRESULT __stdcall SetMasterVolumeLevelScalar(float fLevel, const GUID* pguidEventContext) override {
        return SetMasterVolume(fLevel, pguidEventContext);
    }

    ole32::HRESULT __stdcall GetMasterVolumeLevel(float* pfLevelDB) override {
        if (!pfLevelDB) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_masterVolume <= 0.00001f) {
            *pfLevelDB = -96.0f;
        } else {
            *pfLevelDB = 20.0f * std::log10(m_masterVolume);
        }
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetMasterVolumeLevelScalar(float* pfLevel) override {
        return GetMasterVolume(pfLevel);
    }

    ole32::HRESULT __stdcall SetChannelVolumeLevel(uint32_t nChannel, float fLevelDB, const GUID* pguidEventContext) override {
        float scalar = std::clamp(std::pow(10.0f, fLevelDB / 20.0f), 0.0f, 1.0f);
        return SetChannelVolumeLevelScalar(nChannel, scalar, pguidEventContext);
    }

    ole32::HRESULT __stdcall SetChannelVolumeLevelScalar(uint32_t nChannel, float fLevel, const GUID* /*pguidEventContext*/) override {
        if (fLevel < 0.0f || fLevel > 1.0f) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (nChannel >= m_channelVolumes.size()) return ole32::E_INVALIDARG;
        m_channelVolumes[nChannel] = fLevel;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetChannelVolumeLevel(uint32_t nChannel, float* pfLevelDB) override {
        if (!pfLevelDB) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (nChannel >= m_channelVolumes.size()) return ole32::E_INVALIDARG;
        float v = m_channelVolumes[nChannel];
        *pfLevelDB = (v <= 0.00001f) ? -96.0f : (20.0f * std::log10(v));
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetChannelVolumeLevelScalar(uint32_t nChannel, float* pfLevel) override {
        if (!pfLevel) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (nChannel >= m_channelVolumes.size()) return ole32::E_INVALIDARG;
        *pfLevel = m_channelVolumes[nChannel];
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetVolumeStepInfo(uint32_t* pnStep, uint32_t* pnStepCount) override {
        if (!pnStep || !pnStepCount) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pnStepCount = 100;
        *pnStep = static_cast<uint32_t>(m_masterVolume * 100.0f);
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall VolumeStepUp(const GUID* pguidEventContext) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_masterVolume = std::min(1.0f, m_masterVolume + 0.01f);
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall VolumeStepDown(const GUID* pguidEventContext) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_masterVolume = std::max(0.0f, m_masterVolume - 0.01f);
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall QueryHardwareSupport(uint32_t* pdwHardwareSupportMask) override {
        if (!pdwHardwareSupportMask) return ole32::E_POINTER;
        *pdwHardwareSupportMask = 0x7; // Volume, Mute, Meter
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetVolumeRange(float* pflVolumeMindB, float* pflVolumeMaxdB, float* pflVolumeIncrementdB) override {
        if (pflVolumeMindB) *pflVolumeMindB = -96.0f;
        if (pflVolumeMaxdB) *pflVolumeMaxdB = 0.0f;
        if (pflVolumeIncrementdB) *pflVolumeIncrementdB = 0.5f;
        return ole32::S_OK;
    }
};

class MMDeviceImpl : public IMMDevice, public IMMEndpoint {
private:
    std::atomic<uint32_t> m_refCount{1};
    std::wstring m_id;
    std::wstring m_friendlyName;
    EndpointFormFactor m_formFactor;
    EDataFlow m_dataFlow;
    uint32_t m_state{DEVICE_STATE_ACTIVE};
    std::shared_ptr<PropertyStoreImpl> m_propertyStore;

public:
    MMDeviceImpl(
        std::wstring id,
        std::wstring friendlyName,
        EndpointFormFactor formFactor,
        EDataFlow dataFlow,
        uint32_t state = DEVICE_STATE_ACTIVE
    ) : m_id(std::move(id)),
        m_friendlyName(std::move(friendlyName)),
        m_formFactor(formFactor),
        m_dataFlow(dataFlow),
        m_state(state),
        m_propertyStore(std::make_shared<PropertyStoreImpl>())
    {
        // Populate standard endpoint properties
        PROPVARIANT pvFriendly{};
        pvFriendly.vt = ole32::VT_LPWSTR;
        pvFriendly.pwszVal = static_cast<wchar_t*>(ole32::CoTaskMemAlloc((m_friendlyName.size() + 1) * sizeof(wchar_t)));
        if (pvFriendly.pwszVal) {
            std::wcscpy(pvFriendly.pwszVal, m_friendlyName.c_str());
            m_propertyStore->SetValue(PKEY_Device_FriendlyName, pvFriendly);
            PropVariantClear(&pvFriendly);
        }

        PROPVARIANT pvForm{};
        pvForm.vt = ole32::VT_UI4;
        pvForm.ulVal = static_cast<uint32_t>(m_formFactor);
        m_propertyStore->SetValue(PKEY_AudioEndpoint_FormFactor, pvForm);
    }

    ole32::HRESULT __stdcall QueryInterface(ole32::REFIID riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMMDevice) {
            *ppvObject = static_cast<IMMDevice*>(this);
            AddRef();
            return ole32::S_OK;
        } else if (riid == IID_IMMEndpoint) {
            *ppvObject = static_cast<IMMEndpoint*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t c = m_refCount.fetch_sub(1) - 1;
        if (c == 0) delete this;
        return c;
    }

    // IMMDevice
    ole32::HRESULT __stdcall Activate(
        ole32::REFIID iid,
        uint32_t /*dwClsCtx*/,
        PROPVARIANT* /*pActivationParams*/,
        void** ppInterface
    ) override {
        if (!ppInterface) return ole32::E_POINTER;
        *ppInterface = nullptr;

        if (iid == IID_IAudioClient || iid == IID_IAudioClient2 || iid == IID_IAudioClient3 ||
            iid == IID_IAudioEndpointVolume || iid == IID_ISimpleAudioVolume) {
            auto* client = new AudioClientImpl(m_dataFlow);
            return client->QueryInterface(iid, ppInterface);
        }
        return ole32::E_NOINTERFACE;
    }

    ole32::HRESULT __stdcall OpenPropertyStore(uint32_t /*stgmAccess*/, IPropertyStore** ppProperties) override {
        if (!ppProperties) return ole32::E_POINTER;
        m_propertyStore->AddRef();
        *ppProperties = m_propertyStore.get();
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetId(wchar_t** ppstrId) override {
        if (!ppstrId) return ole32::E_POINTER;
        size_t len = m_id.size();
        auto* str = static_cast<wchar_t*>(ole32::CoTaskMemAlloc((len + 1) * sizeof(wchar_t)));
        if (!str) return ole32::E_OUTOFMEMORY;
        std::wcscpy(str, m_id.c_str());
        *ppstrId = str;
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall GetState(uint32_t* pdwState) override {
        if (!pdwState) return ole32::E_POINTER;
        *pdwState = m_state;
        return ole32::S_OK;
    }

    // IMMEndpoint
    ole32::HRESULT __stdcall GetDataFlow(EDataFlow* pDataFlow) override {
        if (!pDataFlow) return ole32::E_POINTER;
        *pDataFlow = m_dataFlow;
        return ole32::S_OK;
    }

    [[nodiscard]] const std::wstring& getId() const noexcept { return m_id; }
    [[nodiscard]] const std::wstring& getFriendlyName() const noexcept { return m_friendlyName; }
    [[nodiscard]] EndpointFormFactor getFormFactor() const noexcept { return m_formFactor; }
    [[nodiscard]] EDataFlow getDataFlow() const noexcept { return m_dataFlow; }
    void setState(uint32_t state) noexcept { m_state = state; }
};

class MMDeviceCollectionImpl : public IMMDeviceCollection {
private:
    std::atomic<uint32_t> m_refCount{1};
    std::vector<IMMDevice*> m_devices;

public:
    MMDeviceCollectionImpl(std::vector<IMMDevice*> devices)
        : m_devices(std::move(devices)) {
        for (auto* d : m_devices) {
            d->AddRef();
        }
    }

    ~MMDeviceCollectionImpl() override {
        for (auto* d : m_devices) {
            d->Release();
        }
    }

    ole32::HRESULT __stdcall QueryInterface(ole32::REFIID riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMMDeviceCollection) {
            *ppvObject = static_cast<IMMDeviceCollection*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t c = m_refCount.fetch_sub(1) - 1;
        if (c == 0) delete this;
        return c;
    }

    ole32::HRESULT __stdcall GetCount(uint32_t* pcDevices) override {
        if (!pcDevices) return ole32::E_POINTER;
        *pcDevices = static_cast<uint32_t>(m_devices.size());
        return ole32::S_OK;
    }

    ole32::HRESULT __stdcall Item(uint32_t nDevice, IMMDevice** ppDevice) override {
        if (!ppDevice) return ole32::E_POINTER;
        if (nDevice >= m_devices.size()) return ole32::E_INVALIDARG;
        m_devices[nDevice]->AddRef();
        *ppDevice = m_devices[nDevice];
        return ole32::S_OK;
    }
};

// ============================================================================
// 6. Windows Audio Service & Enumerator Engine (audiosrv.dll)
// ============================================================================

class WindowsAudioService {
private:
    std::vector<std::shared_ptr<MMDeviceImpl>> m_devices;
    std::wstring m_defaultRenderConsole;
    std::wstring m_defaultRenderMultimedia;
    std::wstring m_defaultRenderCommunications;
    std::wstring m_defaultCaptureConsole;
    std::wstring m_defaultCaptureMultimedia;
    std::wstring m_defaultCaptureCommunications;

    std::vector<IMMNotificationClient*> m_notificationClients;
    std::atomic<bool> m_serviceRunning{true};
    mutable std::mutex m_mutex;

    WindowsAudioService() {
        initializeEndpoints();
    }

public:
    static WindowsAudioService& get() {
        static WindowsAudioService s_instance;
        return s_instance;
    }

    void initializeEndpoints() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_devices.clear();

        // 1. Default Render Endpoint: Speakers (Mica High Definition Audio)
        auto devSpeakers = std::make_shared<MMDeviceImpl>(
            L"{0.0.0.00000000}.{387532A1-0C02-4D78-9B21-000000000001}",
            L"Speakers (Mica High Definition Audio)",
            Speakers,
            eRender,
            DEVICE_STATE_ACTIVE
        );
        m_devices.push_back(devSpeakers);
        m_defaultRenderConsole = devSpeakers->getId();
        m_defaultRenderMultimedia = devSpeakers->getId();

        // 2. Headphone Render Endpoint: Headphones (Mica Front Panel Audio)
        auto devHeadphones = std::make_shared<MMDeviceImpl>(
            L"{0.0.0.00000000}.{387532A1-0C02-4D78-9B21-000000000002}",
            L"Headphones (Mica Front Audio)",
            Headphones,
            eRender,
            DEVICE_STATE_ACTIVE
        );
        m_devices.push_back(devHeadphones);
        m_defaultRenderCommunications = devHeadphones->getId();

        // 3. Capture Endpoint: Microphone (Mica HD Audio Array)
        auto devMic = std::make_shared<MMDeviceImpl>(
            L"{0.0.1.00000000}.{387532A1-0C02-4D78-9B21-000000000003}",
            L"Microphone (Mica HD Audio Array)",
            Microphone,
            eCapture,
            DEVICE_STATE_ACTIVE
        );
        m_devices.push_back(devMic);
        m_defaultCaptureConsole = devMic->getId();
        m_defaultCaptureMultimedia = devMic->getId();
        m_defaultCaptureCommunications = devMic->getId();
    }

    ole32::HRESULT enumAudioEndpoints(EDataFlow dataFlow, uint32_t dwStateMask, IMMDeviceCollection** ppDevices) {
        if (!ppDevices) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<IMMDevice*> matching;
        for (const auto& dev : m_devices) {
            uint32_t state = 0;
            dev->GetState(&state);
            if ((state & dwStateMask) == 0) continue;

            if (dataFlow == eAll || dev->getDataFlow() == dataFlow) {
                matching.push_back(dev.get());
            }
        }

        *ppDevices = new MMDeviceCollectionImpl(std::move(matching));
        return ole32::S_OK;
    }

    ole32::HRESULT getDefaultAudioEndpoint(EDataFlow dataFlow, ERole role, IMMDevice** ppEndpoint) {
        if (!ppEndpoint) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring targetId;
        if (dataFlow == eRender) {
            if (role == eCommunications) targetId = m_defaultRenderCommunications;
            else targetId = m_defaultRenderConsole;
        } else if (dataFlow == eCapture) {
            targetId = m_defaultCaptureConsole;
        } else {
            return ole32::E_INVALIDARG;
        }

        for (const auto& dev : m_devices) {
            if (dev->getId() == targetId) {
                dev->AddRef();
                *ppEndpoint = dev.get();
                return ole32::S_OK;
            }
        }

        return AUDCLNT_E_DEVICE_INVALIDATED;
    }

    ole32::HRESULT getDevice(const wchar_t* pwstrId, IMMDevice** ppDevice) {
        if (!pwstrId || !ppDevice) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring query(pwstrId);
        for (const auto& dev : m_devices) {
            if (dev->getId() == query) {
                dev->AddRef();
                *ppDevice = dev.get();
                return ole32::S_OK;
            }
        }
        return AUDCLNT_E_DEVICE_INVALIDATED;
    }

    ole32::HRESULT registerNotificationClient(IMMNotificationClient* pClient) {
        if (!pClient) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        pClient->AddRef();
        m_notificationClients.push_back(pClient);
        return ole32::S_OK;
    }

    ole32::HRESULT unregisterNotificationClient(IMMNotificationClient* pClient) {
        if (!pClient) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find(m_notificationClients.begin(), m_notificationClients.end(), pClient);
        if (it != m_notificationClients.end()) {
            (*it)->Release();
            m_notificationClients.erase(it);
            return ole32::S_OK;
        }
        return ole32::E_FAIL;
    }

    [[nodiscard]] size_t getEndpointCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_devices.size();
    }

    [[nodiscard]] std::vector<std::shared_ptr<MMDeviceImpl>> getEndpoints() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_devices;
    }

    [[nodiscard]] bool isRunning() const noexcept {
        return m_serviceRunning.load();
    }
};

class MMDeviceEnumeratorImpl : public IMMDeviceEnumerator {
private:
    std::atomic<uint32_t> m_refCount{1};

public:
    MMDeviceEnumeratorImpl() = default;

    ole32::HRESULT __stdcall QueryInterface(ole32::REFIID riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMMDeviceEnumerator) {
            *ppvObject = static_cast<IMMDeviceEnumerator*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t c = m_refCount.fetch_sub(1) - 1;
        if (c == 0) delete this;
        return c;
    }

    ole32::HRESULT __stdcall EnumAudioEndpoints(EDataFlow dataFlow, uint32_t dwStateMask, IMMDeviceCollection** ppDevices) override {
        return WindowsAudioService::get().enumAudioEndpoints(dataFlow, dwStateMask, ppDevices);
    }

    ole32::HRESULT __stdcall GetDefaultAudioEndpoint(EDataFlow dataFlow, ERole role, IMMDevice** ppEndpoint) override {
        return WindowsAudioService::get().getDefaultAudioEndpoint(dataFlow, role, ppEndpoint);
    }

    ole32::HRESULT __stdcall GetDevice(const wchar_t* pwstrId, IMMDevice** ppDevice) override {
        return WindowsAudioService::get().getDevice(pwstrId, ppDevice);
    }

    ole32::HRESULT __stdcall RegisterEndpointNotificationCallback(IMMNotificationClient* pClient) override {
        return WindowsAudioService::get().registerNotificationClient(pClient);
    }

    ole32::HRESULT __stdcall UnregisterEndpointNotificationCallback(IMMNotificationClient* pClient) override {
        return WindowsAudioService::get().unregisterNotificationClient(pClient);
    }
};

class MMDeviceEnumeratorFactory : public ole32::IClassFactory {
private:
    std::atomic<uint32_t> m_refCount{1};

public:
    MMDeviceEnumeratorFactory() = default;

    ole32::HRESULT __stdcall QueryInterface(ole32::REFIID riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == ole32::IID_IClassFactory) {
            *ppvObject = static_cast<ole32::IClassFactory*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t c = m_refCount.fetch_sub(1) - 1;
        if (c == 0) delete this;
        return c;
    }

    ole32::HRESULT __stdcall CreateInstance(ole32::IUnknown* pUnkOuter, ole32::REFIID riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (pUnkOuter) return ole32::CLASS_E_NOAGGREGATION;
        auto* enumerator = new MMDeviceEnumeratorImpl();
        ole32::HRESULT hr = enumerator->QueryInterface(riid, ppvObject);
        enumerator->Release();
        return hr;
    }

    ole32::HRESULT __stdcall LockServer(win32::BOOL) override {
        return ole32::S_OK;
    }
};

// ============================================================================
// 7. Dynamic Exports & Subsystem Initialization
// ============================================================================

inline ole32::HRESULT __stdcall DllGetClassObject(ole32::REFCLSID rclsid, ole32::REFIID riid, void** ppv) {
    if (!ppv) return ole32::E_POINTER;
    *ppv = nullptr;
    if (rclsid == CLSID_MMDeviceEnumerator) {
        auto* factory = new MMDeviceEnumeratorFactory();
        ole32::HRESULT hr = factory->QueryInterface(riid, ppv);
        factory->Release();
        return hr;
    }
    return ole32::CLASS_E_CLASSNOTAVAILABLE;
}

inline ole32::HRESULT __stdcall DllCanUnloadNow() {
    return ole32::S_FALSE;
}

inline ole32::HRESULT __stdcall DllRegisterServer() {
    return ole32::S_OK;
}

inline ole32::HRESULT __stdcall DllUnregisterServer() {
    return ole32::S_OK;
}

inline void InitializeWASAPISubsystem() {
    auto& ldr = ldr::DynamicLoader::get();

    // Register mmdevapi.dll exports
    ldr.registerExport("mmdevapi.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));
    ldr.registerExport("mmdevapi.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("mmdevapi.dll", "DllRegisterServer", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("mmdevapi.dll", "DllUnregisterServer", reinterpret_cast<void*>(DllUnregisterServer));

    // Register audiosrv.dll exports
    ldr.registerExport("audiosrv.dll", "ServiceMain", reinterpret_cast<void*>(DllRegisterServer));

    // Register COM Class Factory for CLSID_MMDeviceEnumerator in ole32 runtime
    static MMDeviceEnumeratorFactory s_factory;
    uint32_t cookie = 0;
    (void)ole32::CoRegisterClassObject(
        CLSID_MMDeviceEnumerator,
        &s_factory,
        ole32::CLSCTX_INPROC_SERVER,
        ole32::REGCLS_MULTIPLEUSE,
        &cookie
    );

    // Register Windows Audio Service in Service Control Manager (SCM)
    auto& scm = scm::ServiceControlManager::get();
    if (!scm.getServiceRecord(L"AudioSrv")) {
        auto audioSrv = std::make_shared<scm::ServiceRecord>();
        audioSrv->serviceName = L"AudioSrv";
        audioSrv->displayName = L"Windows Audio";
        audioSrv->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        audioSrv->startType = scm::SERVICE_AUTO_START;
        audioSrv->svchostGroup = "LocalServiceNetworkRestricted";
        audioSrv->binaryPath = L"C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted";
        audioSrv->serviceStartName = L"NT AUTHORITY\\LocalService";
        audioSrv->status.dwServiceType = audioSrv->serviceType;
        audioSrv->status.dwCurrentState = scm::SERVICE_RUNNING;
        audioSrv->status.dwProcessId = scm::SvcHostManager::get().getOrCreateGroupProcess("LocalServiceNetworkRestricted");
        scm::SvcHostManager::get().assignService("LocalServiceNetworkRestricted", audioSrv->serviceName);
        scm.registerServiceRecord(audioSrv);
    }
}

} // namespace micant::wasapi
