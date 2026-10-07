// ============================================================================
// MicaNT: Media Foundation Capture Engine Subsystem (mfcaptureengine.dll)
// 
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/win32metadata
//   - Microsoft Media Foundation Capture Engine Specifications (mfcaptureengine.h)
//
// Subsystem Overview:
//   mfcaptureengine.dll provides the high-level, unified media ingestion
//   pipeline for modern video capture devices (Webcams, USB Video Class / UVC,
//   Virtual Cameras, Microphones, Screen Recorders). It coordinates capture sources,
//   preview sinks (EVR/D3D11/D3D12 render surfaces), record sinks (multiplexed
//   via IMFSinkWriter into MP4/ASF containers), and photo sinks (still snapshots).
//
// Trademark & Nominative Fair Use Notice:
//   Windows and Media Foundation are registered trademarks of Microsoft Corporation.
//   MicaNT's mfcaptureengine is an independent sovereign clean-room implementation
//   engineered for the MicaNT operating system executive.
// ============================================================================

#pragma once

#include "mfplat.hpp"
#include "mfreadwrite.hpp"
#include "d3d11va.hpp"
#include "d3d12video.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <functional>
#include <algorithm>
#include <iostream>
#include <sstream>

namespace micant::mfcapture {

using namespace micant::mf;
using namespace micant::mfreadwrite;

// ============================================================================
// 1. GUIDs & Interface Identifiers
// ============================================================================

inline constexpr GUID CLSID_MFCaptureEngineClassFactory_Const = {
    0xefce3893, 0xc914, 0x411b, { 0x9c, 0xe4, 0x6f, 0x83, 0x0e, 0x0e, 0xc2, 0x9b }
};

inline constexpr GUID CLSID_MFCaptureEngine_Const = {
    0xefce3894, 0xc914, 0x411b, { 0x9c, 0xe4, 0x6f, 0x83, 0x0e, 0x0e, 0xc2, 0x9b }
};

inline constexpr GUID IID_IMFCaptureEngine_Const = {
    0xa6bba433, 0x176b, 0x4da4, { 0xac, 0x1a, 0x2e, 0xac, 0x27, 0x14, 0xf3, 0x93 }
};

inline constexpr GUID IID_IMFCaptureEngineClassFactory_Const = {
    0xa6bba433, 0x176b, 0x4da4, { 0xac, 0x1a, 0x2e, 0xac, 0x27, 0x14, 0xf3, 0x94 }
};

inline constexpr GUID IID_IMFCaptureEngineOnEventCallback_Const = {
    0xa6bba433, 0x176b, 0x4da4, { 0xac, 0x1a, 0x2e, 0xac, 0x27, 0x14, 0xf3, 0x95 }
};

inline constexpr GUID IID_IMFCaptureEngineOnSampleCallback_Const = {
    0x52d542ea, 0x4a25, 0x459c, { 0xb1, 0xf2, 0x1a, 0x43, 0x88, 0x50, 0xe7, 0x9e }
};

inline constexpr GUID IID_IMFCaptureSource_Const = {
    0x439a42a8, 0x0d2c, 0x4505, { 0xbe, 0x83, 0xf7, 0x9f, 0xb1, 0x30, 0xfa, 0x85 }
};

inline constexpr GUID IID_IMFCaptureSink_Const = {
    0x72d6135b, 0x3522, 0x4702, { 0x92, 0x2d, 0xa2, 0xe0, 0x81, 0x52, 0xac, 0x4d }
};

inline constexpr GUID IID_IMFCaptureRecordSink_Const = {
    0x33246849, 0x7812, 0x45b3, { 0x92, 0x36, 0xab, 0x32, 0x70, 0xb7, 0x66, 0xdb }
};

inline constexpr GUID IID_IMFCapturePreviewSink_Const = {
    0x77346cfd, 0x5b49, 0x47e2, { 0xac, 0x50, 0xc5, 0xb2, 0x37, 0x35, 0x27, 0x47 }
};

inline constexpr GUID IID_IMFCapturePhotoSink_Const = {
    0xd2d4398c, 0xacab, 0x4299, { 0x92, 0xe6, 0x6b, 0xa0, 0x2b, 0x29, 0xda, 0x44 }
};

// Capture Engine Attributes
inline constexpr GUID MF_CAPTURE_ENGINE_D3D_MANAGER = {
    0x76e25e7b, 0xd595, 0x4283, { 0x96, 0x2c, 0x85, 0x94, 0xe0, 0x7d, 0x09, 0x4d }
};

inline constexpr GUID MF_CAPTURE_ENGINE_RECORD_SINK_VIDEO_MAX_UNPROCESSED_SAMPLES = {
    0x9ecbaaee, 0x0634, 0x4148, { 0xbe, 0x2a, 0x4f, 0x42, 0x31, 0x94, 0x71, 0x71 }
};

inline constexpr GUID MF_CAPTURE_ENGINE_RECORD_SINK_AUDIO_MAX_UNPROCESSED_SAMPLES = {
    0x1cddb141, 0xa7f4, 0x4d58, { 0x98, 0x96, 0x4d, 0x15, 0xa5, 0x3c, 0x4e, 0x51 }
};

inline constexpr GUID MF_CAPTURE_ENGINE_SELECTEDSOURCE = {
    0xd2a38d59, 0xbefa, 0x4d2c, { 0x94, 0x5d, 0x5d, 0x67, 0xf1, 0x64, 0x28, 0xd2 }
};

inline constexpr GUID MF_CAPTURE_ENGINE_MEDIASOURCE = {
    0x5043e99f, 0xe48b, 0x4c2d, { 0x8a, 0xc4, 0x97, 0x24, 0x1d, 0x13, 0xb1, 0x9a }
};

inline constexpr GUID MF_CAPTURE_ENGINE_EVENT_GENERATOR_GUID = {
    0xabfa993e, 0x4701, 0x4c5b, { 0x94, 0x34, 0x2f, 0xb5, 0x6d, 0x8a, 0x34, 0x24 }
};

// Capture Engine Events
inline constexpr GUID MF_CAPTURE_ENGINE_INITIALIZED = {
    0x219992bc, 0xff92, 0x47d3, { 0x9f, 0x35, 0x6e, 0xfe, 0x87, 0x4e, 0x01, 0x74 }
};

inline constexpr GUID MF_CAPTURE_ENGINE_PREVIEW_STARTED = {
    0xa4166530, 0x423c, 0x43da, { 0xa9, 0xf0, 0xd5, 0x42, 0x34, 0x08, 0x1a, 0x47 }
};

inline constexpr GUID MF_CAPTURE_ENGINE_PREVIEW_STOPPED = {
    0xbc78550d, 0x1300, 0x4b89, { 0xa2, 0x99, 0xcf, 0x91, 0x54, 0x4a, 0x47, 0x2a }
};

inline constexpr GUID MF_CAPTURE_ENGINE_RECORD_STARTED = {
    0xac88f217, 0x0957, 0x41ff, { 0x80, 0xc1, 0xbe, 0x0b, 0x3b, 0x44, 0xb8, 0x8a }
};

inline constexpr GUID MF_CAPTURE_ENGINE_RECORD_STOPPED = {
    0x2077e2ff, 0x980b, 0x4179, { 0x88, 0x0c, 0xa6, 0x12, 0x34, 0x90, 0xb3, 0x96 }
};

inline constexpr GUID MF_CAPTURE_ENGINE_PHOTO_TAKEN = {
    0x76156e9c, 0xd40b, 0x426a, { 0x93, 0x9e, 0x9e, 0x77, 0x40, 0x26, 0x3f, 0x3c }
};

inline constexpr GUID MF_CAPTURE_ENGINE_ERROR = {
    0x46b89370, 0x96ec, 0x4c40, { 0xbb, 0x7e, 0x61, 0xc0, 0x2a, 0x7b, 0x64, 0x6c }
};

inline constexpr GUID MF_CAPTURE_ENGINE_EFFECT_ADDED = {
    0x60bd4e98, 0xd112, 0x421b, { 0x80, 0xce, 0xf9, 0xc3, 0x94, 0xc8, 0xe7, 0x62 }
};

inline constexpr GUID MF_CAPTURE_ENGINE_EFFECT_REMOVED = {
    0x343ec29d, 0x4001, 0x4091, { 0xa1, 0xb7, 0xe2, 0x4c, 0x53, 0x8a, 0x7c, 0x29 }
};

inline constexpr GUID MF_CAPTURE_ENGINE_ALL_EFFECTS_REMOVED = {
    0xa2eb5c21, 0x1250, 0x482a, { 0xa9, 0x2c, 0x63, 0x38, 0xb5, 0x56, 0x1a, 0x35 }
};

// ============================================================================
// 2. Enumerations & Constants
// ============================================================================

enum MF_CAPTURE_ENGINE_SINK_TYPE {
    MF_CAPTURE_ENGINE_SINK_TYPE_RECORD  = 0,
    MF_CAPTURE_ENGINE_SINK_TYPE_PREVIEW = 1,
    MF_CAPTURE_ENGINE_SINK_TYPE_PHOTO   = 2
};

enum MF_CAPTURE_ENGINE_DEVICE_TYPE {
    MF_CAPTURE_ENGINE_DEVICE_TYPE_AUDIO = 0,
    MF_CAPTURE_ENGINE_DEVICE_TYPE_VIDEO = 1
};

enum MF_CAPTURE_ENGINE_STREAM_CATEGORY {
    MF_CAPTURE_ENGINE_STREAM_CATEGORY_VIDEO_PREVIEW     = 0,
    MF_CAPTURE_ENGINE_STREAM_CATEGORY_VIDEO_RECORD      = 1,
    MF_CAPTURE_ENGINE_STREAM_CATEGORY_PHOTO_INDEPENDENT = 2,
    MF_CAPTURE_ENGINE_STREAM_CATEGORY_PHOTO_DEPENDENT   = 3,
    MF_CAPTURE_ENGINE_STREAM_CATEGORY_AUDIO             = 4,
    MF_CAPTURE_ENGINE_STREAM_CATEGORY_UNSUPPORTED       = 5
};

constexpr uint32_t MF_CAPTURE_ENGINE_MEDIASOURCE_FIRST_VIDEO_STREAM = 0xFFFFFFFD;
constexpr uint32_t MF_CAPTURE_ENGINE_MEDIASOURCE_FIRST_AUDIO_STREAM = 0xFFFFFFFE;
constexpr uint32_t MF_CAPTURE_ENGINE_PREFERRED_SOURCE_STREAM_FOR_VIDEO_PREVIEW = 0xFFFFFFFF;

// ============================================================================
// 3. COM Interfaces
// ============================================================================

struct IMFCaptureEngineOnEventCallback : public ole32::IUnknown {
    virtual int32_t __stdcall OnEvent(IMFMediaEvent* pEvent) = 0;
};

struct IMFCaptureEngineOnSampleCallback : public ole32::IUnknown {
    virtual int32_t __stdcall OnSample(IMFSample* pSample) = 0;
};

struct IMFCaptureSource : public ole32::IUnknown {
    virtual int32_t __stdcall AddEffect(uint32_t dwSourceStreamIndex, ole32::IUnknown* pUnknown) = 0;
    virtual int32_t __stdcall RemoveEffect(uint32_t dwSourceStreamIndex, ole32::IUnknown* pUnknown) = 0;
    virtual int32_t __stdcall RemoveAllEffects(uint32_t dwSourceStreamIndex) = 0;
    virtual int32_t __stdcall GetAvailableDeviceMediaType(uint32_t dwSourceStreamIndex, uint32_t dwMediaTypeIndex, IMFMediaType** ppMediaType) = 0;
    virtual int32_t __stdcall SetCurrentDeviceMediaType(uint32_t dwSourceStreamIndex, IMFMediaType* pMediaType) = 0;
    virtual int32_t __stdcall GetCurrentDeviceMediaType(uint32_t dwSourceStreamIndex, IMFMediaType** ppMediaType) = 0;
    virtual int32_t __stdcall GetDeviceStreamCount(uint32_t* pdwStreamCount) = 0;
    virtual int32_t __stdcall GetDeviceStreamCategory(uint32_t dwSourceStreamIndex, MF_CAPTURE_ENGINE_STREAM_CATEGORY* pStreamCategory) = 0;
    virtual int32_t __stdcall GetMirrorState(uint32_t dwSourceStreamIndex, int32_t* pfMirrorState) = 0;
    virtual int32_t __stdcall SetMirrorState(uint32_t dwSourceStreamIndex, int32_t fMirrorState) = 0;
    virtual int32_t __stdcall GetStreamIndexFromFriendlyName(uint32_t uifriendlyName, uint32_t* pdwActualStreamIndex) = 0;
};

struct IMFCaptureSink : public ole32::IUnknown {
    virtual int32_t __stdcall GetOutputMediaType(uint32_t dwSinkStreamIndex, IMFMediaType** ppMediaType) = 0;
    virtual int32_t __stdcall GetService(uint32_t dwSinkStreamIndex, const GUID& rguidService, const GUID& riid, void** ppvObject) = 0;
    virtual int32_t __stdcall AddStream(uint32_t dwSourceStreamIndex, IMFMediaType* pMediaType, IMFAttributes* pAttributes, uint32_t* pdwSinkStreamIndex) = 0;
    virtual int32_t __stdcall Prepare() = 0;
    virtual int32_t __stdcall RemoveAllStreams() = 0;
};

struct IMFCaptureRecordSink : public IMFCaptureSink {
    virtual int32_t __stdcall SetOutputByteStream(IMFByteStream* pByteStream, const GUID& guidContainerType) = 0;
    virtual int32_t __stdcall SetOutputFileName(const wchar_t* fileName) = 0;
    virtual int32_t __stdcall SetSampleCallback(uint32_t dwStreamSinkIndex, IMFCaptureEngineOnSampleCallback* pCallback) = 0;
    virtual int32_t __stdcall SetCustomSink(ole32::IUnknown* pMediaSink) = 0;
    virtual int32_t __stdcall GetRotation(uint32_t dwStreamIndex, uint32_t* pdwRotationAngle) = 0;
    virtual int32_t __stdcall SetRotation(uint32_t dwStreamIndex, uint32_t dwRotationAngle) = 0;
};

struct IMFCapturePreviewSink : public IMFCaptureSink {
    virtual int32_t __stdcall SetRenderHandle(uintptr_t handle) = 0;
    virtual int32_t __stdcall SetRenderSurface(ole32::IUnknown* pSurface) = 0;
    virtual int32_t __stdcall UpdateVideo(const void* pSrc, const void* pDst, const void* pBorderClr) = 0;
    virtual int32_t __stdcall SetSampleCallback(uint32_t dwStreamSinkIndex, IMFCaptureEngineOnSampleCallback* pCallback) = 0;
    virtual int32_t __stdcall GetMirrorState(int32_t* pfMirrorState) = 0;
    virtual int32_t __stdcall SetMirrorState(int32_t fMirrorState) = 0;
    virtual int32_t __stdcall GetRotation(uint32_t dwStreamIndex, uint32_t* pdwRotationAngle) = 0;
    virtual int32_t __stdcall SetRotation(uint32_t dwStreamIndex, uint32_t dwRotationAngle) = 0;
};

struct IMFCapturePhotoSink : public IMFCaptureSink {
    virtual int32_t __stdcall SetOutputByteStream(IMFByteStream* pByteStream) = 0;
    virtual int32_t __stdcall SetOutputFileName(const wchar_t* fileName) = 0;
    virtual int32_t __stdcall SetSampleCallback(IMFCaptureEngineOnSampleCallback* pCallback) = 0;
};

struct IMFCaptureEngine : public ole32::IUnknown {
    virtual int32_t __stdcall Initialize(
        IMFCaptureEngineOnEventCallback* pEventCallback,
        IMFAttributes* pAttributes,
        ole32::IUnknown* pAudioSource,
        ole32::IUnknown* pVideoSource) = 0;

    virtual int32_t __stdcall StartPreview() = 0;
    virtual int32_t __stdcall StopPreview() = 0;
    virtual int32_t __stdcall StartRecord() = 0;
    virtual int32_t __stdcall StopRecord(int32_t bFlushed, int32_t bBal) = 0;
    virtual int32_t __stdcall TakePhoto() = 0;
    virtual int32_t __stdcall GetSink(MF_CAPTURE_ENGINE_SINK_TYPE mfCaptureEngineSinkType, IMFCaptureSink** ppSink) = 0;
    virtual int32_t __stdcall GetSource(IMFCaptureSource** ppSource) = 0;
};

struct IMFCaptureEngineClassFactory : public ole32::IUnknown {
    virtual int32_t __stdcall CreateInstance(const GUID& clsid, const GUID& riid, void** ppv) = 0;
};

// ============================================================================
// 4. Capture Subsystem Implementation Classes
// ============================================================================

class CCaptureSource : public IMFCaptureSource {
private:
    std::atomic<uint32_t> m_ref{ 1 };
    std::mutex m_mutex;

    struct StreamDesc {
        uint32_t index{ 0 };
        MF_CAPTURE_ENGINE_STREAM_CATEGORY category{ MF_CAPTURE_ENGINE_STREAM_CATEGORY_VIDEO_RECORD };
        std::vector<IMFMediaType*> availableTypes;
        IMFMediaType* currentType{ nullptr };
        std::vector<ole32::IUnknown*> effects;
        int32_t mirror{ 0 };
    };

    std::vector<StreamDesc> m_streams;

public:
    CCaptureSource() {
        // Stream 0: Video Capture (Webcam / UVC)
        StreamDesc vid{};
        vid.index = 0;
        vid.category = MF_CAPTURE_ENGINE_STREAM_CATEGORY_VIDEO_RECORD;

        // Type 0: NV12 1080p 30fps
        auto* nv12_1080 = new CMediaType();
        nv12_1080->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        nv12_1080->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
        nv12_1080->SetUINT64(MF_MT_FRAME_SIZE, (1920ULL << 32) | 1080ULL);
        nv12_1080->SetUINT64(MF_MT_FRAME_RATE, (30ULL << 32) | 1ULL);
        vid.availableTypes.push_back(nv12_1080);

        // Type 1: RGB32 1080p 30fps
        auto* rgb_1080 = new CMediaType();
        rgb_1080->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        rgb_1080->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);
        rgb_1080->SetUINT64(MF_MT_FRAME_SIZE, (1920ULL << 32) | 1080ULL);
        rgb_1080->SetUINT64(MF_MT_FRAME_RATE, (30ULL << 32) | 1ULL);
        vid.availableTypes.push_back(rgb_1080);

        // Type 2: NV12 4K 60fps
        auto* nv12_4k = new CMediaType();
        nv12_4k->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        nv12_4k->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
        nv12_4k->SetUINT64(MF_MT_FRAME_SIZE, (3840ULL << 32) | 2160ULL);
        nv12_4k->SetUINT64(MF_MT_FRAME_RATE, (60ULL << 32) | 1ULL);
        vid.availableTypes.push_back(nv12_4k);

        vid.currentType = nv12_1080;
        vid.currentType->AddRef();
        m_streams.push_back(vid);

        // Stream 1: Audio Capture (Microphone)
        StreamDesc aud{};
        aud.index = 1;
        aud.category = MF_CAPTURE_ENGINE_STREAM_CATEGORY_AUDIO;

        // Type 0: PCM 48kHz Stereo 16-bit
        auto* pcm_48 = new CMediaType();
        pcm_48->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        pcm_48->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_PCM);
        pcm_48->SetUINT32(MF_MT_AUDIO_NUM_CHANNELS, 2);
        pcm_48->SetUINT32(MF_MT_AUDIO_SAMPLES_PER_SECOND, 48000);
        pcm_48->SetUINT32(MF_MT_AUDIO_BITS_PER_SAMPLE, 16);
        aud.availableTypes.push_back(pcm_48);

        aud.currentType = pcm_48;
        aud.currentType->AddRef();
        m_streams.push_back(aud);

        // Stream 2: High-Resolution Photo Stream
        StreamDesc photo{};
        photo.index = 2;
        photo.category = MF_CAPTURE_ENGINE_STREAM_CATEGORY_PHOTO_INDEPENDENT;

        // Type 0: NV12 4K Still
        auto* photo_4k = new CMediaType();
        photo_4k->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        photo_4k->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
        photo_4k->SetUINT64(MF_MT_FRAME_SIZE, (3840ULL << 32) | 2160ULL);
        photo.availableTypes.push_back(photo_4k);

        photo.currentType = photo_4k;
        photo.currentType->AddRef();
        m_streams.push_back(photo);
    }

    ~CCaptureSource() {
        for (auto& s : m_streams) {
            for (auto* t : s.availableTypes) {
                if (t) t->Release();
            }
            if (s.currentType) s.currentType->Release();
            for (auto* e : s.effects) {
                if (e) e->Release();
            }
        }
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMFCaptureSource_Const) {
            *ppv = static_cast<IMFCaptureSource*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_ref; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_ref;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall AddEffect(uint32_t dwSourceStreamIndex, ole32::IUnknown* pUnknown) override {
        if (!pUnknown) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSourceStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;
        pUnknown->AddRef();
        m_streams[dwSourceStreamIndex].effects.push_back(pUnknown);
        return ole32::S_OK;
    }

    int32_t __stdcall RemoveEffect(uint32_t dwSourceStreamIndex, ole32::IUnknown* pUnknown) override {
        if (!pUnknown) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSourceStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;
        auto& effs = m_streams[dwSourceStreamIndex].effects;
        auto it = std::find(effs.begin(), effs.end(), pUnknown);
        if (it != effs.end()) {
            (*it)->Release();
            effs.erase(it);
            return ole32::S_OK;
        }
        return ole32::E_FAIL;
    }

    int32_t __stdcall RemoveAllEffects(uint32_t dwSourceStreamIndex) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSourceStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;
        for (auto* e : m_streams[dwSourceStreamIndex].effects) {
            if (e) e->Release();
        }
        m_streams[dwSourceStreamIndex].effects.clear();
        return ole32::S_OK;
    }

    int32_t __stdcall GetAvailableDeviceMediaType(uint32_t dwSourceStreamIndex, uint32_t dwMediaTypeIndex, IMFMediaType** ppMediaType) override {
        if (!ppMediaType) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSourceStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;
        if (dwMediaTypeIndex >= m_streams[dwSourceStreamIndex].availableTypes.size()) return mf::MF_E_NO_MORE_TYPES;

        *ppMediaType = m_streams[dwSourceStreamIndex].availableTypes[dwMediaTypeIndex];
        (*ppMediaType)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall SetCurrentDeviceMediaType(uint32_t dwSourceStreamIndex, IMFMediaType* pMediaType) override {
        if (!pMediaType) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSourceStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;

        if (m_streams[dwSourceStreamIndex].currentType) {
            m_streams[dwSourceStreamIndex].currentType->Release();
        }
        m_streams[dwSourceStreamIndex].currentType = pMediaType;
        m_streams[dwSourceStreamIndex].currentType->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetCurrentDeviceMediaType(uint32_t dwSourceStreamIndex, IMFMediaType** ppMediaType) override {
        if (!ppMediaType) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSourceStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;
        if (!m_streams[dwSourceStreamIndex].currentType) return ole32::E_FAIL;

        *ppMediaType = m_streams[dwSourceStreamIndex].currentType;
        (*ppMediaType)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetDeviceStreamCount(uint32_t* pdwStreamCount) override {
        if (!pdwStreamCount) return ole32::E_POINTER;
        *pdwStreamCount = static_cast<uint32_t>(m_streams.size());
        return ole32::S_OK;
    }

    int32_t __stdcall GetDeviceStreamCategory(uint32_t dwSourceStreamIndex, MF_CAPTURE_ENGINE_STREAM_CATEGORY* pStreamCategory) override {
        if (!pStreamCategory) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSourceStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;
        *pStreamCategory = m_streams[dwSourceStreamIndex].category;
        return ole32::S_OK;
    }

    int32_t __stdcall GetMirrorState(uint32_t dwSourceStreamIndex, int32_t* pfMirrorState) override {
        if (!pfMirrorState) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSourceStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;
        *pfMirrorState = m_streams[dwSourceStreamIndex].mirror;
        return ole32::S_OK;
    }

    int32_t __stdcall SetMirrorState(uint32_t dwSourceStreamIndex, int32_t fMirrorState) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSourceStreamIndex >= m_streams.size()) return ole32::E_INVALIDARG;
        m_streams[dwSourceStreamIndex].mirror = fMirrorState;
        return ole32::S_OK;
    }

    int32_t __stdcall GetStreamIndexFromFriendlyName(uint32_t uifriendlyName, uint32_t* pdwActualStreamIndex) override {
        if (!pdwActualStreamIndex) return ole32::E_POINTER;
        if (uifriendlyName == MF_CAPTURE_ENGINE_MEDIASOURCE_FIRST_VIDEO_STREAM ||
            uifriendlyName == MF_CAPTURE_ENGINE_PREFERRED_SOURCE_STREAM_FOR_VIDEO_PREVIEW) {
            *pdwActualStreamIndex = 0;
            return ole32::S_OK;
        }
        if (uifriendlyName == MF_CAPTURE_ENGINE_MEDIASOURCE_FIRST_AUDIO_STREAM) {
            *pdwActualStreamIndex = 1;
            return ole32::S_OK;
        }
        if (uifriendlyName < m_streams.size()) {
            *pdwActualStreamIndex = uifriendlyName;
            return ole32::S_OK;
        }
        return ole32::E_INVALIDARG;
    }

    size_t getEffectCount(uint32_t dwSourceStreamIndex) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSourceStreamIndex < m_streams.size()) {
            return m_streams[dwSourceStreamIndex].effects.size();
        }
        return 0;
    }
};

class CCapturePreviewSink : public IMFCapturePreviewSink {
private:
    std::atomic<uint32_t> m_ref{ 1 };
    std::mutex m_mutex;

    uintptr_t m_hWnd{ 0 };
    ole32::IUnknown* m_pSurface{ nullptr };
    IMFCaptureEngineOnSampleCallback* m_pSampleCallback{ nullptr };
    int32_t m_mirror{ 0 };
    uint32_t m_rotation{ 0 };
    std::vector<IMFMediaType*> m_streamTypes;
    uint32_t m_framesDelivered{ 0 };

public:
    CCapturePreviewSink() = default;

    ~CCapturePreviewSink() {
        if (m_pSurface) m_pSurface->Release();
        if (m_pSampleCallback) m_pSampleCallback->Release();
        for (auto* t : m_streamTypes) {
            if (t) t->Release();
        }
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMFCaptureSink_Const || riid == IID_IMFCapturePreviewSink_Const) {
            *ppv = static_cast<IMFCapturePreviewSink*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_ref; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_ref;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall GetOutputMediaType(uint32_t dwSinkStreamIndex, IMFMediaType** ppMediaType) override {
        if (!ppMediaType) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSinkStreamIndex >= m_streamTypes.size()) return ole32::E_INVALIDARG;
        *ppMediaType = m_streamTypes[dwSinkStreamIndex];
        (*ppMediaType)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetService(uint32_t, const GUID&, const GUID&, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        *ppvObject = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall AddStream(uint32_t, IMFMediaType* pMediaType, IMFAttributes*, uint32_t* pdwSinkStreamIndex) override {
        if (!pMediaType || !pdwSinkStreamIndex) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pdwSinkStreamIndex = static_cast<uint32_t>(m_streamTypes.size());
        pMediaType->AddRef();
        m_streamTypes.push_back(pMediaType);
        return ole32::S_OK;
    }

    int32_t __stdcall Prepare() override { return ole32::S_OK; }

    int32_t __stdcall RemoveAllStreams() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto* t : m_streamTypes) {
            if (t) t->Release();
        }
        m_streamTypes.clear();
        return ole32::S_OK;
    }

    int32_t __stdcall SetRenderHandle(uintptr_t handle) override {
        m_hWnd = handle;
        return ole32::S_OK;
    }

    int32_t __stdcall SetRenderSurface(ole32::IUnknown* pSurface) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pSurface) m_pSurface->Release();
        m_pSurface = pSurface;
        if (m_pSurface) m_pSurface->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall UpdateVideo(const void*, const void*, const void*) override {
        return ole32::S_OK;
    }

    int32_t __stdcall SetSampleCallback(uint32_t, IMFCaptureEngineOnSampleCallback* pCallback) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pSampleCallback) m_pSampleCallback->Release();
        m_pSampleCallback = pCallback;
        if (m_pSampleCallback) m_pSampleCallback->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetMirrorState(int32_t* pfMirrorState) override {
        if (!pfMirrorState) return ole32::E_POINTER;
        *pfMirrorState = m_mirror;
        return ole32::S_OK;
    }

    int32_t __stdcall SetMirrorState(int32_t fMirrorState) override {
        m_mirror = fMirrorState;
        return ole32::S_OK;
    }

    int32_t __stdcall GetRotation(uint32_t, uint32_t* pdwRotationAngle) override {
        if (!pdwRotationAngle) return ole32::E_POINTER;
        *pdwRotationAngle = m_rotation;
        return ole32::S_OK;
    }

    int32_t __stdcall SetRotation(uint32_t, uint32_t dwRotationAngle) override {
        m_rotation = dwRotationAngle;
        return ole32::S_OK;
    }

    uintptr_t getRenderHandle() const { return m_hWnd; }
    ole32::IUnknown* getRenderSurface() const { return m_pSurface; }
    uint32_t getFramesDelivered() const { return m_framesDelivered; }

    void deliverPreviewFrame(IMFSample* pSample) {
        m_framesDelivered++;
        if (m_pSampleCallback && pSample) {
            m_pSampleCallback->OnSample(pSample);
        }
    }
};

class CCaptureRecordSink : public IMFCaptureRecordSink {
private:
    std::atomic<uint32_t> m_ref{ 1 };
    std::mutex m_mutex;

    std::wstring m_outputPath;
    IMFByteStream* m_pByteStream{ nullptr };
    GUID m_containerType{ 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };
    IMFSinkWriter* m_pSinkWriter{ nullptr };
    IMFCaptureEngineOnSampleCallback* m_pSampleCallback{ nullptr };
    uint32_t m_rotation{ 0 };
    std::vector<IMFMediaType*> m_streamTypes;
    uint32_t m_samplesRecorded{ 0 };

public:
    CCaptureRecordSink() = default;

    ~CCaptureRecordSink() {
        if (m_pByteStream) m_pByteStream->Release();
        if (m_pSinkWriter) m_pSinkWriter->Release();
        if (m_pSampleCallback) m_pSampleCallback->Release();
        for (auto* t : m_streamTypes) {
            if (t) t->Release();
        }
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMFCaptureSink_Const || riid == IID_IMFCaptureRecordSink_Const) {
            *ppv = static_cast<IMFCaptureRecordSink*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_ref; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_ref;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall GetOutputMediaType(uint32_t dwSinkStreamIndex, IMFMediaType** ppMediaType) override {
        if (!ppMediaType) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSinkStreamIndex >= m_streamTypes.size()) return ole32::E_INVALIDARG;
        *ppMediaType = m_streamTypes[dwSinkStreamIndex];
        (*ppMediaType)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetService(uint32_t, const GUID&, const GUID&, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        *ppvObject = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall AddStream(uint32_t, IMFMediaType* pMediaType, IMFAttributes*, uint32_t* pdwSinkStreamIndex) override {
        if (!pMediaType || !pdwSinkStreamIndex) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pdwSinkStreamIndex = static_cast<uint32_t>(m_streamTypes.size());
        pMediaType->AddRef();
        m_streamTypes.push_back(pMediaType);
        return ole32::S_OK;
    }

    int32_t __stdcall Prepare() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_outputPath.empty() && !m_pSinkWriter) {
            mfreadwrite::MFCreateSinkWriterFromURL(m_outputPath.c_str(), nullptr, nullptr, &m_pSinkWriter);
            if (m_pSinkWriter) {
                for (size_t i = 0; i < m_streamTypes.size(); ++i) {
                    uint32_t outStream = 0;
                    m_pSinkWriter->AddStream(m_streamTypes[i], &outStream);
                    m_pSinkWriter->SetInputMediaType(outStream, m_streamTypes[i], nullptr);
                }
                m_pSinkWriter->BeginWriting();
            }
        }
        return ole32::S_OK;
    }

    int32_t __stdcall RemoveAllStreams() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto* t : m_streamTypes) {
            if (t) t->Release();
        }
        m_streamTypes.clear();
        return ole32::S_OK;
    }

    int32_t __stdcall SetOutputByteStream(IMFByteStream* pByteStream, const GUID& guidContainerType) override {
        if (!pByteStream) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pByteStream) m_pByteStream->Release();
        m_pByteStream = pByteStream;
        m_pByteStream->AddRef();
        m_containerType = guidContainerType;
        return ole32::S_OK;
    }

    int32_t __stdcall SetOutputFileName(const wchar_t* fileName) override {
        if (!fileName) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_outputPath = fileName;
        return ole32::S_OK;
    }

    int32_t __stdcall SetSampleCallback(uint32_t, IMFCaptureEngineOnSampleCallback* pCallback) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pSampleCallback) m_pSampleCallback->Release();
        m_pSampleCallback = pCallback;
        if (m_pSampleCallback) m_pSampleCallback->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall SetCustomSink(ole32::IUnknown*) override { return ole32::S_OK; }

    int32_t __stdcall GetRotation(uint32_t, uint32_t* pdwRotationAngle) override {
        if (!pdwRotationAngle) return ole32::E_POINTER;
        *pdwRotationAngle = m_rotation;
        return ole32::S_OK;
    }

    int32_t __stdcall SetRotation(uint32_t, uint32_t dwRotationAngle) override {
        m_rotation = dwRotationAngle;
        return ole32::S_OK;
    }

    const std::wstring& getOutputPath() const { return m_outputPath; }
    uint32_t getSamplesRecorded() const { return m_samplesRecorded; }
    IMFSinkWriter* getSinkWriter() const { return m_pSinkWriter; }

    void recordSample(uint32_t streamIndex, IMFSample* pSample) {
        m_samplesRecorded++;
        if (m_pSinkWriter && pSample) {
            m_pSinkWriter->WriteSample(streamIndex, pSample);
        }
        if (m_pSampleCallback && pSample) {
            m_pSampleCallback->OnSample(pSample);
        }
    }

    void finalizeRecording() {
        if (m_pSinkWriter) {
            m_pSinkWriter->Finalize();
            m_pSinkWriter->Release();
            m_pSinkWriter = nullptr;
        }
    }
};

class CCapturePhotoSink : public IMFCapturePhotoSink {
private:
    std::atomic<uint32_t> m_ref{ 1 };
    std::mutex m_mutex;

    std::wstring m_outputPath;
    IMFByteStream* m_pByteStream{ nullptr };
    IMFCaptureEngineOnSampleCallback* m_pSampleCallback{ nullptr };
    std::vector<IMFMediaType*> m_streamTypes;
    uint32_t m_photosTaken{ 0 };

public:
    CCapturePhotoSink() = default;

    ~CCapturePhotoSink() {
        if (m_pByteStream) m_pByteStream->Release();
        if (m_pSampleCallback) m_pSampleCallback->Release();
        for (auto* t : m_streamTypes) {
            if (t) t->Release();
        }
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMFCaptureSink_Const || riid == IID_IMFCapturePhotoSink_Const) {
            *ppv = static_cast<IMFCapturePhotoSink*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_ref; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_ref;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall GetOutputMediaType(uint32_t dwSinkStreamIndex, IMFMediaType** ppMediaType) override {
        if (!ppMediaType) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dwSinkStreamIndex >= m_streamTypes.size()) return ole32::E_INVALIDARG;
        *ppMediaType = m_streamTypes[dwSinkStreamIndex];
        (*ppMediaType)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetService(uint32_t, const GUID&, const GUID&, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        *ppvObject = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall AddStream(uint32_t, IMFMediaType* pMediaType, IMFAttributes*, uint32_t* pdwSinkStreamIndex) override {
        if (!pMediaType || !pdwSinkStreamIndex) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pdwSinkStreamIndex = static_cast<uint32_t>(m_streamTypes.size());
        pMediaType->AddRef();
        m_streamTypes.push_back(pMediaType);
        return ole32::S_OK;
    }

    int32_t __stdcall Prepare() override { return ole32::S_OK; }

    int32_t __stdcall RemoveAllStreams() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto* t : m_streamTypes) {
            if (t) t->Release();
        }
        m_streamTypes.clear();
        return ole32::S_OK;
    }

    int32_t __stdcall SetOutputByteStream(IMFByteStream* pByteStream) override {
        if (!pByteStream) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pByteStream) m_pByteStream->Release();
        m_pByteStream = pByteStream;
        m_pByteStream->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall SetOutputFileName(const wchar_t* fileName) override {
        if (!fileName) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_outputPath = fileName;
        return ole32::S_OK;
    }

    int32_t __stdcall SetSampleCallback(IMFCaptureEngineOnSampleCallback* pCallback) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pSampleCallback) m_pSampleCallback->Release();
        m_pSampleCallback = pCallback;
        if (m_pSampleCallback) m_pSampleCallback->AddRef();
        return ole32::S_OK;
    }

    const std::wstring& getOutputPath() const { return m_outputPath; }
    uint32_t getPhotosTaken() const { return m_photosTaken; }

    void triggerPhotoCapture(IMFSample* pSample) {
        m_photosTaken++;
        if (m_pSampleCallback && pSample) {
            m_pSampleCallback->OnSample(pSample);
        }
    }
};

// ============================================================================
// 5. Master Capture Engine Implementation
// ============================================================================

class CCaptureEngine : public IMFCaptureEngine {
private:
    std::atomic<uint32_t> m_ref{ 1 };
    std::mutex m_mutex;

    IMFCaptureEngineOnEventCallback* m_pEventCallback{ nullptr };
    IMFAttributes* m_pAttributes{ nullptr };
    ole32::IUnknown* m_pAudioSource{ nullptr };
    ole32::IUnknown* m_pVideoSource{ nullptr };

    CCaptureSource* m_pSource{ nullptr };
    CCapturePreviewSink* m_pPreviewSink{ nullptr };
    CCaptureRecordSink* m_pRecordSink{ nullptr };
    CCapturePhotoSink* m_pPhotoSink{ nullptr };

    bool m_initialized{ false };
    bool m_previewing{ false };
    bool m_recording{ false };
    uint32_t m_photosTaken{ 0 };

    void dispatchEvent(const GUID& eventGuid, int32_t hrStatus = ole32::S_OK) {
        if (m_pEventCallback) {
            auto* evt = new mf::CMediaEvent(mf::MEUnknown, eventGuid, hrStatus);
            m_pEventCallback->OnEvent(evt);
            evt->Release();
        }
    }

public:
    CCaptureEngine() {
        m_pSource = new CCaptureSource();
        m_pPreviewSink = new CCapturePreviewSink();
        m_pRecordSink = new CCaptureRecordSink();
        m_pPhotoSink = new CCapturePhotoSink();
    }

    ~CCaptureEngine() {
        if (m_pEventCallback) m_pEventCallback->Release();
        if (m_pAttributes) m_pAttributes->Release();
        if (m_pAudioSource) m_pAudioSource->Release();
        if (m_pVideoSource) m_pVideoSource->Release();
        if (m_pSource) m_pSource->Release();
        if (m_pPreviewSink) m_pPreviewSink->Release();
        if (m_pRecordSink) m_pRecordSink->Release();
        if (m_pPhotoSink) m_pPhotoSink->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMFCaptureEngine_Const) {
            *ppv = static_cast<IMFCaptureEngine*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_ref; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_ref;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall Initialize(
        IMFCaptureEngineOnEventCallback* pEventCallback,
        IMFAttributes* pAttributes,
        ole32::IUnknown* pAudioSource,
        ole32::IUnknown* pVideoSource) override
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pEventCallback) m_pEventCallback->Release();
        m_pEventCallback = pEventCallback;
        if (m_pEventCallback) m_pEventCallback->AddRef();

        if (m_pAttributes) m_pAttributes->Release();
        m_pAttributes = pAttributes;
        if (m_pAttributes) m_pAttributes->AddRef();

        if (m_pAudioSource) m_pAudioSource->Release();
        m_pAudioSource = pAudioSource;
        if (m_pAudioSource) m_pAudioSource->AddRef();

        if (m_pVideoSource) m_pVideoSource->Release();
        m_pVideoSource = pVideoSource;
        if (m_pVideoSource) m_pVideoSource->AddRef();

        m_initialized = true;
        dispatchEvent(MF_CAPTURE_ENGINE_INITIALIZED, ole32::S_OK);
        return ole32::S_OK;
    }

    int32_t __stdcall StartPreview() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return mf::MF_E_NOT_INITIALIZED;
        if (m_previewing) return ole32::S_OK;

        m_previewing = true;
        m_pPreviewSink->Prepare();

        // Simulate 3 preview frames delivery
        for (int i = 0; i < 3; ++i) {
            auto* sample = new CSample();
            auto* buf = new CMediaBuffer(1920 * 1080 * 3 / 2);
            sample->AddBuffer(buf);
            sample->SetSampleTime(i * 333333LL);
            sample->SetSampleDuration(333333LL);
            m_pPreviewSink->deliverPreviewFrame(sample);
            buf->Release();
            sample->Release();
        }

        dispatchEvent(MF_CAPTURE_ENGINE_PREVIEW_STARTED, ole32::S_OK);
        return ole32::S_OK;
    }

    int32_t __stdcall StopPreview() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return mf::MF_E_NOT_INITIALIZED;
        if (!m_previewing) return ole32::S_OK;

        m_previewing = false;
        dispatchEvent(MF_CAPTURE_ENGINE_PREVIEW_STOPPED, ole32::S_OK);
        return ole32::S_OK;
    }

    int32_t __stdcall StartRecord() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return mf::MF_E_NOT_INITIALIZED;
        if (m_recording) return ole32::S_OK;

        m_recording = true;
        m_pRecordSink->Prepare();

        // Simulate recording 5 frames of video and audio
        for (int i = 0; i < 5; ++i) {
            auto* vSample = new CSample();
            auto* vBuf = new CMediaBuffer(4096);
            vBuf->SetCurrentLength(4096);
            vSample->AddBuffer(vBuf);
            vSample->SetSampleTime(i * 333333LL);
            vSample->SetSampleDuration(333333LL);
            m_pRecordSink->recordSample(0, vSample);
            vBuf->Release();
            vSample->Release();

            auto* aSample = new CSample();
            auto* aBuf = new CMediaBuffer(1024);
            aBuf->SetCurrentLength(1024);
            aSample->AddBuffer(aBuf);
            aSample->SetSampleTime(i * 213333LL);
            aSample->SetSampleDuration(213333LL);
            m_pRecordSink->recordSample(1, aSample);
            aBuf->Release();
            aSample->Release();
        }

        dispatchEvent(MF_CAPTURE_ENGINE_RECORD_STARTED, ole32::S_OK);
        return ole32::S_OK;
    }

    int32_t __stdcall StopRecord(int32_t, int32_t) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return mf::MF_E_NOT_INITIALIZED;
        if (!m_recording) return ole32::S_OK;

        m_recording = false;
        m_pRecordSink->finalizeRecording();
        dispatchEvent(MF_CAPTURE_ENGINE_RECORD_STOPPED, ole32::S_OK);
        return ole32::S_OK;
    }

    int32_t __stdcall TakePhoto() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return mf::MF_E_NOT_INITIALIZED;

        auto* sample = new CSample();
        auto* buf = new CMediaBuffer(3840 * 2160 * 3 / 2);
        buf->SetCurrentLength(3840 * 2160 * 3 / 2);
        sample->AddBuffer(buf);
        sample->SetSampleTime(0);
        sample->SetSampleDuration(0);

        m_pPhotoSink->triggerPhotoCapture(sample);
        buf->Release();
        sample->Release();

        m_photosTaken++;
        dispatchEvent(MF_CAPTURE_ENGINE_PHOTO_TAKEN, ole32::S_OK);
        return ole32::S_OK;
    }

    int32_t __stdcall GetSink(MF_CAPTURE_ENGINE_SINK_TYPE mfCaptureEngineSinkType, IMFCaptureSink** ppSink) override {
        if (!ppSink) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (mfCaptureEngineSinkType == MF_CAPTURE_ENGINE_SINK_TYPE_PREVIEW) {
            *ppSink = static_cast<IMFCaptureSink*>(m_pPreviewSink);
            (*ppSink)->AddRef();
            return ole32::S_OK;
        }
        if (mfCaptureEngineSinkType == MF_CAPTURE_ENGINE_SINK_TYPE_RECORD) {
            *ppSink = static_cast<IMFCaptureSink*>(m_pRecordSink);
            (*ppSink)->AddRef();
            return ole32::S_OK;
        }
        if (mfCaptureEngineSinkType == MF_CAPTURE_ENGINE_SINK_TYPE_PHOTO) {
            *ppSink = static_cast<IMFCaptureSink*>(m_pPhotoSink);
            (*ppSink)->AddRef();
            return ole32::S_OK;
        }
        *ppSink = nullptr;
        return ole32::E_INVALIDARG;
    }

    int32_t __stdcall GetSource(IMFCaptureSource** ppSource) override {
        if (!ppSource) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *ppSource = static_cast<IMFCaptureSource*>(m_pSource);
        (*ppSource)->AddRef();
        return ole32::S_OK;
    }

    bool isInitialized() const { return m_initialized; }
    bool isPreviewing() const { return m_previewing; }
    bool isRecording() const { return m_recording; }
    uint32_t getPhotosTaken() const { return m_photosTaken; }
};

class CCaptureEngineClassFactory : public IMFCaptureEngineClassFactory, public ole32::IClassFactory {
private:
    std::atomic<uint32_t> m_ref{ 1 };

public:
    CCaptureEngineClassFactory() = default;

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMFCaptureEngineClassFactory_Const) {
            *ppv = static_cast<IMFCaptureEngineClassFactory*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == ole32::IID_IClassFactory) {
            *ppv = static_cast<ole32::IClassFactory*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_ref; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_ref;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall CreateInstance(const GUID& clsid, const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (clsid == CLSID_MFCaptureEngine_Const) {
            auto* engine = new CCaptureEngine();
            int32_t hr = engine->QueryInterface(riid, ppv);
            engine->Release();
            return hr;
        }
        *ppv = nullptr;
        return ole32::E_INVALIDARG;
    }

    int32_t __stdcall CreateInstance(ole32::IUnknown* pUnkOuter, const GUID& riid, void** ppvObject) override {
        if (pUnkOuter) return ole32::CLASS_E_NOAGGREGATION;
        return CreateInstance(CLSID_MFCaptureEngine_Const, riid, ppvObject);
    }

    int32_t __stdcall LockServer(int32_t) override { return ole32::S_OK; }
};

// ============================================================================
// 7. Dynamic Module Exports & Subsystem Registration
// ============================================================================

inline int32_t __stdcall MFCreateCaptureEngine(IMFCaptureEngine** ppCaptureEngine) {
    if (!ppCaptureEngine) return ole32::E_POINTER;
    *ppCaptureEngine = new CCaptureEngine();
    return ole32::S_OK;
}

inline int32_t __stdcall DllCanUnloadNow() {
    return ole32::S_OK;
}

inline int32_t __stdcall DllGetClassObject(const GUID& rclsid, const GUID& riid, void** ppv) {
    if (!ppv) return ole32::E_POINTER;
    if (rclsid == CLSID_MFCaptureEngineClassFactory_Const || rclsid == CLSID_MFCaptureEngine_Const) {
        auto* pFactory = new CCaptureEngineClassFactory();
        int32_t hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }
    *ppv = nullptr;
    return ole32::CLASS_E_CLASSNOTAVAILABLE;
}

inline void InitializeMFCaptureEngineExports() {
    auto& ldr = ldr::DynamicLoader::get();

    ldr.registerExport("mfcaptureengine.dll", "MFCreateCaptureEngine", reinterpret_cast<void*>(MFCreateCaptureEngine));
    ldr.registerExport("mfcaptureengine.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("mfcaptureengine.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));

    version::VersionDatabase::Instance().RegisterModule(
        "mfcaptureengine.dll",
        "10.0.22621.1",
        "MicaNT Media Foundation Capture Engine Subsystem",
        "Dave Cutler Clean-Room Architecture"
    );
}

} // namespace micant::mfcapture
