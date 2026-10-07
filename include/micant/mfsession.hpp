#pragma once

/**
 * @file mfsession.hpp
 * @brief Clean-Room Windows Media Foundation Topology Loader & Presentation Clock Pipeline
 *        (mf.dll / wmvdecod.dll).
 *
 * Implements Microsoft Media Foundation Topology resolution (IMFTopoLoader),
 * Presentation Clock & Rate Control (IMFPresentationClock, IMFClock, IMFRateControl, IMFRateSupport),
 * Clock State Sinks (IMFClockStateSink), Sequencer Source (IMFSequencerSource), and
 * Windows Media Video/Audio decoders (CWMVDecoderMFT, CWMADecoderMFT).
 *
 * Referenced exclusively from Microsoft's MIT-licensed win32metadata / Media Foundation specifications.
 * 100% clean-room engineering. Zero proprietary, leaked, or decompiled code.
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <cmath>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ole32.hpp"
#include "ldr.hpp"
#include "mfplat.hpp"

namespace micant::mf {

// ============================================================================
// 1. Media Session Enums, Structures & GUIDs
// ============================================================================

enum MFCLOCK_STATE {
    MFCLOCK_STATE_INVALID = 0,
    MFCLOCK_STATE_RUNNING = 1,
    MFCLOCK_STATE_STOPPED = 2,
    MFCLOCK_STATE_PAUSED  = 3
};

enum MFCLOCK_CHARACTERISTICS_FLAGS {
    MFCLOCK_CHARACTERISTICS_FLAG_FREQUENCY_10MHZ = 0x00000002,
    MFCLOCK_CHARACTERISTICS_FLAG_ALWAYS_RUNNING   = 0x00000004,
    MFCLOCK_CHARACTERISTICS_FLAG_IS_SYSTEM_CLOCK  = 0x00000008
};

enum MFRATE_DIRECTION {
    MFRATE_FORWARD = 0,
    MFRATE_REVERSE = 1
};

enum MFSequencerFlags {
    MFSequencerFlag_Base    = 0,
    MFSequencerFlag_Append  = 1,
    MFSequencerFlag_PreRoll = 2
};

struct MFCLOCK_PROPERTIES {
    uint64_t qwCorrelationRate{ 0 };
    GUID     guidClockId{};
    uint32_t dwClockFlags{ 0 };
    uint64_t qwClockFrequency{ 10000000 }; // 10MHz (100-nanosecond ticks)
    uint32_t dwClockTolerance{ 1 };
    uint32_t dwClockJitter{ 0 };
};

using MFSequencerElementId = uint32_t;

inline constexpr int32_t MF_E_UNSUPPORTED_RATE = static_cast<int32_t>(0xC00D36E3L);
inline constexpr int32_t MF_E_NOT_FOUND        = static_cast<int32_t>(0xC00D36D5L);

inline constexpr GUID IID_IMFTransform =
    { 0xBFEE914F, 0x0333, 0x4F08, { 0x8C, 0xE6, 0x5F, 0x7D, 0x0E, 0x07, 0x65, 0xBC } };

// Media Subtypes: Windows Media Video & Audio
// FourCC definitions:
// WMV1 = 0x31564D57
// WMV2 = 0x32564D57
// WMV3 = 0x33564D57
// WVC1 = 0x31435657
inline constexpr GUID MFVideoFormat_WMV1 =
    { 0x31564D57, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFVideoFormat_WMV2 =
    { 0x32564D57, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFVideoFormat_WMV3 =
    { 0x33564D57, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFVideoFormat_WVC1 =
    { 0x31435657, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };

// Audio Formats: WMA
// 0x0161 = WMAudioV8
// 0x0162 = WMAudioV9
// 0x0163 = WMAudio_Lossless
inline constexpr GUID MFAudioFormat_WMAudioV8 =
    { 0x00000161, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFAudioFormat_WMAudioV9 =
    { 0x00000162, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
inline constexpr GUID MFAudioFormat_WMAudio_Lossless =
    { 0x00000163, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };

// CLSIDs
inline constexpr GUID CLSID_CWMVDecMediaObject =
    { 0x82D353DF, 0x90BD, 0x4382, { 0x8B, 0xC2, 0x3F, 0x61, 0x92, 0xB7, 0x6E, 0x34 } };
inline constexpr GUID CLSID_CWMADecMediaObject =
    { 0x2EEB4ADF, 0x4578, 0x4D10, { 0xBC, 0xA7, 0xBB, 0x95, 0x5F, 0x56, 0x32, 0x0A } };
inline constexpr GUID CLSID_MFSequencerSource =
    { 0x6BC49EE4, 0x8E25, 0x4CF7, { 0xA8, 0x34, 0x44, 0x37, 0x99, 0xD0, 0x65, 0xEB } };
inline constexpr GUID CLSID_MFPresentationClock =
    { 0x868777D9, 0xB019, 0x4089, { 0xAB, 0x97, 0x83, 0x32, 0x6E, 0x0E, 0xA6, 0xD1 } };
inline constexpr GUID CLSID_MFTopoLoader =
    { 0xDE9A6157, 0xF35D, 0x4797, { 0x9E, 0x50, 0x4F, 0x12, 0x77, 0xDB, 0x86, 0x97 } };

// IIDs
inline constexpr GUID IID_IMFClockStateSink =
    { 0xF6696E82, 0x747B, 0x4FCA, { 0xAC, 0xA5, 0x42, 0xAF, 0x23, 0x20, 0x17, 0x0F } };
inline constexpr GUID IID_IMFClock =
    { 0x2EB1E945, 0x18B8, 0x4139, { 0x9B, 0x1A, 0xF5, 0xD5, 0x84, 0x81, 0x85, 0x30 } };
inline constexpr GUID IID_IMFPresentationClock =
    { 0x868777D9, 0xB019, 0x4089, { 0xAB, 0x97, 0x83, 0x32, 0x6E, 0x0E, 0xA6, 0xD1 } };
inline constexpr GUID IID_IMFRateControl =
    { 0x88DDCD21, 0x03C3, 0x4275, { 0xAC, 0x68, 0xD5, 0xDD, 0x3C, 0x6F, 0xDF, 0x70 } };
inline constexpr GUID IID_IMFRateSupport =
    { 0x0A5CED30, 0xE91C, 0x4C29, { 0x99, 0x14, 0x02, 0x12, 0xC2, 0x1B, 0x20, 0x45 } };
inline constexpr GUID IID_IMFTopoLoader =
    { 0xDE9A6157, 0xF35D, 0x4797, { 0x9E, 0x50, 0x4F, 0x12, 0x77, 0xDB, 0x86, 0x97 } };
inline constexpr GUID IID_IMFSequencerSource =
    { 0x19703470, 0x1031, 0x4293, { 0x8D, 0x8A, 0xAC, 0x29, 0x7A, 0x34, 0x11, 0xCE } };

// ============================================================================
// 2. Interfaces
// ============================================================================

struct IMFClockStateSink : public ole32::IUnknown {
    virtual int32_t __stdcall OnClockStart(MFTIME hnsSystemTime, LONGLONG llClockStartOffset) = 0;
    virtual int32_t __stdcall OnClockStop(MFTIME hnsSystemTime) = 0;
    virtual int32_t __stdcall OnClockPause(MFTIME hnsSystemTime) = 0;
    virtual int32_t __stdcall OnClockRestart(MFTIME hnsSystemTime) = 0;
    virtual int32_t __stdcall OnClockSetRate(MFTIME hnsSystemTime, float flRate) = 0;
};

struct IMFClock : public ole32::IUnknown {
    virtual int32_t __stdcall GetClockCharacteristics(uint32_t* pdwCharacteristics) = 0;
    virtual int32_t __stdcall GetCorrelatedTime(uint32_t dwReserved, LONGLONG* pllClockTime, MFTIME* phnsSystemTime) = 0;
    virtual int32_t __stdcall GetContinuityKey(uint32_t* pdwContinuityKey) = 0;
    virtual int32_t __stdcall GetState(uint32_t dwReserved, MFCLOCK_STATE* peClockState) = 0;
    virtual int32_t __stdcall GetProperties(MFCLOCK_PROPERTIES* pClockProperties) = 0;
};

struct IMFPresentationClock : public IMFClock {
    virtual int32_t __stdcall SetTimeSource(IMFClock* pClock) = 0;
    virtual int32_t __stdcall GetTimeSource(IMFClock** ppClock) = 0;
    virtual int32_t __stdcall GetTime(MFTIME* phnsClockTime) = 0;
    virtual int32_t __stdcall AddClockStateSink(IMFClockStateSink* pStateSink) = 0;
    virtual int32_t __stdcall RemoveClockStateSink(IMFClockStateSink* pStateSink) = 0;
    virtual int32_t __stdcall Start(LONGLONG llClockStartOffset) = 0;
    virtual int32_t __stdcall Stop() = 0;
    virtual int32_t __stdcall Pause() = 0;
};

struct IMFRateControl : public ole32::IUnknown {
    virtual int32_t __stdcall SetRate(int32_t fThin, float flRate) = 0;
    virtual int32_t __stdcall GetRate(int32_t* pfThin, float* pflRate) = 0;
};

struct IMFRateSupport : public ole32::IUnknown {
    virtual int32_t __stdcall GetSlowestRate(MFRATE_DIRECTION eDirection, int32_t fThin, float* pflRate) = 0;
    virtual int32_t __stdcall GetFastestRate(MFRATE_DIRECTION eDirection, int32_t fThin, float* pflRate) = 0;
    virtual int32_t __stdcall IsRateSupported(int32_t fThin, float flRate, float* pflNearestSupportedRate) = 0;
};

struct IMFTopoLoader : public ole32::IUnknown {
    virtual int32_t __stdcall Load(IMFTopology* pInputTopo, IMFTopology** ppOutputTopo, IMFTopology* pCurrentTopo) = 0;
};

struct IMFSequencerSource : public ole32::IUnknown {
    virtual int32_t __stdcall AppendTopology(IMFTopology* pTopology, uint32_t dwFlags, uint32_t* pdwSequenceId) = 0;
    virtual int32_t __stdcall DeleteTopology(uint32_t dwSequenceId) = 0;
    virtual int32_t __stdcall GetPresentationContext(uint32_t dwSequenceId, IMFTopology** ppTopology) = 0;
    virtual int32_t __stdcall UpdateTopology(uint32_t dwSequenceId, IMFTopology* pTopology) = 0;
    virtual int32_t __stdcall UpdateTopologyFlags(uint32_t dwSequenceId, uint32_t dwFlags) = 0;
};

// ============================================================================
// 3. Concrete Implementations
// ============================================================================

// --- Windows Media Video Decoder MFT ---
class CWMVDecoderMFT : public CBaseTransform {
public:
    CWMVDecoderMFT()
        : CBaseTransform("Windows Media Video Decoder MFT", CLSID_CWMVDecMediaObject, MFT_CATEGORY_VIDEO_DECODER) {}

    int32_t __stdcall GetInputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        GUID subType{};
        switch (dwTypeIndex) {
            case 0: subType = MFVideoFormat_WMV1; break;
            case 1: subType = MFVideoFormat_WMV2; break;
            case 2: subType = MFVideoFormat_WMV3; break;
            case 3: subType = MFVideoFormat_WVC1; break;
            default: return ole32::E_FAIL;
        }
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        mt->SetGUID(MF_MT_SUBTYPE, subType);
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

// --- Windows Media Audio Decoder MFT ---
class CWMADecoderMFT : public CBaseTransform {
public:
    CWMADecoderMFT()
        : CBaseTransform("Windows Media Audio Decoder MFT", CLSID_CWMADecMediaObject, MFT_CATEGORY_AUDIO_DECODER) {}

    int32_t __stdcall GetInputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        GUID subType{};
        switch (dwTypeIndex) {
            case 0: subType = MFAudioFormat_WMAudioV8; break;
            case 1: subType = MFAudioFormat_WMAudioV9; break;
            case 2: subType = MFAudioFormat_WMAudio_Lossless; break;
            default: return ole32::E_FAIL;
        }
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        mt->SetGUID(MF_MT_SUBTYPE, subType);
        *ppType = mt;
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputAvailableType(uint32_t, uint32_t dwTypeIndex, IMFMediaType** ppType) override {
        if (!ppType) return ole32::E_POINTER;
        if (dwTypeIndex > 1) return ole32::E_FAIL;
        auto* mt = new CMediaType();
        mt->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        mt->SetGUID(MF_MT_SUBTYPE, (dwTypeIndex == 0) ? MFAudioFormat_PCM : MFAudioFormat_Float);
        *ppType = mt;
        return ole32::S_OK;
    }
};

// --- Presentation Clock & Rate Control ---
class CPresentationClock : public IMFPresentationClock, public IMFRateControl, public IMFRateSupport {
private:
    uint32_t m_refCount{ 1 };
    std::mutex m_mutex;
    MFCLOCK_STATE m_state{ MFCLOCK_STATE_STOPPED };
    float m_rate{ 1.0f };
    int32_t m_thin{ 0 };
    LONGLONG m_startOffset{ 0 };
    LONGLONG m_pauseTime{ 0 };
    std::chrono::steady_clock::time_point m_startTimePoint;
    std::vector<IMFClockStateSink*> m_sinks;
    IMFClock* m_pTimeSource{ nullptr };
    uint32_t m_continuityKey{ 1 };

    static MFTIME GetSystemTimeHns() noexcept {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() / 100;
    }

public:
    CPresentationClock() = default;
    ~CPresentationClock() override {
        for (auto* sink : m_sinks) {
            if (sink) sink->Release();
        }
        m_sinks.clear();
        if (m_pTimeSource) {
            m_pTimeSource->Release();
            m_pTimeSource = nullptr;
        }
    }

    // IUnknown
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMFClock || riid == IID_IMFPresentationClock) {
            *ppvObject = static_cast<IMFPresentationClock*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMFRateControl) {
            *ppvObject = static_cast<IMFRateControl*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == IID_IMFRateSupport) {
            *ppvObject = static_cast<IMFRateSupport*>(this);
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

    // IMFClock
    int32_t __stdcall GetClockCharacteristics(uint32_t* pdwCharacteristics) override {
        if (!pdwCharacteristics) return ole32::E_POINTER;
        *pdwCharacteristics = MFCLOCK_CHARACTERISTICS_FLAG_FREQUENCY_10MHZ |
                              MFCLOCK_CHARACTERISTICS_FLAG_IS_SYSTEM_CLOCK;
        return ole32::S_OK;
    }

    int32_t __stdcall GetCorrelatedTime(uint32_t, LONGLONG* pllClockTime, MFTIME* phnsSystemTime) override {
        if (!pllClockTime || !phnsSystemTime) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *phnsSystemTime = GetSystemTimeHns();
        if (m_state == MFCLOCK_STATE_STOPPED) {
            *pllClockTime = 0;
        } else if (m_state == MFCLOCK_STATE_PAUSED) {
            *pllClockTime = m_pauseTime;
        } else {
            auto now = std::chrono::steady_clock::now();
            auto elapsedNs = std::chrono::duration_cast<std::chrono::nanoseconds>(now - m_startTimePoint).count();
            LONGLONG elapsedHns = static_cast<LONGLONG>((elapsedNs / 100.0) * m_rate);
            *pllClockTime = m_startOffset + elapsedHns;
        }
        return ole32::S_OK;
    }

    int32_t __stdcall GetContinuityKey(uint32_t* pdwContinuityKey) override {
        if (!pdwContinuityKey) return ole32::E_POINTER;
        *pdwContinuityKey = m_continuityKey;
        return ole32::S_OK;
    }

    int32_t __stdcall GetState(uint32_t, MFCLOCK_STATE* peClockState) override {
        if (!peClockState) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *peClockState = m_state;
        return ole32::S_OK;
    }

    int32_t __stdcall GetProperties(MFCLOCK_PROPERTIES* pClockProperties) override {
        if (!pClockProperties) return ole32::E_POINTER;
        pClockProperties->qwCorrelationRate = 1;
        pClockProperties->guidClockId = CLSID_MFPresentationClock;
        pClockProperties->dwClockFlags = 0;
        pClockProperties->qwClockFrequency = 10000000; // 10MHz (100ns units)
        pClockProperties->dwClockTolerance = 1;
        pClockProperties->dwClockJitter = 0;
        return ole32::S_OK;
    }

    // IMFPresentationClock
    int32_t __stdcall SetTimeSource(IMFClock* pClock) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pTimeSource) m_pTimeSource->Release();
        m_pTimeSource = pClock;
        if (m_pTimeSource) m_pTimeSource->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetTimeSource(IMFClock** ppClock) override {
        if (!ppClock) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *ppClock = m_pTimeSource;
        if (*ppClock) (*ppClock)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetTime(MFTIME* phnsClockTime) override {
        if (!phnsClockTime) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state == MFCLOCK_STATE_STOPPED) {
            *phnsClockTime = 0;
        } else if (m_state == MFCLOCK_STATE_PAUSED) {
            *phnsClockTime = m_pauseTime;
        } else {
            auto now = std::chrono::steady_clock::now();
            auto elapsedNs = std::chrono::duration_cast<std::chrono::nanoseconds>(now - m_startTimePoint).count();
            LONGLONG elapsedHns = static_cast<LONGLONG>((elapsedNs / 100.0) * m_rate);
            *phnsClockTime = m_startOffset + elapsedHns;
        }
        return ole32::S_OK;
    }

    int32_t __stdcall AddClockStateSink(IMFClockStateSink* pStateSink) override {
        if (!pStateSink) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto* s : m_sinks) {
            if (s == pStateSink) return ole32::S_OK;
        }
        pStateSink->AddRef();
        m_sinks.push_back(pStateSink);
        return ole32::S_OK;
    }

    int32_t __stdcall RemoveClockStateSink(IMFClockStateSink* pStateSink) override {
        if (!pStateSink) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find(m_sinks.begin(), m_sinks.end(), pStateSink);
        if (it != m_sinks.end()) {
            (*it)->Release();
            m_sinks.erase(it);
            return ole32::S_OK;
        }
        return ole32::E_FAIL;
    }

    int32_t __stdcall Start(LONGLONG llClockStartOffset) override {
        std::vector<IMFClockStateSink*> sinksCopy;
        MFTIME hnsSys = 0;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_startOffset = llClockStartOffset;
            m_startTimePoint = std::chrono::steady_clock::now();
            m_state = MFCLOCK_STATE_RUNNING;
            m_continuityKey++;
            hnsSys = GetSystemTimeHns();
            sinksCopy = m_sinks;
            for (auto* s : sinksCopy) s->AddRef();
        }
        for (auto* s : sinksCopy) {
            s->OnClockStart(hnsSys, llClockStartOffset);
            s->Release();
        }
        return ole32::S_OK;
    }

    int32_t __stdcall Stop() override {
        std::vector<IMFClockStateSink*> sinksCopy;
        MFTIME hnsSys = 0;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_state = MFCLOCK_STATE_STOPPED;
            m_pauseTime = 0;
            m_startOffset = 0;
            hnsSys = GetSystemTimeHns();
            sinksCopy = m_sinks;
            for (auto* s : sinksCopy) s->AddRef();
        }
        for (auto* s : sinksCopy) {
            s->OnClockStop(hnsSys);
            s->Release();
        }
        return ole32::S_OK;
    }

    int32_t __stdcall Pause() override {
        std::vector<IMFClockStateSink*> sinksCopy;
        MFTIME hnsSys = 0;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_state == MFCLOCK_STATE_RUNNING) {
                auto now = std::chrono::steady_clock::now();
                auto elapsedNs = std::chrono::duration_cast<std::chrono::nanoseconds>(now - m_startTimePoint).count();
                LONGLONG elapsedHns = static_cast<LONGLONG>((elapsedNs / 100.0) * m_rate);
                m_pauseTime = m_startOffset + elapsedHns;
            }
            m_state = MFCLOCK_STATE_PAUSED;
            hnsSys = GetSystemTimeHns();
            sinksCopy = m_sinks;
            for (auto* s : sinksCopy) s->AddRef();
        }
        for (auto* s : sinksCopy) {
            s->OnClockPause(hnsSys);
            s->Release();
        }
        return ole32::S_OK;
    }

    // IMFRateControl
    int32_t __stdcall SetRate(int32_t fThin, float flRate) override {
        std::vector<IMFClockStateSink*> sinksCopy;
        MFTIME hnsSys = 0;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_state == MFCLOCK_STATE_RUNNING) {
                auto now = std::chrono::steady_clock::now();
                auto elapsedNs = std::chrono::duration_cast<std::chrono::nanoseconds>(now - m_startTimePoint).count();
                LONGLONG elapsedHns = static_cast<LONGLONG>((elapsedNs / 100.0) * m_rate);
                m_startOffset += elapsedHns;
                m_startTimePoint = now;
            }
            m_rate = flRate;
            m_thin = fThin;
            hnsSys = GetSystemTimeHns();
            sinksCopy = m_sinks;
            for (auto* s : sinksCopy) s->AddRef();
        }
        for (auto* s : sinksCopy) {
            s->OnClockSetRate(hnsSys, flRate);
            s->Release();
        }
        return ole32::S_OK;
    }

    int32_t __stdcall GetRate(int32_t* pfThin, float* pflRate) override {
        if (!pflRate) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (pfThin) *pfThin = m_thin;
        *pflRate = m_rate;
        return ole32::S_OK;
    }

    // IMFRateSupport
    int32_t __stdcall GetSlowestRate(MFRATE_DIRECTION eDirection, int32_t, float* pflRate) override {
        if (!pflRate) return ole32::E_POINTER;
        *pflRate = (eDirection == MFRATE_REVERSE) ? -0.125f : 0.125f;
        return ole32::S_OK;
    }

    int32_t __stdcall GetFastestRate(MFRATE_DIRECTION eDirection, int32_t, float* pflRate) override {
        if (!pflRate) return ole32::E_POINTER;
        *pflRate = (eDirection == MFRATE_REVERSE) ? -16.0f : 16.0f;
        return ole32::S_OK;
    }

    int32_t __stdcall IsRateSupported(int32_t, float flRate, float* pflNearestSupportedRate) override {
        if (pflNearestSupportedRate) *pflNearestSupportedRate = flRate;
        if (flRate >= -16.0f && flRate <= 16.0f) {
            return ole32::S_OK;
        }
        if (pflNearestSupportedRate) {
            *pflNearestSupportedRate = (flRate < 0.0f) ? -16.0f : 16.0f;
        }
        return MF_E_UNSUPPORTED_RATE;
    }
};

// --- Topology Loader ---
class CTopoLoader : public IMFTopoLoader {
private:
    uint32_t m_refCount{ 1 };

public:
    CTopoLoader() = default;
    ~CTopoLoader() override = default;

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMFTopoLoader) {
            *ppvObject = static_cast<IMFTopoLoader*>(this);
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

    int32_t __stdcall Load(IMFTopology* pInputTopo, IMFTopology** ppOutputTopo, IMFTopology*) override {
        if (!pInputTopo || !ppOutputTopo) return ole32::E_POINTER;

        auto* pFullTopo = new CTopology();
        pInputTopo->CopyAllItems(static_cast<IMFTopology*>(pFullTopo));
        uint64_t topoId = 0;
        pInputTopo->GetTopologyID(&topoId);

        uint16_t nodeCount = 0;
        pInputTopo->GetNodeCount(&nodeCount);

        std::map<IMFTopologyNode*, IMFTopologyNode*> oldToNewMap;

        for (uint16_t i = 0; i < nodeCount; ++i) {
            IMFTopologyNode* pNode = nullptr;
            if (pInputTopo->GetNode(i, &pNode) == ole32::S_OK && pNode) {
                MF_TOPOLOGY_TYPE nodeType{};
                pNode->GetNodeType(&nodeType);
                auto* pNewNode = new CTopologyNode(nodeType);
                pNode->CopyAllItems(static_cast<IMFTopologyNode*>(pNewNode));
                uint64_t nId = 0;
                pNode->GetTopoNodeID(&nId);
                pNewNode->SetTopoNodeID(nId);
                ole32::IUnknown* pObj = nullptr;
                if (pNode->GetObject(&pObj) == ole32::S_OK && pObj) {
                    pNewNode->SetObject(pObj);
                    pObj->Release();
                }
                pFullTopo->AddNode(pNewNode);
                oldToNewMap[pNode] = pNewNode;
                pNewNode->Release(); // AddNode holds ref
                pNode->Release();
            }
        }

        // Now resolve connections and splice decoders/converters if necessary
        for (uint16_t i = 0; i < nodeCount; ++i) {
            IMFTopologyNode* pOldSrc = nullptr;
            if (pInputTopo->GetNode(i, &pOldSrc) == ole32::S_OK && pOldSrc) {
                MF_TOPOLOGY_TYPE srcType{};
                pOldSrc->GetNodeType(&srcType);
                auto* pNewSrc = oldToNewMap[pOldSrc];

                uint32_t outCount = 0;
                pOldSrc->GetOutputCount(&outCount);
                for (uint32_t o = 0; o < outCount; ++o) {
                    IMFTopologyNode* pOldDst = nullptr;
                    uint32_t dstInputIdx = 0;
                    if (pOldSrc->GetOutput(o, &pOldDst, &dstInputIdx) == ole32::S_OK && pOldDst) {
                        MF_TOPOLOGY_TYPE dstType{};
                        pOldDst->GetNodeType(&dstType);
                        auto* pNewDst = oldToNewMap[pOldDst];

                        // If Source connects to Output Sink, determine if decoding is required
                        if (srcType == MF_TOPOLOGY_SOURCESTREAM_NODE && dstType == MF_TOPOLOGY_OUTPUT_NODE) {
                            GUID majorType{};
                            GUID subType{};
                            pOldSrc->GetGUID(MF_MT_MAJOR_TYPE, &majorType);
                            pOldSrc->GetGUID(MF_MT_SUBTYPE, &subType);

                            GUID dstSubtype{};
                            pOldDst->GetGUID(MF_MT_SUBTYPE, &dstSubtype);

                            // Video resolution
                            if (majorType == MFMediaType_Video ||
                                subType == MFVideoFormat_H264 ||
                                subType == MFVideoFormat_WMV1 ||
                                subType == MFVideoFormat_WMV2 ||
                                subType == MFVideoFormat_WMV3 ||
                                subType == MFVideoFormat_WVC1) {

                                IMFTopologyNode* pDecoderNode = nullptr;
                                MFCreateTopologyNode(MF_TOPOLOGY_TRANSFORM_NODE, &pDecoderNode);

                                if (subType == MFVideoFormat_H264) {
                                    auto* pDec = new CH264DecoderMFT();
                                    pDecoderNode->SetObject(pDec);
                                    pDec->Release();
                                    pDecoderNode->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
                                } else {
                                    auto* pDec = new CWMVDecoderMFT();
                                    pDecoderNode->SetObject(pDec);
                                    pDec->Release();
                                    pDecoderNode->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
                                }
                                pFullTopo->AddNode(pDecoderNode);

                                // Check if Color Converter is needed
                                if (dstSubtype == MFVideoFormat_RGB32) {
                                    IMFTopologyNode* pColorNode = nullptr;
                                    MFCreateTopologyNode(MF_TOPOLOGY_TRANSFORM_NODE, &pColorNode);
                                    auto* pColorMft = new CColorConvertMFT();
                                    pColorNode->SetObject(pColorMft);
                                    pColorMft->Release();
                                    pColorNode->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);
                                    pFullTopo->AddNode(pColorNode);

                                    // Source -> Decoder -> ColorConverter -> Output
                                    pNewSrc->ConnectOutput(o, pDecoderNode, 0);
                                    pDecoderNode->ConnectOutput(0, pColorNode, 0);
                                    pColorNode->ConnectOutput(0, pNewDst, dstInputIdx);

                                    pColorNode->Release();
                                } else {
                                    // Source -> Decoder -> Output
                                    pNewSrc->ConnectOutput(o, pDecoderNode, 0);
                                    pDecoderNode->ConnectOutput(0, pNewDst, dstInputIdx);
                                }
                                pDecoderNode->Release();
                            }
                            // Audio resolution
                            else if (majorType == MFMediaType_Audio ||
                                     subType == MFAudioFormat_AAC ||
                                     subType == MFAudioFormat_WMAudioV8 ||
                                     subType == MFAudioFormat_WMAudioV9 ||
                                     subType == MFAudioFormat_WMAudio_Lossless) {

                                IMFTopologyNode* pDecoderNode = nullptr;
                                MFCreateTopologyNode(MF_TOPOLOGY_TRANSFORM_NODE, &pDecoderNode);

                                if (subType == MFAudioFormat_AAC) {
                                    auto* pDec = new CAACDecoderMFT();
                                    pDecoderNode->SetObject(pDec);
                                    pDec->Release();
                                    pDecoderNode->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_PCM);
                                } else {
                                    auto* pDec = new CWMADecoderMFT();
                                    pDecoderNode->SetObject(pDec);
                                    pDec->Release();
                                    pDecoderNode->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_PCM);
                                }
                                pFullTopo->AddNode(pDecoderNode);

                                // Source -> Decoder -> Output
                                pNewSrc->ConnectOutput(o, pDecoderNode, 0);
                                pDecoderNode->ConnectOutput(0, pNewDst, dstInputIdx);
                                pDecoderNode->Release();
                            } else {
                                // Direct connection
                                pNewSrc->ConnectOutput(o, pNewDst, dstInputIdx);
                            }
                        } else {
                            // Non-partial or existing connection
                            pNewSrc->ConnectOutput(o, pNewDst, dstInputIdx);
                        }
                        pOldDst->Release();
                    }
                }
                pOldSrc->Release();
            }
        }

        *ppOutputTopo = pFullTopo;
        return ole32::S_OK;
    }
};

// --- Media Sequencer Source ---
class CSequencerSource : public IMFSequencerSource {
private:
    uint32_t m_refCount{ 1 };
    std::mutex m_mutex;
    struct Entry {
        uint32_t id;
        IMFTopology* pTopology;
        uint32_t flags;
    };
    std::vector<Entry> m_entries;
    uint32_t m_nextId{ 1001 };

public:
    CSequencerSource() = default;
    ~CSequencerSource() override {
        for (auto& e : m_entries) {
            if (e.pTopology) e.pTopology->Release();
        }
        m_entries.clear();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMFSequencerSource) {
            *ppvObject = static_cast<IMFSequencerSource*>(this);
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

    int32_t __stdcall AppendTopology(IMFTopology* pTopology, uint32_t dwFlags, uint32_t* pdwSequenceId) override {
        if (!pTopology || !pdwSequenceId) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        pTopology->AddRef();
        uint32_t id = m_nextId++;
        m_entries.push_back({ id, pTopology, dwFlags });
        *pdwSequenceId = id;
        return ole32::S_OK;
    }

    int32_t __stdcall DeleteTopology(uint32_t dwSequenceId) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(m_entries.begin(), m_entries.end(), [dwSequenceId](const Entry& e) {
            return e.id == dwSequenceId;
        });
        if (it != m_entries.end()) {
            if (it->pTopology) it->pTopology->Release();
            m_entries.erase(it);
            return ole32::S_OK;
        }
        return MF_E_NOT_FOUND;
    }

    int32_t __stdcall GetPresentationContext(uint32_t dwSequenceId, IMFTopology** ppTopology) override {
        if (!ppTopology) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(m_entries.begin(), m_entries.end(), [dwSequenceId](const Entry& e) {
            return e.id == dwSequenceId;
        });
        if (it != m_entries.end()) {
            *ppTopology = it->pTopology;
            (*ppTopology)->AddRef();
            return ole32::S_OK;
        }
        return MF_E_NOT_FOUND;
    }

    int32_t __stdcall UpdateTopology(uint32_t dwSequenceId, IMFTopology* pTopology) override {
        if (!pTopology) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(m_entries.begin(), m_entries.end(), [dwSequenceId](const Entry& e) {
            return e.id == dwSequenceId;
        });
        if (it != m_entries.end()) {
            if (it->pTopology) it->pTopology->Release();
            it->pTopology = pTopology;
            it->pTopology->AddRef();
            return ole32::S_OK;
        }
        return MF_E_NOT_FOUND;
    }

    int32_t __stdcall UpdateTopologyFlags(uint32_t dwSequenceId, uint32_t dwFlags) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(m_entries.begin(), m_entries.end(), [dwSequenceId](const Entry& e) {
            return e.id == dwSequenceId;
        });
        if (it != m_entries.end()) {
            it->flags = dwFlags;
            return ole32::S_OK;
        }
        return MF_E_NOT_FOUND;
    }
};

// --- Generic COM Class Factory ---
template <typename T>
class CMediaClassFactory : public ole32::IClassFactory {
private:
    uint32_t m_refCount{ 1 };
public:
    CMediaClassFactory() = default;
    virtual ~CMediaClassFactory() = default;

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

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall CreateInstance(ole32::IUnknown* pUnkOuter, const GUID& riid, void** ppvObject) override {
        if (pUnkOuter) return ole32::CLASS_E_NOAGGREGATION;
        if (!ppvObject) return ole32::E_POINTER;
        auto* pObj = new T();
        int32_t hr = pObj->QueryInterface(riid, ppvObject);
        pObj->Release();
        return hr;
    }

    int32_t __stdcall LockServer(int32_t) override {
        return ole32::S_OK;
    }
};

// ============================================================================
// 4. Factory APIs & Dynamic Loader Exports
// ============================================================================

inline int32_t __stdcall MFCreateTopoLoader(IMFTopoLoader** ppTopoLoader) {
    if (!ppTopoLoader) return ole32::E_POINTER;
    *ppTopoLoader = new CTopoLoader();
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreatePresentationClock(IMFPresentationClock** ppPresentationClock) {
    if (!ppPresentationClock) return ole32::E_POINTER;
    *ppPresentationClock = new CPresentationClock();
    return ole32::S_OK;
}

inline int32_t __stdcall MFCreateSequencerSource(ole32::IUnknown*, IMFSequencerSource** ppSequencerSource) {
    if (!ppSequencerSource) return ole32::E_POINTER;
    *ppSequencerSource = new CSequencerSource();
    return ole32::S_OK;
}

inline int32_t __stdcall DllCanUnloadNow_WmvDecod() {
    return ole32::S_OK;
}

inline int32_t __stdcall DllGetClassObject_WmvDecod(const GUID& rclsid, const GUID& riid, void** ppv) {
    if (!ppv) return ole32::E_POINTER;
    *ppv = nullptr;
    if (rclsid == CLSID_CWMVDecMediaObject) {
        auto* pFactory = new CMediaClassFactory<CWMVDecoderMFT>();
        int32_t hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }
    if (rclsid == CLSID_CWMADecMediaObject) {
        auto* pFactory = new CMediaClassFactory<CWMADecoderMFT>();
        int32_t hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }
    return ole32::CLASS_E_CLASSNOTAVAILABLE;
}

inline void InitializeMediaFoundationSessionExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // mf.dll session pipeline exports
    ldr.registerExport("mf.dll", "MFCreateTopoLoader", reinterpret_cast<void*>(&MFCreateTopoLoader));
    ldr.registerExport("mf.dll", "MFCreatePresentationClock", reinterpret_cast<void*>(&MFCreatePresentationClock));
    ldr.registerExport("mf.dll", "MFCreateSequencerSource", reinterpret_cast<void*>(&MFCreateSequencerSource));

    // wmvdecod.dll codec exports
    ldr.registerExport("wmvdecod.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&DllCanUnloadNow_WmvDecod));
    ldr.registerExport("wmvdecod.dll", "DllGetClassObject", reinterpret_cast<void*>(&DllGetClassObject_WmvDecod));

    // Register built-in decoders in Media Foundation Platform registry
    MediaFoundationPlatform::get().registerBuiltinTransform(std::make_shared<CWMVDecoderMFT>());
    MediaFoundationPlatform::get().registerBuiltinTransform(std::make_shared<CWMADecoderMFT>());

    // Register COM Class Factories with OLE32
    static uint32_t regWmv = 0;
    static uint32_t regWma = 0;
    if (regWmv == 0) {
        auto* pFactoryWmv = new CMediaClassFactory<CWMVDecoderMFT>();
        ole32::CoRegisterClassObject(CLSID_CWMVDecMediaObject, pFactoryWmv, 1 /* CLSCTX_INPROC_SERVER */, 0, &regWmv);
        pFactoryWmv->Release();
    }
    if (regWma == 0) {
        auto* pFactoryWma = new CMediaClassFactory<CWMADecoderMFT>();
        ole32::CoRegisterClassObject(CLSID_CWMADecMediaObject, pFactoryWma, 1 /* CLSCTX_INPROC_SERVER */, 0, &regWma);
        pFactoryWma->Release();
    }
}

} // namespace micant::mf
