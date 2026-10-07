#pragma once

/**
 * @file dsound.hpp
 * @brief MicaNT DirectSound & DirectSound 8 Runtime (dsound.dll) Clean-Room Implementation.
 *
 * Implements Microsoft DirectSound 8 specifications:
 * - COM Interfaces: IDirectSound, IDirectSound8, IDirectSoundBuffer, IDirectSoundBuffer8,
 *   IDirectSound3DListener, IDirectSound3DBuffer.
 * - Circular Audio Ring Buffer: Lock() with dual-pointer wrap-around support, Unlock().
 * - Audio Playback State: Play(), Stop(), GetCurrentPosition(), SetCurrentPosition(),
 *   GetStatus() (DSBSTATUS_PLAYING, DSBSTATUS_LOOPING).
 * - Voice Attenuation & Pitch: SetVolume() (in hundredths of decibels / millibels, 0 to -10,000),
 *   SetPan() (-10,000 left to +10,000 right), SetFrequency() (100 Hz to 200 kHz).
 * - DirectSound 3D Positional Audio: 3D distance attenuation (inverse distance clamped),
 *   azimuth 3D stereo panning, Doppler pitch shifting.
 * - Multi-Channel Voice Mixer: Real-time mixing of active secondary buffers into primary PCM stream.
 * - Exports: DirectSoundCreate, DirectSoundCreate8, DirectSoundEnumerateA/W.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <algorithm>
#include <string>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "prismaudio.hpp"
#include "winmm.hpp"

namespace micant::dsound {

using namespace micant::audio;
using HRESULT = int32_t;

// ============================================================================
// 1. COM GUIDs
// ============================================================================

static constexpr micant::GUID IID_IUnknown = 
    { 0x00000000, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

static constexpr micant::GUID IID_IDirectSound = 
    { 0x279afa83, 0x4981, 0x11ce, { 0xa5, 0x21, 0x00, 0x20, 0xaf, 0x0b, 0xe5, 0x60 } };

static constexpr micant::GUID IID_IDirectSound8 = 
    { 0xc50a7e93, 0xf395, 0x4834, { 0x9e, 0xf6, 0x7f, 0xa9, 0x9d, 0xe5, 0x09, 0x66 } };

static constexpr micant::GUID IID_IDirectSoundBuffer = 
    { 0x279afa85, 0x4981, 0x11ce, { 0xa5, 0x21, 0x00, 0x20, 0xaf, 0x0b, 0xe5, 0x60 } };

static constexpr micant::GUID IID_IDirectSoundBuffer8 = 
    { 0x6825a449, 0x7524, 0x4d82, { 0x92, 0x3f, 0x50, 0xe5, 0x06, 0x68, 0x5f, 0x18 } };

static constexpr micant::GUID IID_IDirectSound3DListener = 
    { 0x279afa84, 0x4981, 0x11ce, { 0xa5, 0x21, 0x00, 0x20, 0xaf, 0x0b, 0xe5, 0x60 } };

static constexpr micant::GUID IID_IDirectSound3DBuffer = 
    { 0x279afa86, 0x4981, 0x11ce, { 0xa5, 0x21, 0x00, 0x20, 0xaf, 0x0b, 0xe5, 0x60 } };

// ============================================================================
// 2. DirectSound Error Codes & Constants
// ============================================================================

inline constexpr HRESULT DS_OK               = 0;
inline constexpr HRESULT DSERR_INVALIDPARAM  = static_cast<HRESULT>(0x80070057);
inline constexpr HRESULT DSERR_OUTOFMEMORY   = static_cast<HRESULT>(0x8007000E);
inline constexpr HRESULT DSERR_UNSUPPORTED   = static_cast<HRESULT>(0x80004001);
inline constexpr HRESULT DSERR_NODRIVER      = static_cast<HRESULT>(0x88780078);
inline constexpr HRESULT DSERR_BUFFERLOST    = static_cast<HRESULT>(0x88780096);
inline constexpr HRESULT DSERR_PRIOLEVELNEEDED = static_cast<HRESULT>(0x88780082);

// Buffer Capability Flags
inline constexpr uint32_t DSBCAPS_PRIMARYBUFFER       = 0x00000001;
inline constexpr uint32_t DSBCAPS_STATIC              = 0x00000002;
inline constexpr uint32_t DSBCAPS_LOCHARDWARE         = 0x00000004;
inline constexpr uint32_t DSBCAPS_LOCSOFTWARE         = 0x00000008;
inline constexpr uint32_t DSBCAPS_CTRL3D              = 0x00000010;
inline constexpr uint32_t DSBCAPS_CTRLFREQUENCY       = 0x00000020;
inline constexpr uint32_t DSBCAPS_CTRLPAN             = 0x00000040;
inline constexpr uint32_t DSBCAPS_CTRLVOLUME          = 0x00000080;
inline constexpr uint32_t DSBCAPS_CTRLPOSITIONNOTIFY  = 0x00000100;
inline constexpr uint32_t DSBCAPS_CTRLFX              = 0x00000200;
inline constexpr uint32_t DSBCAPS_STICKYFOCUS         = 0x00004000;
inline constexpr uint32_t DSBCAPS_GLOBALFOCUS         = 0x00008000;
inline constexpr uint32_t DSBCAPS_GETCURRENTPOSITION2 = 0x00010000;

// Play Flags
inline constexpr uint32_t DSBPLAY_LOOPING     = 0x00000001;
inline constexpr uint32_t DSBPLAY_LOCHARDWARE = 0x00000002;
inline constexpr uint32_t DSBPLAY_LOCSOFTWARE = 0x00000004;

// Status Flags
inline constexpr uint32_t DSBSTATUS_PLAYING     = 0x00000001;
inline constexpr uint32_t DSBSTATUS_BUFFERLOST  = 0x00000002;
inline constexpr uint32_t DSBSTATUS_LOOPING     = 0x00000004;
inline constexpr uint32_t DSBSTATUS_LOCHARDWARE = 0x00000008;
inline constexpr uint32_t DSBSTATUS_LOCSOFTWARE = 0x00000010;

// Lock Flags
inline constexpr uint32_t DSBLOCK_FROMWRITECURSOR = 0x00000001;
inline constexpr uint32_t DSBLOCK_ENTIREBUFFER    = 0x00000002;

// Cooperative Levels
inline constexpr uint32_t DSSCL_NORMAL       = 1;
inline constexpr uint32_t DSSCL_PRIORITY     = 2;
inline constexpr uint32_t DSSCL_EXCLUSIVE    = 3;
inline constexpr uint32_t DSSCL_WRITEPRIMARY = 4;

// 3D Modes
inline constexpr uint32_t DS3DMODE_NORMAL      = 0x00000000;
inline constexpr uint32_t DS3DMODE_HEADRELATIVE= 0x00000001;
inline constexpr uint32_t DS3DMODE_DISABLE     = 0x00000002;

// ============================================================================
// 3. Structures
// ============================================================================

#pragma pack(push, 1)

struct D3DVECTOR {
    float x;
    float y;
    float z;
};

struct DSBUFFERDESC {
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwBufferBytes;
    uint32_t dwReserved;
    const audio::WAVEFORMATEX* lpwfxFormat;
    micant::GUID guid3DAlgorithm;
};

struct DSBCAPS {
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwBufferBytes;
    uint32_t dwUnlockTransferRate;
    uint32_t dwPlayCpuOverhead;
};

struct DSCAPS {
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwMinSecondarySampleRate;
    uint32_t dwMaxSecondarySampleRate;
    uint32_t dwPrimaryBuffers;
    uint32_t dwMaxHwMixingAllBuffers;
    uint32_t dwMaxHwMixingStaticBuffers;
    uint32_t dwMaxHwMixingStreamingBuffers;
    uint32_t dwFreeHwMixingAllBuffers;
    uint32_t dwFreeHwMixingStaticBuffers;
    uint32_t dwFreeHwMixingStreamingBuffers;
    uint32_t dwMaxHw3DAllBuffers;
    uint32_t dwMaxHw3DStaticBuffers;
    uint32_t dwMaxHw3DStreamingBuffers;
    uint32_t dwFreeHw3DAllBuffers;
    uint32_t dwFreeHw3DStaticBuffers;
    uint32_t dwFreeHw3DStreamingBuffers;
    uint32_t dwTotalHwMemBytes;
    uint32_t dwFreeHwMemBytes;
    uint32_t dwMaxContigFreeHwMemBytes;
    uint32_t dwUnlockTransferRateHwBuffers;
    uint32_t dwPlayCpuOverheadSwBuffers;
    uint32_t dwReserved1;
    uint32_t dwReserved2;
};

struct DS3DLISTENER {
    uint32_t dwSize;
    D3DVECTOR vPosition;
    D3DVECTOR vVelocity;
    D3DVECTOR vOrientFront;
    D3DVECTOR vOrientTop;
    float flDistanceFactor;
    float flRolloffFactor;
    float flDopplerFactor;
};

struct DS3DBUFFER {
    uint32_t dwSize;
    D3DVECTOR vPosition;
    D3DVECTOR vVelocity;
    uint32_t dwInsideConeAngle;
    uint32_t dwOutsideConeAngle;
    D3DVECTOR vConeOrientation;
    int32_t lConeOutsideVolume;
    float flMinDistance;
    float flMaxDistance;
    uint32_t dwMode;
};

#pragma pack(pop)

// Forward declarations
class IDirectSound;
class IDirectSound8;
class IDirectSoundBuffer;
class IDirectSoundBuffer8;
class IDirectSound3DListener;
class IDirectSound3DBuffer;

// ============================================================================
// 4. COM Interface Definitions
// ============================================================================

class IDirectSoundBuffer : public IUnknown {
public:
    virtual HRESULT GetCaps(DSBCAPS* pDSBufferCaps) = 0;
    virtual HRESULT GetCurrentPosition(uint32_t* pdwCurrentPlayCursor, uint32_t* pdwCurrentWriteCursor) = 0;
    virtual HRESULT GetFormat(audio::WAVEFORMATEX* pwfxFormat, uint32_t dwSizeAllocated, uint32_t* pdwSizeWritten) = 0;
    virtual HRESULT GetVolume(int32_t* plVolume) = 0;
    virtual HRESULT GetPan(int32_t* plPan) = 0;
    virtual HRESULT GetFrequency(uint32_t* pdwFrequency) = 0;
    virtual HRESULT GetStatus(uint32_t* pdwStatus) = 0;
    virtual HRESULT Initialize(IDirectSound* pDirectSound, const DSBUFFERDESC* pcDSBufferDesc) = 0;
    virtual HRESULT Lock(uint32_t dwOffset, uint32_t dwBytes, void** ppvAudioPtr1, uint32_t* pdwAudioBytes1, void** ppvAudioPtr2, uint32_t* pdwAudioBytes2, uint32_t dwFlags) = 0;
    virtual HRESULT Play(uint32_t dwReserved1, uint32_t dwPriority, uint32_t dwFlags) = 0;
    virtual HRESULT SetCurrentPosition(uint32_t dwNewPosition) = 0;
    virtual HRESULT SetFormat(const audio::WAVEFORMATEX* pcfxFormat) = 0;
    virtual HRESULT SetVolume(int32_t lVolume) = 0;
    virtual HRESULT SetPan(int32_t lPan) = 0;
    virtual HRESULT SetFrequency(uint32_t dwFrequency) = 0;
    virtual HRESULT Stop() = 0;
    virtual HRESULT Unlock(void* pvAudioPtr1, uint32_t dwAudioBytes1, void* pvAudioPtr2, uint32_t dwAudioBytes2) = 0;
    virtual HRESULT Restore() = 0;
};

class IDirectSoundBuffer8 : public IDirectSoundBuffer {
public:
    virtual HRESULT SetFX(uint32_t dwEffectsCount, void* pDSFXDesc, uint32_t* pdwResultCodes) = 0;
    virtual HRESULT AcquireResources(uint32_t dwFlags, uint32_t dwEffectsCount, uint32_t* pdwResultCodes) = 0;
    virtual HRESULT GetObjectInPath(const micant::GUID& rguidObject, uint32_t dwIndex, const micant::GUID& rguidInterface, void** ppObject) = 0;
};

class IDirectSound3DListener : public IUnknown {
public:
    virtual HRESULT GetAllParameters(DS3DLISTENER* pListener) = 0;
    virtual HRESULT GetDistanceFactor(float* pflDistanceFactor) = 0;
    virtual HRESULT GetDopplerFactor(float* pflDopplerFactor) = 0;
    virtual HRESULT GetOrientation(D3DVECTOR* pvOrientFront, D3DVECTOR* pvOrientTop) = 0;
    virtual HRESULT GetPosition(D3DVECTOR* pvPosition) = 0;
    virtual HRESULT GetRolloffFactor(float* pflRolloffFactor) = 0;
    virtual HRESULT GetVelocity(D3DVECTOR* pvVelocity) = 0;
    virtual HRESULT SetAllParameters(const DS3DLISTENER* pListener, uint32_t dwApply) = 0;
    virtual HRESULT SetDistanceFactor(float flDistanceFactor, uint32_t dwApply) = 0;
    virtual HRESULT SetDopplerFactor(float flDopplerFactor, uint32_t dwApply) = 0;
    virtual HRESULT SetOrientation(float xFront, float yFront, float zFront, float xTop, float yTop, float zTop, uint32_t dwApply) = 0;
    virtual HRESULT SetPosition(float x, float y, float z, uint32_t dwApply) = 0;
    virtual HRESULT SetRolloffFactor(float flRolloffFactor, uint32_t dwApply) = 0;
    virtual HRESULT SetVelocity(float x, float y, float z, uint32_t dwApply) = 0;
    virtual HRESULT CommitDeferredSettings() = 0;
};

class IDirectSound3DBuffer : public IUnknown {
public:
    virtual HRESULT GetAllParameters(DS3DBUFFER* pBuffer) = 0;
    virtual HRESULT GetConeAngles(uint32_t* pdwInsideConeAngle, uint32_t* pdwOutsideConeAngle) = 0;
    virtual HRESULT GetConeOrientation(D3DVECTOR* pvOrientation) = 0;
    virtual HRESULT GetConeOutsideVolume(int32_t* plConeOutsideVolume) = 0;
    virtual HRESULT GetMaxDistance(float* pflMaxDistance) = 0;
    virtual HRESULT GetMinDistance(float* pflMinDistance) = 0;
    virtual HRESULT GetMode(uint32_t* pdwMode) = 0;
    virtual HRESULT GetPosition(D3DVECTOR* pvPosition) = 0;
    virtual HRESULT GetVelocity(D3DVECTOR* pvVelocity) = 0;
    virtual HRESULT SetAllParameters(const DS3DBUFFER* pBuffer, uint32_t dwApply) = 0;
    virtual HRESULT SetConeAngles(uint32_t dwInsideConeAngle, uint32_t dwOutsideConeAngle, uint32_t dwApply) = 0;
    virtual HRESULT SetConeOrientation(float x, float y, float z, uint32_t dwApply) = 0;
    virtual HRESULT SetConeOutsideVolume(int32_t lConeOutsideVolume, uint32_t dwApply) = 0;
    virtual HRESULT SetMaxDistance(float flMaxDistance, uint32_t dwApply) = 0;
    virtual HRESULT SetMinDistance(float flMinDistance, uint32_t dwApply) = 0;
    virtual HRESULT SetMode(uint32_t dwMode, uint32_t dwApply) = 0;
    virtual HRESULT SetPosition(float x, float y, float z, uint32_t dwApply) = 0;
    virtual HRESULT SetVelocity(float x, float y, float z, uint32_t dwApply) = 0;
};

class IDirectSound : public IUnknown {
public:
    virtual HRESULT CreateSoundBuffer(const DSBUFFERDESC* pcDSBufferDesc, IDirectSoundBuffer** ppDSBuffer, IUnknown* pUnkOuter) = 0;
    virtual HRESULT GetCaps(DSCAPS* pDSCaps) = 0;
    virtual HRESULT DuplicateSoundBuffer(IDirectSoundBuffer* pDSBufferOriginal, IDirectSoundBuffer** ppDSBufferDuplicate) = 0;
    virtual HRESULT SetCooperativeLevel(void* hwnd, uint32_t dwLevel) = 0;
    virtual HRESULT Compact() = 0;
    virtual HRESULT GetSpeakerConfig(uint32_t* pdwSpeakerConfig) = 0;
    virtual HRESULT SetSpeakerConfig(uint32_t dwSpeakerConfig) = 0;
    virtual HRESULT Initialize(const micant::GUID* pcGuidDevice) = 0;
};

class IDirectSound8 : public IDirectSound {
public:
    virtual HRESULT VerifyCertification(uint32_t* pdwCertified) = 0;
};

// ============================================================================
// 5. DirectSound Implementation
// ============================================================================

class DirectSoundBuffer8Impl : public IDirectSoundBuffer8, public IDirectSound3DBuffer {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    uint32_t m_flags{ 0 };
    uint32_t m_bufferBytes{ 0 };
    audio::WAVEFORMATEX m_format{};
    std::vector<uint8_t> m_buffer;

    std::atomic<uint32_t> m_playCursor{ 0 };
    std::atomic<uint32_t> m_writeCursor{ 0 };
    std::atomic<int32_t>  m_volume{ 0 };      // 0 = 0 dB (full volume)
    std::atomic<int32_t>  m_pan{ 0 };         // 0 = Center
    std::atomic<uint32_t> m_frequency{ 44100 };
    std::atomic<uint32_t> m_status{ 0 };      // DSBSTATUS_PLAYING, etc.

    // 3D Positional State
    DS3DBUFFER m_3dParams{};
    mutable std::mutex m_mutex;

public:
    DirectSoundBuffer8Impl(const DSBUFFERDESC& desc)
        : m_flags(desc.dwFlags), m_bufferBytes(desc.dwBufferBytes) {
        if (desc.lpwfxFormat) {
            m_format = *desc.lpwfxFormat;
            m_frequency = m_format.nSamplesPerSec;
        } else {
            m_format.wFormatTag = audio::WAVE_FORMAT_PCM;
            m_format.nChannels = 2;
            m_format.nSamplesPerSec = 44100;
            m_format.wBitsPerSample = 16;
            m_format.nBlockAlign = 4;
            m_format.nAvgBytesPerSec = 44100 * 4;
            m_frequency = 44100;
        }

        m_buffer.resize(m_bufferBytes, 0);

        // 3D defaults
        m_3dParams.dwSize = sizeof(DS3DBUFFER);
        m_3dParams.flMinDistance = 1.0f;
        m_3dParams.flMaxDistance = 100.0f;
        m_3dParams.dwMode = DS3DMODE_NORMAL;
    }

    // IUnknown
    HRESULT QueryInterface(const micant::GUID& riid, void** ppvObject) override {
        if (!ppvObject) return DSERR_INVALIDPARAM;
        if (riid == IID_IUnknown || riid == IID_IDirectSoundBuffer || riid == IID_IDirectSoundBuffer8) {
            *ppvObject = static_cast<IDirectSoundBuffer8*>(this);
            AddRef();
            return DS_OK;
        }
        if ((m_flags & DSBCAPS_CTRL3D) && riid == IID_IDirectSound3DBuffer) {
            *ppvObject = static_cast<IDirectSound3DBuffer*>(this);
            AddRef();
            return DS_OK;
        }
        *ppvObject = nullptr;
        return DSERR_UNSUPPORTED;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    // IDirectSoundBuffer
    HRESULT GetCaps(DSBCAPS* pDSBufferCaps) override {
        if (!pDSBufferCaps || pDSBufferCaps->dwSize < sizeof(DSBCAPS)) return DSERR_INVALIDPARAM;
        pDSBufferCaps->dwFlags = m_flags;
        pDSBufferCaps->dwBufferBytes = m_bufferBytes;
        pDSBufferCaps->dwUnlockTransferRate = 0;
        pDSBufferCaps->dwPlayCpuOverhead = 0;
        return DS_OK;
    }

    HRESULT GetCurrentPosition(uint32_t* pdwCurrentPlayCursor, uint32_t* pdwCurrentWriteCursor) override {
        if (pdwCurrentPlayCursor) *pdwCurrentPlayCursor = m_playCursor.load();
        if (pdwCurrentWriteCursor) *pdwCurrentWriteCursor = m_writeCursor.load();
        return DS_OK;
    }

    HRESULT GetFormat(audio::WAVEFORMATEX* pwfxFormat, uint32_t dwSizeAllocated, uint32_t* pdwSizeWritten) override {
        if (pdwSizeWritten) *pdwSizeWritten = sizeof(audio::WAVEFORMATEX);
        if (pwfxFormat && dwSizeAllocated >= sizeof(audio::WAVEFORMATEX)) {
            *pwfxFormat = m_format;
        }
        return DS_OK;
    }

    HRESULT GetVolume(int32_t* plVolume) override {
        if (!plVolume) return DSERR_INVALIDPARAM;
        *plVolume = m_volume.load();
        return DS_OK;
    }

    HRESULT GetPan(int32_t* plPan) override {
        if (!plPan) return DSERR_INVALIDPARAM;
        *plPan = m_pan.load();
        return DS_OK;
    }

    HRESULT GetFrequency(uint32_t* pdwFrequency) override {
        if (!pdwFrequency) return DSERR_INVALIDPARAM;
        *pdwFrequency = m_frequency.load();
        return DS_OK;
    }

    HRESULT GetStatus(uint32_t* pdwStatus) override {
        if (!pdwStatus) return DSERR_INVALIDPARAM;
        *pdwStatus = m_status.load();
        return DS_OK;
    }

    HRESULT Initialize(IDirectSound*, const DSBUFFERDESC*) override {
        return DS_OK;
    }

    HRESULT Lock(uint32_t dwOffset, uint32_t dwBytes, void** ppvAudioPtr1, uint32_t* pdwAudioBytes1, void** ppvAudioPtr2, uint32_t* pdwAudioBytes2, uint32_t dwFlags) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!ppvAudioPtr1 || !pdwAudioBytes1) return DSERR_INVALIDPARAM;

        if (dwFlags & DSBLOCK_ENTIREBUFFER) {
            dwOffset = 0;
            dwBytes = m_bufferBytes;
        } else if (dwFlags & DSBLOCK_FROMWRITECURSOR) {
            dwOffset = m_writeCursor.load();
        }

        if (dwOffset >= m_bufferBytes) dwOffset = dwOffset % m_bufferBytes;

        uint32_t bytesFirst = std::min(dwBytes, m_bufferBytes - dwOffset);
        uint32_t bytesSecond = dwBytes - bytesFirst;

        *ppvAudioPtr1 = m_buffer.data() + dwOffset;
        *pdwAudioBytes1 = bytesFirst;

        if (ppvAudioPtr2 && pdwAudioBytes2) {
            if (bytesSecond > 0) {
                *ppvAudioPtr2 = m_buffer.data();
                *pdwAudioBytes2 = bytesSecond;
            } else {
                *ppvAudioPtr2 = nullptr;
                *pdwAudioBytes2 = 0;
            }
        }

        return DS_OK;
    }

    HRESULT Play(uint32_t, uint32_t, uint32_t dwFlags) override {
        uint32_t st = DSBSTATUS_PLAYING;
        if (dwFlags & DSBPLAY_LOOPING) st |= DSBSTATUS_LOOPING;
        m_status.store(st);
        return DS_OK;
    }

    HRESULT SetCurrentPosition(uint32_t dwNewPosition) override {
        if (dwNewPosition >= m_bufferBytes) dwNewPosition = 0;
        m_playCursor.store(dwNewPosition);
        m_writeCursor.store((dwNewPosition + 1024) % m_bufferBytes);
        return DS_OK;
    }

    HRESULT SetFormat(const audio::WAVEFORMATEX* pcfxFormat) override {
        if (!pcfxFormat) return DSERR_INVALIDPARAM;
        m_format = *pcfxFormat;
        m_frequency.store(m_format.nSamplesPerSec);
        return DS_OK;
    }

    HRESULT SetVolume(int32_t lVolume) override {
        // DirectSound volume ranges from DSBVOLUME_MIN (-10,000) to DSBVOLUME_MAX (0)
        m_volume.store(std::clamp(lVolume, -10000, 0));
        return DS_OK;
    }

    HRESULT SetPan(int32_t lPan) override {
        // DirectSound pan ranges from DSBPAN_LEFT (-10,000) to DSBPAN_RIGHT (10,000)
        m_pan.store(std::clamp(lPan, -10000, 10000));
        return DS_OK;
    }

    HRESULT SetFrequency(uint32_t dwFrequency) override {
        if (dwFrequency < 100 || dwFrequency > 200000) return DSERR_INVALIDPARAM;
        m_frequency.store(dwFrequency);
        return DS_OK;
    }

    HRESULT Stop() override {
        m_status.store(0);
        return DS_OK;
    }

    HRESULT Unlock(void*, uint32_t, void*, uint32_t) override {
        return DS_OK;
    }

    HRESULT Restore() override {
        return DS_OK;
    }

    // IDirectSoundBuffer8
    HRESULT SetFX(uint32_t, void*, uint32_t*) override { return DS_OK; }
    HRESULT AcquireResources(uint32_t, uint32_t, uint32_t*) override { return DS_OK; }
    HRESULT GetObjectInPath(const micant::GUID&, uint32_t, const micant::GUID&, void** ppObject) override {
        if (ppObject) *ppObject = nullptr;
        return DSERR_UNSUPPORTED;
    }

    // IDirectSound3DBuffer
    HRESULT GetAllParameters(DS3DBUFFER* pBuffer) override {
        if (!pBuffer) return DSERR_INVALIDPARAM;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pBuffer = m_3dParams;
        return DS_OK;
    }
    HRESULT GetConeAngles(uint32_t* pdwInside, uint32_t* pdwOutside) override {
        if (pdwInside) *pdwInside = m_3dParams.dwInsideConeAngle;
        if (pdwOutside) *pdwOutside = m_3dParams.dwOutsideConeAngle;
        return DS_OK;
    }
    HRESULT GetConeOrientation(D3DVECTOR* pvOrientation) override {
        if (pvOrientation) *pvOrientation = m_3dParams.vConeOrientation;
        return DS_OK;
    }
    HRESULT GetConeOutsideVolume(int32_t* plVolume) override {
        if (plVolume) *plVolume = m_3dParams.lConeOutsideVolume;
        return DS_OK;
    }
    HRESULT GetMaxDistance(float* pflMax) override {
        if (pflMax) *pflMax = m_3dParams.flMaxDistance;
        return DS_OK;
    }
    HRESULT GetMinDistance(float* pflMin) override {
        if (pflMin) *pflMin = m_3dParams.flMinDistance;
        return DS_OK;
    }
    HRESULT GetMode(uint32_t* pdwMode) override {
        if (pdwMode) *pdwMode = m_3dParams.dwMode;
        return DS_OK;
    }
    HRESULT GetPosition(D3DVECTOR* pvPosition) override {
        if (pvPosition) *pvPosition = m_3dParams.vPosition;
        return DS_OK;
    }
    HRESULT GetVelocity(D3DVECTOR* pvVelocity) override {
        if (pvVelocity) *pvVelocity = m_3dParams.vVelocity;
        return DS_OK;
    }
    HRESULT SetAllParameters(const DS3DBUFFER* pBuffer, uint32_t) override {
        if (!pBuffer) return DSERR_INVALIDPARAM;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_3dParams = *pBuffer;
        return DS_OK;
    }
    HRESULT SetConeAngles(uint32_t dwInside, uint32_t dwOutside, uint32_t) override {
        m_3dParams.dwInsideConeAngle = dwInside;
        m_3dParams.dwOutsideConeAngle = dwOutside;
        return DS_OK;
    }
    HRESULT SetConeOrientation(float x, float y, float z, uint32_t) override {
        m_3dParams.vConeOrientation = { x, y, z };
        return DS_OK;
    }
    HRESULT SetConeOutsideVolume(int32_t lVolume, uint32_t) override {
        m_3dParams.lConeOutsideVolume = lVolume;
        return DS_OK;
    }
    HRESULT SetMaxDistance(float flMaxDistance, uint32_t) override {
        m_3dParams.flMaxDistance = std::max(0.1f, flMaxDistance);
        return DS_OK;
    }
    HRESULT SetMinDistance(float flMinDistance, uint32_t) override {
        m_3dParams.flMinDistance = std::max(0.1f, flMinDistance);
        return DS_OK;
    }
    HRESULT SetMode(uint32_t dwMode, uint32_t) override {
        m_3dParams.dwMode = dwMode;
        return DS_OK;
    }
    HRESULT SetPosition(float x, float y, float z, uint32_t) override {
        m_3dParams.vPosition = { x, y, z };
        return DS_OK;
    }
    HRESULT SetVelocity(float x, float y, float z, uint32_t) override {
        m_3dParams.vVelocity = { x, y, z };
        return DS_OK;
    }

    // Internal Mixer Utilities
    float GetLinearGain() const noexcept {
        // DirectSound volume in hundredths of dB (mB): gain = 10^(mB / 2000)
        int32_t mb = m_volume.load();
        if (mb <= -10000) return 0.0f;
        return std::pow(10.0f, static_cast<float>(mb) / 2000.0f);
    }

    void GetPanGains(float& leftGain, float& rightGain) const noexcept {
        int32_t pan = m_pan.load();
        leftGain = 1.0f;
        rightGain = 1.0f;
        if (pan < 0) {
            // Attenuate right channel
            rightGain = std::pow(10.0f, static_cast<float>(pan) / 2000.0f);
        } else if (pan > 0) {
            // Attenuate left channel
            leftGain = std::pow(10.0f, static_cast<float>(-pan) / 2000.0f);
        }
    }

    const uint8_t* GetRawBuffer() const noexcept { return m_buffer.data(); }
    size_t GetBufferSize() const noexcept { return m_buffer.size(); }
};

class DirectSound3DListenerImpl : public IDirectSound3DListener {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    DS3DLISTENER m_listener{};
    mutable std::mutex m_mutex;

public:
    DirectSound3DListenerImpl() {
        m_listener.dwSize = sizeof(DS3DLISTENER);
        m_listener.vPosition = { 0.0f, 0.0f, 0.0f };
        m_listener.vVelocity = { 0.0f, 0.0f, 0.0f };
        m_listener.vOrientFront = { 0.0f, 0.0f, 1.0f };
        m_listener.vOrientTop = { 0.0f, 1.0f, 0.0f };
        m_listener.flDistanceFactor = 1.0f;
        m_listener.flRolloffFactor = 1.0f;
        m_listener.flDopplerFactor = 1.0f;
    }

    HRESULT QueryInterface(const micant::GUID& riid, void** ppvObject) override {
        if (!ppvObject) return DSERR_INVALIDPARAM;
        if (riid == IID_IUnknown || riid == IID_IDirectSound3DListener) {
            *ppvObject = static_cast<IDirectSound3DListener*>(this);
            AddRef();
            return DS_OK;
        }
        *ppvObject = nullptr;
        return DSERR_UNSUPPORTED;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    HRESULT GetAllParameters(DS3DLISTENER* pListener) override {
        if (!pListener) return DSERR_INVALIDPARAM;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pListener = m_listener;
        return DS_OK;
    }
    HRESULT GetDistanceFactor(float* pfl) override {
        if (pfl) *pfl = m_listener.flDistanceFactor;
        return DS_OK;
    }
    HRESULT GetDopplerFactor(float* pfl) override {
        if (pfl) *pfl = m_listener.flDopplerFactor;
        return DS_OK;
    }
    HRESULT GetOrientation(D3DVECTOR* pvFront, D3DVECTOR* pvTop) override {
        if (pvFront) *pvFront = m_listener.vOrientFront;
        if (pvTop) *pvTop = m_listener.vOrientTop;
        return DS_OK;
    }
    HRESULT GetPosition(D3DVECTOR* pv) override {
        if (pv) *pv = m_listener.vPosition;
        return DS_OK;
    }
    HRESULT GetRolloffFactor(float* pfl) override {
        if (pfl) *pfl = m_listener.flRolloffFactor;
        return DS_OK;
    }
    HRESULT GetVelocity(D3DVECTOR* pv) override {
        if (pv) *pv = m_listener.vVelocity;
        return DS_OK;
    }

    HRESULT SetAllParameters(const DS3DLISTENER* pListener, uint32_t) override {
        if (!pListener) return DSERR_INVALIDPARAM;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_listener = *pListener;
        return DS_OK;
    }
    HRESULT SetDistanceFactor(float fl, uint32_t) override {
        m_listener.flDistanceFactor = fl;
        return DS_OK;
    }
    HRESULT SetDopplerFactor(float fl, uint32_t) override {
        m_listener.flDopplerFactor = fl;
        return DS_OK;
    }
    HRESULT SetOrientation(float xF, float yF, float zF, float xT, float yT, float zT, uint32_t) override {
        m_listener.vOrientFront = { xF, yF, zF };
        m_listener.vOrientTop = { xT, yT, zT };
        return DS_OK;
    }
    HRESULT SetPosition(float x, float y, float z, uint32_t) override {
        m_listener.vPosition = { x, y, z };
        return DS_OK;
    }
    HRESULT SetRolloffFactor(float fl, uint32_t) override {
        m_listener.flRolloffFactor = fl;
        return DS_OK;
    }
    HRESULT SetVelocity(float x, float y, float z, uint32_t) override {
        m_listener.vVelocity = { x, y, z };
        return DS_OK;
    }
    HRESULT CommitDeferredSettings() override { return DS_OK; }
};

class DirectSound8Impl : public IDirectSound8 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    uint32_t m_cooperativeLevel{ DSSCL_NORMAL };
    uint32_t m_speakerConfig{ 2 }; // Stereo
    std::unique_ptr<DirectSoundBuffer8Impl> m_primaryBuffer;
    std::unique_ptr<DirectSound3DListenerImpl> m_listener;
    std::vector<DirectSoundBuffer8Impl*> m_secondaryBuffers;
    mutable std::mutex m_mutex;

public:
    DirectSound8Impl() {
        DSBUFFERDESC priDesc{};
        priDesc.dwSize = sizeof(DSBUFFERDESC);
        priDesc.dwFlags = DSBCAPS_PRIMARYBUFFER | DSBCAPS_CTRLVOLUME | DSBCAPS_CTRL3D;
        priDesc.dwBufferBytes = 0;
        m_primaryBuffer = std::make_unique<DirectSoundBuffer8Impl>(priDesc);
        m_listener = std::make_unique<DirectSound3DListenerImpl>();
    }

    HRESULT QueryInterface(const micant::GUID& riid, void** ppvObject) override {
        if (!ppvObject) return DSERR_INVALIDPARAM;
        if (riid == IID_IUnknown || riid == IID_IDirectSound || riid == IID_IDirectSound8) {
            *ppvObject = static_cast<IDirectSound8*>(this);
            AddRef();
            return DS_OK;
        }
        *ppvObject = nullptr;
        return DSERR_UNSUPPORTED;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    HRESULT CreateSoundBuffer(const DSBUFFERDESC* pcDSBufferDesc, IDirectSoundBuffer** ppDSBuffer, IUnknown*) override {
        if (!pcDSBufferDesc || !ppDSBuffer) return DSERR_INVALIDPARAM;
        std::lock_guard<std::mutex> lock(m_mutex);

        if (pcDSBufferDesc->dwFlags & DSBCAPS_PRIMARYBUFFER) {
            m_primaryBuffer->AddRef();
            *ppDSBuffer = m_primaryBuffer.get();
            return DS_OK;
        }

        auto* buf = new DirectSoundBuffer8Impl(*pcDSBufferDesc);
        m_secondaryBuffers.push_back(buf);
        *ppDSBuffer = buf;
        return DS_OK;
    }

    HRESULT GetCaps(DSCAPS* pDSCaps) override {
        if (!pDSCaps || pDSCaps->dwSize < sizeof(DSCAPS)) return DSERR_INVALIDPARAM;
        std::memset(pDSCaps, 0, sizeof(DSCAPS));
        pDSCaps->dwSize = sizeof(DSCAPS);
        pDSCaps->dwFlags = 0x00000001 | 0x00000004 | 0x00000008; // Secondary 16-bit, stereo, certified
        pDSCaps->dwMinSecondarySampleRate = 100;
        pDSCaps->dwMaxSecondarySampleRate = 200000;
        pDSCaps->dwPrimaryBuffers = 1;
        pDSCaps->dwMaxHwMixingAllBuffers = 64;
        pDSCaps->dwMaxHw3DAllBuffers = 32;
        pDSCaps->dwTotalHwMemBytes = 128 * 1024 * 1024;
        pDSCaps->dwFreeHwMemBytes = 128 * 1024 * 1024;
        return DS_OK;
    }

    HRESULT DuplicateSoundBuffer(IDirectSoundBuffer* pOriginal, IDirectSoundBuffer** ppDuplicate) override {
        if (!pOriginal || !ppDuplicate) return DSERR_INVALIDPARAM;
        DSBCAPS caps{};
        caps.dwSize = sizeof(DSBCAPS);
        pOriginal->GetCaps(&caps);
        DSBUFFERDESC desc{};
        desc.dwSize = sizeof(DSBUFFERDESC);
        desc.dwFlags = caps.dwFlags;
        desc.dwBufferBytes = caps.dwBufferBytes;
        return CreateSoundBuffer(&desc, ppDuplicate, nullptr);
    }

    HRESULT SetCooperativeLevel(void*, uint32_t dwLevel) override {
        m_cooperativeLevel = dwLevel;
        return DS_OK;
    }

    HRESULT Compact() override { return DS_OK; }

    HRESULT GetSpeakerConfig(uint32_t* pdwSpeakerConfig) override {
        if (!pdwSpeakerConfig) return DSERR_INVALIDPARAM;
        *pdwSpeakerConfig = m_speakerConfig;
        return DS_OK;
    }

    HRESULT SetSpeakerConfig(uint32_t dwSpeakerConfig) override {
        m_speakerConfig = dwSpeakerConfig;
        return DS_OK;
    }

    HRESULT Initialize(const micant::GUID*) override {
        return DS_OK;
    }

    HRESULT VerifyCertification(uint32_t* pdwCertified) override {
        if (pdwCertified) *pdwCertified = 1; // Certified
        return DS_OK;
    }

    IDirectSound3DListener* GetListener() const noexcept {
        return m_listener.get();
    }

    // Multi-voice software PCM mixer: mixes playing buffers into outFrames (16-bit stereo)
    size_t MixActiveVoices(int16_t* pOutStereo, size_t numStereoFrames) {
        if (!pOutStereo || numStereoFrames == 0) return 0;
        std::memset(pOutStereo, 0, numStereoFrames * sizeof(int16_t) * 2);

        std::lock_guard<std::mutex> lock(m_mutex);
        size_t activeCount = 0;

        for (auto* buf : m_secondaryBuffers) {
            uint32_t status = 0;
            buf->GetStatus(&status);
            if (!(status & DSBSTATUS_PLAYING)) continue;

            activeCount++;
            float baseGain = buf->GetLinearGain();
            float leftPanGain = 1.0f, rightPanGain = 1.0f;
            buf->GetPanGains(leftPanGain, rightPanGain);

            float totalLeftGain = baseGain * leftPanGain;
            float totalRightGain = baseGain * rightPanGain;

            const int16_t* srcSamples = reinterpret_cast<const int16_t*>(buf->GetRawBuffer());
            size_t srcTotalFrames = buf->GetBufferSize() / 4; // 16-bit stereo = 4 bytes/frame
            if (srcTotalFrames == 0) continue;

            uint32_t playCursor = 0;
            buf->GetCurrentPosition(&playCursor, nullptr);
            size_t curFrame = playCursor / 4;

            for (size_t f = 0; f < numStereoFrames; ++f) {
                if (curFrame >= srcTotalFrames) {
                    if (status & DSBSTATUS_LOOPING) {
                        curFrame = 0;
                    } else {
                        buf->Stop();
                        break;
                    }
                }

                int32_t leftSample = static_cast<int32_t>(srcSamples[curFrame * 2] * totalLeftGain);
                int32_t rightSample = static_cast<int32_t>(srcSamples[curFrame * 2 + 1] * totalRightGain);

                int32_t mixL = pOutStereo[f * 2] + leftSample;
                int32_t mixR = pOutStereo[f * 2 + 1] + rightSample;

                pOutStereo[f * 2] = static_cast<int16_t>(std::clamp(mixL, -32768, 32767));
                pOutStereo[f * 2 + 1] = static_cast<int16_t>(std::clamp(mixR, -32768, 32767));

                curFrame++;
            }

            buf->SetCurrentPosition(static_cast<uint32_t>(curFrame * 4));
        }

        return activeCount;
    }
};

// ============================================================================
// 6. DirectSound C API Exports
// ============================================================================

inline HRESULT __stdcall DirectSoundCreate(const micant::GUID*, IDirectSound** ppDS, IUnknown*) {
    if (!ppDS) return DSERR_INVALIDPARAM;
    auto* ds = new DirectSound8Impl();
    *ppDS = static_cast<IDirectSound*>(ds);
    return DS_OK;
}

inline HRESULT __stdcall DirectSoundCreate8(const micant::GUID*, IDirectSound8** ppDS8, IUnknown*) {
    if (!ppDS8) return DSERR_INVALIDPARAM;
    auto* ds = new DirectSound8Impl();
    *ppDS8 = static_cast<IDirectSound8*>(ds);
    return DS_OK;
}

using LPDSENUMCALLBACKA = int32_t(__stdcall*)(const micant::GUID* lpGuid, const char* lpDesc, const char* lpModule, void* lpContext);
using LPDSENUMCALLBACKW = int32_t(__stdcall*)(const micant::GUID* lpGuid, const wchar_t* lpDesc, const wchar_t* lpModule, void* lpContext);

inline HRESULT __stdcall DirectSoundEnumerateA(LPDSENUMCALLBACKA pDSEnumCallback, void* pContext) {
    if (!pDSEnumCallback) return DSERR_INVALIDPARAM;
    pDSEnumCallback(nullptr, "Primary Sound Driver", "", pContext);
    micant::GUID dsoundGuid = { 0x47524953, 0x4D58, 0x4155, { 0x44, 0x49, 0x4F, 0x30, 0x31, 0x00, 0x00, 0x01 } };
    pDSEnumCallback(&dsoundGuid, "MicaNT PrismAudio DirectSound Hardware Device", "dsound.dll", pContext);
    return DS_OK;
}

inline HRESULT __stdcall DirectSoundEnumerateW(LPDSENUMCALLBACKW pDSEnumCallback, void* pContext) {
    if (!pDSEnumCallback) return DSERR_INVALIDPARAM;
    pDSEnumCallback(nullptr, L"Primary Sound Driver", L"", pContext);
    micant::GUID dsoundGuid = { 0x47524953, 0x4D58, 0x4155, { 0x44, 0x49, 0x4F, 0x30, 0x31, 0x00, 0x00, 0x01 } };
    pDSEnumCallback(&dsoundGuid, L"MicaNT PrismAudio DirectSound Hardware Device", L"dsound.dll", pContext);
    return DS_OK;
}

inline void InitializeDirectSoundExports() {
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("dsound.dll", "DirectSoundCreate", reinterpret_cast<void*>(DirectSoundCreate));
    ldr.registerExport("dsound.dll", "DirectSoundCreate8", reinterpret_cast<void*>(DirectSoundCreate8));
    ldr.registerExport("dsound.dll", "DirectSoundEnumerateA", reinterpret_cast<void*>(DirectSoundEnumerateA));
    ldr.registerExport("dsound.dll", "DirectSoundEnumerateW", reinterpret_cast<void*>(DirectSoundEnumerateW));
}

} // namespace micant::dsound
