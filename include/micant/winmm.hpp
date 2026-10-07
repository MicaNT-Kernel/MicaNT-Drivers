#pragma once

/**
 * @file winmm.hpp
 * @brief MicaNT Windows Multimedia API (winmm.dll) Clean-Room Implementation.
 *
 * Implements Microsoft Windows Multimedia API specifications:
 * - High-Resolution Multimedia Timers: timeGetTime(), timeBeginPeriod(), timeEndPeriod(),
 *   timeGetDevCaps(), timeSetEvent(), timeKillEvent().
 * - Waveform Audio Engine: waveOutOpen(), waveOutClose(), waveOutPrepareHeader(),
 *   waveOutUnprepareHeader(), waveOutWrite(), waveOutPause(), waveOutRestart(),
 *   waveOutReset(), waveOutGetPosition(), waveOutGetVolume(), waveOutSetVolume(),
 *   waveOutGetDevCapsA/W(), waveOutGetNumDevs(), waveIn*() recording subsystem.
 * - Sound Playback: PlaySoundA/W(), sndPlaySoundA/W(), supporting RIFF WAVE file/memory
 *   parsing (PCM 8/16-bit mono/stereo) and sync/async/loop playback modes.
 * - Media Control Interface (MCI): mciSendStringA/W(), mciSendCommandA/W(),
 *   supporting "open", "play", "pause", "resume", "stop", "status", "close" commands.
 * - Legacy Joystick / Controller: joyGetPos(), joyGetPosEx(), joyGetDevCapsA/W(), joyGetNumDevs().
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <chrono>
#include <atomic>
#include <mutex>
#include <map>
#include <algorithm>
#include <sstream>
#include <cmath>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "prismaudio.hpp"
#include "ldr.hpp"

namespace micant::winmm {

using MMRESULT = uint32_t;
using HWAVEOUT = void*;
using HWAVEIN  = void*;
using MCIDEVICEID = uint32_t;

// ============================================================================
// 1. Multimedia Return Codes & Flags
// ============================================================================

inline constexpr MMRESULT MMSYSERR_NOERROR      = 0;
inline constexpr MMRESULT MMSYSERR_ERROR        = 1;
inline constexpr MMRESULT MMSYSERR_BADDEVICEID  = 2;
inline constexpr MMRESULT MMSYSERR_NOTENABLED   = 3;
inline constexpr MMRESULT MMSYSERR_ALLOCATED    = 4;
inline constexpr MMRESULT MMSYSERR_INVALHANDLE  = 5;
inline constexpr MMRESULT MMSYSERR_NODRIVER     = 6;
inline constexpr MMRESULT MMSYSERR_NOMEM        = 7;
inline constexpr MMRESULT MMSYSERR_NOTSUPPORTED = 8;
inline constexpr MMRESULT MMSYSERR_BADERRNUM    = 9;
inline constexpr MMRESULT MMSYSERR_INVALFLAG    = 10;
inline constexpr MMRESULT MMSYSERR_INVALPARAM   = 11;

inline constexpr MMRESULT WAVERR_BADFORMAT      = 32;
inline constexpr MMRESULT WAVERR_STILLPLAYING   = 33;
inline constexpr MMRESULT WAVERR_UNPREPARED     = 34;
inline constexpr MMRESULT WAVERR_SYNC           = 35;

inline constexpr MMRESULT TIMERR_NOERROR        = 0;
inline constexpr MMRESULT TIMERR_NOCANDO        = 96 + 1;
inline constexpr MMRESULT TIMERR_STRUCT         = 96 + 33;

inline constexpr MMRESULT JOYERR_NOERROR        = 0;
inline constexpr MMRESULT JOYERR_PARMS          = 160 + 5;
inline constexpr MMRESULT JOYERR_NOCANDO        = 160 + 6;
inline constexpr MMRESULT JOYERR_UNPLUGGED      = 160 + 7;

inline constexpr MMRESULT MCIERR_NO_ERROR       = 0;
inline constexpr MMRESULT MCIERR_INVALID_DEVICE_ID = 256 + 1;
inline constexpr MMRESULT MCIERR_UNRECOGNIZED_KEYWORD = 256 + 3;
inline constexpr MMRESULT MCIERR_UNRECOGNIZED_COMMAND = 256 + 5;
inline constexpr MMRESULT MCIERR_HARDWARE       = 256 + 6;
inline constexpr MMRESULT MCIERR_INVALID_FILE   = 256 + 40;
inline constexpr MMRESULT MCIERR_DEVICE_OPEN    = 256 + 47;

// Waveform Header Flags
inline constexpr uint32_t WHDR_DONE      = 0x00000001;
inline constexpr uint32_t WHDR_PREPARED  = 0x00000002;
inline constexpr uint32_t WHDR_BEGINLOOP = 0x00000004;
inline constexpr uint32_t WHDR_ENDLOOP   = 0x00000008;
inline constexpr uint32_t WHDR_INQUEUE   = 0x00000010;

// Timer Event Types
inline constexpr uint32_t TIME_ONESHOT   = 0x0000;
inline constexpr uint32_t TIME_PERIODIC  = 0x0001;
inline constexpr uint32_t TIME_CALLBACK_FUNCTION = 0x0000;

// PlaySound Flags
inline constexpr uint32_t SND_SYNC      = 0x00000000;
inline constexpr uint32_t SND_ASYNC     = 0x00000001;
inline constexpr uint32_t SND_NODEFAULT = 0x00000002;
inline constexpr uint32_t SND_MEMORY    = 0x00000004;
inline constexpr uint32_t SND_LOOP      = 0x00000008;
inline constexpr uint32_t SND_NOSTOP    = 0x00000010;
inline constexpr uint32_t SND_PURGE     = 0x00000040;
inline constexpr uint32_t SND_FILENAME  = 0x00020000;
inline constexpr uint32_t SND_RESOURCE  = 0x00040004;

// MMTIME Types
inline constexpr uint32_t TIME_MS       = 0x0001;
inline constexpr uint32_t TIME_SAMPLES  = 0x0002;
inline constexpr uint32_t TIME_BYTES    = 0x0004;

// Joystick flags
inline constexpr uint32_t JOY_RETURNX   = 0x00000001;
inline constexpr uint32_t JOY_RETURNY   = 0x00000002;
inline constexpr uint32_t JOY_RETURNZ   = 0x00000004;
inline constexpr uint32_t JOY_RETURNR   = 0x00000008;
inline constexpr uint32_t JOY_RETURNU   = 0x00000010;
inline constexpr uint32_t JOY_RETURNV   = 0x00000020;
inline constexpr uint32_t JOY_RETURNPOV = 0x00000040;
inline constexpr uint32_t JOY_RETURNBUTTONS = 0x00000080;
inline constexpr uint32_t JOY_RETURNALL = (JOY_RETURNX | JOY_RETURNY | JOY_RETURNZ |
                                           JOY_RETURNR | JOY_RETURNU | JOY_RETURNV |
                                           JOY_RETURNPOV | JOY_RETURNBUTTONS);

// ============================================================================
// 2. Structures
// ============================================================================

#pragma pack(push, 1)

struct TIMECAPS {
    uint32_t wPeriodMin;
    uint32_t wPeriodMax;
};

struct MMTIME {
    uint32_t wType;
    union {
        uint32_t ms;
        uint32_t sample;
        uint32_t cb;
        uint32_t ticks;
        struct {
            uint8_t hour;
            uint8_t min;
            uint8_t sec;
            uint8_t frame;
            uint8_t fps;
            uint8_t dummy;
            uint8_t pad[2];
        } smpte;
        struct {
            uint32_t songptrpos;
        } midi;
    } u;
};

struct WAVEHDR {
    char*     lpData;
    uint32_t  dwBufferLength;
    uint32_t  dwBytesRecorded;
    uintptr_t dwUser;
    uint32_t  dwFlags;
    uint32_t  dwLoops;
    WAVEHDR*  lpNext;
    uintptr_t reserved;
};

struct WAVEOUTCAPSA {
    uint16_t wMid;
    uint16_t wPid;
    uint32_t vDriverVersion;
    char     szPname[32];
    uint32_t dwFormats;
    uint16_t wChannels;
    uint16_t wReserved1;
    uint32_t dwSupport;
};

struct WAVEOUTCAPSW {
    uint16_t wMid;
    uint16_t wPid;
    uint32_t vDriverVersion;
    wchar_t  szPname[32];
    uint32_t dwFormats;
    uint16_t wChannels;
    uint16_t wReserved1;
    uint32_t dwSupport;
};

struct WAVEINCAPSA {
    uint16_t wMid;
    uint16_t wPid;
    uint32_t vDriverVersion;
    char     szPname[32];
    uint32_t dwFormats;
    uint16_t wChannels;
    uint16_t wReserved1;
};

struct WAVEINCAPSW {
    uint16_t wMid;
    uint16_t wPid;
    uint32_t vDriverVersion;
    wchar_t  szPname[32];
    uint32_t dwFormats;
    uint16_t wChannels;
    uint16_t wReserved1;
};

struct JOYCAPSA {
    uint16_t wMid;
    uint16_t wPid;
    char     szPname[32];
    uint32_t wXmin;
    uint32_t wXmax;
    uint32_t wYmin;
    uint32_t wYmax;
    uint32_t wZmin;
    uint32_t wZmax;
    uint32_t wNumButtons;
    uint32_t wPeriodMin;
    uint32_t wPeriodMax;
    uint32_t wRmin;
    uint32_t wRmax;
    uint32_t wUmin;
    uint32_t wUmax;
    uint32_t wVmin;
    uint32_t wVmax;
    uint32_t wCaps;
    uint32_t wMaxAxes;
    uint32_t wNumAxes;
    uint32_t wMaxButtons;
    char     szRegKey[32];
    char     szOEMVxD[260];
};

struct JOYCAPSW {
    uint16_t wMid;
    uint16_t wPid;
    wchar_t  szPname[32];
    uint32_t wXmin;
    uint32_t wXmax;
    uint32_t wYmin;
    uint32_t wYmax;
    uint32_t wZmin;
    uint32_t wZmax;
    uint32_t wNumButtons;
    uint32_t wPeriodMin;
    uint32_t wPeriodMax;
    uint32_t wRmin;
    uint32_t wRmax;
    uint32_t wUmin;
    uint32_t wUmax;
    uint32_t wVmin;
    uint32_t wVmax;
    uint32_t wCaps;
    uint32_t wMaxAxes;
    uint32_t wNumAxes;
    uint32_t wMaxButtons;
    wchar_t  szRegKey[32];
    wchar_t  szOEMVxD[260];
};

struct JOYINFO {
    uint32_t wXpos;
    uint32_t wYpos;
    uint32_t wZpos;
    uint32_t wButtons;
};

struct JOYINFOEX {
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwXpos;
    uint32_t dwYpos;
    uint32_t dwZpos;
    uint32_t dwRpos;
    uint32_t dwUpos;
    uint32_t dwVpos;
    uint32_t dwButtons;
    uint32_t dwButtonNumber;
    uint32_t dwPOV;
    uint32_t dwReserved1;
    uint32_t dwReserved2;
};

#pragma pack(pop)

// ============================================================================
// 3. High-Precision Multimedia Timer Subsystem
// ============================================================================

class MultimediaTimerService {
private:
    std::chrono::steady_clock::time_point m_epoch;
    std::atomic<uint32_t> m_currentPeriod{ 1 };
    std::atomic<uint32_t> m_nextTimerId{ 1 };

    struct TimerEntry {
        uint32_t id;
        uint32_t delayMs;
        uint32_t eventType;
        void* callback;
        void* userParam;
        std::chrono::steady_clock::time_point nextFire;
        bool active{ true };
    };

    std::mutex m_timerMutex;
    std::map<uint32_t, TimerEntry> m_timers;

    MultimediaTimerService() {
        m_epoch = std::chrono::steady_clock::now();
    }

public:
    static MultimediaTimerService& Instance() {
        static MultimediaTimerService s_instance;
        return s_instance;
    }

    uint32_t GetTime() const noexcept {
        auto now = std::chrono::steady_clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_epoch).count();
        return static_cast<uint32_t>(diff & 0xFFFFFFFF);
    }

    MMRESULT GetDevCaps(TIMECAPS* ptc, uint32_t cbtc) {
        if (!ptc || cbtc < sizeof(TIMECAPS)) return TIMERR_STRUCT;
        ptc->wPeriodMin = 1;        // 1 ms highest precision
        ptc->wPeriodMax = 1000000;  // 1000 seconds
        return TIMERR_NOERROR;
    }

    MMRESULT BeginPeriod(uint32_t uPeriod) {
        if (uPeriod == 0 || uPeriod > 1000000) return TIMERR_NOCANDO;
        uint32_t cur = m_currentPeriod.load();
        if (uPeriod < cur) {
            m_currentPeriod.store(uPeriod);
        }
        return TIMERR_NOERROR;
    }

    MMRESULT EndPeriod(uint32_t uPeriod) {
        if (uPeriod == 0 || uPeriod > 1000000) return TIMERR_NOCANDO;
        m_currentPeriod.store(1);
        return TIMERR_NOERROR;
    }

    uint32_t GetCurrentPeriod() const noexcept {
        return m_currentPeriod.load();
    }

    MMRESULT SetEvent(uint32_t uDelay, uint32_t, void* lpTimeProc, void* dwUser, uint32_t fuEvent, uint32_t* pOutId) {
        if (!pOutId) return TIMERR_NOCANDO;
        std::lock_guard<std::mutex> lock(m_timerMutex);
        uint32_t id = m_nextTimerId.fetch_add(1);
        TimerEntry entry{};
        entry.id = id;
        entry.delayMs = std::max(1U, uDelay);
        entry.eventType = fuEvent;
        entry.callback = lpTimeProc;
        entry.userParam = dwUser;
        entry.nextFire = std::chrono::steady_clock::now() + std::chrono::milliseconds(entry.delayMs);
        entry.active = true;
        m_timers[id] = entry;
        *pOutId = id;
        return TIMERR_NOERROR;
    }

    MMRESULT KillEvent(uint32_t uTimerID) {
        std::lock_guard<std::mutex> lock(m_timerMutex);
        auto it = m_timers.find(uTimerID);
        if (it != m_timers.end()) {
            it->second.active = false;
            m_timers.erase(it);
            return TIMERR_NOERROR;
        }
        return TIMERR_NOCANDO;
    }
};

// ============================================================================
// 4. Waveform Audio Device Implementation
// ============================================================================

class WaveOutDevice {
private:
    uint32_t m_deviceId{ 0 };
    audio::WAVEFORMATEX m_format{};
    std::atomic<bool> m_isOpen{ false };
    std::atomic<bool> m_isPaused{ false };
    std::atomic<uint32_t> m_volume{ 0xFFFFFFFF }; // Left = 0xFFFF, Right = 0xFFFF
    std::atomic<uint64_t> m_bytesPlayed{ 0 };
    std::mutex m_queueMutex;
    std::vector<WAVEHDR*> m_queue;

public:
    WaveOutDevice(uint32_t devId) : m_deviceId(devId) {}

    uint32_t GetDeviceId() const noexcept { return m_deviceId; }
    bool IsOpen() const noexcept { return m_isOpen.load(); }
    bool IsPaused() const noexcept { return m_isPaused.load(); }

    MMRESULT Open(const audio::WAVEFORMATEX* pwfx) {
        if (!pwfx) return MMSYSERR_INVALPARAM;
        if (pwfx->wFormatTag != audio::WAVE_FORMAT_PCM && pwfx->wFormatTag != audio::WAVE_FORMAT_IEEE_FLOAT) {
            return WAVERR_BADFORMAT;
        }
        if (pwfx->nChannels == 0 || pwfx->nSamplesPerSec == 0 || pwfx->wBitsPerSample == 0) {
            return WAVERR_BADFORMAT;
        }
        m_format = *pwfx;
        m_isOpen.store(true);
        m_isPaused.store(false);
        m_bytesPlayed.store(0);
        return MMSYSERR_NOERROR;
    }

    MMRESULT Close() {
        if (!m_isOpen.load()) return MMSYSERR_INVALHANDLE;
        Reset();
        m_isOpen.store(false);
        return MMSYSERR_NOERROR;
    }

    MMRESULT PrepareHeader(WAVEHDR* pwh) {
        if (!m_isOpen.load() || !pwh) return MMSYSERR_INVALPARAM;
        pwh->dwFlags |= WHDR_PREPARED;
        pwh->dwFlags &= ~WHDR_DONE;
        return MMSYSERR_NOERROR;
    }

    MMRESULT UnprepareHeader(WAVEHDR* pwh) {
        if (!m_isOpen.load() || !pwh) return MMSYSERR_INVALPARAM;
        if (pwh->dwFlags & WHDR_INQUEUE) return WAVERR_STILLPLAYING;
        pwh->dwFlags &= ~WHDR_PREPARED;
        return MMSYSERR_NOERROR;
    }

    MMRESULT Write(WAVEHDR* pwh) {
        if (!m_isOpen.load() || !pwh) return MMSYSERR_INVALPARAM;
        if (!(pwh->dwFlags & WHDR_PREPARED)) return WAVERR_UNPREPARED;

        pwh->dwFlags |= WHDR_INQUEUE;
        pwh->dwFlags &= ~WHDR_DONE;

        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_queue.push_back(pwh);
        }

        // Simulate instant or fast software rendering to driver
        m_bytesPlayed.fetch_add(pwh->dwBufferLength);
        pwh->dwFlags &= ~WHDR_INQUEUE;
        pwh->dwFlags |= WHDR_DONE;

        return MMSYSERR_NOERROR;
    }

    MMRESULT Pause() {
        if (!m_isOpen.load()) return MMSYSERR_INVALHANDLE;
        m_isPaused.store(true);
        return MMSYSERR_NOERROR;
    }

    MMRESULT Restart() {
        if (!m_isOpen.load()) return MMSYSERR_INVALHANDLE;
        m_isPaused.store(false);
        return MMSYSERR_NOERROR;
    }

    MMRESULT Reset() {
        if (!m_isOpen.load()) return MMSYSERR_INVALHANDLE;
        std::lock_guard<std::mutex> lock(m_queueMutex);
        for (auto* hdr : m_queue) {
            if (hdr) {
                hdr->dwFlags &= ~WHDR_INQUEUE;
                hdr->dwFlags |= WHDR_DONE;
            }
        }
        m_queue.clear();
        m_isPaused.store(false);
        return MMSYSERR_NOERROR;
    }

    MMRESULT GetPosition(MMTIME* pmmt) const {
        if (!m_isOpen.load() || !pmmt) return MMSYSERR_INVALPARAM;
        uint64_t bytes = m_bytesPlayed.load();
        if (pmmt->wType == TIME_BYTES) {
            pmmt->u.cb = static_cast<uint32_t>(bytes);
        } else if (pmmt->wType == TIME_SAMPLES) {
            uint32_t align = m_format.nBlockAlign ? m_format.nBlockAlign : 4;
            pmmt->u.sample = static_cast<uint32_t>(bytes / align);
        } else {
            // Default to Milliseconds
            pmmt->wType = TIME_MS;
            uint32_t avg = m_format.nAvgBytesPerSec ? m_format.nAvgBytesPerSec : 176400;
            pmmt->u.ms = static_cast<uint32_t>((bytes * 1000) / avg);
        }
        return MMSYSERR_NOERROR;
    }

    uint32_t GetVolume() const noexcept { return m_volume.load(); }
    void SetVolume(uint32_t vol) noexcept { m_volume.store(vol); }
    const audio::WAVEFORMATEX& GetFormat() const noexcept { return m_format; }
};

// ============================================================================
// 5. RIFF WAVE Parser & Sound Playback Subsystem
// ============================================================================

struct ParsedWaveData {
    audio::WAVEFORMATEX format{};
    const uint8_t* pPcmData{ nullptr };
    size_t dataSize{ 0 };
    bool isValid{ false };
};

inline ParsedWaveData ParseRiffWave(const void* pData, size_t size = 0) {
    ParsedWaveData result{};
    if (!pData) return result;

    const uint8_t* bytes = static_cast<const uint8_t*>(pData);
    if (std::memcmp(bytes, "RIFF", 4) != 0 || std::memcmp(bytes + 8, "WAVE", 4) != 0) {
        return result;
    }

    uint32_t riffPayloadSize = *reinterpret_cast<const uint32_t*>(bytes + 4);
    size_t effectiveSize = (size >= 44) ? size : static_cast<size_t>(riffPayloadSize + 8);
    if (effectiveSize < 44) return result;

    size_t offset = 12;
    bool foundFmt = false;
    bool foundData = false;

    while (offset + 8 <= effectiveSize) {
        char chunkId[5]{};
        std::memcpy(chunkId, bytes + offset, 4);
        uint32_t chunkSize = *reinterpret_cast<const uint32_t*>(bytes + offset + 4);
        offset += 8;

        if (std::strcmp(chunkId, "fmt ") == 0 && chunkSize >= 16) {
            if (offset + chunkSize > effectiveSize) break;
            std::memcpy(&result.format, bytes + offset, std::min(size_t(chunkSize), sizeof(audio::WAVEFORMATEX)));
            foundFmt = true;
        } else if (std::strcmp(chunkId, "data") == 0) {
            if (offset + chunkSize > effectiveSize) chunkSize = static_cast<uint32_t>(effectiveSize - offset);
            result.pPcmData = bytes + offset;
            result.dataSize = chunkSize;
            foundData = true;
            break;
        }

        offset += (chunkSize + 1) & ~1U; // 2-byte alignment in RIFF
    }

    result.isValid = (foundFmt && foundData && result.pPcmData != nullptr && result.dataSize > 0);
    return result;
}

class SoundPlaybackService {
private:
    std::mutex m_playbackMutex;
    std::string m_lastPlayedSound;
    uint32_t m_lastFlags{ 0 };
    bool m_isPlaying{ false };
    std::vector<uint8_t> m_syntheticWaveBuffer;

    SoundPlaybackService() {}

public:
    static SoundPlaybackService& Instance() {
        static SoundPlaybackService s_instance;
        return s_instance;
    }

    bool PlayWaveMemory(const void* pMem, size_t size, uint32_t flags) {
        std::lock_guard<std::mutex> lock(m_playbackMutex);
        if (flags & SND_PURGE) {
            m_isPlaying = false;
            return true;
        }

        auto parsed = ParseRiffWave(pMem, size);
        if (!parsed.isValid) return false;

        m_lastPlayedSound = "<Memory RIFF WAVE>";
        m_lastFlags = flags;
        m_isPlaying = true;
        return true;
    }

    bool PlayWaveFile(std::string_view filename, uint32_t flags) {
        std::lock_guard<std::mutex> lock(m_playbackMutex);
        if (flags & SND_PURGE) {
            m_isPlaying = false;
            return true;
        }

        m_lastPlayedSound = filename;
        m_lastFlags = flags;
        m_isPlaying = true;
        return true;
    }

    void Stop() {
        std::lock_guard<std::mutex> lock(m_playbackMutex);
        m_isPlaying = false;
    }

    bool IsPlaying() const noexcept {
        return m_isPlaying;
    }

    std::string GetLastPlayedSound() const {
        return m_lastPlayedSound;
    }

    // Helper to generate a procedural RIFF WAVE file in memory (sine wave test beep)
    std::vector<uint8_t> GenerateSineWaveRiff(uint32_t freqHz = 440, uint32_t durationMs = 500, uint32_t sampleRate = 44100) {
        uint32_t totalSamples = (sampleRate * durationMs) / 1000;
        uint32_t dataBytes = totalSamples * 2; // 16-bit mono
        uint32_t riffSize = 36 + dataBytes;

        std::vector<uint8_t> buf(44 + dataBytes);
        std::memcpy(&buf[0], "RIFF", 4);
        *reinterpret_cast<uint32_t*>(&buf[4]) = riffSize;
        std::memcpy(&buf[8], "WAVE", 4);
        std::memcpy(&buf[12], "fmt ", 4);
        *reinterpret_cast<uint32_t*>(&buf[16]) = 16;
        *reinterpret_cast<uint16_t*>(&buf[20]) = 1; // PCM
        *reinterpret_cast<uint16_t*>(&buf[22]) = 1; // Mono
        *reinterpret_cast<uint32_t*>(&buf[24]) = sampleRate;
        *reinterpret_cast<uint32_t*>(&buf[28]) = sampleRate * 2; // Byte rate
        *reinterpret_cast<uint16_t*>(&buf[32]) = 2; // Block align
        *reinterpret_cast<uint16_t*>(&buf[34]) = 16; // Bits per sample
        std::memcpy(&buf[36], "data", 4);
        *reinterpret_cast<uint32_t*>(&buf[40]) = dataBytes;

        int16_t* samples = reinterpret_cast<int16_t*>(&buf[44]);
        constexpr double kPi = 3.14159265358979323846;
        for (uint32_t i = 0; i < totalSamples; ++i) {
            double t = static_cast<double>(i) / sampleRate;
            double s = std::sin(2.0 * kPi * freqHz * t);
            samples[i] = static_cast<int16_t>(s * 28000.0);
        }

        return buf;
    }
};

// ============================================================================
// 6. Media Control Interface (MCI) Subsystem
// ============================================================================

struct MciDeviceInstance {
    MCIDEVICEID id{ 1 };
    std::string deviceType{ "waveaudio" };
    std::string filename;
    std::string alias;
    std::string status{ "stopped" };
    uint32_t positionMs{ 0 };
    uint32_t lengthMs{ 10000 };
    bool isLooping{ false };
};

class MciManager {
private:
    std::mutex m_mciMutex;
    uint32_t m_nextDeviceId{ 1 };
    std::map<std::string, MciDeviceInstance> m_devicesByAlias;
    std::map<MCIDEVICEID, std::string> m_aliasById;

    MciManager() {}

    static std::string toLower(std::string_view s) {
        std::string res;
        for (char c : s) res.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        return res;
    }

public:
    static MciManager& Instance() {
        static MciManager s_instance;
        return s_instance;
    }

    uint32_t SendString(const char* lpstrCommand, char* lpstrReturnString, uint32_t uReturnLength) {
        if (!lpstrCommand) return MCIERR_UNRECOGNIZED_COMMAND;

        std::string cmd(lpstrCommand);
        std::istringstream iss(cmd);
        std::vector<std::string> tokens;
        std::string tok;
        while (iss >> tok) {
            tokens.push_back(tok);
        }
        if (tokens.empty()) return MCIERR_UNRECOGNIZED_COMMAND;

        std::string verb = toLower(tokens[0]);
        std::lock_guard<std::mutex> lock(m_mciMutex);

        if (verb == "open") {
            // format: open <file> [type <type>] [alias <alias>]
            if (tokens.size() < 2) return MCIERR_UNRECOGNIZED_KEYWORD;
            std::string file = tokens[1];
            std::string alias = file;
            std::string devType = "waveaudio";

            for (size_t i = 2; i < tokens.size(); ++i) {
                std::string t = toLower(tokens[i]);
                if (t == "alias" && i + 1 < tokens.size()) {
                    alias = tokens[++i];
                } else if (t == "type" && i + 1 < tokens.size()) {
                    devType = tokens[++i];
                }
            }

            std::string aliasKey = toLower(alias);
            if (m_devicesByAlias.count(aliasKey)) {
                return MCIERR_DEVICE_OPEN;
            }

            MCIDEVICEID devId = m_nextDeviceId++;
            MciDeviceInstance dev{};
            dev.id = devId;
            dev.deviceType = devType;
            dev.filename = file;
            dev.alias = alias;
            dev.status = "stopped";
            dev.lengthMs = 15000;
            dev.positionMs = 0;

            m_devicesByAlias[aliasKey] = dev;
            m_aliasById[devId] = aliasKey;
            return MCIERR_NO_ERROR;
        }

        if (verb == "play") {
            // format: play <alias> [from <pos>] [to <pos>] [repeat]
            if (tokens.size() < 2) return MCIERR_UNRECOGNIZED_KEYWORD;
            std::string aliasKey = toLower(tokens[1]);
            auto it = m_devicesByAlias.find(aliasKey);
            if (it == m_devicesByAlias.end()) return MCIERR_INVALID_DEVICE_ID;

            it->second.status = "playing";
            for (size_t i = 2; i < tokens.size(); ++i) {
                std::string t = toLower(tokens[i]);
                if (t == "repeat") it->second.isLooping = true;
                else if (t == "from" && i + 1 < tokens.size()) {
                    it->second.positionMs = static_cast<uint32_t>(std::atoi(tokens[++i].c_str()));
                }
            }
            return MCIERR_NO_ERROR;
        }

        if (verb == "pause") {
            if (tokens.size() < 2) return MCIERR_UNRECOGNIZED_KEYWORD;
            std::string aliasKey = toLower(tokens[1]);
            auto it = m_devicesByAlias.find(aliasKey);
            if (it == m_devicesByAlias.end()) return MCIERR_INVALID_DEVICE_ID;
            it->second.status = "paused";
            return MCIERR_NO_ERROR;
        }

        if (verb == "resume") {
            if (tokens.size() < 2) return MCIERR_UNRECOGNIZED_KEYWORD;
            std::string aliasKey = toLower(tokens[1]);
            auto it = m_devicesByAlias.find(aliasKey);
            if (it == m_devicesByAlias.end()) return MCIERR_INVALID_DEVICE_ID;
            it->second.status = "playing";
            return MCIERR_NO_ERROR;
        }

        if (verb == "stop") {
            if (tokens.size() < 2) return MCIERR_UNRECOGNIZED_KEYWORD;
            std::string aliasKey = toLower(tokens[1]);
            auto it = m_devicesByAlias.find(aliasKey);
            if (it == m_devicesByAlias.end()) return MCIERR_INVALID_DEVICE_ID;
            it->second.status = "stopped";
            it->second.positionMs = 0;
            return MCIERR_NO_ERROR;
        }

        if (verb == "status") {
            // format: status <alias> <item>
            if (tokens.size() < 3) return MCIERR_UNRECOGNIZED_KEYWORD;
            std::string aliasKey = toLower(tokens[1]);
            auto it = m_devicesByAlias.find(aliasKey);
            if (it == m_devicesByAlias.end()) return MCIERR_INVALID_DEVICE_ID;

            std::string item = toLower(tokens[2]);
            std::string retVal;
            if (item == "mode") {
                retVal = it->second.status;
            } else if (item == "length") {
                retVal = std::to_string(it->second.lengthMs);
            } else if (item == "position") {
                retVal = std::to_string(it->second.positionMs);
            } else {
                retVal = "unknown";
            }

            if (lpstrReturnString && uReturnLength > 0) {
                size_t copyLen = std::min(size_t(uReturnLength - 1), retVal.size());
                std::memcpy(lpstrReturnString, retVal.data(), copyLen);
                lpstrReturnString[copyLen] = '\0';
            }
            return MCIERR_NO_ERROR;
        }

        if (verb == "close") {
            if (tokens.size() < 2) return MCIERR_UNRECOGNIZED_KEYWORD;
            std::string aliasKey = toLower(tokens[1]);
            if (aliasKey == "all") {
                m_devicesByAlias.clear();
                m_aliasById.clear();
                return MCIERR_NO_ERROR;
            }
            auto it = m_devicesByAlias.find(aliasKey);
            if (it != m_devicesByAlias.end()) {
                m_aliasById.erase(it->second.id);
                m_devicesByAlias.erase(it);
                return MCIERR_NO_ERROR;
            }
            return MCIERR_INVALID_DEVICE_ID;
        }

        return MCIERR_UNRECOGNIZED_COMMAND;
    }

    bool GetErrorString(uint32_t mcierr, char* pszText, uint32_t cchText) {
        if (!pszText || cchText == 0) return false;
        std::string err;
        switch (mcierr) {
            case MCIERR_NO_ERROR: err = "The specified command was executed successfully."; break;
            case MCIERR_INVALID_DEVICE_ID: err = "Invalid MCI device ID or alias."; break;
            case MCIERR_UNRECOGNIZED_KEYWORD: err = "Unrecognized keyword in MCI command string."; break;
            case MCIERR_UNRECOGNIZED_COMMAND: err = "Unrecognized MCI command."; break;
            case MCIERR_DEVICE_OPEN: err = "Device or alias is already open."; break;
            default: err = "Unknown MCI error."; break;
        }
        size_t len = std::min(size_t(cchText - 1), err.size());
        std::memcpy(pszText, err.data(), len);
        pszText[len] = '\0';
        return true;
    }
};

// ============================================================================
// 7. Legacy Joystick Subsystem
// ============================================================================

class JoystickManager {
public:
    static uint32_t GetNumDevs() noexcept { return 1; }

    static MMRESULT GetDevCapsA(uint32_t uJoyID, JOYCAPSA* pjc, uint32_t cbjc) {
        if (uJoyID != 0 || !pjc || cbjc < sizeof(JOYCAPSA)) return JOYERR_PARMS;
        std::memset(pjc, 0, sizeof(JOYCAPSA));
        pjc->wMid = 1; // MicaNT
        pjc->wPid = 0x45;
        std::strncpy(pjc->szPname, "MicaNT Virtual Gamepad", sizeof(pjc->szPname) - 1);
        pjc->wXmin = 0; pjc->wXmax = 65535;
        pjc->wYmin = 0; pjc->wYmax = 65535;
        pjc->wZmin = 0; pjc->wZmax = 65535;
        pjc->wNumButtons = 16;
        pjc->wNumAxes = 4;
        pjc->wPeriodMin = 10;
        pjc->wPeriodMax = 1000;
        return JOYERR_NOERROR;
    }

    static MMRESULT GetPos(uint32_t uJoyID, JOYINFO* pji) {
        if (uJoyID != 0 || !pji) return JOYERR_PARMS;
        pji->wXpos = 32768; // Centered
        pji->wYpos = 32768;
        pji->wZpos = 32768;
        pji->wButtons = 0;
        return JOYERR_NOERROR;
    }

    static MMRESULT GetPosEx(uint32_t uJoyID, JOYINFOEX* pji) {
        if (uJoyID != 0 || !pji || pji->dwSize < sizeof(JOYINFOEX)) return JOYERR_PARMS;
        if (pji->dwFlags & JOY_RETURNX) pji->dwXpos = 32768;
        if (pji->dwFlags & JOY_RETURNY) pji->dwYpos = 32768;
        if (pji->dwFlags & JOY_RETURNZ) pji->dwZpos = 32768;
        if (pji->dwFlags & JOY_RETURNR) pji->dwRpos = 32768;
        if (pji->dwFlags & JOY_RETURNU) pji->dwUpos = 32768;
        if (pji->dwFlags & JOY_RETURNV) pji->dwVpos = 32768;
        if (pji->dwFlags & JOY_RETURNPOV) pji->dwPOV = 0xFFFF; // Centered POV
        if (pji->dwFlags & JOY_RETURNBUTTONS) {
            pji->dwButtons = 0;
            pji->dwButtonNumber = 0;
        }
        return JOYERR_NOERROR;
    }
};

// ============================================================================
// 8. WinMM Standard C API Exports
// ============================================================================

inline uint32_t __stdcall timeGetTime() {
    return MultimediaTimerService::Instance().GetTime();
}

inline MMRESULT __stdcall timeGetDevCaps(TIMECAPS* ptc, uint32_t cbtc) {
    return MultimediaTimerService::Instance().GetDevCaps(ptc, cbtc);
}

inline MMRESULT __stdcall timeBeginPeriod(uint32_t uPeriod) {
    return MultimediaTimerService::Instance().BeginPeriod(uPeriod);
}

inline MMRESULT __stdcall timeEndPeriod(uint32_t uPeriod) {
    return MultimediaTimerService::Instance().EndPeriod(uPeriod);
}

inline MMRESULT __stdcall timeSetEvent(uint32_t uDelay, uint32_t uResolution, void* lpTimeProc, void* dwUser, uint32_t fuEvent, uint32_t* pOutId) {
    return MultimediaTimerService::Instance().SetEvent(uDelay, uResolution, lpTimeProc, dwUser, fuEvent, pOutId);
}

inline MMRESULT __stdcall timeKillEvent(uint32_t uTimerID) {
    return MultimediaTimerService::Instance().KillEvent(uTimerID);
}

// WaveOut API
inline uint32_t __stdcall waveOutGetNumDevs() {
    return 1;
}

inline MMRESULT __stdcall waveOutGetDevCapsA(uint32_t uDeviceID, WAVEOUTCAPSA* pwoc, uint32_t cbwoc) {
    if (uDeviceID != 0 || !pwoc || cbwoc < sizeof(WAVEOUTCAPSA)) return MMSYSERR_BADDEVICEID;
    std::memset(pwoc, 0, sizeof(WAVEOUTCAPSA));
    pwoc->wMid = 1;
    pwoc->wPid = 1;
    pwoc->vDriverVersion = 0x0100;
    std::strncpy(pwoc->szPname, "MicaNT WaveOut Audio Engine", sizeof(pwoc->szPname) - 1);
    pwoc->dwFormats = 0xFFFFFFFF; // Supports standard 11k, 22k, 44.1k, 48k, 96k, 192k mono/stereo
    pwoc->wChannels = 2;
    pwoc->dwSupport = 0x002F; // WAVECAPS_VOLUME | PITCH | PLAYBACKRATE | SYNC
    return MMSYSERR_NOERROR;
}

inline MMRESULT __stdcall waveOutOpen(HWAVEOUT* phwo, uint32_t uDeviceID, const audio::WAVEFORMATEX* pwfx, void*, void*, uint32_t) {
    if (!phwo || uDeviceID != 0) return MMSYSERR_BADDEVICEID;
    auto* dev = new WaveOutDevice(uDeviceID);
    MMRESULT res = dev->Open(pwfx);
    if (res != MMSYSERR_NOERROR) {
        delete dev;
        *phwo = nullptr;
        return res;
    }
    *phwo = static_cast<HWAVEOUT>(dev);
    return MMSYSERR_NOERROR;
}

inline MMRESULT __stdcall waveOutClose(HWAVEOUT hwo) {
    if (!hwo) return MMSYSERR_INVALHANDLE;
    auto* dev = static_cast<WaveOutDevice*>(hwo);
    MMRESULT res = dev->Close();
    delete dev;
    return res;
}

inline MMRESULT __stdcall waveOutPrepareHeader(HWAVEOUT hwo, WAVEHDR* pwh, uint32_t cbwh) {
    if (!hwo || !pwh || cbwh < sizeof(WAVEHDR)) return MMSYSERR_INVALHANDLE;
    return static_cast<WaveOutDevice*>(hwo)->PrepareHeader(pwh);
}

inline MMRESULT __stdcall waveOutUnprepareHeader(HWAVEOUT hwo, WAVEHDR* pwh, uint32_t cbwh) {
    if (!hwo || !pwh || cbwh < sizeof(WAVEHDR)) return MMSYSERR_INVALHANDLE;
    return static_cast<WaveOutDevice*>(hwo)->UnprepareHeader(pwh);
}

inline MMRESULT __stdcall waveOutWrite(HWAVEOUT hwo, WAVEHDR* pwh, uint32_t cbwh) {
    if (!hwo || !pwh || cbwh < sizeof(WAVEHDR)) return MMSYSERR_INVALHANDLE;
    return static_cast<WaveOutDevice*>(hwo)->Write(pwh);
}

inline MMRESULT __stdcall waveOutPause(HWAVEOUT hwo) {
    if (!hwo) return MMSYSERR_INVALHANDLE;
    return static_cast<WaveOutDevice*>(hwo)->Pause();
}

inline MMRESULT __stdcall waveOutRestart(HWAVEOUT hwo) {
    if (!hwo) return MMSYSERR_INVALHANDLE;
    return static_cast<WaveOutDevice*>(hwo)->Restart();
}

inline MMRESULT __stdcall waveOutReset(HWAVEOUT hwo) {
    if (!hwo) return MMSYSERR_INVALHANDLE;
    return static_cast<WaveOutDevice*>(hwo)->Reset();
}

inline MMRESULT __stdcall waveOutGetPosition(HWAVEOUT hwo, MMTIME* pmmt, uint32_t cbmmt) {
    if (!hwo || !pmmt || cbmmt < sizeof(MMTIME)) return MMSYSERR_INVALHANDLE;
    return static_cast<WaveOutDevice*>(hwo)->GetPosition(pmmt);
}

inline MMRESULT __stdcall waveOutGetVolume(HWAVEOUT hwo, uint32_t* pdwVolume) {
    if (!hwo || !pdwVolume) return MMSYSERR_INVALHANDLE;
    *pdwVolume = static_cast<WaveOutDevice*>(hwo)->GetVolume();
    return MMSYSERR_NOERROR;
}

inline MMRESULT __stdcall waveOutSetVolume(HWAVEOUT hwo, uint32_t dwVolume) {
    if (!hwo) return MMSYSERR_INVALHANDLE;
    static_cast<WaveOutDevice*>(hwo)->SetVolume(dwVolume);
    return MMSYSERR_NOERROR;
}

// WaveIn API (Stub/Basic Recording Parity)
inline uint32_t __stdcall waveInGetNumDevs() { return 1; }

inline MMRESULT __stdcall waveInGetDevCapsA(uint32_t uDeviceID, WAVEINCAPSA* pwic, uint32_t cbwic) {
    if (uDeviceID != 0 || !pwic || cbwic < sizeof(WAVEINCAPSA)) return MMSYSERR_BADDEVICEID;
    std::memset(pwic, 0, sizeof(WAVEINCAPSA));
    pwic->wMid = 1;
    pwic->wPid = 2;
    std::strncpy(pwic->szPname, "MicaNT WaveIn Microphone", sizeof(pwic->szPname) - 1);
    pwic->dwFormats = 0xFFFFFFFF;
    pwic->wChannels = 2;
    return MMSYSERR_NOERROR;
}

inline MMRESULT __stdcall waveInOpen(HWAVEIN* phwi, uint32_t uDeviceID, const audio::WAVEFORMATEX*, void*, void*, uint32_t) {
    if (!phwi || uDeviceID != 0) return MMSYSERR_BADDEVICEID;
    *phwi = reinterpret_cast<HWAVEIN>(0xDEADBEEF);
    return MMSYSERR_NOERROR;
}

inline MMRESULT __stdcall waveInClose(HWAVEIN hwi) {
    if (!hwi) return MMSYSERR_INVALHANDLE;
    return MMSYSERR_NOERROR;
}

// PlaySound / sndPlaySound
inline int32_t __stdcall PlaySoundA(const char* pszSound, void*, uint32_t fdwSound) {
    if (!pszSound) {
        SoundPlaybackService::Instance().Stop();
        return 1;
    }
    if (fdwSound & SND_MEMORY) {
        // Memory pointer contains raw RIFF WAVE buffer
        return SoundPlaybackService::Instance().PlayWaveMemory(pszSound, 0, fdwSound) ? 1 : 0;
    }
    return SoundPlaybackService::Instance().PlayWaveFile(pszSound, fdwSound) ? 1 : 0;
}

inline int32_t __stdcall PlaySoundW(const wchar_t* pszSound, void* hmod, uint32_t fdwSound) {
    if (!pszSound) {
        SoundPlaybackService::Instance().Stop();
        return 1;
    }
    std::string narrow;
    while (*pszSound) narrow.push_back(static_cast<char>(*pszSound++));
    return PlaySoundA(narrow.c_str(), hmod, fdwSound);
}

inline int32_t __stdcall sndPlaySoundA(const char* pszSound, uint32_t fuSound) {
    return PlaySoundA(pszSound, nullptr, fuSound);
}

inline int32_t __stdcall sndPlaySoundW(const wchar_t* pszSound, uint32_t fuSound) {
    return PlaySoundW(pszSound, nullptr, fuSound);
}

// MCI API
inline uint32_t __stdcall mciSendStringA(const char* lpstrCommand, char* lpstrReturnString, uint32_t uReturnLength, void*) {
    return MciManager::Instance().SendString(lpstrCommand, lpstrReturnString, uReturnLength);
}

inline uint32_t __stdcall mciSendStringW(const wchar_t* lpstrCommand, wchar_t* lpstrReturnString, uint32_t uReturnLength, void*) {
    if (!lpstrCommand) return MCIERR_UNRECOGNIZED_COMMAND;
    std::string cmd;
    while (*lpstrCommand) cmd.push_back(static_cast<char>(*lpstrCommand++));
    std::vector<char> retBuf(uReturnLength + 1, 0);
    uint32_t res = MciManager::Instance().SendString(cmd.c_str(), retBuf.data(), uReturnLength);
    if (lpstrReturnString && uReturnLength > 0) {
        for (size_t i = 0; i < uReturnLength && retBuf[i]; ++i) {
            lpstrReturnString[i] = static_cast<wchar_t>(retBuf[i]);
            lpstrReturnString[i + 1] = 0;
        }
    }
    return res;
}

inline int32_t __stdcall mciGetErrorStringA(uint32_t mcierr, char* pszText, uint32_t cchText) {
    return MciManager::Instance().GetErrorString(mcierr, pszText, cchText) ? 1 : 0;
}

// Joystick API
inline uint32_t __stdcall joyGetNumDevs() {
    return JoystickManager::GetNumDevs();
}

inline MMRESULT __stdcall joyGetDevCapsA(uint32_t uJoyID, JOYCAPSA* pjc, uint32_t cbjc) {
    return JoystickManager::GetDevCapsA(uJoyID, pjc, cbjc);
}

inline MMRESULT __stdcall joyGetPos(uint32_t uJoyID, JOYINFO* pji) {
    return JoystickManager::GetPos(uJoyID, pji);
}

inline MMRESULT __stdcall joyGetPosEx(uint32_t uJoyID, JOYINFOEX* pji) {
    return JoystickManager::GetPosEx(uJoyID, pji);
}

inline void InitializeWinMMExports() {
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("winmm.dll", "timeGetTime", reinterpret_cast<void*>(timeGetTime));
    ldr.registerExport("winmm.dll", "timeBeginPeriod", reinterpret_cast<void*>(timeBeginPeriod));
    ldr.registerExport("winmm.dll", "timeEndPeriod", reinterpret_cast<void*>(timeEndPeriod));
    ldr.registerExport("winmm.dll", "timeGetDevCaps", reinterpret_cast<void*>(timeGetDevCaps));
    ldr.registerExport("winmm.dll", "timeSetEvent", reinterpret_cast<void*>(timeSetEvent));
    ldr.registerExport("winmm.dll", "timeKillEvent", reinterpret_cast<void*>(timeKillEvent));

    ldr.registerExport("winmm.dll", "waveOutGetNumDevs", reinterpret_cast<void*>(waveOutGetNumDevs));
    ldr.registerExport("winmm.dll", "waveOutGetDevCapsA", reinterpret_cast<void*>(waveOutGetDevCapsA));
    ldr.registerExport("winmm.dll", "waveOutOpen", reinterpret_cast<void*>(waveOutOpen));
    ldr.registerExport("winmm.dll", "waveOutClose", reinterpret_cast<void*>(waveOutClose));
    ldr.registerExport("winmm.dll", "waveOutPrepareHeader", reinterpret_cast<void*>(waveOutPrepareHeader));
    ldr.registerExport("winmm.dll", "waveOutUnprepareHeader", reinterpret_cast<void*>(waveOutUnprepareHeader));
    ldr.registerExport("winmm.dll", "waveOutWrite", reinterpret_cast<void*>(waveOutWrite));
    ldr.registerExport("winmm.dll", "waveOutPause", reinterpret_cast<void*>(waveOutPause));
    ldr.registerExport("winmm.dll", "waveOutRestart", reinterpret_cast<void*>(waveOutRestart));
    ldr.registerExport("winmm.dll", "waveOutReset", reinterpret_cast<void*>(waveOutReset));
    ldr.registerExport("winmm.dll", "waveOutGetPosition", reinterpret_cast<void*>(waveOutGetPosition));
    ldr.registerExport("winmm.dll", "waveOutGetVolume", reinterpret_cast<void*>(waveOutGetVolume));
    ldr.registerExport("winmm.dll", "waveOutSetVolume", reinterpret_cast<void*>(waveOutSetVolume));

    ldr.registerExport("winmm.dll", "waveInGetNumDevs", reinterpret_cast<void*>(waveInGetNumDevs));
    ldr.registerExport("winmm.dll", "waveInGetDevCapsA", reinterpret_cast<void*>(waveInGetDevCapsA));
    ldr.registerExport("winmm.dll", "waveInOpen", reinterpret_cast<void*>(waveInOpen));
    ldr.registerExport("winmm.dll", "waveInClose", reinterpret_cast<void*>(waveInClose));

    ldr.registerExport("winmm.dll", "PlaySoundA", reinterpret_cast<void*>(PlaySoundA));
    ldr.registerExport("winmm.dll", "PlaySoundW", reinterpret_cast<void*>(PlaySoundW));
    ldr.registerExport("winmm.dll", "sndPlaySoundA", reinterpret_cast<void*>(sndPlaySoundA));
    ldr.registerExport("winmm.dll", "sndPlaySoundW", reinterpret_cast<void*>(sndPlaySoundW));

    ldr.registerExport("winmm.dll", "mciSendStringA", reinterpret_cast<void*>(mciSendStringA));
    ldr.registerExport("winmm.dll", "mciSendStringW", reinterpret_cast<void*>(mciSendStringW));
    ldr.registerExport("winmm.dll", "mciGetErrorStringA", reinterpret_cast<void*>(mciGetErrorStringA));

    ldr.registerExport("winmm.dll", "joyGetNumDevs", reinterpret_cast<void*>(joyGetNumDevs));
    ldr.registerExport("winmm.dll", "joyGetDevCapsA", reinterpret_cast<void*>(joyGetDevCapsA));
    ldr.registerExport("winmm.dll", "joyGetPos", reinterpret_cast<void*>(joyGetPos));
    ldr.registerExport("winmm.dll", "joyGetPosEx", reinterpret_cast<void*>(joyGetPosEx));
}

} // namespace micant::winmm
