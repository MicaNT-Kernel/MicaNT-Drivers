// ============================================================================
// MicaNT: PrismAudio - Sovereign Audio Engine & Microsoft XAudio2 Parity
//
// Named in tribute to Dave Cutler's DEC PRISM RISC project and Windows NT
// multi-channel multimedia architecture.
//
// Strict Clean-Room Implementation in modern ISO C++23.
// Compatible with Microsoft DirectX-Headers / DirectXTK12 Audio specifications.
// ============================================================================

#pragma once

#include "prismx.hpp"
#include "ldr.hpp"
#include <cstdint>
#include <cstddef>
#include <cmath>
#include <vector>
#include <memory>
#include <string>
#include <string_view>
#include <array>
#include <algorithm>
#include <cstring>
#include <mutex>
#include <numbers>

namespace micant::audio {

using namespace micant::prismx;

// ============================================================================
// 1. Audio Formats & Constants
// ============================================================================

inline constexpr uint16_t WAVE_FORMAT_PCM        = 1;
inline constexpr uint16_t WAVE_FORMAT_IEEE_FLOAT = 3;

struct WAVEFORMATEX {
    uint16_t wFormatTag{WAVE_FORMAT_PCM};
    uint16_t nChannels{2};
    uint32_t nSamplesPerSec{48000};
    uint32_t nAvgBytesPerSec{192000};
    uint16_t nBlockAlign{4};
    uint16_t wBitsPerSample{16};
    uint16_t cbSize{0};
};

struct XAUDIO2_BUFFER {
    uint32_t Flags{0};
    uint32_t AudioBytes{0};
    const uint8_t* pAudioData{nullptr};
    uint32_t PlayBegin{0};
    uint32_t PlayLength{0};
    uint32_t LoopBegin{0};
    uint32_t LoopLength{0};
    uint32_t LoopCount{0};
    void* pContext{nullptr};
};

inline constexpr uint32_t XAUDIO2_COMMIT_NOW   = 0;
inline constexpr uint32_t XAUDIO2_LOOP_INFINITE = 255;

struct XAUDIO2_VOICE_STATE {
    void* pCurrentBufferContext{nullptr};
    uint32_t BuffersQueued{0};
    uint64_t SamplesPlayed{0};
};

// Standard GUIDs
inline constexpr IID IID_IXAudio2 = {
    0x2b02e3cf, 0x2e0b, 0x4ec3, { 0xbe, 0x45, 0xca, 0x08, 0xea, 0x82, 0x8c, 0xf6 }
};
inline constexpr IID IID_IXAudio2Voice = {
    0x6e9f168b, 0x4e6d, 0x4eb2, { 0xb2, 0x90, 0x8b, 0xa1, 0x47, 0x0a, 0x7a, 0x36 }
};

// ============================================================================
// 2. 3D Spatial Positional Audio Types
// ============================================================================

struct AudioVector3 {
    float x{0.0f};
    float y{0.0f};
    float z{0.0f};

    constexpr AudioVector3() = default;
    constexpr AudioVector3(float x_, float y_, float z_) : x(x_), y(y_), z(z_) {}

    float Length() const {
        return std::sqrt(x * x + y * y + z * z);
    }
};

struct AudioEmitter {
    AudioVector3 position{0.0f, 0.0f, 0.0f};
    AudioVector3 velocity{0.0f, 0.0f, 0.0f};
    float innerRadius{1.0f};
    float outerRadius{100.0f};
};

struct AudioListener {
    AudioVector3 position{0.0f, 0.0f, 0.0f};
    AudioVector3 velocity{0.0f, 0.0f, 0.0f};
    AudioVector3 forward{0.0f, 0.0f, 1.0f};
    AudioVector3 up{0.0f, 1.0f, 0.0f};
};

// ============================================================================
// 3. COM Interfaces for XAudio2 Parity
// ============================================================================

class IXAudio2Voice {
public:
    virtual void GetVoiceDetails(void* pVoiceDetails) = 0;
    virtual int32_t SetVolume(float Volume, uint32_t OperationSet = 0) = 0;
    virtual void GetVolume(float* pVolume) = 0;
    virtual int32_t SetChannelVolumes(uint32_t Channels, const float* pVolumes, uint32_t OperationSet = 0) = 0;
    virtual void DestroyVoice() = 0;
    virtual ~IXAudio2Voice() = default;
};

class IXAudio2SourceVoice : public IXAudio2Voice {
public:
    virtual int32_t Start(uint32_t Flags = 0, uint32_t OperationSet = 0) = 0;
    virtual int32_t Stop(uint32_t Flags = 0, uint32_t OperationSet = 0) = 0;
    virtual int32_t SubmitSourceBuffer(const XAUDIO2_BUFFER* pBuffer, const void* pBufferWMA = nullptr) = 0;
    virtual int32_t FlushSourceBuffers() = 0;
    virtual int32_t Discontinuity() = 0;
    virtual int32_t ExitLoop(uint32_t OperationSet = 0) = 0;
    virtual void GetState(XAUDIO2_VOICE_STATE* pVoiceState, uint32_t Flags = 0) = 0;
    virtual int32_t SetFrequencyRatio(float Ratio, uint32_t OperationSet = 0) = 0;
    virtual void GetFrequencyRatio(float* pRatio) = 0;
};

class IXAudio2MasteringVoice : public IXAudio2Voice {
public:
    virtual int32_t GetChannelMask(uint32_t* pChannelMask) = 0;
};

class IXAudio2 : public IUnknown {
public:
    virtual int32_t CreateSourceVoice(
        IXAudio2SourceVoice** ppSourceVoice,
        const WAVEFORMATEX* pSourceFormat,
        uint32_t Flags = 0,
        float MaxFrequencyRatio = 2.0f,
        void* pCallback = nullptr
    ) = 0;

    virtual int32_t CreateMasteringVoice(
        IXAudio2MasteringVoice** ppMasteringVoice,
        uint32_t InputChannels = 0,
        uint32_t InputSampleRate = 0,
        uint32_t Flags = 0,
        const wchar_t* szDeviceId = nullptr
    ) = 0;

    virtual int32_t StartEngine() = 0;
    virtual void StopEngine() = 0;
    virtual int32_t CommitChanges(uint32_t OperationSet = 0) = 0;
};

// ============================================================================
// 4. PrismAudio Voice Implementations
// ============================================================================

class PrismAudioSourceVoiceImpl : public IXAudio2SourceVoice {
public:
    PrismAudioSourceVoiceImpl(const WAVEFORMATEX& fmt, float maxRatio)
        : m_format(fmt), m_maxFrequencyRatio(maxRatio) {}

    void GetVoiceDetails(void* pVoiceDetails) override {
        (void)pVoiceDetails;
    }

    int32_t SetVolume(float Volume, uint32_t OperationSet = 0) override {
        (void)OperationSet;
        m_volume = std::clamp(Volume, 0.0f, 16.0f);
        return 0;
    }

    void GetVolume(float* pVolume) override {
        if (pVolume) *pVolume = m_volume;
    }

    int32_t SetChannelVolumes(uint32_t Channels, const float* pVolumes, uint32_t OperationSet = 0) override {
        (void)OperationSet;
        if (!pVolumes || Channels == 0) return -1;
        m_channelVolumes.assign(pVolumes, pVolumes + Channels);
        return 0;
    }

    void DestroyVoice() override {
        m_active = false;
        m_buffers.clear();
    }

    int32_t Start(uint32_t Flags = 0, uint32_t OperationSet = 0) override {
        (void)Flags;
        (void)OperationSet;
        m_playing = true;
        return 0;
    }

    int32_t Stop(uint32_t Flags = 0, uint32_t OperationSet = 0) override {
        (void)Flags;
        (void)OperationSet;
        m_playing = false;
        return 0;
    }

    int32_t SubmitSourceBuffer(const XAUDIO2_BUFFER* pBuffer, const void* pBufferWMA = nullptr) override {
        (void)pBufferWMA;
        if (!pBuffer || !pBuffer->pAudioData || pBuffer->AudioBytes == 0) return -1;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_buffers.push_back(*pBuffer);
        return 0;
    }

    int32_t FlushSourceBuffers() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_buffers.clear();
        m_currentBufferIndex = 0;
        m_currentSampleOffset = 0;
        return 0;
    }

    int32_t Discontinuity() override {
        return 0;
    }

    int32_t ExitLoop(uint32_t OperationSet = 0) override {
        (void)OperationSet;
        m_exitLoopRequested = true;
        return 0;
    }

    void GetState(XAUDIO2_VOICE_STATE* pVoiceState, uint32_t Flags = 0) override {
        (void)Flags;
        if (!pVoiceState) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        pVoiceState->BuffersQueued = static_cast<uint32_t>(m_buffers.size() - m_currentBufferIndex);
        pVoiceState->SamplesPlayed = m_totalSamplesPlayed;
        if (m_currentBufferIndex < m_buffers.size()) {
            pVoiceState->pCurrentBufferContext = m_buffers[m_currentBufferIndex].pContext;
        } else {
            pVoiceState->pCurrentBufferContext = nullptr;
        }
    }

    int32_t SetFrequencyRatio(float Ratio, uint32_t OperationSet = 0) override {
        (void)OperationSet;
        m_frequencyRatio = std::clamp(Ratio, 0.1f, m_maxFrequencyRatio);
        return 0;
    }

    void GetFrequencyRatio(float* pRatio) override {
        if (pRatio) *pRatio = m_frequencyRatio;
    }

    bool IsPlaying() const { return m_playing && m_active; }
    const WAVEFORMATEX& GetFormat() const { return m_format; }

    // Renders audio frames into a float destination buffer (stereo interleaved)
    void MixInto(float* outputStereo, uint32_t frameCount, uint32_t targetSampleRate) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_playing || m_currentBufferIndex >= m_buffers.size()) return;

        float effectiveRatio = (static_cast<float>(m_format.nSamplesPerSec) / static_cast<float>(targetSampleRate)) * m_frequencyRatio;

        for (uint32_t f = 0; f < frameCount; ++f) {
            if (m_currentBufferIndex >= m_buffers.size()) break;

            const auto& curBuf = m_buffers[m_currentBufferIndex];
            size_t bytesPerFrame = (m_format.wBitsPerSample / 8) * m_format.nChannels;
            size_t totalFrames = curBuf.AudioBytes / bytesPerFrame;

            size_t frameIndex = static_cast<size_t>(m_currentSampleOffset);
            if (frameIndex >= totalFrames) {
                // Move to next buffer or handle loop
                if (curBuf.LoopCount > 0 && !m_exitLoopRequested) {
                    m_currentSampleOffset = curBuf.LoopBegin;
                    frameIndex = curBuf.LoopBegin;
                } else {
                    m_currentBufferIndex++;
                    m_currentSampleOffset = 0;
                    if (m_currentBufferIndex >= m_buffers.size()) break;
                    continue;
                }
            }

            // Read sample
            float leftSample = 0.0f;
            float rightSample = 0.0f;

            if (m_format.wBitsPerSample == 16) {
                const int16_t* pcm = reinterpret_cast<const int16_t*>(curBuf.pAudioData);
                if (m_format.nChannels == 1) {
                    float s = pcm[frameIndex] / 32768.0f;
                    leftSample = s;
                    rightSample = s;
                } else {
                    leftSample = pcm[frameIndex * 2 + 0] / 32768.0f;
                    rightSample = pcm[frameIndex * 2 + 1] / 32768.0f;
                }
            } else if (m_format.wBitsPerSample == 32 && m_format.wFormatTag == WAVE_FORMAT_IEEE_FLOAT) {
                const float* pcm = reinterpret_cast<const float*>(curBuf.pAudioData);
                if (m_format.nChannels == 1) {
                    leftSample = pcm[frameIndex];
                    rightSample = pcm[frameIndex];
                } else {
                    leftSample = pcm[frameIndex * 2 + 0];
                    rightSample = pcm[frameIndex * 2 + 1];
                }
            }

            // Apply volume & panning
            float leftVol = m_volume;
            float rightVol = m_volume;
            if (m_channelVolumes.size() >= 2) {
                leftVol *= m_channelVolumes[0];
                rightVol *= m_channelVolumes[1];
            }

            outputStereo[f * 2 + 0] += leftSample * leftVol;
            outputStereo[f * 2 + 1] += rightSample * rightVol;

            m_currentSampleOffset += effectiveRatio;
            m_totalSamplesPlayed++;
        }
    }

private:
    std::mutex m_mutex;
    WAVEFORMATEX m_format;
    float m_maxFrequencyRatio{2.0f};
    float m_frequencyRatio{1.0f};
    float m_volume{1.0f};
    std::vector<float> m_channelVolumes{1.0f, 1.0f};
    std::vector<XAUDIO2_BUFFER> m_buffers;
    size_t m_currentBufferIndex{0};
    double m_currentSampleOffset{0.0};
    uint64_t m_totalSamplesPlayed{0};
    bool m_playing{false};
    bool m_active{true};
    bool m_exitLoopRequested{false};
};

class PrismAudioMasteringVoiceImpl : public IXAudio2MasteringVoice {
public:
    PrismAudioMasteringVoiceImpl(uint32_t channels, uint32_t sampleRate)
        : m_channels(channels ? channels : 2), m_sampleRate(sampleRate ? sampleRate : 48000) {}

    void GetVoiceDetails(void* pVoiceDetails) override {
        (void)pVoiceDetails;
    }

    int32_t SetVolume(float Volume, uint32_t OperationSet = 0) override {
        (void)OperationSet;
        m_volume = std::clamp(Volume, 0.0f, 4.0f);
        return 0;
    }

    void GetVolume(float* pVolume) override {
        if (pVolume) *pVolume = m_volume;
    }

    int32_t SetChannelVolumes(uint32_t Channels, const float* pVolumes, uint32_t OperationSet = 0) override {
        (void)Channels;
        (void)pVolumes;
        (void)OperationSet;
        return 0;
    }

    void DestroyVoice() override {}

    int32_t GetChannelMask(uint32_t* pChannelMask) override {
        if (pChannelMask) *pChannelMask = 0x3; // SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT
        return 0;
    }

    uint32_t GetChannels() const { return m_channels; }
    uint32_t GetSampleRate() const { return m_sampleRate; }
    float GetMasterVolume() const { return m_volume; }

private:
    uint32_t m_channels{2};
    uint32_t m_sampleRate{48000};
    float m_volume{1.0f};
};

// ============================================================================
// 5. PrismAudioEngineImpl & Software Mixer
// ============================================================================

class PrismAudioEngineImpl : public IXAudio2 {
public:
    PrismAudioEngineImpl() = default;
    ~PrismAudioEngineImpl() override = default;

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return -1;
        if (riid == IID_IUnknown || riid == IID_IXAudio2) {
            *ppvObject = static_cast<IXAudio2*>(this);
            AddRef();
            return 0;
        }
        *ppvObject = nullptr;
        return -2147467262; // E_NOINTERFACE
    }

    uint32_t AddRef() override {
        return ++m_refCount;
    }

    uint32_t Release() override {
        uint32_t res = --m_refCount;
        if (res == 0) {
            delete this;
        }
        return res;
    }

    int32_t CreateSourceVoice(
        IXAudio2SourceVoice** ppSourceVoice,
        const WAVEFORMATEX* pSourceFormat,
        uint32_t Flags = 0,
        float MaxFrequencyRatio = 2.0f,
        void* pCallback = nullptr
    ) override {
        (void)Flags;
        (void)pCallback;
        if (!ppSourceVoice || !pSourceFormat) return -1;

        auto voice = std::make_unique<PrismAudioSourceVoiceImpl>(*pSourceFormat, MaxFrequencyRatio);
        std::lock_guard<std::mutex> lock(m_mutex);
        *ppSourceVoice = voice.get();
        m_sourceVoices.push_back(std::move(voice));
        return 0;
    }

    int32_t CreateMasteringVoice(
        IXAudio2MasteringVoice** ppMasteringVoice,
        uint32_t InputChannels = 0,
        uint32_t InputSampleRate = 0,
        uint32_t Flags = 0,
        const wchar_t* szDeviceId = nullptr
    ) override {
        (void)Flags;
        (void)szDeviceId;
        if (!ppMasteringVoice) return -1;

        auto master = std::make_unique<PrismAudioMasteringVoiceImpl>(InputChannels, InputSampleRate);
        std::lock_guard<std::mutex> lock(m_mutex);
        *ppMasteringVoice = master.get();
        m_masteringVoice = std::move(master);
        return 0;
    }

    int32_t StartEngine() override {
        m_engineRunning = true;
        return 0;
    }

    void StopEngine() override {
        m_engineRunning = false;
    }

    int32_t CommitChanges(uint32_t OperationSet = 0) override {
        (void)OperationSet;
        return 0;
    }

    /**
     * @brief Mixes one cycle of audio from all active voices into an output buffer.
     * @param frameCount Number of stereo frames to mix.
     * @param outStereo Interleaved stereo PCM output (floats in range [-1.0, 1.0]).
     */
    void ProcessMixingCycle(uint32_t frameCount, std::vector<float>& outStereo) {
        std::lock_guard<std::mutex> lock(m_mutex);
        outStereo.assign(frameCount * 2, 0.0f);
        if (!m_engineRunning || !m_masteringVoice) return;

        uint32_t sampleRate = m_masteringVoice->GetSampleRate();
        float masterVol = m_masteringVoice->GetMasterVolume();

        for (auto& voice : m_sourceVoices) {
            if (voice->IsPlaying()) {
                voice->MixInto(outStereo.data(), frameCount, sampleRate);
            }
        }

        // Apply master volume and soft limiting
        for (float& sample : outStereo) {
            sample *= masterVol;
            // Soft clipping (tanh approximation: x / (1 + |x|))
            sample = sample / (1.0f + std::abs(sample));
        }
    }

    // ========================================================================
    // 6. Built-in Procedural Audio Synthesizer & Spatial Math
    // ========================================================================

    enum class ToneType {
        Sine,
        Square,
        Triangle,
        Sawtooth,
        Noise
    };

    /**
     * @brief Generates a procedural 16-bit PCM waveform buffer.
     */
    static std::vector<uint8_t> SynthesizeTone(
        ToneType tone,
        float freqHz,
        float durationSec,
        uint32_t sampleRate = 48000,
        float amplitude = 0.5f
    ) {
        size_t totalSamples = static_cast<size_t>(durationSec * sampleRate);
        std::vector<uint8_t> buffer(totalSamples * sizeof(int16_t));
        int16_t* pcm = reinterpret_cast<int16_t*>(buffer.data());

        float phase = 0.0f;
        float phaseInc = (2.0f * std::numbers::pi_v<float> * freqHz) / static_cast<float>(sampleRate);

        for (size_t i = 0; i < totalSamples; ++i) {
            float val = 0.0f;
            switch (tone) {
                case ToneType::Sine:
                    val = std::sin(phase);
                    break;
                case ToneType::Square:
                    val = (std::sin(phase) >= 0.0f) ? 1.0f : -1.0f;
                    break;
                case ToneType::Triangle:
                    val = (2.0f / std::numbers::pi_v<float>)* std::asin(std::sin(phase));
                    break;
                case ToneType::Sawtooth:
                    val = (2.0f * (phase / (2.0f * std::numbers::pi_v<float>))) - 1.0f;
                    break;
                case ToneType::Noise:
                    val = (static_cast<float>(rand()) / static_cast<float>(RAND_MAX)) * 2.0f - 1.0f;
                    break;
            }

            pcm[i] = static_cast<int16_t>(std::clamp(val * amplitude, -1.0f, 1.0f) * 32767.0f);
            phase += phaseInc;
            if (phase >= 2.0f * std::numbers::pi_v<float>) {
                phase -= 2.0f * std::numbers::pi_v<float>;
            }
        }

        return buffer;
    }

    /**
     * @brief Computes 3D spatial attenuation and stereo panning factors.
     */
    static void Calculate3DSpatial(
        const AudioListener& listener,
        const AudioEmitter& emitter,
        float& outVolumeFactor,
        float& outPanLeft,
        float& outPanRight
    ) {
        float dx = emitter.position.x - listener.position.x;
        float dy = emitter.position.y - listener.position.y;
        float dz = emitter.position.z - listener.position.z;
        float dist = std::sqrt(dx * dx + dy * dy + dz * dz);

        // Inverse distance falloff
        if (dist <= emitter.innerRadius) {
            outVolumeFactor = 1.0f;
        } else if (dist >= emitter.outerRadius) {
            outVolumeFactor = 0.0f;
        } else {
            outVolumeFactor = emitter.innerRadius / (emitter.innerRadius + (dist - emitter.innerRadius));
        }

        // Stereo pan based on relative X position
        float horizDist = std::sqrt(dx * dx + dz * dz);
        float pan = 0.0f;
        if (horizDist > 0.001f) {
            pan = std::clamp(dx / horizDist, -1.0f, 1.0f);
        }

        outPanLeft  = std::sqrt(0.5f * (1.0f - pan));
        outPanRight = std::sqrt(0.5f * (1.0f + pan));
    }

private:
    std::atomic<uint32_t> m_refCount{1};
    std::mutex m_mutex;
    bool m_engineRunning{true};
    std::unique_ptr<PrismAudioMasteringVoiceImpl> m_masteringVoice;
    std::vector<std::unique_ptr<PrismAudioSourceVoiceImpl>> m_sourceVoices;
};

// ============================================================================
// 7. Dynamic Loader Export Registration
// ============================================================================

inline int32_t XAudio2Create(IXAudio2** ppXAudio2, uint32_t Flags = 0, uint32_t XAudio2Processor = 0) {
    (void)Flags;
    (void)XAudio2Processor;
    if (!ppXAudio2) return -1;
    auto engine = new PrismAudioEngineImpl();
    *ppXAudio2 = engine;
    return 0;
}

inline void InitializeAudioSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // Export XAudio2Create in xaudio2_9.dll and xaudio2_8.dll
    ldr.registerExport("xaudio2_9.dll", "XAudio2Create", reinterpret_cast<void*>(&XAudio2Create));
    ldr.registerExport("xaudio2_8.dll", "XAudio2Create", reinterpret_cast<void*>(&XAudio2Create));
}

} // namespace micant::audio

namespace micant::prismaudio {
    using namespace micant::audio;
}
