// ============================================================================
// MicaNT: VectorHID - Sovereign Game Controller & Input Subsystem (xinput1_4.dll)
//
// Clean-Room Implementation in modern ISO C++23.
// Compatible with Microsoft XInput specifications and DirectXTK12 GamePad.
// ============================================================================

#pragma once

#include "ldr.hpp"
#include <cstdint>
#include <cstring>
#include <array>
#include <mutex>
#include <algorithm>
#include <cmath>

namespace micant::hid {

// ============================================================================
// 1. Constants & Bitmasks
// ============================================================================

inline constexpr uint16_t XINPUT_GAMEPAD_DPAD_UP        = 0x0001;
inline constexpr uint16_t XINPUT_GAMEPAD_DPAD_DOWN      = 0x0002;
inline constexpr uint16_t XINPUT_GAMEPAD_DPAD_LEFT      = 0x0004;
inline constexpr uint16_t XINPUT_GAMEPAD_DPAD_RIGHT     = 0x0008;
inline constexpr uint16_t XINPUT_GAMEPAD_START          = 0x0010;
inline constexpr uint16_t XINPUT_GAMEPAD_BACK           = 0x0020;
inline constexpr uint16_t XINPUT_GAMEPAD_LEFT_THUMB     = 0x0040;
inline constexpr uint16_t XINPUT_GAMEPAD_RIGHT_THUMB    = 0x0080;
inline constexpr uint16_t XINPUT_GAMEPAD_LEFT_SHOULDER  = 0x0100;
inline constexpr uint16_t XINPUT_GAMEPAD_RIGHT_SHOULDER = 0x0200;
inline constexpr uint16_t XINPUT_GAMEPAD_A              = 0x1000;
inline constexpr uint16_t XINPUT_GAMEPAD_B              = 0x2000;
inline constexpr uint16_t XINPUT_GAMEPAD_X              = 0x4000;
inline constexpr uint16_t XINPUT_GAMEPAD_Y              = 0x8000;

inline constexpr int16_t XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE  = 7849;
inline constexpr int16_t XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE = 8689;
inline constexpr uint8_t XINPUT_GAMEPAD_TRIGGER_THRESHOLD    = 30;

inline constexpr uint8_t XINPUT_DEVTYPE_GAMEPAD       = 0x01;
inline constexpr uint8_t XINPUT_DEVSUBTYPE_GAMEPAD    = 0x01;
inline constexpr uint16_t XINPUT_CAPS_VOICE_SUPPORTED = 0x0004;

inline constexpr uint32_t ERROR_SUCCESS               = 0;
inline constexpr uint32_t ERROR_DEVICE_NOT_CONNECTED  = 1167;
inline constexpr uint32_t ERROR_INVALID_PARAMETER     = 87;

// ============================================================================
// 2. XInput Data Structures
// ============================================================================

struct XINPUT_GAMEPAD {
    uint16_t wButtons{0};
    uint8_t  bLeftTrigger{0};
    uint8_t  bRightTrigger{0};
    int16_t  sThumbLX{0};
    int16_t  sThumbLY{0};
    int16_t  sThumbRX{0};
    int16_t  sThumbRY{0};
};

struct XINPUT_STATE {
    uint32_t dwPacketNumber{0};
    XINPUT_GAMEPAD Gamepad{};
};

struct XINPUT_VIBRATION {
    uint16_t wLeftMotorSpeed{0};
    uint16_t wRightMotorSpeed{0};
};

struct XINPUT_CAPABILITIES {
    uint8_t  Type{XINPUT_DEVTYPE_GAMEPAD};
    uint8_t  SubType{XINPUT_DEVSUBTYPE_GAMEPAD};
    uint16_t Flags{0};
    XINPUT_GAMEPAD Gamepad{};
    XINPUT_VIBRATION Vibration{};
};

// ============================================================================
// 3. VectorControllerManager
// ============================================================================

class VectorControllerManager {
public:
    static VectorControllerManager& get() {
        static VectorControllerManager instance;
        return instance;
    }

    VectorControllerManager() {
        // Default: Slot 0 connected
        m_slots[0].connected = true;
    }

    uint32_t GetState(uint32_t userIndex, XINPUT_STATE* pState) {
        if (userIndex >= 4) return ERROR_DEVICE_NOT_CONNECTED;
        if (!pState) return ERROR_INVALID_PARAMETER;

        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_slots[userIndex].connected) {
            return ERROR_DEVICE_NOT_CONNECTED;
        }

        *pState = m_slots[userIndex].state;
        return ERROR_SUCCESS;
    }

    uint32_t SetState(uint32_t userIndex, const XINPUT_VIBRATION* pVibration) {
        if (userIndex >= 4) return ERROR_DEVICE_NOT_CONNECTED;
        if (!pVibration) return ERROR_INVALID_PARAMETER;

        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_slots[userIndex].connected) {
            return ERROR_DEVICE_NOT_CONNECTED;
        }

        m_slots[userIndex].vibration = *pVibration;
        return ERROR_SUCCESS;
    }

    uint32_t GetCapabilities(uint32_t userIndex, uint32_t dwFlags, XINPUT_CAPABILITIES* pCapabilities) {
        (void)dwFlags;
        if (userIndex >= 4) return ERROR_DEVICE_NOT_CONNECTED;
        if (!pCapabilities) return ERROR_INVALID_PARAMETER;

        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_slots[userIndex].connected) {
            return ERROR_DEVICE_NOT_CONNECTED;
        }

        pCapabilities->Type = XINPUT_DEVTYPE_GAMEPAD;
        pCapabilities->SubType = XINPUT_DEVSUBTYPE_GAMEPAD;
        pCapabilities->Flags = XINPUT_CAPS_VOICE_SUPPORTED;
        pCapabilities->Gamepad.wButtons = 0xFFFF;
        pCapabilities->Gamepad.bLeftTrigger = 255;
        pCapabilities->Gamepad.bRightTrigger = 255;
        pCapabilities->Gamepad.sThumbLX = 32767;
        pCapabilities->Gamepad.sThumbLY = 32767;
        pCapabilities->Gamepad.sThumbRX = 32767;
        pCapabilities->Gamepad.sThumbRY = 32767;
        pCapabilities->Vibration.wLeftMotorSpeed = 65535;
        pCapabilities->Vibration.wRightMotorSpeed = 65535;

        return ERROR_SUCCESS;
    }

    // Programmatic test & simulation helpers
    void SetSlotConnected(uint32_t userIndex, bool connected) {
        if (userIndex < 4) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_slots[userIndex].connected = connected;
        }
    }

    void SetSlotState(uint32_t userIndex, const XINPUT_GAMEPAD& pad) {
        if (userIndex < 4) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_slots[userIndex].state.dwPacketNumber++;
            m_slots[userIndex].state.Gamepad = pad;
        }
    }

    XINPUT_VIBRATION GetSlotVibration(uint32_t userIndex) {
        if (userIndex < 4) {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_slots[userIndex].vibration;
        }
        return {};
    }

    /**
     * @brief Deadzone normalization for analog thumbstick input.
     */
    static void NormalizeThumbstick(
        int16_t rawX,
        int16_t rawY,
        int16_t deadzone,
        float& outX,
        float& outY
    ) {
        float fx = static_cast<float>(rawX);
        float fy = static_cast<float>(rawY);
        float mag = std::sqrt(fx * fx + fy * fy);

        if (mag > deadzone) {
            if (mag > 32767.0f) mag = 32767.0f;
            mag -= deadzone;
            float normMag = mag / (32767.0f - deadzone);
            outX = (fx / (mag + deadzone)) * normMag;
            outY = (fy / (mag + deadzone)) * normMag;
        } else {
            outX = 0.0f;
            outY = 0.0f;
        }
    }

private:
    struct Slot {
        bool connected{false};
        XINPUT_STATE state{};
        XINPUT_VIBRATION vibration{};
    };

    std::mutex m_mutex;
    std::array<Slot, 4> m_slots{};
};

// ============================================================================
// 4. C Function Exports
// ============================================================================

inline uint32_t XInputGetState(uint32_t dwUserIndex, XINPUT_STATE* pState) {
    return VectorControllerManager::get().GetState(dwUserIndex, pState);
}

inline uint32_t XInputSetState(uint32_t dwUserIndex, XINPUT_VIBRATION* pVibration) {
    return VectorControllerManager::get().SetState(dwUserIndex, pVibration);
}

inline uint32_t XInputGetCapabilities(uint32_t dwUserIndex, uint32_t dwFlags, XINPUT_CAPABILITIES* pCapabilities) {
    return VectorControllerManager::get().GetCapabilities(dwUserIndex, dwFlags, pCapabilities);
}

inline void XInputEnable(int32_t enable) {
    (void)enable;
}

inline void InitializeInputSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    for (const char* dll : { "xinput1_4.dll", "xinput1_3.dll", "xinput9_1_0.dll" }) {
        ldr.registerExport(dll, "XInputGetState", reinterpret_cast<void*>(&XInputGetState));
        ldr.registerExport(dll, "XInputSetState", reinterpret_cast<void*>(&XInputSetState));
        ldr.registerExport(dll, "XInputGetCapabilities", reinterpret_cast<void*>(&XInputGetCapabilities));
        ldr.registerExport(dll, "XInputEnable", reinterpret_cast<void*>(&XInputEnable));
    }
}

} // namespace micant::hid

namespace micant::xinput {
    using namespace micant::hid;
}
