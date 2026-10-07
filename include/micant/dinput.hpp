// ============================================================================
// MicaNT: PrismInput - DirectInput 8 Subsystem (dinput8.dll)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Compatible with Microsoft DirectInput 8 specifications and game input loops.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <memory>
#include <mutex>
#include <atomic>
#include "ntdef.hpp"
#include "prismx.hpp"
#include "ldr.hpp"

namespace micant::dinput {

using namespace micant::prismx;

// ============================================================================
// 1. DirectInput 8 Constants & GUIDs
// ============================================================================

inline constexpr uint32_t DIRECTINPUT_VERSION = 0x0800;

inline constexpr int32_t DI_OK                 = 0;
inline constexpr int32_t DIERR_NOTINITIALIZED   = -2147024891; // 0x80070005
inline constexpr int32_t DIERR_INVALIDPARAM     = -2147024809; // 0x80070057
inline constexpr int32_t DIERR_NOTACQUIRED      = -2147024866; // 0x8007001E
inline constexpr int32_t DIERR_OTHERAPPHASPRIO  = -2147024891;
inline constexpr int32_t DIERR_DEVICEFULL       = -2147024784;

// Cooperative Levels
inline constexpr uint32_t DISCL_EXCLUSIVE    = 0x00000001;
inline constexpr uint32_t DISCL_NONEXCLUSIVE = 0x00000002;
inline constexpr uint32_t DISCL_FOREGROUND   = 0x00000004;
inline constexpr uint32_t DISCL_BACKGROUND   = 0x00000008;
inline constexpr uint32_t DISCL_NOWINKEY     = 0x00000010;

// Device Types
inline constexpr uint32_t DI8DEVCLASS_ALL      = 0;
inline constexpr uint32_t DI8DEVCLASS_DEVICE   = 1;
inline constexpr uint32_t DI8DEVCLASS_POINTER  = 2;
inline constexpr uint32_t DI8DEVCLASS_KEYBOARD = 3;
inline constexpr uint32_t DI8DEVCLASS_GAMECTRL = 4;

inline constexpr uint32_t DI8DEVTYPE_MOUSE    = 0x12;
inline constexpr uint32_t DI8DEVTYPE_KEYBOARD = 0x13;
inline constexpr uint32_t DI8DEVTYPE_JOYSTICK = 0x14;
inline constexpr uint32_t DI8DEVTYPE_GAMEPAD  = 0x15;

// DirectInput COM Interface GUIDs
inline constexpr GUID CLSID_DirectInput8 = {
    0x25E609E4, 0xB259, 0x11CF, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 }
};

inline constexpr IID IID_IDirectInput8W = {
    0xBF7988D0, 0x480D, 0x4A60, { 0xB2, 0x24, 0x2E, 0x36, 0x8C, 0x64, 0x98, 0x28 }
};

inline constexpr IID IID_IDirectInputDevice8W = {
    0x54524EA4, 0xB482, 0x497F, { 0x8C, 0x8F, 0x59, 0x82, 0x38, 0xB6, 0xB8, 0x93 }
};

inline constexpr GUID GUID_SysMouse = {
    0x6F1D2B60, 0xD5A0, 0x11CF, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 }
};

inline constexpr GUID GUID_SysKeyboard = {
    0x6F1D2B61, 0xD5A0, 0x11CF, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 }
};

// ============================================================================
// 2. DirectInput Structures
// ============================================================================

struct DIMOUSESTATE {
    int32_t lX{0};
    int32_t lY{0};
    int32_t lZ{0};
    uint8_t rgbButtons[4]{};
};

struct DIMOUSESTATE2 {
    int32_t lX{0};
    int32_t lY{0};
    int32_t lZ{0};
    uint8_t rgbButtons[8]{};
};

struct DIOBJECTDATAFORMAT {
    const GUID* pguid{nullptr};
    uint32_t    dwOfs{0};
    uint32_t    dwType{0};
    uint32_t    dwFlags{0};
};

struct DIDATAFORMAT {
    uint32_t dwSize{sizeof(DIDATAFORMAT)};
    uint32_t dwObjSize{sizeof(DIOBJECTDATAFORMAT)};
    uint32_t dwFlags{0};
    uint32_t dwDataSize{0};
    uint32_t dwNumObjs{0};
    DIOBJECTDATAFORMAT* rgodf{nullptr};
};

struct DIDEVICEINSTANCEW {
    uint32_t dwSize{sizeof(DIDEVICEINSTANCEW)};
    GUID     guidInstance{};
    GUID     guidProduct{};
    uint32_t dwDevType{0};
    wchar_t  tszInstanceName[260]{};
    wchar_t  tszProductName[260]{};
    GUID     guidFFDriver{};
    uint16_t wUsagePage{0};
    uint16_t wUsage{0};
};

// ============================================================================
// 3. COM Interface Declarations
// ============================================================================

class IDirectInputDevice8W : public IUnknown {
public:
    virtual int32_t SetCooperativeLevel(void* hwnd, uint32_t dwFlags) = 0;
    virtual int32_t SetDataFormat(const DIDATAFORMAT* lpdf) = 0;
    virtual int32_t Acquire() = 0;
    virtual int32_t Unacquire() = 0;
    virtual int32_t GetDeviceState(uint32_t cbData, void* lpvData) = 0;
    virtual int32_t Poll() = 0;
};

class IDirectInput8W : public IUnknown {
public:
    virtual int32_t CreateDevice(const GUID& rguid, IDirectInputDevice8W** lplpDirectInputDevice, IUnknown* pUnkOuter) = 0;
    virtual int32_t EnumDevices(uint32_t dwDevType, void* lpCallback, void* pvRef, uint32_t dwFlags) = 0;
};

// ============================================================================
// 4. Device Implementations: Mouse & Keyboard
// ============================================================================

class DirectInputMouseDevice : public IDirectInputDevice8W {
public:
    DirectInputMouseDevice() = default;

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return DIERR_INVALIDPARAM;
        if (riid == IID_IUnknown || riid == IID_IDirectInputDevice8W) {
            *ppvObject = static_cast<IDirectInputDevice8W*>(this);
            AddRef();
            return DI_OK;
        }
        *ppvObject = nullptr;
        return -2147467262; // E_NOINTERFACE
    }

    uint32_t AddRef() override { return ++refCount_; }
    uint32_t Release() override {
        uint32_t c = --refCount_;
        if (c == 0) delete this;
        return c;
    }

    int32_t SetCooperativeLevel(void* /*hwnd*/, uint32_t /*dwFlags*/) override {
        return DI_OK;
    }

    int32_t SetDataFormat(const DIDATAFORMAT* lpdf) override {
        if (!lpdf) return DIERR_INVALIDPARAM;
        dataFormatSize_ = lpdf->dwDataSize;
        return DI_OK;
    }

    int32_t Acquire() override {
        acquired_ = true;
        return DI_OK;
    }

    int32_t Unacquire() override {
        acquired_ = false;
        return DI_OK;
    }

    int32_t Poll() override {
        return DI_OK;
    }

    int32_t GetDeviceState(uint32_t cbData, void* lpvData) override {
        if (!lpvData) return DIERR_INVALIDPARAM;
        if (!acquired_) return DIERR_NOTACQUIRED;

        std::lock_guard<std::mutex> lock(mutex_);
        if (cbData >= sizeof(DIMOUSESTATE2)) {
            auto* pState2 = reinterpret_cast<DIMOUSESTATE2*>(lpvData);
            *pState2 = state2_;
        } else if (cbData >= sizeof(DIMOUSESTATE)) {
            auto* pState = reinterpret_cast<DIMOUSESTATE*>(lpvData);
            pState->lX = state2_.lX;
            pState->lY = state2_.lY;
            pState->lZ = state2_.lZ;
            std::memcpy(pState->rgbButtons, state2_.rgbButtons, 4);
        } else {
            return DIERR_INVALIDPARAM;
        }

        // Relative axis deltas clear upon read
        state2_.lX = 0;
        state2_.lY = 0;
        state2_.lZ = 0;
        return DI_OK;
    }

    void injectMotion(int32_t dx, int32_t dy, int32_t dz) {
        std::lock_guard<std::mutex> lock(mutex_);
        state2_.lX += dx;
        state2_.lY += dy;
        state2_.lZ += dz;
    }

    void injectButton(uint8_t buttonIndex, bool isDown) {
        if (buttonIndex < 8) {
            std::lock_guard<std::mutex> lock(mutex_);
            state2_.rgbButtons[buttonIndex] = isDown ? 0x80 : 0x00;
        }
    }

private:
    std::atomic<uint32_t> refCount_{1};
    std::atomic<bool> acquired_{false};
    uint32_t dataFormatSize_{sizeof(DIMOUSESTATE)};
    std::mutex mutex_;
    DIMOUSESTATE2 state2_{};
};

class DirectInputKeyboardDevice : public IDirectInputDevice8W {
public:
    DirectInputKeyboardDevice() = default;

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return DIERR_INVALIDPARAM;
        if (riid == IID_IUnknown || riid == IID_IDirectInputDevice8W) {
            *ppvObject = static_cast<IDirectInputDevice8W*>(this);
            AddRef();
            return DI_OK;
        }
        *ppvObject = nullptr;
        return -2147467262; // E_NOINTERFACE
    }

    uint32_t AddRef() override { return ++refCount_; }
    uint32_t Release() override {
        uint32_t c = --refCount_;
        if (c == 0) delete this;
        return c;
    }

    int32_t SetCooperativeLevel(void* /*hwnd*/, uint32_t /*dwFlags*/) override {
        return DI_OK;
    }

    int32_t SetDataFormat(const DIDATAFORMAT* /*lpdf*/) override {
        return DI_OK;
    }

    int32_t Acquire() override {
        acquired_ = true;
        return DI_OK;
    }

    int32_t Unacquire() override {
        acquired_ = false;
        return DI_OK;
    }

    int32_t Poll() override {
        return DI_OK;
    }

    int32_t GetDeviceState(uint32_t cbData, void* lpvData) override {
        if (!lpvData) return DIERR_INVALIDPARAM;
        if (!acquired_) return DIERR_NOTACQUIRED;
        if (cbData < 256) return DIERR_INVALIDPARAM;

        std::lock_guard<std::mutex> lock(mutex_);
        std::memcpy(lpvData, keyBuffer_.data(), 256);
        return DI_OK;
    }

    void injectKey(uint8_t scanCode, bool isDown) {
        std::lock_guard<std::mutex> lock(mutex_);
        keyBuffer_[scanCode] = isDown ? 0x80 : 0x00;
    }

private:
    std::atomic<uint32_t> refCount_{1};
    std::atomic<bool> acquired_{false};
    std::mutex mutex_;
    std::array<uint8_t, 256> keyBuffer_{};
};

// ============================================================================
// 5. DirectInput8 System Root Object
// ============================================================================

class DirectInput8Impl : public IDirectInput8W {
public:
    DirectInput8Impl() = default;

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return DIERR_INVALIDPARAM;
        if (riid == IID_IUnknown || riid == IID_IDirectInput8W) {
            *ppvObject = static_cast<IDirectInput8W*>(this);
            AddRef();
            return DI_OK;
        }
        *ppvObject = nullptr;
        return -2147467262; // E_NOINTERFACE
    }

    uint32_t AddRef() override { return ++refCount_; }
    uint32_t Release() override {
        uint32_t c = --refCount_;
        if (c == 0) delete this;
        return c;
    }

    int32_t CreateDevice(const GUID& rguid, IDirectInputDevice8W** lplpDirectInputDevice, IUnknown* /*pUnkOuter*/) override {
        if (!lplpDirectInputDevice) return DIERR_INVALIDPARAM;

        if (rguid == GUID_SysMouse) {
            *lplpDirectInputDevice = new DirectInputMouseDevice();
            return DI_OK;
        }

        if (rguid == GUID_SysKeyboard) {
            *lplpDirectInputDevice = new DirectInputKeyboardDevice();
            return DI_OK;
        }

        *lplpDirectInputDevice = nullptr;
        return DIERR_NOTINITIALIZED;
    }

    int32_t EnumDevices(uint32_t /*dwDevType*/, void* /*lpCallback*/, void* /*pvRef*/, uint32_t /*dwFlags*/) override {
        return DI_OK;
    }

private:
    std::atomic<uint32_t> refCount_{1};
};

// ============================================================================
// 6. DirectInput8 Factory API & Subsystem Exports
// ============================================================================

inline int32_t DirectInput8Create(
    void* /*hinst*/,
    uint32_t dwVersion,
    const IID& riidltf,
    void** ppvOut,
    IUnknown* /*punkOuter*/
) noexcept {
    if (!ppvOut) return DIERR_INVALIDPARAM;
    if (dwVersion < DIRECTINPUT_VERSION) return DIERR_NOTINITIALIZED;

    if (riidltf == IID_IDirectInput8W || riidltf == IID_IUnknown) {
        auto* pDI = new DirectInput8Impl();
        *ppvOut = static_cast<IDirectInput8W*>(pDI);
        return DI_OK;
    }

    *ppvOut = nullptr;
    return -2147467262; // E_NOINTERFACE
}

inline void InitializeDirectInputSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("dinput8.dll", "DirectInput8Create", reinterpret_cast<void*>(DirectInput8Create));
}

} // namespace micant::dinput
