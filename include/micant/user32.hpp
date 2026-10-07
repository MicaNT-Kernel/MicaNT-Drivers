// ============================================================================
// MicaNT: PrismUI & User32 Subsystem (user32.dll)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Provides complete Win32 Window Management, Message Dispatching, Surface
// Compositor Backing, Presentation Hooks, and High-Precision Raw Input.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <deque>
#include <algorithm>
#include <cstring>
#include "ntdef.hpp"
#include "kernel32.hpp"
#include "ldr.hpp"
#include "winlogon.hpp"
#include "prismx.hpp"

namespace micant::user32 {

// ============================================================================
// 1. Win32 Window Data Types & Handles
// ============================================================================

using UINT    = uint32_t;
using WPARAM  = uintptr_t;
using LPARAM  = intptr_t;
using LRESULT = intptr_t;

using HDC       = void*;
using HINSTANCE = void*;
using HICON     = void*;
using HCURSOR   = void*;
using HBRUSH    = void*;
using HMENU     = void*;
using HRAWINPUT = void*;

using WNDPROC = LRESULT (*)(win32::HWND, UINT, WPARAM, LPARAM);

using POINT = micant::prismx::POINT;
using RECT  = micant::prismx::RECT;

struct MSG {
    win32::HWND hwnd{nullptr};
    UINT        message{0};
    WPARAM      wParam{0};
    LPARAM      lParam{0};
    uint32_t    time{0};
    POINT       pt{0, 0};
};

struct PAINTSTRUCT {
    HDC         hdc{nullptr};
    win32::BOOL fErase{win32::FALSE};
    RECT        rcPaint{0, 0, 0, 0};
    win32::BOOL fRestore{win32::FALSE};
    win32::BOOL fIncUpdate{win32::FALSE};
    uint8_t     rgbReserved[32]{};
};

struct WNDCLASSEXW {
    UINT        cbSize{sizeof(WNDCLASSEXW)};
    UINT        style{0};
    WNDPROC     lpfnWndProc{nullptr};
    int         cbClsExtra{0};
    int         cbWndExtra{0};
    HINSTANCE   hInstance{nullptr};
    HICON       hIcon{nullptr};
    HCURSOR     hCursor{nullptr};
    HBRUSH      hbrBackground{nullptr};
    const wchar_t* lpszMenuName{nullptr};
    const wchar_t* lpszClassName{nullptr};
    HICON       hIconSm{nullptr};
};

struct WNDCLASSW {
    UINT        style{0};
    WNDPROC     lpfnWndProc{nullptr};
    int         cbClsExtra{0};
    int         cbWndExtra{0};
    HINSTANCE   hInstance{nullptr};
    HICON       hIcon{nullptr};
    HCURSOR     hCursor{nullptr};
    HBRUSH      hbrBackground{nullptr};
    const wchar_t* lpszMenuName{nullptr};
    const wchar_t* lpszClassName{nullptr};
};

struct CREATESTRUCTW {
    void*       lpCreateParams{nullptr};
    HINSTANCE   hInstance{nullptr};
    HMENU       hMenu{nullptr};
    win32::HWND hwndParent{nullptr};
    int         cy{0};
    int         cx{0};
    int         y{0};
    int         x{0};
    uint32_t    style{0};
    const wchar_t* lpszName{nullptr};
    const wchar_t* lpszClass{nullptr};
    uint32_t    dwExStyle{0};
};

// ============================================================================
// 2. Window Styles, Messages & Constants
// ============================================================================

// Window Styles
inline constexpr uint32_t WS_OVERLAPPED       = 0x00000000;
inline constexpr uint32_t WS_POPUP            = 0x80000000;
inline constexpr uint32_t WS_CHILD            = 0x40000000;
inline constexpr uint32_t WS_MINIMIZE         = 0x20000000;
inline constexpr uint32_t WS_VISIBLE          = 0x10000000;
inline constexpr uint32_t WS_DISABLED         = 0x08000000;
inline constexpr uint32_t WS_CLIPSIBLINGS     = 0x04000000;
inline constexpr uint32_t WS_CLIPCHILDREN     = 0x02000000;
inline constexpr uint32_t WS_MAXIMIZE         = 0x01000000;
inline constexpr uint32_t WS_CAPTION          = 0x00C00000;
inline constexpr uint32_t WS_BORDER           = 0x00800000;
inline constexpr uint32_t WS_DLGFRAME         = 0x00400000;
inline constexpr uint32_t WS_VSCROLL          = 0x00200000;
inline constexpr uint32_t WS_HSCROLL          = 0x00100000;
inline constexpr uint32_t WS_SYSMENU          = 0x00080000;
inline constexpr uint32_t WS_THICKFRAME       = 0x00040000;
inline constexpr uint32_t WS_MINIMIZEBOX      = 0x00020000;
inline constexpr uint32_t WS_MAXIMIZEBOX      = 0x00010000;
inline constexpr uint32_t WS_OVERLAPPEDWINDOW = (WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);

// Window Extended Styles
inline constexpr uint32_t WS_EX_DLGMODALFRAME  = 0x00000001;
inline constexpr uint32_t WS_EX_TOPMOST        = 0x00000008;
inline constexpr uint32_t WS_EX_TRANSPARENT    = 0x00000020;
inline constexpr uint32_t WS_EX_TOOLWINDOW     = 0x00000080;
inline constexpr uint32_t WS_EX_WINDOWEDGE     = 0x00000100;
inline constexpr uint32_t WS_EX_CLIENTEDGE     = 0x00000200;
inline constexpr uint32_t WS_EX_APPWINDOW      = 0x00040000;
inline constexpr uint32_t WS_EX_LAYERED        = 0x00080000;

// Messages
inline constexpr uint32_t WM_NULL            = 0x0000;
inline constexpr uint32_t WM_CREATE          = 0x0001;
inline constexpr uint32_t WM_DESTROY         = 0x0002;
inline constexpr uint32_t WM_MOVE            = 0x0003;
inline constexpr uint32_t WM_SIZE            = 0x0005;
inline constexpr uint32_t WM_ACTIVATE        = 0x0006;
inline constexpr uint32_t WM_SETFOCUS        = 0x0007;
inline constexpr uint32_t WM_KILLFOCUS       = 0x0008;
inline constexpr uint32_t WM_ENABLE          = 0x000A;
inline constexpr uint32_t WM_PAINT           = 0x000F;
inline constexpr uint32_t WM_CLOSE           = 0x0010;
inline constexpr uint32_t WM_QUIT            = 0x0012;
inline constexpr uint32_t WM_ERASEBKGND      = 0x0014;
inline constexpr uint32_t WM_SHOWWINDOW      = 0x0018;
inline constexpr uint32_t WM_INPUT           = 0x00FF;
inline constexpr uint32_t WM_KEYDOWN         = 0x0100;
inline constexpr uint32_t WM_KEYUP           = 0x0101;
inline constexpr uint32_t WM_CHAR            = 0x0102;
inline constexpr uint32_t WM_MOUSEMOVE       = 0x0200;
inline constexpr uint32_t WM_LBUTTONDOWN     = 0x0201;
inline constexpr uint32_t WM_LBUTTONUP       = 0x0202;
inline constexpr uint32_t WM_RBUTTONDOWN     = 0x0204;
inline constexpr uint32_t WM_RBUTTONUP       = 0x0205;
inline constexpr uint32_t WM_MBUTTONDOWN     = 0x0207;
inline constexpr uint32_t WM_MBUTTONUP       = 0x0208;
inline constexpr uint32_t WM_MOUSEWHEEL      = 0x020A;
inline constexpr uint32_t WM_USER            = 0x0400;

// ShowWindow Commands
inline constexpr int SW_HIDE            = 0;
inline constexpr int SW_SHOWNORMAL      = 1;
inline constexpr int SW_NORMAL          = 1;
inline constexpr int SW_SHOWMINIMIZED   = 2;
inline constexpr int SW_SHOWMAXIMIZED   = 3;
inline constexpr int SW_MAXIMIZE        = 3;
inline constexpr int SW_SHOWNOACTIVATE  = 4;
inline constexpr int SW_SHOW            = 5;
inline constexpr int SW_MINIMIZE        = 6;
inline constexpr int SW_SHOWMINNOACTIVE = 7;
inline constexpr int SW_SHOWNA          = 8;
inline constexpr int SW_RESTORE         = 9;

// PeekMessage Options
inline constexpr uint32_t PM_NOREMOVE = 0x0000;
inline constexpr uint32_t PM_REMOVE   = 0x0001;
inline constexpr uint32_t PM_NOYIELD  = 0x0002;

// SetWindowPos Flags
inline constexpr uint32_t SWP_NOSIZE       = 0x0001;
inline constexpr uint32_t SWP_NOMOVE       = 0x0002;
inline constexpr uint32_t SWP_NOZORDER     = 0x0004;
inline constexpr uint32_t SWP_NOREDRAW     = 0x0008;
inline constexpr uint32_t SWP_NOACTIVATE   = 0x0010;
inline constexpr uint32_t SWP_FRAMECHANGED = 0x0020;
inline constexpr uint32_t SWP_SHOWWINDOW   = 0x0040;
inline constexpr uint32_t SWP_HIDEWINDOW   = 0x0080;

// WindowLongPtr offsets
inline constexpr int GWL_WNDPROC    = -4;
inline constexpr int GWL_HINSTANCE  = -6;
inline constexpr int GWL_HWNDPARENT = -8;
inline constexpr int GWL_STYLE      = -16;
inline constexpr int GWL_EXSTYLE    = -20;
inline constexpr int GWL_USERDATA   = -21;
inline constexpr int GWL_ID         = -12;

inline constexpr int GWLP_WNDPROC    = -4;
inline constexpr int GWLP_HINSTANCE  = -6;
inline constexpr int GWLP_HWNDPARENT = -8;
inline constexpr int GWLP_USERDATA   = -21;
inline constexpr int GWLP_ID         = -12;

// Raw Input Constants
inline constexpr uint32_t RIM_TYPEMOUSE    = 0;
inline constexpr uint32_t RIM_TYPEKEYBOARD = 1;
inline constexpr uint32_t RIM_TYPEHID      = 2;

inline constexpr uint32_t RIDEV_INPUTSINK = 0x00000100;
inline constexpr uint32_t RID_INPUT       = 0x10000003;
inline constexpr uint32_t RID_HEADER      = 0x10000005;

inline constexpr uint16_t RI_MOUSE_LEFT_BUTTON_DOWN   = 0x0001;
inline constexpr uint16_t RI_MOUSE_LEFT_BUTTON_UP     = 0x0002;
inline constexpr uint16_t RI_MOUSE_RIGHT_BUTTON_DOWN  = 0x0004;
inline constexpr uint16_t RI_MOUSE_RIGHT_BUTTON_UP    = 0x0008;
inline constexpr uint16_t RI_MOUSE_MIDDLE_BUTTON_DOWN = 0x0010;
inline constexpr uint16_t RI_MOUSE_MIDDLE_BUTTON_UP   = 0x0020;
inline constexpr uint16_t RI_MOUSE_WHEEL              = 0x0400;

struct RAWINPUTHEADER {
    uint32_t dwType{0};
    uint32_t dwSize{0};
    win32::HANDLE hDevice{nullptr};
    WPARAM   wParam{0};
};

struct RAWMOUSE {
    uint16_t usFlags{0};
    uint16_t usButtonFlags{0};
    uint16_t usButtonData{0};
    uint32_t ulRawButtons{0};
    int32_t  lLastX{0};
    int32_t  lLastY{0};
    uint32_t ulExtraInformation{0};
};

struct RAWKEYBOARD {
    uint16_t MakeCode{0};
    uint16_t Flags{0};
    uint16_t Reserved{0};
    uint16_t VKey{0};
    uint32_t Message{0};
    uint32_t ExtraInformation{0};
};

struct RAWINPUT {
    RAWINPUTHEADER header{};
    union {
        RAWMOUSE    mouse;
        RAWKEYBOARD keyboard;
    } data{};
};

struct RAWINPUTDEVICE {
    uint16_t    usUsagePage{0};
    uint16_t    usUsage{0};
    uint32_t    dwFlags{0};
    win32::HWND hwndTarget{nullptr};
};

// ============================================================================
// 3. Window Object & Backbuffer Compositor Surface
// ============================================================================

class WindowObject {
public:
    win32::HWND   hwnd{nullptr};
    std::wstring  className;
    std::wstring  windowName;
    uint32_t      style{0};
    uint32_t      exStyle{0};
    int32_t       x{0};
    int32_t       y{0};
    int32_t       width{800};
    int32_t       height{600};
    WNDPROC       wndProc{nullptr};
    HINSTANCE     hInstance{nullptr};
    win32::HWND   hwndParent{nullptr};
    bool          visible{false};
    bool          minimized{false};
    bool          active{false};
    uintptr_t     userData{0};

    // 32-bit RGBA dedicated backbuffer surface
    std::vector<uint32_t> surfacePixels;
    bool                  dirty{true};
    RECT                  dirtyRect{0, 0, 800, 600};

    WindowObject(win32::HWND h, std::wstring_view cls, std::wstring_view name, uint32_t st, uint32_t exSt,
                 int x_, int y_, int w, int h_, WNDPROC proc, HINSTANCE inst, win32::HWND parent)
        : hwnd(h), className(cls), windowName(name), style(st), exStyle(exSt),
          x(x_), y(y_), width(std::max(1, w)), height(std::max(1, h_)),
          wndProc(proc), hInstance(inst), hwndParent(parent) {
        surfacePixels.resize(static_cast<size_t>(width) * height, 0xFF000000); // Opaque black
        dirtyRect = RECT{0, 0, width, height};
    }

    void resize(int32_t newWidth, int32_t newHeight) {
        width = std::max(1, newWidth);
        height = std::max(1, newHeight);
        surfacePixels.assign(static_cast<size_t>(width) * height, 0xFF000000);
        dirty = true;
        dirtyRect = RECT{0, 0, width, height};
    }
};

// ============================================================================
// 4. Sovereign Window Manager Engine
// ============================================================================

class WindowManager {
public:
    static WindowManager& get() {
        static WindowManager instance;
        return instance;
    }

    // ------------------------------------------------------------------------
    // Window Class Registry
    // ------------------------------------------------------------------------
    uint16_t registerClass(const WNDCLASSEXW* lpwcx) {
        if (!lpwcx || !lpwcx->lpszClassName) return 0;
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        std::wstring name = lpwcx->lpszClassName;
        classRegistry_[name] = *lpwcx;
        return static_cast<uint16_t>(classRegistry_.size() & 0xFFFF);
    }

    bool unregisterClass(const wchar_t* lpClassName, HINSTANCE /*hInstance*/) {
        if (!lpClassName) return false;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return classRegistry_.erase(lpClassName) > 0;
    }

    bool getClassInfo(const wchar_t* lpClassName, WNDCLASSEXW* lpwcx) {
        if (!lpClassName || !lpwcx) return false;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = classRegistry_.find(lpClassName);
        if (it != classRegistry_.end()) {
            *lpwcx = it->second;
            return true;
        }
        return false;
    }

    // ------------------------------------------------------------------------
    // Window Lifecycle
    // ------------------------------------------------------------------------
    win32::HWND createWindow(
        uint32_t dwExStyle,
        const wchar_t* lpClassName,
        const wchar_t* lpWindowName,
        uint32_t dwStyle,
        int x, int y, int nWidth, int nHeight,
        win32::HWND hWndParent,
        HMENU /*hMenu*/,
        HINSTANCE hInstance,
        void* lpParam
    ) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        std::wstring clsName = lpClassName ? lpClassName : L"";
        std::wstring winName = lpWindowName ? lpWindowName : L"";

        WNDPROC proc = nullptr;
        auto classIt = classRegistry_.find(clsName);
        if (classIt != classRegistry_.end()) {
            proc = classIt->second.lpfnWndProc;
        }

        uintptr_t handleVal = nextHwnd_++;
        win32::HWND hwnd = reinterpret_cast<win32::HWND>(handleVal);

        int actualW = (nWidth <= 0) ? 800 : nWidth;
        int actualH = (nHeight <= 0) ? 600 : nHeight;

        auto window = std::make_shared<WindowObject>(
            hwnd, clsName, winName, dwStyle, dwExStyle,
            x, y, actualW, actualH, proc, hInstance, hWndParent
        );

        windows_[hwnd] = window;
        if (!activeHwnd_) activeHwnd_ = hwnd;

        // Deliver WM_CREATE synchronously
        if (proc) {
            CREATESTRUCTW cs{};
            cs.lpCreateParams = lpParam;
            cs.hInstance = hInstance;
            cs.hwndParent = hWndParent;
            cs.cy = actualH;
            cs.cx = actualW;
            cs.y = y;
            cs.x = x;
            cs.style = dwStyle;
            cs.lpszName = lpWindowName;
            cs.lpszClass = lpClassName;
            cs.dwExStyle = dwExStyle;

            proc(hwnd, WM_CREATE, 0, reinterpret_cast<LPARAM>(&cs));
        }

        if ((dwStyle & WS_VISIBLE) != 0) {
            window->visible = true;
            postMessageInternal(hwnd, WM_SIZE, 0, (actualH << 16) | (actualW & 0xFFFF));
            postMessageInternal(hwnd, WM_PAINT, 0, 0);
        }

        return hwnd;
    }

    bool destroyWindow(win32::HWND hWnd) {
        std::shared_ptr<WindowObject> win;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            auto it = windows_.find(hWnd);
            if (it == windows_.end()) return false;
            win = it->second;
            windows_.erase(it);
            if (activeHwnd_ == hWnd) activeHwnd_ = nullptr;
            if (focusHwnd_ == hWnd) focusHwnd_ = nullptr;
        }

        if (win && win->wndProc) {
            win->wndProc(hWnd, WM_DESTROY, 0, 0);
        }
        return true;
    }

    std::shared_ptr<WindowObject> getWindow(win32::HWND hWnd) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it != windows_.end()) return it->second;
        return nullptr;
    }

    bool isWindow(win32::HWND hWnd) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return windows_.find(hWnd) != windows_.end();
    }

    // ------------------------------------------------------------------------
    // Message Pump & Event Routing
    // ------------------------------------------------------------------------
    bool postMessage(win32::HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return postMessageInternal(hWnd, uMsg, wParam, lParam);
    }

    LRESULT sendMessage(win32::HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        std::shared_ptr<WindowObject> win;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            auto it = windows_.find(hWnd);
            if (it != windows_.end()) win = it->second;
        }

        if (win && win->wndProc) {
            return win->wndProc(hWnd, uMsg, wParam, lParam);
        }
        return defWindowProc(hWnd, uMsg, wParam, lParam);
    }

    bool peekMessage(MSG* lpMsg, win32::HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg) {
        if (!lpMsg) return false;
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        for (auto it = messageQueue_.begin(); it != messageQueue_.end(); ++it) {
            if (hWnd && it->hwnd != hWnd) continue;
            if (wMsgFilterMin && wMsgFilterMax && (it->message < wMsgFilterMin || it->message > wMsgFilterMax)) continue;

            *lpMsg = *it;
            if ((wRemoveMsg & PM_REMOVE) != 0) {
                messageQueue_.erase(it);
            }
            return true;
        }

        // If no posted message found, check for dirty paint
        if (!hWnd) {
            for (auto& pair : windows_) {
                if (pair.second->visible && pair.second->dirty) {
                    lpMsg->hwnd = pair.first;
                    lpMsg->message = WM_PAINT;
                    lpMsg->wParam = 0;
                    lpMsg->lParam = 0;
                    lpMsg->time = 0;
                    lpMsg->pt = POINT{0, 0};
                    if ((wRemoveMsg & PM_REMOVE) != 0) {
                        pair.second->dirty = false;
                    }
                    return true;
                }
            }
        } else {
            auto it = windows_.find(hWnd);
            if (it != windows_.end() && it->second->visible && it->second->dirty) {
                lpMsg->hwnd = hWnd;
                lpMsg->message = WM_PAINT;
                lpMsg->wParam = 0;
                lpMsg->lParam = 0;
                lpMsg->time = 0;
                lpMsg->pt = POINT{0, 0};
                if ((wRemoveMsg & PM_REMOVE) != 0) {
                    it->second->dirty = false;
                }
                return true;
            }
        }

        return false;
    }

    bool getMessage(MSG* lpMsg, win32::HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax) {
        if (!lpMsg) return false;

        // Peek with remove
        if (peekMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, PM_REMOVE)) {
            return (lpMsg->message != WM_QUIT);
        }

        // Default empty message
        lpMsg->hwnd = hWnd;
        lpMsg->message = WM_NULL;
        lpMsg->wParam = 0;
        lpMsg->lParam = 0;
        return true;
    }

    void postQuitMessage(int nExitCode) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        MSG msg{};
        msg.hwnd = nullptr;
        msg.message = WM_QUIT;
        msg.wParam = static_cast<WPARAM>(nExitCode);
        messageQueue_.push_back(msg);
    }

    LRESULT dispatchMessage(const MSG* lpMsg) {
        if (!lpMsg) return 0;
        if (lpMsg->hwnd) {
            std::shared_ptr<WindowObject> win;
            {
                std::lock_guard<std::recursive_mutex> lock(mutex_);
                auto it = windows_.find(lpMsg->hwnd);
                if (it != windows_.end()) win = it->second;
            }
            if (win && win->wndProc) {
                return win->wndProc(lpMsg->hwnd, lpMsg->message, lpMsg->wParam, lpMsg->lParam);
            }
        }
        return defWindowProc(lpMsg->hwnd, lpMsg->message, lpMsg->wParam, lpMsg->lParam);
    }

    LRESULT defWindowProc(win32::HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        switch (uMsg) {
            case WM_CLOSE:
                destroyWindow(hWnd);
                return 0;
            case WM_PAINT:
                // Auto validate window region
                validateRect(hWnd, nullptr);
                return 0;
            default:
                break;
        }
        return 0;
    }

    // ------------------------------------------------------------------------
    // Geometry, Painting & GDI Surface
    // ------------------------------------------------------------------------
    bool getClientRect(win32::HWND hWnd, RECT* lpRect) {
        if (!lpRect) return false;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it != windows_.end()) {
            lpRect->left = 0;
            lpRect->top = 0;
            lpRect->right = it->second->width;
            lpRect->bottom = it->second->height;
            return true;
        }
        return false;
    }

    bool getWindowRect(win32::HWND hWnd, RECT* lpRect) {
        if (!lpRect) return false;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it != windows_.end()) {
            lpRect->left = it->second->x;
            lpRect->top = it->second->y;
            lpRect->right = it->second->x + it->second->width;
            lpRect->bottom = it->second->y + it->second->height;
            return true;
        }
        return false;
    }

    bool setWindowPos(win32::HWND hWnd, win32::HWND /*hWndInsertAfter*/, int X, int Y, int cx, int cy, UINT uFlags) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it == windows_.end()) return false;

        auto win = it->second;
        if ((uFlags & SWP_NOMOVE) == 0) {
            win->x = X;
            win->y = Y;
        }
        if ((uFlags & SWP_NOSIZE) == 0) {
            win->resize(cx, cy);
            postMessageInternal(hWnd, WM_SIZE, 0, (win->height << 16) | (win->width & 0xFFFF));
        }
        if ((uFlags & SWP_SHOWWINDOW) != 0) {
            win->visible = true;
        }
        if ((uFlags & SWP_HIDEWINDOW) != 0) {
            win->visible = false;
        }
        return true;
    }

    bool invalidateRect(win32::HWND hWnd, const RECT* lpRect, win32::BOOL /*bErase*/) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it != windows_.end()) {
            it->second->dirty = true;
            if (lpRect) it->second->dirtyRect = *lpRect;
            else it->second->dirtyRect = RECT{0, 0, it->second->width, it->second->height};
            return true;
        }
        return false;
    }

    bool validateRect(win32::HWND hWnd, const RECT* /*lpRect*/) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it != windows_.end()) {
            it->second->dirty = false;
            return true;
        }
        return false;
    }

    HDC beginPaint(win32::HWND hWnd, PAINTSTRUCT* lpPaint) {
        if (!lpPaint) return nullptr;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it != windows_.end()) {
            lpPaint->hdc = reinterpret_cast<HDC>(reinterpret_cast<uintptr_t>(hWnd) | 0x1);
            lpPaint->rcPaint = it->second->dirtyRect;
            lpPaint->fErase = win32::FALSE;
            it->second->dirty = false;
            return lpPaint->hdc;
        }
        return nullptr;
    }

    bool endPaint(win32::HWND hWnd, const PAINTSTRUCT* /*lpPaint*/) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it != windows_.end()) {
            it->second->dirty = false;
            return true;
        }
        return false;
    }

    // ------------------------------------------------------------------------
    // Presentation Blit & Surface Bridge
    // ------------------------------------------------------------------------
    void blitToWindow(win32::HWND hWnd, const uint8_t* pData, uint32_t width, uint32_t height, uint32_t pitch) {
        if (!hWnd || !pData) return;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it == windows_.end()) return;

        auto win = it->second;
        uint32_t copyW = std::min(static_cast<uint32_t>(win->width), width);
        uint32_t copyH = std::min(static_cast<uint32_t>(win->height), height);

        for (uint32_t row = 0; row < copyH; ++row) {
            const auto* srcRow = reinterpret_cast<const uint32_t*>(pData + row * pitch);
            auto* dstRow = &win->surfacePixels[row * static_cast<size_t>(win->width)];
            std::memcpy(dstRow, srcRow, copyW * sizeof(uint32_t));
        }

        win->dirty = false;
    }

    const uint32_t* getWindowPixelBuffer(win32::HWND hWnd, uint32_t* pWidth, uint32_t* pHeight) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it != windows_.end()) {
            if (pWidth) *pWidth = static_cast<uint32_t>(it->second->width);
            if (pHeight) *pHeight = static_cast<uint32_t>(it->second->height);
            return it->second->surfacePixels.data();
        }
        return nullptr;
    }

    // ------------------------------------------------------------------------
    // Raw Input Subsystem
    // ------------------------------------------------------------------------
    bool registerRawInputDevices(const RAWINPUTDEVICE* pRawInputDevices, UINT uiNumDevices, UINT cbSize) {
        if (!pRawInputDevices || cbSize < sizeof(RAWINPUTDEVICE)) return false;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        registeredRawDevices_.assign(pRawInputDevices, pRawInputDevices + uiNumDevices);
        return true;
    }

    UINT getRawInputData(HRAWINPUT hRawInput, UINT uiCommand, void* pData, UINT* pcbSize, UINT cbSizeHeader) {
        if (!pcbSize || cbSizeHeader < sizeof(RAWINPUTHEADER)) return static_cast<UINT>(-1);
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        auto it = rawInputBuffer_.find(hRawInput);
        if (it == rawInputBuffer_.end()) return static_cast<UINT>(-1);

        const auto& packet = it->second;
        UINT requiredSize = sizeof(RAWINPUT);

        if (uiCommand == RID_HEADER) {
            requiredSize = sizeof(RAWINPUTHEADER);
            if (!pData || *pcbSize < requiredSize) {
                *pcbSize = requiredSize;
                return 0;
            }
            std::memcpy(pData, &packet.header, sizeof(RAWINPUTHEADER));
            return sizeof(RAWINPUTHEADER);
        }

        if (uiCommand == RID_INPUT) {
            if (!pData || *pcbSize < requiredSize) {
                *pcbSize = requiredSize;
                return 0;
            }
            std::memcpy(pData, &packet, sizeof(RAWINPUT));
            return sizeof(RAWINPUT);
        }

        return static_cast<UINT>(-1);
    }

    HRAWINPUT injectRawMouse(win32::HWND hWnd, int32_t dx, int32_t dy, uint16_t buttonFlags) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        HRAWINPUT handle = reinterpret_cast<HRAWINPUT>(nextRawHandle_++);

        RAWINPUT ri{};
        ri.header.dwType = RIM_TYPEMOUSE;
        ri.header.dwSize = sizeof(RAWINPUT);
        ri.header.hDevice = reinterpret_cast<win32::HANDLE>(0x000000000000B001ULL);
        ri.data.mouse.lLastX = dx;
        ri.data.mouse.lLastY = dy;
        ri.data.mouse.usButtonFlags = buttonFlags;

        rawInputBuffer_[handle] = ri;
        postMessageInternal(hWnd, WM_INPUT, 0, reinterpret_cast<LPARAM>(handle));
        return handle;
    }

    HRAWINPUT injectRawKeyboard(win32::HWND hWnd, uint16_t vkey, uint16_t makeCode, uint16_t flags, uint32_t message) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        HRAWINPUT handle = reinterpret_cast<HRAWINPUT>(nextRawHandle_++);

        RAWINPUT ri{};
        ri.header.dwType = RIM_TYPEKEYBOARD;
        ri.header.dwSize = sizeof(RAWINPUT);
        ri.header.hDevice = reinterpret_cast<win32::HANDLE>(0x000000000000B002ULL);
        ri.data.keyboard.VKey = vkey;
        ri.data.keyboard.MakeCode = makeCode;
        ri.data.keyboard.Flags = flags;
        ri.data.keyboard.Message = message;

        rawInputBuffer_[handle] = ri;
        postMessageInternal(hWnd, WM_INPUT, 0, reinterpret_cast<LPARAM>(handle));
        return handle;
    }

    // ------------------------------------------------------------------------
    // Focus, Active Window & Long Attributes
    // ------------------------------------------------------------------------
    win32::HWND getActiveWindow() const noexcept { return activeHwnd_; }
    win32::HWND setActiveWindow(win32::HWND hWnd) noexcept {
        win32::HWND prev = activeHwnd_;
        activeHwnd_ = hWnd;
        return prev;
    }

    win32::HWND getFocus() const noexcept { return focusHwnd_; }
    win32::HWND setFocus(win32::HWND hWnd) noexcept {
        win32::HWND prev = focusHwnd_;
        focusHwnd_ = hWnd;
        return prev;
    }

    uintptr_t setWindowLongPtr(win32::HWND hWnd, int nIndex, uintptr_t dwNewLong) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it == windows_.end()) return 0;

        auto win = it->second;
        uintptr_t oldVal = 0;
        switch (nIndex) {
            case GWLP_USERDATA:
                oldVal = win->userData;
                win->userData = dwNewLong;
                break;
            case GWLP_WNDPROC:
                oldVal = reinterpret_cast<uintptr_t>(win->wndProc);
                win->wndProc = reinterpret_cast<WNDPROC>(dwNewLong);
                break;
            case GWL_STYLE:
                oldVal = win->style;
                win->style = static_cast<uint32_t>(dwNewLong);
                break;
            case GWL_EXSTYLE:
                oldVal = win->exStyle;
                win->exStyle = static_cast<uint32_t>(dwNewLong);
                break;
            default:
                break;
        }
        return oldVal;
    }

    uintptr_t getWindowLongPtr(win32::HWND hWnd, int nIndex) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = windows_.find(hWnd);
        if (it == windows_.end()) return 0;

        auto win = it->second;
        switch (nIndex) {
            case GWLP_USERDATA: return win->userData;
            case GWLP_WNDPROC:  return reinterpret_cast<uintptr_t>(win->wndProc);
            case GWL_STYLE:     return win->style;
            case GWL_EXSTYLE:   return win->exStyle;
            default:            return 0;
        }
    }

private:
    WindowManager() = default;

    bool postMessageInternal(win32::HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        MSG msg{};
        msg.hwnd = hWnd;
        msg.message = uMsg;
        msg.wParam = wParam;
        msg.lParam = lParam;
        msg.time = 0;
        msg.pt = POINT{0, 0};
        messageQueue_.push_back(msg);
        return true;
    }

    std::recursive_mutex mutex_;
    uintptr_t nextHwnd_{0x00010001};
    uintptr_t nextRawHandle_{0x00000001};
    win32::HWND activeHwnd_{nullptr};
    win32::HWND focusHwnd_{nullptr};

    std::unordered_map<std::wstring, WNDCLASSEXW> classRegistry_;
    std::unordered_map<win32::HWND, std::shared_ptr<WindowObject>> windows_;
    std::deque<MSG> messageQueue_;
    std::vector<RAWINPUTDEVICE> registeredRawDevices_;
    std::unordered_map<HRAWINPUT, RAWINPUT> rawInputBuffer_;
};

// ============================================================================
// 5. Presentation Callback Hook
// ============================================================================

inline void BlitToWindowCallback(void* hwnd, const uint8_t* pData, uint32_t width, uint32_t height, uint32_t pitch) {
    WindowManager::get().blitToWindow(reinterpret_cast<win32::HWND>(hwnd), pData, width, height, pitch);
}

// ============================================================================
// 6. Win32 User32 C-API Functions
// ============================================================================

inline uint16_t RegisterClassExW(const WNDCLASSEXW* lpwcx) noexcept {
    return WindowManager::get().registerClass(lpwcx);
}

inline uint16_t RegisterClassW(const WNDCLASSW* lpWndClass) noexcept {
    if (!lpWndClass) return 0;
    WNDCLASSEXW wcex{};
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = lpWndClass->style;
    wcex.lpfnWndProc = lpWndClass->lpfnWndProc;
    wcex.cbClsExtra = lpWndClass->cbClsExtra;
    wcex.cbWndExtra = lpWndClass->cbWndExtra;
    wcex.hInstance = lpWndClass->hInstance;
    wcex.hIcon = lpWndClass->hIcon;
    wcex.hCursor = lpWndClass->hCursor;
    wcex.hbrBackground = lpWndClass->hbrBackground;
    wcex.lpszMenuName = lpWndClass->lpszMenuName;
    wcex.lpszClassName = lpWndClass->lpszClassName;
    return WindowManager::get().registerClass(&wcex);
}

inline win32::BOOL UnregisterClassW(const wchar_t* lpClassName, HINSTANCE hInstance) noexcept {
    return WindowManager::get().unregisterClass(lpClassName, hInstance) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL GetClassInfoExW(HINSTANCE /*hInstance*/, const wchar_t* lpClassName, WNDCLASSEXW* lpwcx) noexcept {
    return WindowManager::get().getClassInfo(lpClassName, lpwcx) ? win32::TRUE : win32::FALSE;
}

inline win32::HWND CreateWindowExW(
    uint32_t dwExStyle,
    const wchar_t* lpClassName,
    const wchar_t* lpWindowName,
    uint32_t dwStyle,
    int X, int Y, int nWidth, int nHeight,
    win32::HWND hWndParent,
    HMENU hMenu,
    HINSTANCE hInstance,
    void* lpParam
) noexcept {
    return WindowManager::get().createWindow(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

inline win32::HWND CreateWindowExA(
    uint32_t dwExStyle,
    const char* lpClassName,
    const char* lpWindowName,
    uint32_t dwStyle,
    int X, int Y, int nWidth, int nHeight,
    win32::HWND hWndParent,
    HMENU hMenu,
    HINSTANCE hInstance,
    void* lpParam
) noexcept {
    std::wstring wCls = lpClassName ? std::wstring(lpClassName, lpClassName + std::strlen(lpClassName)) : L"";
    std::wstring wName = lpWindowName ? std::wstring(lpWindowName, lpWindowName + std::strlen(lpWindowName)) : L"";
    return WindowManager::get().createWindow(dwExStyle, wCls.c_str(), wName.c_str(), dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

inline win32::BOOL DestroyWindow(win32::HWND hWnd) noexcept {
    return WindowManager::get().destroyWindow(hWnd) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL IsWindow(win32::HWND hWnd) noexcept {
    return WindowManager::get().isWindow(hWnd) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL ShowWindow(win32::HWND hWnd, int nCmdShow) noexcept {
    auto win = WindowManager::get().getWindow(hWnd);
    if (!win) return win32::FALSE;

    win32::BOOL prevVisible = win->visible ? win32::TRUE : win32::FALSE;
    if (nCmdShow == SW_HIDE) {
        win->visible = false;
    } else {
        win->visible = true;
        win->minimized = (nCmdShow == SW_SHOWMINIMIZED || nCmdShow == SW_MINIMIZE);
        WindowManager::get().postMessage(hWnd, WM_PAINT, 0, 0);
    }
    return prevVisible;
}

inline win32::BOOL IsWindowVisible(win32::HWND hWnd) noexcept {
    auto win = WindowManager::get().getWindow(hWnd);
    return (win && win->visible) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL IsIconic(win32::HWND hWnd) noexcept {
    auto win = WindowManager::get().getWindow(hWnd);
    return (win && win->minimized) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL UpdateWindow(win32::HWND hWnd) noexcept {
    auto win = WindowManager::get().getWindow(hWnd);
    if (win && win->dirty) {
        WindowManager::get().sendMessage(hWnd, WM_PAINT, 0, 0);
    }
    return win32::TRUE;
}

inline win32::BOOL InvalidateRect(win32::HWND hWnd, const RECT* lpRect, win32::BOOL bErase) noexcept {
    return WindowManager::get().invalidateRect(hWnd, lpRect, bErase) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL ValidateRect(win32::HWND hWnd, const RECT* lpRect) noexcept {
    return WindowManager::get().validateRect(hWnd, lpRect) ? win32::TRUE : win32::FALSE;
}


inline win32::BOOL GetClientRect(win32::HWND hWnd, RECT* lpRect) noexcept {
    return WindowManager::get().getClientRect(hWnd, lpRect) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL GetWindowRect(win32::HWND hWnd, RECT* lpRect) noexcept {
    return WindowManager::get().getWindowRect(hWnd, lpRect) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL AdjustWindowRectEx(RECT* lpRect, uint32_t /*dwStyle*/, win32::BOOL /*bMenu*/, uint32_t /*dwExStyle*/) noexcept {
    if (!lpRect) return win32::FALSE;
    // Standard standard border padding
    lpRect->left   -= 8;
    lpRect->top    -= 31; // Titlebar + border
    lpRect->right  += 8;
    lpRect->bottom += 8;
    return win32::TRUE;
}

inline win32::BOOL SetWindowPos(win32::HWND hWnd, win32::HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags) noexcept {
    return WindowManager::get().setWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL MoveWindow(win32::HWND hWnd, int X, int Y, int nWidth, int nHeight, win32::BOOL bRepaint) noexcept {
    UINT flags = SWP_NOZORDER | SWP_NOACTIVATE;
    if (!bRepaint) flags |= SWP_NOREDRAW;
    return WindowManager::get().setWindowPos(hWnd, nullptr, X, Y, nWidth, nHeight, flags) ? win32::TRUE : win32::FALSE;
}

inline uintptr_t SetWindowLongPtrW(win32::HWND hWnd, int nIndex, uintptr_t dwNewLong) noexcept {
    return WindowManager::get().setWindowLongPtr(hWnd, nIndex, dwNewLong);
}

inline uintptr_t GetWindowLongPtrW(win32::HWND hWnd, int nIndex) noexcept {
    return WindowManager::get().getWindowLongPtr(hWnd, nIndex);
}

inline int32_t SetWindowLongW(win32::HWND hWnd, int nIndex, int32_t dwNewLong) noexcept {
    return static_cast<int32_t>(WindowManager::get().setWindowLongPtr(hWnd, nIndex, static_cast<uintptr_t>(dwNewLong)));
}

inline int32_t GetWindowLongW(win32::HWND hWnd, int nIndex) noexcept {
    return static_cast<int32_t>(WindowManager::get().getWindowLongPtr(hWnd, nIndex));
}

inline win32::BOOL PostMessageW(win32::HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) noexcept {
    return WindowManager::get().postMessage(hWnd, Msg, wParam, lParam) ? win32::TRUE : win32::FALSE;
}

inline LRESULT SendMessageW(win32::HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) noexcept {
    return WindowManager::get().sendMessage(hWnd, Msg, wParam, lParam);
}

inline win32::BOOL PeekMessageW(MSG* lpMsg, win32::HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg) noexcept {
    return WindowManager::get().peekMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL PeekMessageA(MSG* lpMsg, win32::HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg) noexcept {
    return WindowManager::get().peekMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL GetMessageW(MSG* lpMsg, win32::HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax) noexcept {
    return WindowManager::get().getMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL TranslateMessage(const MSG* lpMsg) noexcept {
    if (!lpMsg) return win32::FALSE;
    if (lpMsg->message == WM_KEYDOWN) {
        // Synthesize WM_CHAR message for printable ASCII characters
        if (lpMsg->wParam >= 0x20 && lpMsg->wParam <= 0x7E) {
            WindowManager::get().postMessage(lpMsg->hwnd, WM_CHAR, lpMsg->wParam, lpMsg->lParam);
            return win32::TRUE;
        }
    }
    return win32::FALSE;
}

inline LRESULT DispatchMessageW(const MSG* lpMsg) noexcept {
    return WindowManager::get().dispatchMessage(lpMsg);
}

inline int64_t DispatchMessageA(const MSG* lpMsg) noexcept {
    return static_cast<int64_t>(WindowManager::get().dispatchMessage(lpMsg));
}

inline void PostQuitMessage(int nExitCode) noexcept {
    WindowManager::get().postQuitMessage(nExitCode);
}

inline LRESULT DefWindowProcW(win32::HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) noexcept {
    return WindowManager::get().defWindowProc(hWnd, Msg, wParam, lParam);
}

using GetDCHookFn = HDC (*)(win32::HWND);
inline GetDCHookFn g_pfnGetDCHook = nullptr;

inline void SetGetDCHook(GetDCHookFn fn) noexcept {
    g_pfnGetDCHook = fn;
}

using ReleaseDCHookFn = int (*)(win32::HWND, HDC);
inline ReleaseDCHookFn g_pfnReleaseDCHook = nullptr;

inline void SetReleaseDCHook(ReleaseDCHookFn fn) noexcept {
    g_pfnReleaseDCHook = fn;
}

inline HDC GetDC(win32::HWND hWnd) noexcept {
    if (g_pfnGetDCHook) return g_pfnGetDCHook(hWnd);
    return reinterpret_cast<HDC>(reinterpret_cast<uintptr_t>(hWnd) | 0x1);
}

inline int ReleaseDC(win32::HWND hWnd, HDC hDC) noexcept {
    if (g_pfnReleaseDCHook) return g_pfnReleaseDCHook(hWnd, hDC);
    WindowManager::get().invalidateRect(hWnd, nullptr, win32::FALSE);
    return 1;
}

inline constexpr UINT MB_OK = 0x00000000;
inline constexpr UINT MB_OKCANCEL = 0x00000001;
inline constexpr UINT MB_ABORTRETRYIGNORE = 0x00000002;
inline constexpr UINT MB_YESNOCANCEL = 0x00000003;
inline constexpr UINT MB_YESNO = 0x00000004;
inline constexpr UINT MB_RETRYCANCEL = 0x00000005;

inline constexpr int IDOK = 1;
inline constexpr int IDCANCEL = 2;
inline constexpr int IDABORT = 3;
inline constexpr int IDRETRY = 4;
inline constexpr int IDIGNORE = 5;
inline constexpr int IDYES = 6;
inline constexpr int IDNO = 7;

inline int MessageBoxW(win32::HWND hWnd, const wchar_t* lpText, const wchar_t* lpCaption, UINT uType) noexcept {
    (void)hWnd; (void)uType;
    (void)lpText; (void)lpCaption;
    return IDOK;
}

inline int MessageBoxA(win32::HWND hWnd, const char* lpText, const char* lpCaption, UINT uType) noexcept {
    (void)hWnd; (void)uType;
    (void)lpText; (void)lpCaption;
    return IDOK;
}

inline HDC BeginPaint(win32::HWND hWnd, PAINTSTRUCT* lpPaint) noexcept {
    return WindowManager::get().beginPaint(hWnd, lpPaint);
}

inline win32::BOOL EndPaint(win32::HWND hWnd, const PAINTSTRUCT* lpPaint) noexcept {
    return WindowManager::get().endPaint(hWnd, lpPaint) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL RegisterRawInputDevices(const RAWINPUTDEVICE* pRawInputDevices, UINT uiNumDevices, UINT cbSize) noexcept {
    return WindowManager::get().registerRawInputDevices(pRawInputDevices, uiNumDevices, cbSize) ? win32::TRUE : win32::FALSE;
}

inline UINT GetRawInputData(HRAWINPUT hRawInput, UINT uiCommand, void* pData, UINT* pcbSize, UINT cbSizeHeader) noexcept {
    return WindowManager::get().getRawInputData(hRawInput, uiCommand, pData, pcbSize, cbSizeHeader);
}

// ----------------------------------------------------------------------------
// Desktop & Synchronization Bridge (from existing user32)
// ----------------------------------------------------------------------------

inline uint32_t MsgWaitForMultipleObjects(
    uint32_t nCount,
    const win32::HANDLE* pHandles,
    win32::BOOL fWaitAll,
    uint32_t dwMilliseconds,
    uint32_t /*dwWakeMask*/
) noexcept {
    return win32::WaitForMultipleObjects(nCount, pHandles, fWaitAll, dwMilliseconds);
}

inline win32::BOOL LockWorkStation() noexcept {
    return winlogon::WinlogonManager::get().lockWorkstation() ? win32::TRUE : win32::FALSE;
}

inline win32::HANDLE OpenDesktopW(
    const wchar_t* lpszDesktop,
    uint32_t /*dwFlags*/,
    win32::BOOL /*fInherit*/,
    uint32_t /*dwDesiredAccess*/
) noexcept {
    if (!lpszDesktop) return nullptr;
    if (_wcsicmp(lpszDesktop, L"Winlogon") == 0) {
        return reinterpret_cast<win32::HANDLE>(0x0000000000000010ULL);
    }
    if (_wcsicmp(lpszDesktop, L"Default") == 0) {
        return reinterpret_cast<win32::HANDLE>(0x0000000000000020ULL);
    }
    return nullptr;
}

inline win32::BOOL SwitchDesktop(win32::HANDLE hDesktop) noexcept {
    if (hDesktop == reinterpret_cast<win32::HANDLE>(0x0000000000000010ULL)) {
        winlogon::WinlogonManager::get().switchDesktop(winlogon::DesktopType::Winlogon);
        return win32::TRUE;
    }
    if (hDesktop == reinterpret_cast<win32::HANDLE>(0x0000000000000020ULL)) {
        winlogon::WinlogonManager::get().switchDesktop(winlogon::DesktopType::Default);
        return win32::TRUE;
    }
    return win32::FALSE;
}

inline win32::BOOL CloseDesktop(win32::HANDLE /*hDesktop*/) noexcept {
    return win32::TRUE;
}

// ============================================================================
// 7. Subsystem Export Registration
// ============================================================================

inline void InitializeUser32SubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // Hook SwapChain backbuffer presenter
    prismx::PrismXSwapChainImpl::SetGlobalWindowPresenter(BlitToWindowCallback);

    ldr.registerExport("user32.dll", "RegisterClassExW", reinterpret_cast<void*>(RegisterClassExW));
    ldr.registerExport("user32.dll", "RegisterClassW", reinterpret_cast<void*>(RegisterClassW));
    ldr.registerExport("user32.dll", "UnregisterClassW", reinterpret_cast<void*>(UnregisterClassW));
    ldr.registerExport("user32.dll", "GetClassInfoExW", reinterpret_cast<void*>(GetClassInfoExW));
    ldr.registerExport("user32.dll", "CreateWindowExW", reinterpret_cast<void*>(CreateWindowExW));
    ldr.registerExport("user32.dll", "CreateWindowExA", reinterpret_cast<void*>(CreateWindowExA));
    ldr.registerExport("user32.dll", "DestroyWindow", reinterpret_cast<void*>(DestroyWindow));
    ldr.registerExport("user32.dll", "IsWindow", reinterpret_cast<void*>(IsWindow));
    ldr.registerExport("user32.dll", "ShowWindow", reinterpret_cast<void*>(ShowWindow));
    ldr.registerExport("user32.dll", "IsWindowVisible", reinterpret_cast<void*>(IsWindowVisible));
    ldr.registerExport("user32.dll", "IsIconic", reinterpret_cast<void*>(IsIconic));
    ldr.registerExport("user32.dll", "UpdateWindow", reinterpret_cast<void*>(UpdateWindow));
    ldr.registerExport("user32.dll", "InvalidateRect", reinterpret_cast<void*>(InvalidateRect));
    ldr.registerExport("user32.dll", "ValidateRect", reinterpret_cast<void*>(ValidateRect));
    ldr.registerExport("user32.dll", "GetClientRect", reinterpret_cast<void*>(GetClientRect));
    ldr.registerExport("user32.dll", "GetWindowRect", reinterpret_cast<void*>(GetWindowRect));
    ldr.registerExport("user32.dll", "AdjustWindowRectEx", reinterpret_cast<void*>(AdjustWindowRectEx));
    ldr.registerExport("user32.dll", "SetWindowPos", reinterpret_cast<void*>(SetWindowPos));
    ldr.registerExport("user32.dll", "MoveWindow", reinterpret_cast<void*>(MoveWindow));
    ldr.registerExport("user32.dll", "SetWindowLongPtrW", reinterpret_cast<void*>(SetWindowLongPtrW));
    ldr.registerExport("user32.dll", "GetWindowLongPtrW", reinterpret_cast<void*>(GetWindowLongPtrW));
    ldr.registerExport("user32.dll", "SetWindowLongW", reinterpret_cast<void*>(SetWindowLongW));
    ldr.registerExport("user32.dll", "GetWindowLongW", reinterpret_cast<void*>(GetWindowLongW));
    ldr.registerExport("user32.dll", "PostMessageW", reinterpret_cast<void*>(PostMessageW));
    ldr.registerExport("user32.dll", "SendMessageW", reinterpret_cast<void*>(SendMessageW));
    ldr.registerExport("user32.dll", "PeekMessageW", reinterpret_cast<void*>(PeekMessageW));
    ldr.registerExport("user32.dll", "PeekMessageA", reinterpret_cast<void*>(PeekMessageA));
    ldr.registerExport("user32.dll", "GetMessageW", reinterpret_cast<void*>(GetMessageW));
    ldr.registerExport("user32.dll", "TranslateMessage", reinterpret_cast<void*>(TranslateMessage));
    ldr.registerExport("user32.dll", "DispatchMessageW", reinterpret_cast<void*>(DispatchMessageW));
    ldr.registerExport("user32.dll", "DispatchMessageA", reinterpret_cast<void*>(DispatchMessageA));
    ldr.registerExport("user32.dll", "PostQuitMessage", reinterpret_cast<void*>(PostQuitMessage));
    ldr.registerExport("user32.dll", "DefWindowProcW", reinterpret_cast<void*>(DefWindowProcW));
    ldr.registerExport("user32.dll", "GetDC", reinterpret_cast<void*>(GetDC));
    ldr.registerExport("user32.dll", "ReleaseDC", reinterpret_cast<void*>(ReleaseDC));
    ldr.registerExport("user32.dll", "BeginPaint", reinterpret_cast<void*>(BeginPaint));
    ldr.registerExport("user32.dll", "EndPaint", reinterpret_cast<void*>(EndPaint));
    ldr.registerExport("user32.dll", "RegisterRawInputDevices", reinterpret_cast<void*>(RegisterRawInputDevices));
    ldr.registerExport("user32.dll", "GetRawInputData", reinterpret_cast<void*>(GetRawInputData));
    ldr.registerExport("user32.dll", "MsgWaitForMultipleObjects", reinterpret_cast<void*>(MsgWaitForMultipleObjects));
    ldr.registerExport("user32.dll", "LockWorkStation", reinterpret_cast<void*>(LockWorkStation));
    ldr.registerExport("user32.dll", "OpenDesktopW", reinterpret_cast<void*>(OpenDesktopW));
    ldr.registerExport("user32.dll", "SwitchDesktop", reinterpret_cast<void*>(SwitchDesktop));
    ldr.registerExport("user32.dll", "CloseDesktop", reinterpret_cast<void*>(CloseDesktop));
    ldr.registerExport("user32.dll", "MessageBoxW", reinterpret_cast<void*>(MessageBoxW));
    ldr.registerExport("user32.dll", "MessageBoxA", reinterpret_cast<void*>(MessageBoxA));
}

} // namespace micant::user32
