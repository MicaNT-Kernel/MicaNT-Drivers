// ============================================================================
// MicaNT: TitanPTY / SurPTY - Windows Pseudo Console (ConPTY) & Terminal Host
//
// Named in tribute to Dave Cutler's Windows NT Console Architecture, DEC VT
// terminal standards, and modern sovereign terminal emulation engines.
//
// Strict Clean-Room Implementation in modern ISO C++23.
// Compatible with Microsoft Windows Pseudo Console specification, win32metadata,
// and OpenConsole headless VT terminal protocols.
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "conhost.hpp"
#include "ldr.hpp"
#include "scm.hpp"
#include "version.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <deque>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include <format>
#include <chrono>

namespace micant::conpty {

// ============================================================================
// 1. Types, Constants & Win32 API Definitions
// ============================================================================

using HPCON = void*;

inline constexpr uint32_t PSEUDOCONSOLE_INHERIT_CURSOR = (1u << 0);
inline constexpr uintptr_t PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;

using HRESULT = int32_t;
inline constexpr HRESULT S_OK          = 0;
inline constexpr HRESULT S_FALSE       = 1;
inline constexpr HRESULT E_FAIL        = static_cast<HRESULT>(0x80004005);
inline constexpr HRESULT E_INVALIDARG  = static_cast<HRESULT>(0x80070057);
inline constexpr HRESULT E_HANDLE      = static_cast<HRESULT>(0x80070006);
inline constexpr HRESULT E_OUTOFMEMORY = static_cast<HRESULT>(0x8007000E);

#ifndef WINAPI
#define WINAPI __stdcall
#endif

#ifndef BOOL
using BOOL = int32_t;
inline constexpr BOOL TRUE  = 1;
inline constexpr BOOL FALSE = 0;
#endif

struct COORD {
    int16_t X{0};
    int16_t Y{0};

    auto operator<=>(const COORD&) const = default;
};

struct SMALL_RECT {
    int16_t Left{0};
    int16_t Top{0};
    int16_t Right{0};
    int16_t Bottom{0};
};

struct CONSOLE_SCREEN_BUFFER_INFOEX {
    uint32_t cbSize{sizeof(CONSOLE_SCREEN_BUFFER_INFOEX)};
    COORD dwSize{80, 24};
    COORD dwCursorPosition{0, 0};
    uint16_t wAttributes{conhost::DEFAULT_CONSOLE_ATTRIBUTES};
    SMALL_RECT srWindow{0, 0, 79, 23};
    COORD dwMaximumWindowSize{80, 24};
    uint16_t wPopupAttributes{0x00F5};
    BOOL bFullscreenSupported{FALSE};
    uint32_t ColorTable[16]{};
};

// ============================================================================
// 2. Color & Style Definitions
// ============================================================================

struct ConptyColor {
    uint8_t R{204};
    uint8_t G{204};
    uint8_t B{204};
    bool IsTrueColor{false};
    uint8_t AnsiCode{7}; // Standard 16-color ANSI index (0..15)

    auto operator<=>(const ConptyColor&) const = default;
};

struct ConptyCell {
    char32_t Character{U' '};
    uint16_t Win32Attr{conhost::DEFAULT_CONSOLE_ATTRIBUTES};
    ConptyColor Fg{204, 204, 204, false, 7};
    ConptyColor Bg{12, 12, 12, false, 0};
    bool Bold{false};
    bool Underline{false};
    bool Invert{false};
    bool Italic{false};

    auto operator<=>(const ConptyCell&) const = default;
};

enum class CursorStyle : uint8_t {
    Default           = 0,
    BlinkingBlock     = 1,
    SteadyBlock       = 2,
    BlinkingUnderline = 3,
    SteadyUnderline   = 4,
    BlinkingBar       = 5,
    SteadyBar         = 6
};

// ============================================================================
// 3. Win32 Input Records & Event Types
// ============================================================================

enum class ConptyEventType : uint16_t {
    KeyEvent              = 0x0001,
    MouseEvent            = 0x0002,
    WindowBufferSizeEvent = 0x0004,
    MenuEvent             = 0x0008,
    FocusEvent            = 0x0010
};

// Modifier Key Flags
inline constexpr uint32_t RIGHT_ALT_PRESSED  = 0x0001;
inline constexpr uint32_t LEFT_ALT_PRESSED   = 0x0002;
inline constexpr uint32_t RIGHT_CTRL_PRESSED = 0x0004;
inline constexpr uint32_t LEFT_CTRL_PRESSED  = 0x0008;
inline constexpr uint32_t SHIFT_PRESSED      = 0x0010;
inline constexpr uint32_t NUMLOCK_ON         = 0x0020;
inline constexpr uint32_t SCROLLLOCK_ON      = 0x0040;
inline constexpr uint32_t CAPSLOCK_ON        = 0x0080;
inline constexpr uint32_t ENHANCED_KEY       = 0x0100;

// Mouse Button & Event Flags
inline constexpr uint32_t FROM_LEFT_1ST_BUTTON_PRESSED = 0x0001;
inline constexpr uint32_t RIGHTMOST_BUTTON_PRESSED     = 0x0002;
inline constexpr uint32_t FROM_LEFT_2ND_BUTTON_PRESSED = 0x0004;
inline constexpr uint32_t MOUSE_MOVED                  = 0x0001;
inline constexpr uint32_t DOUBLE_CLICK                 = 0x0002;
inline constexpr uint32_t MOUSE_WHEELED                = 0x0004;
inline constexpr uint32_t MOUSE_HWHEELED               = 0x0008;

// Common Virtual Key Codes
inline constexpr uint16_t VK_BACK   = 0x08;
inline constexpr uint16_t VK_TAB    = 0x09;
inline constexpr uint16_t VK_RETURN = 0x0D;
inline constexpr uint16_t VK_ESCAPE = 0x1B;
inline constexpr uint16_t VK_SPACE  = 0x20;
inline constexpr uint16_t VK_PRIOR  = 0x21; // Page Up
inline constexpr uint16_t VK_NEXT   = 0x22; // Page Down
inline constexpr uint16_t VK_END    = 0x23;
inline constexpr uint16_t VK_HOME   = 0x24;
inline constexpr uint16_t VK_LEFT   = 0x25;
inline constexpr uint16_t VK_UP     = 0x26;
inline constexpr uint16_t VK_RIGHT  = 0x27;
inline constexpr uint16_t VK_DOWN   = 0x28;
inline constexpr uint16_t VK_INSERT = 0x2D;
inline constexpr uint16_t VK_DELETE = 0x2E;
inline constexpr uint16_t VK_F1     = 0x70;
inline constexpr uint16_t VK_F2     = 0x71;
inline constexpr uint16_t VK_F3     = 0x72;
inline constexpr uint16_t VK_F4     = 0x73;
inline constexpr uint16_t VK_F5     = 0x74;
inline constexpr uint16_t VK_F6     = 0x75;
inline constexpr uint16_t VK_F7     = 0x76;
inline constexpr uint16_t VK_F8     = 0x77;
inline constexpr uint16_t VK_F9     = 0x78;
inline constexpr uint16_t VK_F10    = 0x79;
inline constexpr uint16_t VK_F11    = 0x7A;
inline constexpr uint16_t VK_F12    = 0x7B;

struct KEY_EVENT_RECORD {
    BOOL     bKeyDown{TRUE};
    uint16_t wRepeatCount{1};
    uint16_t wVirtualKeyCode{0};
    uint16_t wVirtualScanCode{0};
    wchar_t  uChar{0};
    uint32_t dwControlKeyState{0};
};

struct MOUSE_EVENT_RECORD {
    COORD    dwMousePosition{0, 0};
    uint32_t dwButtonState{0};
    uint32_t dwControlKeyState{0};
    uint32_t dwEventFlags{0};
};

struct WINDOW_BUFFER_SIZE_RECORD {
    COORD dwSize{80, 24};
};

struct MENU_EVENT_RECORD {
    uint32_t dwCommandId{0};
};

struct FOCUS_EVENT_RECORD {
    BOOL bSetFocus{TRUE};
};

struct INPUT_RECORD {
    ConptyEventType EventType{ConptyEventType::KeyEvent};
    union {
        KEY_EVENT_RECORD          KeyEvent;
        MOUSE_EVENT_RECORD        MouseEvent;
        WINDOW_BUFFER_SIZE_RECORD WindowBufferSizeEvent;
        MENU_EVENT_RECORD         MenuEvent;
        FOCUS_EVENT_RECORD        FocusEvent;
    } Event;
};

// ============================================================================
// 4. In-Memory Bidirectional Pipe Buffer (Courier Pipe)
// ============================================================================

class ConptyPipe {
private:
    mutable std::mutex m_mutex;
    std::string        m_buffer;

public:
    ConptyPipe() = default;

    void write(const void* data, size_t size) {
        if (!data || size == 0) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_buffer.append(reinterpret_cast<const char*>(data), size);
    }

    void writeString(std::string_view str) {
        if (str.empty()) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_buffer.append(str);
    }

    size_t read(void* data, size_t maxSize) {
        if (!data || maxSize == 0) return 0;
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t bytesToRead = std::min(maxSize, m_buffer.size());
        if (bytesToRead == 0) return 0;

        std::memcpy(data, m_buffer.data(), bytesToRead);
        m_buffer.erase(0, bytesToRead);
        return bytesToRead;
    }

    std::string readString(size_t maxBytes = 0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_buffer.empty()) return "";

        size_t count = (maxBytes == 0) ? m_buffer.size() : std::min(maxBytes, m_buffer.size());
        std::string result = m_buffer.substr(0, count);
        m_buffer.erase(0, count);
        return result;
    }

    std::string peekString() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_buffer;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_buffer.size();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_buffer.clear();
    }
};

// ============================================================================
// 5. 2D Screen Buffer Matrix
// ============================================================================

class ConptyBuffer {
private:
    int16_t                m_width{80};
    int16_t                m_height{24};
    std::vector<ConptyCell> m_cells;

public:
    ConptyBuffer(int16_t width = 80, int16_t height = 24)
        : m_width(width), m_height(height) {
        resize(width, height);
    }

    void resize(int16_t width, int16_t height) {
        m_width = std::max<int16_t>(1, width);
        m_height = std::max<int16_t>(1, height);
        m_cells.assign(static_cast<size_t>(m_width) * m_height, ConptyCell{});
    }

    [[nodiscard]] int16_t getWidth() const noexcept { return m_width; }
    [[nodiscard]] int16_t getHeight() const noexcept { return m_height; }

    [[nodiscard]] ConptyCell getCell(int16_t x, int16_t y) const noexcept {
        if (x < 0 || x >= m_width || y < 0 || y >= m_height) {
            return ConptyCell{};
        }
        return m_cells[y * m_width + x];
    }

    void setCell(int16_t x, int16_t y, const ConptyCell& cell) noexcept {
        if (x >= 0 && x < m_width && y >= 0 && y < m_height) {
            m_cells[y * m_width + x] = cell;
        }
    }

    void clear(const ConptyCell& fill = ConptyCell{}) {
        std::fill(m_cells.begin(), m_cells.end(), fill);
    }

    void scrollUp(int16_t lines, const ConptyCell& fill = ConptyCell{}) {
        if (lines <= 0) return;
        if (lines >= m_height) {
            clear(fill);
            return;
        }

        size_t rowStride = static_cast<size_t>(m_width);
        for (int16_t y = 0; y < m_height - lines; ++y) {
            std::copy_n(
                m_cells.begin() + (y + lines) * rowStride,
                rowStride,
                m_cells.begin() + y * rowStride
            );
        }

        for (int16_t y = m_height - lines; y < m_height; ++y) {
            std::fill_n(m_cells.begin() + y * rowStride, rowStride, fill);
        }
    }

    [[nodiscard]] const std::vector<ConptyCell>& getCells() const noexcept {
        return m_cells;
    }
};

// ============================================================================
// 6. ConPTY Session Implementation
// ============================================================================

class ConptySession {
private:
    mutable std::mutex m_mutex;

    HPCON       m_handle{nullptr};
    uint64_t    m_id{0};
    COORD       m_size{80, 24};
    uint32_t    m_flags{0};
    bool        m_isActive{true};
    std::string m_title{"MicaNT Sovereign PseudoConsole"};

    // Buffer Architecture (Primary + Alternate Screen Buffer)
    ConptyBuffer m_primaryBuffer;
    ConptyBuffer m_alternateBuffer;
    bool         m_isAlternateActive{false};

    // Shadow Buffer for Differential Rendering
    ConptyBuffer m_shadowBuffer;
    COORD        m_shadowCursor{-1, -1};
    ConptyColor  m_shadowFg{255, 255, 255, false, 255};
    ConptyColor  m_shadowBg{255, 255, 255, false, 255};
    bool         m_shadowBold{false};
    bool         m_shadowUnderline{false};
    bool         m_shadowInvert{false};

    // Cursor State
    COORD       m_cursorPos{0, 0};
    bool        m_cursorVisible{true};
    CursorStyle m_cursorStyle{CursorStyle::Default};

    // Current Style for Active Writes
    ConptyColor m_currentFg{204, 204, 204, false, 7};
    ConptyColor m_currentBg{12, 12, 12, false, 0};
    uint16_t    m_currentWin32Attr{conhost::DEFAULT_CONSOLE_ATTRIBUTES};
    bool        m_currentBold{false};
    bool        m_currentUnderline{false};
    bool        m_currentInvert{false};
    bool        m_currentItalic{false};

    // Pipes connected to Terminal Emulator
    std::shared_ptr<ConptyPipe> m_inPipe;  // Reads from Terminal (VT input stream)
    std::shared_ptr<ConptyPipe> m_outPipe; // Writes to Terminal (VT rendered output)

    // Win32 Input Queue
    std::deque<INPUT_RECORD> m_inputQueue;

    // Attached Processes (e.g. cmd.exe, winget.exe, bash)
    std::vector<uint32_t> m_attachedPids;

    // Telemetry Statistics
    uint64_t m_totalBytesRendered{0};
    uint64_t m_totalBytesInputParsed{0};
    uint64_t m_totalInputEventsEnqueued{0};
    uint64_t m_totalFramesRendered{0};

public:
    ConptySession(
        HPCON handle,
        uint64_t id,
        COORD size,
        uint32_t flags,
        std::shared_ptr<ConptyPipe> inPipe,
        std::shared_ptr<ConptyPipe> outPipe
    )
        : m_handle(handle)
        , m_id(id)
        , m_size(size)
        , m_flags(flags)
        , m_primaryBuffer(size.X, size.Y)
        , m_alternateBuffer(size.X, size.Y)
        , m_shadowBuffer(size.X, size.Y)
        , m_inPipe(inPipe ? inPipe : std::make_shared<ConptyPipe>())
        , m_outPipe(outPipe ? outPipe : std::make_shared<ConptyPipe>())
    {
        m_shadowBuffer.clear(ConptyCell{U'\0'});
        // Emit initial terminal synchronization sequence
        m_outPipe->writeString("\x1b[?25h"); // Show cursor
    }

    [[nodiscard]] HPCON getHandle() const noexcept { return m_handle; }
    [[nodiscard]] uint64_t getId() const noexcept { return m_id; }
    [[nodiscard]] COORD getSize() const noexcept { std::lock_guard<std::mutex> lk(m_mutex); return m_size; }
    [[nodiscard]] uint32_t getFlags() const noexcept { return m_flags; }
    [[nodiscard]] bool isActive() const noexcept { std::lock_guard<std::mutex> lk(m_mutex); return m_isActive; }
    [[nodiscard]] std::string getTitle() const { std::lock_guard<std::mutex> lk(m_mutex); return m_title; }
    [[nodiscard]] std::shared_ptr<ConptyPipe> getInputPipe() const noexcept { return m_inPipe; }
    [[nodiscard]] std::shared_ptr<ConptyPipe> getOutputPipe() const noexcept { return m_outPipe; }

    void close() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_isActive = false;
        // Emit terminal reset upon close
        if (m_outPipe) {
            m_outPipe->writeString("\x1b[0m\x1b[?25h\r\n");
        }
    }

    // Process Association
    void attachProcess(uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (std::find(m_attachedPids.begin(), m_attachedPids.end(), pid) == m_attachedPids.end()) {
            m_attachedPids.push_back(pid);
        }
    }

    void detachProcess(uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove(m_attachedPids.begin(), m_attachedPids.end(), pid);
        if (it != m_attachedPids.end()) {
            m_attachedPids.erase(it, m_attachedPids.end());
        }
    }

    [[nodiscard]] std::vector<uint32_t> getAttachedPids() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_attachedPids;
    }

    // Geometry & Resize
    HRESULT resize(COORD newSize) {
        if (newSize.X <= 0 || newSize.Y <= 0) return E_INVALIDARG;

        std::lock_guard<std::mutex> lock(m_mutex);
        m_size = newSize;
        m_primaryBuffer.resize(newSize.X, newSize.Y);
        m_alternateBuffer.resize(newSize.X, newSize.Y);
        m_shadowBuffer.resize(newSize.X, newSize.Y);
        m_shadowCursor = {-1, -1};

        m_cursorPos.X = std::clamp<int16_t>(m_cursorPos.X, 0, newSize.X - 1);
        m_cursorPos.Y = std::clamp<int16_t>(m_cursorPos.Y, 0, newSize.Y - 1);

        // Notify terminal of geometry change via standard xterm sequence
        std::string resizeSeq = std::format("\x1b[8;{};{}t", newSize.Y, newSize.X);
        m_outPipe->writeString(resizeSeq);

        // Queue WindowBufferSizeEvent for attached Win32 console application
        INPUT_RECORD rec{};
        rec.EventType = ConptyEventType::WindowBufferSizeEvent;
        rec.Event.WindowBufferSizeEvent.dwSize = newSize;
        m_inputQueue.push_back(rec);

        renderFullLocked();
        return S_OK;
    }

    // Styling & Attributes
    void setTextColorRgb(uint8_t r, uint8_t g, uint8_t b) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentFg = {r, g, b, true, 0};
    }

    void setBackgroundColorRgb(uint8_t r, uint8_t g, uint8_t b) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentBg = {r, g, b, true, 0};
    }

    void setWin32Attributes(uint16_t attr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentWin32Attr = attr;
        m_currentBold = (attr & conhost::FOREGROUND_INTENSITY) != 0;

        uint8_t fgIdx = static_cast<uint8_t>(attr & 0x0F);
        uint8_t bgIdx = static_cast<uint8_t>((attr >> 4) & 0x0F);

        bootvid::Color fgCol = conhost::ConsoleAttrToColor(attr, true);
        bootvid::Color bgCol = conhost::ConsoleAttrToColor(attr, false);

        m_currentFg = {fgCol.r, fgCol.g, fgCol.b, false, fgIdx};
        m_currentBg = {bgCol.r, bgCol.g, bgCol.b, false, bgIdx};
    }

    void setTextStyles(bool bold, bool underline, bool invert, bool italic = false) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentBold = bold;
        m_currentUnderline = underline;
        m_currentInvert = invert;
        m_currentItalic = italic;
    }

    void setCursorPosition(COORD pos) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cursorPos.X = std::clamp<int16_t>(pos.X, 0, m_size.X - 1);
        m_cursorPos.Y = std::clamp<int16_t>(pos.Y, 0, m_size.Y - 1);
    }

    [[nodiscard]] COORD getCursorPosition() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_cursorPos;
    }

    void setCursorVisibility(bool visible) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_cursorVisible != visible) {
            m_cursorVisible = visible;
            m_outPipe->writeString(visible ? "\x1b[?25h" : "\x1b[?25l");
        }
    }

    void setCursorStyle(CursorStyle style) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cursorStyle = style;
        m_outPipe->writeString(std::format("\x1b[{} q", static_cast<uint8_t>(style)));
    }

    void setTitle(std::string_view title) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_title = title;
        m_outPipe->writeString(std::format("\x1b]0;{}\x07", title));
    }

    void setAlternateScreenBuffer(bool enable) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_isAlternateActive != enable) {
            m_isAlternateActive = enable;
            m_outPipe->writeString(enable ? "\x1b[?1049h" : "\x1b[?1049l");
            renderFullLocked();
        }
    }

    [[nodiscard]] bool isAlternateScreenActive() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_isAlternateActive;
    }

    // Console Screen Writing (Win32 API Parity)
    void writeChar(char32_t ch) {
        std::lock_guard<std::mutex> lock(m_mutex);
        writeCharLocked(ch);
        renderDifferentialLocked();
    }

    void writeString(std::string_view text) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (size_t i = 0; i < text.size(); ++i) {
            char32_t ch = static_cast<unsigned char>(text[i]);
            // Simple UTF-8 lead-byte decode
            if ((ch & 0x80) == 0) {
                // 1-byte ASCII
            } else if ((ch & 0xE0) == 0xC0 && i + 1 < text.size()) {
                ch = ((ch & 0x1F) << 6) | (static_cast<unsigned char>(text[++i]) & 0x3F);
            } else if ((ch & 0xF0) == 0xE0 && i + 2 < text.size()) {
                ch = ((ch & 0x0F) << 12) |
                     ((static_cast<unsigned char>(text[i + 1]) & 0x3F) << 6) |
                     (static_cast<unsigned char>(text[i + 2]) & 0x3F);
                i += 2;
            }
            writeCharLocked(ch);
        }
        renderDifferentialLocked();
    }

    void writeAt(COORD pos, std::string_view text, uint16_t attr = conhost::DEFAULT_CONSOLE_ATTRIBUTES) {
        std::lock_guard<std::mutex> lock(m_mutex);
        setWin32AttributesLocked(attr);
        m_cursorPos.X = std::clamp<int16_t>(pos.X, 0, m_size.X - 1);
        m_cursorPos.Y = std::clamp<int16_t>(pos.Y, 0, m_size.Y - 1);

        for (char c : text) {
            writeCharLocked(static_cast<char32_t>(static_cast<unsigned char>(c)));
        }
        renderDifferentialLocked();
    }

    void fillOutputCharacter(COORD pos, wchar_t ch, uint32_t count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        ConptyBuffer& buf = getActiveBufferLocked();
        int16_t x = pos.X;
        int16_t y = pos.Y;

        for (uint32_t i = 0; i < count; ++i) {
            if (x >= m_size.X) {
                x = 0;
                y++;
                if (y >= m_size.Y) break;
            }
            ConptyCell cell = buf.getCell(x, y);
            cell.Character = static_cast<char32_t>(ch);
            buf.setCell(x, y, cell);
            x++;
        }
        renderDifferentialLocked();
    }

    void fillOutputAttribute(COORD pos, uint16_t attr, uint32_t count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        ConptyBuffer& buf = getActiveBufferLocked();
        int16_t x = pos.X;
        int16_t y = pos.Y;

        bootvid::Color fg = conhost::ConsoleAttrToColor(attr, true);
        bootvid::Color bg = conhost::ConsoleAttrToColor(attr, false);

        for (uint32_t i = 0; i < count; ++i) {
            if (x >= m_size.X) {
                x = 0;
                y++;
                if (y >= m_size.Y) break;
            }
            ConptyCell cell = buf.getCell(x, y);
            cell.Win32Attr = attr;
            cell.Fg = {fg.r, fg.g, fg.b, false, static_cast<uint8_t>(attr & 0x0F)};
            cell.Bg = {bg.r, bg.g, bg.b, false, static_cast<uint8_t>((attr >> 4) & 0x0F)};
            cell.Bold = (attr & conhost::FOREGROUND_INTENSITY) != 0;
            buf.setCell(x, y, cell);
            x++;
        }
        renderDifferentialLocked();
    }

    void clearScreen() {
        std::lock_guard<std::mutex> lock(m_mutex);
        ConptyCell blank{};
        blank.Fg = m_currentFg;
        blank.Bg = m_currentBg;
        blank.Win32Attr = m_currentWin32Attr;
        getActiveBufferLocked().clear(blank);
        m_cursorPos = {0, 0};
        renderFullLocked();
    }

    [[nodiscard]] ConptyCell getCell(int16_t x, int16_t y) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return const_cast<ConptySession*>(this)->getActiveBufferLocked().getCell(x, y);
    }

    // ========================================================================
    // 7. Differential VT Rendering Engine
    // ========================================================================

    void renderDifferential() {
        std::lock_guard<std::mutex> lock(m_mutex);
        renderDifferentialLocked();
    }

    void renderFull() {
        std::lock_guard<std::mutex> lock(m_mutex);
        renderFullLocked();
    }

    // ========================================================================
    // 8. VT Input Sequence Parser & Event Queueing
    // ========================================================================

    void processTerminalInput(std::string_view vtData) {
        if (vtData.empty()) return;

        std::lock_guard<std::mutex> lock(m_mutex);
        m_totalBytesInputParsed += vtData.size();

        size_t idx = 0;
        while (idx < vtData.size()) {
            char ch = vtData[idx];

            if (ch == '\x1b') {
                // Potential Escape Sequence
                if (idx + 1 >= vtData.size()) {
                    // Lone Escape Key
                    enqueueKeyLocked(VK_ESCAPE, 0x01, L'\x1b');
                    idx++;
                    continue;
                }

                char next = vtData[idx + 1];
                if (next == '[') {
                    // CSI Sequence: \x1b[ ...
                    size_t csiStart = idx + 2;
                    size_t csiEnd = csiStart;
                    while (csiEnd < vtData.size() && (vtData[csiEnd] < 0x40 || vtData[csiEnd] > 0x7E)) {
                        csiEnd++;
                    }

                    if (csiEnd < vtData.size()) {
                        std::string_view csiBody = vtData.substr(csiStart, csiEnd - csiStart);
                        char finalChar = vtData[csiEnd];
                        idx = csiEnd + 1;

                        parseCsiSequenceLocked(csiBody, finalChar);
                        continue;
                    } else {
                        // Incomplete CSI, consume escape
                        idx++;
                        continue;
                    }
                } else if (next == 'O') {
                    // SS3 Sequence: \x1bOP (F1), \x1bOQ (F2), etc.
                    if (idx + 2 < vtData.size()) {
                        char func = vtData[idx + 2];
                        idx += 3;
                        switch (func) {
                            case 'P': enqueueKeyLocked(VK_F1, 0x3B, 0); break;
                            case 'Q': enqueueKeyLocked(VK_F2, 0x3C, 0); break;
                            case 'R': enqueueKeyLocked(VK_F3, 0x3D, 0); break;
                            case 'S': enqueueKeyLocked(VK_F4, 0x3E, 0); break;
                            default: break;
                        }
                        continue;
                    }
                }

                // Unrecognized escape, consume ESC
                idx++;
                continue;
            }

            // Standard ASCII / Control Characters
            idx++;
            switch (ch) {
                case '\r':
                case '\n':
                    enqueueKeyLocked(VK_RETURN, 0x1C, L'\r');
                    break;
                case '\t':
                    enqueueKeyLocked(VK_TAB, 0x0F, L'\t');
                    break;
                case '\x08':
                case '\x7f':
                    enqueueKeyLocked(VK_BACK, 0x0E, L'\x08');
                    break;
                case '\x03': // Ctrl+C
                    enqueueKeyLocked('C', 0x2E, 3, LEFT_CTRL_PRESSED);
                    break;
                case '\x04': // Ctrl+D
                    enqueueKeyLocked('D', 0x20, 4, LEFT_CTRL_PRESSED);
                    break;
                case '\x1a': // Ctrl+Z
                    enqueueKeyLocked('Z', 0x2C, 26, LEFT_CTRL_PRESSED);
                    break;
                default: {
                    wchar_t wch = static_cast<wchar_t>(static_cast<unsigned char>(ch));
                    uint16_t vk = (ch >= 'a' && ch <= 'z') ? static_cast<uint16_t>(ch - 32) : static_cast<uint16_t>(ch);
                    enqueueKeyLocked(vk, 0, wch);
                    break;
                }
            }
        }
    }

    bool dequeueInputRecord(INPUT_RECORD* pRecord) {
        if (!pRecord) return false;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_inputQueue.empty()) return false;

        *pRecord = m_inputQueue.front();
        m_inputQueue.pop_front();
        return true;
    }

    bool peekInputRecord(INPUT_RECORD* pRecord) const {
        if (!pRecord) return false;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_inputQueue.empty()) return false;

        *pRecord = m_inputQueue.front();
        return true;
    }

    [[nodiscard]] size_t getInputQueueSize() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_inputQueue.size();
    }

    // Telemetry Introspection
    [[nodiscard]] uint64_t getTotalBytesRendered() const { return m_totalBytesRendered; }
    [[nodiscard]] uint64_t getTotalBytesInputParsed() const { return m_totalBytesInputParsed; }
    [[nodiscard]] uint64_t getTotalInputEventsEnqueued() const { return m_totalInputEventsEnqueued; }
    [[nodiscard]] uint64_t getTotalFramesRendered() const { return m_totalFramesRendered; }

private:
    ConptyBuffer& getActiveBufferLocked() {
        return m_isAlternateActive ? m_alternateBuffer : m_primaryBuffer;
    }

    void setWin32AttributesLocked(uint16_t attr) {
        m_currentWin32Attr = attr;
        m_currentBold = (attr & conhost::FOREGROUND_INTENSITY) != 0;

        uint8_t fgIdx = static_cast<uint8_t>(attr & 0x0F);
        uint8_t bgIdx = static_cast<uint8_t>((attr >> 4) & 0x0F);

        bootvid::Color fgCol = conhost::ConsoleAttrToColor(attr, true);
        bootvid::Color bgCol = conhost::ConsoleAttrToColor(attr, false);

        m_currentFg = {fgCol.r, fgCol.g, fgCol.b, false, fgIdx};
        m_currentBg = {bgCol.r, bgCol.g, bgCol.b, false, bgIdx};
    }

    void writeCharLocked(char32_t ch) {
        ConptyBuffer& buf = getActiveBufferLocked();

        if (ch == U'\r') {
            m_cursorPos.X = 0;
            return;
        }
        if (ch == U'\n') {
            m_cursorPos.X = 0;
            m_cursorPos.Y++;
            if (m_cursorPos.Y >= m_size.Y) {
                buf.scrollUp(1, ConptyCell{U' ', m_currentWin32Attr, m_currentFg, m_currentBg});
                m_cursorPos.Y = m_size.Y - 1;
            }
            return;
        }
        if (ch == U'\b') {
            if (m_cursorPos.X > 0) m_cursorPos.X--;
            return;
        }

        ConptyCell cell;
        cell.Character = ch;
        cell.Win32Attr = m_currentWin32Attr;
        cell.Fg = m_currentFg;
        cell.Bg = m_currentBg;
        cell.Bold = m_currentBold;
        cell.Underline = m_currentUnderline;
        cell.Invert = m_currentInvert;
        cell.Italic = m_currentItalic;

        buf.setCell(m_cursorPos.X, m_cursorPos.Y, cell);
        m_cursorPos.X++;

        if (m_cursorPos.X >= m_size.X) {
            m_cursorPos.X = 0;
            m_cursorPos.Y++;
            if (m_cursorPos.Y >= m_size.Y) {
                buf.scrollUp(1, ConptyCell{U' ', m_currentWin32Attr, m_currentFg, m_currentBg});
                m_cursorPos.Y = m_size.Y - 1;
            }
        }
    }

    void renderDifferentialLocked() {
        if (!m_isActive || !m_outPipe) return;

        ConptyBuffer& cur = getActiveBufferLocked();
        std::string diffStream;
        diffStream.reserve(512);

        int16_t currentEmitX = -1;
        int16_t currentEmitY = -1;

        for (int16_t y = 0; y < m_size.Y; ++y) {
            for (int16_t x = 0; x < m_size.X; ++x) {
                ConptyCell newCell = cur.getCell(x, y);
                ConptyCell oldCell = m_shadowBuffer.getCell(x, y);

                if (newCell == oldCell) continue;

                // Move cursor if not adjacent
                if (currentEmitY != y || currentEmitX != x) {
                    diffStream.append(std::format("\x1b[{};{}H", y + 1, x + 1));
                    currentEmitY = y;
                    currentEmitX = x;
                }

                // Emit attribute changes
                emitStyleDiffLocked(newCell, diffStream);

                // Emit character
                if (newCell.Character < 128) {
                    diffStream.push_back(static_cast<char>(newCell.Character));
                } else {
                    // Simple UTF-8 encode
                    char32_t cp = newCell.Character;
                    if (cp <= 0x7FF) {
                        diffStream.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
                        diffStream.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    } else if (cp <= 0xFFFF) {
                        diffStream.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
                        diffStream.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                        diffStream.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    } else {
                        diffStream.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
                        diffStream.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                        diffStream.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                        diffStream.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    }
                }

                m_shadowBuffer.setCell(x, y, newCell);
                currentEmitX++;
            }
        }

        // Restore final cursor position to active cursor
        if (m_shadowCursor != m_cursorPos) {
            diffStream.append(std::format("\x1b[{};{}H", m_cursorPos.Y + 1, m_cursorPos.X + 1));
            m_shadowCursor = m_cursorPos;
        }

        if (!diffStream.empty()) {
            m_totalBytesRendered += diffStream.size();
            m_totalFramesRendered++;
            m_outPipe->writeString(diffStream);
        }
    }

    void renderFullLocked() {
        if (!m_isActive || !m_outPipe) return;

        // Reset shadow tracking to force full redraw
        m_shadowBuffer.clear(ConptyCell{U'\0'});
        m_shadowFg = {255, 255, 255, false, 255};
        m_shadowBg = {255, 255, 255, false, 255};
        m_shadowBold = false;
        m_shadowUnderline = false;
        m_shadowInvert = false;
        m_shadowCursor = {-1, -1};

        std::string resetSeq = "\x1b[0m\x1b[2J\x1b[H";
        m_outPipe->writeString(resetSeq);
        m_totalBytesRendered += resetSeq.size();

        renderDifferentialLocked();
    }

    void emitStyleDiffLocked(const ConptyCell& cell, std::string& out) {
        bool needReset = false;
        if (m_shadowBold && !cell.Bold) needReset = true;
        if (m_shadowUnderline && !cell.Underline) needReset = true;
        if (m_shadowInvert && !cell.Invert) needReset = true;

        if (needReset) {
            out.append("\x1b[0m");
            m_shadowBold = false;
            m_shadowUnderline = false;
            m_shadowInvert = false;
            m_shadowFg = {255, 255, 255, false, 255};
            m_shadowBg = {255, 255, 255, false, 255};
        }

        if (cell.Bold && !m_shadowBold) {
            out.append("\x1b[1m");
            m_shadowBold = true;
        }
        if (cell.Underline && !m_shadowUnderline) {
            out.append("\x1b[4m");
            m_shadowUnderline = true;
        }
        if (cell.Invert && !m_shadowInvert) {
            out.append("\x1b[7m");
            m_shadowInvert = true;
        }

        // Foreground color
        if (cell.Fg != m_shadowFg) {
            if (cell.Fg.IsTrueColor) {
                out.append(std::format("\x1b[38;2;{};{};{}m", cell.Fg.R, cell.Fg.G, cell.Fg.B));
            } else {
                if (cell.Fg.AnsiCode < 8) {
                    out.append(std::format("\x1b[{}m", 30 + cell.Fg.AnsiCode));
                } else {
                    out.append(std::format("\x1b[{}m", 90 + (cell.Fg.AnsiCode - 8)));
                }
            }
            m_shadowFg = cell.Fg;
        }

        // Background color
        if (cell.Bg != m_shadowBg) {
            if (cell.Bg.IsTrueColor) {
                out.append(std::format("\x1b[48;2;{};{};{}m", cell.Bg.R, cell.Bg.G, cell.Bg.B));
            } else {
                if (cell.Bg.AnsiCode < 8) {
                    out.append(std::format("\x1b[{}m", 40 + cell.Bg.AnsiCode));
                } else {
                    out.append(std::format("\x1b[{}m", 100 + (cell.Bg.AnsiCode - 8)));
                }
            }
            m_shadowBg = cell.Bg;
        }
    }

    void enqueueKeyLocked(uint16_t vk, uint16_t scan, wchar_t ch, uint32_t mod = 0) {
        INPUT_RECORD rec{};
        rec.EventType = ConptyEventType::KeyEvent;
        rec.Event.KeyEvent.bKeyDown = TRUE;
        rec.Event.KeyEvent.wRepeatCount = 1;
        rec.Event.KeyEvent.wVirtualKeyCode = vk;
        rec.Event.KeyEvent.wVirtualScanCode = scan;
        rec.Event.KeyEvent.uChar = ch;
        rec.Event.KeyEvent.dwControlKeyState = mod;

        m_inputQueue.push_back(rec);
        m_totalInputEventsEnqueued++;
    }

    void enqueueMouseLocked(COORD pos, uint32_t btn, uint32_t flags = 0, uint32_t mod = 0) {
        INPUT_RECORD rec{};
        rec.EventType = ConptyEventType::MouseEvent;
        rec.Event.MouseEvent.dwMousePosition = pos;
        rec.Event.MouseEvent.dwButtonState = btn;
        rec.Event.MouseEvent.dwControlKeyState = mod;
        rec.Event.MouseEvent.dwEventFlags = flags;

        m_inputQueue.push_back(rec);
        m_totalInputEventsEnqueued++;
    }

    void parseCsiSequenceLocked(std::string_view body, char finalChar) {
        // Arrow Keys
        switch (finalChar) {
            case 'A': enqueueKeyLocked(VK_UP, 0x48, 0, ENHANCED_KEY); return;
            case 'B': enqueueKeyLocked(VK_DOWN, 0x50, 0, ENHANCED_KEY); return;
            case 'C': enqueueKeyLocked(VK_RIGHT, 0x4D, 0, ENHANCED_KEY); return;
            case 'D': enqueueKeyLocked(VK_LEFT, 0x4B, 0, ENHANCED_KEY); return;
            case 'H': enqueueKeyLocked(VK_HOME, 0x47, 0, ENHANCED_KEY); return;
            case 'F': enqueueKeyLocked(VK_END, 0x4F, 0, ENHANCED_KEY); return;
            case 'Z': enqueueKeyLocked(VK_TAB, 0x0F, L'\t', SHIFT_PRESSED); return;
            default: break;
        }

        // Tilde Sequences: \x1b[<num>~
        if (finalChar == '~') {
            int code = 0;
            try {
                code = std::stoi(std::string(body));
            } catch (...) { return; }

            switch (code) {
                case 1:  enqueueKeyLocked(VK_HOME, 0x47, 0, ENHANCED_KEY); break;
                case 2:  enqueueKeyLocked(VK_INSERT, 0x52, 0, ENHANCED_KEY); break;
                case 3:  enqueueKeyLocked(VK_DELETE, 0x53, 0, ENHANCED_KEY); break;
                case 4:  enqueueKeyLocked(VK_END, 0x4F, 0, ENHANCED_KEY); break;
                case 5:  enqueueKeyLocked(VK_PRIOR, 0x49, 0, ENHANCED_KEY); break; // PgUp
                case 6:  enqueueKeyLocked(VK_NEXT, 0x51, 0, ENHANCED_KEY); break;  // PgDn
                case 15: enqueueKeyLocked(VK_F1 + 4, 0x3F, 0); break; // F5
                case 17: enqueueKeyLocked(VK_F1 + 5, 0x40, 0); break; // F6
                case 18: enqueueKeyLocked(VK_F1 + 6, 0x41, 0); break; // F7
                case 19: enqueueKeyLocked(VK_F1 + 7, 0x42, 0); break; // F8
                case 20: enqueueKeyLocked(VK_F1 + 8, 0x43, 0); break; // F9
                case 21: enqueueKeyLocked(VK_F1 + 9, 0x44, 0); break; // F10
                case 23: enqueueKeyLocked(VK_F1 + 10, 0x57, 0); break; // F11
                case 24: enqueueKeyLocked(VK_F1 + 11, 0x58, 0); break; // F12
                default: break;
            }
            return;
        }

        // SGR Mouse format: \x1b[<Btn;X;YM or \x1b[<Btn;X;Ym
        if ((finalChar == 'M' || finalChar == 'm') && body.starts_with("<")) {
            std::string params(body.substr(1));
            std::stringstream ss(params);
            std::string tokBtn, tokX, tokY;
            if (std::getline(ss, tokBtn, ';') && std::getline(ss, tokX, ';') && std::getline(ss, tokY, ';')) {
                try {
                    int btn = std::stoi(tokBtn);
                    int x = std::stoi(tokX) - 1; // 1-indexed to 0-indexed
                    int y = std::stoi(tokY) - 1;

                    uint32_t btnState = 0;
                    uint32_t evtFlags = 0;
                    if (finalChar == 'M') {
                        if (btn == 0) btnState = FROM_LEFT_1ST_BUTTON_PRESSED;
                        else if (btn == 2) btnState = RIGHTMOST_BUTTON_PRESSED;
                        else if (btn == 1) btnState = FROM_LEFT_2ND_BUTTON_PRESSED;
                        else if (btn == 64) { btnState = 0x00780000; evtFlags = MOUSE_WHEELED; }
                        else if (btn == 65) { btnState = 0xFF880000; evtFlags = MOUSE_WHEELED; }
                    }

                    enqueueMouseLocked(
                        COORD{static_cast<int16_t>(std::max(0, x)), static_cast<int16_t>(std::max(0, y))},
                        btnState,
                        evtFlags
                    );
                } catch (...) {}
            }
        }
    }
};

// ============================================================================
// 9. ConPTY Subsystem Engine (Singleton Manager)
// ============================================================================

struct ConptySessionInfo {
    HPCON       Handle{nullptr};
    uint64_t    Id{0};
    COORD       Size{80, 24};
    uint32_t    Flags{0};
    bool        IsActive{true};
    std::string Title;
    size_t      AttachedProcessCount{0};
    uint64_t    TotalBytesRendered{0};
    uint64_t    TotalInputEventsEnqueued{0};
};

class TitanPtyEngine {
private:
    std::mutex m_mutex;
    uint64_t   m_nextId{100};
    std::unordered_map<HPCON, std::shared_ptr<ConptySession>> m_sessions;

    TitanPtyEngine() = default;

public:
    static TitanPtyEngine& Instance() {
        static TitanPtyEngine s_instance;
        return s_instance;
    }

    HRESULT createPseudoConsole(
        COORD size,
        std::shared_ptr<ConptyPipe> inPipe,
        std::shared_ptr<ConptyPipe> outPipe,
        uint32_t flags,
        HPCON* phPC
    ) {
        if (!phPC) return E_INVALIDARG;
        if (size.X <= 0 || size.Y <= 0) return E_INVALIDARG;

        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t id = m_nextId++;
        HPCON handle = reinterpret_cast<HPCON>(static_cast<uintptr_t>(id));

        auto session = std::make_shared<ConptySession>(handle, id, size, flags, inPipe, outPipe);
        m_sessions[handle] = session;

        *phPC = handle;
        return S_OK;
    }

    HRESULT resizePseudoConsole(HPCON hPC, COORD size) {
        std::shared_ptr<ConptySession> session;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_sessions.find(hPC);
            if (it == m_sessions.end()) return E_HANDLE;
            session = it->second;
        }
        return session->resize(size);
    }

    void closePseudoConsole(HPCON hPC) {
        std::shared_ptr<ConptySession> session;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_sessions.find(hPC);
            if (it == m_sessions.end()) return;
            session = it->second;
            m_sessions.erase(it);
        }
        if (session) {
            session->close();
        }
    }

    std::shared_ptr<ConptySession> getSession(HPCON hPC) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(hPC);
        if (it != m_sessions.end()) {
            return it->second;
        }
        return nullptr;
    }

    size_t getSessionCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sessions.size();
    }

    std::vector<ConptySessionInfo> getSessionsSnapshot() {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<ConptySessionInfo> list;
        list.reserve(m_sessions.size());

        for (const auto& [handle, session] : m_sessions) {
            ConptySessionInfo info;
            info.Handle = handle;
            info.Id = session->getId();
            info.Size = session->getSize();
            info.Flags = session->getFlags();
            info.IsActive = session->isActive();
            info.Title = session->getTitle();
            info.AttachedProcessCount = session->getAttachedPids().size();
            info.TotalBytesRendered = session->getTotalBytesRendered();
            info.TotalInputEventsEnqueued = session->getTotalInputEventsEnqueued();
            list.push_back(info);
        }
        return list;
    }
};

// ============================================================================
// 10. Process Thread Attribute List Implementation
// ============================================================================

struct PROC_THREAD_ATTRIBUTE_ENTRY {
    uintptr_t Attribute{0};
    size_t    Size{0};
    void*     Value{nullptr};
};

struct PROC_THREAD_ATTRIBUTE_LIST {
    uint32_t MaxAttributes{0};
    uint32_t Count{0};
    std::vector<PROC_THREAD_ATTRIBUTE_ENTRY> Entries;
};

using LPPROC_THREAD_ATTRIBUTE_LIST = PROC_THREAD_ATTRIBUTE_LIST*;

inline BOOL WINAPI InitializeProcThreadAttributeList(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    uint32_t dwAttributeCount,
    uint32_t dwFlags,
    size_t* lpSize
) {
    (void)dwFlags;
    size_t requiredSize = sizeof(PROC_THREAD_ATTRIBUTE_LIST) + (sizeof(PROC_THREAD_ATTRIBUTE_ENTRY) * dwAttributeCount);
    if (lpSize) {
        *lpSize = requiredSize;
    }

    if (!lpAttributeList) {
        return FALSE;
    }

    lpAttributeList->MaxAttributes = dwAttributeCount;
    lpAttributeList->Count = 0;
    lpAttributeList->Entries.clear();
    lpAttributeList->Entries.reserve(dwAttributeCount);
    return TRUE;
}

inline BOOL WINAPI UpdateProcThreadAttribute(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    uint32_t dwFlags,
    uintptr_t Attribute,
    void* lpValue,
    size_t cbSize,
    void* lpPreviousValue,
    size_t* lpReturnSize
) {
    (void)dwFlags;
    (void)lpPreviousValue;
    (void)lpReturnSize;

    if (!lpAttributeList) return FALSE;
    if (lpAttributeList->Count >= lpAttributeList->MaxAttributes) return FALSE;

    lpAttributeList->Entries.push_back(PROC_THREAD_ATTRIBUTE_ENTRY{
        .Attribute = Attribute,
        .Size = cbSize,
        .Value = lpValue
    });
    lpAttributeList->Count++;
    return TRUE;
}

inline void WINAPI DeleteProcThreadAttributeList(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
) {
    if (lpAttributeList) {
        lpAttributeList->Entries.clear();
        lpAttributeList->Count = 0;
        lpAttributeList->MaxAttributes = 0;
    }
}

// ============================================================================
// 11. Standard Win32 C ABI Exports
// ============================================================================

inline HRESULT WINAPI CreatePseudoConsole(
    COORD size,
    void* hInput,
    void* hOutput,
    uint32_t dwFlags,
    HPCON* phPC
) {
    (void)hInput;
    (void)hOutput;
    return TitanPtyEngine::Instance().createPseudoConsole(
        size,
        nullptr, // Default in-memory pipes
        nullptr,
        dwFlags,
        phPC
    );
}

inline HRESULT WINAPI ResizePseudoConsole(
    HPCON hPC,
    COORD size
) {
    return TitanPtyEngine::Instance().resizePseudoConsole(hPC, size);
}

inline void WINAPI ClosePseudoConsole(
    HPCON hPC
) {
    TitanPtyEngine::Instance().closePseudoConsole(hPC);
}

// ============================================================================
// 12. Subsystem Export & SCM Registration
// ============================================================================

inline void InitializeConptySubsystem() {
    static bool s_initialized = false;
    if (s_initialized) return;
    s_initialized = true;

    // 1. Dynamic Loader Exports in kernel32.dll
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("kernel32.dll", "CreatePseudoConsole", reinterpret_cast<void*>(CreatePseudoConsole));
    ldr.registerExport("kernel32.dll", "ResizePseudoConsole", reinterpret_cast<void*>(ResizePseudoConsole));
    ldr.registerExport("kernel32.dll", "ClosePseudoConsole", reinterpret_cast<void*>(ClosePseudoConsole));
    ldr.registerExport("kernel32.dll", "InitializeProcThreadAttributeList", reinterpret_cast<void*>(InitializeProcThreadAttributeList));
    ldr.registerExport("kernel32.dll", "UpdateProcThreadAttribute", reinterpret_cast<void*>(UpdateProcThreadAttribute));
    ldr.registerExport("kernel32.dll", "DeleteProcThreadAttributeList", reinterpret_cast<void*>(DeleteProcThreadAttributeList));

    // 2. Register OpenConsole Host Service in SCM
    auto openConsoleSvc = std::make_shared<scm::ServiceRecord>();
    openConsoleSvc->serviceName = L"OpenConsole";
    openConsoleSvc->displayName = L"OpenConsole Terminal Host Engine";
    openConsoleSvc->serviceType = scm::SERVICE_WIN32_OWN_PROCESS;
    openConsoleSvc->startType = scm::SERVICE_AUTO_START;
    openConsoleSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
    openConsoleSvc->binaryPath = L"C:\\Windows\\System32\\OpenConsole.exe";
    openConsoleSvc->serviceStartName = L"LocalSystem";
    openConsoleSvc->status.dwProcessId = 1190;
    openConsoleSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    openConsoleSvc->status.dwControlsAccepted = scm::SERVICE_ACCEPT_STOP | scm::SERVICE_ACCEPT_SHUTDOWN;

    scm::ServiceControlManager::get().registerServiceRecord(openConsoleSvc);

    // 3. Register Version Information
    version::VersionDatabase::Instance().RegisterModule(
        "OpenConsole.exe",
        "10.0.22621.1",
        "MicaNT Sovereign OpenConsole Terminal Host"
    );
}

} // namespace micant::conpty
