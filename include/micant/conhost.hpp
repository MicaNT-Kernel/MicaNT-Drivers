#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <algorithm>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "bootvid.hpp"

namespace micant::conhost {

// Standard Win32 Console Color Attributes
inline constexpr uint16_t FOREGROUND_BLUE      = 0x0001;
inline constexpr uint16_t FOREGROUND_GREEN     = 0x0002;
inline constexpr uint16_t FOREGROUND_RED       = 0x0004;
inline constexpr uint16_t FOREGROUND_INTENSITY = 0x0008;
inline constexpr uint16_t BACKGROUND_BLUE      = 0x0010;
inline constexpr uint16_t BACKGROUND_GREEN     = 0x0020;
inline constexpr uint16_t BACKGROUND_RED       = 0x0040;
inline constexpr uint16_t BACKGROUND_INTENSITY = 0x0080;

inline constexpr uint16_t DEFAULT_CONSOLE_ATTRIBUTES = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; // White on black

/**
 * @brief 2D Coordinate in Console character grid.
 */
struct Coord {
    int16_t x{0};
    int16_t y{0};
};

/**
 * @brief Window bounds in character coordinates.
 */
struct SmallRect {
    int16_t left{0};
    int16_t top{0};
    int16_t right{0};
    int16_t bottom{0};
};

/**
 * @brief Character and Attribute cell.
 */
struct CharInfo {
    wchar_t character{L' '};
    uint16_t attributes{DEFAULT_CONSOLE_ATTRIBUTES};
};

/**
 * @brief Win32 CONSOLE_SCREEN_BUFFER_INFO
 */
struct ConsoleScreenBufferInfo {
    Coord dwSize{};
    Coord dwCursorPosition{};
    uint16_t wAttributes{DEFAULT_CONSOLE_ATTRIBUTES};
    SmallRect srWindow{};
    Coord dwMaximumWindowSize{};
};

/**
 * @brief Convert Win32 4-bit console color attributes to 32-bit bootvid::Color.
 */
inline bootvid::Color ConsoleAttrToColor(uint16_t attr, bool isForeground) noexcept {
    uint8_t flags = isForeground ? static_cast<uint8_t>(attr & 0x0F) : static_cast<uint8_t>((attr >> 4) & 0x0F);
    bool b = (flags & 0x01) != 0;
    bool g = (flags & 0x02) != 0;
    bool r = (flags & 0x04) != 0;
    bool intensity = (flags & 0x08) != 0;

    uint8_t base = intensity ? 255 : 170;
    if (!r && !g && !b) {
        return intensity ? bootvid::Color(85, 85, 85) : bootvid::Color(0, 0, 0);
    }
    return bootvid::Color(
        r ? base : 0,
        g ? base : 0,
        b ? base : 0
    );
}

/**
 * @brief 2D Matrix Console Screen Buffer.
 * Supports scrolling, line-wrapping, and rendering to GOP linear framebuffer.
 */
class ConsoleScreenBuffer {
private:
    int16_t m_width{80};
    int16_t m_height{25};
    Coord m_cursorPosition{0, 0};
    uint16_t m_currentAttributes{DEFAULT_CONSOLE_ATTRIBUTES};
    std::vector<CharInfo> m_cells;
    bool m_cursorVisible{true};

public:
    ConsoleScreenBuffer(int16_t width = 80, int16_t height = 25)
        : m_width(width), m_height(height) {
        m_cells.resize(static_cast<size_t>(m_width) * m_height, CharInfo{L' ', DEFAULT_CONSOLE_ATTRIBUTES});
    }

    [[nodiscard]] int16_t getWidth() const noexcept { return m_width; }
    [[nodiscard]] int16_t getHeight() const noexcept { return m_height; }
    [[nodiscard]] Coord getCursorPosition() const noexcept { return m_cursorPosition; }
    [[nodiscard]] uint16_t getAttributes() const noexcept { return m_currentAttributes; }

    [[nodiscard]] ConsoleScreenBufferInfo getScreenBufferInfo() const noexcept {
        return ConsoleScreenBufferInfo{
            .dwSize = { m_width, m_height },
            .dwCursorPosition = m_cursorPosition,
            .wAttributes = m_currentAttributes,
            .srWindow = { 0, 0, static_cast<int16_t>(m_width - 1), static_cast<int16_t>(m_height - 1) },
            .dwMaximumWindowSize = { m_width, m_height }
        };
    }

    void setAttributes(uint16_t attr) noexcept {
        m_currentAttributes = attr;
    }

    void setCursorPosition(Coord pos) noexcept {
        m_cursorPosition.x = std::clamp<int16_t>(pos.x, 0, m_width - 1);
        m_cursorPosition.y = std::clamp<int16_t>(pos.y, 0, m_height - 1);
    }

    [[nodiscard]] CharInfo getCell(int16_t x, int16_t y) const noexcept {
        if (x < 0 || x >= m_width || y < 0 || y >= m_height) return {L' ', 0};
        return m_cells[y * m_width + x];
    }

    void clear() {
        for (auto& cell : m_cells) {
            cell.character = L' ';
            cell.attributes = m_currentAttributes;
        }
        m_cursorPosition = {0, 0};
    }

    /**
     * @brief Scroll the buffer up by N rows.
     */
    void scrollUp(int16_t rows = 1) {
        if (rows <= 0) return;
        if (rows >= m_height) {
            clear();
            return;
        }

        // Shift rows up
        for (int16_t y = 0; y < m_height - rows; ++y) {
            for (int16_t x = 0; x < m_width; ++x) {
                m_cells[y * m_width + x] = m_cells[(y + rows) * m_width + x];
            }
        }

        // Clear bottom rows
        for (int16_t y = m_height - rows; y < m_height; ++y) {
            for (int16_t x = 0; x < m_width; ++x) {
                m_cells[y * m_width + x] = CharInfo{L' ', m_currentAttributes};
            }
        }
    }

    /**
     * @brief Write a single wide character to the console grid.
     */
    void writeChar(wchar_t c) {
        if (c == L'\r') {
            m_cursorPosition.x = 0;
            return;
        }
        if (c == L'\n') {
            m_cursorPosition.x = 0;
            m_cursorPosition.y++;
            if (m_cursorPosition.y >= m_height) {
                scrollUp(1);
                m_cursorPosition.y = m_height - 1;
            }
            return;
        }
        if (c == L'\t') {
            m_cursorPosition.x = static_cast<int16_t>((m_cursorPosition.x + 8) & ~7);
            if (m_cursorPosition.x >= m_width) {
                m_cursorPosition.x = 0;
                m_cursorPosition.y++;
                if (m_cursorPosition.y >= m_height) {
                    scrollUp(1);
                    m_cursorPosition.y = m_height - 1;
                }
            }
            return;
        }
        if (c == L'\b') {
            if (m_cursorPosition.x > 0) {
                m_cursorPosition.x--;
                m_cells[m_cursorPosition.y * m_width + m_cursorPosition.x] = CharInfo{L' ', m_currentAttributes};
            }
            return;
        }

        // Put character at cursor
        if (m_cursorPosition.x < m_width && m_cursorPosition.y < m_height) {
            m_cells[m_cursorPosition.y * m_width + m_cursorPosition.x] = CharInfo{c, m_currentAttributes};
        }

        m_cursorPosition.x++;
        if (m_cursorPosition.x >= m_width) {
            m_cursorPosition.x = 0;
            m_cursorPosition.y++;
            if (m_cursorPosition.y >= m_height) {
                scrollUp(1);
                m_cursorPosition.y = m_height - 1;
            }
        }
    }

    /**
     * @brief Write a string to the buffer.
     */
    void writeString(std::wstring_view text) {
        for (wchar_t c : text) {
            writeChar(c);
        }
    }

    /**
     * @brief Retrieve complete buffer content as single multiline string.
     */
    [[nodiscard]] std::wstring getBufferText() const {
        std::wstring result;
        result.reserve(static_cast<size_t>(m_width) * m_height);
        for (int16_t y = 0; y < m_height; ++y) {
            for (int16_t x = 0; x < m_width; ++x) {
                result += m_cells[y * m_width + x].character;
            }
            result += L'\n';
        }
        return result;
    }

    /**
     * @brief Render this console screen buffer to a GOP linear framebuffer region.
     */
    void renderToFramebuffer(bootvid::BootVideoDriver& driver, uint32_t startX, uint32_t startY, uint32_t fontScale = 1) const {
        if (!driver.isInitialized()) return;

        uint32_t cellW = 8 * fontScale;
        uint32_t cellH = 8 * fontScale;

        // Render each cell
        for (int16_t cy = 0; cy < m_height; ++cy) {
            for (int16_t cx = 0; cx < m_width; ++cx) {
                const auto& cell = m_cells[cy * m_width + cx];
                bootvid::Color fg = ConsoleAttrToColor(cell.attributes, true);
                bootvid::Color bg = ConsoleAttrToColor(cell.attributes, false);

                uint32_t px = startX + (cx * cellW);
                uint32_t py = startY + (cy * cellH);

                char asciiChar = (cell.character >= 32 && cell.character <= 126) 
                                 ? static_cast<char>(cell.character) 
                                 : ' ';
                driver.drawChar(px, py, asciiChar, fg, bg, fontScale);
            }
        }

        // Draw cursor
        if (m_cursorVisible && m_cursorPosition.x < m_width && m_cursorPosition.y < m_height) {
            uint32_t curX = startX + (m_cursorPosition.x * cellW);
            uint32_t curY = startY + (m_cursorPosition.y * cellH) + cellH - 2;
            driver.fillRectangle(curX, curY, cellW, 2, bootvid::Color::white());
        }
    }
};

/**
 * @brief Represents an active Console Host session.
 */
class ConsoleSession {
private:
    uint32_t m_ownerProcessId{0};
    std::wstring m_title{L"MicaNT Console Window"};
    ConsoleScreenBuffer m_screenBuffer{80, 25};
    Handle m_inputHandle{0x10};
    Handle m_outputHandle{0x14};
    Handle m_errorHandle{0x18};
    std::wstring m_inputQueue;
    std::mutex m_mutex;

public:
    ConsoleSession(uint32_t ownerPid, std::wstring title = L"MicaNT Console Window")
        : m_ownerProcessId(ownerPid), m_title(std::move(title)) {}

    [[nodiscard]] uint32_t getOwnerPid() const noexcept { return m_ownerProcessId; }
    [[nodiscard]] const std::wstring& getTitle() const noexcept { return m_title; }
    void setTitle(std::wstring_view title) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_title = std::wstring(title);
    }

    [[nodiscard]] Handle getInputHandle() const noexcept { return m_inputHandle; }
    [[nodiscard]] Handle getOutputHandle() const noexcept { return m_outputHandle; }
    [[nodiscard]] Handle getErrorHandle() const noexcept { return m_errorHandle; }

    ConsoleScreenBuffer& getScreenBuffer() noexcept { return m_screenBuffer; }
    const ConsoleScreenBuffer& getScreenBuffer() const noexcept { return m_screenBuffer; }

    void writeOutput(std::wstring_view text) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_screenBuffer.writeString(text);
    }

    void queueInput(std::wstring_view text) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_inputQueue.append(text);
    }

    size_t readInput(wchar_t* buffer, size_t maxChars) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!buffer || maxChars == 0) return 0;
        size_t count = std::min(maxChars, m_inputQueue.length());
        for (size_t i = 0; i < count; ++i) {
            buffer[i] = m_inputQueue[i];
        }
        m_inputQueue.erase(0, count);
        return count;
    }
};

/**
 * @brief Console Host Manager (`conhost.exe` daemon abstraction).
 */
class ConhostManager {
private:
    std::mutex m_mutex;
    std::unordered_map<uint32_t, std::shared_ptr<ConsoleSession>> m_sessions;
    uint32_t m_nextSessionId{1};

    ConhostManager() = default;

public:
    static ConhostManager& get() noexcept {
        static ConhostManager instance;
        return instance;
    }

    std::shared_ptr<ConsoleSession> allocateConsole(uint32_t pid, std::wstring_view title = L"MicaNT Console Window") {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(pid);
        if (it != m_sessions.end()) {
            return it->second; // Process already has a console
        }

        auto session = std::make_shared<ConsoleSession>(pid, std::wstring(title));
        m_sessions[pid] = session;
        return session;
    }

    std::shared_ptr<ConsoleSession> getConsole(uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(pid);
        if (it != m_sessions.end()) {
            return it->second;
        }
        return nullptr;
    }

    bool freeConsole(uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sessions.erase(pid) > 0;
    }

    [[nodiscard]] size_t getActiveConsoleCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sessions.size();
    }
};

} // namespace micant::conhost
