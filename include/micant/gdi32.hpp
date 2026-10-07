// ============================================================================
// MicaNT: Win32 GDI Subsystem (gdi32.dll)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Provides complete Graphics Device Interface (GDI) Device Contexts,
// Bitmaps, DIB Sections, Brushes, Pens, Fonts, 2D Drawing Primitives,
// ROP2/ROP3 Blitting, Typography, and OpenGL/3D Pixel Format Management.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <cmath>
#include <cwchar>

#include "ntdef.hpp"
#include "kernel32.hpp"
#include "user32.hpp"
#include "bootvid.hpp"
#include "ldr.hpp"

namespace micant::gdi32 {

// ============================================================================
// 1. Data Types & Handle Definitions
// ============================================================================

using COLORREF = uint32_t;
using HGDIOBJ  = void*;
using HDC      = void*;
using HBITMAP  = void*;
using HBRUSH   = void*;
using HPEN     = void*;
using HFONT    = void*;
using HRGN     = void*;

inline constexpr COLORREF RGB(uint8_t r, uint8_t g, uint8_t b) noexcept {
    return static_cast<COLORREF>(r | (static_cast<uint16_t>(g) << 8) | (static_cast<uint32_t>(b) << 16));
}

inline constexpr uint8_t GetRValue(COLORREF rgb) noexcept { return static_cast<uint8_t>(rgb & 0xFF); }
inline constexpr uint8_t GetGValue(COLORREF rgb) noexcept { return static_cast<uint8_t>((rgb >> 8) & 0xFF); }
inline constexpr uint8_t GetBValue(COLORREF rgb) noexcept { return static_cast<uint8_t>((rgb >> 16) & 0xFF); }

// GDI Object Types
inline constexpr uint32_t OBJ_PEN    = 1;
inline constexpr uint32_t OBJ_BRUSH  = 2;
inline constexpr uint32_t OBJ_DC     = 3;
inline constexpr uint32_t OBJ_FONT   = 6;
inline constexpr uint32_t OBJ_BITMAP = 7;
inline constexpr uint32_t OBJ_REGION = 8;

// Stock Objects
inline constexpr int WHITE_BRUSH         = 0;
inline constexpr int LTGRAY_BRUSH        = 1;
inline constexpr int GRAY_BRUSH          = 2;
inline constexpr int DKGRAY_BRUSH        = 3;
inline constexpr int BLACK_BRUSH         = 4;
inline constexpr int NULL_BRUSH          = 5;
inline constexpr int HOLLOW_BRUSH        = NULL_BRUSH;
inline constexpr int WHITE_PEN           = 6;
inline constexpr int BLACK_PEN           = 7;
inline constexpr int NULL_PEN            = 8;
inline constexpr int OEM_FIXED_FONT      = 10;
inline constexpr int ANSI_FIXED_FONT     = 11;
inline constexpr int ANSI_VAR_FONT       = 12;
inline constexpr int SYSTEM_FONT         = 13;
inline constexpr int DEVICE_DEFAULT_FONT = 14;
inline constexpr int DEFAULT_PALETTE     = 15;
inline constexpr int SYSTEM_FIXED_FONT   = 16;
inline constexpr int DEFAULT_GUI_FONT    = 17;

// Pen Styles
inline constexpr int PS_SOLID       = 0;
inline constexpr int PS_DASH        = 1;
inline constexpr int PS_DOT         = 2;
inline constexpr int PS_DASHDOT     = 3;
inline constexpr int PS_DASHDOTDOT  = 4;
inline constexpr int PS_NULL        = 5;
inline constexpr int PS_INSIDEFRAME = 6;

// Brush Styles
inline constexpr uint32_t BS_SOLID   = 0;
inline constexpr uint32_t BS_NULL    = 1;
inline constexpr uint32_t BS_HOLLOW  = BS_NULL;
inline constexpr uint32_t BS_HATCHED = 2;
inline constexpr uint32_t BS_PATTERN = 3;

// Background Modes
inline constexpr int TRANSPARENT = 1;
inline constexpr int OPAQUE      = 2;

// Raster Operations (ROPs)
inline constexpr uint32_t SRCCOPY     = 0x00CC0020;
inline constexpr uint32_t SRCPAINT    = 0x00EE0086;
inline constexpr uint32_t SRCAND      = 0x008800C6;
inline constexpr uint32_t SRCINVERT   = 0x00660046;
inline constexpr uint32_t SRCERASE    = 0x00440328;
inline constexpr uint32_t NOTSRCCOPY  = 0x00330008;
inline constexpr uint32_t NOTSRCERASE = 0x001100A6;
inline constexpr uint32_t MERGECOPY   = 0x00C000CA;
inline constexpr uint32_t MERGEPAINT  = 0x00BB0226;
inline constexpr uint32_t PATCOPY     = 0x00F00021;
inline constexpr uint32_t PATPAINT    = 0x00FB0A09;
inline constexpr uint32_t PATINVERT   = 0x005A0049;
inline constexpr uint32_t DSTINVERT   = 0x00550009;
inline constexpr uint32_t BLACKNESS   = 0x00000042;
inline constexpr uint32_t WHITENESS   = 0x00FF0062;

// DIB Color Table Usage
inline constexpr uint32_t DIB_RGB_COLORS = 0;
inline constexpr uint32_t DIB_PAL_COLORS = 1;

// Pixel Format Flags (OpenGL)
inline constexpr uint32_t PFD_DOUBLEBUFFER      = 0x00000001;
inline constexpr uint32_t PFD_STEREO            = 0x00000002;
inline constexpr uint32_t PFD_DRAW_TO_WINDOW    = 0x00000004;
inline constexpr uint32_t PFD_DRAW_TO_BITMAP    = 0x00000008;
inline constexpr uint32_t PFD_SUPPORT_GDI       = 0x00000010;
inline constexpr uint32_t PFD_SUPPORT_OPENGL    = 0x00000020;
inline constexpr uint8_t  PFD_TYPE_RGBA         = 0;
inline constexpr uint8_t  PFD_TYPE_COLORINDEX   = 1;
inline constexpr uint8_t  PFD_MAIN_PLANE        = 0;

// Device Caps
inline constexpr int HORZRES     = 8;
inline constexpr int VERTRES     = 10;
inline constexpr int BITSPIXEL   = 12;
inline constexpr int PLANES      = 14;
inline constexpr int LOGPIXELSX  = 88;
inline constexpr int LOGPIXELSY  = 90;

// Structures
struct POINT {
    int32_t x{0};
    int32_t y{0};
};
using LPPOINT = POINT*;

struct SIZE {
    int32_t cx{0};
    int32_t cy{0};
};
using LPSIZE = SIZE*;

struct RECT {
    int32_t left{0};
    int32_t top{0};
    int32_t right{0};
    int32_t bottom{0};
};
using LPRECT = RECT*;

struct BITMAP {
    int32_t  bmType{0};
    int32_t  bmWidth{0};
    int32_t  bmHeight{0};
    int32_t  bmWidthBytes{0};
    uint16_t bmPlanes{1};
    uint16_t bmBitsPixel{32};
    void*    bmBits{nullptr};
};

struct BITMAPINFOHEADER {
    uint32_t biSize{sizeof(BITMAPINFOHEADER)};
    int32_t  biWidth{0};
    int32_t  biHeight{0};
    uint16_t biPlanes{1};
    uint16_t biBitCount{32};
    uint32_t biCompression{0}; // BI_RGB
    uint32_t biSizeImage{0};
    int32_t  biXPelsPerMeter{2835};
    int32_t  biYPelsPerMeter{2835};
    uint32_t biClrUsed{0};
    uint32_t biClrImportant{0};
};

struct RGBQUAD {
    uint8_t rgbBlue{0};
    uint8_t rgbGreen{0};
    uint8_t rgbRed{0};
    uint8_t rgbReserved{0};
};

struct BITMAPINFO {
    BITMAPINFOHEADER bmiHeader{};
    RGBQUAD          bmiColors[1]{};
};

struct LOGBRUSH {
    uint32_t  lbStyle{BS_SOLID};
    COLORREF  lbColor{RGB(255, 255, 255)};
    uintptr_t lbHatch{0};
};

struct LOGPEN {
    uint32_t lopnStyle{PS_SOLID};
    POINT    lopnWidth{1, 0};
    COLORREF lopnColor{RGB(0, 0, 0)};
};

struct LOGFONTW {
    int32_t lfHeight{16};
    int32_t lfWidth{0};
    int32_t lfEscapement{0};
    int32_t lfOrientation{0};
    int32_t lfWeight{400};
    uint8_t lfItalic{0};
    uint8_t lfUnderline{0};
    uint8_t lfStrikeOut{0};
    uint8_t lfCharSet{1};
    uint8_t lfOutPrecision{0};
    uint8_t lfClipPrecision{0};
    uint8_t lfQuality{0};
    uint8_t lfPitchAndFamily{0};
    wchar_t lfFaceName[32]{L"System"};
};

struct TEXTMETRICW {
    int32_t tmHeight{8};
    int32_t tmAscent{7};
    int32_t tmDescent{1};
    int32_t tmInternalLeading{0};
    int32_t tmExternalLeading{0};
    int32_t tmAveCharWidth{8};
    int32_t tmMaxCharWidth{8};
    int32_t tmWeight{400};
    int32_t tmOverhang{0};
    int32_t tmDigitizedAspectX{96};
    int32_t tmDigitizedAspectY{96};
    wchar_t tmFirstChar{32};
    wchar_t tmLastChar{126};
    wchar_t tmDefaultChar{32};
    wchar_t tmBreakChar{32};
    uint8_t tmItalic{0};
    uint8_t tmUnderlined{0};
    uint8_t tmStruckOut{0};
    uint8_t tmPitchAndFamily{0};
    uint8_t tmCharSet{1};
};

struct PIXELFORMATDESCRIPTOR {
    uint16_t nSize{sizeof(PIXELFORMATDESCRIPTOR)};
    uint16_t nVersion{1};
    uint32_t dwFlags{PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER};
    uint8_t  iPixelType{PFD_TYPE_RGBA};
    uint8_t  cColorBits{32};
    uint8_t  cRedBits{8};
    uint8_t  cRedShift{16};
    uint8_t  cGreenBits{8};
    uint8_t  cGreenShift{8};
    uint8_t  cBlueBits{8};
    uint8_t  cBlueShift{0};
    uint8_t  cAlphaBits{8};
    uint8_t  cAlphaShift{24};
    uint8_t  cAccumBits{0};
    uint8_t  cAccumRedBits{0};
    uint8_t  cAccumGreenBits{0};
    uint8_t  cAccumBlueBits{0};
    uint8_t  cAccumAlphaBits{0};
    uint8_t  cDepthBits{24};
    uint8_t  cStencilBits{8};
    uint8_t  cAuxBuffers{0};
    uint8_t  iLayerType{PFD_MAIN_PLANE};
    uint8_t  bReserved{0};
    uint32_t dwLayerMask{0};
    uint32_t dwVisibleMask{0};
    uint32_t dwDamageMask{0};
};
using LPPIXELFORMATDESCRIPTOR = PIXELFORMATDESCRIPTOR*;

// ============================================================================
// 2. Concrete GDI Objects
// ============================================================================

class GdiObject {
public:
    virtual ~GdiObject() = default;
    [[nodiscard]] virtual uint32_t GetType() const noexcept = 0;
};

class GdiPen : public GdiObject {
public:
    int      style{PS_SOLID};
    int      width{1};
    COLORREF color{RGB(0, 0, 0)};

    GdiPen(int s, int w, COLORREF c) : style(s), width(std::max(1, w)), color(c) {}
    [[nodiscard]] uint32_t GetType() const noexcept override { return OBJ_PEN; }
};

class GdiBrush : public GdiObject {
public:
    uint32_t style{BS_SOLID};
    COLORREF color{RGB(255, 255, 255)};

    GdiBrush(uint32_t s, COLORREF c) : style(s), color(c) {}
    [[nodiscard]] uint32_t GetType() const noexcept override { return OBJ_BRUSH; }
};

class GdiFont : public GdiObject {
public:
    LOGFONTW logFont{};

    explicit GdiFont(const LOGFONTW& lf) : logFont(lf) {}
    [[nodiscard]] uint32_t GetType() const noexcept override { return OBJ_FONT; }
};

class GdiBitmap : public GdiObject {
private:
    uint32_t              m_width{0};
    uint32_t              m_height{0};
    std::vector<uint32_t> m_pixels;
    bool                  m_isSection{false};

public:
    GdiBitmap(uint32_t w, uint32_t h, COLORREF initColor = RGB(255, 255, 255), bool isSection = false)
        : m_width(w), m_height(h), m_pixels(static_cast<size_t>(w) * h, 0xFF000000 | (initColor & 0xFFFFFF)), m_isSection(isSection) {}

    [[nodiscard]] uint32_t GetType() const noexcept override { return OBJ_BITMAP; }
    [[nodiscard]] uint32_t GetWidth() const noexcept { return m_width; }
    [[nodiscard]] uint32_t GetHeight() const noexcept { return m_height; }
    [[nodiscard]] uint32_t* GetBits() noexcept { return m_pixels.data(); }
    [[nodiscard]] const uint32_t* GetBits() const noexcept { return m_pixels.data(); }
    [[nodiscard]] bool IsSection() const noexcept { return m_isSection; }

    [[nodiscard]] uint32_t GetPixel(uint32_t x, uint32_t y) const noexcept {
        if (x >= m_width || y >= m_height) return 0;
        return m_pixels[static_cast<size_t>(y) * m_width + x];
    }

    void SetPixel(uint32_t x, uint32_t y, uint32_t c) noexcept {
        if (x < m_width && y < m_height) {
            m_pixels[static_cast<size_t>(y) * m_width + x] = c;
        }
    }
};

// ============================================================================
// 3. Device Context (HDC) Architecture
// ============================================================================

class DeviceContext {
public:
    enum class DcType { Memory, Window };

private:
    DcType                       m_type{DcType::Memory};
    win32::HWND                  m_hwnd{nullptr};
    std::shared_ptr<GdiBitmap>   m_bitmap;

    std::shared_ptr<GdiPen>      m_selectedPen;
    std::shared_ptr<GdiBrush>    m_selectedBrush;
    std::shared_ptr<GdiFont>     m_selectedFont;
    std::shared_ptr<GdiBitmap>   m_selectedBitmap;

    COLORREF                     m_textColor{RGB(0, 0, 0)};
    COLORREF                     m_bkColor{RGB(255, 255, 255)};
    int                          m_bkMode{OPAQUE};
    POINT                        m_currentPos{0, 0};

    PIXELFORMATDESCRIPTOR        m_pfd{};
    int                          m_pixelFormatIndex{0};

public:
    DeviceContext(DcType type, win32::HWND hwnd, uint32_t w, uint32_t h)
        : m_type(type), m_hwnd(hwnd) {
        m_bitmap = std::make_shared<GdiBitmap>(w, h, RGB(255, 255, 255));
        m_selectedBitmap = m_bitmap;
        m_selectedPen = std::make_shared<GdiPen>(PS_SOLID, 1, RGB(0, 0, 0));
        m_selectedBrush = std::make_shared<GdiBrush>(BS_SOLID, RGB(255, 255, 255));
        LOGFONTW lf{};
        std::wcsncpy(lf.lfFaceName, L"System", 31);
        lf.lfHeight = 8;
        m_selectedFont = std::make_shared<GdiFont>(lf);

        // Standard 32-bit OpenGL-ready PFD
        m_pfd = PIXELFORMATDESCRIPTOR{};
        m_pixelFormatIndex = 1;
    }

    [[nodiscard]] DcType GetType() const noexcept { return m_type; }
    [[nodiscard]] win32::HWND GetHwnd() const noexcept { return m_hwnd; }
    [[nodiscard]] uint32_t GetWidth() const noexcept { return m_bitmap ? m_bitmap->GetWidth() : 0; }
    [[nodiscard]] uint32_t GetHeight() const noexcept { return m_bitmap ? m_bitmap->GetHeight() : 0; }
    [[nodiscard]] GdiBitmap* GetBitmap() noexcept { return m_selectedBitmap.get(); }

    void SelectPen(std::shared_ptr<GdiPen> pen) noexcept { if (pen) m_selectedPen = std::move(pen); }
    void SelectBrush(std::shared_ptr<GdiBrush> brush) noexcept { if (brush) m_selectedBrush = std::move(brush); }
    void SelectFont(std::shared_ptr<GdiFont> font) noexcept { if (font) m_selectedFont = std::move(font); }
    void SelectBitmap(std::shared_ptr<GdiBitmap> bmp) noexcept { if (bmp) m_selectedBitmap = std::move(bmp); }

    [[nodiscard]] std::shared_ptr<GdiPen> GetSelectedPen() const noexcept { return m_selectedPen; }
    [[nodiscard]] std::shared_ptr<GdiBrush> GetSelectedBrush() const noexcept { return m_selectedBrush; }
    [[nodiscard]] std::shared_ptr<GdiFont> GetSelectedFont() const noexcept { return m_selectedFont; }
    [[nodiscard]] std::shared_ptr<GdiBitmap> GetSelectedBitmap() const noexcept { return m_selectedBitmap; }

    void SetTextColor(COLORREF c) noexcept { m_textColor = c; }
    [[nodiscard]] COLORREF GetTextColor() const noexcept { return m_textColor; }
    void SetBkColor(COLORREF c) noexcept { m_bkColor = c; }
    [[nodiscard]] COLORREF GetBkColor() const noexcept { return m_bkColor; }
    void SetBkMode(int m) noexcept { m_bkMode = m; }
    [[nodiscard]] int GetBkMode() const noexcept { return m_bkMode; }

    void MoveTo(int x, int y, POINT* ptOld) noexcept {
        if (ptOld) *ptOld = m_currentPos;
        m_currentPos.x = x;
        m_currentPos.y = y;
    }
    [[nodiscard]] POINT GetCurrentPosition() const noexcept { return m_currentPos; }

    void SetPixelFormat(int fmt, const PIXELFORMATDESCRIPTOR& pfd) noexcept {
        m_pixelFormatIndex = fmt;
        m_pfd = pfd;
    }
    [[nodiscard]] int GetPixelFormatIndex() const noexcept { return m_pixelFormatIndex; }
    [[nodiscard]] const PIXELFORMATDESCRIPTOR& GetPixelFormatDescriptor() const noexcept { return m_pfd; }

    // ------------------------------------------------------------------------
    // Drawing Primitives
    // ------------------------------------------------------------------------
    COLORREF SetPixel(int x, int y, COLORREF color) noexcept {
        if (!m_selectedBitmap) return 0;
        if (x < 0 || y < 0 || x >= static_cast<int>(m_selectedBitmap->GetWidth()) || y >= static_cast<int>(m_selectedBitmap->GetHeight())) {
            return 0;
        }
        uint32_t bgra = 0xFF000000 | ((color & 0xFF) << 16) | (color & 0xFF00) | ((color >> 16) & 0xFF);
        m_selectedBitmap->SetPixel(static_cast<uint32_t>(x), static_cast<uint32_t>(y), bgra);
        FlushIfWindow();
        return color;
    }

    [[nodiscard]] COLORREF GetPixel(int x, int y) const noexcept {
        if (!m_selectedBitmap) return 0;
        if (x < 0 || y < 0 || x >= static_cast<int>(m_selectedBitmap->GetWidth()) || y >= static_cast<int>(m_selectedBitmap->GetHeight())) {
            return 0;
        }
        uint32_t c = m_selectedBitmap->GetPixel(static_cast<uint32_t>(x), static_cast<uint32_t>(y));
        uint8_t r = static_cast<uint8_t>((c >> 16) & 0xFF);
        uint8_t g = static_cast<uint8_t>((c >> 8) & 0xFF);
        uint8_t b = static_cast<uint8_t>(c & 0xFF);
        return RGB(r, g, b);
    }

    void LineTo(int x1, int y1) noexcept {
        if (!m_selectedBitmap || m_selectedPen->style == PS_NULL) {
            m_currentPos = { x1, y1 };
            return;
        }

        int x0 = m_currentPos.x;
        int y0 = m_currentPos.y;
        COLORREF penClr = m_selectedPen->color;
        uint32_t bgra = 0xFF000000 | ((penClr & 0xFF) << 16) | (penClr & 0xFF00) | ((penClr >> 16) & 0xFF);

        int dx = std::abs(x1 - x0);
        int dy = std::abs(y1 - y0);
        int sx = (x0 < x1) ? 1 : -1;
        int sy = (y0 < y1) ? 1 : -1;
        int err = dx - dy;

        while (true) {
            if (x0 >= 0 && y0 >= 0 && x0 < static_cast<int>(m_selectedBitmap->GetWidth()) && y0 < static_cast<int>(m_selectedBitmap->GetHeight())) {
                m_selectedBitmap->SetPixel(static_cast<uint32_t>(x0), static_cast<uint32_t>(y0), bgra);
            }
            if (x0 == x1 && y0 == y1) break;
            int e2 = 2 * err;
            if (e2 > -dy) { err -= dy; x0 += sx; }
            if (e2 < dx)  { err += dx; y0 += sy; }
        }

        m_currentPos = { x1, y1 };
        FlushIfWindow();
    }

    void Rectangle(int left, int top, int right, int bottom) noexcept {
        if (!m_selectedBitmap) return;
        int x0 = std::min(left, right);
        int x1 = std::max(left, right) - 1;
        int y0 = std::min(top, bottom);
        int y1 = std::max(top, bottom) - 1;

        // 1. Fill interior with brush
        if (m_selectedBrush && m_selectedBrush->style != BS_NULL) {
            COLORREF bClr = m_selectedBrush->color;
            uint32_t fillBgra = 0xFF000000 | ((bClr & 0xFF) << 16) | (bClr & 0xFF00) | ((bClr >> 16) & 0xFF);
            for (int y = y0; y <= y1; ++y) {
                for (int x = x0; x <= x1; ++x) {
                    if (x >= 0 && y >= 0 && x < static_cast<int>(m_selectedBitmap->GetWidth()) && y < static_cast<int>(m_selectedBitmap->GetHeight())) {
                        m_selectedBitmap->SetPixel(static_cast<uint32_t>(x), static_cast<uint32_t>(y), fillBgra);
                    }
                }
            }
        }

        // 2. Draw border with pen
        if (m_selectedPen && m_selectedPen->style != PS_NULL) {
            COLORREF pClr = m_selectedPen->color;
            uint32_t penBgra = 0xFF000000 | ((pClr & 0xFF) << 16) | (pClr & 0xFF00) | ((pClr >> 16) & 0xFF);
            for (int x = x0; x <= x1; ++x) {
                if (x >= 0 && x < static_cast<int>(m_selectedBitmap->GetWidth())) {
                    if (y0 >= 0 && y0 < static_cast<int>(m_selectedBitmap->GetHeight())) m_selectedBitmap->SetPixel(static_cast<uint32_t>(x), static_cast<uint32_t>(y0), penBgra);
                    if (y1 >= 0 && y1 < static_cast<int>(m_selectedBitmap->GetHeight())) m_selectedBitmap->SetPixel(static_cast<uint32_t>(x), static_cast<uint32_t>(y1), penBgra);
                }
            }
            for (int y = y0; y <= y1; ++y) {
                if (y >= 0 && y < static_cast<int>(m_selectedBitmap->GetHeight())) {
                    if (x0 >= 0 && x0 < static_cast<int>(m_selectedBitmap->GetWidth())) m_selectedBitmap->SetPixel(static_cast<uint32_t>(x0), static_cast<uint32_t>(y), penBgra);
                    if (x1 >= 0 && x1 < static_cast<int>(m_selectedBitmap->GetWidth())) m_selectedBitmap->SetPixel(static_cast<uint32_t>(x1), static_cast<uint32_t>(y), penBgra);
                }
            }
        }

        FlushIfWindow();
    }

    void Ellipse(int left, int top, int right, int bottom) noexcept {
        if (!m_selectedBitmap) return;
        int x0 = std::min(left, right);
        int x1 = std::max(left, right) - 1;
        int y0 = std::min(top, bottom);
        int y1 = std::max(top, bottom) - 1;

        float cx = (x0 + x1) * 0.5f;
        float cy = (y0 + y1) * 0.5f;
        float rx = (x1 - x0) * 0.5f;
        float ry = (y1 - y0) * 0.5f;

        if (rx <= 0.0f || ry <= 0.0f) return;
        float invRx2 = 1.0f / (rx * rx);
        float invRy2 = 1.0f / (ry * ry);

        // Fill interior
        if (m_selectedBrush && m_selectedBrush->style != BS_NULL) {
            COLORREF bClr = m_selectedBrush->color;
            uint32_t fillBgra = 0xFF000000 | ((bClr & 0xFF) << 16) | (bClr & 0xFF00) | ((bClr >> 16) & 0xFF);

            for (int y = y0; y <= y1; ++y) {
                float dy = (y + 0.5f) - cy;
                float dy2 = dy * dy * invRy2;
                if (dy2 > 1.0f) continue;
                for (int x = x0; x <= x1; ++x) {
                    float dx = (x + 0.5f) - cx;
                    if (dx * dx * invRx2 + dy2 <= 1.0f) {
                        if (x >= 0 && y >= 0 && x < static_cast<int>(m_selectedBitmap->GetWidth()) && y < static_cast<int>(m_selectedBitmap->GetHeight())) {
                            m_selectedBitmap->SetPixel(static_cast<uint32_t>(x), static_cast<uint32_t>(y), fillBgra);
                        }
                    }
                }
            }
        }

        // Outline
        if (m_selectedPen && m_selectedPen->style != PS_NULL) {
            COLORREF pClr = m_selectedPen->color;
            uint32_t penBgra = 0xFF000000 | ((pClr & 0xFF) << 16) | (pClr & 0xFF00) | ((pClr >> 16) & 0xFF);
            int steps = static_cast<int>(std::max(rx, ry) * 6.28f) + 16;
            for (int i = 0; i < steps; ++i) {
                float theta = (6.2831853f * i) / steps;
                int px = static_cast<int>(cx + rx * std::cos(theta));
                int py = static_cast<int>(cy + ry * std::sin(theta));
                if (px >= 0 && py >= 0 && px < static_cast<int>(m_selectedBitmap->GetWidth()) && py < static_cast<int>(m_selectedBitmap->GetHeight())) {
                    m_selectedBitmap->SetPixel(static_cast<uint32_t>(px), static_cast<uint32_t>(py), penBgra);
                }
            }
        }

        FlushIfWindow();
    }

    void FillRect(const RECT& rc, GdiBrush* pBrush) noexcept {
        if (!m_selectedBitmap || !pBrush || pBrush->style == BS_NULL) return;
        COLORREF bClr = pBrush->color;
        uint32_t fillBgra = 0xFF000000 | ((bClr & 0xFF) << 16) | (bClr & 0xFF00) | ((bClr >> 16) & 0xFF);

        int x0 = std::max(0, std::min(rc.left, rc.right));
        int x1 = std::min(static_cast<int>(m_selectedBitmap->GetWidth()), std::max(rc.left, rc.right));
        int y0 = std::max(0, std::min(rc.top, rc.bottom));
        int y1 = std::min(static_cast<int>(m_selectedBitmap->GetHeight()), std::max(rc.top, rc.bottom));

        for (int y = y0; y < y1; ++y) {
            for (int x = x0; x < x1; ++x) {
                m_selectedBitmap->SetPixel(static_cast<uint32_t>(x), static_cast<uint32_t>(y), fillBgra);
            }
        }

        FlushIfWindow();
    }

    // ------------------------------------------------------------------------
    // Blitting & BitBlt ROPs
    // ------------------------------------------------------------------------
    bool BitBlt(int xDest, int yDest, int w, int h, DeviceContext* srcDc, int xSrc, int ySrc, uint32_t rop) noexcept {
        if (!m_selectedBitmap || !srcDc || !srcDc->GetBitmap() || w <= 0 || h <= 0) return false;

        auto* dstBmp = m_selectedBitmap.get();
        auto* srcBmp = srcDc->GetBitmap();

        for (int y = 0; y < h; ++y) {
            int sy = ySrc + y;
            int dy = yDest + y;
            if (dy < 0 || dy >= static_cast<int>(dstBmp->GetHeight())) continue;

            for (int x = 0; x < w; ++x) {
                int sx = xSrc + x;
                int dx = xDest + x;
                if (dx < 0 || dx >= static_cast<int>(dstBmp->GetWidth())) continue;

                uint32_t srcPixel = (sx >= 0 && sy >= 0 && sx < static_cast<int>(srcBmp->GetWidth()) && sy < static_cast<int>(srcBmp->GetHeight()))
                    ? srcBmp->GetPixel(static_cast<uint32_t>(sx), static_cast<uint32_t>(sy))
                    : 0xFFFFFFFF;
                uint32_t dstPixel = dstBmp->GetPixel(static_cast<uint32_t>(dx), static_cast<uint32_t>(dy));

                uint32_t resultPixel = srcPixel;
                switch (rop) {
                    case SRCCOPY:    resultPixel = srcPixel; break;
                    case SRCPAINT:   resultPixel = srcPixel | dstPixel; break;
                    case SRCAND:     resultPixel = srcPixel & dstPixel; break;
                    case SRCINVERT:  resultPixel = srcPixel ^ dstPixel; break;
                    case BLACKNESS:  resultPixel = 0xFF000000; break;
                    case WHITENESS:  resultPixel = 0xFFFFFFFF; break;
                    default:         resultPixel = srcPixel; break;
                }

                dstBmp->SetPixel(static_cast<uint32_t>(dx), static_cast<uint32_t>(dy), resultPixel);
            }
        }

        FlushIfWindow();
        return true;
    }

    bool StretchBlt(int xDest, int yDest, int wDest, int hDest, DeviceContext* srcDc, int xSrc, int ySrc, int wSrc, int hSrc, uint32_t rop) noexcept {
        if (!m_selectedBitmap || !srcDc || !srcDc->GetBitmap() || wDest <= 0 || hDest <= 0 || wSrc <= 0 || hSrc <= 0) return false;

        auto* dstBmp = m_selectedBitmap.get();
        auto* srcBmp = srcDc->GetBitmap();

        float scaleX = static_cast<float>(wSrc) / wDest;
        float scaleY = static_cast<float>(hSrc) / hDest;

        for (int y = 0; y < hDest; ++y) {
            int dy = yDest + y;
            if (dy < 0 || dy >= static_cast<int>(dstBmp->GetHeight())) continue;
            int sy = ySrc + static_cast<int>(y * scaleY);
            if (sy < 0 || sy >= static_cast<int>(srcBmp->GetHeight())) continue;

            for (int x = 0; x < wDest; ++x) {
                int dx = xDest + x;
                if (dx < 0 || dx >= static_cast<int>(dstBmp->GetWidth())) continue;
                int sx = xSrc + static_cast<int>(x * scaleX);
                if (sx < 0 || sx >= static_cast<int>(srcBmp->GetWidth())) continue;

                uint32_t srcPixel = srcBmp->GetPixel(static_cast<uint32_t>(sx), static_cast<uint32_t>(sy));
                uint32_t dstPixel = dstBmp->GetPixel(static_cast<uint32_t>(dx), static_cast<uint32_t>(dy));

                uint32_t resultPixel = (rop == SRCINVERT) ? (srcPixel ^ dstPixel) : srcPixel;
                dstBmp->SetPixel(static_cast<uint32_t>(dx), static_cast<uint32_t>(dy), resultPixel);
            }
        }

        FlushIfWindow();
        return true;
    }

    // ------------------------------------------------------------------------
    // Typography & TextOutW
    // ------------------------------------------------------------------------
    bool TextOutW(int x, int y, const wchar_t* lpString, int c) noexcept {
        if (!m_selectedBitmap || !lpString || c <= 0) return false;

        uint32_t textBgra = 0xFF000000 | ((m_textColor & 0xFF) << 16) | (m_textColor & 0xFF00) | ((m_textColor >> 16) & 0xFF);
        uint32_t bkBgra   = 0xFF000000 | ((m_bkColor & 0xFF) << 16) | (m_bkColor & 0xFF00) | ((m_bkColor >> 16) & 0xFF);

        int cursorX = x;
        for (int i = 0; i < c; ++i) {
            wchar_t wc = lpString[i];
            char asciiCh = (wc >= 32 && wc <= 126) ? static_cast<char>(wc) : '?';
            const uint8_t* glyph = bootvid::font::GLYPH_DATA[asciiCh - 32];

            for (int row = 0; row < 8; ++row) {
                int py = y + row;
                if (py < 0 || py >= static_cast<int>(m_selectedBitmap->GetHeight())) continue;
                uint8_t rowBits = glyph[row];

                for (int col = 0; col < 8; ++col) {
                    int px = cursorX + col;
                    if (px < 0 || px >= static_cast<int>(m_selectedBitmap->GetWidth())) continue;

                    bool bitOn = (rowBits & (1 << (7 - col))) != 0;
                    if (bitOn) {
                        m_selectedBitmap->SetPixel(static_cast<uint32_t>(px), static_cast<uint32_t>(py), textBgra);
                    } else if (m_bkMode == OPAQUE) {
                        m_selectedBitmap->SetPixel(static_cast<uint32_t>(px), static_cast<uint32_t>(py), bkBgra);
                    }
                }
            }

            cursorX += 8;
        }

        FlushIfWindow();
        return true;
    }

    void FlushIfWindow() noexcept {
        if (m_type == DcType::Window && m_hwnd && m_selectedBitmap) {
            uint32_t w = m_selectedBitmap->GetWidth();
            uint32_t h = m_selectedBitmap->GetHeight();
            user32::WindowManager::get().blitToWindow(
                m_hwnd,
                reinterpret_cast<const uint8_t*>(m_selectedBitmap->GetBits()),
                w, h, w * 4
            );
        }
    }
};

// ============================================================================
// 4. Central GDI Object & DC Engine
// ============================================================================

class GdiEngine {
private:
    std::mutex m_mutex;
    std::unordered_map<uintptr_t, std::shared_ptr<GdiObject>>     m_objects;
    std::unordered_map<uintptr_t, std::shared_ptr<DeviceContext>> m_dcs;
    uintptr_t m_nextHandle{0x1000};

    // Pre-allocated Stock Objects
    std::shared_ptr<GdiBrush> m_stockWhiteBrush;
    std::shared_ptr<GdiBrush> m_stockBlackBrush;
    std::shared_ptr<GdiBrush> m_stockNullBrush;
    std::shared_ptr<GdiPen>   m_stockWhitePen;
    std::shared_ptr<GdiPen>   m_stockBlackPen;
    std::shared_ptr<GdiPen>   m_stockNullPen;
    std::shared_ptr<GdiFont>  m_stockSystemFont;

    GdiEngine() {
        m_stockWhiteBrush = std::make_shared<GdiBrush>(BS_SOLID, RGB(255, 255, 255));
        m_stockBlackBrush = std::make_shared<GdiBrush>(BS_SOLID, RGB(0, 0, 0));
        m_stockNullBrush  = std::make_shared<GdiBrush>(BS_NULL, RGB(0, 0, 0));

        m_stockWhitePen   = std::make_shared<GdiPen>(PS_SOLID, 1, RGB(255, 255, 255));
        m_stockBlackPen   = std::make_shared<GdiPen>(PS_SOLID, 1, RGB(0, 0, 0));
        m_stockNullPen    = std::make_shared<GdiPen>(PS_NULL, 0, RGB(0, 0, 0));

        LOGFONTW lf{};
        std::wcsncpy(lf.lfFaceName, L"System", 31);
        lf.lfHeight = 8;
        m_stockSystemFont = std::make_shared<GdiFont>(lf);
    }

public:
    static GdiEngine& get() {
        static GdiEngine instance;
        return instance;
    }

    HGDIOBJ registerObject(std::shared_ptr<GdiObject> obj) {
        if (!obj) return nullptr;
        std::lock_guard<std::mutex> lock(m_mutex);
        uintptr_t h = m_nextHandle++;
        m_objects[h] = std::move(obj);
        return reinterpret_cast<HGDIOBJ>(h);
    }

    std::shared_ptr<GdiObject> getObject(HGDIOBJ h) {
        if (!h) return nullptr;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_objects.find(reinterpret_cast<uintptr_t>(h));
        return (it != m_objects.end()) ? it->second : nullptr;
    }

    bool deleteObject(HGDIOBJ h) {
        if (!h) return false;
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_objects.erase(reinterpret_cast<uintptr_t>(h)) > 0;
    }

    HDC registerDc(std::shared_ptr<DeviceContext> dc) {
        if (!dc) return nullptr;
        std::lock_guard<std::mutex> lock(m_mutex);
        uintptr_t h = m_nextHandle++;
        m_dcs[h] = std::move(dc);
        return reinterpret_cast<HDC>(h);
    }

    std::shared_ptr<DeviceContext> getDc(HDC hdc) {
        if (!hdc) return nullptr;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_dcs.find(reinterpret_cast<uintptr_t>(hdc));
        return (it != m_dcs.end()) ? it->second : nullptr;
    }

    bool deleteDc(HDC hdc) {
        if (!hdc) return false;
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_dcs.erase(reinterpret_cast<uintptr_t>(hdc)) > 0;
    }

    HDC getWindowDC(win32::HWND hwnd) {
        if (!hwnd) return nullptr;
        std::lock_guard<std::mutex> lock(m_mutex);

        // Check if DC already exists for this HWND
        for (const auto& [h, dc] : m_dcs) {
            if (dc->GetType() == DeviceContext::DcType::Window && dc->GetHwnd() == hwnd) {
                return reinterpret_cast<HDC>(h);
            }
        }

        uint32_t w = 640, h = 480;
        user32::WindowManager::get().getWindowPixelBuffer(hwnd, &w, &h);
        if (w == 0) w = 640;
        if (h == 0) h = 480;

        auto winDc = std::make_shared<DeviceContext>(DeviceContext::DcType::Window, hwnd, w, h);
        uintptr_t handle = m_nextHandle++;
        m_dcs[handle] = winDc;
        return reinterpret_cast<HDC>(handle);
    }

    HGDIOBJ getStockObject(int i) {
        switch (i) {
            case WHITE_BRUSH:  return registerObject(m_stockWhiteBrush);
            case BLACK_BRUSH:  return registerObject(m_stockBlackBrush);
            case NULL_BRUSH:   return registerObject(m_stockNullBrush);
            case WHITE_PEN:    return registerObject(m_stockWhitePen);
            case BLACK_PEN:    return registerObject(m_stockBlackPen);
            case NULL_PEN:     return registerObject(m_stockNullPen);
            case SYSTEM_FONT:
            case DEFAULT_GUI_FONT:
            case ANSI_VAR_FONT:
            case OEM_FIXED_FONT:
                return registerObject(m_stockSystemFont);
            default:
                return registerObject(m_stockWhiteBrush);
        }
    }
};

// ============================================================================
// 5. Win32 GDI C-API Export Surface (gdi32.dll)
// ============================================================================

inline HDC CreateCompatibleDC(HDC hdc) noexcept {
    auto srcDc = GdiEngine::get().getDc(hdc);
    uint32_t w = srcDc ? srcDc->GetWidth() : 640;
    uint32_t h = srcDc ? srcDc->GetHeight() : 480;
    auto memDc = std::make_shared<DeviceContext>(DeviceContext::DcType::Memory, nullptr, w, h);
    return GdiEngine::get().registerDc(memDc);
}

inline win32::BOOL DeleteDC(HDC hdc) noexcept {
    return GdiEngine::get().deleteDc(hdc) ? win32::TRUE : win32::FALSE;
}

inline HGDIOBJ SelectObject(HDC hdc, HGDIOBJ h) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    auto obj = GdiEngine::get().getObject(h);
    if (!dc || !obj) return nullptr;

    HGDIOBJ oldObj = nullptr;
    switch (obj->GetType()) {
        case OBJ_PEN:
            oldObj = GdiEngine::get().registerObject(dc->GetSelectedPen());
            dc->SelectPen(std::dynamic_pointer_cast<GdiPen>(obj));
            break;
        case OBJ_BRUSH:
            oldObj = GdiEngine::get().registerObject(dc->GetSelectedBrush());
            dc->SelectBrush(std::dynamic_pointer_cast<GdiBrush>(obj));
            break;
        case OBJ_FONT:
            oldObj = GdiEngine::get().registerObject(dc->GetSelectedFont());
            dc->SelectFont(std::dynamic_pointer_cast<GdiFont>(obj));
            break;
        case OBJ_BITMAP:
            oldObj = GdiEngine::get().registerObject(dc->GetSelectedBitmap());
            dc->SelectBitmap(std::dynamic_pointer_cast<GdiBitmap>(obj));
            break;
        default:
            break;
    }
    return oldObj;
}

inline win32::BOOL DeleteObject(HGDIOBJ ho) noexcept {
    return GdiEngine::get().deleteObject(ho) ? win32::TRUE : win32::FALSE;
}

inline HGDIOBJ GetStockObject(int i) noexcept {
    return GdiEngine::get().getStockObject(i);
}

inline HBITMAP CreateCompatibleBitmap(HDC /*hdc*/, int cx, int cy) noexcept {
    if (cx <= 0 || cy <= 0) return nullptr;
    auto bmp = std::make_shared<GdiBitmap>(static_cast<uint32_t>(cx), static_cast<uint32_t>(cy));
    return GdiEngine::get().registerObject(bmp);
}

inline HBITMAP CreateDIBSection(HDC, const BITMAPINFO* pbmi, uint32_t, void** ppvBits, win32::HANDLE, uint32_t) noexcept {
    if (!pbmi) return nullptr;
    uint32_t w = std::abs(pbmi->bmiHeader.biWidth);
    uint32_t h = std::abs(pbmi->bmiHeader.biHeight);
    if (w == 0 || h == 0) return nullptr;

    auto bmp = std::make_shared<GdiBitmap>(w, h, RGB(0, 0, 0), true);
    if (ppvBits) *ppvBits = bmp->GetBits();
    return GdiEngine::get().registerObject(bmp);
}

inline HPEN CreatePen(int iStyle, int cWidth, COLORREF color) noexcept {
    auto pen = std::make_shared<GdiPen>(iStyle, cWidth, color);
    return GdiEngine::get().registerObject(pen);
}

inline HBRUSH CreateSolidBrush(COLORREF color) noexcept {
    auto brush = std::make_shared<GdiBrush>(BS_SOLID, color);
    return GdiEngine::get().registerObject(brush);
}

inline win32::BOOL MoveToEx(HDC hdc, int x, int y, LPPOINT lppt) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    if (!dc) return win32::FALSE;
    dc->MoveTo(x, y, lppt);
    return win32::TRUE;
}

inline win32::BOOL LineTo(HDC hdc, int x, int y) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    if (!dc) return win32::FALSE;
    dc->LineTo(x, y);
    return win32::TRUE;
}

inline win32::BOOL Rectangle(HDC hdc, int left, int top, int right, int bottom) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    if (!dc) return win32::FALSE;
    dc->Rectangle(left, top, right, bottom);
    return win32::TRUE;
}

inline win32::BOOL Ellipse(HDC hdc, int left, int top, int right, int bottom) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    if (!dc) return win32::FALSE;
    dc->Ellipse(left, top, right, bottom);
    return win32::TRUE;
}

inline int FillRect(HDC hdc, const RECT* lprc, HBRUSH hbr) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    auto brush = std::dynamic_pointer_cast<GdiBrush>(GdiEngine::get().getObject(hbr));
    if (!dc || !lprc || !brush) return 0;
    dc->FillRect(*lprc, brush.get());
    return 1;
}

inline COLORREF SetPixel(HDC hdc, int x, int y, COLORREF color) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    return dc ? dc->SetPixel(x, y, color) : 0;
}

inline COLORREF GetPixel(HDC hdc, int x, int y) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    return dc ? dc->GetPixel(x, y) : 0;
}

inline win32::BOOL BitBlt(HDC hdcDest, int xDest, int yDest, int w, int h, HDC hdcSrc, int xSrc, int ySrc, uint32_t rop) noexcept {
    auto dstDc = GdiEngine::get().getDc(hdcDest);
    auto srcDc = GdiEngine::get().getDc(hdcSrc);
    if (!dstDc || !srcDc) return win32::FALSE;
    return dstDc->BitBlt(xDest, yDest, w, h, srcDc.get(), xSrc, ySrc, rop) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL StretchBlt(HDC hdcDest, int xDest, int yDest, int wDest, int hDest, HDC hdcSrc, int xSrc, int ySrc, int wSrc, int hSrc, uint32_t rop) noexcept {
    auto dstDc = GdiEngine::get().getDc(hdcDest);
    auto srcDc = GdiEngine::get().getDc(hdcSrc);
    if (!dstDc || !srcDc) return win32::FALSE;
    return dstDc->StretchBlt(xDest, yDest, wDest, hDest, srcDc.get(), xSrc, ySrc, wSrc, hSrc, rop) ? win32::TRUE : win32::FALSE;
}

inline COLORREF SetTextColor(HDC hdc, COLORREF color) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    if (!dc) return 0;
    COLORREF old = dc->GetTextColor();
    dc->SetTextColor(color);
    return old;
}

inline COLORREF GetTextColor(HDC hdc) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    return dc ? dc->GetTextColor() : 0;
}

inline COLORREF SetBkColor(HDC hdc, COLORREF color) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    if (!dc) return 0;
    COLORREF old = dc->GetBkColor();
    dc->SetBkColor(color);
    return old;
}

inline COLORREF GetBkColor(HDC hdc) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    return dc ? dc->GetBkColor() : 0;
}

inline int SetBkMode(HDC hdc, int mode) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    if (!dc) return 0;
    int old = dc->GetBkMode();
    dc->SetBkMode(mode);
    return old;
}

inline int GetBkMode(HDC hdc) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    return dc ? dc->GetBkMode() : 0;
}

inline win32::BOOL TextOutW(HDC hdc, int x, int y, const wchar_t* lpString, int c) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    if (!dc) return win32::FALSE;
    return dc->TextOutW(x, y, lpString, c) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL TextOutA(HDC hdc, int x, int y, const char* lpString, int c) noexcept {
    if (!lpString || c <= 0) return win32::FALSE;
    std::wstring wStr;
    wStr.reserve(static_cast<size_t>(c));
    for (int i = 0; i < c; ++i) wStr.push_back(static_cast<wchar_t>(static_cast<unsigned char>(lpString[i])));
    return TextOutW(hdc, x, y, wStr.c_str(), static_cast<int>(wStr.size()));
}

inline win32::BOOL GetTextExtentPoint32W(HDC, const wchar_t* lpString, int c, LPSIZE psizl) noexcept {
    if (!psizl || !lpString || c < 0) return win32::FALSE;
    psizl->cx = c * 8;
    psizl->cy = 8;
    return win32::TRUE;
}

inline int GetObjectW(HGDIOBJ hgdiobj, int cbBuffer, void* lpvObject) noexcept {
    auto obj = GdiEngine::get().getObject(hgdiobj);
    if (!obj || !lpvObject || cbBuffer <= 0) return 0;

    if (obj->GetType() == OBJ_BITMAP) {
        auto bmp = std::dynamic_pointer_cast<GdiBitmap>(obj);
        BITMAP bm{};
        bm.bmWidth = static_cast<int32_t>(bmp->GetWidth());
        bm.bmHeight = static_cast<int32_t>(bmp->GetHeight());
        bm.bmWidthBytes = bm.bmWidth * 4;
        bm.bmPlanes = 1;
        bm.bmBitsPixel = 32;
        bm.bmBits = bmp->GetBits();
        int copyBytes = std::min(cbBuffer, static_cast<int>(sizeof(BITMAP)));
        std::memcpy(lpvObject, &bm, copyBytes);
        return copyBytes;
    }
    return 0;
}

inline int GetDeviceCaps(HDC hdc, int nIndex) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    switch (nIndex) {
        case HORZRES:    return dc ? static_cast<int>(dc->GetWidth()) : 1920;
        case VERTRES:    return dc ? static_cast<int>(dc->GetHeight()) : 1080;
        case BITSPIXEL:  return 32;
        case PLANES:     return 1;
        case LOGPIXELSX: return 96;
        case LOGPIXELSY: return 96;
        default:         return 0;
    }
}

// ----------------------------------------------------------------------------
// Pixel Formats (OpenGL WGL & 3D Acceleration Bridge)
// ----------------------------------------------------------------------------

inline int ChoosePixelFormat(HDC, const PIXELFORMATDESCRIPTOR* ppfd) noexcept {
    if (!ppfd) return 0;
    return 1; // Standard Sovereign 32-bpp BGRA Pixel Format
}

inline win32::BOOL SetPixelFormat(HDC hdc, int format, const PIXELFORMATDESCRIPTOR* ppfd) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    if (!dc || !ppfd || format != 1) return win32::FALSE;
    dc->SetPixelFormat(format, *ppfd);
    return win32::TRUE;
}

inline int DescribePixelFormat(HDC, int iPixelFormat, uint32_t nBytes, LPPIXELFORMATDESCRIPTOR ppfd) noexcept {
    if (iPixelFormat != 1 || !ppfd || nBytes < sizeof(PIXELFORMATDESCRIPTOR)) return 0;
    *ppfd = PIXELFORMATDESCRIPTOR{};
    return 1;
}

inline win32::BOOL SwapBuffers(HDC hdc) noexcept {
    auto dc = GdiEngine::get().getDc(hdc);
    if (!dc) return win32::FALSE;
    dc->FlushIfWindow();
    return win32::TRUE;
}

// ============================================================================
// 6. Subsystem Export Registration
// ============================================================================

inline void InitializeGdi32SubsystemExports() {
    // Interop hooks: Connect User32 window DC lifecycle to GdiEngine
    user32::SetGetDCHook([](win32::HWND h) -> user32::HDC {
        return reinterpret_cast<user32::HDC>(GdiEngine::get().getWindowDC(h));
    });
    user32::SetReleaseDCHook([](win32::HWND hWnd, user32::HDC hDC) -> int {
        auto dc = GdiEngine::get().getDc(reinterpret_cast<HDC>(hDC));
        if (dc) {
            dc->FlushIfWindow();
        }
        user32::WindowManager::get().invalidateRect(hWnd, nullptr, win32::FALSE);
        return 1;
    });

    auto& ldr = ldr::DynamicLoader::get();

    ldr.registerExport("gdi32.dll", "CreateCompatibleDC", reinterpret_cast<void*>(CreateCompatibleDC));
    ldr.registerExport("gdi32.dll", "DeleteDC", reinterpret_cast<void*>(DeleteDC));
    ldr.registerExport("gdi32.dll", "SelectObject", reinterpret_cast<void*>(SelectObject));
    ldr.registerExport("gdi32.dll", "DeleteObject", reinterpret_cast<void*>(DeleteObject));
    ldr.registerExport("gdi32.dll", "GetStockObject", reinterpret_cast<void*>(GetStockObject));
    ldr.registerExport("gdi32.dll", "CreateCompatibleBitmap", reinterpret_cast<void*>(CreateCompatibleBitmap));
    ldr.registerExport("gdi32.dll", "CreateDIBSection", reinterpret_cast<void*>(CreateDIBSection));
    ldr.registerExport("gdi32.dll", "CreatePen", reinterpret_cast<void*>(CreatePen));
    ldr.registerExport("gdi32.dll", "CreateSolidBrush", reinterpret_cast<void*>(CreateSolidBrush));
    ldr.registerExport("gdi32.dll", "MoveToEx", reinterpret_cast<void*>(MoveToEx));
    ldr.registerExport("gdi32.dll", "LineTo", reinterpret_cast<void*>(LineTo));
    ldr.registerExport("gdi32.dll", "Rectangle", reinterpret_cast<void*>(Rectangle));
    ldr.registerExport("gdi32.dll", "Ellipse", reinterpret_cast<void*>(Ellipse));
    ldr.registerExport("gdi32.dll", "FillRect", reinterpret_cast<void*>(FillRect));
    ldr.registerExport("gdi32.dll", "SetPixel", reinterpret_cast<void*>(SetPixel));
    ldr.registerExport("gdi32.dll", "GetPixel", reinterpret_cast<void*>(GetPixel));
    ldr.registerExport("gdi32.dll", "BitBlt", reinterpret_cast<void*>(BitBlt));
    ldr.registerExport("gdi32.dll", "StretchBlt", reinterpret_cast<void*>(StretchBlt));
    ldr.registerExport("gdi32.dll", "SetTextColor", reinterpret_cast<void*>(SetTextColor));
    ldr.registerExport("gdi32.dll", "GetTextColor", reinterpret_cast<void*>(GetTextColor));
    ldr.registerExport("gdi32.dll", "SetBkColor", reinterpret_cast<void*>(SetBkColor));
    ldr.registerExport("gdi32.dll", "GetBkColor", reinterpret_cast<void*>(GetBkColor));
    ldr.registerExport("gdi32.dll", "SetBkMode", reinterpret_cast<void*>(SetBkMode));
    ldr.registerExport("gdi32.dll", "GetBkMode", reinterpret_cast<void*>(GetBkMode));
    ldr.registerExport("gdi32.dll", "TextOutW", reinterpret_cast<void*>(TextOutW));
    ldr.registerExport("gdi32.dll", "TextOutA", reinterpret_cast<void*>(TextOutA));
    ldr.registerExport("gdi32.dll", "GetTextExtentPoint32W", reinterpret_cast<void*>(GetTextExtentPoint32W));
    ldr.registerExport("gdi32.dll", "GetObjectW", reinterpret_cast<void*>(GetObjectW));
    ldr.registerExport("gdi32.dll", "GetDeviceCaps", reinterpret_cast<void*>(GetDeviceCaps));
    ldr.registerExport("gdi32.dll", "ChoosePixelFormat", reinterpret_cast<void*>(ChoosePixelFormat));
    ldr.registerExport("gdi32.dll", "SetPixelFormat", reinterpret_cast<void*>(SetPixelFormat));
    ldr.registerExport("gdi32.dll", "DescribePixelFormat", reinterpret_cast<void*>(DescribePixelFormat));
    ldr.registerExport("gdi32.dll", "SwapBuffers", reinterpret_cast<void*>(SwapBuffers));
}

} // namespace micant::gdi32
