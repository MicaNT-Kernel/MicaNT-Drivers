#pragma once

#include <cstdint>
#include <string_view>
#include <vector>
#include <span>
#include <algorithm>
#include <cmath>
#include <cstring>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "boot.hpp"

namespace micant::bootvid {

// ============================================================================
// 1. Color Representation & Palettes
// ============================================================================

/**
 * @brief 32-bit RGBA/BGRA Color representation.
 */
struct Color {
    uint8_t b{0};
    uint8_t g{0};
    uint8_t r{0};
    uint8_t a{255};

    constexpr Color() = default;
    constexpr Color(uint8_t red, uint8_t green, uint8_t blue, uint8_t alpha = 255)
        : b(blue), g(green), r(red), a(alpha) {}

    [[nodiscard]] constexpr uint32_t toBgra32() const noexcept {
        return (static_cast<uint32_t>(a) << 24) |
               (static_cast<uint32_t>(r) << 16) |
               (static_cast<uint32_t>(g) << 8)  |
               (static_cast<uint32_t>(b));
    }

    [[nodiscard]] constexpr uint32_t toRgba32() const noexcept {
        return (static_cast<uint32_t>(a) << 24) |
               (static_cast<uint32_t>(b) << 16) |
               (static_cast<uint32_t>(g) << 8)  |
               (static_cast<uint32_t>(r));
    }

    [[nodiscard]] constexpr bool operator==(const Color& other) const noexcept {
        return r == other.r && g == other.g && b == other.b && a == other.a;
    }

    [[nodiscard]] constexpr bool operator!=(const Color& other) const noexcept {
        return !(*this == other);
    }

    // Standard Color Palette
    static constexpr Color transparent() noexcept { return Color(0, 0, 0, 0); }
    static constexpr Color black()       noexcept { return Color(0, 0, 0); }
    static constexpr Color white()       noexcept { return Color(255, 255, 255); }
    static constexpr Color micaDark()    noexcept { return Color(18, 20, 28); }       // Modern Dark Slate #12141C
    static constexpr Color micaSurface() noexcept { return Color(28, 32, 44); }      // Panel Surface #1C202C
    static constexpr Color micaBorder()  noexcept { return Color(54, 60, 80); }       // Accent Border #363C50
    static constexpr Color micaCyan()    noexcept { return Color(0, 210, 255); }      // Mica Cyan #00D2FF
    static constexpr Color micaBlue()    noexcept { return Color(0, 120, 215); }      // Mica Azure #0078D7
    static constexpr Color micaViolet()  noexcept { return Color(127, 0, 255); }      // Prism Violet #7F00FF
    static constexpr Color micaAmber()   noexcept { return Color(255, 170, 0); }      // Spectral Amber #FFAA00
    static constexpr Color micaGreen()   noexcept { return Color(16, 185, 129); }     // Emerald Green #10B981
    static constexpr Color gray(uint8_t v) noexcept { return Color(v, v, v); }

    /**
     * @brief Linear interpolation between two colors.
     */
    static constexpr Color lerp(const Color& c1, const Color& c2, float t) noexcept {
        t = std::clamp(t, 0.0f, 1.0f);
        return Color(
            static_cast<uint8_t>(c1.r + static_cast<float>(c2.r - c1.r) * t),
            static_cast<uint8_t>(c1.g + static_cast<float>(c2.g - c1.g) * t),
            static_cast<uint8_t>(c1.b + static_cast<float>(c2.b - c1.b) * t),
            static_cast<uint8_t>(c1.a + static_cast<float>(c2.a - c1.a) * t)
        );
    }
};

// ============================================================================
// 2. BMP Image Specification & Clean-Room Parser / Encoder
// ============================================================================

#pragma pack(push, 1)
struct BitmapFileHeader {
    uint16_t bfType{0x4D42}; // 'BM'
    uint32_t bfSize{0};
    uint16_t bfReserved1{0};
    uint16_t bfReserved2{0};
    uint32_t bfOffBits{54};
};

struct BitmapInfoHeader {
    uint32_t biSize{40};
    int32_t  biWidth{0};
    int32_t  biHeight{0};
    uint16_t biPlanes{1};
    uint16_t biBitCount{32};
    uint32_t biCompression{0}; // 0 = BI_RGB uncompressed
    uint32_t biSizeImage{0};
    int32_t  biXPelsPerMeter{2835};
    int32_t  biYPelsPerMeter{2835};
    uint32_t biClrUsed{0};
    uint32_t biClrImportant{0};
};
#pragma pack(pop)

/**
 * @brief In-memory decoded bitmap graphic (e.g. custom user boot logo).
 */
struct BmpImage {
    uint32_t width{0};
    uint32_t height{0};
    uint16_t bpp{32};
    std::vector<Color> pixels; // Row-major: pixels[y * width + x]

    [[nodiscard]] bool isValid() const noexcept {
        return width > 0 && height > 0 && pixels.size() == (static_cast<size_t>(width) * height);
    }

    [[nodiscard]] Color getPixel(uint32_t x, uint32_t y) const noexcept {
        if (x >= width || y >= height) return Color::transparent();
        return pixels[y * width + x];
    }

    void setPixel(uint32_t x, uint32_t y, Color color) {
        if (x < width && y < height) {
            pixels[y * width + x] = color;
        }
    }
};

/**
 * @brief Clean-room BMP parser & encoder.
 */
class BmpCodec {
public:
    /**
     * @brief Decodes an uncompressed 24-bit or 32-bit Windows BMP from raw memory.
     */
    static bool decode(std::span<const uint8_t> buffer, BmpImage& outImage) {
        if (buffer.size() < sizeof(BitmapFileHeader) + sizeof(BitmapInfoHeader)) {
            return false;
        }

        BitmapFileHeader fileHdr{};
        std::memcpy(&fileHdr, buffer.data(), sizeof(BitmapFileHeader));

        if (fileHdr.bfType != 0x4D42) { // 'BM'
            return false;
        }

        BitmapInfoHeader infoHdr{};
        std::memcpy(&infoHdr, buffer.data() + sizeof(BitmapFileHeader), sizeof(BitmapInfoHeader));

        if (infoHdr.biSize < 40 || infoHdr.biCompression != 0) {
            return false; // Only uncompressed BI_RGB is supported in bootloader
        }

        if (infoHdr.biBitCount != 24 && infoHdr.biBitCount != 32) {
            return false;
        }

        uint32_t width = static_cast<uint32_t>(std::abs(infoHdr.biWidth));
        uint32_t height = static_cast<uint32_t>(std::abs(infoHdr.biHeight));
        if (width == 0 || height == 0 || width > 4096 || height > 4096) {
            return false;
        }

        bool bottomUp = (infoHdr.biHeight > 0);
        uint32_t bytesPerPixel = infoHdr.biBitCount / 8;
        uint32_t rowStride = ((width * bytesPerPixel + 3) / 4) * 4; // Row size padded to 4 bytes

        if (fileHdr.bfOffBits + (rowStride * height) > buffer.size()) {
            return false;
        }

        outImage.width = width;
        outImage.height = height;
        outImage.bpp = infoHdr.biBitCount;
        outImage.pixels.resize(static_cast<size_t>(width) * height);

        const uint8_t* pixelData = buffer.data() + fileHdr.bfOffBits;

        for (uint32_t y = 0; y < height; ++y) {
            uint32_t srcY = bottomUp ? (height - 1 - y) : y;
            const uint8_t* srcRow = pixelData + (srcY * rowStride);

            for (uint32_t x = 0; x < width; ++x) {
                const uint8_t* px = srcRow + (x * bytesPerPixel);
                Color color;
                color.b = px[0];
                color.g = px[1];
                color.r = px[2];
                color.a = (bytesPerPixel == 4) ? px[3] : 255;
                outImage.pixels[y * width + x] = color;
            }
        }

        return true;
    }

    /**
     * @brief Encodes an image into standard 32-bit BMP bytes.
     */
    static std::vector<uint8_t> encode(const BmpImage& image) {
        if (!image.isValid()) return {};

        uint32_t rowStride = image.width * 4;
        uint32_t imageSize = rowStride * image.height;
        uint32_t fileSize = sizeof(BitmapFileHeader) + sizeof(BitmapInfoHeader) + imageSize;

        std::vector<uint8_t> bytes(fileSize);

        BitmapFileHeader fileHdr{};
        fileHdr.bfType = 0x4D42;
        fileHdr.bfSize = fileSize;
        fileHdr.bfOffBits = sizeof(BitmapFileHeader) + sizeof(BitmapInfoHeader);

        BitmapInfoHeader infoHdr{};
        infoHdr.biSize = sizeof(BitmapInfoHeader);
        infoHdr.biWidth = static_cast<int32_t>(image.width);
        infoHdr.biHeight = static_cast<int32_t>(image.height); // bottom-up
        infoHdr.biPlanes = 1;
        infoHdr.biBitCount = 32;
        infoHdr.biCompression = 0;
        infoHdr.biSizeImage = imageSize;

        std::memcpy(bytes.data(), &fileHdr, sizeof(fileHdr));
        std::memcpy(bytes.data() + sizeof(fileHdr), &infoHdr, sizeof(infoHdr));

        uint8_t* destPixels = bytes.data() + fileHdr.bfOffBits;

        for (uint32_t y = 0; y < image.height; ++y) {
            uint32_t srcY = image.height - 1 - y; // bottom-up
            const Color* srcRow = &image.pixels[srcY * image.width];
            uint8_t* dstRow = destPixels + (y * rowStride);

            for (uint32_t x = 0; x < image.width; ++x) {
                dstRow[x * 4 + 0] = srcRow[x].b;
                dstRow[x * 4 + 1] = srcRow[x].g;
                dstRow[x * 4 + 2] = srcRow[x].r;
                dstRow[x * 4 + 3] = srcRow[x].a;
            }
        }

        return bytes;
    }
};

// ============================================================================
// 3. Clean-Room 8x8 ASCII Font Matrix
// ============================================================================

namespace font {

/**
 * @brief Clean-room 8x8 bitmap glyphs for printable ASCII 32 (' ') through 126 ('~').
 * Each character is 8 rows of 8 bits (1 byte per row, MSB to LSB).
 */
inline constexpr uint8_t GLYPH_DATA[95][8] = {
    // 32: ' '
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    // 33: '!'
    {0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00},
    // 34: '"'
    {0x66, 0x66, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00},
    // 35: '#'
    {0x6C, 0x6C, 0xFE, 0x6C, 0xFE, 0x6C, 0x6C, 0x00},
    // 36: '$'
    {0x18, 0x7E, 0xD8, 0x7C, 0x1B, 0x7E, 0x18, 0x00},
    // 37: '%'
    {0x62, 0x64, 0x08, 0x10, 0x20, 0x26, 0x46, 0x00},
    // 38: '&'
    {0x38, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0x76, 0x00},
    // 39: '''
    {0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00},
    // 40: '('
    {0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00},
    // 41: ')'
    {0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00},
    // 42: '*'
    {0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00},
    // 43: '+'
    {0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00},
    // 44: ','
    {0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30, 0x00},
    // 45: '-'
    {0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00},
    // 46: '.'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00},
    // 47: '/'
    {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00},
    // 48: '0'
    {0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C, 0x00},
    // 49: '1'
    {0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00},
    // 50: '2'
    {0x3C, 0x66, 0x06, 0x0C, 0x30, 0x60, 0x7E, 0x00},
    // 51: '3'
    {0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00},
    // 52: '4'
    {0x0C, 0x1C, 0x3C, 0x6C, 0xFE, 0x0C, 0x0C, 0x00},
    // 53: '5'
    {0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00},
    // 54: '6'
    {0x3C, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x3C, 0x00},
    // 55: '7'
    {0x7E, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00},
    // 56: '8'
    {0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00},
    // 57: '9'
    {0x3C, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x38, 0x00},
    // 58: ':'
    {0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00},
    // 59: ';'
    {0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x30, 0x00},
    // 60: '<'
    {0x06, 0x0C, 0x18, 0x30, 0x18, 0x0C, 0x06, 0x00},
    // 61: '='
    {0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00},
    // 62: '>'
    {0x60, 0x30, 0x18, 0x0C, 0x18, 0x30, 0x60, 0x00},
    // 63: '?'
    {0x3C, 0x66, 0x06, 0x0C, 0x18, 0x00, 0x18, 0x00},
    // 64: '@'
    {0x3C, 0x66, 0x6E, 0x6E, 0x60, 0x62, 0x3C, 0x00},
    // 65: 'A'
    {0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x00},
    // 66: 'B'
    {0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00},
    // 67: 'C'
    {0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00},
    // 68: 'D'
    {0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00},
    // 69: 'E'
    {0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00},
    // 70: 'F'
    {0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00},
    // 71: 'G'
    {0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3A, 0x00},
    // 72: 'H'
    {0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00},
    // 73: 'I'
    {0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00},
    // 74: 'J'
    {0x0E, 0x06, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00},
    // 75: 'K'
    {0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00},
    // 76: 'L'
    {0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00},
    // 77: 'M'
    {0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00},
    // 78: 'N'
    {0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00},
    // 79: 'O'
    {0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00},
    // 80: 'P'
    {0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00},
    // 81: 'Q'
    {0x3C, 0x66, 0x66, 0x66, 0x6A, 0x64, 0x3A, 0x00},
    // 82: 'R'
    {0x7C, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, 0x00},
    // 83: 'S'
    {0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00},
    // 84: 'T'
    {0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00},
    // 85: 'U'
    {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00},
    // 86: 'V'
    {0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00},
    // 87: 'W'
    {0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00},
    // 88: 'X'
    {0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00},
    // 89: 'Y'
    {0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00},
    // 90: 'Z'
    {0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00},
    // 91: '['
    {0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00},
    // 92: '\'
    {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x00},
    // 93: ']'
    {0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00},
    // 94: '^'
    {0x18, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00},
    // 95: '_'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00},
    // 96: '`'
    {0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00},
    // 97: 'a'
    {0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, 0x00},
    // 98: 'b'
    {0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00},
    // 99: 'c'
    {0x00, 0x00, 0x3C, 0x66, 0x60, 0x66, 0x3C, 0x00},
    // 100: 'd'
    {0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x00},
    // 101: 'e'
    {0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00},
    // 102: 'f'
    {0x1C, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x30, 0x00},
    // 103: 'g'
    {0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x7C},
    // 104: 'h'
    {0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00},
    // 105: 'i'
    {0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00},
    // 106: 'j'
    {0x0C, 0x00, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38},
    // 107: 'k'
    {0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66, 0x00},
    // 108: 'l'
    {0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00},
    // 109: 'm'
    {0x00, 0x00, 0x76, 0x7F, 0x6B, 0x6B, 0x6B, 0x00},
    // 110: 'n'
    {0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00},
    // 111: 'o'
    {0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00},
    // 112: 'p'
    {0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60},
    // 113: 'q'
    {0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06},
    // 114: 'r'
    {0x00, 0x00, 0x7C, 0x66, 0x60, 0x60, 0x60, 0x00},
    // 115: 's'
    {0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x00},
    // 116: 't'
    {0x30, 0x30, 0x7C, 0x30, 0x30, 0x34, 0x18, 0x00},
    // 117: 'u'
    {0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00},
    // 118: 'v'
    {0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00},
    // 119: 'w'
    {0x00, 0x00, 0x63, 0x6B, 0x6B, 0x7F, 0x36, 0x00},
    // 120: 'x'
    {0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00},
    // 121: 'y'
    {0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x7C},
    // 122: 'z'
    {0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00},
    // 123: '{'
    {0x0E, 0x18, 0x18, 0x70, 0x18, 0x18, 0x0E, 0x00},
    // 124: '|'
    {0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00},
    // 125: '}'
    {0x70, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x70, 0x00},
    // 126: '~'
    {0x76, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};

} // namespace font

// ============================================================================
// 4. Boot Video Driver (bootvid)
// ============================================================================

/**
 * @brief Modern clean-room Boot Video Driver for UEFI GOP & Kernel Bootvid.
 */
class BootVideoDriver {
private:
    uint32_t* m_framebuffer{nullptr};
    uint32_t m_width{0};
    uint32_t m_height{0};
    uint32_t m_pixelsPerScanLine{0};
    uint32_t m_pixelFormat{1}; // 1 = BGRA, 0 = RGBA
    bool m_ownsBuffer{false};

public:
    BootVideoDriver() = default;

    ~BootVideoDriver() {
        reset();
    }

    // Move-only semantics
    BootVideoDriver(const BootVideoDriver&) = delete;
    BootVideoDriver& operator=(const BootVideoDriver&) = delete;

    BootVideoDriver(BootVideoDriver&& other) noexcept
        : m_framebuffer(other.m_framebuffer),
          m_width(other.m_width),
          m_height(other.m_height),
          m_pixelsPerScanLine(other.m_pixelsPerScanLine),
          m_pixelFormat(other.m_pixelFormat),
          m_ownsBuffer(other.m_ownsBuffer) {
        other.m_framebuffer = nullptr;
        other.m_ownsBuffer = false;
    }

    BootVideoDriver& operator=(BootVideoDriver&& other) noexcept {
        if (this != &other) {
            reset();
            m_framebuffer = other.m_framebuffer;
            m_width = other.m_width;
            m_height = other.m_height;
            m_pixelsPerScanLine = other.m_pixelsPerScanLine;
            m_pixelFormat = other.m_pixelFormat;
            m_ownsBuffer = other.m_ownsBuffer;

            other.m_framebuffer = nullptr;
            other.m_ownsBuffer = false;
        }
        return *this;
    }

    /**
     * @brief Initialize with an existing GOP framebuffer descriptor.
     */
    bool initialize(const boot::FramebufferDescriptor& desc) {
        reset();
        if (desc.physicalBase == 0 || desc.width == 0 || desc.height == 0) {
            return false;
        }
        m_framebuffer = reinterpret_cast<uint32_t*>(desc.physicalBase);
        m_width = desc.width;
        m_height = desc.height;
        m_pixelsPerScanLine = (desc.pixelsPerScanLine > 0) ? desc.pixelsPerScanLine : desc.width;
        m_pixelFormat = desc.pixelFormat;
        m_ownsBuffer = false;
        return true;
    }

    /**
     * @brief Initialize a virtual memory framebuffer (useful for test harnesses, offscreen rendering, and previews).
     */
    bool initializeVirtual(uint32_t width, uint32_t height) {
        reset();
        if (width == 0 || height == 0) return false;
        m_width = width;
        m_height = height;
        m_pixelsPerScanLine = width;
        m_pixelFormat = 1; // BGRA
        m_framebuffer = new uint32_t[static_cast<size_t>(width) * height]();
        m_ownsBuffer = true;
        return true;
    }

    void reset() noexcept {
        if (m_ownsBuffer && m_framebuffer) {
            delete[] m_framebuffer;
        }
        m_framebuffer = nullptr;
        m_width = 0;
        m_height = 0;
        m_pixelsPerScanLine = 0;
        m_ownsBuffer = false;
    }

    [[nodiscard]] bool isInitialized() const noexcept { return m_framebuffer != nullptr; }
    [[nodiscard]] uint32_t getWidth() const noexcept { return m_width; }
    [[nodiscard]] uint32_t getHeight() const noexcept { return m_height; }
    [[nodiscard]] uint32_t getPitch() const noexcept { return m_pixelsPerScanLine; }
    [[nodiscard]] const uint32_t* getRawBuffer() const noexcept { return m_framebuffer; }

    // ------------------------------------------------------------------------
    // Drawing Primitives
    // ------------------------------------------------------------------------

    void putPixel(uint32_t x, uint32_t y, Color color) noexcept {
        if (!m_framebuffer || x >= m_width || y >= m_height) return;

        uint32_t pixelValue = (m_pixelFormat == 0) ? color.toRgba32() : color.toBgra32();
        if (color.a == 255) {
            m_framebuffer[y * m_pixelsPerScanLine + x] = pixelValue;
        } else if (color.a > 0) {
            // Alpha blending
            Color bg = getPixel(x, y);
            Color blended = Color::lerp(bg, color, static_cast<float>(color.a) / 255.0f);
            m_framebuffer[y * m_pixelsPerScanLine + x] = (m_pixelFormat == 0) ? blended.toRgba32() : blended.toBgra32();
        }
    }

    [[nodiscard]] Color getPixel(uint32_t x, uint32_t y) const noexcept {
        if (!m_framebuffer || x >= m_width || y >= m_height) return Color::black();
        uint32_t val = m_framebuffer[y * m_pixelsPerScanLine + x];
        Color c;
        if (m_pixelFormat == 0) { // RGBA
            c.r = static_cast<uint8_t>(val & 0xFF);
            c.g = static_cast<uint8_t>((val >> 8) & 0xFF);
            c.b = static_cast<uint8_t>((val >> 16) & 0xFF);
            c.a = static_cast<uint8_t>((val >> 24) & 0xFF);
        } else { // BGRA
            c.b = static_cast<uint8_t>(val & 0xFF);
            c.g = static_cast<uint8_t>((val >> 8) & 0xFF);
            c.r = static_cast<uint8_t>((val >> 16) & 0xFF);
            c.a = static_cast<uint8_t>((val >> 24) & 0xFF);
        }
        return c;
    }

    void clear(Color color) noexcept {
        if (!m_framebuffer) return;
        uint32_t val = (m_pixelFormat == 0) ? color.toRgba32() : color.toBgra32();
        if (m_pixelsPerScanLine == m_width) {
            std::fill_n(m_framebuffer, static_cast<size_t>(m_width) * m_height, val);
        } else {
            for (uint32_t y = 0; y < m_height; ++y) {
                std::fill_n(&m_framebuffer[y * m_pixelsPerScanLine], m_width, val);
            }
        }
    }

    void fillRectangle(uint32_t x, uint32_t y, uint32_t width, uint32_t height, Color color) noexcept {
        if (!m_framebuffer || x >= m_width || y >= m_height) return;
        uint32_t xEnd = std::min(x + width, m_width);
        uint32_t yEnd = std::min(y + height, m_height);

        for (uint32_t cy = y; cy < yEnd; ++cy) {
            for (uint32_t cx = x; cx < xEnd; ++cx) {
                putPixel(cx, cy, color);
            }
        }
    }

    void drawRectangle(uint32_t x, uint32_t y, uint32_t width, uint32_t height, Color color, uint32_t thickness = 1) noexcept {
        if (width == 0 || height == 0 || thickness == 0) return;
        // Top & bottom
        fillRectangle(x, y, width, thickness, color);
        fillRectangle(x, y + height - thickness, width, thickness, color);
        // Left & right
        fillRectangle(x, y, thickness, height, color);
        fillRectangle(x + width - thickness, y, thickness, height, color);
    }

    void drawVerticalGradient(uint32_t x, uint32_t y, uint32_t width, uint32_t height, Color topColor, Color bottomColor) noexcept {
        if (!m_framebuffer || height == 0) return;
        for (uint32_t row = 0; row < height; ++row) {
            float t = static_cast<float>(row) / static_cast<float>(height);
            Color rowColor = Color::lerp(topColor, bottomColor, t);
            fillRectangle(x, y + row, width, 1, rowColor);
        }
    }

    void drawHorizontalGradient(uint32_t x, uint32_t y, uint32_t width, uint32_t height, Color leftColor, Color rightColor) noexcept {
        if (!m_framebuffer || width == 0) return;
        for (uint32_t col = 0; col < width; ++col) {
            float t = static_cast<float>(col) / static_cast<float>(width);
            Color colColor = Color::lerp(leftColor, rightColor, t);
            fillRectangle(x + col, y, 1, height, colColor);
        }
    }

    void drawLine(int32_t x0, int32_t y0, int32_t x1, int32_t y1, Color color) noexcept {
        int32_t dx = std::abs(x1 - x0);
        int32_t sx = (x0 < x1) ? 1 : -1;
        int32_t dy = -std::abs(y1 - y0);
        int32_t sy = (y0 < y1) ? 1 : -1;
        int32_t err = dx + dy;

        while (true) {
            if (x0 >= 0 && x0 < static_cast<int32_t>(m_width) && y0 >= 0 && y0 < static_cast<int32_t>(m_height)) {
                putPixel(static_cast<uint32_t>(x0), static_cast<uint32_t>(y0), color);
            }
            if (x0 == x1 && y0 == y1) break;
            int32_t e2 = 2 * err;
            if (e2 >= dy) { err += dy; x0 += sx; }
            if (e2 <= dx) { err += dx; y0 += sy; }
        }
    }

    void drawCircle(uint32_t centerX, uint32_t centerY, uint32_t radius, Color color, bool filled = false) noexcept {
        int32_t x = static_cast<int32_t>(radius);
        int32_t y = 0;
        int32_t err = 0;

        while (x >= y) {
            if (filled) {
                drawLine(static_cast<int32_t>(centerX) - x, static_cast<int32_t>(centerY) + y, static_cast<int32_t>(centerX) + x, static_cast<int32_t>(centerY) + y, color);
                drawLine(static_cast<int32_t>(centerX) - y, static_cast<int32_t>(centerY) + x, static_cast<int32_t>(centerX) + y, static_cast<int32_t>(centerY) + x, color);
                drawLine(static_cast<int32_t>(centerX) - x, static_cast<int32_t>(centerY) - y, static_cast<int32_t>(centerX) + x, static_cast<int32_t>(centerY) - y, color);
                drawLine(static_cast<int32_t>(centerX) - y, static_cast<int32_t>(centerY) - x, static_cast<int32_t>(centerX) + y, static_cast<int32_t>(centerY) - x, color);
            } else {
                putPixel(centerX + x, centerY + y, color);
                putPixel(centerX + y, centerY + x, color);
                putPixel(centerX - y, centerY + x, color);
                putPixel(centerX - x, centerY + y, color);
                putPixel(centerX - x, centerY - y, color);
                putPixel(centerX - y, centerY - x, color);
                putPixel(centerX + y, centerY - x, color);
                putPixel(centerX + x, centerY - y, color);
            }

            if (err <= 0) {
                y += 1;
                err += 2 * y + 1;
            }
            if (err > 0) {
                x -= 1;
                err -= 2 * x + 1;
            }
        }
    }

    // ------------------------------------------------------------------------
    // Typography & Text
    // ------------------------------------------------------------------------

    void drawChar(uint32_t x, uint32_t y, char c, Color fg, Color bg = Color::transparent(), uint32_t scale = 1) noexcept {
        if (c < 32 || c > 126) c = '?';
        const uint8_t* glyph = font::GLYPH_DATA[c - 32];

        for (uint32_t row = 0; row < 8; ++row) {
            uint8_t bits = glyph[row];
            for (uint32_t col = 0; col < 8; ++col) {
                bool isSet = (bits & (0x80 >> col)) != 0;
                Color pxColor = isSet ? fg : bg;
                if (pxColor.a > 0) {
                    if (scale == 1) {
                        putPixel(x + col, y + row, pxColor);
                    } else {
                        fillRectangle(x + (col * scale), y + (row * scale), scale, scale, pxColor);
                    }
                }
            }
        }
    }

    void drawString(uint32_t x, uint32_t y, std::string_view str, Color fg, Color bg = Color::transparent(), uint32_t scale = 1) noexcept {
        uint32_t cursorX = x;
        uint32_t cursorY = y;
        uint32_t charWidth = 8 * scale;
        uint32_t charHeight = 8 * scale;

        for (char c : str) {
            if (c == '\n') {
                cursorX = x;
                cursorY += charHeight + (2 * scale);
                continue;
            }
            drawChar(cursorX, cursorY, c, fg, bg, scale);
            cursorX += charWidth;
        }
    }

    void drawStringCentered(uint32_t centerY, std::string_view str, Color fg, uint32_t scale = 1) noexcept {
        uint32_t totalWidth = static_cast<uint32_t>(str.length()) * 8 * scale;
        uint32_t startX = (m_width > totalWidth) ? ((m_width - totalWidth) / 2) : 0;
        drawString(startX, centerY, str, fg, Color::transparent(), scale);
    }

    // ------------------------------------------------------------------------
    // Bitmap Graphics & Custom Boot Logos
    // ------------------------------------------------------------------------

    void drawBitmap(uint32_t x, uint32_t y, const BmpImage& bmp) noexcept {
        if (!bmp.isValid()) return;
        for (uint32_t by = 0; by < bmp.height; ++by) {
            for (uint32_t bx = 0; bx < bmp.width; ++bx) {
                Color c = bmp.getPixel(bx, by);
                if (c.a > 0) {
                    putPixel(x + bx, y + by, c);
                }
            }
        }
    }

    void drawBitmapCentered(uint32_t centerY, const BmpImage& bmp) noexcept {
        if (!bmp.isValid()) return;
        uint32_t startX = (m_width > bmp.width) ? ((m_width - bmp.width) / 2) : 0;
        drawBitmap(startX, centerY, bmp);
    }

    // ------------------------------------------------------------------------
    // Dave Cutler's 1988 DEC "Mica" Prism Emblem & Boot Splash
    // ------------------------------------------------------------------------

    /**
     * @brief Procedurally renders Dave Cutler's 1988 DEC Mica Prism Emblem:
     * A stylized multi-faceted quartz crystal refracting spectral rays (Cyan, Blue, Violet, Amber).
     */
    void drawMicaPrism(uint32_t centerX, uint32_t centerY, uint32_t size) noexcept {
        int32_t s = static_cast<int32_t>(size);
        int32_t cx = static_cast<int32_t>(centerX);
        int32_t cy = static_cast<int32_t>(centerY);

        // Prism Vertices (Hexagonal Isometric Crystal)
        // Top apex: (cx, cy - s)
        // Bottom apex: (cx, cy + s)
        // Left facet: (cx - s * 0.7, cy - s * 0.2) to (cx - s * 0.7, cy + s * 0.2)
        // Right facet: (cx + s * 0.7, cy - s * 0.2) to (cx + s * 0.7, cy + s * 0.2)

        // Draw Left Facet (Mica Azure Gradient)
        for (int32_t y = -s; y <= s; ++y) {
            float progress = static_cast<float>(y + s) / static_cast<float>(2 * s);
            int32_t widthAtY = static_cast<int32_t>((1.0f - std::abs(static_cast<float>(y) / static_cast<float>(s))) * (s * 0.75f));
            for (int32_t x = -widthAtY; x < 0; ++x) {
                float facetT = static_cast<float>(x + widthAtY) / static_cast<float>(widthAtY + 1);
                Color leftCol = Color::lerp(Color::micaCyan(), Color::micaBlue(), (progress + facetT) * 0.5f);
                putPixel(static_cast<uint32_t>(cx + x), static_cast<uint32_t>(cy + y), leftCol);
            }
            // Draw Right Facet (Prism Violet & Amber Gradient)
            for (int32_t x = 0; x <= widthAtY; ++x) {
                float facetT = static_cast<float>(x) / static_cast<float>(widthAtY + 1);
                Color rightCol = Color::lerp(Color::micaBlue(), Color::micaViolet(), (progress + facetT) * 0.5f);
                putPixel(static_cast<uint32_t>(cx + x), static_cast<uint32_t>(cy + y), rightCol);
            }
        }

        // Draw Center Ridge (Shimmer Highlight)
        for (int32_t y = -s; y <= s; ++y) {
            putPixel(static_cast<uint32_t>(cx), static_cast<uint32_t>(cy + y), Color::white());
            putPixel(static_cast<uint32_t>(cx + 1), static_cast<uint32_t>(cy + y), Color::micaCyan());
        }

        // Draw Refracted Spectral Beams Emanating from Right
        int32_t beamStartX = cx + static_cast<int32_t>(s * 0.75f) / 2;
        drawLine(beamStartX, cy - s / 4, beamStartX + s * 2, cy - s * 2 / 3, Color::micaAmber());
        drawLine(beamStartX, cy,         beamStartX + s * 2, cy - s / 4,     Color::micaCyan());
        drawLine(beamStartX, cy + s / 4, beamStartX + s * 2, cy + s / 6,     Color::micaViolet());
    }

    /**
     * @brief Smooth Progress Bar
     */
    void drawProgressBar(uint32_t x, uint32_t y, uint32_t width, uint32_t height,
                         float progress, Color fillColor, Color bgColor, Color borderColor) noexcept {
        drawRectangle(x, y, width, height, borderColor, 1);
        fillRectangle(x + 1, y + 1, width - 2, height - 2, bgColor);
        uint32_t fillWidth = static_cast<uint32_t>((width - 2) * std::clamp(progress, 0.0f, 1.0f));
        if (fillWidth > 0) {
            fillRectangle(x + 1, y + 1, fillWidth, height - 2, fillColor);
        }
    }

    /**
     * @brief Animated Orbital Spinner (for waiting / loading states)
     */
    void drawOrbitalSpinner(uint32_t centerX, uint32_t centerY, uint32_t radius, float angleRad, Color color) noexcept {
        constexpr int NUM_DOTS = 6;
        for (int i = 0; i < NUM_DOTS; ++i) {
            float dotAngle = angleRad - (static_cast<float>(i) * 0.35f);
            float dotRadius = static_cast<float>(radius);
            int32_t dx = static_cast<int32_t>(std::cos(dotAngle) * dotRadius);
            int32_t dy = static_cast<int32_t>(std::sin(dotAngle) * dotRadius);
            float fade = 1.0f - (static_cast<float>(i) / static_cast<float>(NUM_DOTS));
            Color dotColor = color;
            dotColor.a = static_cast<uint8_t>(255.0f * fade);
            drawCircle(centerX + dx, centerY + dy, 3, dotColor, true);
        }
    }

    /**
     * @brief Full Modern MicaNT Boot Splash Screen.
     */
    void renderBootSplash(std::string_view statusText = "Starting Executive Services...",
                          float progress = 0.5f,
                          const BmpImage* customLogo = nullptr) noexcept {
        if (!m_framebuffer) return;

        // 1. Background Slate Fill with subtle top-to-bottom vignette
        drawVerticalGradient(0, 0, m_width, m_height, Color(14, 16, 24), Color::micaDark());

        uint32_t centerY = m_height / 3;

        // 2. Logo: Custom User BMP or Dave Cutler's Mica Prism
        if (customLogo && customLogo->isValid()) {
            drawBitmapCentered(centerY - (customLogo->height / 2), *customLogo);
        } else {
            drawMicaPrism(m_width / 2, centerY, 48);
        }

        // 3. Typography
        uint32_t textY = centerY + 80;
        drawStringCentered(textY, "M i c a N T", Color::white(), 2);
        drawStringCentered(textY + 28, "Clean-Room NT Kernel Architecture (x86_64)", Color::micaCyan(), 1);

        // 4. Progress Bar
        uint32_t barWidth = std::min(m_width * 2 / 5, 400u);
        uint32_t barHeight = 8;
        uint32_t barX = (m_width - barWidth) / 2;
        uint32_t barY = textY + 64;

        drawProgressBar(barX, barY, barWidth, barHeight, progress, Color::micaCyan(), Color::micaSurface(), Color::micaBorder());

        // 5. Status Text
        drawStringCentered(barY + 16, statusText, Color::gray(180), 1);
    }
};

// ============================================================================
// 5. Classic NT bootvid.dll Export Compatibility Emulation
// ============================================================================

/**
 * @brief Singleton wrapper exposing the classic NT bootvid API surface.
 */
class BootVideoSubsystem {
private:
    BootVideoDriver m_driver;
    bool m_initialized{false};

    BootVideoSubsystem() = default;

public:
    static BootVideoSubsystem& get() noexcept {
        static BootVideoSubsystem instance;
        return instance;
    }

    bool initialize(const boot::FramebufferDescriptor& desc) {
        m_initialized = m_driver.initialize(desc);
        return m_initialized;
    }

    bool initializeVirtual(uint32_t width = 1024, uint32_t height = 768) {
        m_initialized = m_driver.initializeVirtual(width, height);
        return m_initialized;
    }

    [[nodiscard]] BootVideoDriver& getDriver() noexcept { return m_driver; }
    [[nodiscard]] bool isInitialized() const noexcept { return m_initialized; }

    // Standard NT bootvid API
    bool vidInitialize(void* framebuffer, uint32_t width, uint32_t height, uint32_t pitch, uint32_t format = 1) {
        boot::FramebufferDescriptor desc{
            .physicalBase = reinterpret_cast<uint64_t>(framebuffer),
            .size = static_cast<uint64_t>(pitch) * height * 4,
            .width = width,
            .height = height,
            .pixelsPerScanLine = pitch,
            .pixelFormat = format
        };
        return initialize(desc);
    }

    void vidResetDisplay(bool clearScreen = true) {
        if (m_initialized && clearScreen) {
            m_driver.clear(Color::black());
        }
    }

    void vidDisplayString(uint32_t x, uint32_t y, std::string_view str, Color fg = Color::white(), Color bg = Color::transparent()) {
        if (m_initialized) {
            m_driver.drawString(x, y, str, fg, bg);
        }
    }

    void vidSolidColorFill(uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, Color color) {
        if (m_initialized && x2 >= x1 && y2 >= y1) {
            m_driver.fillRectangle(x1, y1, (x2 - x1) + 1, (y2 - y1) + 1, color);
        }
    }

    void vidBufferToScreenBlt(uint32_t x, uint32_t y, const BmpImage& bmp) {
        if (m_initialized) {
            m_driver.drawBitmap(x, y, bmp);
        }
    }
};

} // namespace micant::bootvid
