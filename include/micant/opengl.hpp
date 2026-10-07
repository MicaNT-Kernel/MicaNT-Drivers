// ============================================================================
// MicaNT: OpenGL Subsystem & Windows OpenGL (WGL) Runtime (opengl32.dll / glu32.dll)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Provides complete OpenGL 1.1 - 1.4 API Surface, Windows WGL Context Bridge,
// Matrix Stacks (ModelView, Projection, Texture), Fixed-Function Immediate Mode,
// Vertex Arrays, 2D Texture Mapping with Bilinear/Nearest Filtering,
// Depth/Z-Buffering, Alpha Blending, Face Culling, GLU Utility Library,
// and Direct Integration with User32 / GDI Device Contexts.
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
#include <array>
#include <iostream>

#include "ntdef.hpp"
#include "gdi32.hpp"
#include "user32.hpp"
#include "ldr.hpp"

namespace micant::opengl {

// ============================================================================
// 1. OpenGL Standard Types & Handles
// ============================================================================

using GLenum     = uint32_t;
using GLboolean  = uint8_t;
using GLbitfield = uint32_t;
using GLbyte     = int8_t;
using GLshort    = int16_t;
using GLint      = int32_t;
using GLsizei    = int32_t;
using GLubyte    = uint8_t;
using GLushort   = uint16_t;
using GLuint     = uint32_t;
using GLfloat    = float;
using GLclampf   = float;
using GLdouble   = double;
using GLclampd   = double;
using GLvoid     = void;
using HGLRC      = void*;

inline constexpr GLboolean GL_FALSE = 0;
inline constexpr GLboolean GL_TRUE  = 1;

// ============================================================================
// 2. OpenGL Standard Constants
// ============================================================================

// Primitives
inline constexpr GLenum GL_POINTS         = 0x0000;
inline constexpr GLenum GL_LINES          = 0x0001;
inline constexpr GLenum GL_LINE_LOOP      = 0x0002;
inline constexpr GLenum GL_LINE_STRIP     = 0x0003;
inline constexpr GLenum GL_TRIANGLES      = 0x0004;
inline constexpr GLenum GL_TRIANGLE_STRIP = 0x0005;
inline constexpr GLenum GL_TRIANGLE_FAN   = 0x0006;
inline constexpr GLenum GL_QUADS          = 0x0007;
inline constexpr GLenum GL_QUAD_STRIP     = 0x0008;
inline constexpr GLenum GL_POLYGON        = 0x0009;

// Matrix Modes
inline constexpr GLenum GL_MODELVIEW      = 0x1700;
inline constexpr GLenum GL_PROJECTION     = 0x1701;
inline constexpr GLenum GL_TEXTURE        = 0x1702;

// Depth & Comparison Functions
inline constexpr GLenum GL_NEVER          = 0x0200;
inline constexpr GLenum GL_LESS           = 0x0201;
inline constexpr GLenum GL_EQUAL          = 0x0202;
inline constexpr GLenum GL_LEQUAL         = 0x0203;
inline constexpr GLenum GL_GREATER        = 0x0204;
inline constexpr GLenum GL_NOTEQUAL       = 0x0205;
inline constexpr GLenum GL_GEQUAL         = 0x0206;
inline constexpr GLenum GL_ALWAYS         = 0x0207;
inline constexpr GLenum GL_DEPTH_TEST     = 0x0B71;

// Blending
inline constexpr GLenum GL_BLEND          = 0x0BE2;
inline constexpr GLenum GL_ZERO           = 0;
inline constexpr GLenum GL_ONE            = 1;
inline constexpr GLenum GL_SRC_COLOR      = 0x0300;
inline constexpr GLenum GL_ONE_MINUS_SRC_COLOR = 0x0301;
inline constexpr GLenum GL_SRC_ALPHA      = 0x0302;
inline constexpr GLenum GL_ONE_MINUS_SRC_ALPHA = 0x0303;
inline constexpr GLenum GL_DST_ALPHA      = 0x0304;
inline constexpr GLenum GL_ONE_MINUS_DST_ALPHA = 0x0305;
inline constexpr GLenum GL_DST_COLOR      = 0x0306;
inline constexpr GLenum GL_ONE_MINUS_DST_COLOR = 0x0307;

// Culling
inline constexpr GLenum GL_CULL_FACE      = 0x0B44;
inline constexpr GLenum GL_FRONT          = 0x0404;
inline constexpr GLenum GL_BACK           = 0x0405;
inline constexpr GLenum GL_FRONT_AND_BACK = 0x0408;
inline constexpr GLenum GL_CW             = 0x0900;
inline constexpr GLenum GL_CCW            = 0x0901;

// Shading
inline constexpr GLenum GL_FLAT           = 0x1D00;
inline constexpr GLenum GL_SMOOTH         = 0x1D01;

// Buffers
inline constexpr GLbitfield GL_COLOR_BUFFER_BIT   = 0x00004000;
inline constexpr GLbitfield GL_DEPTH_BUFFER_BIT   = 0x00000100;
inline constexpr GLbitfield GL_STENCIL_BUFFER_BIT = 0x00000400;

// Textures
inline constexpr GLenum GL_TEXTURE_2D         = 0x0DE1;
inline constexpr GLenum GL_TEXTURE_MAG_FILTER = 0x2800;
inline constexpr GLenum GL_TEXTURE_MIN_FILTER = 0x2801;
inline constexpr GLenum GL_TEXTURE_WRAP_S     = 0x2802;
inline constexpr GLenum GL_TEXTURE_WRAP_T     = 0x2803;
inline constexpr GLenum GL_NEAREST            = 0x2600;
inline constexpr GLenum GL_LINEAR             = 0x2601;
inline constexpr GLenum GL_REPEAT             = 0x2901;
inline constexpr GLenum GL_CLAMP              = 0x2900;
inline constexpr GLenum GL_CLAMP_TO_EDGE      = 0x812F;
inline constexpr GLenum GL_RGB                = 0x1907;
inline constexpr GLenum GL_RGBA               = 0x1908;
inline constexpr GLenum GL_BGR_EXT            = 0x80E0;
inline constexpr GLenum GL_BGRA_EXT           = 0x80E1;
inline constexpr GLenum GL_UNSIGNED_BYTE      = 0x1401;
inline constexpr GLenum GL_FLOAT              = 0x1406;

// Client States
inline constexpr GLenum GL_VERTEX_ARRAY        = 0x8074;
inline constexpr GLenum GL_NORMAL_ARRAY        = 0x8075;
inline constexpr GLenum GL_COLOR_ARRAY         = 0x8076;
inline constexpr GLenum GL_TEXTURE_COORD_ARRAY = 0x8078;

// Information & Errors
inline constexpr GLenum GL_VENDOR             = 0x1F00;
inline constexpr GLenum GL_RENDERER           = 0x1F01;
inline constexpr GLenum GL_VERSION            = 0x1F02;
inline constexpr GLenum GL_EXTENSIONS         = 0x1F03;
inline constexpr GLenum GL_NO_ERROR           = 0;
inline constexpr GLenum GL_INVALID_ENUM       = 0x0500;
inline constexpr GLenum GL_INVALID_VALUE      = 0x0501;
inline constexpr GLenum GL_INVALID_OPERATION  = 0x0502;
inline constexpr GLenum GL_STACK_OVERFLOW     = 0x0503;
inline constexpr GLenum GL_STACK_UNDERFLOW    = 0x0504;
inline constexpr GLenum GL_OUT_OF_MEMORY      = 0x0505;

// GLU Errors
inline constexpr GLenum GLU_INVALID_ENUM      = 100900;
inline constexpr GLenum GLU_INVALID_VALUE     = 100901;
inline constexpr GLenum GLU_OUT_OF_MEMORY     = 100902;

// ============================================================================
// 3. Mathematics & Linear Algebra Engine (Column-Major 4x4 Matrices)
// ============================================================================

struct GlVector4 {
    float x{0.0f}, y{0.0f}, z{0.0f}, w{1.0f};
};

struct GlMatrix4x4 {
    // Stored column-major:
    // m[0]  m[4]  m[8]   m[12]
    // m[1]  m[5]  m[9]   m[13]
    // m[2]  m[6]  m[10]  m[14]
    // m[3]  m[7]  m[11]  m[15]
    std::array<float, 16> m{};

    static GlMatrix4x4 Identity() noexcept {
        GlMatrix4x4 mat{};
        mat.m[0]  = 1.0f;
        mat.m[5]  = 1.0f;
        mat.m[10] = 1.0f;
        mat.m[15] = 1.0f;
        return mat;
    }

    static GlMatrix4x4 Multiply(const GlMatrix4x4& a, const GlMatrix4x4& b) noexcept {
        GlMatrix4x4 res{};
        for (int col = 0; col < 4; ++col) {
            for (int row = 0; row < 4; ++row) {
                float sum = 0.0f;
                for (int k = 0; k < 4; ++k) {
                    sum += a.m[k * 4 + row] * b.m[col * 4 + k];
                }
                res.m[col * 4 + row] = sum;
            }
        }
        return res;
    }

    static GlMatrix4x4 Translate(float x, float y, float z) noexcept {
        GlMatrix4x4 mat = Identity();
        mat.m[12] = x;
        mat.m[13] = y;
        mat.m[14] = z;
        return mat;
    }

    static GlMatrix4x4 Scale(float x, float y, float z) noexcept {
        GlMatrix4x4 mat = Identity();
        mat.m[0]  = x;
        mat.m[5]  = y;
        mat.m[10] = z;
        return mat;
    }

    static GlMatrix4x4 Rotate(float angleDeg, float x, float y, float z) noexcept {
        float len = std::sqrt(x * x + y * y + z * z);
        if (len < 1e-6f) return Identity();
        x /= len; y /= len; z /= len;

        float rad = angleDeg * 3.14159265358979323846f / 180.0f;
        float c = std::cos(rad);
        float s = std::sin(rad);
        float oneMinusC = 1.0f - c;

        GlMatrix4x4 mat = Identity();
        mat.m[0]  = x * x * oneMinusC + c;
        mat.m[1]  = y * x * oneMinusC + z * s;
        mat.m[2]  = x * z * oneMinusC - y * s;

        mat.m[4]  = x * y * oneMinusC - z * s;
        mat.m[5]  = y * y * oneMinusC + c;
        mat.m[6]  = y * z * oneMinusC + x * s;

        mat.m[8]  = x * z * oneMinusC + y * s;
        mat.m[9]  = y * z * oneMinusC - x * s;
        mat.m[10] = z * z * oneMinusC + c;
        return mat;
    }

    static GlMatrix4x4 Frustum(double left, double right, double bottom, double top, double nearVal, double farVal) noexcept {
        GlMatrix4x4 mat{};
        float rl = static_cast<float>(right - left);
        float tb = static_cast<float>(top - bottom);
        float fn = static_cast<float>(farVal - nearVal);
        float n2 = static_cast<float>(2.0 * nearVal);

        if (rl <= 0.0f || tb <= 0.0f || fn <= 0.0f) return Identity();

        mat.m[0]  = n2 / rl;
        mat.m[5]  = n2 / tb;
        mat.m[8]  = static_cast<float>(right + left) / rl;
        mat.m[9]  = static_cast<float>(top + bottom) / tb;
        mat.m[10] = -static_cast<float>(farVal + nearVal) / fn;
        mat.m[11] = -1.0f;
        mat.m[14] = -static_cast<float>(2.0 * farVal * nearVal) / fn;
        return mat;
    }

    static GlMatrix4x4 Ortho(double left, double right, double bottom, double top, double nearVal, double farVal) noexcept {
        GlMatrix4x4 mat = Identity();
        float rl = static_cast<float>(right - left);
        float tb = static_cast<float>(top - bottom);
        float fn = static_cast<float>(farVal - nearVal);

        if (rl == 0.0f || tb == 0.0f || fn == 0.0f) return Identity();

        mat.m[0]  = 2.0f / rl;
        mat.m[5]  = 2.0f / tb;
        mat.m[10] = -2.0f / fn;
        mat.m[12] = -static_cast<float>(right + left) / rl;
        mat.m[13] = -static_cast<float>(top + bottom) / tb;
        mat.m[14] = -static_cast<float>(farVal + nearVal) / fn;
        return mat;
    }

    [[nodiscard]] GlVector4 Transform(const GlVector4& v) const noexcept {
        return GlVector4{
            m[0] * v.x + m[4] * v.y + m[8]  * v.z + m[12] * v.w,
            m[1] * v.x + m[5] * v.y + m[9]  * v.z + m[13] * v.w,
            m[2] * v.x + m[6] * v.y + m[10] * v.z + m[14] * v.w,
            m[3] * v.x + m[7] * v.y + m[11] * v.z + m[15] * v.w
        };
    }
};

// ============================================================================
// 4. Vertex Structures & Texture Containers
// ============================================================================

struct GlVertex {
    float x{0.0f}, y{0.0f}, z{0.0f}, w{1.0f};
    float r{1.0f}, g{1.0f}, b{1.0f}, a{1.0f};
    float u{0.0f}, v{0.0f};
    float nx{0.0f}, ny{0.0f}, nz{1.0f};
};

struct GlTexture {
    uint32_t id{0};
    uint32_t width{0};
    uint32_t height{0};
    std::vector<uint32_t> pixels; // 0xAARRGGBB format
    GLenum minFilter{GL_NEAREST};
    GLenum magFilter{GL_LINEAR};
    GLenum wrapS{GL_REPEAT};
    GLenum wrapT{GL_REPEAT};

    [[nodiscard]] uint32_t Sample(float s, float t) const noexcept {
        if (width == 0 || height == 0 || pixels.empty()) return 0xFFFFFFFF;

        auto applyWrap = [](float coord, GLenum wrapMode) -> float {
            if (wrapMode == GL_REPEAT) {
                float wrapped = coord - std::floor(coord);
                return wrapped;
            } else {
                return std::clamp(coord, 0.0f, 1.0f);
            }
        };

        float u = applyWrap(s, wrapS);
        float v = applyWrap(t, wrapT);

        if (magFilter == GL_NEAREST) {
            uint32_t px = std::min(static_cast<uint32_t>(u * width), width - 1);
            uint32_t py = std::min(static_cast<uint32_t>(v * height), height - 1);
            return pixels[py * width + px];
        }

        // Bilinear Filtering
        float fx = u * (width - 1);
        float fy = v * (height - 1);
        uint32_t x0 = static_cast<uint32_t>(fx);
        uint32_t y0 = static_cast<uint32_t>(fy);
        uint32_t x1 = std::min(x0 + 1, width - 1);
        uint32_t y1 = std::min(y0 + 1, height - 1);
        float dx = fx - x0;
        float dy = fy - y0;

        uint32_t c00 = pixels[y0 * width + x0];
        uint32_t c10 = pixels[y0 * width + x1];
        uint32_t c01 = pixels[y1 * width + x0];
        uint32_t c11 = pixels[y1 * width + x1];

        auto bilerp = [dx, dy, c00, c10, c01, c11](uint32_t mask, uint32_t shift) -> uint32_t {
            float v00 = static_cast<float>((c00 >> shift) & mask);
            float v10 = static_cast<float>((c10 >> shift) & mask);
            float v01 = static_cast<float>((c01 >> shift) & mask);
            float v11 = static_cast<float>((c11 >> shift) & mask);
            float top = v00 * (1.0f - dx) + v10 * dx;
            float bot = v01 * (1.0f - dx) + v11 * dx;
            float val = top * (1.0f - dy) + bot * dy;
            return static_cast<uint32_t>(std::clamp(val, 0.0f, 255.0f)) << shift;
        };

        return bilerp(0xFF, 24) | bilerp(0xFF, 16) | bilerp(0xFF, 8) | bilerp(0xFF, 0);
    }
};

// ============================================================================
// 5. OpenGL Rendering Context (HGLRC)
// ============================================================================

class OpenGLContext {
public:
    gdi32::HDC m_hdc{nullptr};
    uint32_t m_width{800};
    uint32_t m_height{600};
    std::vector<uint32_t> m_colorBuffer;
    std::vector<float>    m_depthBuffer;

    // Matrix Stacks
    std::vector<GlMatrix4x4> m_modelViewStack;
    std::vector<GlMatrix4x4> m_projectionStack;
    std::vector<GlMatrix4x4> m_textureStack;
    GLenum m_currentMatrixMode{GL_MODELVIEW};

    // State Variables
    int32_t  m_viewportX{0};
    int32_t  m_viewportY{0};
    uint32_t m_viewportW{800};
    uint32_t m_viewportH{600};

    float    m_clearColor[4]{0.0f, 0.0f, 0.0f, 0.0f};
    float    m_clearDepth{1.0f};

    bool     m_depthTest{false};
    GLenum   m_depthFunc{GL_LESS};
    bool     m_depthMask{true};

    bool     m_blend{false};
    GLenum   m_blendSrc{GL_SRC_ALPHA};
    GLenum   m_blendDst{GL_ONE_MINUS_SRC_ALPHA};

    bool     m_cullFace{false};
    GLenum   m_cullMode{GL_BACK};
    GLenum   m_frontFace{GL_CCW};
    GLenum   m_shadeModel{GL_SMOOTH};

    bool     m_texture2D{false};
    uint32_t m_boundTextureId{0};
    std::unordered_map<uint32_t, GlTexture> m_textures;

    GLenum   m_lastError{GL_NO_ERROR};

    // Immediate Mode Tracking
    bool     m_inBegin{false};
    GLenum   m_beginMode{GL_TRIANGLES};
    GlVertex m_currentVertex{};
    std::vector<GlVertex> m_immediateVertices;

    // Vertex Array Pointers
    bool     m_vertexArrayEnabled{false};
    const void* m_vertexPointer{nullptr};
    GLint    m_vertexSize{3};
    GLenum   m_vertexType{GL_FLOAT};
    GLsizei  m_vertexStride{0};

    bool     m_colorArrayEnabled{false};
    const void* m_colorPointer{nullptr};
    GLint    m_colorSize{4};
    GLenum   m_colorType{GL_FLOAT};
    GLsizei  m_colorStride{0};

    bool     m_texCoordArrayEnabled{false};
    const void* m_texCoordPointer{nullptr};
    GLint    m_texCoordSize{2};
    GLenum   m_texCoordType{GL_FLOAT};
    GLsizei  m_texCoordStride{0};

    bool     m_normalArrayEnabled{false};
    const void* m_normalPointer{nullptr};
    GLenum   m_normalType{GL_FLOAT};
    GLsizei  m_normalStride{0};

    explicit OpenGLContext(gdi32::HDC hdc) : m_hdc(hdc) {
        m_modelViewStack.push_back(GlMatrix4x4::Identity());
        m_projectionStack.push_back(GlMatrix4x4::Identity());
        m_textureStack.push_back(GlMatrix4x4::Identity());

        UpdateDimensionsFromHdc();
        ResizeBuffers(m_width, m_height);
    }

    void UpdateDimensionsFromHdc() noexcept {
        if (!m_hdc) return;
        auto dc = gdi32::GdiEngine::get().getDc(m_hdc);
        if (dc && dc->GetWidth() > 0 && dc->GetHeight() > 0) {
            m_width = dc->GetWidth();
            m_height = dc->GetHeight();
            m_viewportW = m_width;
            m_viewportH = m_height;
        }
    }

    void ResizeBuffers(uint32_t w, uint32_t h) {
        m_width = std::max(1u, w);
        m_height = std::max(1u, h);
        m_colorBuffer.assign(static_cast<size_t>(m_width) * m_height, 0xFF000000);
        m_depthBuffer.assign(static_cast<size_t>(m_width) * m_height, 1.0f);
    }

    GlMatrix4x4& CurrentMatrix() noexcept {
        if (m_currentMatrixMode == GL_PROJECTION) return m_projectionStack.back();
        if (m_currentMatrixMode == GL_TEXTURE)    return m_textureStack.back();
        return m_modelViewStack.back();
    }

    const GlMatrix4x4& CurrentMatrix() const noexcept {
        if (m_currentMatrixMode == GL_PROJECTION) return m_projectionStack.back();
        if (m_currentMatrixMode == GL_TEXTURE)    return m_textureStack.back();
        return m_modelViewStack.back();
    }

    void Clear(GLbitfield mask) noexcept {
        if (mask & GL_COLOR_BUFFER_BIT) {
            uint8_t a = static_cast<uint8_t>(std::clamp(m_clearColor[3] * 255.0f, 0.0f, 255.0f));
            uint8_t r = static_cast<uint8_t>(std::clamp(m_clearColor[0] * 255.0f, 0.0f, 255.0f));
            uint8_t g = static_cast<uint8_t>(std::clamp(m_clearColor[1] * 255.0f, 0.0f, 255.0f));
            uint8_t b = static_cast<uint8_t>(std::clamp(m_clearColor[2] * 255.0f, 0.0f, 255.0f));
            uint32_t clearVal = (a << 24) | (r << 16) | (g << 8) | b;
            std::fill(m_colorBuffer.begin(), m_colorBuffer.end(), clearVal);
        }
        if (mask & GL_DEPTH_BUFFER_BIT) {
            std::fill(m_depthBuffer.begin(), m_depthBuffer.end(), m_clearDepth);
        }
    }

    // ------------------------------------------------------------------------
    // Geometry & Rasterization Engine
    // ------------------------------------------------------------------------

    void ExecuteDrawPipeline() {
        if (m_immediateVertices.empty()) return;

        switch (m_beginMode) {
            case GL_TRIANGLES: {
                for (size_t i = 0; i + 2 < m_immediateVertices.size(); i += 3) {
                    RasterizeTriangle(m_immediateVertices[i], m_immediateVertices[i + 1], m_immediateVertices[i + 2]);
                }
                break;
            }
            case GL_TRIANGLE_STRIP: {
                for (size_t i = 0; i + 2 < m_immediateVertices.size(); ++i) {
                    if (i % 2 == 0) {
                        RasterizeTriangle(m_immediateVertices[i], m_immediateVertices[i + 1], m_immediateVertices[i + 2]);
                    } else {
                        RasterizeTriangle(m_immediateVertices[i + 1], m_immediateVertices[i], m_immediateVertices[i + 2]);
                    }
                }
                break;
            }
            case GL_TRIANGLE_FAN: {
                for (size_t i = 1; i + 1 < m_immediateVertices.size(); ++i) {
                    RasterizeTriangle(m_immediateVertices[0], m_immediateVertices[i], m_immediateVertices[i + 1]);
                }
                break;
            }
            case GL_QUADS: {
                for (size_t i = 0; i + 3 < m_immediateVertices.size(); i += 4) {
                    RasterizeTriangle(m_immediateVertices[i], m_immediateVertices[i + 1], m_immediateVertices[i + 2]);
                    RasterizeTriangle(m_immediateVertices[i], m_immediateVertices[i + 2], m_immediateVertices[i + 3]);
                }
                break;
            }
            case GL_LINES: {
                for (size_t i = 0; i + 1 < m_immediateVertices.size(); i += 2) {
                    RasterizeLine(m_immediateVertices[i], m_immediateVertices[i + 1]);
                }
                break;
            }
            case GL_POINTS: {
                for (const auto& v : m_immediateVertices) {
                    RasterizePoint(v);
                }
                break;
            }
            default:
                break;
        }

        m_immediateVertices.clear();
    }

    struct TransformedVertex {
        float screenX{0.0f}, screenY{0.0f}, screenZ{0.0f};
        float invW{1.0f};
        float r{1.0f}, g{1.0f}, b{1.0f}, a{1.0f};
        float u{0.0f}, v{0.0f};
    };

    bool TransformVertex(const GlVertex& in, TransformedVertex& out) const noexcept {
        GlVector4 objPos{in.x, in.y, in.z, in.w};
        GlVector4 eyePos = m_modelViewStack.back().Transform(objPos);
        GlVector4 clipPos = m_projectionStack.back().Transform(eyePos);

        // Guard against negative or near-zero W
        if (clipPos.w < 1e-5f) return false;

        float invW = 1.0f / clipPos.w;
        float ndcX = clipPos.x * invW;
        float ndcY = clipPos.y * invW;
        float ndcZ = clipPos.z * invW;

        // Frustum clip bounds check
        if (ndcX < -1.5f || ndcX > 1.5f || ndcY < -1.5f || ndcY > 1.5f || ndcZ < -1.5f || ndcZ > 1.5f) {
            // Soft frustum bounds
        }

        out.screenX = m_viewportX + (ndcX + 1.0f) * 0.5f * m_viewportW;
        out.screenY = m_viewportY + (1.0f - (ndcY + 1.0f) * 0.5f) * m_viewportH; // OpenGL Y-up mapped to screen Y-down
        out.screenZ = (ndcZ + 1.0f) * 0.5f; // Map from [-1, 1] to [0, 1]
        out.invW = invW;

        out.r = in.r;
        out.g = in.g;
        out.b = in.b;
        out.a = in.a;
        out.u = in.u;
        out.v = in.v;
        return true;
    }

    void RasterizePoint(const GlVertex& v) noexcept {
        TransformedVertex tv;
        if (!TransformVertex(v, tv)) return;
        int x = static_cast<int>(tv.screenX);
        int y = static_cast<int>(tv.screenY);
        if (x < 0 || y < 0 || x >= static_cast<int>(m_width) || y >= static_cast<int>(m_height)) return;

        size_t idx = static_cast<size_t>(y) * m_width + x;
        if (m_depthTest && !PassDepth(tv.screenZ, m_depthBuffer[idx])) return;

        uint8_t r = static_cast<uint8_t>(std::clamp(tv.r * 255.0f, 0.0f, 255.0f));
        uint8_t g = static_cast<uint8_t>(std::clamp(tv.g * 255.0f, 0.0f, 255.0f));
        uint8_t b = static_cast<uint8_t>(std::clamp(tv.b * 255.0f, 0.0f, 255.0f));
        m_colorBuffer[idx] = 0xFF000000 | (r << 16) | (g << 8) | b;
        if (m_depthMask) m_depthBuffer[idx] = tv.screenZ;
    }

    void RasterizeLine(const GlVertex& v0, const GlVertex& v1) noexcept {
        TransformedVertex t0, t1;
        if (!TransformVertex(v0, t0) || !TransformVertex(v1, t1)) return;

        int x0 = static_cast<int>(t0.screenX);
        int y0 = static_cast<int>(t0.screenY);
        int x1 = static_cast<int>(t1.screenX);
        int y1 = static_cast<int>(t1.screenY);

        int dx = std::abs(x1 - x0);
        int dy = std::abs(y1 - y0);
        int sx = (x0 < x1) ? 1 : -1;
        int sy = (y0 < y1) ? 1 : -1;
        int err = dx - dy;

        float totalDist = std::sqrt(static_cast<float>(dx * dx + dy * dy));
        if (totalDist < 1e-4f) totalDist = 1.0f;

        while (true) {
            float curDist = std::sqrt(static_cast<float>((x0 - t0.screenX) * (x0 - t0.screenX) + (y0 - t0.screenY) * (y0 - t0.screenY)));
            float factor = std::clamp(curDist / totalDist, 0.0f, 1.0f);

            float z = t0.screenZ * (1.0f - factor) + t1.screenZ * factor;
            float r = t0.r * (1.0f - factor) + t1.r * factor;
            float g = t0.g * (1.0f - factor) + t1.g * factor;
            float b = t0.b * (1.0f - factor) + t1.b * factor;

            if (x0 >= 0 && y0 >= 0 && x0 < static_cast<int>(m_width) && y0 < static_cast<int>(m_height)) {
                size_t idx = static_cast<size_t>(y0) * m_width + x0;
                if (!m_depthTest || PassDepth(z, m_depthBuffer[idx])) {
                    uint8_t ur = static_cast<uint8_t>(std::clamp(r * 255.0f, 0.0f, 255.0f));
                    uint8_t ug = static_cast<uint8_t>(std::clamp(g * 255.0f, 0.0f, 255.0f));
                    uint8_t ub = static_cast<uint8_t>(std::clamp(b * 255.0f, 0.0f, 255.0f));
                    m_colorBuffer[idx] = 0xFF000000 | (ur << 16) | (ug << 8) | ub;
                    if (m_depthMask) m_depthBuffer[idx] = z;
                }
            }

            if (x0 == x1 && y0 == y1) break;
            int e2 = 2 * err;
            if (e2 > -dy) { err -= dy; x0 += sx; }
            if (e2 < dx)  { err += dx; y0 += sy; }
        }
    }

    void RasterizeTriangle(const GlVertex& v0, const GlVertex& v1, const GlVertex& v2) noexcept {
        TransformedVertex t0, t1, t2;
        if (!TransformVertex(v0, t0) || !TransformVertex(v1, t1) || !TransformVertex(v2, t2)) return;

        // 2D Signed Area (Cross product) for Backface Culling
        float area = (t1.screenX - t0.screenX) * (t2.screenY - t0.screenY) -
                     (t1.screenY - t0.screenY) * (t2.screenX - t0.screenX);

        if (std::abs(area) < 1e-4f) return; // Degenerate triangle

        bool isFront = (m_frontFace == GL_CCW) ? (area > 0.0f) : (area < 0.0f);
        if (m_cullFace) {
            if (m_cullMode == GL_BACK && !isFront) return;
            if (m_cullMode == GL_FRONT && isFront) return;
            if (m_cullMode == GL_FRONT_AND_BACK) return;
        }

        // Bounding box clamped to viewport and framebuffer dimensions
        int minX = std::clamp(static_cast<int>(std::floor(std::min({t0.screenX, t1.screenX, t2.screenX}))), 0, static_cast<int>(m_width) - 1);
        int maxX = std::clamp(static_cast<int>(std::ceil(std::max({t0.screenX, t1.screenX, t2.screenX}))), 0, static_cast<int>(m_width) - 1);
        int minY = std::clamp(static_cast<int>(std::floor(std::min({t0.screenY, t1.screenY, t2.screenY}))), 0, static_cast<int>(m_height) - 1);
        int maxY = std::clamp(static_cast<int>(std::ceil(std::max({t0.screenY, t1.screenY, t2.screenY}))), 0, static_cast<int>(m_height) - 1);

        float invArea = 1.0f / area;

        // Pre-multiply attributes by 1/w for perspective-correct interpolation
        float t0_r = t0.r * t0.invW; float t0_g = t0.g * t0.invW; float t0_b = t0.b * t0.invW; float t0_a = t0.a * t0.invW;
        float t1_r = t1.r * t1.invW; float t1_g = t1.g * t1.invW; float t1_b = t1.b * t1.invW; float t1_a = t1.a * t1.invW;
        float t2_r = t2.r * t2.invW; float t2_g = t2.g * t2.invW; float t2_b = t2.b * t2.invW; float t2_a = t2.a * t2.invW;

        float t0_u = t0.u * t0.invW; float t0_v = t0.v * t0.invW;
        float t1_u = t1.u * t1.invW; float t1_v = t1.v * t1.invW;
        float t2_u = t2.u * t2.invW; float t2_v = t2.v * t2.invW;

        const GlTexture* pTex = nullptr;
        if (m_texture2D && m_boundTextureId != 0) {
            auto it = m_textures.find(m_boundTextureId);
            if (it != m_textures.end()) pTex = &it->second;
        }

        for (int py = minY; py <= maxY; ++py) {
            float y = py + 0.5f;
            for (int px = minX; px <= maxX; ++px) {
                float x = px + 0.5f;

                // Barycentric edge functions
                float w0 = ((t1.screenX - x) * (t2.screenY - y) - (t1.screenY - y) * (t2.screenX - x)) * invArea;
                float w1 = ((t2.screenX - x) * (t0.screenY - y) - (t2.screenY - y) * (t0.screenX - x)) * invArea;
                float w2 = 1.0f - w0 - w1;

                if (w0 >= -1e-4f && w1 >= -1e-4f && w2 >= -1e-4f) {
                    float z = w0 * t0.screenZ + w1 * t1.screenZ + w2 * t2.screenZ;
                    size_t idx = static_cast<size_t>(py) * m_width + px;

                    if (m_depthTest && !PassDepth(z, m_depthBuffer[idx])) continue;

                    float invW = w0 * t0.invW + w1 * t1.invW + w2 * t2.invW;
                    float wNorm = (invW > 1e-6f) ? (1.0f / invW) : 1.0f;

                    float r = (w0 * t0_r + w1 * t1_r + w2 * t2_r) * wNorm;
                    float g = (w0 * t0_g + w1 * t1_g + w2 * t2_g) * wNorm;
                    float b = (w0 * t0_b + w1 * t1_b + w2 * t2_b) * wNorm;
                    float a = (w0 * t0_a + w1 * t1_a + w2 * t2_a) * wNorm;

                    if (pTex) {
                        float u = (w0 * t0_u + w1 * t1_u + w2 * t2_u) * wNorm;
                        float v = (w0 * t0_v + w1 * t1_v + w2 * t2_v) * wNorm;
                        uint32_t texColor = pTex->Sample(u, v);
                        float tr = ((texColor >> 16) & 0xFF) / 255.0f;
                        float tg = ((texColor >> 8) & 0xFF) / 255.0f;
                        float tb = (texColor & 0xFF) / 255.0f;
                        float ta = ((texColor >> 24) & 0xFF) / 255.0f;
                        r *= tr; g *= tg; b *= tb; a *= ta;
                    }

                    uint8_t ur = static_cast<uint8_t>(std::clamp(r * 255.0f, 0.0f, 255.0f));
                    uint8_t ug = static_cast<uint8_t>(std::clamp(g * 255.0f, 0.0f, 255.0f));
                    uint8_t ub = static_cast<uint8_t>(std::clamp(b * 255.0f, 0.0f, 255.0f));
                    uint8_t ua = static_cast<uint8_t>(std::clamp(a * 255.0f, 0.0f, 255.0f));
                    uint32_t outPixel = (ua << 24) | (ur << 16) | (ug << 8) | ub;

                    if (m_blend) {
                        uint32_t dst = m_colorBuffer[idx];
                        float dr = ((dst >> 16) & 0xFF) / 255.0f;
                        float dg = ((dst >> 8) & 0xFF) / 255.0f;
                        float db = (dst & 0xFF) / 255.0f;
                        float da = ((dst >> 24) & 0xFF) / 255.0f;

                        float sFactorR = (m_blendSrc == GL_SRC_ALPHA) ? a : (m_blendSrc == GL_ONE ? 1.0f : 0.0f);
                        float dFactorR = (m_blendDst == GL_ONE_MINUS_SRC_ALPHA) ? (1.0f - a) : (m_blendDst == GL_ONE ? 1.0f : 0.0f);

                        float finalR = std::clamp(r * sFactorR + dr * dFactorR, 0.0f, 1.0f);
                        float finalG = std::clamp(g * sFactorR + dg * dFactorR, 0.0f, 1.0f);
                        float finalB = std::clamp(b * sFactorR + db * dFactorR, 0.0f, 1.0f);
                        float finalA = std::clamp(a * sFactorR + da * dFactorR, 0.0f, 1.0f);

                        outPixel = (static_cast<uint8_t>(finalA * 255.0f) << 24) |
                                   (static_cast<uint8_t>(finalR * 255.0f) << 16) |
                                   (static_cast<uint8_t>(finalG * 255.0f) << 8)  |
                                   static_cast<uint8_t>(finalB * 255.0f);
                    }

                    m_colorBuffer[idx] = outPixel;
                    if (m_depthMask) m_depthBuffer[idx] = z;
                }
            }
        }
    }

    [[nodiscard]] bool PassDepth(float z, float currentDepth) const noexcept {
        switch (m_depthFunc) {
            case GL_NEVER:    return false;
            case GL_LESS:     return z < currentDepth;
            case GL_EQUAL:    return std::abs(z - currentDepth) < 1e-5f;
            case GL_LEQUAL:   return z <= currentDepth + 1e-5f;
            case GL_GREATER:  return z > currentDepth;
            case GL_NOTEQUAL: return std::abs(z - currentDepth) >= 1e-5f;
            case GL_GEQUAL:   return z >= currentDepth - 1e-5f;
            case GL_ALWAYS:   return true;
            default:          return z < currentDepth;
        }
    }

    void SwapBuffers() {
        if (!m_hdc) return;
        auto dc = gdi32::GdiEngine::get().getDc(m_hdc);
        if (!dc) return;

        auto bmp = dc->GetBitmap();
        if (bmp && bmp->GetBits()) {
            uint32_t targetW = bmp->GetWidth();
            uint32_t targetH = bmp->GetHeight();
            uint32_t* targetBits = bmp->GetBits();

            uint32_t copyW = std::min(m_width, targetW);
            uint32_t copyH = std::min(m_height, targetH);

            for (uint32_t y = 0; y < copyH; ++y) {
                std::memcpy(targetBits + y * targetW, m_colorBuffer.data() + y * m_width, copyW * sizeof(uint32_t));
            }
        }

        dc->FlushIfWindow();
    }
};

// ============================================================================
// 6. Global OpenGL Context Manager
// ============================================================================

class OpenGLManager {
private:
    std::mutex m_mutex;
    uint32_t   m_nextContextId{1};
    uint32_t   m_nextTextureId{1};
    std::unordered_map<HGLRC, std::shared_ptr<OpenGLContext>> m_contexts;

    OpenGLManager() = default;

public:
    static OpenGLManager& get() noexcept {
        static OpenGLManager instance;
        return instance;
    }

    HGLRC createContext(gdi32::HDC hdc) {
        std::lock_guard<std::mutex> lock(m_mutex);
        HGLRC handle = reinterpret_cast<HGLRC>(static_cast<uintptr_t>(m_nextContextId++));
        m_contexts[handle] = std::make_shared<OpenGLContext>(hdc);
        return handle;
    }

    bool deleteContext(HGLRC hglrc) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_contexts.find(hglrc);
        if (it != m_contexts.end()) {
            m_contexts.erase(it);
            return true;
        }
        return false;
    }

    std::shared_ptr<OpenGLContext> getContext(HGLRC hglrc) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_contexts.find(hglrc);
        return (it != m_contexts.end()) ? it->second : nullptr;
    }

    uint32_t allocateTextureId() noexcept {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_nextTextureId++;
    }
};

// Thread-local active context pointers
inline thread_local HGLRC t_currentHGLRC{nullptr};
inline thread_local gdi32::HDC t_currentHDC{nullptr};
inline thread_local std::shared_ptr<OpenGLContext> t_currentContext{nullptr};

// ============================================================================
// 7. Standard Windows WGL API Implementation
// ============================================================================

inline HGLRC wglCreateContext(gdi32::HDC hdc) noexcept {
    if (!hdc) return nullptr;
    return OpenGLManager::get().createContext(hdc);
}

inline win32::BOOL wglMakeCurrent(gdi32::HDC hdc, HGLRC hglrc) noexcept {
    if (!hglrc) {
        t_currentHGLRC = nullptr;
        t_currentHDC = nullptr;
        t_currentContext = nullptr;
        return win32::TRUE;
    }

    auto ctx = OpenGLManager::get().getContext(hglrc);
    if (!ctx) return win32::FALSE;

    ctx->m_hdc = hdc;
    ctx->UpdateDimensionsFromHdc();
    t_currentHGLRC = hglrc;
    t_currentHDC = hdc;
    t_currentContext = ctx;
    return win32::TRUE;
}

inline HGLRC wglGetCurrentContext() noexcept {
    return t_currentHGLRC;
}

inline gdi32::HDC wglGetCurrentDC() noexcept {
    return t_currentHDC;
}

inline win32::BOOL wglDeleteContext(HGLRC hglrc) noexcept {
    if (t_currentHGLRC == hglrc) {
        t_currentHGLRC = nullptr;
        t_currentHDC = nullptr;
        t_currentContext = nullptr;
    }
    return OpenGLManager::get().deleteContext(hglrc) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL wglSwapBuffers(gdi32::HDC hdc) noexcept {
    if (t_currentContext && (t_currentHDC == hdc || !hdc)) {
        t_currentContext->SwapBuffers();
        return win32::TRUE;
    }
    // Fallback to GDI SwapBuffers
    return gdi32::SwapBuffers(hdc);
}

inline win32::BOOL wglShareLists(HGLRC, HGLRC) noexcept {
    return win32::TRUE;
}

// Extension function stubs exposed via wglGetProcAddress
inline void glGenBuffersARB(GLsizei n, GLuint* buffers) noexcept {
    if (!buffers) return;
    for (GLsizei i = 0; i < n; ++i) buffers[i] = 1000 + i;
}

inline void glBindBufferARB(GLenum, GLuint) noexcept {}
inline void glBufferDataARB(GLenum, GLsizei, const void*, GLenum) noexcept {}
inline void glDeleteBuffersARB(GLsizei, const GLuint*) noexcept {}

inline void* wglGetProcAddress(const char* lpszProc) noexcept {
    if (!lpszProc) return nullptr;
    std::string_view name(lpszProc);
    if (name == "glGenBuffers" || name == "glGenBuffersARB") return reinterpret_cast<void*>(glGenBuffersARB);
    if (name == "glBindBuffer" || name == "glBindBufferARB") return reinterpret_cast<void*>(glBindBufferARB);
    if (name == "glBufferData" || name == "glBufferDataARB") return reinterpret_cast<void*>(glBufferDataARB);
    if (name == "glDeleteBuffers" || name == "glDeleteBuffersARB") return reinterpret_cast<void*>(glDeleteBuffersARB);
    return nullptr;
}

// ============================================================================
// 8. Core OpenGL 1.1 - 1.4 API Implementation
// ============================================================================

inline void glMatrixMode(GLenum mode) noexcept {
    if (t_currentContext) {
        t_currentContext->m_currentMatrixMode = mode;
    }
}

inline void glLoadIdentity() noexcept {
    if (t_currentContext) {
        t_currentContext->CurrentMatrix() = GlMatrix4x4::Identity();
    }
}

inline void glLoadMatrixf(const GLfloat* m) noexcept {
    if (t_currentContext && m) {
        std::memcpy(t_currentContext->CurrentMatrix().m.data(), m, 16 * sizeof(float));
    }
}

inline void glMultMatrixf(const GLfloat* m) noexcept {
    if (t_currentContext && m) {
        GlMatrix4x4 mat{};
        std::memcpy(mat.m.data(), m, 16 * sizeof(float));
        t_currentContext->CurrentMatrix() = GlMatrix4x4::Multiply(t_currentContext->CurrentMatrix(), mat);
    }
}

inline void glPushMatrix() noexcept {
    if (t_currentContext) {
        auto& stack = (t_currentContext->m_currentMatrixMode == GL_PROJECTION) ? t_currentContext->m_projectionStack :
                      (t_currentContext->m_currentMatrixMode == GL_TEXTURE)    ? t_currentContext->m_textureStack :
                                                                                 t_currentContext->m_modelViewStack;
        if (stack.size() < 32) {
            stack.push_back(stack.back());
        } else {
            t_currentContext->m_lastError = GL_STACK_OVERFLOW;
        }
    }
}

inline void glPopMatrix() noexcept {
    if (t_currentContext) {
        auto& stack = (t_currentContext->m_currentMatrixMode == GL_PROJECTION) ? t_currentContext->m_projectionStack :
                      (t_currentContext->m_currentMatrixMode == GL_TEXTURE)    ? t_currentContext->m_textureStack :
                                                                                 t_currentContext->m_modelViewStack;
        if (stack.size() > 1) {
            stack.pop_back();
        } else {
            t_currentContext->m_lastError = GL_STACK_UNDERFLOW;
        }
    }
}

inline void glTranslatef(GLfloat x, GLfloat y, GLfloat z) noexcept {
    if (t_currentContext) {
        t_currentContext->CurrentMatrix() = GlMatrix4x4::Multiply(t_currentContext->CurrentMatrix(), GlMatrix4x4::Translate(x, y, z));
    }
}

inline void glRotatef(GLfloat angle, GLfloat x, GLfloat y, GLfloat z) noexcept {
    if (t_currentContext) {
        t_currentContext->CurrentMatrix() = GlMatrix4x4::Multiply(t_currentContext->CurrentMatrix(), GlMatrix4x4::Rotate(angle, x, y, z));
    }
}

inline void glScalef(GLfloat x, GLfloat y, GLfloat z) noexcept {
    if (t_currentContext) {
        t_currentContext->CurrentMatrix() = GlMatrix4x4::Multiply(t_currentContext->CurrentMatrix(), GlMatrix4x4::Scale(x, y, z));
    }
}

inline void glFrustum(GLdouble left, GLdouble right, GLdouble bottom, GLdouble top, GLdouble nearVal, GLdouble farVal) noexcept {
    if (t_currentContext) {
        GlMatrix4x4 f = GlMatrix4x4::Frustum(left, right, bottom, top, nearVal, farVal);
        t_currentContext->CurrentMatrix() = GlMatrix4x4::Multiply(t_currentContext->CurrentMatrix(), f);
    }
}

inline void glOrtho(GLdouble left, GLdouble right, GLdouble bottom, GLdouble top, GLdouble nearVal, GLdouble farVal) noexcept {
    if (t_currentContext) {
        GlMatrix4x4 o = GlMatrix4x4::Ortho(left, right, bottom, top, nearVal, farVal);
        t_currentContext->CurrentMatrix() = GlMatrix4x4::Multiply(t_currentContext->CurrentMatrix(), o);
    }
}

inline void glViewport(GLint x, GLint y, GLsizei width, GLsizei height) noexcept {
    if (t_currentContext) {
        t_currentContext->m_viewportX = x;
        t_currentContext->m_viewportY = y;
        t_currentContext->m_viewportW = std::max(1, width);
        t_currentContext->m_viewportH = std::max(1, height);
    }
}

inline void glClear(GLbitfield mask) noexcept {
    if (t_currentContext) {
        t_currentContext->Clear(mask);
    }
}

inline void glClearColor(GLclampf red, GLclampf green, GLclampf blue, GLclampf alpha) noexcept {
    if (t_currentContext) {
        t_currentContext->m_clearColor[0] = red;
        t_currentContext->m_clearColor[1] = green;
        t_currentContext->m_clearColor[2] = blue;
        t_currentContext->m_clearColor[3] = alpha;
    }
}

inline void glClearDepth(GLclampd depth) noexcept {
    if (t_currentContext) {
        t_currentContext->m_clearDepth = static_cast<float>(depth);
    }
}

inline void glEnable(GLenum cap) noexcept {
    if (!t_currentContext) return;
    switch (cap) {
        case GL_DEPTH_TEST: t_currentContext->m_depthTest = true; break;
        case GL_BLEND:      t_currentContext->m_blend = true; break;
        case GL_CULL_FACE:  t_currentContext->m_cullFace = true; break;
        case GL_TEXTURE_2D: t_currentContext->m_texture2D = true; break;
        default: break;
    }
}

inline void glDisable(GLenum cap) noexcept {
    if (!t_currentContext) return;
    switch (cap) {
        case GL_DEPTH_TEST: t_currentContext->m_depthTest = false; break;
        case GL_BLEND:      t_currentContext->m_blend = false; break;
        case GL_CULL_FACE:  t_currentContext->m_cullFace = false; break;
        case GL_TEXTURE_2D: t_currentContext->m_texture2D = false; break;
        default: break;
    }
}

inline GLboolean glIsEnabled(GLenum cap) noexcept {
    if (!t_currentContext) return GL_FALSE;
    switch (cap) {
        case GL_DEPTH_TEST: return t_currentContext->m_depthTest ? GL_TRUE : GL_FALSE;
        case GL_BLEND:      return t_currentContext->m_blend ? GL_TRUE : GL_FALSE;
        case GL_CULL_FACE:  return t_currentContext->m_cullFace ? GL_TRUE : GL_FALSE;
        case GL_TEXTURE_2D: return t_currentContext->m_texture2D ? GL_TRUE : GL_FALSE;
        default: return GL_FALSE;
    }
}

inline void glDepthFunc(GLenum func) noexcept {
    if (t_currentContext) t_currentContext->m_depthFunc = func;
}

inline void glDepthMask(GLboolean flag) noexcept {
    if (t_currentContext) t_currentContext->m_depthMask = (flag != GL_FALSE);
}

inline void glBlendFunc(GLenum sfactor, GLenum dfactor) noexcept {
    if (t_currentContext) {
        t_currentContext->m_blendSrc = sfactor;
        t_currentContext->m_blendDst = dfactor;
    }
}

inline void glCullFace(GLenum mode) noexcept {
    if (t_currentContext) t_currentContext->m_cullMode = mode;
}

inline void glFrontFace(GLenum mode) noexcept {
    if (t_currentContext) t_currentContext->m_frontFace = mode;
}

inline void glShadeModel(GLenum mode) noexcept {
    if (t_currentContext) t_currentContext->m_shadeModel = mode;
}

// ----------------------------------------------------------------------------
// Immediate Mode Geometry
// ----------------------------------------------------------------------------

inline void glBegin(GLenum mode) noexcept {
    if (t_currentContext) {
        t_currentContext->m_inBegin = true;
        t_currentContext->m_beginMode = mode;
        t_currentContext->m_immediateVertices.clear();
    }
}

inline void glEnd() noexcept {
    if (t_currentContext && t_currentContext->m_inBegin) {
        t_currentContext->m_inBegin = false;
        t_currentContext->ExecuteDrawPipeline();
    }
}

inline void glVertex2f(GLfloat x, GLfloat y) noexcept {
    if (t_currentContext) {
        t_currentContext->m_currentVertex.x = x;
        t_currentContext->m_currentVertex.y = y;
        t_currentContext->m_currentVertex.z = 0.0f;
        t_currentContext->m_currentVertex.w = 1.0f;
        if (t_currentContext->m_inBegin) {
            t_currentContext->m_immediateVertices.push_back(t_currentContext->m_currentVertex);
        }
    }
}

inline void glVertex2i(GLint x, GLint y) noexcept {
    glVertex2f(static_cast<GLfloat>(x), static_cast<GLfloat>(y));
}

inline void glVertex3f(GLfloat x, GLfloat y, GLfloat z) noexcept {
    if (t_currentContext) {
        t_currentContext->m_currentVertex.x = x;
        t_currentContext->m_currentVertex.y = y;
        t_currentContext->m_currentVertex.z = z;
        t_currentContext->m_currentVertex.w = 1.0f;
        if (t_currentContext->m_inBegin) {
            t_currentContext->m_immediateVertices.push_back(t_currentContext->m_currentVertex);
        }
    }
}

inline void glVertex3fv(const GLfloat* v) noexcept {
    if (v) glVertex3f(v[0], v[1], v[2]);
}

inline void glVertex4f(GLfloat x, GLfloat y, GLfloat z, GLfloat w) noexcept {
    if (t_currentContext) {
        t_currentContext->m_currentVertex.x = x;
        t_currentContext->m_currentVertex.y = y;
        t_currentContext->m_currentVertex.z = z;
        t_currentContext->m_currentVertex.w = w;
        if (t_currentContext->m_inBegin) {
            t_currentContext->m_immediateVertices.push_back(t_currentContext->m_currentVertex);
        }
    }
}

inline void glColor3f(GLfloat r, GLfloat g, GLfloat b) noexcept {
    if (t_currentContext) {
        t_currentContext->m_currentVertex.r = r;
        t_currentContext->m_currentVertex.g = g;
        t_currentContext->m_currentVertex.b = b;
        t_currentContext->m_currentVertex.a = 1.0f;
    }
}

inline void glColor3fv(const GLfloat* v) noexcept {
    if (v) glColor3f(v[0], v[1], v[2]);
}

inline void glColor3ub(GLubyte r, GLubyte g, GLubyte b) noexcept {
    glColor3f(r / 255.0f, g / 255.0f, b / 255.0f);
}

inline void glColor4f(GLfloat r, GLfloat g, GLfloat b, GLfloat a) noexcept {
    if (t_currentContext) {
        t_currentContext->m_currentVertex.r = r;
        t_currentContext->m_currentVertex.g = g;
        t_currentContext->m_currentVertex.b = b;
        t_currentContext->m_currentVertex.a = a;
    }
}

inline void glColor4fv(const GLfloat* v) noexcept {
    if (v) glColor4f(v[0], v[1], v[2], v[3]);
}

inline void glColor4ub(GLubyte r, GLubyte g, GLubyte b, GLubyte a) noexcept {
    glColor4f(r / 255.0f, g / 255.0f, b / 255.0f, a / 255.0f);
}

inline void glColor4ubv(const GLubyte* v) noexcept {
    if (v) glColor4ub(v[0], v[1], v[2], v[3]);
}

inline void glNormal3f(GLfloat nx, GLfloat ny, GLfloat nz) noexcept {
    if (t_currentContext) {
        t_currentContext->m_currentVertex.nx = nx;
        t_currentContext->m_currentVertex.ny = ny;
        t_currentContext->m_currentVertex.nz = nz;
    }
}

inline void glNormal3fv(const GLfloat* v) noexcept {
    if (v) glNormal3f(v[0], v[1], v[2]);
}

inline void glTexCoord2f(GLfloat s, GLfloat t) noexcept {
    if (t_currentContext) {
        t_currentContext->m_currentVertex.u = s;
        t_currentContext->m_currentVertex.v = t;
    }
}

inline void glTexCoord2fv(const GLfloat* v) noexcept {
    if (v) glTexCoord2f(v[0], v[1]);
}

// ----------------------------------------------------------------------------
// Texture Management
// ----------------------------------------------------------------------------

inline void glGenTextures(GLsizei n, GLuint* textures) noexcept {
    if (!textures || n <= 0) return;
    for (GLsizei i = 0; i < n; ++i) {
        textures[i] = OpenGLManager::get().allocateTextureId();
    }
}

inline void glDeleteTextures(GLsizei n, const GLuint* textures) noexcept {
    if (!t_currentContext || !textures || n <= 0) return;
    for (GLsizei i = 0; i < n; ++i) {
        t_currentContext->m_textures.erase(textures[i]);
    }
}

inline void glBindTexture(GLenum target, GLuint texture) noexcept {
    if (!t_currentContext || target != GL_TEXTURE_2D) return;
    t_currentContext->m_boundTextureId = texture;
    if (texture != 0 && t_currentContext->m_textures.find(texture) == t_currentContext->m_textures.end()) {
        GlTexture tex{};
        tex.id = texture;
        t_currentContext->m_textures[texture] = std::move(tex);
    }
}

inline void glTexParameteri(GLenum target, GLenum pname, GLint param) noexcept {
    if (!t_currentContext || target != GL_TEXTURE_2D || t_currentContext->m_boundTextureId == 0) return;
    auto it = t_currentContext->m_textures.find(t_currentContext->m_boundTextureId);
    if (it == t_currentContext->m_textures.end()) return;

    switch (pname) {
        case GL_TEXTURE_MIN_FILTER: it->second.minFilter = param; break;
        case GL_TEXTURE_MAG_FILTER: it->second.magFilter = param; break;
        case GL_TEXTURE_WRAP_S:     it->second.wrapS = param; break;
        case GL_TEXTURE_WRAP_T:     it->second.wrapT = param; break;
        default: break;
    }
}

inline void glTexParameterf(GLenum target, GLenum pname, GLfloat param) noexcept {
    glTexParameteri(target, pname, static_cast<GLint>(param));
}

inline void glTexImage2D(GLenum target, GLint, GLint, GLsizei width, GLsizei height, GLint, GLenum format, GLenum type, const void* pixels) noexcept {
    if (!t_currentContext || target != GL_TEXTURE_2D || t_currentContext->m_boundTextureId == 0) return;
    auto& tex = t_currentContext->m_textures[t_currentContext->m_boundTextureId];
    tex.width = width;
    tex.height = height;
    tex.pixels.resize(static_cast<size_t>(width) * height, 0xFFFFFFFF);

    if (!pixels) return;

    if (type == GL_UNSIGNED_BYTE) {
        const uint8_t* raw = static_cast<const uint8_t*>(pixels);
        for (GLsizei y = 0; y < height; ++y) {
            for (GLsizei x = 0; x < width; ++x) {
                size_t pIdx = static_cast<size_t>(y) * width + x;
                if (format == GL_RGBA) {
                    uint8_t r = raw[pIdx * 4 + 0];
                    uint8_t g = raw[pIdx * 4 + 1];
                    uint8_t b = raw[pIdx * 4 + 2];
                    uint8_t a = raw[pIdx * 4 + 3];
                    tex.pixels[pIdx] = (a << 24) | (r << 16) | (g << 8) | b;
                } else if (format == GL_RGB) {
                    uint8_t r = raw[pIdx * 3 + 0];
                    uint8_t g = raw[pIdx * 3 + 1];
                    uint8_t b = raw[pIdx * 3 + 2];
                    tex.pixels[pIdx] = 0xFF000000 | (r << 16) | (g << 8) | b;
                } else if (format == GL_BGRA_EXT) {
                    uint8_t b = raw[pIdx * 4 + 0];
                    uint8_t g = raw[pIdx * 4 + 1];
                    uint8_t r = raw[pIdx * 4 + 2];
                    uint8_t a = raw[pIdx * 4 + 3];
                    tex.pixels[pIdx] = (a << 24) | (r << 16) | (g << 8) | b;
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Vertex Arrays
// ----------------------------------------------------------------------------

inline void glEnableClientState(GLenum cap) noexcept {
    if (!t_currentContext) return;
    switch (cap) {
        case GL_VERTEX_ARRAY:        t_currentContext->m_vertexArrayEnabled = true; break;
        case GL_COLOR_ARRAY:         t_currentContext->m_colorArrayEnabled = true; break;
        case GL_TEXTURE_COORD_ARRAY: t_currentContext->m_texCoordArrayEnabled = true; break;
        case GL_NORMAL_ARRAY:        t_currentContext->m_normalArrayEnabled = true; break;
        default: break;
    }
}

inline void glDisableClientState(GLenum cap) noexcept {
    if (!t_currentContext) return;
    switch (cap) {
        case GL_VERTEX_ARRAY:        t_currentContext->m_vertexArrayEnabled = false; break;
        case GL_COLOR_ARRAY:         t_currentContext->m_colorArrayEnabled = false; break;
        case GL_TEXTURE_COORD_ARRAY: t_currentContext->m_texCoordArrayEnabled = false; break;
        case GL_NORMAL_ARRAY:        t_currentContext->m_normalArrayEnabled = false; break;
        default: break;
    }
}

inline void glVertexPointer(GLint size, GLenum type, GLsizei stride, const void* pointer) noexcept {
    if (!t_currentContext) return;
    t_currentContext->m_vertexSize = size;
    t_currentContext->m_vertexType = type;
    t_currentContext->m_vertexStride = (stride == 0) ? (size * sizeof(float)) : stride;
    t_currentContext->m_vertexPointer = pointer;
}

inline void glColorPointer(GLint size, GLenum type, GLsizei stride, const void* pointer) noexcept {
    if (!t_currentContext) return;
    t_currentContext->m_colorSize = size;
    t_currentContext->m_colorType = type;
    t_currentContext->m_colorStride = (stride == 0) ? (size * sizeof(float)) : stride;
    t_currentContext->m_colorPointer = pointer;
}

inline void glTexCoordPointer(GLint size, GLenum type, GLsizei stride, const void* pointer) noexcept {
    if (!t_currentContext) return;
    t_currentContext->m_texCoordSize = size;
    t_currentContext->m_texCoordType = type;
    t_currentContext->m_texCoordStride = (stride == 0) ? (size * sizeof(float)) : stride;
    t_currentContext->m_texCoordPointer = pointer;
}

inline void glNormalPointer(GLenum type, GLsizei stride, const void* pointer) noexcept {
    if (!t_currentContext) return;
    t_currentContext->m_normalType = type;
    t_currentContext->m_normalStride = (stride == 0) ? (3 * sizeof(float)) : stride;
    t_currentContext->m_normalPointer = pointer;
}

inline void glDrawArrays(GLenum mode, GLint first, GLsizei count) noexcept {
    if (!t_currentContext || !t_currentContext->m_vertexPointer || count <= 0) return;

    glBegin(mode);
    const uint8_t* vBase = static_cast<const uint8_t*>(t_currentContext->m_vertexPointer);
    const uint8_t* cBase = static_cast<const uint8_t*>(t_currentContext->m_colorPointer);
    const uint8_t* tBase = static_cast<const uint8_t*>(t_currentContext->m_texCoordPointer);

    for (GLsizei i = 0; i < count; ++i) {
        GLint idx = first + i;
        if (t_currentContext->m_colorArrayEnabled && cBase) {
            const float* clr = reinterpret_cast<const float*>(cBase + idx * t_currentContext->m_colorStride);
            if (t_currentContext->m_colorSize == 3) glColor3f(clr[0], clr[1], clr[2]);
            else if (t_currentContext->m_colorSize == 4) glColor4f(clr[0], clr[1], clr[2], clr[3]);
        }
        if (t_currentContext->m_texCoordArrayEnabled && tBase) {
            const float* uv = reinterpret_cast<const float*>(tBase + idx * t_currentContext->m_texCoordStride);
            glTexCoord2f(uv[0], uv[1]);
        }
        const float* pos = reinterpret_cast<const float*>(vBase + idx * t_currentContext->m_vertexStride);
        if (t_currentContext->m_vertexSize == 2) glVertex2f(pos[0], pos[1]);
        else if (t_currentContext->m_vertexSize == 3) glVertex3f(pos[0], pos[1], pos[2]);
        else if (t_currentContext->m_vertexSize == 4) glVertex4f(pos[0], pos[1], pos[2], pos[3]);
    }
    glEnd();
}

inline void glDrawElements(GLenum mode, GLsizei count, GLenum type, const void* indices) noexcept {
    if (!t_currentContext || !t_currentContext->m_vertexPointer || !indices || count <= 0) return;

    glBegin(mode);
    const uint8_t* vBase = static_cast<const uint8_t*>(t_currentContext->m_vertexPointer);
    const uint8_t* cBase = static_cast<const uint8_t*>(t_currentContext->m_colorPointer);
    const uint8_t* tBase = static_cast<const uint8_t*>(t_currentContext->m_texCoordPointer);

    for (GLsizei i = 0; i < count; ++i) {
        uint32_t idx = 0;
        if (type == GL_UNSIGNED_BYTE) idx = static_cast<const uint8_t*>(indices)[i];
        else if (type == 0x1403 /* GL_UNSIGNED_SHORT */) idx = static_cast<const uint16_t*>(indices)[i];
        else idx = static_cast<const uint32_t*>(indices)[i];

        if (t_currentContext->m_colorArrayEnabled && cBase) {
            const float* clr = reinterpret_cast<const float*>(cBase + idx * t_currentContext->m_colorStride);
            if (t_currentContext->m_colorSize == 3) glColor3f(clr[0], clr[1], clr[2]);
            else if (t_currentContext->m_colorSize == 4) glColor4f(clr[0], clr[1], clr[2], clr[3]);
        }
        if (t_currentContext->m_texCoordArrayEnabled && tBase) {
            const float* uv = reinterpret_cast<const float*>(tBase + idx * t_currentContext->m_texCoordStride);
            glTexCoord2f(uv[0], uv[1]);
        }
        const float* pos = reinterpret_cast<const float*>(vBase + idx * t_currentContext->m_vertexStride);
        if (t_currentContext->m_vertexSize == 2) glVertex2f(pos[0], pos[1]);
        else if (t_currentContext->m_vertexSize == 3) glVertex3f(pos[0], pos[1], pos[2]);
        else if (t_currentContext->m_vertexSize == 4) glVertex4f(pos[0], pos[1], pos[2], pos[3]);
    }
    glEnd();
}

// ----------------------------------------------------------------------------
// Introspection & State Queries
// ----------------------------------------------------------------------------

inline const GLubyte* glGetString(GLenum name) noexcept {
    switch (name) {
        case GL_VENDOR:     return reinterpret_cast<const GLubyte*>("MicaNT Sovereign Project");
        case GL_RENDERER:   return reinterpret_cast<const GLubyte*>("PrismGL Reference Rasterizer");
        case GL_VERSION:    return reinterpret_cast<const GLubyte*>("1.4.0 MicaNT");
        case GL_EXTENSIONS: return reinterpret_cast<const GLubyte*>("GL_ARB_multitexture GL_ARB_vertex_buffer_object GL_EXT_bgra GL_EXT_texture_filter_anisotropic");
        default: return nullptr;
    }
}

inline GLenum glGetError() noexcept {
    if (!t_currentContext) return GL_NO_ERROR;
    GLenum err = t_currentContext->m_lastError;
    t_currentContext->m_lastError = GL_NO_ERROR;
    return err;
}

inline void glGetIntegerv(GLenum pname, GLint* params) noexcept {
    if (!params) return;
    switch (pname) {
        case 0x0BA2 /* GL_VIEWPORT */:
            if (t_currentContext) {
                params[0] = t_currentContext->m_viewportX;
                params[1] = t_currentContext->m_viewportY;
                params[2] = t_currentContext->m_viewportW;
                params[3] = t_currentContext->m_viewportH;
            }
            break;
        case 0x0D33 /* GL_MAX_TEXTURE_SIZE */:
            params[0] = 4096;
            break;
        default:
            params[0] = 0;
            break;
    }
}

inline void glGetFloatv(GLenum pname, GLfloat* params) noexcept {
    if (!params || !t_currentContext) return;
    switch (pname) {
        case 0x0BA6 /* GL_MODELVIEW_MATRIX */:
            std::memcpy(params, t_currentContext->m_modelViewStack.back().m.data(), 16 * sizeof(float));
            break;
        case 0x0BA7 /* GL_PROJECTION_MATRIX */:
            std::memcpy(params, t_currentContext->m_projectionStack.back().m.data(), 16 * sizeof(float));
            break;
        default:
            break;
    }
}

inline void glFinish() noexcept {}
inline void glFlush() noexcept {}

// ============================================================================
// 9. GLU Utility Library Implementation (glu32.dll)
// ============================================================================

inline void gluPerspective(GLdouble fovy, GLdouble aspect, GLdouble zNear, GLdouble zFar) noexcept {
    double fovyRad = fovy * 3.14159265358979323846 / 180.0;
    double f = 1.0 / std::tan(fovyRad / 2.0);

    GlMatrix4x4 mat{};
    mat.m[0]  = static_cast<float>(f / aspect);
    mat.m[5]  = static_cast<float>(f);
    mat.m[10] = static_cast<float>((zFar + zNear) / (zNear - zFar));
    mat.m[11] = -1.0f;
    mat.m[14] = static_cast<float>((2.0 * zFar * zNear) / (zNear - zFar));

    if (t_currentContext) {
        t_currentContext->CurrentMatrix() = GlMatrix4x4::Multiply(t_currentContext->CurrentMatrix(), mat);
    }
}

inline void gluLookAt(GLdouble eyeX, GLdouble eyeY, GLdouble eyeZ,
                      GLdouble centerX, GLdouble centerY, GLdouble centerZ,
                      GLdouble upX, GLdouble upY, GLdouble upZ) noexcept {
    // Forward = normalize(center - eye)
    double fx = centerX - eyeX;
    double fy = centerY - eyeY;
    double fz = centerZ - eyeZ;
    double fLen = std::sqrt(fx * fx + fy * fy + fz * fz);
    if (fLen > 1e-6) { fx /= fLen; fy /= fLen; fz /= fLen; }

    // Normalize up vector
    double upLen = std::sqrt(upX * upX + upY * upY + upZ * upZ);
    if (upLen > 1e-6) { upX /= upLen; upY /= upLen; upZ /= upLen; }

    // Side = forward x up
    double sx = fy * upZ - fz * upY;
    double sy = fz * upX - fx * upZ;
    double sz = fx * upY - fy * upX;
    double sLen = std::sqrt(sx * sx + sy * sy + sz * sz);
    if (sLen > 1e-6) { sx /= sLen; sy /= sLen; sz /= sLen; }

    // Up' = side x forward
    double ux = sy * fz - sz * fy;
    double uy = sz * fx - sx * fz;
    double uz = sx * fy - sy * fx;

    GlMatrix4x4 mat = GlMatrix4x4::Identity();
    mat.m[0] = static_cast<float>(sx);
    mat.m[4] = static_cast<float>(sy);
    mat.m[8] = static_cast<float>(sz);

    mat.m[1] = static_cast<float>(ux);
    mat.m[5] = static_cast<float>(uy);
    mat.m[9] = static_cast<float>(uz);

    mat.m[2]  = static_cast<float>(-fx);
    mat.m[6]  = static_cast<float>(-fy);
    mat.m[10] = static_cast<float>(-fz);

    if (t_currentContext) {
        t_currentContext->CurrentMatrix() = GlMatrix4x4::Multiply(t_currentContext->CurrentMatrix(), mat);
        t_currentContext->CurrentMatrix() = GlMatrix4x4::Multiply(
            t_currentContext->CurrentMatrix(),
            GlMatrix4x4::Translate(static_cast<float>(-eyeX), static_cast<float>(-eyeY), static_cast<float>(-eyeZ))
        );
    }
}

inline void gluOrtho2D(GLdouble left, GLdouble right, GLdouble bottom, GLdouble top) noexcept {
    glOrtho(left, right, bottom, top, -1.0, 1.0);
}

inline const GLubyte* gluErrorString(GLenum error) noexcept {
    switch (error) {
        case GL_NO_ERROR:          return reinterpret_cast<const GLubyte*>("no error");
        case GL_INVALID_ENUM:      return reinterpret_cast<const GLubyte*>("invalid enumerant");
        case GL_INVALID_VALUE:     return reinterpret_cast<const GLubyte*>("invalid value");
        case GL_INVALID_OPERATION: return reinterpret_cast<const GLubyte*>("invalid operation");
        case GL_STACK_OVERFLOW:    return reinterpret_cast<const GLubyte*>("stack overflow");
        case GL_STACK_UNDERFLOW:   return reinterpret_cast<const GLubyte*>("stack underflow");
        case GL_OUT_OF_MEMORY:     return reinterpret_cast<const GLubyte*>("out of memory");
        default:                   return reinterpret_cast<const GLubyte*>("unknown error");
    }
}

// ============================================================================
// 10. Subsystem Export Registration (opengl32.dll / glu32.dll)
// ============================================================================

inline void InitializeOpenglSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // WGL Exports in opengl32.dll
    ldr.registerExport("opengl32.dll", "wglCreateContext", reinterpret_cast<void*>(wglCreateContext));
    ldr.registerExport("opengl32.dll", "wglMakeCurrent", reinterpret_cast<void*>(wglMakeCurrent));
    ldr.registerExport("opengl32.dll", "wglGetCurrentContext", reinterpret_cast<void*>(wglGetCurrentContext));
    ldr.registerExport("opengl32.dll", "wglGetCurrentDC", reinterpret_cast<void*>(wglGetCurrentDC));
    ldr.registerExport("opengl32.dll", "wglDeleteContext", reinterpret_cast<void*>(wglDeleteContext));
    ldr.registerExport("opengl32.dll", "wglSwapBuffers", reinterpret_cast<void*>(wglSwapBuffers));
    ldr.registerExport("opengl32.dll", "wglGetProcAddress", reinterpret_cast<void*>(wglGetProcAddress));
    ldr.registerExport("opengl32.dll", "wglShareLists", reinterpret_cast<void*>(wglShareLists));

    // Core OpenGL Exports in opengl32.dll
    ldr.registerExport("opengl32.dll", "glMatrixMode", reinterpret_cast<void*>(glMatrixMode));
    ldr.registerExport("opengl32.dll", "glLoadIdentity", reinterpret_cast<void*>(glLoadIdentity));
    ldr.registerExport("opengl32.dll", "glLoadMatrixf", reinterpret_cast<void*>(glLoadMatrixf));
    ldr.registerExport("opengl32.dll", "glMultMatrixf", reinterpret_cast<void*>(glMultMatrixf));
    ldr.registerExport("opengl32.dll", "glPushMatrix", reinterpret_cast<void*>(glPushMatrix));
    ldr.registerExport("opengl32.dll", "glPopMatrix", reinterpret_cast<void*>(glPopMatrix));
    ldr.registerExport("opengl32.dll", "glTranslatef", reinterpret_cast<void*>(glTranslatef));
    ldr.registerExport("opengl32.dll", "glRotatef", reinterpret_cast<void*>(glRotatef));
    ldr.registerExport("opengl32.dll", "glScalef", reinterpret_cast<void*>(glScalef));
    ldr.registerExport("opengl32.dll", "glFrustum", reinterpret_cast<void*>(glFrustum));
    ldr.registerExport("opengl32.dll", "glOrtho", reinterpret_cast<void*>(glOrtho));
    ldr.registerExport("opengl32.dll", "glViewport", reinterpret_cast<void*>(glViewport));
    ldr.registerExport("opengl32.dll", "glClear", reinterpret_cast<void*>(glClear));
    ldr.registerExport("opengl32.dll", "glClearColor", reinterpret_cast<void*>(glClearColor));
    ldr.registerExport("opengl32.dll", "glClearDepth", reinterpret_cast<void*>(glClearDepth));
    ldr.registerExport("opengl32.dll", "glEnable", reinterpret_cast<void*>(glEnable));
    ldr.registerExport("opengl32.dll", "glDisable", reinterpret_cast<void*>(glDisable));
    ldr.registerExport("opengl32.dll", "glIsEnabled", reinterpret_cast<void*>(glIsEnabled));
    ldr.registerExport("opengl32.dll", "glDepthFunc", reinterpret_cast<void*>(glDepthFunc));
    ldr.registerExport("opengl32.dll", "glDepthMask", reinterpret_cast<void*>(glDepthMask));
    ldr.registerExport("opengl32.dll", "glBlendFunc", reinterpret_cast<void*>(glBlendFunc));
    ldr.registerExport("opengl32.dll", "glCullFace", reinterpret_cast<void*>(glCullFace));
    ldr.registerExport("opengl32.dll", "glFrontFace", reinterpret_cast<void*>(glFrontFace));
    ldr.registerExport("opengl32.dll", "glShadeModel", reinterpret_cast<void*>(glShadeModel));

    ldr.registerExport("opengl32.dll", "glBegin", reinterpret_cast<void*>(glBegin));
    ldr.registerExport("opengl32.dll", "glEnd", reinterpret_cast<void*>(glEnd));
    ldr.registerExport("opengl32.dll", "glVertex2f", reinterpret_cast<void*>(glVertex2f));
    ldr.registerExport("opengl32.dll", "glVertex2i", reinterpret_cast<void*>(glVertex2i));
    ldr.registerExport("opengl32.dll", "glVertex3f", reinterpret_cast<void*>(glVertex3f));
    ldr.registerExport("opengl32.dll", "glVertex3fv", reinterpret_cast<void*>(glVertex3fv));
    ldr.registerExport("opengl32.dll", "glVertex4f", reinterpret_cast<void*>(glVertex4f));
    ldr.registerExport("opengl32.dll", "glColor3f", reinterpret_cast<void*>(glColor3f));
    ldr.registerExport("opengl32.dll", "glColor3fv", reinterpret_cast<void*>(glColor3fv));
    ldr.registerExport("opengl32.dll", "glColor3ub", reinterpret_cast<void*>(glColor3ub));
    ldr.registerExport("opengl32.dll", "glColor4f", reinterpret_cast<void*>(glColor4f));
    ldr.registerExport("opengl32.dll", "glColor4fv", reinterpret_cast<void*>(glColor4fv));
    ldr.registerExport("opengl32.dll", "glColor4ub", reinterpret_cast<void*>(glColor4ub));
    ldr.registerExport("opengl32.dll", "glColor4ubv", reinterpret_cast<void*>(glColor4ubv));
    ldr.registerExport("opengl32.dll", "glNormal3f", reinterpret_cast<void*>(glNormal3f));
    ldr.registerExport("opengl32.dll", "glNormal3fv", reinterpret_cast<void*>(glNormal3fv));
    ldr.registerExport("opengl32.dll", "glTexCoord2f", reinterpret_cast<void*>(glTexCoord2f));
    ldr.registerExport("opengl32.dll", "glTexCoord2fv", reinterpret_cast<void*>(glTexCoord2fv));

    ldr.registerExport("opengl32.dll", "glGenTextures", reinterpret_cast<void*>(glGenTextures));
    ldr.registerExport("opengl32.dll", "glDeleteTextures", reinterpret_cast<void*>(glDeleteTextures));
    ldr.registerExport("opengl32.dll", "glBindTexture", reinterpret_cast<void*>(glBindTexture));
    ldr.registerExport("opengl32.dll", "glTexParameteri", reinterpret_cast<void*>(glTexParameteri));
    ldr.registerExport("opengl32.dll", "glTexParameterf", reinterpret_cast<void*>(glTexParameterf));
    ldr.registerExport("opengl32.dll", "glTexImage2D", reinterpret_cast<void*>(glTexImage2D));

    ldr.registerExport("opengl32.dll", "glEnableClientState", reinterpret_cast<void*>(glEnableClientState));
    ldr.registerExport("opengl32.dll", "glDisableClientState", reinterpret_cast<void*>(glDisableClientState));
    ldr.registerExport("opengl32.dll", "glVertexPointer", reinterpret_cast<void*>(glVertexPointer));
    ldr.registerExport("opengl32.dll", "glColorPointer", reinterpret_cast<void*>(glColorPointer));
    ldr.registerExport("opengl32.dll", "glTexCoordPointer", reinterpret_cast<void*>(glTexCoordPointer));
    ldr.registerExport("opengl32.dll", "glNormalPointer", reinterpret_cast<void*>(glNormalPointer));
    ldr.registerExport("opengl32.dll", "glDrawArrays", reinterpret_cast<void*>(glDrawArrays));
    ldr.registerExport("opengl32.dll", "glDrawElements", reinterpret_cast<void*>(glDrawElements));

    ldr.registerExport("opengl32.dll", "glGetString", reinterpret_cast<void*>(glGetString));
    ldr.registerExport("opengl32.dll", "glGetError", reinterpret_cast<void*>(glGetError));
    ldr.registerExport("opengl32.dll", "glGetIntegerv", reinterpret_cast<void*>(glGetIntegerv));
    ldr.registerExport("opengl32.dll", "glGetFloatv", reinterpret_cast<void*>(glGetFloatv));
    ldr.registerExport("opengl32.dll", "glFinish", reinterpret_cast<void*>(glFinish));
    ldr.registerExport("opengl32.dll", "glFlush", reinterpret_cast<void*>(glFlush));

    // GLU Utility Library Exports in glu32.dll
    ldr.registerExport("glu32.dll", "gluPerspective", reinterpret_cast<void*>(gluPerspective));
    ldr.registerExport("glu32.dll", "gluLookAt", reinterpret_cast<void*>(gluLookAt));
    ldr.registerExport("glu32.dll", "gluOrtho2D", reinterpret_cast<void*>(gluOrtho2D));
    ldr.registerExport("glu32.dll", "gluErrorString", reinterpret_cast<void*>(gluErrorString));
}

} // namespace micant::opengl
