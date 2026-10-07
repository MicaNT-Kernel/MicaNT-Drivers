#pragma once

#include <micant/ntdef.hpp>
#include <micant/ole32.hpp>
#include <micant/oleaut32.hpp>
#include <micant/ldr.hpp>
#include <micant/version.hpp>
#include <micant/gdi32.hpp>
#include <micant/bootvid.hpp>

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <cstring>
#include <algorithm>
#include <functional>
#include <cmath>
#include <sstream>
#include <iomanip>

namespace micant::gdiplus {

// ============================================================================
// 1. GDI+ Status Codes & Types
// ============================================================================

enum Status {
    Ok                          = 0,
    GenericError                = 1,
    InvalidParameter            = 2,
    OutOfMemory                 = 3,
    ObjectBusy                  = 4,
    InsufficientBuffer          = 5,
    NotImplemented              = 6,
    Win32Error                  = 7,
    WrongState                  = 8,
    Aborted                     = 9,
    FileNotFound                = 10,
    ValueOverflow               = 11,
    AccessDenied                = 12,
    UnknownImageFormat          = 13,
    PropertyNotFound            = 14,
    PropertyNotSupported        = 15,
    ProfileNotFound             = 16
};

using GpStatus = Status;
using ARGB     = uint32_t;
using REAL     = float;

enum Unit {
    UnitWorld       = 0,
    UnitDisplay     = 1,
    UnitPixel       = 2,
    UnitPoint       = 3,
    UnitInch        = 4,
    UnitDocument    = 5,
    UnitMillimeter  = 6
};

enum SmoothingMode {
    SmoothingModeInvalid     = -1,
    SmoothingModeDefault     = 0,
    SmoothingModeHighSpeed   = 1,
    SmoothingModeHighQuality = 2,
    SmoothingModeNone        = 3,
    SmoothingModeAntiAlias   = 4
};

enum CompositingMode {
    CompositingModeSourceOver    = 0,
    CompositingModeSourceCopy    = 1
};

enum CompositingQuality {
    CompositingQualityInvalid      = -1,
    CompositingQualityDefault      = 0,
    CompositingQualityHighSpeed    = 1,
    CompositingQualityHighQuality  = 2,
    CompositingQualityGammaCorrected = 3,
    CompositingQualityAssumeLinear = 4
};

enum InterpolationMode {
    InterpolationModeInvalid             = -1,
    InterpolationModeDefault             = 0,
    InterpolationModeLowQuality          = 1,
    InterpolationModeHighQuality         = 2,
    InterpolationModeBilinear            = 3,
    InterpolationModeBicubic             = 4,
    InterpolationModeNearestNeighbor     = 5,
    InterpolationModeHighQualityBilinear = 6,
    InterpolationModeHighQualityBicubic  = 7
};

enum PixelOffsetMode {
    PixelOffsetModeInvalid     = -1,
    PixelOffsetModeDefault     = 0,
    PixelOffsetModeHighSpeed   = 1,
    PixelOffsetModeHighQuality = 2,
    PixelOffsetModeNone        = 3,
    PixelOffsetModeHalf        = 4
};

enum DashStyle {
    DashStyleSolid        = 0,
    DashStyleDash         = 1,
    DashStyleDot          = 2,
    DashStyleDashDot      = 3,
    DashStyleDashDotDot   = 4,
    DashStyleCustom       = 5
};

enum LineCap {
    LineCapFlat             = 0,
    LineCapSquare           = 1,
    LineCapRound            = 2,
    LineCapTriangle         = 3,
    LineCapNoAnchor         = 0x10,
    LineCapSquareAnchor     = 0x11,
    LineCapRoundAnchor      = 0x12,
    LineCapDiamondAnchor    = 0x13,
    LineCapArrowAnchor      = 0x14,
    LineCapCustom           = 0xFF
};

enum LineJoin {
    LineJoinMiter           = 0,
    LineJoinBevel           = 1,
    LineJoinRound           = 2,
    LineJoinMiterClipped    = 3
};

enum BrushType {
    BrushTypeSolidColor     = 0,
    BrushTypeHatchFill       = 1,
    BrushTypeTextureFill     = 2,
    BrushTypePathGradient    = 3,
    BrushTypeLinearGradient  = 4
};

enum LinearGradientMode {
    LinearGradientModeHorizontal        = 0,
    LinearGradientModeVertical          = 1,
    LinearGradientModeForwardDiagonal   = 2,
    LinearGradientModeBackwardDiagonal  = 3
};

enum FillMode {
    FillModeAlternate   = 0,
    FillModeWinding     = 1
};

enum MatrixOrder {
    MatrixOrderPrepend  = 0,
    MatrixOrderAppend   = 1
};

enum CombineMode {
    CombineModeReplace      = 0,
    CombineModeIntersect    = 1,
    CombineModeUnion        = 2,
    CombineModeXor          = 3,
    CombineModeExclude      = 4,
    CombineModeComplement   = 5
};

enum PixelFormat {
    PixelFormatUndefined       = 0,
    PixelFormatDontCare        = 0,
    PixelFormat1bppIndexed     = 0x00030101,
    PixelFormat4bppIndexed     = 0x00030402,
    PixelFormat8bppIndexed     = 0x00030803,
    PixelFormat16bppGrayScale  = 0x00101004,
    PixelFormat16bppRGB555     = 0x00021005,
    PixelFormat16bppRGB565     = 0x00021006,
    PixelFormat16bppARGB1555   = 0x00061007,
    PixelFormat24bppRGB        = 0x00021808,
    PixelFormat32bppRGB        = 0x00022009,
    PixelFormat32bppARGB       = 0x0026200A,
    PixelFormat32bppPARGB      = 0x000E200B
};

enum ImageType {
    ImageTypeUnknown    = 0,
    ImageTypeBitmap     = 1,
    ImageTypeMetafile   = 2
};

enum ImageLockMode {
    ImageLockModeRead           = 0x0001,
    ImageLockModeWrite          = 0x0002,
    ImageLockModeUserInputBuf   = 0x0004
};

// ============================================================================
// 2. Geometric Primitives & Color
// ============================================================================

struct Point {
    int32_t X{ 0 };
    int32_t Y{ 0 };

    Point() = default;
    Point(int32_t x, int32_t y) : X(x), Y(y) {}
};

struct PointF {
    float X{ 0.0f };
    float Y{ 0.0f };

    PointF() = default;
    PointF(float x, float y) : X(x), Y(y) {}
};

struct Size {
    int32_t Width{ 0 };
    int32_t Height{ 0 };

    Size() = default;
    Size(int32_t w, int32_t h) : Width(w), Height(h) {}
};

struct SizeF {
    float Width{ 0.0f };
    float Height{ 0.0f };

    SizeF() = default;
    SizeF(float w, float h) : Width(w), Height(h) {}
};

struct Rect {
    int32_t X{ 0 };
    int32_t Y{ 0 };
    int32_t Width{ 0 };
    int32_t Height{ 0 };

    Rect() = default;
    Rect(int32_t x, int32_t y, int32_t w, int32_t h)
        : X(x), Y(y), Width(w), Height(h) {}

    int32_t GetLeft() const { return X; }
    int32_t GetTop() const { return Y; }
    int32_t GetRight() const { return X + Width; }
    int32_t GetBottom() const { return Y + Height; }
    bool IsEmptyArea() const { return (Width <= 0 || Height <= 0); }
};

struct RectF {
    float X{ 0.0f };
    float Y{ 0.0f };
    float Width{ 0.0f };
    float Height{ 0.0f };

    RectF() = default;
    RectF(float x, float y, float w, float h)
        : X(x), Y(y), Width(w), Height(h) {}

    float GetLeft() const { return X; }
    float GetTop() const { return Y; }
    float GetRight() const { return X + Width; }
    float GetBottom() const { return Y + Height; }
    bool IsEmptyArea() const { return (Width <= 0.0f || Height <= 0.0f); }
};

class Color {
private:
    ARGB m_value{ 0xFF000000 };

public:
    Color() = default;
    explicit Color(ARGB val) : m_value(val) {}
    Color(uint8_t r, uint8_t g, uint8_t b)
        : m_value(MakeARGB(255, r, g, b)) {}
    Color(uint8_t a, uint8_t r, uint8_t g, uint8_t b)
        : m_value(MakeARGB(a, r, g, b)) {}

    static ARGB MakeARGB(uint8_t a, uint8_t r, uint8_t g, uint8_t b) {
        return (static_cast<uint32_t>(a) << 24) |
               (static_cast<uint32_t>(r) << 16) |
               (static_cast<uint32_t>(g) << 8)  |
               static_cast<uint32_t>(b);
    }

    uint8_t GetA() const { return static_cast<uint8_t>((m_value >> 24) & 0xFF); }
    uint8_t GetR() const { return static_cast<uint8_t>((m_value >> 16) & 0xFF); }
    uint8_t GetG() const { return static_cast<uint8_t>((m_value >> 8) & 0xFF); }
    uint8_t GetB() const { return static_cast<uint8_t>(m_value & 0xFF); }
    ARGB GetValue() const { return m_value; }
    void SetValue(ARGB val) { m_value = val; }

    uint32_t ToCOLORREF() const {
        return (static_cast<uint32_t>(GetR())) |
               (static_cast<uint32_t>(GetG()) << 8) |
               (static_cast<uint32_t>(GetB()) << 16);
    }

    static Color Black()       { return Color(0xFF000000); }
    static Color White()       { return Color(0xFFFFFFFF); }
    static Color Red()         { return Color(0xFFFF0000); }
    static Color Green()       { return Color(0xFF00FF00); }
    static Color Blue()        { return Color(0xFF0000FF); }
    static Color Yellow()      { return Color(0xFFFFFF00); }
    static Color Cyan()        { return Color(0xFF00FFFF); }
    static Color Magenta()     { return Color(0xFFFF00FF); }
    static Color Transparent() { return Color(0x00000000); }
};

// ============================================================================
// 3. GDI+ Startup & Lifecycle
// ============================================================================

enum DebugEventLevel {
    DebugEventLevelFatal    = 0,
    DebugEventLevelWarning  = 1
};

using DebugEventProc = void (__stdcall *)(DebugEventLevel level, const char* message);

struct GdiplusStartupInput {
    uint32_t GdiplusVersion{ 1 };
    DebugEventProc DebugEventCallback{ nullptr };
    int32_t SuppressBackgroundThread{ 0 };
    int32_t SuppressExternalCodecs{ 0 };

    GdiplusStartupInput(DebugEventProc debugCallback = nullptr,
                        int32_t suppressBackgroundThread = 0,
                        int32_t suppressExternalCodecs = 0)
        : DebugEventCallback(debugCallback),
          SuppressBackgroundThread(suppressBackgroundThread),
          SuppressExternalCodecs(suppressExternalCodecs) {}
};

struct GdiplusStartupOutput {
    void* NotificationHook{ nullptr };
    void* NotificationUnhook{ nullptr };
};

inline std::atomic<uint64_t> g_gdiplusTokenCounter{ 100 };
inline std::atomic<bool>     g_gdiplusInitialized{ false };

inline Status __stdcall GdiplusStartup(uintptr_t* token, const GdiplusStartupInput* input, GdiplusStartupOutput* output) {
    if (!token) return InvalidParameter;
    (void)input;
    if (output) {
        output->NotificationHook = nullptr;
        output->NotificationUnhook = nullptr;
    }
    *token = g_gdiplusTokenCounter.fetch_add(1);
    g_gdiplusInitialized.store(true);
    return Ok;
}

inline void __stdcall GdiplusShutdown(uintptr_t token) {
    (void)token;
    g_gdiplusInitialized.store(false);
}

// ============================================================================
// 4. Matrix & Affine Transformations (GpMatrix / Matrix)
// ============================================================================

class Matrix {
private:
    float m_m11{ 1.0f }, m_m12{ 0.0f };
    float m_m21{ 0.0f }, m_m22{ 1.0f };
    float m_dx{ 0.0f },  m_dy{ 0.0f };

public:
    Matrix() = default;
    Matrix(float m11, float m12, float m21, float m22, float dx, float dy)
        : m_m11(m11), m_m12(m12), m_m21(m21), m_m22(m22), m_dx(dx), m_dy(dy) {}

    Status GetElements(float* m) const {
        if (!m) return InvalidParameter;
        m[0] = m_m11; m[1] = m_m12;
        m[2] = m_m21; m[3] = m_m22;
        m[4] = m_dx;  m[5] = m_dy;
        return Ok;
    }

    Status SetElements(float m11, float m12, float m21, float m22, float dx, float dy) {
        m_m11 = m11; m_m12 = m12;
        m_m21 = m21; m_m22 = m22;
        m_dx = dx;   m_dy = dy;
        return Ok;
    }

    bool IsIdentity() const {
        return (m_m11 == 1.0f && m_m12 == 0.0f &&
                m_m21 == 0.0f && m_m22 == 1.0f &&
                m_dx == 0.0f  && m_dy == 0.0f);
    }

    Status Reset() {
        m_m11 = 1.0f; m_m12 = 0.0f;
        m_m21 = 0.0f; m_m22 = 1.0f;
        m_dx = 0.0f;  m_dy = 0.0f;
        return Ok;
    }

    Status Translate(float offsetX, float offsetY, MatrixOrder order = MatrixOrderPrepend) {
        if (order == MatrixOrderPrepend) {
            m_dx += offsetX * m_m11 + offsetY * m_m21;
            m_dy += offsetX * m_m12 + offsetY * m_m22;
        } else {
            m_dx += offsetX;
            m_dy += offsetY;
        }
        return Ok;
    }

    Status Scale(float scaleX, float scaleY, MatrixOrder order = MatrixOrderPrepend) {
        if (order == MatrixOrderPrepend) {
            m_m11 *= scaleX; m_m12 *= scaleX;
            m_m21 *= scaleY; m_m22 *= scaleY;
        } else {
            m_m11 *= scaleX; m_m21 *= scaleX; m_dx *= scaleX;
            m_m12 *= scaleY; m_m22 *= scaleY; m_dy *= scaleY;
        }
        return Ok;
    }

    Status Rotate(float angleDeg, MatrixOrder order = MatrixOrderPrepend) {
        float rad = angleDeg * 3.14159265358979323846f / 180.0f;
        float c = std::cos(rad);
        float s = std::sin(rad);
        Matrix rot(c, s, -s, c, 0.0f, 0.0f);
        return Multiply(&rot, order);
    }

    Status Multiply(const Matrix* other, MatrixOrder order = MatrixOrderPrepend) {
        if (!other) return InvalidParameter;
        float o[6];
        other->GetElements(o);
        if (order == MatrixOrderPrepend) {
            float n11 = o[0] * m_m11 + o[1] * m_m21;
            float n12 = o[0] * m_m12 + o[1] * m_m22;
            float n21 = o[2] * m_m11 + o[3] * m_m21;
            float n22 = o[2] * m_m12 + o[3] * m_m22;
            float ndx = o[4] * m_m11 + o[5] * m_m21 + m_dx;
            float ndy = o[4] * m_m12 + o[5] * m_m22 + m_dy;
            m_m11 = n11; m_m12 = n12; m_m21 = n21; m_m22 = n22; m_dx = ndx; m_dy = ndy;
        } else {
            float n11 = m_m11 * o[0] + m_m12 * o[2];
            float n12 = m_m11 * o[1] + m_m12 * o[3];
            float n21 = m_m21 * o[0] + m_m22 * o[2];
            float n22 = m_m21 * o[1] + m_m22 * o[3];
            float ndx = m_dx * o[0] + m_dy * o[2] + o[4];
            float ndy = m_dx * o[1] + m_dy * o[3] + o[5];
            m_m11 = n11; m_m12 = n12; m_m21 = n21; m_m22 = n22; m_dx = ndx; m_dy = ndy;
        }
        return Ok;
    }

    Status TransformPoints(PointF* pts, int32_t count) const {
        if (!pts || count <= 0) return InvalidParameter;
        for (int32_t i = 0; i < count; ++i) {
            float x = pts[i].X;
            float y = pts[i].Y;
            pts[i].X = x * m_m11 + y * m_m21 + m_dx;
            pts[i].Y = x * m_m12 + y * m_m22 + m_dy;
        }
        return Ok;
    }
};

using GpMatrix = Matrix;

// ============================================================================
// 5. Brushes (Brush, SolidBrush, LinearGradientBrush, HatchBrush)
// ============================================================================

class Brush {
protected:
    BrushType m_type{ BrushTypeSolidColor };

public:
    virtual ~Brush() = default;
    virtual Brush* Clone() const = 0;
    BrushType GetType() const { return m_type; }
};

using GpBrush = Brush;

class SolidBrush : public Brush {
private:
    Color m_color{ Color::Black() };

public:
    SolidBrush() { m_type = BrushTypeSolidColor; }
    explicit SolidBrush(const Color& c) : m_color(c) { m_type = BrushTypeSolidColor; }

    Brush* Clone() const override { return new SolidBrush(m_color); }
    Status GetColor(Color* c) const { if (!c) return InvalidParameter; *c = m_color; return Ok; }
    Status SetColor(const Color& c) { m_color = c; return Ok; }
};

using GpSolidFill = SolidBrush;

class LinearGradientBrush : public Brush {
private:
    PointF m_p1{ 0.0f, 0.0f };
    PointF m_p2{ 100.0f, 100.0f };
    Color m_c1{ Color::White() };
    Color m_c2{ Color::Black() };
    LinearGradientMode m_mode{ LinearGradientModeHorizontal };

public:
    LinearGradientBrush(const PointF& p1, const PointF& p2, const Color& c1, const Color& c2)
        : m_p1(p1), m_p2(p2), m_c1(c1), m_c2(c2) {
        m_type = BrushTypeLinearGradient;
    }

    LinearGradientBrush(const RectF& rect, const Color& c1, const Color& c2, LinearGradientMode mode)
        : m_p1(rect.X, rect.Y), m_p2(rect.X + rect.Width, rect.Y + rect.Height),
          m_c1(c1), m_c2(c2), m_mode(mode) {
        m_type = BrushTypeLinearGradient;
    }

    Brush* Clone() const override {
        return new LinearGradientBrush(m_p1, m_p2, m_c1, m_c2);
    }

    Status GetLinearColors(Color* colors) const {
        if (!colors) return InvalidParameter;
        colors[0] = m_c1;
        colors[1] = m_c2;
        return Ok;
    }

    Status SetLinearColors(const Color& c1, const Color& c2) {
        m_c1 = c1; m_c2 = c2;
        return Ok;
    }

    LinearGradientMode GetMode() const { return m_mode; }
};

using GpLineGradient = LinearGradientBrush;

// ============================================================================
// 6. Pens (Pen)
// ============================================================================

class Pen {
private:
    Color m_color{ Color::Black() };
    float m_width{ 1.0f };
    DashStyle m_dashStyle{ DashStyleSolid };
    LineCap m_startCap{ LineCapFlat };
    LineCap m_endCap{ LineCapFlat };
    LineJoin m_lineJoin{ LineJoinMiter };
    std::unique_ptr<Brush> m_brush;

public:
    Pen(const Color& color, float width = 1.0f)
        : m_color(color), m_width(std::max(0.0f, width)) {
        m_brush = std::make_unique<SolidBrush>(color);
    }

    explicit Pen(const Brush* brush, float width = 1.0f)
        : m_width(std::max(0.0f, width)) {
        if (brush) {
            m_brush.reset(brush->Clone());
            if (brush->GetType() == BrushTypeSolidColor) {
                static_cast<const SolidBrush*>(brush)->GetColor(&m_color);
            }
        } else {
            m_brush = std::make_unique<SolidBrush>(Color::Black());
        }
    }

    Pen(const Pen& other)
        : m_color(other.m_color), m_width(other.m_width),
          m_dashStyle(other.m_dashStyle), m_startCap(other.m_startCap),
          m_endCap(other.m_endCap), m_lineJoin(other.m_lineJoin) {
        if (other.m_brush) m_brush.reset(other.m_brush->Clone());
    }

    Pen& operator=(const Pen& other) {
        if (this != &other) {
            m_color = other.m_color;
            m_width = other.m_width;
            m_dashStyle = other.m_dashStyle;
            m_startCap = other.m_startCap;
            m_endCap = other.m_endCap;
            m_lineJoin = other.m_lineJoin;
            if (other.m_brush) m_brush.reset(other.m_brush->Clone());
        }
        return *this;
    }

    Pen* Clone() const { return new Pen(*this); }

    Status GetColor(Color* color) const {
        if (!color) return InvalidParameter;
        *color = m_color;
        return Ok;
    }

    Status SetColor(const Color& color) {
        m_color = color;
        m_brush = std::make_unique<SolidBrush>(color);
        return Ok;
    }

    float GetWidth() const { return m_width; }
    Status SetWidth(float width) { m_width = std::max(0.0f, width); return Ok; }

    DashStyle GetDashStyle() const { return m_dashStyle; }
    Status SetDashStyle(DashStyle style) { m_dashStyle = style; return Ok; }

    LineCap GetStartCap() const { return m_startCap; }
    LineCap GetEndCap() const { return m_endCap; }
    Status SetLineCap(LineCap startCap, LineCap endCap, LineCap) {
        m_startCap = startCap;
        m_endCap = endCap;
        return Ok;
    }

    LineJoin GetLineJoin() const { return m_lineJoin; }
    Status SetLineJoin(LineJoin join) { m_lineJoin = join; return Ok; }
};

using GpPen = Pen;

class Graphics;

// ============================================================================
// 7. GraphicsPath & Regions (GpPath, GpRegion)
// ============================================================================

enum PathPointType : uint8_t {
    PathPointTypeStart           = 0,
    PathPointTypeLine            = 1,
    PathPointTypeBezier          = 3,
    PathPointTypePathTypeMask    = 0x07,
    PathPointTypeDashMode        = 0x10,
    PathPointTypePathMarker      = 0x20,
    PathPointTypeCloseSubpath    = 0x80
};

class GraphicsPath {
private:
    FillMode m_fillMode{ FillModeAlternate };
    std::vector<PointF> m_points;
    std::vector<uint8_t> m_types;

public:
    GraphicsPath(FillMode mode = FillModeAlternate) : m_fillMode(mode) {}

    GraphicsPath(const PointF* pts, const uint8_t* types, int32_t count, FillMode mode = FillModeAlternate)
        : m_fillMode(mode) {
        if (pts && types && count > 0) {
            m_points.assign(pts, pts + count);
            m_types.assign(types, types + count);
        }
    }

    GraphicsPath* Clone() const {
        auto* p = new GraphicsPath(m_fillMode);
        p->m_points = m_points;
        p->m_types = m_types;
        return p;
    }

    Status Reset() {
        m_points.clear();
        m_types.clear();
        return Ok;
    }

    int32_t GetPointCount() const { return static_cast<int32_t>(m_points.size()); }
    FillMode GetFillMode() const { return m_fillMode; }
    Status SetFillMode(FillMode mode) { m_fillMode = mode; return Ok; }

    Status GetPathPoints(PointF* pts, int32_t count) const {
        if (!pts || count < static_cast<int32_t>(m_points.size())) return InvalidParameter;
        std::copy(m_points.begin(), m_points.end(), pts);
        return Ok;
    }

    Status GetPathTypes(uint8_t* types, int32_t count) const {
        if (!types || count < static_cast<int32_t>(m_types.size())) return InvalidParameter;
        std::copy(m_types.begin(), m_types.end(), types);
        return Ok;
    }

    Status StartFigure() {
        // Next point added will be PathPointTypeStart
        return Ok;
    }

    Status CloseFigure() {
        if (!m_types.empty()) {
            m_types.back() |= PathPointTypeCloseSubpath;
        }
        return Ok;
    }

    Status AddLine(float x1, float y1, float x2, float y2) {
        if (m_points.empty() || (m_types.back() & PathPointTypeCloseSubpath)) {
            m_points.emplace_back(x1, y1);
            m_types.push_back(PathPointTypeStart);
        }
        m_points.emplace_back(x2, y2);
        m_types.push_back(PathPointTypeLine);
        return Ok;
    }

    Status AddRectangle(const RectF& rect) {
        StartFigure();
        AddLine(rect.X, rect.Y, rect.X + rect.Width, rect.Y);
        AddLine(rect.X + rect.Width, rect.Y, rect.X + rect.Width, rect.Y + rect.Height);
        AddLine(rect.X + rect.Width, rect.Y + rect.Height, rect.X, rect.Y + rect.Height);
        CloseFigure();
        return Ok;
    }

    Status AddEllipse(float x, float y, float width, float height) {
        // Approximate ellipse with 8-point polygon for vector geometry
        const int n = 16;
        float rx = width * 0.5f;
        float ry = height * 0.5f;
        float cx = x + rx;
        float cy = y + ry;
        for (int i = 0; i <= n; ++i) {
            float rad = (i % n) * (2.0f * 3.1415926535f / n);
            float px = cx + rx * std::cos(rad);
            float py = cy + ry * std::sin(rad);
            if (i == 0) {
                m_points.emplace_back(px, py);
                m_types.push_back(PathPointTypeStart);
            } else if (i < n) {
                m_points.emplace_back(px, py);
                m_types.push_back(PathPointTypeLine);
            }
        }
        CloseFigure();
        return Ok;
    }

    Status AddPolygon(const PointF* pts, int32_t count) {
        if (!pts || count < 3) return InvalidParameter;
        m_points.emplace_back(pts[0]);
        m_types.push_back(PathPointTypeStart);
        for (int32_t i = 1; i < count; ++i) {
            m_points.emplace_back(pts[i]);
            m_types.push_back(PathPointTypeLine);
        }
        CloseFigure();
        return Ok;
    }

    Status Transform(const Matrix* matrix) {
        if (!matrix) return InvalidParameter;
        return matrix->TransformPoints(m_points.data(), static_cast<int32_t>(m_points.size()));
    }
};

using GpPath = GraphicsPath;

class Region {
private:
    RectF m_bounds{ 0, 0, 0, 0 };
    bool  m_isInfinite{ true };

public:
    Region() = default;
    explicit Region(const RectF& rect) : m_bounds(rect), m_isInfinite(false) {}

    Region* Clone() const {
        auto* r = new Region(m_bounds);
        r->m_isInfinite = m_isInfinite;
        return r;
    }

    Status MakeInfinite() { m_isInfinite = true; m_bounds = { 0, 0, 0, 0 }; return Ok; }
    Status MakeEmpty()    { m_isInfinite = false; m_bounds = { 0, 0, 0, 0 }; return Ok; }
    bool IsInfinite(const Graphics*) const { return m_isInfinite; }
    bool IsEmpty(const Graphics*) const { return (!m_isInfinite && m_bounds.IsEmptyArea()); }

    Status GetBounds(RectF* rect, const Graphics*) const {
        if (!rect) return InvalidParameter;
        *rect = m_bounds;
        return Ok;
    }

    Status Intersect(const RectF& rect) {
        if (m_isInfinite) {
            m_bounds = rect;
            m_isInfinite = false;
        } else {
            float l = std::max(m_bounds.X, rect.X);
            float t = std::max(m_bounds.Y, rect.Y);
            float r = std::min(m_bounds.GetRight(), rect.GetRight());
            float b = std::min(m_bounds.GetBottom(), rect.GetBottom());
            if (r > l && b > t) {
                m_bounds = RectF(l, t, r - l, b - t);
            } else {
                MakeEmpty();
            }
        }
        return Ok;
    }

    Status Union(const RectF& rect) {
        if (m_isInfinite) return Ok;
        if (m_bounds.IsEmptyArea()) {
            m_bounds = rect;
            return Ok;
        }
        float l = std::min(m_bounds.X, rect.X);
        float t = std::min(m_bounds.Y, rect.Y);
        float r = std::max(m_bounds.GetRight(), rect.GetRight());
        float b = std::max(m_bounds.GetBottom(), rect.GetBottom());
        m_bounds = RectF(l, t, r - l, b - t);
        return Ok;
    }
};

using GpRegion = Region;

// ============================================================================
// 8. Image & Bitmap (GpImage, GpBitmap)
// ============================================================================

struct BitmapData {
    uint32_t    Width{ 0 };
    uint32_t    Height{ 0 };
    int32_t     Stride{ 0 };
    PixelFormat PixelFormat{ PixelFormat32bppARGB };
    void*       Scan0{ nullptr };
    uintptr_t   Reserved{ 0 };
};

// Standard GDI+ Image Format GUIDs
inline constexpr GUID ImageFormatUndefined = { 0xb96b3ca9, 0x0728, 0x11d3, { 0x9d, 0x7b, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e } };
inline constexpr GUID ImageFormatMemoryBMP = { 0xb96b3caa, 0x0728, 0x11d3, { 0x9d, 0x7b, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e } };
inline constexpr GUID ImageFormatBMP       = { 0xb96b3cab, 0x0728, 0x11d3, { 0x9d, 0x7b, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e } };
inline constexpr GUID ImageFormatJPEG      = { 0xb96b3cae, 0x0728, 0x11d3, { 0x9d, 0x7b, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e } };
inline constexpr GUID ImageFormatPNG       = { 0xb96b3caf, 0x0728, 0x11d3, { 0x9d, 0x7b, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e } };
inline constexpr GUID ImageFormatGIF       = { 0xb96b3cb0, 0x0728, 0x11d3, { 0x9d, 0x7b, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e } };
inline constexpr GUID ImageFormatTIFF      = { 0xb96b3cb1, 0x0728, 0x11d3, { 0x9d, 0x7b, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e } };
inline constexpr GUID ImageFormatICO       = { 0xb96b3cb5, 0x0728, 0x11d3, { 0x9d, 0x7b, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e } };

class Image {
protected:
    ImageType   m_type{ ImageTypeBitmap };
    uint32_t    m_width{ 0 };
    uint32_t    m_height{ 0 };
    PixelFormat m_pixelFormat{ PixelFormat32bppARGB };
    GUID        m_rawFormat{ ImageFormatBMP };

public:
    virtual ~Image() = default;
    virtual Image* Clone() const = 0;

    ImageType GetType() const { return m_type; }
    uint32_t GetWidth() const { return m_width; }
    uint32_t GetHeight() const { return m_height; }
    PixelFormat GetPixelFormat() const { return m_pixelFormat; }
    Status GetRawFormat(GUID* format) const {
        if (!format) return InvalidParameter;
        *format = m_rawFormat;
        return Ok;
    }
};

using GpImage = Image;

class Bitmap : public Image {
private:
    std::vector<uint32_t> m_pixels; // 32-bpp ARGB buffer
    int32_t m_stride{ 0 };
    bool m_isLocked{ false };

public:
    Bitmap(uint32_t width, uint32_t height, PixelFormat format = PixelFormat32bppARGB) {
        m_type = ImageTypeBitmap;
        m_width = width;
        m_height = height;
        m_pixelFormat = format;
        m_stride = width * 4;
        m_pixels.resize(width * height, 0x00000000);
        m_rawFormat = ImageFormatBMP;
    }

    Bitmap(uint32_t width, uint32_t height, int32_t stride, PixelFormat format, uint8_t* scan0) {
        m_type = ImageTypeBitmap;
        m_width = width;
        m_height = height;
        m_pixelFormat = format;
        m_stride = (stride != 0) ? stride : static_cast<int32_t>(width * 4);
        m_pixels.resize(width * height);
        if (scan0) {
            std::memcpy(m_pixels.data(), scan0, width * height * 4);
        } else {
            std::fill(m_pixels.begin(), m_pixels.end(), 0x00000000);
        }
        m_rawFormat = ImageFormatBMP;
    }

    Image* Clone() const override {
        auto* bmp = new Bitmap(m_width, m_height, m_pixelFormat);
        bmp->m_pixels = m_pixels;
        return bmp;
    }

    Status GetPixel(int32_t x, int32_t y, Color* color) const {
        if (!color || x < 0 || y < 0 || static_cast<uint32_t>(x) >= m_width || static_cast<uint32_t>(y) >= m_height) {
            return InvalidParameter;
        }
        *color = Color(m_pixels[y * m_width + x]);
        return Ok;
    }

    Status SetPixel(int32_t x, int32_t y, const Color& color) {
        if (x < 0 || y < 0 || static_cast<uint32_t>(x) >= m_width || static_cast<uint32_t>(y) >= m_height) {
            return InvalidParameter;
        }
        m_pixels[y * m_width + x] = color.GetValue();
        return Ok;
    }

    Status LockBits(const Rect* rect, uint32_t flags, PixelFormat format, BitmapData* lockedBitmapData) {
        (void)flags; (void)format;
        if (!lockedBitmapData) return InvalidParameter;
        if (m_isLocked) return WrongState;
        m_isLocked = true;

        lockedBitmapData->Width = rect ? rect->Width : m_width;
        lockedBitmapData->Height = rect ? rect->Height : m_height;
        lockedBitmapData->Stride = m_stride;
        lockedBitmapData->PixelFormat = m_pixelFormat;
        lockedBitmapData->Scan0 = m_pixels.data();
        return Ok;
    }

    Status UnlockBits(BitmapData* lockedBitmapData) {
        if (!lockedBitmapData || !m_isLocked) return WrongState;
        m_isLocked = false;
        return Ok;
    }

    uint32_t* GetPixelBuffer() { return m_pixels.data(); }
    const uint32_t* GetPixelBuffer() const { return m_pixels.data(); }
};

using GpBitmap = Bitmap;

// ============================================================================
// 9. Graphics Drawing Surface (GpGraphics / Graphics)
// ============================================================================

class Graphics {
private:
    gdi32::HDC      m_hdc{ nullptr };
    Bitmap*         m_targetBitmap{ nullptr };
    bool            m_ownsTargetBitmap{ false };
    SmoothingMode   m_smoothingMode{ SmoothingModeDefault };
    CompositingMode m_compositingMode{ CompositingModeSourceOver };
    Matrix          m_transform;
    Region          m_clip;

    void SetPixelInternal(int32_t x, int32_t y, const Color& color) {
        if (m_targetBitmap) {
            m_targetBitmap->SetPixel(x, y, color);
        } else if (m_hdc) {
            gdi32::SetPixel(m_hdc, x, y, color.ToCOLORREF());
        }
    }

public:
    explicit Graphics(gdi32::HDC hdc) : m_hdc(hdc) {}

    explicit Graphics(Image* image) {
        if (image && image->GetType() == ImageTypeBitmap) {
            m_targetBitmap = static_cast<Bitmap*>(image);
        }
    }

    ~Graphics() {
        if (m_ownsTargetBitmap && m_targetBitmap) delete m_targetBitmap;
    }

    static Graphics* FromHDC(gdi32::HDC hdc) { return new Graphics(hdc); }
    static Graphics* FromImage(Image* image) { return new Graphics(image); }

    SmoothingMode GetSmoothingMode() const { return m_smoothingMode; }
    Status SetSmoothingMode(SmoothingMode mode) { m_smoothingMode = mode; return Ok; }

    CompositingMode GetCompositingMode() const { return m_compositingMode; }
    Status SetCompositingMode(CompositingMode mode) { m_compositingMode = mode; return Ok; }

    Status GetTransform(Matrix* matrix) const {
        if (!matrix) return InvalidParameter;
        *matrix = m_transform;
        return Ok;
    }

    Status SetTransform(const Matrix* matrix) {
        if (!matrix) return InvalidParameter;
        m_transform = *matrix;
        return Ok;
    }

    Status ResetTransform() { return m_transform.Reset(); }

    Status Clear(const Color& color) {
        if (m_targetBitmap) {
            uint32_t* buf = m_targetBitmap->GetPixelBuffer();
            size_t count = m_targetBitmap->GetWidth() * m_targetBitmap->GetHeight();
            std::fill(buf, buf + count, color.GetValue());
            return Ok;
        }
        if (m_hdc) {
            gdi32::RECT r{ 0, 0, 1920, 1080 };
            gdi32::HBRUSH hBr = gdi32::CreateSolidBrush(color.ToCOLORREF());
            gdi32::FillRect(m_hdc, &r, hBr);
            gdi32::DeleteObject(hBr);
            return Ok;
        }
        return Ok;
    }

    Status DrawLine(const Pen* pen, float x1, float y1, float x2, float y2) {
        if (!pen) return InvalidParameter;
        Color c;
        pen->GetColor(&c);

        // Apply Transform
        PointF pts[2] = { { x1, y1 }, { x2, y2 } };
        m_transform.TransformPoints(pts, 2);

        int32_t ix1 = static_cast<int32_t>(std::round(pts[0].X));
        int32_t iy1 = static_cast<int32_t>(std::round(pts[0].Y));
        int32_t ix2 = static_cast<int32_t>(std::round(pts[1].X));
        int32_t iy2 = static_cast<int32_t>(std::round(pts[1].Y));

        // Bresenham's line algorithm
        int32_t dx = std::abs(ix2 - ix1);
        int32_t dy = std::abs(iy2 - iy1);
        int32_t sx = (ix1 < ix2) ? 1 : -1;
        int32_t sy = (iy1 < iy2) ? 1 : -1;
        int32_t err = dx - dy;

        while (true) {
            SetPixelInternal(ix1, iy1, c);
            if (ix1 == ix2 && iy1 == iy2) break;
            int32_t e2 = 2 * err;
            if (e2 > -dy) { err -= dy; ix1 += sx; }
            if (e2 < dx)  { err += dx; iy1 += sy; }
        }
        return Ok;
    }

    Status DrawRectangle(const Pen* pen, float x, float y, float width, float height) {
        DrawLine(pen, x, y, x + width, y);
        DrawLine(pen, x + width, y, x + width, y + height);
        DrawLine(pen, x + width, y + height, x, y + height);
        DrawLine(pen, x, y + height, x, y);
        return Ok;
    }

    Status FillRectangle(const Brush* brush, float x, float y, float width, float height) {
        if (!brush) return InvalidParameter;
        Color c = Color::Black();
        if (brush->GetType() == BrushTypeSolidColor) {
            static_cast<const SolidBrush*>(brush)->GetColor(&c);
        } else if (brush->GetType() == BrushTypeLinearGradient) {
            Color clrs[2];
            static_cast<const LinearGradientBrush*>(brush)->GetLinearColors(clrs);
            c = clrs[0];
        }

        int32_t ix = static_cast<int32_t>(x);
        int32_t iy = static_cast<int32_t>(y);
        int32_t iw = static_cast<int32_t>(width);
        int32_t ih = static_cast<int32_t>(height);

        for (int32_t py = iy; py < iy + ih; ++py) {
            for (int32_t px = ix; px < ix + iw; ++px) {
                SetPixelInternal(px, py, c);
            }
        }
        return Ok;
    }

    Status DrawEllipse(const Pen* pen, float x, float y, float width, float height) {
        if (!pen) return InvalidParameter;
        GraphicsPath path;
        path.AddEllipse(x, y, width, height);
        return DrawPath(pen, &path);
    }

    Status FillEllipse(const Brush* brush, float x, float y, float width, float height) {
        if (!brush) return InvalidParameter;
        Color c = Color::Black();
        if (brush->GetType() == BrushTypeSolidColor) {
            static_cast<const SolidBrush*>(brush)->GetColor(&c);
        }

        float rx = width * 0.5f;
        float ry = height * 0.5f;
        float cx = x + rx;
        float cy = y + ry;

        int32_t minX = static_cast<int32_t>(std::floor(x));
        int32_t maxX = static_cast<int32_t>(std::ceil(x + width));
        int32_t minY = static_cast<int32_t>(std::floor(y));
        int32_t maxY = static_cast<int32_t>(std::ceil(y + height));

        for (int32_t py = minY; py <= maxY; ++py) {
            for (int32_t px = minX; px <= maxX; ++px) {
                float dx = (px - cx) / rx;
                float dy = (py - cy) / ry;
                if (dx * dx + dy * dy <= 1.0f) {
                    SetPixelInternal(px, py, c);
                }
            }
        }
        return Ok;
    }

    Status DrawPath(const Pen* pen, const GraphicsPath* path) {
        if (!pen || !path) return InvalidParameter;
        int32_t count = path->GetPointCount();
        if (count < 2) return Ok;

        std::vector<PointF> pts(count);
        std::vector<uint8_t> types(count);
        path->GetPathPoints(pts.data(), count);
        path->GetPathTypes(types.data(), count);

        for (int32_t i = 1; i < count; ++i) {
            if ((types[i] & PathPointTypePathTypeMask) == PathPointTypeLine) {
                DrawLine(pen, pts[i - 1].X, pts[i - 1].Y, pts[i].X, pts[i].Y);
            }
        }
        return Ok;
    }

    Status DrawImage(Image* image, float x, float y) {
        if (!image) return InvalidParameter;
        if (image->GetType() == ImageTypeBitmap) {
            auto* bmp = static_cast<Bitmap*>(image);
            uint32_t w = bmp->GetWidth();
            uint32_t h = bmp->GetHeight();
            for (uint32_t py = 0; py < h; ++py) {
                for (uint32_t px = 0; px < w; ++px) {
                    Color c;
                    bmp->GetPixel(px, py, &c);
                    SetPixelInternal(static_cast<int32_t>(x + px), static_cast<int32_t>(y + py), c);
                }
            }
        }
        return Ok;
    }
};

using GpGraphics = Graphics;

// ============================================================================
// 10. Windows Imaging Component (WIC) Foundation (windowscodecs.dll)
// ============================================================================

// WIC CLSIDs & IIDs
inline constexpr GUID CLSID_WICImagingFactory =
    { 0x317D06E8, 0x5F24, 0x433D, { 0xBD, 0xF7, 0x79, 0xCE, 0x68, 0xD8, 0xAB, 0xC2 } };

inline constexpr GUID IID_IWICImagingFactory =
    { 0xEC5EC888, 0xC19E, 0x4CF0, { 0xB3, 0x90, 0xDA, 0x60, 0x27, 0x93, 0x60, 0xB3 } };

inline constexpr GUID IID_IWICBitmapSource =
    { 0x00000120, 0xA8F2, 0x4877, { 0xBA, 0x0A, 0xFD, 0x2B, 0x66, 0x45, 0xFB, 0x94 } };

inline constexpr GUID IID_IWICBitmap =
    { 0x00000121, 0xA8F2, 0x4877, { 0xBA, 0x0A, 0xFD, 0x2B, 0x66, 0x45, 0xFB, 0x94 } };

inline constexpr GUID IID_IWICBitmapDecoder =
    { 0x9EDDE9E7, 0x8DEE, 0x47EA, { 0x99, 0xDF, 0xE6, 0xFA, 0xF2, 0xED, 0x44, 0xBF } };

inline constexpr GUID IID_IWICBitmapEncoder =
    { 0x00000103, 0xA8F2, 0x4877, { 0xBA, 0x0A, 0xFD, 0x2B, 0x66, 0x45, 0xFB, 0x94 } };

inline constexpr GUID IID_IWICFormatConverter =
    { 0x00000301, 0xA8F2, 0x4877, { 0xBA, 0x0A, 0xFD, 0x2B, 0x66, 0x45, 0xFB, 0x94 } };

// WIC Pixel Formats
inline constexpr GUID GUID_WICPixelFormat32bppPBGRA =
    { 0x6FDDC324, 0x4E03, 0x4BFE, { 0xB1, 0x85, 0x3D, 0x77, 0x76, 0x8D, 0xC9, 0x10 } };

inline constexpr GUID GUID_WICPixelFormat32bppRGBA =
    { 0xF5C7257D, 0x95D4, 0x498E, { 0xAB, 0x0E, 0x63, 0x4B, 0x77, 0x04, 0xBB, 0x11 } };

inline constexpr GUID GUID_WICPixelFormat24bppBGR =
    { 0x6FDDC324, 0x4E03, 0x4BFE, { 0xB1, 0x85, 0x3D, 0x77, 0x76, 0x8D, 0xC9, 0x0C } };

inline constexpr GUID GUID_WICPixelFormat8bppGray =
    { 0x6FDDC324, 0x4E03, 0x4BFE, { 0xB1, 0x85, 0x3D, 0x77, 0x76, 0x8D, 0xC9, 0x08 } };

struct IWICBitmapSource : public ole32::IUnknown {
    virtual int32_t __stdcall GetSize(uint32_t* puiWidth, uint32_t* puiHeight) = 0;
    virtual int32_t __stdcall GetPixelFormat(GUID* pPixelFormat) = 0;
    virtual int32_t __stdcall GetResolution(double* pDpiX, double* pDpiY) = 0;
    virtual int32_t __stdcall CopyPalette(void* pIPalette) = 0;
    virtual int32_t __stdcall CopyPixels(const void* prc, uint32_t cbStride, uint32_t cbBufferSize, uint8_t* pbBuffer) = 0;
};

struct IWICBitmap : public IWICBitmapSource {
    virtual int32_t __stdcall Lock(const void* prcLock, uint32_t flags, void** ppILock) = 0;
    virtual int32_t __stdcall SetPalette(void* pIPalette) = 0;
    virtual int32_t __stdcall SetResolution(double dpiX, double dpiY) = 0;
};

struct IWICFormatConverter : public IWICBitmapSource {
    virtual int32_t __stdcall Initialize(IWICBitmapSource* pISource, const GUID& dstFormat, int32_t dither, void* pIPalette, double alphaThresholdPercent, int32_t paletteTranslate) = 0;
    virtual int32_t __stdcall CanConvert(const GUID& srcPixelFormat, const GUID& dstPixelFormat, int32_t* pfCanConvert) = 0;
};

struct IWICBitmapDecoder : public ole32::IUnknown {
    virtual int32_t __stdcall QueryCapability(void* pIStream, uint32_t* pdwCapability) = 0;
    virtual int32_t __stdcall Initialize(void* pIStream, uint32_t cacheOptions) = 0;
    virtual int32_t __stdcall GetContainerFormat(GUID* pguidContainerFormat) = 0;
    virtual int32_t __stdcall GetDecoderInfo(void** ppIDecoderInfo) = 0;
    virtual int32_t __stdcall CopyPalette(void* pIPalette) = 0;
    virtual int32_t __stdcall GetMetadataQueryReader(void** ppIMetadataQueryReader) = 0;
    virtual int32_t __stdcall GetPreview(IWICBitmapSource** ppIBitmapSource) = 0;
    virtual int32_t __stdcall GetColorContexts(uint32_t cCount, void** ppIColorContexts, uint32_t* pcActualCount) = 0;
    virtual int32_t __stdcall GetThumbnail(IWICBitmapSource** ppIThumbnail) = 0;
    virtual int32_t __stdcall GetFrameCount(uint32_t* pCount) = 0;
    virtual int32_t __stdcall GetFrame(uint32_t index, void** ppIBitmapFrame) = 0;
};

struct IWICBitmapEncoder : public ole32::IUnknown {
    virtual int32_t __stdcall Initialize(void* pIStream, uint32_t cacheOption) = 0;
    virtual int32_t __stdcall GetContainerFormat(GUID* pguidContainerFormat) = 0;
    virtual int32_t __stdcall GetEncoderInfo(void** ppIEncoderInfo) = 0;
    virtual int32_t __stdcall SetColorContexts(uint32_t cCount, void** ppIColorContext) = 0;
    virtual int32_t __stdcall SetPalette(void* pIPalette) = 0;
    virtual int32_t __stdcall SetThumbnail(IWICBitmapSource* pIThumbnail) = 0;
    virtual int32_t __stdcall SetPreview(IWICBitmapSource* pIPreview) = 0;
    virtual int32_t __stdcall CreateNewFrame(void** ppIFrameEncode, void** ppIPropertyBag) = 0;
    virtual int32_t __stdcall Commit() = 0;
    virtual int32_t __stdcall GetMetadataQueryWriter(void** ppIMetadataQueryWriter) = 0;
};

struct IWICImagingFactory : public ole32::IUnknown {
    virtual int32_t __stdcall CreateDecoderFromFilename(const wchar_t* wzFilename, const GUID* pguidVendor, uint32_t dwDesiredAccess, uint32_t metadataOptions, IWICBitmapDecoder** ppIDecoder) = 0;
    virtual int32_t __stdcall CreateDecoderFromStream(void* pIStream, const GUID* pguidVendor, uint32_t metadataOptions, IWICBitmapDecoder** ppIDecoder) = 0;
    virtual int32_t __stdcall CreateDecoderFromFileHandle(uintptr_t hFile, const GUID* pguidVendor, uint32_t metadataOptions, IWICBitmapDecoder** ppIDecoder) = 0;
    virtual int32_t __stdcall CreateComponentInfo(const GUID& clsidComponent, void** ppIInfo) = 0;
    virtual int32_t __stdcall CreateDecoder(const GUID& guidContainerFormat, const GUID* pguidVendor, IWICBitmapDecoder** ppIDecoder) = 0;
    virtual int32_t __stdcall CreateEncoder(const GUID& guidContainerFormat, const GUID* pguidVendor, IWICBitmapEncoder** ppIEncoder) = 0;
    virtual int32_t __stdcall CreatePalette(void** ppIPalette) = 0;
    virtual int32_t __stdcall CreateFormatConverter(IWICFormatConverter** ppIFormatConverter) = 0;
    virtual int32_t __stdcall CreateBitmapScaler(void** ppIBitmapScaler) = 0;
    virtual int32_t __stdcall CreateBitmapClipper(void** ppIBitmapClipper) = 0;
    virtual int32_t __stdcall CreateBitmapFlipRotator(void** ppIBitmapFlipRotator) = 0;
    virtual int32_t __stdcall CreateStream(void** ppIWICStream) = 0;
    virtual int32_t __stdcall CreateColorContext(void** ppIColorContext) = 0;
    virtual int32_t __stdcall CreateColorTransformer(void** ppIColorTransform) = 0;
    virtual int32_t __stdcall CreateBitmap(uint32_t uiWidth, uint32_t uiHeight, const GUID& pixelFormat, uint32_t option, IWICBitmap** ppIBitmap) = 0;
    virtual int32_t __stdcall CreateBitmapFromSource(IWICBitmapSource* pIBitmapSource, uint32_t option, IWICBitmap** ppIBitmap) = 0;
    virtual int32_t __stdcall CreateBitmapFromSourceRect(IWICBitmapSource* pIBitmapSource, uint32_t x, uint32_t y, uint32_t width, uint32_t height, IWICBitmap** ppIBitmap) = 0;
    virtual int32_t __stdcall CreateBitmapFromMemory(uint32_t uiWidth, uint32_t uiHeight, const GUID& pixelFormat, uint32_t cbStride, uint32_t cbBufferSize, uint8_t* pbBuffer, IWICBitmap** ppIBitmap) = 0;
    virtual int32_t __stdcall CreateBitmapFromHBITMAP(void* hBitmap, void* hPalette, int32_t options, IWICBitmap** ppIBitmap) = 0;
    virtual int32_t __stdcall CreateBitmapFromHICON(void* hIcon, IWICBitmap** ppIBitmap) = 0;
    virtual int32_t __stdcall CreateComponentEnumerator(uint32_t componentTypes, uint32_t options, void** ppIEnumUnknown) = 0;
    virtual int32_t __stdcall CreateFastMetadataEncoderFromDecoder(IWICBitmapDecoder* pIDecoder, void** ppIFastEncoder) = 0;
    virtual int32_t __stdcall CreateFastMetadataEncoderFromFrameDecode(void* pIFrameDecoder, void** ppIFastEncoder) = 0;
    virtual int32_t __stdcall CreateQueryWriter(const GUID& guidMetadataFormat, const GUID* pguidVendor, void** ppIQueryWriter) = 0;
    virtual int32_t __stdcall CreateQueryWriterFromReader(void* pIQueryReader, const GUID* pguidVendor, void** ppIQueryWriter) = 0;
};

// ============================================================================
// 11. Concrete WIC Implementation (CWICBitmap, CWICImagingFactory)
// ============================================================================

class CWICBitmap : public IWICBitmap {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    uint32_t m_width{ 0 };
    uint32_t m_height{ 0 };
    GUID m_format{ GUID_WICPixelFormat32bppPBGRA };
    std::vector<uint8_t> m_buffer;
    uint32_t m_stride{ 0 };
    double m_dpiX{ 96.0 };
    double m_dpiY{ 96.0 };
    mutable std::mutex m_mutex;

public:
    CWICBitmap(uint32_t width, uint32_t height, const GUID& format, uint32_t stride = 0, const uint8_t* buffer = nullptr)
        : m_width(width), m_height(height), m_format(format) {
        m_stride = (stride != 0) ? stride : width * 4;
        m_buffer.resize(m_stride * height);
        if (buffer) {
            std::memcpy(m_buffer.data(), buffer, m_buffer.size());
        } else {
            std::fill(m_buffer.begin(), m_buffer.end(), 0);
        }
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IWICBitmapSource || riid == IID_IWICBitmap) {
            *ppvObject = static_cast<IWICBitmap*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IWICBitmapSource
    int32_t __stdcall GetSize(uint32_t* puiWidth, uint32_t* puiHeight) override {
        if (!puiWidth || !puiHeight) return ole32::E_POINTER;
        *puiWidth = m_width;
        *puiHeight = m_height;
        return ole32::S_OK;
    }

    int32_t __stdcall GetPixelFormat(GUID* pPixelFormat) override {
        if (!pPixelFormat) return ole32::E_POINTER;
        *pPixelFormat = m_format;
        return ole32::S_OK;
    }

    int32_t __stdcall GetResolution(double* pDpiX, double* pDpiY) override {
        if (!pDpiX || !pDpiY) return ole32::E_POINTER;
        *pDpiX = m_dpiX;
        *pDpiY = m_dpiY;
        return ole32::S_OK;
    }

    int32_t __stdcall CopyPalette(void*) override { return ole32::E_NOTIMPL; }

    int32_t __stdcall CopyPixels(const void* prc, uint32_t cbStride, uint32_t cbBufferSize, uint8_t* pbBuffer) override {
        (void)prc;
        if (!pbBuffer) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t toCopy = std::min<uint32_t>(cbBufferSize, static_cast<uint32_t>(m_buffer.size()));
        (void)cbStride;
        std::memcpy(pbBuffer, m_buffer.data(), toCopy);
        return ole32::S_OK;
    }

    // IWICBitmap
    int32_t __stdcall Lock(const void*, uint32_t, void** ppILock) override {
        if (ppILock) *ppILock = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall SetPalette(void*) override { return ole32::S_OK; }

    int32_t __stdcall SetResolution(double dpiX, double dpiY) override {
        m_dpiX = dpiX;
        m_dpiY = dpiY;
        return ole32::S_OK;
    }
};

class CWICImagingFactory : public IWICImagingFactory {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    CWICImagingFactory() = default;

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IWICImagingFactory) {
            *ppvObject = static_cast<IWICImagingFactory*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall CreateDecoderFromFilename(const wchar_t*, const GUID*, uint32_t, uint32_t, IWICBitmapDecoder** ppIDecoder) override {
        if (ppIDecoder) *ppIDecoder = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall CreateDecoderFromStream(void*, const GUID*, uint32_t, IWICBitmapDecoder** ppIDecoder) override {
        if (ppIDecoder) *ppIDecoder = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall CreateDecoderFromFileHandle(uintptr_t, const GUID*, uint32_t, IWICBitmapDecoder** ppIDecoder) override {
        if (ppIDecoder) *ppIDecoder = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall CreateComponentInfo(const GUID&, void** ppIInfo) override {
        if (ppIInfo) *ppIInfo = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall CreateDecoder(const GUID&, const GUID*, IWICBitmapDecoder** ppIDecoder) override {
        if (ppIDecoder) *ppIDecoder = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall CreateEncoder(const GUID&, const GUID*, IWICBitmapEncoder** ppIEncoder) override {
        if (ppIEncoder) *ppIEncoder = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall CreatePalette(void** ppIPalette) override {
        if (ppIPalette) *ppIPalette = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall CreateFormatConverter(IWICFormatConverter** ppIFormatConverter) override {
        if (ppIFormatConverter) *ppIFormatConverter = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall CreateBitmapScaler(void** ppIBitmapScaler) override { if (ppIBitmapScaler) *ppIBitmapScaler = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateBitmapClipper(void** ppIBitmapClipper) override { if (ppIBitmapClipper) *ppIBitmapClipper = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateBitmapFlipRotator(void** ppIBitmapFlipRotator) override { if (ppIBitmapFlipRotator) *ppIBitmapFlipRotator = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateStream(void** ppIWICStream) override { if (ppIWICStream) *ppIWICStream = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateColorContext(void** ppIColorContext) override { if (ppIColorContext) *ppIColorContext = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateColorTransformer(void** ppIColorTransform) override { if (ppIColorTransform) *ppIColorTransform = nullptr; return ole32::E_NOTIMPL; }

    int32_t __stdcall CreateBitmap(uint32_t uiWidth, uint32_t uiHeight, const GUID& pixelFormat, uint32_t, IWICBitmap** ppIBitmap) override {
        if (!ppIBitmap) return ole32::E_POINTER;
        *ppIBitmap = new CWICBitmap(uiWidth, uiHeight, pixelFormat);
        return ole32::S_OK;
    }

    int32_t __stdcall CreateBitmapFromSource(IWICBitmapSource* pIBitmapSource, uint32_t, IWICBitmap** ppIBitmap) override {
        if (!pIBitmapSource || !ppIBitmap) return ole32::E_POINTER;
        uint32_t w = 0, h = 0;
        pIBitmapSource->GetSize(&w, &h);
        GUID fmt{};
        pIBitmapSource->GetPixelFormat(&fmt);
        *ppIBitmap = new CWICBitmap(w, h, fmt);
        return ole32::S_OK;
    }

    int32_t __stdcall CreateBitmapFromSourceRect(IWICBitmapSource*, uint32_t, uint32_t, uint32_t, uint32_t, IWICBitmap** ppIBitmap) override {
        if (ppIBitmap) *ppIBitmap = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall CreateBitmapFromMemory(uint32_t uiWidth, uint32_t uiHeight, const GUID& pixelFormat, uint32_t cbStride, uint32_t cbBufferSize, uint8_t* pbBuffer, IWICBitmap** ppIBitmap) override {
        (void)cbBufferSize;
        if (!ppIBitmap || !pbBuffer) return ole32::E_POINTER;
        *ppIBitmap = new CWICBitmap(uiWidth, uiHeight, pixelFormat, cbStride, pbBuffer);
        return ole32::S_OK;
    }

    int32_t __stdcall CreateBitmapFromHBITMAP(void*, void*, int32_t, IWICBitmap** ppIBitmap) override { if (ppIBitmap) *ppIBitmap = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateBitmapFromHICON(void*, IWICBitmap** ppIBitmap) override { if (ppIBitmap) *ppIBitmap = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateComponentEnumerator(uint32_t, uint32_t, void** ppIEnumUnknown) override { if (ppIEnumUnknown) *ppIEnumUnknown = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateFastMetadataEncoderFromDecoder(IWICBitmapDecoder*, void** ppIFastEncoder) override { if (ppIFastEncoder) *ppIFastEncoder = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateFastMetadataEncoderFromFrameDecode(void*, void** ppIFastEncoder) override { if (ppIFastEncoder) *ppIFastEncoder = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateQueryWriter(const GUID&, const GUID*, void** ppIQueryWriter) override { if (ppIQueryWriter) *ppIQueryWriter = nullptr; return ole32::E_NOTIMPL; }
    int32_t __stdcall CreateQueryWriterFromReader(void*, const GUID*, void** ppIQueryWriter) override { if (ppIQueryWriter) *ppIQueryWriter = nullptr; return ole32::E_NOTIMPL; }
};

// ============================================================================
// 12. Flat C API Function Exports (gdiplus.dll)
// ============================================================================

inline Status __stdcall GdipCreatePen1(ARGB color, float width, Unit, GpPen** pen) {
    if (!pen) return InvalidParameter;
    *pen = new Pen(Color(color), width);
    return Ok;
}

inline Status __stdcall GdipDeletePen(GpPen* pen) {
    if (!pen) return InvalidParameter;
    delete pen;
    return Ok;
}

inline Status __stdcall GdipCreateSolidFill(ARGB color, GpSolidFill** brush) {
    if (!brush) return InvalidParameter;
    *brush = new SolidBrush(Color(color));
    return Ok;
}

inline Status __stdcall GdipDeleteBrush(GpBrush* brush) {
    if (!brush) return InvalidParameter;
    delete brush;
    return Ok;
}

inline Status __stdcall GdipCreateFromHDC(gdi32::HDC hdc, GpGraphics** graphics) {
    if (!graphics) return InvalidParameter;
    *graphics = Graphics::FromHDC(hdc);
    return Ok;
}

inline Status __stdcall GdipDeleteGraphics(GpGraphics* graphics) {
    if (!graphics) return InvalidParameter;
    delete graphics;
    return Ok;
}

inline Status __stdcall GdipDrawLine(GpGraphics* graphics, GpPen* pen, float x1, float y1, float x2, float y2) {
    if (!graphics || !pen) return InvalidParameter;
    return graphics->DrawLine(pen, x1, y1, x2, y2);
}

inline Status __stdcall GdipFillRectangle(GpGraphics* graphics, GpBrush* brush, float x, float y, float width, float height) {
    if (!graphics || !brush) return InvalidParameter;
    return graphics->FillRectangle(brush, x, y, width, height);
}

inline Status __stdcall GdipCreateBitmapFromScan0(int32_t width, int32_t height, int32_t stride, PixelFormat format, uint8_t* scan0, GpBitmap** bitmap) {
    if (!bitmap || width <= 0 || height <= 0) return InvalidParameter;
    *bitmap = new Bitmap(width, height, stride, format, scan0);
    return Ok;
}

inline Status __stdcall GdipDisposeImage(GpImage* image) {
    if (!image) return InvalidParameter;
    delete image;
    return Ok;
}

inline int32_t __stdcall WICCreateImagingFactory_Proxy(uint32_t, IWICImagingFactory** ppImagingFactory) {
    if (!ppImagingFactory) return ole32::E_POINTER;
    *ppImagingFactory = new CWICImagingFactory();
    return ole32::S_OK;
}

inline int32_t __stdcall DllCanUnloadNow() {
    return ole32::S_OK;
}

// ============================================================================
// 13. Dynamic Export Registration & Class Factory Wiring
// ============================================================================

template <typename T>
class CGdiPlusClassFactory : public ole32::IClassFactory {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == ole32::IID_IClassFactory) {
            *ppvObject = static_cast<ole32::IClassFactory*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall CreateInstance(ole32::IUnknown* pUnkOuter, const GUID& riid, void** ppvObject) override {
        if (pUnkOuter) return ole32::CLASS_E_NOAGGREGATION;
        auto* instance = new T();
        int32_t hr = instance->QueryInterface(riid, ppvObject);
        instance->Release();
        return hr;
    }

    int32_t __stdcall LockServer(int32_t) override { return ole32::S_OK; }
};

inline void InitializeGdiPlusExports() {
    auto& loader = ldr::DynamicLoader::get();

    // gdiplus.dll exports
    loader.registerExport("gdiplus.dll", "GdiplusStartup", reinterpret_cast<void*>(&GdiplusStartup));
    loader.registerExport("gdiplus.dll", "GdiplusShutdown", reinterpret_cast<void*>(&GdiplusShutdown));
    loader.registerExport("gdiplus.dll", "GdipCreatePen1", reinterpret_cast<void*>(&GdipCreatePen1));
    loader.registerExport("gdiplus.dll", "GdipDeletePen", reinterpret_cast<void*>(&GdipDeletePen));
    loader.registerExport("gdiplus.dll", "GdipCreateSolidFill", reinterpret_cast<void*>(&GdipCreateSolidFill));
    loader.registerExport("gdiplus.dll", "GdipDeleteBrush", reinterpret_cast<void*>(&GdipDeleteBrush));
    loader.registerExport("gdiplus.dll", "GdipCreateFromHDC", reinterpret_cast<void*>(&GdipCreateFromHDC));
    loader.registerExport("gdiplus.dll", "GdipDeleteGraphics", reinterpret_cast<void*>(&GdipDeleteGraphics));
    loader.registerExport("gdiplus.dll", "GdipDrawLine", reinterpret_cast<void*>(&GdipDrawLine));
    loader.registerExport("gdiplus.dll", "GdipFillRectangle", reinterpret_cast<void*>(&GdipFillRectangle));
    loader.registerExport("gdiplus.dll", "GdipCreateBitmapFromScan0", reinterpret_cast<void*>(&GdipCreateBitmapFromScan0));
    loader.registerExport("gdiplus.dll", "GdipDisposeImage", reinterpret_cast<void*>(&GdipDisposeImage));
    loader.registerExport("gdiplus.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&DllCanUnloadNow));

    // windowscodecs.dll exports
    loader.registerExport("windowscodecs.dll", "WICCreateImagingFactory_Proxy", reinterpret_cast<void*>(&WICCreateImagingFactory_Proxy));
    loader.registerExport("windowscodecs.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&DllCanUnloadNow));

    // COM Class Factory registration for WIC Imaging Factory
    auto& com = ole32::ComRuntime::get();
    uint32_t regCookie = 0;
    auto* wicFact = new CGdiPlusClassFactory<CWICImagingFactory>();
    com.RegisterClassObject(CLSID_WICImagingFactory, wicFact, 1, 1, &regCookie);
    wicFact->Release();
}

} // namespace micant::gdiplus
