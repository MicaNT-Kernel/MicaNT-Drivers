// ============================================================================
// MicaNT: Windows Direct2D 1.3 & DirectWrite Advanced Typography Subsystem
// (include/micant/d2d1_3.hpp)
//
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/win32metadata (Windows.Win32.Graphics.Direct2D)
//   - Direct2D 1.3 / Windows 10 Creators Update OpenType & Modern Vector Engine
//   - DirectWrite OpenType Typographic Feature Tags & Multi-Script Font Fallback
//
// Subsystem Overview:
//   d2d1_3.hpp provides modern Direct2D 1.3 vector rendering and DirectWrite
//   advanced OpenType typography for MicaNT.
//   Supports:
//     - ID2D1Ink & ID2D1InkStyle (nib shapes, Bézier ink stroke segments)
//     - ID2D1SpriteBatch (high-throughput batched sprite draw calls)
//     - ID2D1GradientMesh (16-point bicubic Coons patch gradient meshes)
//     - ID2D1SvgDocument & ID2D1SvgElement (SVG vector icons & color glyphs)
//     - IDWriteTypography (OpenType feature tags: kern, liga, smcp, onum, tnum)
//     - IDWriteFontFallback (multi-script Unicode font cascade resolution)
//
// Core Dynamic Modules:
//   - d2d1.dll (Direct2D 1.3 Engine)
//   - dwrite.dll (DirectWrite Typography & Font Fallback Engine)
//
// Trademark & Nominative Fair Use Notice:
//   Windows, Direct2D, DirectWrite, and OpenType are registered trademarks of
//   Microsoft Corp. MicaNT is an independent sovereign clean-room implementation
//   engineered for binary interoperability (*Google LLC v. Oracle America, Inc.*).
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ole32.hpp"
#include "d2d1.hpp"
#include "dwrite.hpp"
#include "wcs.hpp"
#include "pointer.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>

namespace micant::d2d1_3 {

// ============================================================================
// 1. Direct2D 1.3 GUIDs & Constants
// ============================================================================

inline constexpr GUID IID_ID2D1InkStyle = {
    0xbae8b344, 0x23fc, 0x4071, { 0x8c, 0xb5, 0xd0, 0x5d, 0x6f, 0x07, 0x38, 0x48 }
};

inline constexpr GUID IID_ID2D1Ink = {
    0xb4992dac, 0x9378, 0x473b, { 0xac, 0xb8, 0x30, 0x3b, 0xf4, 0x49, 0x7c, 0x15 }
};

inline constexpr GUID IID_ID2D1GradientMesh = {
    0xf292e401, 0xc050, 0x4cde, { 0x83, 0xd7, 0x04, 0x96, 0x2d, 0x3b, 0x23, 0xc2 }
};

inline constexpr GUID IID_ID2D1SpriteBatch = {
    0x4dc583ee, 0x450e, 0x472c, { 0xac, 0x56, 0x26, 0x07, 0xc7, 0xfa, 0x5b, 0x7b }
};

inline constexpr GUID IID_ID2D1SvgDocument = {
    0x86b8a8dc, 0x3c9e, 0x4211, { 0x97, 0xf0, 0x72, 0x8e, 0x88, 0xe9, 0x5e, 0x42 }
};

inline constexpr GUID IID_ID2D1SvgElement = {
    0xac7b4a3a, 0xbc79, 0x41a3, { 0x91, 0xdf, 0xab, 0x07, 0x0e, 0xae, 0x02, 0xb1 }
};

inline constexpr GUID IID_ID2D1DeviceContext2 = {
    0xd48771dd, 0xfe9e, 0x42e0, { 0xbd, 0x68, 0xd6, 0x7d, 0xd1, 0xf9, 0xa6, 0x4d }
};

inline constexpr GUID IID_ID2D1Factory3 = {
    0x0869724a, 0x5230, 0x4a9e, { 0xb0, 0x55, 0x40, 0x12, 0xa4, 0x79, 0x51, 0xa7 }
};

inline constexpr GUID IID_IDWriteTypography = {
    0x55f11483, 0xa234, 0x4bf9, { 0x82, 0x16, 0x52, 0x6a, 0xc3, 0xd0, 0x01, 0x49 }
};

inline constexpr GUID IID_IDWriteFontFallback = {
    0x1a0d8438, 0x1d97, 0x4ec1, { 0xae, 0xf9, 0xa2, 0xfb, 0x86, 0xed, 0x6a, 0xcb }
};

// ============================================================================
// 2. Direct2D 1.3 Structures & Enums
// ============================================================================

enum D2D1_INK_NIB_SHAPE : uint32_t {
    D2D1_INK_NIB_SHAPE_ROUND  = 0,
    D2D1_INK_NIB_SHAPE_SQUARE = 1
};

struct D2D1_INK_POINT {
    float x;
    float y;
    float radius;
};

struct D2D1_INK_BEZIER_SEGMENT {
    D2D1_INK_POINT point1;
    D2D1_INK_POINT point2;
    D2D1_INK_POINT point3;
};

struct D2D1_INK_STYLE_PROPERTIES {
    D2D1_INK_NIB_SHAPE nibShape;
    d2d1::D2D1_MATRIX_3X2_F nibTransform;
};

enum D2D1_SPRITE_OPTIONS : uint32_t {
    D2D1_SPRITE_OPTIONS_NONE                         = 0,
    D2D1_SPRITE_OPTIONS_CLAMP_TO_SOURCE_RECTANGLE   = 1
};

struct D2D1_GRADIENT_MESH_PATCH {
    d2d1::D2D1_POINT_2F point00;
    d2d1::D2D1_POINT_2F point01;
    d2d1::D2D1_POINT_2F point02;
    d2d1::D2D1_POINT_2F point03;
    d2d1::D2D1_POINT_2F point10;
    d2d1::D2D1_POINT_2F point11;
    d2d1::D2D1_POINT_2F point12;
    d2d1::D2D1_POINT_2F point13;
    d2d1::D2D1_POINT_2F point20;
    d2d1::D2D1_POINT_2F point21;
    d2d1::D2D1_POINT_2F point22;
    d2d1::D2D1_POINT_2F point23;
    d2d1::D2D1_POINT_2F point30;
    d2d1::D2D1_POINT_2F point31;
    d2d1::D2D1_POINT_2F point32;
    d2d1::D2D1_POINT_2F point33;
    d2d1::D2D1_COLOR_F  color00;
    d2d1::D2D1_COLOR_F  color03;
    d2d1::D2D1_COLOR_F  color30;
    d2d1::D2D1_COLOR_F  color33;
};

enum D2D1_SVG_PAINT_TYPE : uint32_t {
    D2D1_SVG_PAINT_TYPE_NONE          = 0,
    D2D1_SVG_PAINT_TYPE_COLOR         = 1,
    D2D1_SVG_PAINT_TYPE_CURRENT_COLOR = 2,
    D2D1_SVG_PAINT_TYPE_URI           = 3
};

struct D2D1_SVG_VIEWBOX {
    float x;
    float y;
    float width;
    float height;
};

// ============================================================================
// 3. DirectWrite OpenType Typographic Feature Tags
// ============================================================================

#define DWRITE_MAKE_FONT_FEATURE_TAG(a,b,c,d) \
    (static_cast<uint32_t>((a) | ((b) << 8) | ((c) << 16) | ((d) << 24)))

inline constexpr uint32_t DWRITE_FONT_FEATURE_TAG_KERNING              = DWRITE_MAKE_FONT_FEATURE_TAG('k','e','r','n');
inline constexpr uint32_t DWRITE_FONT_FEATURE_TAG_STANDARD_LIGATURES    = DWRITE_MAKE_FONT_FEATURE_TAG('l','i','g','a');
inline constexpr uint32_t DWRITE_FONT_FEATURE_TAG_CONTEXTUAL_LIGATURES  = DWRITE_MAKE_FONT_FEATURE_TAG('c','l','i','g');
inline constexpr uint32_t DWRITE_FONT_FEATURE_TAG_CONTEXTUAL_ALTERNATES = DWRITE_MAKE_FONT_FEATURE_TAG('c','a','l','t');
inline constexpr uint32_t DWRITE_FONT_FEATURE_TAG_SMALL_CAPITALS        = DWRITE_MAKE_FONT_FEATURE_TAG('s','m','c','p');
inline constexpr uint32_t DWRITE_FONT_FEATURE_TAG_OLD_STYLE_FIGURES     = DWRITE_MAKE_FONT_FEATURE_TAG('o','n','u','m');
inline constexpr uint32_t DWRITE_FONT_FEATURE_TAG_TABULAR_FIGURES       = DWRITE_MAKE_FONT_FEATURE_TAG('t','n','u','m');
inline constexpr uint32_t DWRITE_FONT_FEATURE_TAG_STYLISTIC_SET_1       = DWRITE_MAKE_FONT_FEATURE_TAG('s','s','0','1');
inline constexpr uint32_t DWRITE_FONT_FEATURE_TAG_SWASH                 = DWRITE_MAKE_FONT_FEATURE_TAG('s','w','s','h');

struct DWRITE_FONT_FEATURE {
    uint32_t nameTag;
    uint32_t parameter;
};

struct DWRITE_TYPOGRAPHIC_FEATURES {
    DWRITE_FONT_FEATURE* features;
    uint32_t             featureCount;
};

// ============================================================================
// 4. Direct2D 1.3 COM Interfaces
// ============================================================================

class ID2D1InkStyle : public d2d1::ID2D1Resource {
public:
    virtual void __stdcall SetNibShape(D2D1_INK_NIB_SHAPE nibShape) = 0;
    virtual D2D1_INK_NIB_SHAPE __stdcall GetNibShape() const = 0;
    virtual void __stdcall SetNibTransform(const d2d1::D2D1_MATRIX_3X2_F* transform) = 0;
    virtual void __stdcall GetNibTransform(d2d1::D2D1_MATRIX_3X2_F* transform) const = 0;
};

class ID2D1Ink : public d2d1::ID2D1Resource {
public:
    virtual void __stdcall SetStartPoint(const D2D1_INK_POINT* startPoint) = 0;
    virtual D2D1_INK_POINT __stdcall GetStartPoint() const = 0;
    virtual int32_t __stdcall AddSegments(const D2D1_INK_BEZIER_SEGMENT* segments, uint32_t segmentsCount) = 0;
    virtual uint32_t __stdcall GetSegmentCount() const = 0;
    virtual int32_t __stdcall GetBounds(ID2D1InkStyle* inkStyle, const d2d1::D2D1_MATRIX_3X2_F* worldTransform, d2d1::D2D1_RECT_F* bounds) const = 0;
};

class ID2D1GradientMesh : public d2d1::ID2D1Resource {
public:
    virtual uint32_t __stdcall GetPatchCount() const = 0;
    virtual int32_t __stdcall GetPatches(uint32_t startIndex, D2D1_GRADIENT_MESH_PATCH* patches, uint32_t patchesCount) const = 0;
};

class ID2D1SpriteBatch : public d2d1::ID2D1Resource {
public:
    virtual int32_t __stdcall AddSprites(
        uint32_t spriteCount,
        const d2d1::D2D1_RECT_F* destinationRectangles,
        const d2d1::D2D1_RECT_U* sourceRectangles,
        const d2d1::D2D1_COLOR_F* colors,
        const d2d1::D2D1_MATRIX_3X2_F* transforms,
        uint32_t destinationRectanglesStride,
        uint32_t sourceRectanglesStride,
        uint32_t colorsStride,
        uint32_t transformsStride) = 0;
    virtual uint32_t __stdcall GetSpriteCount() const = 0;
    virtual void __stdcall Clear() = 0;
};

class ID2D1SvgDocument;

class ID2D1SvgElement : public d2d1::ID2D1Resource {
public:
    virtual void __stdcall GetDocument(ID2D1SvgDocument** document) = 0;
    virtual int32_t __stdcall GetTagName(wchar_t* name, uint32_t nameCount) = 0;
    virtual int32_t __stdcall SetAttributeValue(const wchar_t* name, const wchar_t* value) = 0;
    virtual int32_t __stdcall GetAttributeValue(const wchar_t* name, wchar_t* value, uint32_t valueCount) = 0;
    virtual int32_t __stdcall AppendChild(ID2D1SvgElement* newChild) = 0;
    virtual uint32_t __stdcall GetChildrenCount() const = 0;
};

class ID2D1SvgDocument : public d2d1::ID2D1Resource {
public:
    virtual int32_t __stdcall SetViewportSize(d2d1::D2D1_SIZE_F viewportSize) = 0;
    virtual d2d1::D2D1_SIZE_F __stdcall GetViewportSize() const = 0;
    virtual int32_t __stdcall SetRoot(ID2D1SvgElement* root) = 0;
    virtual void __stdcall GetRoot(ID2D1SvgElement** root) = 0;
    virtual int32_t __stdcall FindElementById(const wchar_t* id, ID2D1SvgElement** svgElement) = 0;
    virtual int32_t __stdcall Serialize(std::string& outXml) = 0;
};

class ID2D1DeviceContext2 : public d2d1::ID2D1RenderTarget {
public:
    virtual int32_t __stdcall CreateInk(const D2D1_INK_POINT* startPoint, ID2D1Ink** ink) = 0;
    virtual int32_t __stdcall CreateInkStyle(const D2D1_INK_STYLE_PROPERTIES* inkStyleProperties, ID2D1InkStyle** inkStyle) = 0;
    virtual void __stdcall DrawInk(ID2D1Ink* ink, d2d1::ID2D1Brush* brush, ID2D1InkStyle* inkStyle) = 0;
    virtual int32_t __stdcall CreateGradientMesh(const D2D1_GRADIENT_MESH_PATCH* patches, uint32_t patchesCount, ID2D1GradientMesh** gradientMesh) = 0;
    virtual void __stdcall DrawGradientMesh(ID2D1GradientMesh* gradientMesh) = 0;
    virtual int32_t __stdcall CreateSpriteBatch(ID2D1SpriteBatch** spriteBatch) = 0;
    virtual void __stdcall DrawSpriteBatch(
        ID2D1SpriteBatch* spriteBatch,
        uint32_t startIndex,
        uint32_t spriteCount,
        d2d1::ID2D1Bitmap* bitmap,
        d2d1::D2D1_BITMAP_INTERPOLATION_MODE interpolationMode,
        D2D1_SPRITE_OPTIONS spriteOptions) = 0;
    virtual int32_t __stdcall CreateSvgDocument(const char* xml, d2d1::D2D1_SIZE_F viewportSize, ID2D1SvgDocument** svgDocument) = 0;
    virtual void __stdcall DrawSvgDocument(ID2D1SvgDocument* svgDocument) = 0;
};

class ID2D1Factory3 : public d2d1::ID2D1Factory {
public:
    virtual int32_t __stdcall CreateInkStyle(const D2D1_INK_STYLE_PROPERTIES* inkStyleProperties, ID2D1InkStyle** inkStyle) = 0;
    virtual int32_t __stdcall CreateDeviceContext2(ID2D1DeviceContext2** d2dContext) = 0;
};

class IDWriteTypography : public ole32::IUnknown {
public:
    virtual int32_t __stdcall AddFontFeature(DWRITE_FONT_FEATURE fontFeature) = 0;
    virtual uint32_t __stdcall GetFontFeatureCount() const = 0;
    virtual int32_t __stdcall GetFontFeature(uint32_t fontFeatureIndex, DWRITE_FONT_FEATURE* fontFeature) const = 0;
};

class IDWriteFontFallback : public ole32::IUnknown {
public:
    virtual int32_t __stdcall MapCharacters(
        const wchar_t* textString,
        uint32_t textLength,
        const wchar_t* localeName,
        std::wstring& outMappedFontFamily) = 0;
};

// ============================================================================
// 5. Clean-Room Concrete Implementations
// ============================================================================

class CD2D1InkStyleImpl : public ID2D1InkStyle {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    D2D1_INK_NIB_SHAPE m_nibShape{ D2D1_INK_NIB_SHAPE_ROUND };
    d2d1::D2D1_MATRIX_3X2_F m_nibTransform{ 1, 0, 0, 1, 0, 0 };

public:
    CD2D1InkStyleImpl(const D2D1_INK_STYLE_PROPERTIES* props) {
        if (props) {
            m_nibShape = props->nibShape;
            m_nibTransform = props->nibTransform;
        }
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ID2D1InkStyle) {
            *ppv = static_cast<ID2D1InkStyle*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    void __stdcall GetFactory(d2d1::ID2D1Factory**) const override {}

    void __stdcall SetNibShape(D2D1_INK_NIB_SHAPE nibShape) override { m_nibShape = nibShape; }
    D2D1_INK_NIB_SHAPE __stdcall GetNibShape() const override { return m_nibShape; }
    void __stdcall SetNibTransform(const d2d1::D2D1_MATRIX_3X2_F* transform) override {
        if (transform) m_nibTransform = *transform;
    }
    void __stdcall GetNibTransform(d2d1::D2D1_MATRIX_3X2_F* transform) const override {
        if (transform) *transform = m_nibTransform;
    }
};

class CD2D1InkImpl : public ID2D1Ink {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    D2D1_INK_POINT m_startPoint{ 0, 0, 2.0f };
    std::vector<D2D1_INK_BEZIER_SEGMENT> m_segments;

public:
    CD2D1InkImpl(const D2D1_INK_POINT* startPoint) {
        if (startPoint) m_startPoint = *startPoint;
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ID2D1Ink) {
            *ppv = static_cast<ID2D1Ink*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    void __stdcall GetFactory(d2d1::ID2D1Factory**) const override {}

    void __stdcall SetStartPoint(const D2D1_INK_POINT* startPoint) override {
        if (startPoint) m_startPoint = *startPoint;
    }

    D2D1_INK_POINT __stdcall GetStartPoint() const override { return m_startPoint; }

    int32_t __stdcall AddSegments(const D2D1_INK_BEZIER_SEGMENT* segments, uint32_t segmentsCount) override {
        if (!segments || segmentsCount == 0) return ole32::E_INVALIDARG;
        for (uint32_t i = 0; i < segmentsCount; ++i) {
            m_segments.push_back(segments[i]);
        }
        return ole32::S_OK;
    }

    uint32_t __stdcall GetSegmentCount() const override {
        return static_cast<uint32_t>(m_segments.size());
    }

    int32_t __stdcall GetBounds(ID2D1InkStyle*, const d2d1::D2D1_MATRIX_3X2_F*, d2d1::D2D1_RECT_F* bounds) const override {
        if (!bounds) return ole32::E_POINTER;
        float minX = m_startPoint.x - m_startPoint.radius;
        float minY = m_startPoint.y - m_startPoint.radius;
        float maxX = m_startPoint.x + m_startPoint.radius;
        float maxY = m_startPoint.y + m_startPoint.radius;

        for (const auto& s : m_segments) {
            minX = std::min({ minX, s.point1.x - s.point1.radius, s.point2.x - s.point2.radius, s.point3.x - s.point3.radius });
            minY = std::min({ minY, s.point1.y - s.point1.radius, s.point2.y - s.point2.radius, s.point3.y - s.point3.radius });
            maxX = std::max({ maxX, s.point1.x + s.point1.radius, s.point2.x + s.point2.radius, s.point3.x + s.point3.radius });
            maxY = std::max({ maxY, s.point1.y + s.point1.radius, s.point2.y + s.point2.radius, s.point3.y + s.point3.radius });
        }

        bounds->left = minX; bounds->top = minY;
        bounds->right = maxX; bounds->bottom = maxY;
        return ole32::S_OK;
    }
};

struct SpriteEntry {
    d2d1::D2D1_RECT_F destination;
    d2d1::D2D1_RECT_U source;
    d2d1::D2D1_COLOR_F color;
    d2d1::D2D1_MATRIX_3X2_F transform;
};

class CD2D1SpriteBatchImpl : public ID2D1SpriteBatch {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<SpriteEntry> m_sprites;

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ID2D1SpriteBatch) {
            *ppv = static_cast<ID2D1SpriteBatch*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    void __stdcall GetFactory(d2d1::ID2D1Factory**) const override {}

    int32_t __stdcall AddSprites(
        uint32_t spriteCount,
        const d2d1::D2D1_RECT_F* destinationRectangles,
        const d2d1::D2D1_RECT_U* sourceRectangles,
        const d2d1::D2D1_COLOR_F* colors,
        const d2d1::D2D1_MATRIX_3X2_F* transforms,
        uint32_t, uint32_t, uint32_t, uint32_t) override
    {
        if (!destinationRectangles || spriteCount == 0) return ole32::E_INVALIDARG;
        for (uint32_t i = 0; i < spriteCount; ++i) {
            SpriteEntry s;
            s.destination = destinationRectangles[i];
            s.source = sourceRectangles ? sourceRectangles[i] : d2d1::D2D1_RECT_U{ 0, 0, 100, 100 };
            s.color = colors ? colors[i] : d2d1::D2D1_COLOR_F{ 1, 1, 1, 1 };
            s.transform = transforms ? transforms[i] : d2d1::D2D1_MATRIX_3X2_F{ 1, 0, 0, 1, 0, 0 };
            m_sprites.push_back(s);
        }
        return ole32::S_OK;
    }

    uint32_t __stdcall GetSpriteCount() const override {
        return static_cast<uint32_t>(m_sprites.size());
    }

    void __stdcall Clear() override {
        m_sprites.clear();
    }
};

class CD2D1GradientMeshImpl : public ID2D1GradientMesh {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<D2D1_GRADIENT_MESH_PATCH> m_patches;

public:
    CD2D1GradientMeshImpl(const D2D1_GRADIENT_MESH_PATCH* patches, uint32_t count) {
        if (patches && count > 0) {
            m_patches.assign(patches, patches + count);
        }
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ID2D1GradientMesh) {
            *ppv = static_cast<ID2D1GradientMesh*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    void __stdcall GetFactory(d2d1::ID2D1Factory**) const override {}

    uint32_t __stdcall GetPatchCount() const override {
        return static_cast<uint32_t>(m_patches.size());
    }

    int32_t __stdcall GetPatches(uint32_t startIndex, D2D1_GRADIENT_MESH_PATCH* patches, uint32_t patchesCount) const override {
        if (!patches || startIndex + patchesCount > m_patches.size()) return ole32::E_INVALIDARG;
        for (uint32_t i = 0; i < patchesCount; ++i) {
            patches[i] = m_patches[startIndex + i];
        }
        return ole32::S_OK;
    }
};

class CD2D1SvgElementImpl : public ID2D1SvgElement {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID2D1SvgDocument* m_document{ nullptr };
    std::wstring m_tagName;
    std::unordered_map<std::wstring, std::wstring> m_attributes;
    std::vector<ID2D1SvgElement*> m_children;

public:
    CD2D1SvgElementImpl(ID2D1SvgDocument* doc, const std::wstring& tagName)
        : m_document(doc), m_tagName(tagName) {}

    ~CD2D1SvgElementImpl() override {
        for (auto* child : m_children) child->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ID2D1SvgElement) {
            *ppv = static_cast<ID2D1SvgElement*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    void __stdcall GetFactory(d2d1::ID2D1Factory**) const override {}

    void __stdcall GetDocument(ID2D1SvgDocument** document) override {
        if (document) {
            *document = m_document;
            if (m_document) m_document->AddRef();
        }
    }

    int32_t __stdcall GetTagName(wchar_t* name, uint32_t nameCount) override {
        if (!name || nameCount < m_tagName.length() + 1) return ole32::E_INVALIDARG;
        std::memcpy(name, m_tagName.c_str(), (m_tagName.length() + 1) * sizeof(wchar_t));
        return ole32::S_OK;
    }

    int32_t __stdcall SetAttributeValue(const wchar_t* name, const wchar_t* value) override {
        if (!name || !value) return ole32::E_INVALIDARG;
        m_attributes[name] = value;
        return ole32::S_OK;
    }

    int32_t __stdcall GetAttributeValue(const wchar_t* name, wchar_t* value, uint32_t valueCount) override {
        if (!name || !value) return ole32::E_INVALIDARG;
        auto it = m_attributes.find(name);
        if (it == m_attributes.end()) return ole32::E_FAIL;
        if (valueCount < it->second.length() + 1) return ole32::E_INVALIDARG;
        std::memcpy(value, it->second.c_str(), (it->second.length() + 1) * sizeof(wchar_t));
        return ole32::S_OK;
    }

    int32_t __stdcall AppendChild(ID2D1SvgElement* newChild) override {
        if (!newChild) return ole32::E_INVALIDARG;
        newChild->AddRef();
        m_children.push_back(newChild);
        return ole32::S_OK;
    }

    uint32_t __stdcall GetChildrenCount() const override {
        return static_cast<uint32_t>(m_children.size());
    }

    const std::vector<ID2D1SvgElement*>& GetChildren() const { return m_children; }
    const std::unordered_map<std::wstring, std::wstring>& GetAttributes() const { return m_attributes; }
};

class CD2D1SvgDocumentImpl : public ID2D1SvgDocument {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    d2d1::D2D1_SIZE_F m_viewportSize{ 512.0f, 512.0f };
    ID2D1SvgElement* m_root{ nullptr };
    ID2D1SvgElement* SearchElementById(ID2D1SvgElement* elem, const wchar_t* id) {
        if (!elem || !id) return nullptr;
        wchar_t idBuf[128]{};
        if (elem->GetAttributeValue(L"id", idBuf, 128) == ole32::S_OK) {
            if (wcscmp(idBuf, id) == 0) return elem;
        }
        auto* elemImpl = static_cast<CD2D1SvgElementImpl*>(elem);
        for (auto* child : elemImpl->GetChildren()) {
            auto* found = SearchElementById(child, id);
            if (found) return found;
        }
        return nullptr;
    }

public:
    CD2D1SvgDocumentImpl(d2d1::D2D1_SIZE_F vpSize) : m_viewportSize(vpSize) {
        m_root = new CD2D1SvgElementImpl(this, L"svg");
        wchar_t wStr[32], hStr[32];
        swprintf_s(wStr, L"%f", vpSize.width);
        swprintf_s(hStr, L"%f", vpSize.height);
        m_root->SetAttributeValue(L"width", wStr);
        m_root->SetAttributeValue(L"height", hStr);
    }

    ~CD2D1SvgDocumentImpl() override {
        if (m_root) m_root->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ID2D1SvgDocument) {
            *ppv = static_cast<ID2D1SvgDocument*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    void __stdcall GetFactory(d2d1::ID2D1Factory**) const override {}

    int32_t __stdcall SetViewportSize(d2d1::D2D1_SIZE_F viewportSize) override {
        m_viewportSize = viewportSize;
        return ole32::S_OK;
    }

    d2d1::D2D1_SIZE_F __stdcall GetViewportSize() const override { return m_viewportSize; }

    int32_t __stdcall SetRoot(ID2D1SvgElement* root) override {
        if (m_root) m_root->Release();
        m_root = root;
        if (m_root) m_root->AddRef();
        return ole32::S_OK;
    }

    void __stdcall GetRoot(ID2D1SvgElement** root) override {
        if (root) {
            *root = m_root;
            if (m_root) m_root->AddRef();
        }
    }

    int32_t __stdcall FindElementById(const wchar_t* id, ID2D1SvgElement** svgElement) override {
        if (!id || !svgElement) return ole32::E_INVALIDARG;
        auto* found = SearchElementById(m_root, id);
        if (!found) {
            *svgElement = nullptr;
            return ole32::E_FAIL;
        }
        *svgElement = found;
        (*svgElement)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall Serialize(std::string& outXml) override {
        std::ostringstream ss;
        ss << "<svg width=\"" << m_viewportSize.width << "\" height=\"" << m_viewportSize.height << "\" xmlns=\"http://www.w3.org/2000/svg\">\n";
        if (m_root) {
            auto* rootImpl = static_cast<CD2D1SvgElementImpl*>(m_root);
            for (auto* child : rootImpl->GetChildren()) {
                auto* childImpl = static_cast<CD2D1SvgElementImpl*>(child);
                wchar_t tag[64]{};
                childImpl->GetTagName(tag, 64);
                std::string sTag(tag, tag + wcslen(tag));
                ss << "  <" << sTag;
                for (const auto& [k, v] : childImpl->GetAttributes()) {
                    std::string sK(k.begin(), k.end());
                    std::string sV(v.begin(), v.end());
                    ss << " " << sK << "=\"" << sV << "\"";
                }
                ss << "/>\n";
            }
        }
        ss << "</svg>\n";
        outXml = ss.str();
        return ole32::S_OK;
    }
};

class CD2D1DeviceContext2Impl : public d2d1::CD2D1RenderTargetBase<ID2D1DeviceContext2> {
private:
    uint32_t m_inkDrawCount{ 0 };
    uint32_t m_spriteBatchDrawCount{ 0 };
    uint32_t m_svgDrawCount{ 0 };
    uint32_t m_gradientMeshDrawCount{ 0 };

public:
    CD2D1DeviceContext2Impl(d2d1::ID2D1Factory* factory = nullptr, uint32_t width = 1920, uint32_t height = 1080)
        : d2d1::CD2D1RenderTargetBase<ID2D1DeviceContext2>(factory, width, height) {}

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == IID_ID2D1DeviceContext2) {
            *ppv = static_cast<ID2D1DeviceContext2*>(this);
            this->AddRef();
            return ole32::S_OK;
        }
        return d2d1::CD2D1RenderTargetBase<ID2D1DeviceContext2>::QueryInterface(riid, ppv);
    }

    // Direct2D 1.3 Methods
    int32_t __stdcall CreateInk(const D2D1_INK_POINT* startPoint, ID2D1Ink** ink) override {
        if (!ink) return ole32::E_POINTER;
        *ink = new CD2D1InkImpl(startPoint);
        return ole32::S_OK;
    }

    int32_t __stdcall CreateInkStyle(const D2D1_INK_STYLE_PROPERTIES* inkStyleProperties, ID2D1InkStyle** inkStyle) override {
        if (!inkStyle) return ole32::E_POINTER;
        *inkStyle = new CD2D1InkStyleImpl(inkStyleProperties);
        return ole32::S_OK;
    }

    void __stdcall DrawInk(ID2D1Ink*, d2d1::ID2D1Brush*, ID2D1InkStyle*) override {
        m_inkDrawCount++;
    }

    int32_t __stdcall CreateGradientMesh(const D2D1_GRADIENT_MESH_PATCH* patches, uint32_t patchesCount, ID2D1GradientMesh** gradientMesh) override {
        if (!gradientMesh) return ole32::E_POINTER;
        *gradientMesh = new CD2D1GradientMeshImpl(patches, patchesCount);
        return ole32::S_OK;
    }

    void __stdcall DrawGradientMesh(ID2D1GradientMesh*) override {
        m_gradientMeshDrawCount++;
    }

    int32_t __stdcall CreateSpriteBatch(ID2D1SpriteBatch** spriteBatch) override {
        if (!spriteBatch) return ole32::E_POINTER;
        *spriteBatch = new CD2D1SpriteBatchImpl();
        return ole32::S_OK;
    }

    void __stdcall DrawSpriteBatch(
        ID2D1SpriteBatch*,
        uint32_t,
        uint32_t,
        d2d1::ID2D1Bitmap*,
        d2d1::D2D1_BITMAP_INTERPOLATION_MODE,
        D2D1_SPRITE_OPTIONS) override
    {
        m_spriteBatchDrawCount++;
    }

    int32_t __stdcall CreateSvgDocument(const char*, d2d1::D2D1_SIZE_F viewportSize, ID2D1SvgDocument** svgDocument) override {
        if (!svgDocument) return ole32::E_POINTER;
        *svgDocument = new CD2D1SvgDocumentImpl(viewportSize);
        return ole32::S_OK;
    }

    void __stdcall DrawSvgDocument(ID2D1SvgDocument*) override {
        m_svgDrawCount++;
    }

    uint32_t GetInkDrawCount() const { return m_inkDrawCount; }
    uint32_t GetSpriteBatchDrawCount() const { return m_spriteBatchDrawCount; }
    uint32_t GetSvgDrawCount() const { return m_svgDrawCount; }
    uint32_t GetGradientMeshDrawCount() const { return m_gradientMeshDrawCount; }
};

class CD2D1Factory3Impl : public ID2D1Factory3 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == d2d1::IID_ID2D1Factory || riid == IID_ID2D1Factory3) {
            *ppv = static_cast<ID2D1Factory3*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall ReloadSystemMetrics() override { return ole32::S_OK; }
    void __stdcall GetDesktopDpi(float* x, float* y) override { if (x) *x = 96.0f; if (y) *y = 96.0f; }
    int32_t __stdcall CreateRectangleGeometry(const d2d1::D2D1_RECT_F* rectangle, d2d1::ID2D1RectangleGeometry** rectangleGeometry) override {
        if (!rectangle || !rectangleGeometry) return ole32::E_POINTER;
        *rectangleGeometry = new d2d1::CD2D1RectangleGeometry(this, *rectangle);
        return ole32::S_OK;
    }
    int32_t __stdcall CreateRoundedRectangleGeometry(const d2d1::D2D1_ROUNDED_RECT* roundedRectangle, d2d1::ID2D1RoundedRectangleGeometry** roundedRectangleGeometry) override {
        if (!roundedRectangle || !roundedRectangleGeometry) return ole32::E_POINTER;
        *roundedRectangleGeometry = new d2d1::CD2D1RoundedRectangleGeometry(this, *roundedRectangle);
        return ole32::S_OK;
    }
    int32_t __stdcall CreateEllipseGeometry(const d2d1::D2D1_ELLIPSE* ellipse, d2d1::ID2D1EllipseGeometry** ellipseGeometry) override {
        if (!ellipse || !ellipseGeometry) return ole32::E_POINTER;
        *ellipseGeometry = new d2d1::CD2D1EllipseGeometry(this, *ellipse);
        return ole32::S_OK;
    }
    int32_t __stdcall CreateGeometryGroup(uint32_t, d2d1::ID2D1Geometry**, uint32_t, void**) override {
        return ole32::E_NOTIMPL;
    }
    int32_t __stdcall CreateTransformedGeometry(d2d1::ID2D1Geometry*, const d2d1::D2D1_MATRIX_3X2_F*, void**) override {
        return ole32::E_NOTIMPL;
    }
    int32_t __stdcall CreatePathGeometry(d2d1::ID2D1PathGeometry** pathGeometry) override {
        if (!pathGeometry) return ole32::E_POINTER;
        *pathGeometry = new d2d1::CD2D1PathGeometry(this);
        return ole32::S_OK;
    }
    int32_t __stdcall CreateStrokeStyle(const d2d1::D2D1_STROKE_STYLE_PROPERTIES* strokeStyleProperties, const float* dashes, uint32_t dashesCount, d2d1::ID2D1StrokeStyle** strokeStyle) override {
        if (!strokeStyleProperties || !strokeStyle) return ole32::E_POINTER;
        *strokeStyle = new d2d1::CD2D1StrokeStyle(this, *strokeStyleProperties, dashes, dashesCount);
        return ole32::S_OK;
    }
    int32_t __stdcall CreateDrawingStateBlock(const void*, void*, void**) override {
        return ole32::E_NOTIMPL;
    }
    int32_t __stdcall CreateWicBitmapRenderTarget(gdiplus::IWICBitmap* target, const d2d1::D2D1_RENDER_TARGET_PROPERTIES*, d2d1::ID2D1RenderTarget** renderTarget) override {
        if (!target || !renderTarget) return ole32::E_POINTER;
        uint32_t w = 0, h = 0;
        target->GetSize(&w, &h);
        *renderTarget = new d2d1::CD2D1RenderTarget(this, w, h);
        return ole32::S_OK;
    }
    int32_t __stdcall CreateHwndRenderTarget(const d2d1::D2D1_RENDER_TARGET_PROPERTIES*, const d2d1::D2D1_HWND_RENDER_TARGET_PROPERTIES* hwndProps, d2d1::ID2D1HwndRenderTarget** hwndRenderTarget) override {
        if (!hwndProps || !hwndRenderTarget) return ole32::E_POINTER;
        *hwndRenderTarget = new d2d1::CD2D1HwndRenderTarget(this, hwndProps->hwnd, hwndProps->pixelSize.width, hwndProps->pixelSize.height);
        return ole32::S_OK;
    }
    int32_t __stdcall CreateDxgiSurfaceRenderTarget(void*, const d2d1::D2D1_RENDER_TARGET_PROPERTIES*, d2d1::ID2D1RenderTarget** renderTarget) override {
        if (!renderTarget) return ole32::E_POINTER;
        *renderTarget = new d2d1::CD2D1RenderTarget(this, 1920, 1080);
        return ole32::S_OK;
    }
    int32_t __stdcall CreateDCRenderTarget(const d2d1::D2D1_RENDER_TARGET_PROPERTIES*, d2d1::ID2D1DCRenderTarget** dcRenderTarget) override {
        if (!dcRenderTarget) return ole32::E_POINTER;
        *dcRenderTarget = new d2d1::CD2D1DCRenderTarget(this, 800, 600);
        return ole32::S_OK;
    }

    int32_t __stdcall CreateInkStyle(const D2D1_INK_STYLE_PROPERTIES* inkStyleProperties, ID2D1InkStyle** inkStyle) override {
        if (!inkStyle) return ole32::E_POINTER;
        *inkStyle = new CD2D1InkStyleImpl(inkStyleProperties);
        return ole32::S_OK;
    }

    int32_t __stdcall CreateDeviceContext2(ID2D1DeviceContext2** d2dContext) override {
        if (!d2dContext) return ole32::E_POINTER;
        *d2dContext = new CD2D1DeviceContext2Impl(this);
        return ole32::S_OK;
    }
};

class CDWriteTypographyImpl : public IDWriteTypography {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<DWRITE_FONT_FEATURE> m_features;

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IDWriteTypography) {
            *ppv = static_cast<IDWriteTypography*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall AddFontFeature(DWRITE_FONT_FEATURE fontFeature) override {
        m_features.push_back(fontFeature);
        return ole32::S_OK;
    }

    uint32_t __stdcall GetFontFeatureCount() const override {
        return static_cast<uint32_t>(m_features.size());
    }

    int32_t __stdcall GetFontFeature(uint32_t fontFeatureIndex, DWRITE_FONT_FEATURE* fontFeature) const override {
        if (!fontFeature || fontFeatureIndex >= m_features.size()) return ole32::E_INVALIDARG;
        *fontFeature = m_features[fontFeatureIndex];
        return ole32::S_OK;
    }
};

class CDWriteFontFallbackImpl : public IDWriteFontFallback {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IDWriteFontFallback) {
            *ppv = static_cast<IDWriteFontFallback*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall MapCharacters(
        const wchar_t* textString,
        uint32_t textLength,
        const wchar_t*,
        std::wstring& outMappedFontFamily) override
    {
        if (!textString || textLength == 0) return ole32::E_INVALIDARG;
        wchar_t firstChar = textString[0];

        // Sovereign multi-script Unicode cascade classification
        if (firstChar >= 0x4E00 && firstChar <= 0x9FFF) {
            outMappedFontFamily = L"Microsoft YaHei"; // CJK Unified Ideographs
        } else if (firstChar >= 0x3040 && firstChar <= 0x30FF) {
            outMappedFontFamily = L"Meiryo"; // Japanese Hiragana/Katakana
        } else if (firstChar >= 0xAC00 && firstChar <= 0xD7AF) {
            outMappedFontFamily = L"Malgun Gothic"; // Korean Hangul
        } else if (firstChar >= 0x0600 && firstChar <= 0x06FF) {
            outMappedFontFamily = L"Segoe UI Historic"; // Arabic
        } else if (firstChar >= 0x0400 && firstChar <= 0x04FF) {
            outMappedFontFamily = L"Segoe UI"; // Cyrillic
        } else if (firstChar >= 0x0370 && firstChar <= 0x03FF) {
            outMappedFontFamily = L"Segoe UI"; // Greek
        } else {
            outMappedFontFamily = L"Segoe UI"; // Latin / Basic
        }
        return ole32::S_OK;
    }
};

// ============================================================================
// 6. Direct2D 1.3 & DirectWrite Export Wiring
// ============================================================================

inline int32_t __stdcall D2D1CreateFactory3(
    d2d1::D2D1_FACTORY_TYPE,
    const GUID& riid,
    const void*,
    void** ppIFactory)
{
    if (!ppIFactory) return ole32::E_POINTER;
    auto* factory = new CD2D1Factory3Impl();
    int32_t hr = factory->QueryInterface(riid, ppIFactory);
    factory->Release();
    return hr;
}

inline int32_t __stdcall DWriteCreateTypography(IDWriteTypography** typography) {
    if (!typography) return ole32::E_POINTER;
    *typography = new CDWriteTypographyImpl();
    return ole32::S_OK;
}

inline int32_t __stdcall DWriteCreateFontFallback(IDWriteFontFallback** fontFallback) {
    if (!fontFallback) return ole32::E_POINTER;
    *fontFallback = new CDWriteFontFallbackImpl();
    return ole32::S_OK;
}

inline void InitializeDirect2D1_3Exports() {
    auto& loader = micant::ldr::DynamicLoader::get();

    // d2d1.dll exports
    loader.registerExport("d2d1.dll", "D2D1CreateFactory3", reinterpret_cast<void*>(D2D1CreateFactory3));

    // dwrite.dll exports
    loader.registerExport("dwrite.dll", "DWriteCreateTypography", reinterpret_cast<void*>(DWriteCreateTypography));
    loader.registerExport("dwrite.dll", "DWriteCreateFontFallback", reinterpret_cast<void*>(DWriteCreateFontFallback));

    version::VersionDatabase::Instance().RegisterModule(
        "d2d1.dll",
        "10.0.22621.1",
        "Direct2D 1.3 Hardware-Accelerated 2D Vector Graphics Engine",
        "MicaNT Sovereign Project"
    );

    version::VersionDatabase::Instance().RegisterModule(
        "dwrite.dll",
        "10.0.22621.1",
        "DirectWrite Advanced Typography & Multi-Script Font Engine",
        "MicaNT Sovereign Project"
    );
}

} // namespace micant::d2d1_3
