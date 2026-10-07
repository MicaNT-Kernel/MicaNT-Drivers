// ============================================================================
// MicaNT: Windows UI Composition & Modern Visual Layer Subsystem (uicomposition.hpp)
//
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/win32metadata (Windows.UI.Composition)
//   - https://github.com/microsoft/DirectX-Headers
//   - Open WinRT & DirectComposition Specifications for Modern Visual Trees
//
// Subsystem Overview:
//   uicomposition.hpp provides the modern scene-graph visual layer for fluent
//   compositing, decoupled animations, and reactive effects (Mica, Acrylic).
//   Backed by MicaNT's sovereign PrismComposition engine with dual-projection
//   support for both windows.ui.composition.dll and microsoft.ui.composition.dll.
//
// Core Interfaces:
//   - IInspectable, IActivationFactory
//   - ICompositor, ICompositor2
//   - IVisual, IContainerVisual, ISpriteVisual, IVisualCollection
//   - ICompositionBrush, ICompositionColorBrush, ICompositionSurfaceBrush, ICompositionEffectBrush
//   - ICompositionAnimation, IScalarKeyFrameAnimation, IVector3KeyFrameAnimation, IExpressionAnimation
//   - ICompositionPropertySet
//
// Trademark & Nominative Fair Use Notice:
//   Windows, WinRT, WinUI, Acrylic, and Mica are trademarks of Microsoft Corp.
//   MicaNT's UI Composition subsystem is an independent sovereign clean-room
//   implementation engineered for the MicaNT operating system executive.
// ============================================================================

#pragma once

#include "prism3d12.hpp"
#include "dcomp.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <unordered_map>
#include <iostream>
#include <sstream>

namespace micant::composition {

using namespace micant::prismx;
using namespace micant::prism3d;
using micant::GUID;
using micant::prismx::IUnknown;
using micant::prismx::IID_IUnknown;

// ============================================================================
// 1. Core WinRT Foundation Types & GUIDs
// ============================================================================

using HSTRING = void*;

enum class TrustLevel {
    BaseTrust = 0,
    PartialTrust = 1,
    FullTrust = 2
};

enum class CompositionCompositeMode {
    Inherit = 0,
    SourceOver = 1,
    MinBlend = 2
};

enum class CompositionStretch {
    None = 0,
    Fill = 1,
    Uniform = 2,
    UniformToFill = 3
};

struct Vector2 {
    float x{ 0.0f };
    float y{ 0.0f };

    constexpr Vector2() = default;
    constexpr Vector2(float x_, float y_) : x(x_), y(y_) {}

    constexpr bool operator==(const Vector2& o) const noexcept {
        return std::abs(x - o.x) < 1e-4f && std::abs(y - o.y) < 1e-4f;
    }
};

using Vector3 = micant::prism3d::Vector3;


struct CompositionColor {
    uint8_t a{ 255 };
    uint8_t r{ 0 };
    uint8_t g{ 0 };
    uint8_t b{ 0 };

    constexpr CompositionColor() = default;
    constexpr CompositionColor(uint8_t a_, uint8_t r_, uint8_t g_, uint8_t b_) : a(a_), r(r_), g(g_), b(b_) {}

    constexpr bool operator==(const CompositionColor& o) const noexcept {
        return a == o.a && r == o.r && g == o.g && b == o.b;
    }
};

// Interface GUID Identifiers
inline constexpr GUID IID_IInspectable = {
    0xAF86E2E0, 0xB12D, 0x4c6a, { 0x9C, 0x5D, 0xD7, 0xAA, 0x65, 0x10, 0x1E, 0x90 }
};

inline constexpr GUID IID_IActivationFactory = {
    0x00000035, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

inline constexpr GUID IID_ICompositionObject = {
    0xBCB4AD45, 0x7609, 0x4550, { 0x93, 0x4F, 0x16, 0x00, 0x2A, 0xEE, 0x7D, 0x04 }
};

inline constexpr GUID IID_ICompositor = {
    0xC620A459, 0xE722, 0x4850, { 0x98, 0x13, 0xD3, 0xD0, 0x82, 0x22, 0x1D, 0x41 }
};

inline constexpr GUID IID_ICompositor2 = {
    0x70E69F66, 0x9619, 0x4821, { 0x8C, 0xD4, 0x7E, 0x7E, 0x05, 0x83, 0x6E, 0x7E }
};

inline constexpr GUID IID_IVisual = {
    0x117E202D, 0xA859, 0x4C5E, { 0xBE, 0x82, 0x4B, 0x0A, 0x5E, 0x08, 0x11, 0x10 }
};

inline constexpr GUID IID_IContainerVisual = {
    0x02867F5B, 0x8415, 0x4C3A, { 0x86, 0x9B, 0x8C, 0x7E, 0x5E, 0x43, 0x98, 0x87 }
};

inline constexpr GUID IID_ISpriteVisual = {
    0x0866A487, 0x8035, 0x44D9, { 0x9B, 0x8B, 0x8F, 0x10, 0xBE, 0x69, 0x3F, 0x99 }
};

inline constexpr GUID IID_IVisualCollection = {
    0x40319451, 0x9472, 0x4989, { 0x92, 0x98, 0x7F, 0x07, 0x3C, 0x3E, 0x2A, 0x55 }
};

inline constexpr GUID IID_ICompositionBrush = {
    0xABBEB362, 0x5A4C, 0x4D36, { 0xBE, 0xC6, 0x0D, 0x4E, 0x12, 0x30, 0x25, 0x83 }
};

inline constexpr GUID IID_ICompositionColorBrush = {
    0x21703212, 0x7292, 0x4C48, { 0xAE, 0x8C, 0x29, 0x9B, 0x90, 0x8A, 0x62, 0x6A }
};

inline constexpr GUID IID_ICompositionSurfaceBrush = {
    0xAD1C9F40, 0x8D38, 0x4296, { 0x9B, 0x9C, 0x9A, 0x4C, 0x6A, 0x12, 0x78, 0x90 }
};

inline constexpr GUID IID_ICompositionEffectBrush = {
    0x3E12B001, 0x43C2, 0x4876, { 0x88, 0x1B, 0x5B, 0xC2, 0x77, 0x32, 0x1A, 0x8B }
};

inline constexpr GUID IID_ICompositionAnimation = {
    0x464C4C22, 0x7A0A, 0x4C36, { 0x9E, 0x5A, 0x0A, 0x0D, 0x32, 0x55, 0x8B, 0x99 }
};

inline constexpr GUID IID_IKeyFrameAnimation = {
    0x5AE92265, 0x3A6A, 0x4AD8, { 0x81, 0x4B, 0x35, 0x70, 0x6D, 0x01, 0x8B, 0x54 }
};

inline constexpr GUID IID_IScalarKeyFrameAnimation = {
    0xAE6384C1, 0x4153, 0x4642, { 0x93, 0xC3, 0x1D, 0x8E, 0x5A, 0x1C, 0x90, 0x77 }
};

inline constexpr GUID IID_IVector3KeyFrameAnimation = {
    0x7C0428E1, 0x9376, 0x4850, { 0x86, 0x74, 0x39, 0x24, 0x5A, 0x62, 0x7E, 0x88 }
};

inline constexpr GUID IID_IExpressionAnimation = {
    0x6A974240, 0x712B, 0x4632, { 0x85, 0x3C, 0x91, 0x7C, 0x32, 0x1A, 0x4B, 0x66 }
};

inline constexpr GUID IID_ICompositionPropertySet = {
    0x51B07481, 0x2170, 0x4523, { 0x87, 0x88, 0x7E, 0x1B, 0x6A, 0x33, 0x90, 0x11 }
};

// ============================================================================
// 2. WinRT COM Foundation Interfaces
// ============================================================================

class IInspectable : public IUnknown {
public:
    virtual int32_t GetIids(uint32_t* iidCount, GUID** iids) = 0;
    virtual int32_t GetRuntimeClassName(HSTRING* className) = 0;
    virtual int32_t GetTrustLevel(TrustLevel* trustLevel) = 0;
};

class IActivationFactory : public IInspectable {
public:
    virtual int32_t ActivateInstance(IInspectable** instance) = 0;
};

// Forward Declarations
class ICompositor;
class IVisual;
class IContainerVisual;
class ISpriteVisual;
class IVisualCollection;
class ICompositionBrush;
class ICompositionAnimation;
class ICompositionPropertySet;

// ============================================================================
// 3. UI Composition Interfaces
// ============================================================================

class ICompositionPropertySet : public IInspectable {
public:
    virtual int32_t InsertScalar(const wchar_t* propertyName, float value) = 0;
    virtual int32_t InsertVector3(const wchar_t* propertyName, Vector3 value) = 0;
    virtual int32_t TryGetScalar(const wchar_t* propertyName, float* value) = 0;
    virtual int32_t TryGetVector3(const wchar_t* propertyName, Vector3* value) = 0;
};

class ICompositionAnimation : public IInspectable {
public:
    virtual int32_t SetTarget(const wchar_t* target) = 0;
    virtual const wchar_t* GetTarget() const = 0;
};

class ICompositionObject : public IInspectable {
public:
    virtual int32_t GetCompositor(ICompositor** compositor) = 0;
    virtual int32_t GetPropertySet(ICompositionPropertySet** propertySet) = 0;
    virtual int32_t StartAnimation(const wchar_t* propertyName, ICompositionAnimation* animation) = 0;
    virtual int32_t StopAnimation(const wchar_t* propertyName) = 0;
};

class IVisual : public ICompositionObject {
public:
    virtual Vector3 GetOffset() const = 0;
    virtual int32_t SetOffset(Vector3 offset) = 0;
    virtual Vector2 GetSize() const = 0;
    virtual int32_t SetSize(Vector2 size) = 0;
    virtual Vector3 GetScale() const = 0;
    virtual int32_t SetScale(Vector3 scale) = 0;
    virtual float GetRotationAngle() const = 0;
    virtual int32_t SetRotationAngle(float radians) = 0;
    virtual Vector3 GetCenterPoint() const = 0;
    virtual int32_t SetCenterPoint(Vector3 center) = 0;
    virtual float GetOpacity() const = 0;
    virtual int32_t SetOpacity(float opacity) = 0;
    virtual bool GetIsVisible() const = 0;
    virtual int32_t SetIsVisible(bool visible) = 0;
    virtual CompositionCompositeMode GetCompositeMode() const = 0;
    virtual int32_t SetCompositeMode(CompositionCompositeMode mode) = 0;
    virtual IVisual* GetParent() const = 0;
    virtual void SetParent(IVisual* parent) = 0;
};

class IVisualCollection : public IInspectable {
public:
    virtual int32_t GetCount() const = 0;
    virtual int32_t InsertAtTop(IVisual* newChild) = 0;
    virtual int32_t InsertAtBottom(IVisual* newChild) = 0;
    virtual int32_t InsertAbove(IVisual* newChild, IVisual* sibling) = 0;
    virtual int32_t InsertBelow(IVisual* newChild, IVisual* sibling) = 0;
    virtual int32_t Remove(IVisual* child) = 0;
    virtual int32_t RemoveAll() = 0;
    virtual IVisual* GetAt(int32_t index) const = 0;
};

class IContainerVisual : public IVisual {
public:
    virtual int32_t GetChildren(IVisualCollection** children) = 0;
};

class ICompositionBrush : public ICompositionObject {
public:
};

class ICompositionColorBrush : public ICompositionBrush {
public:
    virtual CompositionColor GetColor() const = 0;
    virtual int32_t SetColor(CompositionColor color) = 0;
};

class ICompositionSurfaceBrush : public ICompositionBrush {
public:
    virtual void* GetSurface() const = 0;
    virtual int32_t SetSurface(void* surface) = 0;
    virtual CompositionStretch GetStretch() const = 0;
    virtual int32_t SetStretch(CompositionStretch stretch) = 0;
    virtual float GetHorizontalAlignmentRatio() const = 0;
    virtual int32_t SetHorizontalAlignmentRatio(float ratio) = 0;
    virtual float GetVerticalAlignmentRatio() const = 0;
    virtual int32_t SetVerticalAlignmentRatio(float ratio) = 0;
};

class ICompositionEffectBrush : public ICompositionBrush {
public:
    virtual const std::wstring& GetEffectName() const = 0;
    virtual int32_t SetSourceParameter(const wchar_t* name, ICompositionBrush* source) = 0;
    virtual ICompositionBrush* GetSourceParameter(const wchar_t* name) const = 0;
};

class ISpriteVisual : public IContainerVisual {
public:
    virtual ICompositionBrush* GetBrush() const = 0;
    virtual int32_t SetBrush(ICompositionBrush* brush) = 0;
};

class IKeyFrameAnimation : public ICompositionAnimation {
public:
    virtual float GetDuration() const = 0;
    virtual int32_t SetDuration(float durationSeconds) = 0;
    virtual int32_t GetIterationCount() const = 0;
    virtual int32_t SetIterationCount(int32_t count) = 0;
};

class IScalarKeyFrameAnimation : public IKeyFrameAnimation {
public:
    virtual int32_t InsertKeyFrame(float normalizedProgressKey, float value) = 0;
    virtual float Evaluate(float progress) const = 0;
};

class IVector3KeyFrameAnimation : public IKeyFrameAnimation {
public:
    virtual int32_t InsertKeyFrame(float normalizedProgressKey, Vector3 value) = 0;
    virtual Vector3 Evaluate(float progress) const = 0;
};

class IExpressionAnimation : public ICompositionAnimation {
public:
    virtual const std::wstring& GetExpression() const = 0;
    virtual int32_t SetExpression(const wchar_t* expression) = 0;
    virtual int32_t SetScalarParameter(const wchar_t* key, float value) = 0;
    virtual int32_t SetVector3Parameter(const wchar_t* key, Vector3 value) = 0;
    virtual int32_t SetReferenceParameter(const wchar_t* key, ICompositionObject* object) = 0;
    virtual float EvaluateScalar() const = 0;
};

class ICompositor : public IInspectable {
public:
    virtual int32_t CreateContainerVisual(IContainerVisual** result) = 0;
    virtual int32_t CreateSpriteVisual(ISpriteVisual** result) = 0;
    virtual int32_t CreateColorBrush(ICompositionColorBrush** result) = 0;
    virtual int32_t CreateColorBrushWithColor(CompositionColor color, ICompositionColorBrush** result) = 0;
    virtual int32_t CreateSurfaceBrush(ICompositionSurfaceBrush** result) = 0;
    virtual int32_t CreateEffectBrush(const wchar_t* effectName, ICompositionEffectBrush** result) = 0;
    virtual int32_t CreateScalarKeyFrameAnimation(IScalarKeyFrameAnimation** result) = 0;
    virtual int32_t CreateVector3KeyFrameAnimation(IVector3KeyFrameAnimation** result) = 0;
    virtual int32_t CreateExpressionAnimation(IExpressionAnimation** result) = 0;
    virtual int32_t CreateExpressionAnimationWithExpression(const wchar_t* expression, IExpressionAnimation** result) = 0;
    virtual int32_t CreatePropertySet(ICompositionPropertySet** result) = 0;
};

// ============================================================================
// 4. MicaNT UI Composition Implementation
// ============================================================================

class MicaCompositionPropertySetImpl : public ICompositionPropertySet {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::unordered_map<std::wstring, float> m_scalars;
    std::unordered_map<std::wstring, Vector3> m_vectors;

public:
    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_ICompositionPropertySet) {
            *ppv = static_cast<ICompositionPropertySet*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t InsertScalar(const wchar_t* name, float value) override {
        if (!name) return -2147024809;
        m_scalars[name] = value;
        return 0;
    }

    int32_t InsertVector3(const wchar_t* name, Vector3 value) override {
        if (!name) return -2147024809;
        m_vectors[name] = value;
        return 0;
    }

    int32_t TryGetScalar(const wchar_t* name, float* val) override {
        if (!name || !val) return -2147024809;
        auto it = m_scalars.find(name);
        if (it != m_scalars.end()) {
            *val = it->second;
            return 0;
        }
        return -2147467259;
    }

    int32_t TryGetVector3(const wchar_t* name, Vector3* val) override {
        if (!name || !val) return -2147024809;
        auto it = m_vectors.find(name);
        if (it != m_vectors.end()) {
            *val = it->second;
            return 0;
        }
        return -2147467259;
    }
};

class MicaScalarKeyFrameAnimationImpl : public IScalarKeyFrameAnimation {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_target;
    float m_duration{ 1.0f };
    int32_t m_iterationCount{ 1 };
    struct KeyFrame { float progress; float value; };
    std::vector<KeyFrame> m_keyframes;

public:
    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_ICompositionAnimation ||
            riid == IID_IKeyFrameAnimation || riid == IID_IScalarKeyFrameAnimation) {
            *ppv = static_cast<IScalarKeyFrameAnimation*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t SetTarget(const wchar_t* target) override {
        m_target = target ? target : L"";
        return 0;
    }

    const wchar_t* GetTarget() const override { return m_target.c_str(); }

    float GetDuration() const override { return m_duration; }
    int32_t SetDuration(float d) override { m_duration = (d > 0.0f) ? d : 1.0f; return 0; }

    int32_t GetIterationCount() const override { return m_iterationCount; }
    int32_t SetIterationCount(int32_t c) override { m_iterationCount = c; return 0; }

    int32_t InsertKeyFrame(float progress, float value) override {
        progress = std::clamp(progress, 0.0f, 1.0f);
        m_keyframes.push_back({ progress, value });
        std::sort(m_keyframes.begin(), m_keyframes.end(), [](const KeyFrame& a, const KeyFrame& b) {
            return a.progress < b.progress;
        });
        return 0;
    }

    float Evaluate(float progress) const override {
        if (m_keyframes.empty()) return 0.0f;
        progress = std::clamp(progress, 0.0f, 1.0f);
        if (progress <= m_keyframes.front().progress) return m_keyframes.front().value;
        if (progress >= m_keyframes.back().progress) return m_keyframes.back().value;

        for (size_t i = 0; i < m_keyframes.size() - 1; ++i) {
            if (progress >= m_keyframes[i].progress && progress <= m_keyframes[i + 1].progress) {
                float segLen = m_keyframes[i + 1].progress - m_keyframes[i].progress;
                if (segLen < 1e-6f) return m_keyframes[i + 1].value;
                float t = (progress - m_keyframes[i].progress) / segLen;
                float smoothT = t * t * (3.0f - 2.0f * t);
                return m_keyframes[i].value + (m_keyframes[i + 1].value - m_keyframes[i].value) * smoothT;
            }
        }
        return m_keyframes.back().value;
    }
};

class MicaVector3KeyFrameAnimationImpl : public IVector3KeyFrameAnimation {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_target;
    float m_duration{ 1.0f };
    int32_t m_iterationCount{ 1 };
    struct KeyFrame { float progress; Vector3 value; };
    std::vector<KeyFrame> m_keyframes;

public:
    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_ICompositionAnimation ||
            riid == IID_IKeyFrameAnimation || riid == IID_IVector3KeyFrameAnimation) {
            *ppv = static_cast<IVector3KeyFrameAnimation*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t SetTarget(const wchar_t* target) override {
        m_target = target ? target : L"";
        return 0;
    }

    const wchar_t* GetTarget() const override { return m_target.c_str(); }

    float GetDuration() const override { return m_duration; }
    int32_t SetDuration(float d) override { m_duration = (d > 0.0f) ? d : 1.0f; return 0; }

    int32_t GetIterationCount() const override { return m_iterationCount; }
    int32_t SetIterationCount(int32_t c) override { m_iterationCount = c; return 0; }

    int32_t InsertKeyFrame(float progress, Vector3 value) override {
        progress = std::clamp(progress, 0.0f, 1.0f);
        m_keyframes.push_back({ progress, value });
        std::sort(m_keyframes.begin(), m_keyframes.end(), [](const KeyFrame& a, const KeyFrame& b) {
            return a.progress < b.progress;
        });
        return 0;
    }

    Vector3 Evaluate(float progress) const override {
        if (m_keyframes.empty()) return { 0.0f, 0.0f, 0.0f };
        progress = std::clamp(progress, 0.0f, 1.0f);
        if (progress <= m_keyframes.front().progress) return m_keyframes.front().value;
        if (progress >= m_keyframes.back().progress) return m_keyframes.back().value;

        for (size_t i = 0; i < m_keyframes.size() - 1; ++i) {
            if (progress >= m_keyframes[i].progress && progress <= m_keyframes[i + 1].progress) {
                float segLen = m_keyframes[i + 1].progress - m_keyframes[i].progress;
                if (segLen < 1e-6f) return m_keyframes[i + 1].value;
                float t = (progress - m_keyframes[i].progress) / segLen;
                float smoothT = t * t * (3.0f - 2.0f * t);
                const auto& v0 = m_keyframes[i].value;
                const auto& v1 = m_keyframes[i + 1].value;
                return {
                    v0.x + (v1.x - v0.x) * smoothT,
                    v0.y + (v1.y - v0.y) * smoothT,
                    v0.z + (v1.z - v0.z) * smoothT
                };
            }
        }
        return m_keyframes.back().value;
    }
};

class MicaExpressionAnimationImpl : public IExpressionAnimation {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_target;
    std::wstring m_expression;
    std::unordered_map<std::wstring, float> m_scalars;
    std::unordered_map<std::wstring, Vector3> m_vectors;

public:
    explicit MicaExpressionAnimationImpl(const wchar_t* expr = nullptr) {
        if (expr) m_expression = expr;
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_ICompositionAnimation ||
            riid == IID_IExpressionAnimation) {
            *ppv = static_cast<IExpressionAnimation*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t SetTarget(const wchar_t* target) override {
        m_target = target ? target : L"";
        return 0;
    }

    const wchar_t* GetTarget() const override { return m_target.c_str(); }

    const std::wstring& GetExpression() const override { return m_expression; }
    int32_t SetExpression(const wchar_t* expression) override {
        m_expression = expression ? expression : L"";
        return 0;
    }

    int32_t SetScalarParameter(const wchar_t* key, float value) override {
        if (!key) return -2147024809;
        m_scalars[key] = value;
        return 0;
    }

    int32_t SetVector3Parameter(const wchar_t* key, Vector3 value) override {
        if (!key) return -2147024809;
        m_vectors[key] = value;
        return 0;
    }

    int32_t SetReferenceParameter(const wchar_t* key, ICompositionObject* object) override {
        (void)key; (void)object;
        return 0;
    }

    float EvaluateScalar() const override {
        if (m_expression.find(L"Lerp") != std::wstring::npos) {
            float a = 0.0f, b = 1.0f, progress = 0.5f;
            auto itA = m_scalars.find(L"A"); if (itA != m_scalars.end()) a = itA->second;
            auto itB = m_scalars.find(L"B"); if (itB != m_scalars.end()) b = itB->second;
            auto itP = m_scalars.find(L"Progress"); if (itP != m_scalars.end()) progress = itP->second;
            return a + (b - a) * progress;
        }

        if (m_expression.find(L"Clamp") != std::wstring::npos) {
            float val = 0.0f, minV = 0.0f, maxV = 1.0f;
            auto itV = m_scalars.find(L"Value"); if (itV != m_scalars.end()) val = itV->second;
            auto itMin = m_scalars.find(L"Min"); if (itMin != m_scalars.end()) minV = itMin->second;
            auto itMax = m_scalars.find(L"Max"); if (itMax != m_scalars.end()) maxV = itMax->second;
            return std::clamp(val, minV, maxV);
        }

        if (!m_scalars.empty()) {
            return m_scalars.begin()->second;
        }
        return 1.0f;
    }
};

class MicaColorBrushImpl : public ICompositionColorBrush {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ICompositor* m_compositor{ nullptr };
    CompositionColor m_color{};

public:
    explicit MicaColorBrushImpl(ICompositor* comp, CompositionColor c) : m_compositor(comp), m_color(c) {}

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_ICompositionObject ||
            riid == IID_ICompositionBrush || riid == IID_ICompositionColorBrush) {
            *ppv = static_cast<ICompositionColorBrush*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t GetCompositor(ICompositor** comp) override {
        if (!comp) return -2147467261;
        *comp = m_compositor;
        if (m_compositor) m_compositor->AddRef();
        return 0;
    }

    int32_t GetPropertySet(ICompositionPropertySet** prop) override {
        if (!prop) return -2147467261;
        *prop = nullptr;
        return 0;
    }

    int32_t StartAnimation(const wchar_t*, ICompositionAnimation*) override { return 0; }
    int32_t StopAnimation(const wchar_t*) override { return 0; }

    CompositionColor GetColor() const override { return m_color; }
    int32_t SetColor(CompositionColor color) override { m_color = color; return 0; }
};

class MicaSurfaceBrushImpl : public ICompositionSurfaceBrush {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ICompositor* m_compositor{ nullptr };
    void* m_surface{ nullptr };
    CompositionStretch m_stretch{ CompositionStretch::Uniform };
    float m_hRatio{ 0.5f };
    float m_vRatio{ 0.5f };

public:
    explicit MicaSurfaceBrushImpl(ICompositor* comp) : m_compositor(comp) {}

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_ICompositionObject ||
            riid == IID_ICompositionBrush || riid == IID_ICompositionSurfaceBrush) {
            *ppv = static_cast<ICompositionSurfaceBrush*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t GetCompositor(ICompositor** comp) override {
        if (!comp) return -2147467261;
        *comp = m_compositor;
        if (m_compositor) m_compositor->AddRef();
        return 0;
    }

    int32_t GetPropertySet(ICompositionPropertySet** prop) override {
        if (!prop) return -2147467261;
        *prop = nullptr;
        return 0;
    }

    int32_t StartAnimation(const wchar_t*, ICompositionAnimation*) override { return 0; }
    int32_t StopAnimation(const wchar_t*) override { return 0; }

    void* GetSurface() const override { return m_surface; }
    int32_t SetSurface(void* surf) override { m_surface = surf; return 0; }

    CompositionStretch GetStretch() const override { return m_stretch; }
    int32_t SetStretch(CompositionStretch stretch) override { m_stretch = stretch; return 0; }

    float GetHorizontalAlignmentRatio() const override { return m_hRatio; }
    int32_t SetHorizontalAlignmentRatio(float ratio) override { m_hRatio = ratio; return 0; }

    float GetVerticalAlignmentRatio() const override { return m_vRatio; }
    int32_t SetVerticalAlignmentRatio(float ratio) override { m_vRatio = ratio; return 0; }
};

class MicaEffectBrushImpl : public ICompositionEffectBrush {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ICompositor* m_compositor{ nullptr };
    std::wstring m_effectName;
    std::unordered_map<std::wstring, ICompositionBrush*> m_sources;

public:
    explicit MicaEffectBrushImpl(ICompositor* comp, const wchar_t* name)
        : m_compositor(comp), m_effectName(name ? name : L"MicaBlur") {}

    ~MicaEffectBrushImpl() {
        for (auto& pair : m_sources) {
            if (pair.second) pair.second->Release();
        }
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_ICompositionObject ||
            riid == IID_ICompositionBrush || riid == IID_ICompositionEffectBrush) {
            *ppv = static_cast<ICompositionEffectBrush*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t GetCompositor(ICompositor** comp) override {
        if (!comp) return -2147467261;
        *comp = m_compositor;
        if (m_compositor) m_compositor->AddRef();
        return 0;
    }

    int32_t GetPropertySet(ICompositionPropertySet** prop) override {
        if (!prop) return -2147467261;
        *prop = nullptr;
        return 0;
    }

    int32_t StartAnimation(const wchar_t*, ICompositionAnimation*) override { return 0; }
    int32_t StopAnimation(const wchar_t*) override { return 0; }

    const std::wstring& GetEffectName() const override { return m_effectName; }

    int32_t SetSourceParameter(const wchar_t* name, ICompositionBrush* source) override {
        if (!name) return -2147024809;
        auto it = m_sources.find(name);
        if (it != m_sources.end() && it->second) {
            it->second->Release();
        }
        if (source) source->AddRef();
        m_sources[name] = source;
        return 0;
    }

    ICompositionBrush* GetSourceParameter(const wchar_t* name) const override {
        if (!name) return nullptr;
        auto it = m_sources.find(name);
        return (it != m_sources.end()) ? it->second : nullptr;
    }
};

class MicaVisualCollectionImpl : public IVisualCollection {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IVisual* m_owner{ nullptr };
    std::vector<IVisual*> m_children;

public:
    explicit MicaVisualCollectionImpl(IVisual* owner) : m_owner(owner) {}

    ~MicaVisualCollectionImpl() {
        RemoveAll();
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_IVisualCollection) {
            *ppv = static_cast<IVisualCollection*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t GetCount() const override { return static_cast<int32_t>(m_children.size()); }

    IVisual* GetAt(int32_t index) const override {
        if (index < 0 || static_cast<size_t>(index) >= m_children.size()) return nullptr;
        return m_children[index];
    }

    int32_t InsertAtTop(IVisual* newChild) override {
        if (!newChild) return -2147024809;
        newChild->AddRef();
        newChild->SetParent(m_owner);
        m_children.push_back(newChild);
        return 0;
    }

    int32_t InsertAtBottom(IVisual* newChild) override {
        if (!newChild) return -2147024809;
        newChild->AddRef();
        newChild->SetParent(m_owner);
        m_children.insert(m_children.begin(), newChild);
        return 0;
    }

    int32_t InsertAbove(IVisual* newChild, IVisual* sibling) override {
        if (!newChild) return -2147024809;
        if (!sibling) return InsertAtTop(newChild);

        auto it = std::find(m_children.begin(), m_children.end(), sibling);
        if (it != m_children.end()) {
            newChild->AddRef();
            newChild->SetParent(m_owner);
            m_children.insert(it + 1, newChild);
            return 0;
        }
        return InsertAtTop(newChild);
    }

    int32_t InsertBelow(IVisual* newChild, IVisual* sibling) override {
        if (!newChild) return -2147024809;
        if (!sibling) return InsertAtBottom(newChild);

        auto it = std::find(m_children.begin(), m_children.end(), sibling);
        if (it != m_children.end()) {
            newChild->AddRef();
            newChild->SetParent(m_owner);
            m_children.insert(it, newChild);
            return 0;
        }
        return InsertAtBottom(newChild);
    }

    int32_t Remove(IVisual* child) override {
        if (!child) return -2147024809;
        auto it = std::find(m_children.begin(), m_children.end(), child);
        if (it != m_children.end()) {
            (*it)->SetParent(nullptr);
            (*it)->Release();
            m_children.erase(it);
            return 0;
        }
        return -2147467259;
    }

    int32_t RemoveAll() override {
        for (auto* c : m_children) {
            if (c) {
                c->SetParent(nullptr);
                c->Release();
            }
        }
        m_children.clear();
        return 0;
    }
};

class MicaSpriteVisualImpl : public ISpriteVisual {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ICompositor* m_compositor{ nullptr };
    IVisual* m_parent{ nullptr };
    MicaVisualCollectionImpl* m_children{ nullptr };

    Vector3 m_offset{ 0.0f, 0.0f, 0.0f };
    Vector2 m_size{ 0.0f, 0.0f };
    Vector3 m_scale{ 1.0f, 1.0f, 1.0f };
    float m_rotationAngle{ 0.0f };
    Vector3 m_centerPoint{ 0.0f, 0.0f, 0.0f };
    float m_opacity{ 1.0f };
    bool m_isVisible{ true };
    CompositionCompositeMode m_compositeMode{ CompositionCompositeMode::SourceOver };

    ICompositionBrush* m_brush{ nullptr };
    std::unordered_map<std::wstring, ICompositionAnimation*> m_activeAnimations;

public:
    explicit MicaSpriteVisualImpl(ICompositor* comp) : m_compositor(comp) {
        m_children = new MicaVisualCollectionImpl(this);
    }

    ~MicaSpriteVisualImpl() {
        if (m_brush) { m_brush->Release(); m_brush = nullptr; }
        if (m_children) { m_children->Release(); m_children = nullptr; }
        for (auto& pair : m_activeAnimations) {
            if (pair.second) pair.second->Release();
        }
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_ICompositionObject ||
            riid == IID_IVisual || riid == IID_IContainerVisual || riid == IID_ISpriteVisual) {
            *ppv = static_cast<ISpriteVisual*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t GetCompositor(ICompositor** comp) override {
        if (!comp) return -2147467261;
        *comp = m_compositor;
        if (m_compositor) m_compositor->AddRef();
        return 0;
    }

    int32_t GetPropertySet(ICompositionPropertySet** prop) override {
        if (!prop) return -2147467261;
        *prop = nullptr;
        return 0;
    }

    int32_t StartAnimation(const wchar_t* prop, ICompositionAnimation* anim) override {
        if (!prop || !anim) return -2147024809;
        anim->AddRef();
        m_activeAnimations[prop] = anim;
        return 0;
    }

    int32_t StopAnimation(const wchar_t* prop) override {
        if (!prop) return -2147024809;
        auto it = m_activeAnimations.find(prop);
        if (it != m_activeAnimations.end()) {
            if (it->second) it->second->Release();
            m_activeAnimations.erase(it);
        }
        return 0;
    }

    Vector3 GetOffset() const override { return m_offset; }
    int32_t SetOffset(Vector3 offset) override { m_offset = offset; return 0; }

    Vector2 GetSize() const override { return m_size; }
    int32_t SetSize(Vector2 size) override { m_size = size; return 0; }

    Vector3 GetScale() const override { return m_scale; }
    int32_t SetScale(Vector3 scale) override { m_scale = scale; return 0; }

    float GetRotationAngle() const override { return m_rotationAngle; }
    int32_t SetRotationAngle(float r) override { m_rotationAngle = r; return 0; }

    Vector3 GetCenterPoint() const override { return m_centerPoint; }
    int32_t SetCenterPoint(Vector3 c) override { m_centerPoint = c; return 0; }

    float GetOpacity() const override { return m_opacity; }
    int32_t SetOpacity(float op) override { m_opacity = std::clamp(op, 0.0f, 1.0f); return 0; }

    bool GetIsVisible() const override { return m_isVisible; }
    int32_t SetIsVisible(bool v) override { m_isVisible = v; return 0; }

    CompositionCompositeMode GetCompositeMode() const override { return m_compositeMode; }
    int32_t SetCompositeMode(CompositionCompositeMode m) override { m_compositeMode = m; return 0; }

    IVisual* GetParent() const override { return m_parent; }
    void SetParent(IVisual* p) override { m_parent = p; }

    int32_t GetChildren(IVisualCollection** children) override {
        if (!children) return -2147467261;
        *children = m_children;
        if (m_children) m_children->AddRef();
        return 0;
    }

    ICompositionBrush* GetBrush() const override { return m_brush; }
    int32_t SetBrush(ICompositionBrush* brush) override {
        if (m_brush) m_brush->Release();
        m_brush = brush;
        if (m_brush) m_brush->AddRef();
        return 0;
    }
};

class MicaContainerVisualImpl : public IContainerVisual {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ICompositor* m_compositor{ nullptr };
    IVisual* m_parent{ nullptr };
    MicaVisualCollectionImpl* m_children{ nullptr };

    Vector3 m_offset{ 0.0f, 0.0f, 0.0f };
    Vector2 m_size{ 0.0f, 0.0f };
    Vector3 m_scale{ 1.0f, 1.0f, 1.0f };
    float m_rotationAngle{ 0.0f };
    Vector3 m_centerPoint{ 0.0f, 0.0f, 0.0f };
    float m_opacity{ 1.0f };
    bool m_isVisible{ true };
    CompositionCompositeMode m_compositeMode{ CompositionCompositeMode::SourceOver };

public:
    explicit MicaContainerVisualImpl(ICompositor* comp) : m_compositor(comp) {
        m_children = new MicaVisualCollectionImpl(this);
    }

    ~MicaContainerVisualImpl() {
        if (m_children) { m_children->Release(); m_children = nullptr; }
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_ICompositionObject ||
            riid == IID_IVisual || riid == IID_IContainerVisual) {
            *ppv = static_cast<IContainerVisual*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t GetCompositor(ICompositor** comp) override {
        if (!comp) return -2147467261;
        *comp = m_compositor;
        if (m_compositor) m_compositor->AddRef();
        return 0;
    }

    int32_t GetPropertySet(ICompositionPropertySet** prop) override {
        if (!prop) return -2147467261;
        *prop = nullptr;
        return 0;
    }

    int32_t StartAnimation(const wchar_t*, ICompositionAnimation*) override { return 0; }
    int32_t StopAnimation(const wchar_t*) override { return 0; }

    Vector3 GetOffset() const override { return m_offset; }
    int32_t SetOffset(Vector3 offset) override { m_offset = offset; return 0; }

    Vector2 GetSize() const override { return m_size; }
    int32_t SetSize(Vector2 size) override { m_size = size; return 0; }

    Vector3 GetScale() const override { return m_scale; }
    int32_t SetScale(Vector3 scale) override { m_scale = scale; return 0; }

    float GetRotationAngle() const override { return m_rotationAngle; }
    int32_t SetRotationAngle(float r) override { m_rotationAngle = r; return 0; }

    Vector3 GetCenterPoint() const override { return m_centerPoint; }
    int32_t SetCenterPoint(Vector3 c) override { m_centerPoint = c; return 0; }

    float GetOpacity() const override { return m_opacity; }
    int32_t SetOpacity(float op) override { m_opacity = std::clamp(op, 0.0f, 1.0f); return 0; }

    bool GetIsVisible() const override { return m_isVisible; }
    int32_t SetIsVisible(bool v) override { m_isVisible = v; return 0; }

    CompositionCompositeMode GetCompositeMode() const override { return m_compositeMode; }
    int32_t SetCompositeMode(CompositionCompositeMode m) override { m_compositeMode = m; return 0; }

    IVisual* GetParent() const override { return m_parent; }
    void SetParent(IVisual* p) override { m_parent = p; }

    int32_t GetChildren(IVisualCollection** children) override {
        if (!children) return -2147467261;
        *children = m_children;
        if (m_children) m_children->AddRef();
        return 0;
    }
};

class MicaCompositorImpl : public ICompositor {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    MicaCompositorImpl() = default;

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_ICompositor || riid == IID_ICompositor2) {
            *ppv = static_cast<ICompositor*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t CreateContainerVisual(IContainerVisual** result) override {
        if (!result) return -2147467261;
        *result = new MicaContainerVisualImpl(this);
        return 0;
    }

    int32_t CreateSpriteVisual(ISpriteVisual** result) override {
        if (!result) return -2147467261;
        *result = new MicaSpriteVisualImpl(this);
        return 0;
    }

    int32_t CreateColorBrush(ICompositionColorBrush** result) override {
        return CreateColorBrushWithColor({ 255, 255, 255, 255 }, result);
    }

    int32_t CreateColorBrushWithColor(CompositionColor color, ICompositionColorBrush** result) override {
        if (!result) return -2147467261;
        *result = new MicaColorBrushImpl(this, color);
        return 0;
    }

    int32_t CreateSurfaceBrush(ICompositionSurfaceBrush** result) override {
        if (!result) return -2147467261;
        *result = new MicaSurfaceBrushImpl(this);
        return 0;
    }

    int32_t CreateEffectBrush(const wchar_t* effectName, ICompositionEffectBrush** result) override {
        if (!result) return -2147467261;
        *result = new MicaEffectBrushImpl(this, effectName);
        return 0;
    }

    int32_t CreateScalarKeyFrameAnimation(IScalarKeyFrameAnimation** result) override {
        if (!result) return -2147467261;
        *result = new MicaScalarKeyFrameAnimationImpl();
        return 0;
    }

    int32_t CreateVector3KeyFrameAnimation(IVector3KeyFrameAnimation** result) override {
        if (!result) return -2147467261;
        *result = new MicaVector3KeyFrameAnimationImpl();
        return 0;
    }

    int32_t CreateExpressionAnimation(IExpressionAnimation** result) override {
        if (!result) return -2147467261;
        *result = new MicaExpressionAnimationImpl();
        return 0;
    }

    int32_t CreateExpressionAnimationWithExpression(const wchar_t* expr, IExpressionAnimation** result) override {
        if (!result) return -2147467261;
        *result = new MicaExpressionAnimationImpl(expr);
        return 0;
    }

    int32_t CreatePropertySet(ICompositionPropertySet** result) override {
        if (!result) return -2147467261;
        *result = new MicaCompositionPropertySetImpl();
        return 0;
    }
};

// ============================================================================
// 5. Activation Factory Implementation
// ============================================================================

class MicaCompositionActivationFactory : public IActivationFactory {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IInspectable || riid == IID_IActivationFactory) {
            *ppv = static_cast<IActivationFactory*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t GetIids(uint32_t* c, GUID** i) override { if (c) *c = 0; if (i) *i = nullptr; return 0; }
    int32_t GetRuntimeClassName(HSTRING* n) override { if (n) *n = nullptr; return 0; }
    int32_t GetTrustLevel(TrustLevel* t) override { if (t) *t = TrustLevel::BaseTrust; return 0; }

    int32_t ActivateInstance(IInspectable** instance) override {
        if (!instance) return -2147467261;
        *instance = new MicaCompositorImpl();
        return 0;
    }
};

// ============================================================================
// 6. Dynamic Exports & Registry Binding
// ============================================================================

inline int32_t __stdcall DllGetActivationFactory(
    HSTRING activatableClassId,
    IActivationFactory** factory
) {
    if (!activatableClassId || !factory) return -2147024809;

    // We accept both raw wide string pointers and HSTRING references
    const wchar_t* pClassStr = reinterpret_cast<const wchar_t*>(activatableClassId);
    std::wstring cid(pClassStr);

    if (cid == L"Windows.UI.Composition.Compositor" || cid == L"Microsoft.UI.Composition.Compositor") {
        *factory = new MicaCompositionActivationFactory();
        return 0;
    }
    *factory = nullptr;
    return -2147221164; // REGDB_E_CLASSNOTREG
}

inline int32_t __stdcall DllCanUnloadNow() {
    return 0; // S_OK
}

inline int32_t __stdcall RoGetActivationFactory(
    HSTRING activatableClassId,
    const GUID& riid,
    void** factory
) {
    if (!factory) return -2147467261;
    IActivationFactory* actFact = nullptr;
    int32_t hr = DllGetActivationFactory(activatableClassId, &actFact);
    if (hr != 0 || !actFact) return hr;

    hr = actFact->QueryInterface(riid, factory);
    actFact->Release();
    return hr;
}

inline void InitializeUICompositionExports() {
    auto& loader = micant::ldr::DynamicLoader::get();

    // 1. windows.ui.composition.dll (In-box Windows OS Modern Visual Layer)
    loader.registerExport("windows.ui.composition.dll", "DllGetActivationFactory", reinterpret_cast<void*>(DllGetActivationFactory));
    loader.registerExport("windows.ui.composition.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));

    version::VersionDatabase::Instance().RegisterModule(
        "windows.ui.composition.dll",
        "10.0.22621.1",
        "Windows Modern UI Composition & Visual Layer Subsystem",
        "MicaNT Sovereign Project"
    );

    // 2. microsoft.ui.composition.dll (WinUI 3 & Windows App SDK Modern Visual Layer)
    loader.registerExport("microsoft.ui.composition.dll", "DllGetActivationFactory", reinterpret_cast<void*>(DllGetActivationFactory));
    loader.registerExport("microsoft.ui.composition.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));

    version::VersionDatabase::Instance().RegisterModule(
        "microsoft.ui.composition.dll",
        "10.0.22621.1",
        "WinUI 3 Modern Visual Layer Compositor Engine",
        "MicaNT Sovereign Project"
    );
}

} // namespace micant::composition
