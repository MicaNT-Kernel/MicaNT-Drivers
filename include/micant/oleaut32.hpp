// ============================================================================
// MicaNT: Sovereign Operating System Executive
// include/micant/oleaut32.hpp - Windows OLE Automation & SafeArray Subsystem
// (oleaut32.dll)
//
// 100% Clean-Room Architecture authored from Microsoft win32metadata interface definitions.
// Zero proprietary code used or referenced. Google LLC v. Oracle America (2021).
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <cstring>
#include <cwchar>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <atomic>

#include "ntdef.hpp"
#include "heap.hpp"
#include "kernel32.hpp"
#include "ole32.hpp"
#include "ldr.hpp"

namespace micant::ole32 {

using DISPID   = int32_t;
using MEMBERID = int32_t;
using LCID     = uint32_t;

inline constexpr DISPID DISPID_UNKNOWN     = -1;
inline constexpr DISPID DISPID_VALUE       = 0;
inline constexpr DISPID DISPID_PROPERTYPUT = -3;
inline constexpr DISPID DISPID_NEWENUM     = -4;
inline constexpr DISPID DISPID_EVALUATE    = -5;

inline constexpr uint16_t DISPATCH_METHOD         = 0x1;
inline constexpr uint16_t DISPATCH_PROPERTYGET    = 0x2;
inline constexpr uint16_t DISPATCH_PROPERTYPUT    = 0x4;
inline constexpr uint16_t DISPATCH_PROPERTYPUTREF = 0x8;

struct DISPPARAMS {
    VARIANTARG* rgvarg{nullptr};
    DISPID*     rgdispidNamedArgs{nullptr};
    uint32_t    cArgs{0};
    uint32_t    cNamedArgs{0};
};

struct EXCEPINFO {
    uint16_t wCode{0};
    uint16_t wReserved{0};
    BSTR     bstrSource{nullptr};
    BSTR     bstrDescription{nullptr};
    BSTR     bstrHelpFile{nullptr};
    uint32_t dwHelpContext{0};
    void*    pvReserved{nullptr};
    HRESULT  (__stdcall *pfnDeferredFillIn)(EXCEPINFO*){nullptr};
    HRESULT  scode{0};
};

struct SAFEARRAYBOUND {
    uint32_t cElements{0};
    int32_t  lLbound{0};
};

struct SAFEARRAY {
    uint16_t       cDims{0};
    uint16_t       fFeatures{0};
    uint32_t       cbElements{0};
    uint32_t       cLocks{0};
    void*          pvData{nullptr};
    SAFEARRAYBOUND rgsabound[1];
};

class ITypeInfo;
class ITypeLib;

inline const IID IID_IDispatch = {
    0x00020400, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

class IDispatch : public IUnknown {
public:
    virtual HRESULT __stdcall GetTypeInfoCount(uint32_t* pctinfo) = 0;
    virtual HRESULT __stdcall GetTypeInfo(uint32_t iTInfo, LCID lcid, ITypeInfo** ppTInfo) = 0;
    virtual HRESULT __stdcall GetIDsOfNames(REFIID riid, LPOLESTR* rgszNames, uint32_t cNames, LCID lcid, DISPID* rgDispId) = 0;
    virtual HRESULT __stdcall Invoke(
        DISPID dispIdMember,
        REFIID riid,
        LCID lcid,
        uint16_t wFlags,
        DISPPARAMS* pDispParams,
        VARIANT* pVarResult,
        EXCEPINFO* pExcepInfo,
        uint32_t* puArgErr
    ) = 0;
};

} // namespace micant::ole32

namespace micant::oleaut32 {

using namespace micant::ole32;

// ============================================================================
// 1. Automation Constants, DISPID & HRESULT Codes
// ============================================================================

// OLE Automation Error HRESULTs
inline constexpr HRESULT DISP_E_UNKNOWNINTERFACE  = static_cast<HRESULT>(0x80020001);
inline constexpr HRESULT DISP_E_MEMBERNOTFOUND     = static_cast<HRESULT>(0x80020003);
inline constexpr HRESULT DISP_E_PARAMNOTFOUND      = static_cast<HRESULT>(0x80020004);
inline constexpr HRESULT DISP_E_TYPEMISMATCH       = static_cast<HRESULT>(0x80020005);
inline constexpr HRESULT DISP_E_UNKNOWNNAME        = static_cast<HRESULT>(0x80020006);
inline constexpr HRESULT DISP_E_NONAMEDARGS        = static_cast<HRESULT>(0x80020007);
inline constexpr HRESULT DISP_E_BADPARAMCOUNT      = static_cast<HRESULT>(0x8002000E);
inline constexpr HRESULT DISP_E_PARAMNOTOPTIONAL   = static_cast<HRESULT>(0x8002000F);
inline constexpr HRESULT DISP_E_BADVARTYPE         = static_cast<HRESULT>(0x80020008);
inline constexpr HRESULT DISP_E_OVERFLOW           = static_cast<HRESULT>(0x8002000A);
inline constexpr HRESULT DISP_E_DIVBYZERO          = static_cast<HRESULT>(0x80020012);
inline constexpr HRESULT DISP_E_ARRAYISLOCKED      = static_cast<HRESULT>(0x8002000D);
inline constexpr HRESULT TYPE_E_ELEMENTNOTFOUND    = static_cast<HRESULT>(0x8002802B);
inline constexpr HRESULT TYPE_E_CANTLOADLIBRARY    = static_cast<HRESULT>(0x80029C4A);

// Variant Comparison Results
inline constexpr int32_t VARCMP_LT   = 0;
inline constexpr int32_t VARCMP_EQ   = 1;
inline constexpr int32_t VARCMP_GT   = 2;
inline constexpr int32_t VARCMP_NULL = 3;

// SafeArray Feature Flags
inline constexpr uint16_t FADF_AUTO        = 0x0001;
inline constexpr uint16_t FADF_STATIC      = 0x0002;
inline constexpr uint16_t FADF_EMBEDDED    = 0x0004;
inline constexpr uint16_t FADF_FIXEDSIZE   = 0x0010;
inline constexpr uint16_t FADF_RECORD      = 0x0020;
inline constexpr uint16_t FADF_HAVEIID     = 0x0040;
inline constexpr uint16_t FADF_HAVEVARTYPE = 0x0080;
inline constexpr uint16_t FADF_BSTR        = 0x0100;
inline constexpr uint16_t FADF_UNKNOWN     = 0x0200;
inline constexpr uint16_t FADF_DISPATCH    = 0x0400;
inline constexpr uint16_t FADF_VARIANT     = 0x0800;

// VariantChangeType Flags
inline constexpr uint16_t VARIANT_NOVALUEPROP        = 0x01;
inline constexpr uint16_t VARIANT_ALPHABOOL          = 0x02;
inline constexpr uint16_t VARIANT_NOUSEROVERRIDE     = 0x04;
inline constexpr uint16_t VARIANT_LOCALBOOL          = 0x10;

// ============================================================================
// 4. Extended BSTR Operations
// ============================================================================

inline BSTR SysAllocStringByteLen(const char* psz, uint32_t len) noexcept {
    // BSTR with byte length for binary data / ANSI strings
    uint8_t* mem = static_cast<uint8_t*>(CoTaskMemAlloc(len + sizeof(uint32_t) + sizeof(OLECHAR)));
    if (!mem) return nullptr;

    uint32_t* pLen = reinterpret_cast<uint32_t*>(mem);
    *pLen = len;

    char* strData = reinterpret_cast<char*>(mem + sizeof(uint32_t));
    if (psz) {
        std::memcpy(strData, psz, len);
    } else {
        std::memset(strData, 0, len);
    }
    // Zero terminate both byte and wchar
    strData[len] = '\0';
    strData[len + 1] = '\0';
    return reinterpret_cast<BSTR>(strData);
}

inline win32::BOOL SysReAllocString(BSTR* pbstr, const OLECHAR* psz) noexcept {
    if (!pbstr) return 0;
    BSTR bstrNew = SysAllocString(psz);
    if (!bstrNew && psz) return 0;
    SysFreeString(*pbstr);
    *pbstr = bstrNew;
    return 1;
}

inline win32::BOOL SysReAllocStringLen(BSTR* pbstr, const OLECHAR* psz, uint32_t len) noexcept {
    if (!pbstr) return 0;
    BSTR bstrNew = SysAllocStringLen(psz, len);
    if (!bstrNew && len > 0) return 0;
    SysFreeString(*pbstr);
    *pbstr = bstrNew;
    return 1;
}

// ============================================================================
// 5. SAFEARRAY Implementation (SafeArray*)
// ============================================================================

inline uint32_t GetElementSizeForVarType(VARTYPE vt) noexcept {
    switch (vt) {
        case VT_I1:
        case VT_UI1:
            return 1;
        case VT_I2:
        case VT_UI2:
        case VT_BOOL:
            return 2;
        case VT_I4:
        case VT_UI4:
        case VT_R4:
        case VT_ERROR:
            return 4;
        case VT_I8:
        case VT_UI8:
        case VT_R8:
        case VT_DATE:
        case VT_CY:
            return 8;
        case VT_BSTR:
        case VT_UNKNOWN:
        case VT_DISPATCH:
            return sizeof(void*);
        case VT_VARIANT:
            return sizeof(VARIANT);
        default:
            return sizeof(void*);
    }
}

inline SAFEARRAY* __stdcall SafeArrayCreate(VARTYPE vt, uint32_t cDims, SAFEARRAYBOUND* rgsabound) {
    if (cDims == 0 || !rgsabound) return nullptr;

    uint32_t elemSize = GetElementSizeForVarType(vt);
    uint64_t totalElements = 1;
    for (uint32_t i = 0; i < cDims; ++i) {
        totalElements *= rgsabound[i].cElements;
    }
    if (totalElements == 0) totalElements = 1;

    size_t headerSize = sizeof(SAFEARRAY) + (cDims - 1) * sizeof(SAFEARRAYBOUND);
    auto* psa = static_cast<SAFEARRAY*>(CoTaskMemAlloc(headerSize));
    if (!psa) return nullptr;

    std::memset(psa, 0, headerSize);
    psa->cDims = static_cast<uint16_t>(cDims);
    psa->cbElements = elemSize;
    psa->cLocks = 0;
    psa->fFeatures = FADF_HAVEVARTYPE;

    if (vt == VT_BSTR) psa->fFeatures |= FADF_BSTR;
    else if (vt == VT_UNKNOWN) psa->fFeatures |= FADF_UNKNOWN;
    else if (vt == VT_DISPATCH) psa->fFeatures |= FADF_DISPATCH;
    else if (vt == VT_VARIANT) psa->fFeatures |= FADF_VARIANT;

    for (uint32_t i = 0; i < cDims; ++i) {
        psa->rgsabound[i] = rgsabound[i];
    }

    size_t dataSize = static_cast<size_t>(totalElements * elemSize);
    psa->pvData = CoTaskMemAlloc(dataSize);
    if (!psa->pvData) {
        CoTaskMemFree(psa);
        return nullptr;
    }
    std::memset(psa->pvData, 0, dataSize);

    return psa;
}

inline SAFEARRAY* __stdcall SafeArrayCreateVector(VARTYPE vt, int32_t lLbound, uint32_t cElements) {
    SAFEARRAYBOUND bound{ cElements, lLbound };
    return SafeArrayCreate(vt, 1, &bound);
}

inline HRESULT __stdcall SafeArrayDestroy(SAFEARRAY* psa) {
    if (!psa) return S_OK;
    if (psa->cLocks > 0) return DISP_E_ARRAYISLOCKED;

    uint64_t totalElements = 1;
    for (uint32_t i = 0; i < psa->cDims; ++i) {
        totalElements *= psa->rgsabound[i].cElements;
    }

    if (psa->pvData) {
        if (psa->fFeatures & FADF_BSTR) {
            auto** bstrArr = static_cast<BSTR*>(psa->pvData);
            for (uint64_t i = 0; i < totalElements; ++i) {
                if (bstrArr[i]) SysFreeString(bstrArr[i]);
            }
        } else if (psa->fFeatures & FADF_VARIANT) {
            auto* varArr = static_cast<VARIANT*>(psa->pvData);
            for (uint64_t i = 0; i < totalElements; ++i) {
                VariantClear(&varArr[i]);
            }
        } else if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
            auto** unkArr = static_cast<IUnknown**>(psa->pvData);
            for (uint64_t i = 0; i < totalElements; ++i) {
                if (unkArr[i]) unkArr[i]->Release();
            }
        }
        CoTaskMemFree(psa->pvData);
        psa->pvData = nullptr;
    }

    CoTaskMemFree(psa);
    return S_OK;
}

inline uint32_t __stdcall SafeArrayGetDim(SAFEARRAY* psa) {
    return psa ? psa->cDims : 0;
}

inline uint32_t __stdcall SafeArrayGetElemsize(SAFEARRAY* psa) {
    return psa ? psa->cbElements : 0;
}

inline HRESULT __stdcall SafeArrayGetLBound(SAFEARRAY* psa, uint32_t nDim, int32_t* plLbound) {
    if (!psa || !plLbound || nDim == 0 || nDim > psa->cDims) return E_INVALIDARG;
    *plLbound = psa->rgsabound[nDim - 1].lLbound;
    return S_OK;
}

inline HRESULT __stdcall SafeArrayGetUBound(SAFEARRAY* psa, uint32_t nDim, int32_t* plUbound) {
    if (!psa || !plUbound || nDim == 0 || nDim > psa->cDims) return E_INVALIDARG;
    const auto& b = psa->rgsabound[nDim - 1];
    *plUbound = b.lLbound + static_cast<int32_t>(b.cElements) - 1;
    return S_OK;
}

inline HRESULT __stdcall SafeArrayAccessData(SAFEARRAY* psa, void** ppvData) {
    if (!psa || !ppvData) return E_INVALIDARG;
    psa->cLocks++;
    *ppvData = psa->pvData;
    return S_OK;
}

inline HRESULT __stdcall SafeArrayUnaccessData(SAFEARRAY* psa) {
    if (!psa) return E_INVALIDARG;
    if (psa->cLocks > 0) psa->cLocks--;
    return S_OK;
}

inline size_t SafeArrayCalculateFlatOffset(SAFEARRAY* psa, const int32_t* rgIndices) {
    size_t flatIndex = 0;
    size_t multiplier = 1;

    for (uint32_t i = 0; i < psa->cDims; ++i) {
        int32_t lbound = psa->rgsabound[i].lLbound;
        uint32_t count = psa->rgsabound[i].cElements;
        int32_t idx = rgIndices[i];
        if (idx < lbound || idx >= lbound + static_cast<int32_t>(count)) {
            return static_cast<size_t>(-1); // Out of bounds
        }
        flatIndex += static_cast<size_t>(idx - lbound) * multiplier;
        multiplier *= count;
    }
    return flatIndex;
}

inline HRESULT __stdcall SafeArrayGetElement(SAFEARRAY* psa, int32_t* rgIndices, void* pv) {
    if (!psa || !rgIndices || !pv) return E_INVALIDARG;

    size_t offset = SafeArrayCalculateFlatOffset(psa, rgIndices);
    if (offset == static_cast<size_t>(-1)) return DISP_E_BADPARAMCOUNT;

    uint8_t* src = static_cast<uint8_t*>(psa->pvData) + offset * psa->cbElements;

    if (psa->fFeatures & FADF_BSTR) {
        BSTR bstrSrc = *reinterpret_cast<BSTR*>(src);
        *reinterpret_cast<BSTR*>(pv) = bstrSrc ? SysAllocStringLen(bstrSrc, SysStringLen(bstrSrc)) : nullptr;
    } else if (psa->fFeatures & FADF_VARIANT) {
        VariantCopy(reinterpret_cast<VARIANT*>(pv), reinterpret_cast<const VARIANT*>(src));
    } else if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
        IUnknown* unk = *reinterpret_cast<IUnknown**>(src);
        if (unk) unk->AddRef();
        *reinterpret_cast<IUnknown**>(pv) = unk;
    } else {
        std::memcpy(pv, src, psa->cbElements);
    }
    return S_OK;
}

inline HRESULT __stdcall SafeArrayPutElement(SAFEARRAY* psa, int32_t* rgIndices, void* pv) {
    if (!psa || !rgIndices || !pv) return E_INVALIDARG;

    size_t offset = SafeArrayCalculateFlatOffset(psa, rgIndices);
    if (offset == static_cast<size_t>(-1)) return DISP_E_BADPARAMCOUNT;

    uint8_t* dest = static_cast<uint8_t*>(psa->pvData) + offset * psa->cbElements;

    if (psa->fFeatures & FADF_BSTR) {
        BSTR* pOld = reinterpret_cast<BSTR*>(dest);
        if (*pOld) SysFreeString(*pOld);
        BSTR bstrIn = *reinterpret_cast<BSTR*>(pv);
        *pOld = bstrIn ? SysAllocStringLen(bstrIn, SysStringLen(bstrIn)) : nullptr;
    } else if (psa->fFeatures & FADF_VARIANT) {
        VariantCopy(reinterpret_cast<VARIANT*>(dest), reinterpret_cast<const VARIANT*>(pv));
    } else if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
        IUnknown** pOld = reinterpret_cast<IUnknown**>(dest);
        if (*pOld) (*pOld)->Release();
        IUnknown* unkIn = *reinterpret_cast<IUnknown**>(pv);
        if (unkIn) unkIn->AddRef();
        *pOld = unkIn;
    } else {
        std::memcpy(dest, pv, psa->cbElements);
    }
    return S_OK;
}

inline HRESULT __stdcall SafeArrayCopy(SAFEARRAY* psa, SAFEARRAY** ppsaOut) {
    if (!psa || !ppsaOut) return E_INVALIDARG;
    *ppsaOut = nullptr;

    auto* copy = SafeArrayCreate(VT_UI1, psa->cDims, psa->rgsabound);
    if (!copy) return E_OUTOFMEMORY;

    copy->cbElements = psa->cbElements;
    copy->fFeatures = psa->fFeatures;

    uint64_t totalElements = 1;
    for (uint32_t i = 0; i < psa->cDims; ++i) {
        totalElements *= psa->rgsabound[i].cElements;
    }

    if (psa->fFeatures & FADF_BSTR) {
        auto** src = static_cast<BSTR*>(psa->pvData);
        auto** dst = static_cast<BSTR*>(copy->pvData);
        for (uint64_t i = 0; i < totalElements; ++i) {
            dst[i] = src[i] ? SysAllocStringLen(src[i], SysStringLen(src[i])) : nullptr;
        }
    } else if (psa->fFeatures & FADF_VARIANT) {
        auto* src = static_cast<VARIANT*>(psa->pvData);
        auto* dst = static_cast<VARIANT*>(copy->pvData);
        for (uint64_t i = 0; i < totalElements; ++i) {
            VariantCopy(&dst[i], &src[i]);
        }
    } else if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
        auto** src = static_cast<IUnknown**>(psa->pvData);
        auto** dst = static_cast<IUnknown**>(copy->pvData);
        for (uint64_t i = 0; i < totalElements; ++i) {
            if (src[i]) src[i]->AddRef();
            dst[i] = src[i];
        }
    } else {
        std::memcpy(copy->pvData, psa->pvData, static_cast<size_t>(totalElements * psa->cbElements));
    }

    *ppsaOut = copy;
    return S_OK;
}

inline HRESULT __stdcall SafeArrayRedim(SAFEARRAY* psa, SAFEARRAYBOUND* psaboundNew) {
    if (!psa || !psaboundNew) return E_INVALIDARG;
    if (psa->cLocks > 0) return DISP_E_ARRAYISLOCKED;

    uint64_t otherElements = 1;
    for (uint32_t i = 1; i < psa->cDims; ++i) {
        otherElements *= psa->rgsabound[i].cElements;
    }
    uint64_t newTotal = otherElements * psaboundNew->cElements;
    size_t newBytes = static_cast<size_t>(newTotal * psa->cbElements);

    void* pNewData = CoTaskMemRealloc(psa->pvData, newBytes);
    if (!pNewData && newBytes > 0) return E_OUTOFMEMORY;

    psa->pvData = pNewData;
    psa->rgsabound[0] = *psaboundNew;
    return S_OK;
}

inline HRESULT __stdcall SafeArrayGetVartype(SAFEARRAY* psa, VARTYPE* pvt) {
    if (!psa || !pvt) return E_INVALIDARG;
    if (psa->fFeatures & FADF_BSTR) *pvt = VT_BSTR;
    else if (psa->fFeatures & FADF_UNKNOWN) *pvt = VT_UNKNOWN;
    else if (psa->fFeatures & FADF_DISPATCH) *pvt = VT_DISPATCH;
    else if (psa->fFeatures & FADF_VARIANT) *pvt = VT_VARIANT;
    else {
        switch (psa->cbElements) {
            case 1: *pvt = VT_UI1; break;
            case 2: *pvt = VT_I2; break;
            case 4: *pvt = VT_I4; break;
            case 8: *pvt = VT_I8; break;
            default: *pvt = VT_EMPTY; break;
        }
    }
    return S_OK;
}

// ============================================================================
// 6. Advanced VARIANT Operations (VariantCopyInd, VariantChangeType, VarCmp)
// ============================================================================

inline HRESULT __stdcall VariantCopyInd(VARIANT* pvarDest, const VARIANTARG* pvargSrc) {
    if (!pvarDest || !pvargSrc) return E_INVALIDARG;

    if (!(pvargSrc->vt & VT_BYREF)) {
        return VariantCopy(pvarDest, pvargSrc);
    }

    VariantClear(pvarDest);
    VARTYPE baseVt = pvargSrc->vt & ~VT_BYREF;
    pvarDest->vt = baseVt;

    if (!pvargSrc->byref) return S_OK;

    switch (baseVt) {
        case VT_I1:   pvarDest->bVal = *static_cast<int8_t*>(pvargSrc->byref); break;
        case VT_UI1:  pvarDest->bVal = *static_cast<uint8_t*>(pvargSrc->byref); break;
        case VT_I2:   pvarDest->iVal = *static_cast<int16_t*>(pvargSrc->byref); break;
        case VT_UI2:  pvarDest->uiVal = *static_cast<uint16_t*>(pvargSrc->byref); break;
        case VT_I4:   pvarDest->lVal = *static_cast<int32_t*>(pvargSrc->byref); break;
        case VT_UI4:  pvarDest->ulVal = *static_cast<uint32_t*>(pvargSrc->byref); break;
        case VT_I8:   pvarDest->llVal = *static_cast<int64_t*>(pvargSrc->byref); break;
        case VT_UI8:  pvarDest->ullVal = *static_cast<uint64_t*>(pvargSrc->byref); break;
        case VT_R4:   pvarDest->fltVal = *static_cast<float*>(pvargSrc->byref); break;
        case VT_R8:   pvarDest->dblVal = *static_cast<double*>(pvargSrc->byref); break;
        case VT_BOOL: pvarDest->boolVal = *static_cast<VARIANT_BOOL*>(pvargSrc->byref); break;
        case VT_BSTR: {
            BSTR s = *static_cast<BSTR*>(pvargSrc->byref);
            pvarDest->bstrVal = s ? SysAllocStringLen(s, SysStringLen(s)) : nullptr;
            break;
        }
        case VT_UNKNOWN: {
            IUnknown* unk = *static_cast<IUnknown**>(pvargSrc->byref);
            if (unk) unk->AddRef();
            pvarDest->punkVal = unk;
            break;
        }
        case VT_DISPATCH: {
            IDispatch* disp = *static_cast<IDispatch**>(pvargSrc->byref);
            if (disp) disp->AddRef();
            pvarDest->pdispVal = disp;
            break;
        }
        default:
            pvarDest->byref = pvargSrc->byref;
            break;
    }
    return S_OK;
}

inline HRESULT __stdcall VariantChangeType(
    VARIANTARG* pvargDest,
    const VARIANTARG* pvarSrc,
    [[maybe_unused]] uint16_t wFlags,
    VARTYPE vt
) {
    if (!pvargDest || !pvarSrc) return E_INVALIDARG;

    // Handle byref indirection first
    VARIANT srcInd{};
    VariantInit(&srcInd);
    VariantCopyInd(&srcInd, pvarSrc);

    // Target is same type -> direct copy
    if (srcInd.vt == vt) {
        VariantCopy(pvargDest, &srcInd);
        VariantClear(&srcInd);
        return S_OK;
    }

    VARIANT tmp{};
    VariantInit(&tmp);
    tmp.vt = vt;

    HRESULT hr = S_OK;

    // 1. Conversion to BSTR
    if (vt == VT_BSTR) {
        std::wstring ws;
        switch (srcInd.vt) {
            case VT_EMPTY:   ws = L""; break;
            case VT_NULL:    ws = L""; break;
            case VT_I1:
            case VT_I2:
            case VT_I4:      ws = std::to_wstring(srcInd.lVal); break;
            case VT_UI1:
            case VT_UI2:
            case VT_UI4:     ws = std::to_wstring(srcInd.ulVal); break;
            case VT_I8:      ws = std::to_wstring(srcInd.llVal); break;
            case VT_UI8:     ws = std::to_wstring(srcInd.ullVal); break;
            case VT_R4:      ws = std::to_wstring(srcInd.fltVal); break;
            case VT_R8:      ws = std::to_wstring(srcInd.dblVal); break;
            case VT_BOOL:    ws = (srcInd.boolVal == VARIANT_TRUE) ? L"True" : L"False"; break;
            default:         hr = DISP_E_TYPEMISMATCH; break;
        }
        if (hr == S_OK) {
            tmp.bstrVal = SysAllocString(ws.c_str());
        }
    }
    // 2. Conversion to BOOL
    else if (vt == VT_BOOL) {
        switch (srcInd.vt) {
            case VT_EMPTY:
            case VT_NULL:
                tmp.boolVal = VARIANT_FALSE;
                break;
            case VT_I1:
            case VT_I2:
            case VT_I4:
                tmp.boolVal = (srcInd.lVal != 0) ? VARIANT_TRUE : VARIANT_FALSE;
                break;
            case VT_UI1:
            case VT_UI2:
            case VT_UI4:
                tmp.boolVal = (srcInd.ulVal != 0) ? VARIANT_TRUE : VARIANT_FALSE;
                break;
            case VT_I8:
                tmp.boolVal = (srcInd.llVal != 0) ? VARIANT_TRUE : VARIANT_FALSE;
                break;
            case VT_R4:
                tmp.boolVal = (std::abs(srcInd.fltVal) > 1e-6f) ? VARIANT_TRUE : VARIANT_FALSE;
                break;
            case VT_R8:
                tmp.boolVal = (std::abs(srcInd.dblVal) > 1e-9) ? VARIANT_TRUE : VARIANT_FALSE;
                break;
            case VT_BSTR: {
                if (!srcInd.bstrVal) {
                    tmp.boolVal = VARIANT_FALSE;
                } else {
                    std::wstring ws(srcInd.bstrVal);
                    for (auto& c : ws) c = static_cast<wchar_t>(std::towlower(c));
                    if (ws == L"true" || ws == L"-1" || ws == L"1" || ws == L"yes") {
                        tmp.boolVal = VARIANT_TRUE;
                    } else {
                        tmp.boolVal = VARIANT_FALSE;
                    }
                }
                break;
            }
            default:
                hr = DISP_E_TYPEMISMATCH;
                break;
        }
    }
    // 3. Conversion to Integers (VT_I4 / VT_I8 / VT_UI4 / VT_UI8)
    else if (vt == VT_I4 || vt == VT_I2 || vt == VT_I1 || vt == VT_I8 ||
             vt == VT_UI4 || vt == VT_UI2 || vt == VT_UI1 || vt == VT_UI8) {
        int64_t val64 = 0;
        switch (srcInd.vt) {
            case VT_EMPTY:
            case VT_NULL:
                val64 = 0;
                break;
            case VT_I1:
            case VT_I2:
            case VT_I4:
                val64 = srcInd.lVal;
                break;
            case VT_UI1:
            case VT_UI2:
            case VT_UI4:
                val64 = static_cast<int64_t>(srcInd.ulVal);
                break;
            case VT_I8:
                val64 = srcInd.llVal;
                break;
            case VT_UI8:
                val64 = static_cast<int64_t>(srcInd.ullVal);
                break;
            case VT_R4:
                val64 = static_cast<int64_t>(srcInd.fltVal);
                break;
            case VT_R8:
                val64 = static_cast<int64_t>(srcInd.dblVal);
                break;
            case VT_BOOL:
                val64 = (srcInd.boolVal == VARIANT_TRUE) ? -1 : 0;
                break;
            case VT_BSTR: {
                if (!srcInd.bstrVal || srcInd.bstrVal[0] == L'\0') {
                    val64 = 0;
                } else {
                    wchar_t* end = nullptr;
                    val64 = std::wcstoll(srcInd.bstrVal, &end, 10);
                }
                break;
            }
            default:
                hr = DISP_E_TYPEMISMATCH;
                break;
        }

        if (hr == S_OK) {
            switch (vt) {
                case VT_I1:   tmp.bVal = static_cast<uint8_t>(static_cast<int8_t>(val64)); break;
                case VT_UI1:  tmp.bVal = static_cast<uint8_t>(val64); break;
                case VT_I2:   tmp.iVal = static_cast<int16_t>(val64); break;
                case VT_UI2:  tmp.uiVal = static_cast<uint16_t>(val64); break;
                case VT_I4:   tmp.lVal = static_cast<int32_t>(val64); break;
                case VT_UI4:  tmp.ulVal = static_cast<uint32_t>(val64); break;
                case VT_I8:   tmp.llVal = val64; break;
                case VT_UI8:  tmp.ullVal = static_cast<uint64_t>(val64); break;
                default: break;
            }
        }
    }
    // 4. Conversion to Floating Point (VT_R4 / VT_R8)
    else if (vt == VT_R4 || vt == VT_R8) {
        double dVal = 0.0;
        switch (srcInd.vt) {
            case VT_EMPTY:
            case VT_NULL:
                dVal = 0.0;
                break;
            case VT_I1:
            case VT_I2:
            case VT_I4:
                dVal = static_cast<double>(srcInd.lVal);
                break;
            case VT_UI1:
            case VT_UI2:
            case VT_UI4:
                dVal = static_cast<double>(srcInd.ulVal);
                break;
            case VT_I8:
                dVal = static_cast<double>(srcInd.llVal);
                break;
            case VT_UI8:
                dVal = static_cast<double>(srcInd.ullVal);
                break;
            case VT_R4:
                dVal = static_cast<double>(srcInd.fltVal);
                break;
            case VT_R8:
                dVal = srcInd.dblVal;
                break;
            case VT_BOOL:
                dVal = (srcInd.boolVal == VARIANT_TRUE) ? -1.0 : 0.0;
                break;
            case VT_BSTR: {
                if (!srcInd.bstrVal || srcInd.bstrVal[0] == L'\0') {
                    dVal = 0.0;
                } else {
                    wchar_t* end = nullptr;
                    dVal = std::wcstod(srcInd.bstrVal, &end);
                }
                break;
            }
            default:
                hr = DISP_E_TYPEMISMATCH;
                break;
        }

        if (hr == S_OK) {
            if (vt == VT_R4) tmp.fltVal = static_cast<float>(dVal);
            else tmp.dblVal = dVal;
        }
    } else {
        hr = DISP_E_TYPEMISMATCH;
    }

    VariantClear(&srcInd);

    if (hr == S_OK) {
        VariantClear(pvargDest);
        *pvargDest = tmp;
    }
    return hr;
}

inline HRESULT __stdcall VariantChangeTypeEx(
    VARIANTARG* pvargDest,
    const VARIANTARG* pvarSrc,
    [[maybe_unused]] LCID lcid,
    uint16_t wFlags,
    VARTYPE vt
) {
    return VariantChangeType(pvargDest, pvarSrc, wFlags, vt);
}

inline HRESULT __stdcall VarCmp(VARIANT* pvar1, VARIANT* pvar2, [[maybe_unused]] LCID lcid, [[maybe_unused]] uint32_t dwFlags) {
    if (!pvar1 || !pvar2) return static_cast<HRESULT>(VARCMP_NULL);

    if (pvar1->vt == VT_NULL || pvar2->vt == VT_NULL) return static_cast<HRESULT>(VARCMP_NULL);

    // If types match directly
    if (pvar1->vt == pvar2->vt) {
        switch (pvar1->vt) {
            case VT_EMPTY: return static_cast<HRESULT>(VARCMP_EQ);
            case VT_I1:
            case VT_I2:
            case VT_I4:
                if (pvar1->lVal < pvar2->lVal) return static_cast<HRESULT>(VARCMP_LT);
                if (pvar1->lVal > pvar2->lVal) return static_cast<HRESULT>(VARCMP_GT);
                return static_cast<HRESULT>(VARCMP_EQ);
            case VT_UI1:
            case VT_UI2:
            case VT_UI4:
                if (pvar1->ulVal < pvar2->ulVal) return static_cast<HRESULT>(VARCMP_LT);
                if (pvar1->ulVal > pvar2->ulVal) return static_cast<HRESULT>(VARCMP_GT);
                return static_cast<HRESULT>(VARCMP_EQ);
            case VT_I8:
                if (pvar1->llVal < pvar2->llVal) return static_cast<HRESULT>(VARCMP_LT);
                if (pvar1->llVal > pvar2->llVal) return static_cast<HRESULT>(VARCMP_GT);
                return static_cast<HRESULT>(VARCMP_EQ);
            case VT_R4:
                if (pvar1->fltVal < pvar2->fltVal) return static_cast<HRESULT>(VARCMP_LT);
                if (pvar1->fltVal > pvar2->fltVal) return static_cast<HRESULT>(VARCMP_GT);
                return static_cast<HRESULT>(VARCMP_EQ);
            case VT_R8:
                if (pvar1->dblVal < pvar2->dblVal) return static_cast<HRESULT>(VARCMP_LT);
                if (pvar1->dblVal > pvar2->dblVal) return static_cast<HRESULT>(VARCMP_GT);
                return static_cast<HRESULT>(VARCMP_EQ);
            case VT_BOOL:
                if (pvar1->boolVal == pvar2->boolVal) return static_cast<HRESULT>(VARCMP_EQ);
                return (pvar1->boolVal < pvar2->boolVal) ? static_cast<HRESULT>(VARCMP_LT) : static_cast<HRESULT>(VARCMP_GT);
            case VT_BSTR: {
                if (!pvar1->bstrVal && !pvar2->bstrVal) return static_cast<HRESULT>(VARCMP_EQ);
                if (!pvar1->bstrVal) return static_cast<HRESULT>(VARCMP_LT);
                if (!pvar2->bstrVal) return static_cast<HRESULT>(VARCMP_GT);
                int cmp = std::wcscmp(pvar1->bstrVal, pvar2->bstrVal);
                if (cmp < 0) return static_cast<HRESULT>(VARCMP_LT);
                if (cmp > 0) return static_cast<HRESULT>(VARCMP_GT);
                return static_cast<HRESULT>(VARCMP_EQ);
            }
            default: break;
        }
    }

    // Coerce both to double for numeric comparison
    VARIANT v1Double{}, v2Double{};
    VariantInit(&v1Double);
    VariantInit(&v2Double);

    if (SUCCEEDED(VariantChangeType(&v1Double, pvar1, 0, VT_R8)) &&
        SUCCEEDED(VariantChangeType(&v2Double, pvar2, 0, VT_R8))) {
        int32_t res = VARCMP_EQ;
        if (v1Double.dblVal < v2Double.dblVal) res = VARCMP_LT;
        else if (v1Double.dblVal > v2Double.dblVal) res = VARCMP_GT;
        VariantClear(&v1Double);
        VariantClear(&v2Double);
        return static_cast<HRESULT>(res);
    }

    return static_cast<HRESULT>(VARCMP_NULL);
}

// ============================================================================
// 7. Dynamic Dispatch Helper Functions (DispGetParam, DispInvoke, CreateStdDispatch)
// ============================================================================

inline HRESULT __stdcall DispGetParam(
    DISPPARAMS* pdispparams,
    uint32_t position,
    VARTYPE vtTarg,
    VARIANT* pvarResult,
    uint32_t* puArgErr
) {
    if (!pdispparams || !pvarResult) return E_INVALIDARG;

    // Arguments in DISPPARAMS are passed in reverse order (COM convention)
    if (position >= pdispparams->cArgs) {
        if (puArgErr) *puArgErr = position;
        return DISP_E_PARAMNOTFOUND;
    }

    uint32_t realIndex = pdispparams->cArgs - 1 - position;
    VARIANTARG* pArg = &pdispparams->rgvarg[realIndex];

    if (vtTarg == VT_EMPTY || pArg->vt == vtTarg) {
        return VariantCopy(pvarResult, pArg);
    }

    HRESULT hr = VariantChangeType(pvarResult, pArg, 0, vtTarg);
    if (FAILED(hr) && puArgErr) {
        *puArgErr = position;
    }
    return hr;
}

class StandardDispatch : public IDispatch {
private:
    std::atomic<uint32_t> m_refCount{1};
    IUnknown* m_punkOuter{nullptr};
    std::unordered_map<std::wstring, DISPID> m_nameToId;
    std::unordered_map<DISPID, std::function<HRESULT(DISPPARAMS*, VARIANT*)>> m_methods;
    mutable std::mutex m_mutex;

public:
    explicit StandardDispatch(IUnknown* punkOuter = nullptr) : m_punkOuter(punkOuter) {
        if (m_punkOuter) m_punkOuter->AddRef();
    }

    ~StandardDispatch() override {
        if (m_punkOuter) m_punkOuter->Release();
    }

    void registerMethod(const std::wstring& name, DISPID id, std::function<HRESULT(DISPPARAMS*, VARIANT*)> handler) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_nameToId[name] = id;
        m_methods[id] = std::move(handler);
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch) {
            *ppvObject = static_cast<IDispatch*>(this);
            AddRef();
            return S_OK;
        }
        if (m_punkOuter) {
            return m_punkOuter->QueryInterface(riid, ppvObject);
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t __stdcall Release() override {
        uint32_t count = m_refCount.fetch_sub(1) - 1;
        if (count == 0) delete this;
        return count;
    }

    virtual HRESULT __stdcall GetTypeInfoCount(uint32_t* pctinfo) override {
        if (pctinfo) *pctinfo = 0;
        return S_OK;
    }

    virtual HRESULT __stdcall GetTypeInfo([[maybe_unused]] uint32_t iTInfo, [[maybe_unused]] LCID lcid, ITypeInfo** ppTInfo) override {
        if (!ppTInfo) return E_POINTER;
        *ppTInfo = nullptr;
        return E_NOTIMPL;
    }

    virtual HRESULT __stdcall GetIDsOfNames(
        [[maybe_unused]] REFIID riid,
        LPOLESTR* rgszNames,
        uint32_t cNames,
        [[maybe_unused]] LCID lcid,
        DISPID* rgDispId
    ) override {
        if (!rgszNames || !rgDispId) return E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);

        HRESULT hr = S_OK;
        for (uint32_t i = 0; i < cNames; ++i) {
            if (!rgszNames[i]) {
                rgDispId[i] = DISPID_UNKNOWN;
                hr = DISP_E_UNKNOWNNAME;
                continue;
            }
            std::wstring n(rgszNames[i]);
            auto it = m_nameToId.find(n);
            if (it != m_nameToId.end()) {
                rgDispId[i] = it->second;
            } else {
                rgDispId[i] = DISPID_UNKNOWN;
                hr = DISP_E_UNKNOWNNAME;
            }
        }
        return hr;
    }

    virtual HRESULT __stdcall Invoke(
        DISPID dispIdMember,
        [[maybe_unused]] REFIID riid,
        [[maybe_unused]] LCID lcid,
        [[maybe_unused]] uint16_t wFlags,
        DISPPARAMS* pDispParams,
        VARIANT* pVarResult,
        [[maybe_unused]] EXCEPINFO* pExcepInfo,
        [[maybe_unused]] uint32_t* puArgErr
    ) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_methods.find(dispIdMember);
        if (it == m_methods.end()) return DISP_E_MEMBERNOTFOUND;

        return it->second(pDispParams, pVarResult);
    }
};

inline HRESULT __stdcall CreateStdDispatch(
    IUnknown* punkOuter,
    [[maybe_unused]] void* pvThis,
    [[maybe_unused]] ITypeInfo* ptinfo,
    IUnknown** ppunkStdDisp
) {
    if (!ppunkStdDisp) return E_POINTER;
    auto* disp = new StandardDispatch(punkOuter);
    *ppunkStdDisp = static_cast<IUnknown*>(disp);
    return S_OK;
}

inline HRESULT __stdcall DispInvoke(
    void* _this,
    [[maybe_unused]] ITypeInfo* ptinfo,
    DISPID dispidMember,
    uint16_t wFlags,
    DISPPARAMS* pparams,
    VARIANT* pvarResult,
    EXCEPINFO* pexcepinfo,
    uint32_t* puArgErr
) {
    if (!_this) return E_INVALIDARG;
    auto* disp = reinterpret_cast<IDispatch*>(_this);
    return disp->Invoke(dispidMember, IID_NULL, 0, wFlags, pparams, pvarResult, pexcepinfo, puArgErr);
}

// ============================================================================
// 8. Type Library Engine (ITypeInfo, ITypeLib, TypeLibManager)
// ============================================================================

inline const IID IID_ITypeInfo = {
    0x00020401, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

inline const IID IID_ITypeLib = {
    0x00020402, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

class ITypeInfo : public IUnknown {
public:
    virtual HRESULT __stdcall GetDocumentation(
        MEMBERID memid,
        BSTR* pBstrName,
        BSTR* pBstrDocString,
        uint32_t* pdwHelpContext,
        BSTR* pBstrHelpFile
    ) = 0;
};

class ITypeLib : public IUnknown {
public:
    virtual uint32_t __stdcall GetTypeInfoCount() = 0;
    virtual HRESULT __stdcall GetTypeInfo(uint32_t index, ITypeInfo** ppTInfo) = 0;
    virtual HRESULT __stdcall GetDocumentation(
        int32_t index,
        BSTR* pBstrName,
        BSTR* pBstrDocString,
        uint32_t* pdwHelpContext,
        BSTR* pBstrHelpFile
    ) = 0;
};

class TypeLibImpl : public ITypeLib {
private:
    std::atomic<uint32_t> m_refCount{1};
    std::wstring m_name;
    std::wstring m_doc;
    GUID m_guid{};
    uint16_t m_verMajor{1};
    uint16_t m_verMinor{0};

public:
    TypeLibImpl(std::wstring_view name, std::wstring_view doc, const GUID& guid, uint16_t maj, uint16_t min)
        : m_name(name), m_doc(doc), m_guid(guid), m_verMajor(maj), m_verMinor(min) {}

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ITypeLib) {
            *ppvObject = static_cast<ITypeLib*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t __stdcall Release() override {
        uint32_t count = m_refCount.fetch_sub(1) - 1;
        if (count == 0) delete this;
        return count;
    }

    virtual uint32_t __stdcall GetTypeInfoCount() override {
        return 0;
    }

    virtual HRESULT __stdcall GetTypeInfo([[maybe_unused]] uint32_t index, ITypeInfo** ppTInfo) override {
        if (!ppTInfo) return E_POINTER;
        *ppTInfo = nullptr;
        return TYPE_E_ELEMENTNOTFOUND;
    }

    virtual HRESULT __stdcall GetDocumentation(
        [[maybe_unused]] int32_t index,
        BSTR* pBstrName,
        BSTR* pBstrDocString,
        uint32_t* pdwHelpContext,
        BSTR* pBstrHelpFile
    ) override {
        if (pBstrName) *pBstrName = SysAllocString(m_name.c_str());
        if (pBstrDocString) *pBstrDocString = SysAllocString(m_doc.c_str());
        if (pdwHelpContext) *pdwHelpContext = 0;
        if (pBstrHelpFile) *pBstrHelpFile = nullptr;
        return S_OK;
    }

    const GUID& getGuid() const noexcept { return m_guid; }
    uint16_t getMajor() const noexcept { return m_verMajor; }
    uint16_t getMinor() const noexcept { return m_verMinor; }
    const std::wstring& getName() const noexcept { return m_name; }
};

class TypeLibManager {
public:
    static TypeLibManager& Instance() {
        static TypeLibManager s_mgr;
        return s_mgr;
    }

    HRESULT registerLibrary(const GUID& guid, uint16_t wMaj, uint16_t wMin, const std::wstring& path, ITypeLib* pLib = nullptr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::wstring key = makeKey(guid, wMaj, wMin);
        m_paths[key] = path;
        m_libs[key] = pLib;
        if (pLib) pLib->AddRef();
        return S_OK;
    }

    HRESULT loadLibrary(const OLECHAR* szFile, ITypeLib** pptlib) {
        if (!szFile || !pptlib) return E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);

        // Check if path matches any registered library
        for (const auto& [k, p] : m_paths) {
            if (p == szFile) {
                auto it = m_libs.find(k);
                if (it != m_libs.end() && it->second) {
                    it->second->AddRef();
                    *pptlib = it->second;
                    return S_OK;
                }
            }
        }

        // Synthesize dynamic in-memory TypeLib representation for the requested file
        GUID syntheticGuid{};
        ole32::CoCreateGuid(&syntheticGuid);
        auto* lib = new TypeLibImpl(szFile, L"MicaNT Clean-Room Type Library", syntheticGuid, 1, 0);
        *pptlib = lib;
        return S_OK;
    }

    HRESULT queryPath(const GUID& guid, uint16_t wMaj, uint16_t wMin, BSTR* lpbstrPath) {
        if (!lpbstrPath) return E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        std::wstring key = makeKey(guid, wMaj, wMin);
        auto it = m_paths.find(key);
        if (it != m_paths.end()) {
            *lpbstrPath = SysAllocString(it->second.c_str());
            return S_OK;
        }
        return TYPE_E_CANTLOADLIBRARY;
    }

private:
    TypeLibManager() = default;

    static std::wstring makeKey(const GUID& g, uint16_t maj, uint16_t min) {
        wchar_t buf[128]{};
        std::swprintf(buf, sizeof(buf) / sizeof(wchar_t),
            L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}_%u.%u",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
            g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
            maj, min);
        return std::wstring(buf);
    }

    std::mutex m_mutex;
    std::unordered_map<std::wstring, std::wstring> m_paths;
    std::unordered_map<std::wstring, ITypeLib*> m_libs;
};

inline HRESULT __stdcall LoadTypeLib(const OLECHAR* szFile, ITypeLib** pptlib) {
    return TypeLibManager::Instance().loadLibrary(szFile, pptlib);
}

inline HRESULT __stdcall LoadRegTypeLib(REFGUID rguid, uint16_t wVerMajor, uint16_t wVerMinor, [[maybe_unused]] LCID lcid, ITypeLib** pptlib) {
    BSTR path = nullptr;
    HRESULT hr = TypeLibManager::Instance().queryPath(rguid, wVerMajor, wVerMinor, &path);
    if (FAILED(hr)) return hr;
    hr = LoadTypeLib(path, pptlib);
    SysFreeString(path);
    return hr;
}

inline HRESULT __stdcall RegisterTypeLib(ITypeLib* ptlib, const OLECHAR* szFullPath, [[maybe_unused]] const OLECHAR* szHelpDir) {
    if (!ptlib || !szFullPath) return E_INVALIDARG;
    auto* impl = dynamic_cast<TypeLibImpl*>(ptlib);
    if (impl) {
        TypeLibManager::Instance().registerLibrary(impl->getGuid(), impl->getMajor(), impl->getMinor(), szFullPath, ptlib);
    } else {
        GUID synthetic{};
        ole32::CoCreateGuid(&synthetic);
        TypeLibManager::Instance().registerLibrary(synthetic, 1, 0, szFullPath, ptlib);
    }
    return S_OK;
}

inline HRESULT __stdcall QueryPathOfRegTypeLib(REFGUID guid, uint16_t wVerMajor, uint16_t wVerMinor, [[maybe_unused]] LCID lcid, BSTR* lpbstrPathName) {
    return TypeLibManager::Instance().queryPath(guid, wVerMajor, wVerMinor, lpbstrPathName);
}

// ============================================================================
// 9. Subsystem Export Registration (oleaut32.dll)
// ============================================================================

inline void InitializeOleAut32SubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // BSTR APIs
    ldr.registerExport("oleaut32.dll", "SysAllocString", reinterpret_cast<void*>(SysAllocString));
    ldr.registerExport("oleaut32.dll", "SysAllocStringLen", reinterpret_cast<void*>(SysAllocStringLen));
    ldr.registerExport("oleaut32.dll", "SysAllocStringByteLen", reinterpret_cast<void*>(SysAllocStringByteLen));
    ldr.registerExport("oleaut32.dll", "SysFreeString", reinterpret_cast<void*>(SysFreeString));
    ldr.registerExport("oleaut32.dll", "SysStringLen", reinterpret_cast<void*>(SysStringLen));
    ldr.registerExport("oleaut32.dll", "SysStringByteLen", reinterpret_cast<void*>(SysStringByteLen));
    ldr.registerExport("oleaut32.dll", "SysReAllocString", reinterpret_cast<void*>(SysReAllocString));
    ldr.registerExport("oleaut32.dll", "SysReAllocStringLen", reinterpret_cast<void*>(SysReAllocStringLen));

    // VARIANT APIs
    ldr.registerExport("oleaut32.dll", "VariantInit", reinterpret_cast<void*>(VariantInit));
    ldr.registerExport("oleaut32.dll", "VariantClear", reinterpret_cast<void*>(VariantClear));
    ldr.registerExport("oleaut32.dll", "VariantCopy", reinterpret_cast<void*>(VariantCopy));
    ldr.registerExport("oleaut32.dll", "VariantCopyInd", reinterpret_cast<void*>(VariantCopyInd));
    ldr.registerExport("oleaut32.dll", "VariantChangeType", reinterpret_cast<void*>(VariantChangeType));
    ldr.registerExport("oleaut32.dll", "VariantChangeTypeEx", reinterpret_cast<void*>(VariantChangeTypeEx));
    ldr.registerExport("oleaut32.dll", "VarCmp", reinterpret_cast<void*>(VarCmp));

    // SAFEARRAY APIs
    ldr.registerExport("oleaut32.dll", "SafeArrayCreate", reinterpret_cast<void*>(SafeArrayCreate));
    ldr.registerExport("oleaut32.dll", "SafeArrayCreateVector", reinterpret_cast<void*>(SafeArrayCreateVector));
    ldr.registerExport("oleaut32.dll", "SafeArrayDestroy", reinterpret_cast<void*>(SafeArrayDestroy));
    ldr.registerExport("oleaut32.dll", "SafeArrayGetDim", reinterpret_cast<void*>(SafeArrayGetDim));
    ldr.registerExport("oleaut32.dll", "SafeArrayGetElemsize", reinterpret_cast<void*>(SafeArrayGetElemsize));
    ldr.registerExport("oleaut32.dll", "SafeArrayGetLBound", reinterpret_cast<void*>(SafeArrayGetLBound));
    ldr.registerExport("oleaut32.dll", "SafeArrayGetUBound", reinterpret_cast<void*>(SafeArrayGetUBound));
    ldr.registerExport("oleaut32.dll", "SafeArrayAccessData", reinterpret_cast<void*>(SafeArrayAccessData));
    ldr.registerExport("oleaut32.dll", "SafeArrayUnaccessData", reinterpret_cast<void*>(SafeArrayUnaccessData));
    ldr.registerExport("oleaut32.dll", "SafeArrayGetElement", reinterpret_cast<void*>(SafeArrayGetElement));
    ldr.registerExport("oleaut32.dll", "SafeArrayPutElement", reinterpret_cast<void*>(SafeArrayPutElement));
    ldr.registerExport("oleaut32.dll", "SafeArrayCopy", reinterpret_cast<void*>(SafeArrayCopy));
    ldr.registerExport("oleaut32.dll", "SafeArrayRedim", reinterpret_cast<void*>(SafeArrayRedim));
    ldr.registerExport("oleaut32.dll", "SafeArrayGetVartype", reinterpret_cast<void*>(SafeArrayGetVartype));

    // Dispatch APIs
    ldr.registerExport("oleaut32.dll", "CreateStdDispatch", reinterpret_cast<void*>(CreateStdDispatch));
    ldr.registerExport("oleaut32.dll", "DispGetParam", reinterpret_cast<void*>(DispGetParam));
    ldr.registerExport("oleaut32.dll", "DispInvoke", reinterpret_cast<void*>(DispInvoke));

    // Type Library APIs
    ldr.registerExport("oleaut32.dll", "LoadTypeLib", reinterpret_cast<void*>(LoadTypeLib));
    ldr.registerExport("oleaut32.dll", "LoadRegTypeLib", reinterpret_cast<void*>(LoadRegTypeLib));
    ldr.registerExport("oleaut32.dll", "RegisterTypeLib", reinterpret_cast<void*>(RegisterTypeLib));
    ldr.registerExport("oleaut32.dll", "QueryPathOfRegTypeLib", reinterpret_cast<void*>(QueryPathOfRegTypeLib));
}

} // namespace micant::oleaut32
