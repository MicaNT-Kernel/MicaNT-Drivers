// ============================================================================
// MicaNT: Windows Management Instrumentation (WMI) / WBEM Subsystem
// (wbemprox.dll, fastprox.dll & wmic CLI Engine)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Provides complete Common Information Model (CIM v2) object store,
// WQL (WMI Query Language) engine, standard Win32 management classes
// (Win32_OperatingSystem, Win32_Processor, Win32_ComputerSystem,
//  Win32_LogicalDisk, Win32_NetworkAdapter, Win32_NetworkAdapterConfiguration,
//  Win32_VideoController, Win32_Service, Win32_Process, Win32_BIOS),
// COM Interfaces (IWbemLocator, IWbemServices, IWbemClassObject,
//                 IEnumWbemClassObject, IWbemContext),
// and dynamic COM registration (CLSID_WbemLocator).
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
#include <atomic>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cwchar>

#include "ntdef.hpp"
#include "kernel32.hpp"
#include "ole32.hpp"
#include "oleaut32.hpp"
#include "hal.hpp"
#include "mm.hpp"
#include "fs.hpp"
#include "tcpip.hpp"
#include "scm.hpp"
#include "ldr.hpp"

namespace micant::wbem {

using namespace micant::ole32;

// ============================================================================
// 1. WMI / WBEM CLSIDs, IIDs & Status Codes
// ============================================================================

// CLSID_WbemLocator: {4590F811-1D3A-11D0-891F-00AA004B2E24}
inline constexpr GUID CLSID_WbemLocator = {
    0x4590F811, 0x1D3A, 0x11D0, { 0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24 }
};

// IID_IWbemLocator: {DC12A687-737F-11CF-884D-00AA004B2E24}
inline constexpr GUID IID_IWbemLocator = {
    0xDC12A687, 0x737F, 0x11CF, { 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24 }
};

// IID_IWbemServices: {9556DC99-828C-11CF-A37E-00AA003240C7}
inline constexpr GUID IID_IWbemServices = {
    0x9556DC99, 0x828C, 0x11CF, { 0xA3, 0x7E, 0x00, 0xAA, 0x00, 0x32, 0x40, 0xC7 }
};

// IID_IWbemClassObject: {DC12A681-737F-11CF-884D-00AA004B2E24}
inline constexpr GUID IID_IWbemClassObject = {
    0xDC12A681, 0x737F, 0x11CF, { 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24 }
};

// IID_IEnumWbemClassObject: {027947E1-D731-11CE-A357-000000000001}
inline constexpr GUID IID_IEnumWbemClassObject = {
    0x027947E1, 0xD731, 0x11CE, { 0xA3, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }
};

// IID_IWbemContext: {9CED8F78-229B-11D1-AE2A-00A0C90FFFC3}
inline constexpr GUID IID_IWbemContext = {
    0x9CED8F78, 0x229B, 0x11D1, { 0xAE, 0x2A, 0x00, 0xA0, 0xC9, 0x0F, 0xFF, 0xC3 }
};

// CIM Type Enumerations
enum CIMTYPE_ENUMERATION {
    CIM_ILLEGAL   = 0xFFF,
    CIM_EMPTY     = 0,
    CIM_SINT8     = 16,
    CIM_UINT8     = 17,
    CIM_SINT16    = 2,
    CIM_UINT16    = 18,
    CIM_SINT32    = 3,
    CIM_UINT32    = 19,
    CIM_SINT64    = 20,
    CIM_UINT64    = 21,
    CIM_REAL32    = 4,
    CIM_REAL64    = 5,
    CIM_BOOLEAN   = 11,
    CIM_STRING    = 8,
    CIM_DATETIME  = 101,
    CIM_REFERENCE = 102,
    CIM_CHAR16    = 103,
    CIM_OBJECT    = 13,
    CIM_FLAG_ARRAY= 0x2000
};
using CIMTYPE = int32_t;

// WBEM Status & Error Codes
inline constexpr HRESULT WBEM_S_NO_ERROR                 = static_cast<HRESULT>(0x00000000);
inline constexpr HRESULT WBEM_S_FALSE                    = static_cast<HRESULT>(0x00000001);
inline constexpr HRESULT WBEM_S_TIMEDOUT                 = static_cast<HRESULT>(0x00040004);
inline constexpr HRESULT WBEM_S_NO_MORE_DATA            = static_cast<HRESULT>(0x00040005);
inline constexpr HRESULT WBEM_S_DIFFERENT                = static_cast<HRESULT>(0x0004001B);
inline constexpr HRESULT WBEM_E_FAILED                   = static_cast<HRESULT>(0x80041001);
inline constexpr HRESULT WBEM_E_NOT_FOUND                = static_cast<HRESULT>(0x80041002);
inline constexpr HRESULT WBEM_E_ACCESS_DENIED            = static_cast<HRESULT>(0x80041003);
inline constexpr HRESULT WBEM_E_PROVIDER_FAILURE         = static_cast<HRESULT>(0x80041004);
inline constexpr HRESULT WBEM_E_TYPE_MISMATCH            = static_cast<HRESULT>(0x80041005);
inline constexpr HRESULT WBEM_E_OUT_OF_MEMORY            = static_cast<HRESULT>(0x80041006);
inline constexpr HRESULT WBEM_E_INVALID_CONTEXT          = static_cast<HRESULT>(0x80041007);
inline constexpr HRESULT WBEM_E_INVALID_PARAMETER        = static_cast<HRESULT>(0x80041008);
inline constexpr HRESULT WBEM_E_NOT_AVAILABLE            = static_cast<HRESULT>(0x80041009);
inline constexpr HRESULT WBEM_E_CRITICAL_ERROR           = static_cast<HRESULT>(0x8004100A);
inline constexpr HRESULT WBEM_E_INVALID_STREAM           = static_cast<HRESULT>(0x8004100B);
inline constexpr HRESULT WBEM_E_NOT_SUPPORTED            = static_cast<HRESULT>(0x8004100C);
inline constexpr HRESULT WBEM_E_INVALID_SUPERCLASS       = static_cast<HRESULT>(0x8004100D);
inline constexpr HRESULT WBEM_E_INVALID_NAMESPACE        = static_cast<HRESULT>(0x8004100E);
inline constexpr HRESULT WBEM_E_INVALID_OBJECT           = static_cast<HRESULT>(0x8004100F);
inline constexpr HRESULT WBEM_E_INVALID_CLASS            = static_cast<HRESULT>(0x80041010);
inline constexpr HRESULT WBEM_E_PROVIDER_NOT_FOUND       = static_cast<HRESULT>(0x80041011);
inline constexpr HRESULT WBEM_E_INVALID_QUERY            = static_cast<HRESULT>(0x80041017);
inline constexpr HRESULT WBEM_E_INVALID_QUERY_TYPE       = static_cast<HRESULT>(0x80041018);

// WBEM Execution Flags
inline constexpr int32_t WBEM_FLAG_RETURN_IMMEDIATELY    = 0x10;
inline constexpr int32_t WBEM_FLAG_FORWARD_ONLY          = 0x20;
inline constexpr int32_t WBEM_FLAG_BIDIRECTIONAL         = 0x00;
inline constexpr int32_t WBEM_FLAG_DIRECT_READ           = 0x0200;
inline constexpr int32_t WBEM_FLAG_NONSYSTEM_ONLY        = 0x40;
inline constexpr int32_t WBEM_FLAG_SYSTEM_ONLY           = 0x30;
inline constexpr int32_t WBEM_FLAG_ALWAYS                = 0x00;
inline constexpr uint32_t WBEM_INFINITE                  = 0xFFFFFFFF;

// WBEM Property Flavors
inline constexpr int32_t WBEM_FLAVOR_DONT_PROPAGATE      = 0x00;
inline constexpr int32_t WBEM_FLAVOR_FLAG_PROPAGATE_TO_INSTANCE = 0x01;
inline constexpr int32_t WBEM_FLAVOR_FLAG_PROPAGATE_TO_DERIVED_CLASS = 0x02;
inline constexpr int32_t WBEM_FLAVOR_ORIGIN_SYSTEM       = 0x40;
inline constexpr int32_t WBEM_FLAVOR_ORIGIN_PROPAGATED   = 0x20;
inline constexpr int32_t WBEM_FLAVOR_ORIGIN_LOCAL        = 0x00;

// Forward Declarations
class IWbemContext;
class IWbemClassObject;
class IEnumWbemClassObject;
class IWbemServices;
class IWbemLocator;

// ============================================================================
// 2. Pure Virtual COM Interfaces
// ============================================================================

class IWbemContext : public IUnknown {
public:
    virtual HRESULT __stdcall Clone(IWbemContext** ppNewCopy) = 0;
    virtual HRESULT __stdcall GetNames(int32_t lFlags, oleaut32::SAFEARRAY** pNames) = 0;
    virtual HRESULT __stdcall BeginEnumeration(int32_t lFlags) = 0;
    virtual HRESULT __stdcall Next(int32_t lFlags, BSTR* pstrName, VARIANT* pValue) = 0;
    virtual HRESULT __stdcall EndEnumeration() = 0;
    virtual HRESULT __stdcall SetValue(const wchar_t* wszName, int32_t lFlags, VARIANT* pValue) = 0;
    virtual HRESULT __stdcall GetValue(const wchar_t* wszName, int32_t lFlags, VARIANT* pValue) = 0;
    virtual HRESULT __stdcall DeleteValue(const wchar_t* wszName, int32_t lFlags) = 0;
    virtual HRESULT __stdcall DeleteAll() = 0;
};

class IWbemClassObject : public IUnknown {
public:
    virtual HRESULT __stdcall GetQualifierSet(void** ppQualSet) = 0;
    virtual HRESULT __stdcall Get(const wchar_t* wszName, int32_t lFlags, VARIANT* pVal, CIMTYPE* pType, int32_t* plFlavor) = 0;
    virtual HRESULT __stdcall Put(const wchar_t* wszName, int32_t lFlags, VARIANT* pVal, CIMTYPE Type) = 0;
    virtual HRESULT __stdcall Delete(const wchar_t* wszName) = 0;
    virtual HRESULT __stdcall GetNames(const wchar_t* wszQualifierName, int32_t lFlags, VARIANT* pQualifierVal, oleaut32::SAFEARRAY** pNames) = 0;
    virtual HRESULT __stdcall BeginEnumeration(int32_t lEnumFlags) = 0;
    virtual HRESULT __stdcall Next(int32_t lFlags, BSTR* strName, VARIANT* pVal, CIMTYPE* pType, int32_t* plFlavor) = 0;
    virtual HRESULT __stdcall EndEnumeration() = 0;
    virtual HRESULT __stdcall GetPropertyQualifierSet(const wchar_t* wszProperty, void** ppQualSet) = 0;
    virtual HRESULT __stdcall Clone(IWbemClassObject** ppCopy) = 0;
    virtual HRESULT __stdcall GetObjectText(int32_t lFlags, BSTR* pstrObjectText) = 0;
    virtual HRESULT __stdcall SpawnDerivedClass(int32_t lFlags, IWbemClassObject** ppNewClass) = 0;
    virtual HRESULT __stdcall SpawnInstance(int32_t lFlags, IWbemClassObject** ppNewInstance) = 0;
    virtual HRESULT __stdcall CompareTo(int32_t lFlags, IWbemClassObject* pCompareTo) = 0;
    virtual HRESULT __stdcall GetPropertyOrigin(const wchar_t* wszProperty, BSTR* pstrClassName) = 0;
    virtual HRESULT __stdcall InheritsFrom(const wchar_t* strAncestor) = 0;
    virtual HRESULT __stdcall GetMethod(const wchar_t* wszName, int32_t lFlags, IWbemClassObject** ppInSignature, IWbemClassObject** ppOutSignature) = 0;
    virtual HRESULT __stdcall PutMethod(const wchar_t* wszName, int32_t lFlags, IWbemClassObject* pInSignature, IWbemClassObject* pOutSignature) = 0;
    virtual HRESULT __stdcall DeleteMethod(const wchar_t* wszName) = 0;
    virtual HRESULT __stdcall BeginMethodEnumeration(int32_t lEnumFlags) = 0;
    virtual HRESULT __stdcall NextMethod(int32_t lFlags, BSTR* pstrName, IWbemClassObject** ppInSignature, IWbemClassObject** ppOutSignature) = 0;
    virtual HRESULT __stdcall EndMethodEnumeration() = 0;
    virtual HRESULT __stdcall GetMethodQualifierSet(const wchar_t* wszMethod, void** ppQualSet) = 0;
};

class IEnumWbemClassObject : public IUnknown {
public:
    virtual HRESULT __stdcall Reset() = 0;
    virtual HRESULT __stdcall Next(int32_t lTimeout, uint32_t uCount, IWbemClassObject** apObjects, uint32_t* puReturned) = 0;
    virtual HRESULT __stdcall NextAsync(uint32_t uCount, void* pSink) = 0;
    virtual HRESULT __stdcall Clone(IEnumWbemClassObject** ppEnum) = 0;
    virtual HRESULT __stdcall Skip(int32_t lTimeout, uint32_t nCount) = 0;
};

class IWbemServices : public IUnknown {
public:
    virtual HRESULT __stdcall OpenNamespace(const BSTR strNamespace, int32_t lFlags, IWbemContext* pCtx, IWbemServices** ppWorkingNamespace, void** ppResult) = 0;
    virtual HRESULT __stdcall CancelAsyncCall(void* pSink) = 0;
    virtual HRESULT __stdcall QueryObjectSink(int32_t lFlags, void** ppResponseHandler) = 0;
    virtual HRESULT __stdcall GetObject(const BSTR strObjectPath, int32_t lFlags, IWbemContext* pCtx, IWbemClassObject** ppObject, void** ppCallResult) = 0;
    virtual HRESULT __stdcall GetObjectAsync(const BSTR strObjectPath, int32_t lFlags, IWbemContext* pCtx, void* pResponseHandler) = 0;
    virtual HRESULT __stdcall PutClass(IWbemClassObject* pObject, int32_t lFlags, IWbemContext* pCtx, void** ppCallResult) = 0;
    virtual HRESULT __stdcall PutClassAsync(IWbemClassObject* pObject, int32_t lFlags, IWbemContext* pCtx, void* pResponseHandler) = 0;
    virtual HRESULT __stdcall DeleteClass(const BSTR strClass, int32_t lFlags, IWbemContext* pCtx, void** ppCallResult) = 0;
    virtual HRESULT __stdcall DeleteClassAsync(const BSTR strClass, int32_t lFlags, IWbemContext* pCtx, void* pResponseHandler) = 0;
    virtual HRESULT __stdcall CreateClassEnum(const BSTR strSuperclass, int32_t lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) = 0;
    virtual HRESULT __stdcall CreateClassEnumAsync(const BSTR strSuperclass, int32_t lFlags, IWbemContext* pCtx, void* pResponseHandler) = 0;
    virtual HRESULT __stdcall PutInstance(IWbemClassObject* pInst, int32_t lFlags, IWbemContext* pCtx, void** ppCallResult) = 0;
    virtual HRESULT __stdcall PutInstanceAsync(IWbemClassObject* pInst, int32_t lFlags, IWbemContext* pCtx, void* pResponseHandler) = 0;
    virtual HRESULT __stdcall DeleteInstance(const BSTR strObjectPath, int32_t lFlags, IWbemContext* pCtx, void** ppCallResult) = 0;
    virtual HRESULT __stdcall DeleteInstanceAsync(const BSTR strObjectPath, int32_t lFlags, IWbemContext* pCtx, void* pResponseHandler) = 0;
    virtual HRESULT __stdcall CreateInstanceEnum(const BSTR strFilter, int32_t lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) = 0;
    virtual HRESULT __stdcall CreateInstanceEnumAsync(const BSTR strFilter, int32_t lFlags, IWbemContext* pCtx, void* pResponseHandler) = 0;
    virtual HRESULT __stdcall ExecQuery(const BSTR strQueryLanguage, const BSTR strQuery, int32_t lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) = 0;
    virtual HRESULT __stdcall ExecQueryAsync(const BSTR strQueryLanguage, const BSTR strQuery, int32_t lFlags, IWbemContext* pCtx, void* pResponseHandler) = 0;
    virtual HRESULT __stdcall ExecNotificationQuery(const BSTR strQueryLanguage, const BSTR strQuery, int32_t lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) = 0;
    virtual HRESULT __stdcall ExecNotificationQueryAsync(const BSTR strQueryLanguage, const BSTR strQuery, int32_t lFlags, IWbemContext* pCtx, void* pResponseHandler) = 0;
    virtual HRESULT __stdcall ExecMethod(const BSTR strObjectPath, const BSTR strMethodName, int32_t lFlags, IWbemContext* pCtx, IWbemClassObject* pInParams, IWbemClassObject** ppOutParams, void** ppCallResult) = 0;
    virtual HRESULT __stdcall ExecMethodAsync(const BSTR strObjectPath, const BSTR strMethodName, int32_t lFlags, IWbemContext* pCtx, IWbemClassObject* pInParams, void* pResponseHandler) = 0;
};

class IWbemLocator : public IUnknown {
public:
    virtual HRESULT __stdcall ConnectServer(
        const BSTR strNetworkResource,
        const BSTR strUser,
        const BSTR strPassword,
        const BSTR strLocale,
        int32_t lSecurityFlags,
        const BSTR strAuthority,
        IWbemContext* pCtx,
        IWbemServices** ppNamespace
    ) = 0;
};

// ============================================================================
// 3. Concrete Implementations: WbemClassObject & Property Store
// ============================================================================

struct CimProperty {
    std::wstring name;
    VARIANT value{};
    CIMTYPE type{ CIM_STRING };

    CimProperty() {
        oleaut32::VariantInit(&value);
    }

    CimProperty(std::wstring n, const VARIANT& v, CIMTYPE t)
        : name(std::move(n)), type(t) {
        oleaut32::VariantInit(&value);
        oleaut32::VariantCopy(&value, const_cast<VARIANT*>(&v));
    }

    ~CimProperty() {
        oleaut32::VariantClear(&value);
    }

    CimProperty(const CimProperty& other) : name(other.name), type(other.type) {
        oleaut32::VariantInit(&value);
        oleaut32::VariantCopy(&value, const_cast<VARIANT*>(&other.value));
    }

    CimProperty& operator=(const CimProperty& other) {
        if (this != &other) {
            name = other.name;
            type = other.type;
            oleaut32::VariantCopy(&value, const_cast<VARIANT*>(&other.value));
        }
        return *this;
    }

    CimProperty(CimProperty&& other) noexcept
        : name(std::move(other.name)), value(other.value), type(other.type) {
        oleaut32::VariantInit(&other.value);
    }

    CimProperty& operator=(CimProperty&& other) noexcept {
        if (this != &other) {
            oleaut32::VariantClear(&value);
            name = std::move(other.name);
            value = other.value;
            type = other.type;
            oleaut32::VariantInit(&other.value);
        }
        return *this;
    }
};

class WbemClassObject : public IWbemClassObject {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_className;
    std::vector<std::wstring> m_propertyNames;
    std::unordered_map<std::wstring, CimProperty> m_properties;
    size_t m_enumIndex{ 0 };
    std::mutex m_mutex;

public:
    WbemClassObject(std::wstring className = L"") : m_className(std::move(className)) {}

    // IUnknown
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemClassObject) {
            *ppv = static_cast<IWbemClassObject*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IWbemClassObject
    HRESULT __stdcall GetQualifierSet(void** ppQualSet) override {
        if (ppQualSet) *ppQualSet = nullptr;
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall Get(const wchar_t* wszName, int32_t, VARIANT* pVal, CIMTYPE* pType, int32_t* plFlavor) override {
        if (!wszName || !pVal) return WBEM_E_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring key(wszName);
        if (key == L"__CLASS") {
            pVal->vt = VT_BSTR;
            pVal->bstrVal = ole32::SysAllocString(m_className.c_str());
            if (pType) *pType = CIM_STRING;
            if (plFlavor) *plFlavor = WBEM_FLAVOR_ORIGIN_SYSTEM;
            return WBEM_S_NO_ERROR;
        }

        auto it = m_properties.find(key);
        if (it == m_properties.end()) {
            return WBEM_E_NOT_FOUND;
        }

        oleaut32::VariantInit(pVal);
        oleaut32::VariantCopy(pVal, const_cast<VARIANT*>(&it->second.value));
        if (pType) *pType = it->second.type;
        if (plFlavor) *plFlavor = WBEM_FLAVOR_ORIGIN_LOCAL;
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall Put(const wchar_t* wszName, int32_t, VARIANT* pVal, CIMTYPE Type) override {
        if (!wszName || !pVal) return WBEM_E_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring key(wszName);
        if (m_properties.find(key) == m_properties.end()) {
            m_propertyNames.push_back(key);
        }
        m_properties[key] = CimProperty(key, *pVal, Type);
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall Delete(const wchar_t* wszName) override {
        if (!wszName) return WBEM_E_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring key(wszName);
        auto it = m_properties.find(key);
        if (it != m_properties.end()) {
            m_properties.erase(it);
            auto itName = std::find(m_propertyNames.begin(), m_propertyNames.end(), key);
            if (itName != m_propertyNames.end()) m_propertyNames.erase(itName);
            return WBEM_S_NO_ERROR;
        }
        return WBEM_E_NOT_FOUND;
    }

    HRESULT __stdcall GetNames(const wchar_t*, int32_t, VARIANT*, oleaut32::SAFEARRAY** pNames) override {
        if (!pNames) return WBEM_E_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto* sa = oleaut32::SafeArrayCreateVector(VT_BSTR, 0, static_cast<uint32_t>(m_propertyNames.size()));
        if (!sa) return WBEM_E_OUT_OF_MEMORY;

        for (uint32_t i = 0; i < m_propertyNames.size(); ++i) {
            BSTR bstr = ole32::SysAllocString(m_propertyNames[i].c_str());
            int32_t idx = static_cast<int32_t>(i);
            oleaut32::SafeArrayPutElement(sa, &idx, bstr);
            oleaut32::SysFreeString(bstr);
        }

        *pNames = sa;
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall BeginEnumeration(int32_t) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enumIndex = 0;
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall Next(int32_t, BSTR* strName, VARIANT* pVal, CIMTYPE* pType, int32_t* plFlavor) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_enumIndex >= m_propertyNames.size()) {
            return WBEM_S_NO_MORE_DATA;
        }

        const auto& propName = m_propertyNames[m_enumIndex++];
        if (strName) *strName = ole32::SysAllocString(propName.c_str());

        auto it = m_properties.find(propName);
        if (it != m_properties.end()) {
            if (pVal) {
                oleaut32::VariantInit(pVal);
                oleaut32::VariantCopy(pVal, const_cast<VARIANT*>(&it->second.value));
            }
            if (pType) *pType = it->second.type;
            if (plFlavor) *plFlavor = WBEM_FLAVOR_ORIGIN_LOCAL;
        }
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall EndEnumeration() override {
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall GetPropertyQualifierSet(const wchar_t*, void** ppQualSet) override {
        if (ppQualSet) *ppQualSet = nullptr;
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall Clone(IWbemClassObject** ppCopy) override {
        if (!ppCopy) return WBEM_E_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto* clone = new WbemClassObject(m_className);
        clone->m_propertyNames = m_propertyNames;
        clone->m_properties = m_properties;
        *ppCopy = clone;
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall GetObjectText(int32_t, BSTR* pstrObjectText) override {
        if (!pstrObjectText) return WBEM_E_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wostringstream oss;
        oss << L"instance of " << m_className << L"\n{\n";
        for (const auto& name : m_propertyNames) {
            const auto& prop = m_properties[name];
            oss << L"    " << name << L" = ";
            if (prop.value.vt == VT_BSTR && prop.value.bstrVal) {
                oss << L"\"" << prop.value.bstrVal << L"\"";
            } else if (prop.value.vt == VT_I4) {
                oss << prop.value.lVal;
            } else if (prop.value.vt == VT_UI4) {
                oss << prop.value.ulVal;
            } else if (prop.value.vt == VT_UI8) {
                oss << prop.value.ullVal;
            } else if (prop.value.vt == VT_BOOL) {
                oss << (prop.value.boolVal ? L"TRUE" : L"FALSE");
            } else {
                oss << L"\"<value>\"";
            }
            oss << L";\n";
        }
        oss << L"};\n";

        *pstrObjectText = ole32::SysAllocString(oss.str().c_str());
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall SpawnDerivedClass(int32_t, IWbemClassObject**) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall SpawnInstance(int32_t, IWbemClassObject** ppNewInstance) override { return Clone(ppNewInstance); }
    HRESULT __stdcall CompareTo(int32_t, IWbemClassObject*) override { return WBEM_S_NO_ERROR; }
    HRESULT __stdcall GetPropertyOrigin(const wchar_t*, BSTR* pstrClassName) override {
        if (pstrClassName) *pstrClassName = ole32::SysAllocString(m_className.c_str());
        return WBEM_S_NO_ERROR;
    }
    HRESULT __stdcall InheritsFrom(const wchar_t*) override { return WBEM_S_FALSE; }
    HRESULT __stdcall GetMethod(const wchar_t*, int32_t, IWbemClassObject**, IWbemClassObject**) override { return WBEM_E_NOT_FOUND; }
    HRESULT __stdcall PutMethod(const wchar_t*, int32_t, IWbemClassObject*, IWbemClassObject*) override { return WBEM_S_NO_ERROR; }
    HRESULT __stdcall DeleteMethod(const wchar_t*) override { return WBEM_S_NO_ERROR; }
    HRESULT __stdcall BeginMethodEnumeration(int32_t) override { return WBEM_S_NO_ERROR; }
    HRESULT __stdcall NextMethod(int32_t, BSTR*, IWbemClassObject**, IWbemClassObject**) override { return WBEM_S_NO_MORE_DATA; }
    HRESULT __stdcall EndMethodEnumeration() override { return WBEM_S_NO_ERROR; }
    HRESULT __stdcall GetMethodQualifierSet(const wchar_t*, void** ppQualSet) override {
        if (ppQualSet) *ppQualSet = nullptr;
        return WBEM_S_NO_ERROR;
    }

    // Helper methods
    void SetString(const wchar_t* name, const wchar_t* val) {
        VARIANT v{};
        v.vt = VT_BSTR;
        v.bstrVal = ole32::SysAllocString(val);
        Put(name, 0, &v, CIM_STRING);
        oleaut32::VariantClear(&v);
    }

    void SetInt32(const wchar_t* name, int32_t val) {
        VARIANT v{};
        v.vt = VT_I4;
        v.lVal = val;
        Put(name, 0, &v, CIM_SINT32);
    }

    void SetUInt16(const wchar_t* name, uint16_t val) {
        VARIANT v{};
        v.vt = VT_UI2;
        v.uiVal = val;
        Put(name, 0, &v, CIM_UINT16);
    }

    void SetUInt32(const wchar_t* name, uint32_t val) {
        VARIANT v{};
        v.vt = VT_UI4;
        v.ulVal = val;
        Put(name, 0, &v, CIM_UINT32);
    }

    void SetUInt64(const wchar_t* name, uint64_t val) {
        VARIANT v{};
        v.vt = VT_UI8;
        v.ullVal = val;
        Put(name, 0, &v, CIM_UINT64);
    }

    void SetBool(const wchar_t* name, bool val) {
        VARIANT v{};
        v.vt = VT_BOOL;
        v.boolVal = val ? VARIANT_TRUE : VARIANT_FALSE;
        Put(name, 0, &v, CIM_BOOLEAN);
    }

    const std::wstring& GetClassName() const { return m_className; }
};

// ============================================================================
// 4. Enumerator Implementation: EnumWbemClassObject
// ============================================================================

class EnumWbemClassObject : public IEnumWbemClassObject {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<IWbemClassObject*> m_objects;
    size_t m_cursor{ 0 };
    std::mutex m_mutex;

public:
    EnumWbemClassObject(std::vector<IWbemClassObject*> objs) : m_objects(std::move(objs)) {
        for (auto* obj : m_objects) {
            if (obj) obj->AddRef();
        }
    }

    ~EnumWbemClassObject() {
        for (auto* obj : m_objects) {
            if (obj) obj->Release();
        }
    }

    // IUnknown
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IEnumWbemClassObject) {
            *ppv = static_cast<IEnumWbemClassObject*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IEnumWbemClassObject
    HRESULT __stdcall Reset() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cursor = 0;
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall Next(int32_t, uint32_t uCount, IWbemClassObject** apObjects, uint32_t* puReturned) override {
        if (!apObjects || !puReturned) return WBEM_E_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        uint32_t count = 0;
        while (count < uCount && m_cursor < m_objects.size()) {
            apObjects[count] = m_objects[m_cursor++];
            if (apObjects[count]) apObjects[count]->AddRef();
            count++;
        }
        *puReturned = count;
        return (count == uCount) ? WBEM_S_NO_ERROR : WBEM_S_FALSE;
    }

    HRESULT __stdcall NextAsync(uint32_t, void*) override { return WBEM_E_NOT_SUPPORTED; }

    HRESULT __stdcall Clone(IEnumWbemClassObject** ppEnum) override {
        if (!ppEnum) return WBEM_E_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto* e = new EnumWbemClassObject(m_objects);
        e->m_cursor = m_cursor;
        *ppEnum = e;
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall Skip(int32_t, uint32_t nCount) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cursor = std::min(m_cursor + nCount, m_objects.size());
        return (m_cursor < m_objects.size()) ? WBEM_S_NO_ERROR : WBEM_S_FALSE;
    }
};

// ============================================================================
// 5. Central CIM Repository & Providers
// ============================================================================

class CimRepository {
private:
    std::mutex m_mutex;

    CimRepository() {}

public:
    static CimRepository& Instance() {
        static CimRepository s_inst;
        return s_inst;
    }

    std::vector<IWbemClassObject*> QueryClass(std::wstring_view className) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::wstring cls(className);
        std::vector<IWbemClassObject*> result;

        if (cls == L"Win32_OperatingSystem") {
            auto* obj = new WbemClassObject(L"Win32_OperatingSystem");
            obj->SetString(L"Caption", L"MicaNT 10.0 Sovereign Operating System");
            obj->SetString(L"Version", L"10.0.26100.1");
            obj->SetString(L"BuildNumber", L"26100");
            obj->SetString(L"CSName", L"MICANT-STATION");
            obj->SetString(L"OSArchitecture", L"64-bit");
            obj->SetUInt64(L"TotalVisibleMemorySize", 16777216); // 16 GB in KB
            obj->SetUInt64(L"FreePhysicalMemory", 16252928);     // ~15.5 GB in KB
            obj->SetUInt64(L"TotalVirtualMemorySize", 33554432); // 32 GB in KB
            obj->SetUInt64(L"FreeVirtualMemory", 32505856);
            obj->SetString(L"Status", L"OK");
            obj->SetString(L"Manufacturer", L"Project MICA (Dave Cutler Architecture)");
            obj->SetString(L"WindowsDirectory", L"C:\\Windows");
            obj->SetString(L"SystemDirectory", L"C:\\Windows\\System32");
            obj->SetString(L"BootDevice", L"\\Device\\HarddiskVolume1");
            result.push_back(obj);
        } else if (cls == L"Win32_Processor") {
            auto* obj = new WbemClassObject(L"Win32_Processor");
            obj->SetString(L"Name", L"MicaNT SMP Host Virtual Processor");
            obj->SetString(L"DeviceID", L"CPU0");
            obj->SetUInt32(L"NumberOfCores", 4);
            obj->SetUInt32(L"NumberOfLogicalProcessors", 4);
            obj->SetUInt32(L"MaxClockSpeed", 3600); // 3.6 GHz
            obj->SetUInt16(L"Architecture", 9);    // x64
            obj->SetUInt16(L"AddressWidth", 64);
            obj->SetUInt16(L"DataWidth", 64);
            obj->SetString(L"Manufacturer", L"GenuineMica");
            obj->SetString(L"Status", L"OK");
            obj->SetString(L"SocketDesignation", L"LGA1700");
            result.push_back(obj);
        } else if (cls == L"Win32_ComputerSystem") {
            auto* obj = new WbemClassObject(L"Win32_ComputerSystem");
            obj->SetString(L"Name", L"MICANT-STATION");
            obj->SetString(L"Model", L"MicaNT Sovereign Workstation");
            obj->SetString(L"Manufacturer", L"MicaNT Sovereign Project");
            obj->SetString(L"SystemType", L"x64-based PC");
            obj->SetUInt64(L"TotalPhysicalMemory", 17179869184ULL); // 16 GB in bytes
            obj->SetUInt32(L"NumberOfProcessors", 1);
            obj->SetString(L"Domain", L"WORKGROUP");
            obj->SetString(L"UserName", L"MICANT-STATION\\admin");
            obj->SetString(L"Status", L"OK");
            result.push_back(obj);
        } else if (cls == L"Win32_LogicalDisk") {
            auto* obj = new WbemClassObject(L"Win32_LogicalDisk");
            obj->SetString(L"DeviceID", L"C:");
            obj->SetUInt32(L"DriveType", 3); // Local Hard Disk
            obj->SetString(L"FileSystem", L"NTFS");
            obj->SetString(L"VolumeName", L"MicaNT-System");
            obj->SetUInt64(L"Size", 2199023255552ULL);      // 2 TB
            obj->SetUInt64(L"FreeSpace", 1869169766400ULL); // ~1.7 TB
            obj->SetUInt32(L"MediaType", 12);               // Fixed hard disk
            obj->SetString(L"Status", L"OK");
            result.push_back(obj);
        } else if (cls == L"Win32_NetworkAdapter") {
            auto* obj = new WbemClassObject(L"Win32_NetworkAdapter");
            obj->SetString(L"DeviceID", L"1");
            obj->SetString(L"Name", L"MicaNT Sovereign Gigabit Ethernet Adapter");
            obj->SetString(L"AdapterType", L"Ethernet 802.3");
            obj->SetString(L"MACAddress", L"00:15:5D:01:02:03");
            obj->SetUInt64(L"Speed", 1000000000ULL); // 1 Gbps
            obj->SetUInt16(L"NetConnectionStatus", 2); // Connected
            obj->SetBool(L"PhysicalAdapter", true);
            obj->SetString(L"Status", L"OK");
            result.push_back(obj);
        } else if (cls == L"Win32_NetworkAdapterConfiguration") {
            auto* obj = new WbemClassObject(L"Win32_NetworkAdapterConfiguration");
            obj->SetUInt32(L"Index", 1);
            obj->SetString(L"Description", L"MicaNT Sovereign Gigabit Ethernet Adapter");
            obj->SetBool(L"IPEnabled", true);
            obj->SetString(L"IPAddress", L"192.168.1.100");
            obj->SetString(L"IPSubnet", L"255.255.255.0");
            obj->SetString(L"DefaultIPGateway", L"192.168.1.1");
            obj->SetString(L"MACAddress", L"00:15:5D:01:02:03");
            obj->SetBool(L"DHCPEnabled", true);
            result.push_back(obj);
        } else if (cls == L"Win32_VideoController") {
            auto* obj = new WbemClassObject(L"Win32_VideoController");
            obj->SetString(L"Name", L"MicaNT Sovereign PrismX Graphics Accelerator");
            obj->SetString(L"DeviceID", L"VideoController1");
            obj->SetUInt64(L"AdapterRAM", 8589934592ULL); // 8 GB
            obj->SetString(L"DriverVersion", L"10.0.26100.1");
            obj->SetString(L"VideoProcessor", L"PrismX 3D Pipeline");
            obj->SetUInt32(L"CurrentHorizontalResolution", 1920);
            obj->SetUInt32(L"CurrentVerticalResolution", 1080);
            obj->SetString(L"Status", L"OK");
            result.push_back(obj);
        } else if (cls == L"Win32_Service") {
            struct SvcInfo { const wchar_t* name; const wchar_t* disp; const wchar_t* state; };
            SvcInfo svcs[] = {
                { L"EventLog", L"Windows Event Log", L"Running" },
                { L"LanmanWorkstation", L"Workstation", L"Running" },
                { L"PlugPlay", L"Plug and Play", L"Running" },
                { L"RpcSs", L"Remote Procedure Call (RPC)", L"Running" },
                { L"Winmgmt", L"Windows Management Instrumentation", L"Running" },
                { L"AudioSrv", L"Windows Audio", L"Running" }
            };
            for (const auto& s : svcs) {
                auto* obj = new WbemClassObject(L"Win32_Service");
                obj->SetString(L"Name", s.name);
                obj->SetString(L"DisplayName", s.disp);
                obj->SetString(L"State", s.state);
                obj->SetString(L"StartMode", L"Auto");
                obj->SetString(L"Status", L"OK");
                obj->SetUInt32(L"ProcessId", 4);
                result.push_back(obj);
            }
        } else if (cls == L"Win32_Process") {
            struct ProcInfo { uint32_t pid; const wchar_t* name; };
            ProcInfo procs[] = {
                { 4, L"micant_kernel.exe" },
                { 100, L"csrss.exe" },
                { 104, L"lsass.exe" },
                { 108, L"services.exe" },
                { 120, L"conhost.exe" },
                { 128, L"cmd.exe" }
            };
            for (const auto& p : procs) {
                auto* obj = new WbemClassObject(L"Win32_Process");
                obj->SetUInt32(L"ProcessId", p.pid);
                obj->SetString(L"Name", p.name);
                obj->SetString(L"ExecutablePath", (std::wstring(L"C:\\Windows\\System32\\") + p.name).c_str());
                obj->SetUInt32(L"HandleCount", 128);
                obj->SetUInt32(L"ThreadCount", 4);
                obj->SetUInt64(L"WorkingSetSize", 4194304); // 4 MB
                result.push_back(obj);
            }
        } else if (cls == L"Win32_BIOS") {
            auto* obj = new WbemClassObject(L"Win32_BIOS");
            obj->SetString(L"Manufacturer", L"Dave Cutler DEC/MicaNT UEFI");
            obj->SetString(L"Name", L"MicaNT Sovereign UEFI 2.10");
            obj->SetString(L"Version", L"MICA-2026.1");
            obj->SetString(L"ReleaseDate", L"20261001000000.000000+000");
            obj->SetString(L"SMBIOSBIOSVersion", L"1.0.73");
            obj->SetString(L"Status", L"OK");
            obj->SetBool(L"PrimaryBIOS", true);
            result.push_back(obj);
        }

        return result;
    }

    std::vector<IWbemClassObject*> ExecuteWql(std::wstring_view wqlQuery) {
        std::wstring q(wqlQuery);
        // Trim whitespace
        size_t first = q.find_first_not_of(L" \t\r\n");
        if (first != std::wstring::npos) q = q.substr(first);

        // Simple WQL parser: SELECT <cols> FROM <class> [WHERE <condition>]
        std::wstring upperQ = q;
        std::transform(upperQ.begin(), upperQ.end(), upperQ.begin(), ::towupper);

        size_t selectPos = upperQ.find(L"SELECT ");
        size_t fromPos = upperQ.find(L" FROM ");

        if (selectPos == std::wstring::npos || fromPos == std::wstring::npos || fromPos <= selectPos) {
            return {};
        }

        std::wstring colsStr = q.substr(selectPos + 7, fromPos - (selectPos + 7));
        size_t afterFrom = fromPos + 6;
        size_t wherePos = upperQ.find(L" WHERE ", afterFrom);

        std::wstring targetClass;
        std::wstring whereClause;

        if (wherePos != std::wstring::npos) {
            targetClass = q.substr(afterFrom, wherePos - afterFrom);
            whereClause = q.substr(wherePos + 7);
        } else {
            targetClass = q.substr(afterFrom);
        }

        // Trim class name
        size_t cFirst = targetClass.find_first_not_of(L" \t\r\n");
        size_t cLast = targetClass.find_last_not_of(L" \t\r\n");
        if (cFirst != std::wstring::npos && cLast != std::wstring::npos) {
            targetClass = targetClass.substr(cFirst, cLast - cFirst + 1);
        }

        auto allInstances = QueryClass(targetClass);
        if (whereClause.empty()) {
            return allInstances;
        }

        // Filter instances by WHERE condition: prop = 'val' or prop = 123
        std::vector<IWbemClassObject*> filtered;
        size_t eqPos = whereClause.find(L'=');
        if (eqPos != std::wstring::npos) {
            std::wstring propName = whereClause.substr(0, eqPos);
            std::wstring expectedVal = whereClause.substr(eqPos + 1);

            // Trim propName
            size_t pFirst = propName.find_first_not_of(L" \t\r\n");
            size_t pLast = propName.find_last_not_of(L" \t\r\n");
            if (pFirst != std::wstring::npos && pLast != std::wstring::npos) propName = propName.substr(pFirst, pLast - pFirst + 1);

            // Trim expectedVal & quotes
            size_t vFirst = expectedVal.find_first_not_of(L" \t\r\n'\"");
            size_t vLast = expectedVal.find_last_not_of(L" \t\r\n'\"");
            if (vFirst != std::wstring::npos && vLast != std::wstring::npos) expectedVal = expectedVal.substr(vFirst, vLast - vFirst + 1);

            for (auto* inst : allInstances) {
                VARIANT v{};
                oleaut32::VariantInit(&v);
                CIMTYPE t = 0;
                if (inst->Get(propName.c_str(), 0, &v, &t, nullptr) == WBEM_S_NO_ERROR) {
                    bool match = false;
                    if (v.vt == VT_BSTR && v.bstrVal) {
                        match = (expectedVal == v.bstrVal);
                    } else if (v.vt == VT_I4) {
                        int32_t num = static_cast<int32_t>(std::wcstol(expectedVal.c_str(), nullptr, 10));
                        match = (v.lVal == num);
                    } else if (v.vt == VT_UI4) {
                        uint32_t num = static_cast<uint32_t>(std::wcstoul(expectedVal.c_str(), nullptr, 10));
                        match = (v.ulVal == num);
                    }
                    oleaut32::VariantClear(&v);
                    if (match) {
                        filtered.push_back(inst);
                        continue;
                    }
                }
                inst->Release(); // Dropped from filtered set
            }
            return filtered;
        }

        return allInstances;
    }
};

// ============================================================================
// 6. IWbemServices & IWbemLocator Concrete Classes
// ============================================================================

class WbemServices : public IWbemServices {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_namespace;

public:
    WbemServices(std::wstring ns = L"ROOT\\CIMV2") : m_namespace(std::move(ns)) {}

    // IUnknown
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemServices) {
            *ppv = static_cast<IWbemServices*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IWbemServices
    HRESULT __stdcall OpenNamespace(const BSTR strNamespace, int32_t, IWbemContext*, IWbemServices** ppWorkingNamespace, void**) override {
        if (!strNamespace || !ppWorkingNamespace) return WBEM_E_INVALID_PARAMETER;
        *ppWorkingNamespace = new WbemServices(strNamespace);
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall CancelAsyncCall(void*) override { return WBEM_S_NO_ERROR; }
    HRESULT __stdcall QueryObjectSink(int32_t, void**) override { return WBEM_E_NOT_SUPPORTED; }

    HRESULT __stdcall GetObject(const BSTR strObjectPath, int32_t, IWbemContext*, IWbemClassObject** ppObject, void**) override {
        if (!strObjectPath || !ppObject) return WBEM_E_INVALID_PARAMETER;
        *ppObject = nullptr;

        std::wstring path(strObjectPath);
        // Strip keys if any: Win32_OperatingSystem=@ or Win32_Processor
        size_t dotPos = path.find_first_of(L".=");
        std::wstring clsName = (dotPos != std::wstring::npos) ? path.substr(0, dotPos) : path;

        auto objs = CimRepository::Instance().QueryClass(clsName);
        if (objs.empty()) {
            return WBEM_E_NOT_FOUND;
        }

        *ppObject = objs[0];
        // Release remaining objects if any
        for (size_t i = 1; i < objs.size(); ++i) {
            objs[i]->Release();
        }
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall GetObjectAsync(const BSTR, int32_t, IWbemContext*, void*) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall PutClass(IWbemClassObject*, int32_t, IWbemContext*, void**) override { return WBEM_S_NO_ERROR; }
    HRESULT __stdcall PutClassAsync(IWbemClassObject*, int32_t, IWbemContext*, void*) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall DeleteClass(const BSTR, int32_t, IWbemContext*, void**) override { return WBEM_S_NO_ERROR; }
    HRESULT __stdcall DeleteClassAsync(const BSTR, int32_t, IWbemContext*, void*) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall CreateClassEnum(const BSTR, int32_t, IWbemContext*, IEnumWbemClassObject**) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall CreateClassEnumAsync(const BSTR, int32_t, IWbemContext*, void*) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall PutInstance(IWbemClassObject*, int32_t, IWbemContext*, void**) override { return WBEM_S_NO_ERROR; }
    HRESULT __stdcall PutInstanceAsync(IWbemClassObject*, int32_t, IWbemContext*, void*) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall DeleteInstance(const BSTR, int32_t, IWbemContext*, void**) override { return WBEM_S_NO_ERROR; }
    HRESULT __stdcall DeleteInstanceAsync(const BSTR, int32_t, IWbemContext*, void*) override { return WBEM_E_NOT_SUPPORTED; }

    HRESULT __stdcall CreateInstanceEnum(const BSTR strFilter, int32_t, IWbemContext*, IEnumWbemClassObject** ppEnum) override {
        if (!strFilter || !ppEnum) return WBEM_E_INVALID_PARAMETER;
        *ppEnum = nullptr;

        auto objs = CimRepository::Instance().QueryClass(strFilter);
        *ppEnum = new EnumWbemClassObject(objs);
        // Release our local vector references (EnumWbemClassObject AddRefs them)
        for (auto* obj : objs) {
            obj->Release();
        }
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall CreateInstanceEnumAsync(const BSTR, int32_t, IWbemContext*, void*) override { return WBEM_E_NOT_SUPPORTED; }

    HRESULT __stdcall ExecQuery(const BSTR strQueryLanguage, const BSTR strQuery, int32_t, IWbemContext*, IEnumWbemClassObject** ppEnum) override {
        if (!strQueryLanguage || !strQuery || !ppEnum) return WBEM_E_INVALID_PARAMETER;
        *ppEnum = nullptr;

        std::wstring lang(strQueryLanguage);
        if (lang != L"WQL" && lang != L"wql") {
            return WBEM_E_INVALID_QUERY_TYPE;
        }

        auto objs = CimRepository::Instance().ExecuteWql(strQuery);
        *ppEnum = new EnumWbemClassObject(objs);
        // Release local vector references
        for (auto* obj : objs) {
            obj->Release();
        }
        return WBEM_S_NO_ERROR;
    }

    HRESULT __stdcall ExecQueryAsync(const BSTR, const BSTR, int32_t, IWbemContext*, void*) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall ExecNotificationQuery(const BSTR, const BSTR, int32_t, IWbemContext*, IEnumWbemClassObject**) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall ExecNotificationQueryAsync(const BSTR, const BSTR, int32_t, IWbemContext*, void*) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall ExecMethod(const BSTR, const BSTR, int32_t, IWbemContext*, IWbemClassObject*, IWbemClassObject**, void**) override { return WBEM_E_NOT_SUPPORTED; }
    HRESULT __stdcall ExecMethodAsync(const BSTR, const BSTR, int32_t, IWbemContext*, IWbemClassObject*, void*) override { return WBEM_E_NOT_SUPPORTED; }
};

class WbemLocator : public IWbemLocator {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    WbemLocator() = default;

    // IUnknown
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemLocator) {
            *ppv = static_cast<IWbemLocator*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IWbemLocator
    HRESULT __stdcall ConnectServer(
        const BSTR strNetworkResource,
        const BSTR,
        const BSTR,
        const BSTR,
        int32_t,
        const BSTR,
        IWbemContext*,
        IWbemServices** ppNamespace
    ) override {
        if (!ppNamespace) return WBEM_E_INVALID_PARAMETER;
        *ppNamespace = nullptr;

        std::wstring ns = strNetworkResource ? strNetworkResource : L"ROOT\\CIMV2";
        // Handle \\.\ROOT\CIMV2 prefix
        if (ns.starts_with(L"\\\\.\\")) {
            ns = ns.substr(4);
        } else if (ns.starts_with(L"\\\\localhost\\")) {
            ns = ns.substr(12);
        }

        // Normalize uppercase
        std::wstring upperNs = ns;
        std::transform(upperNs.begin(), upperNs.end(), upperNs.begin(), ::towupper);

        if (upperNs != L"ROOT\\CIMV2" && upperNs != L"ROOT\\DEFAULT" && upperNs != L"ROOT\\WMI") {
            return WBEM_E_INVALID_NAMESPACE;
        }

        *ppNamespace = new WbemServices(upperNs);
        return WBEM_S_NO_ERROR;
    }
};

class WbemLocatorClassFactory : public IClassFactory {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    WbemLocatorClassFactory() = default;

    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    HRESULT __stdcall CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        if (!ppv) return E_POINTER;

        auto* loc = new WbemLocator();
        HRESULT hr = loc->QueryInterface(riid, ppv);
        loc->Release();
        return hr;
    }

    HRESULT __stdcall LockServer(win32::BOOL) override {
        return S_OK;
    }
};

// ============================================================================
// 7. Dynamic Loader Export & COM Registration
// ============================================================================

inline HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (rclsid == CLSID_WbemLocator) {
        auto* factory = new WbemLocatorClassFactory();
        HRESULT hr = factory->QueryInterface(riid, ppv);
        factory->Release();
        return hr;
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

inline HRESULT __stdcall DllCanUnloadNow() {
    return S_OK;
}

inline HRESULT __stdcall DllRegisterServer() {
    return S_OK;
}

inline HRESULT __stdcall DllUnregisterServer() {
    return S_OK;
}

inline void InitializeWbemSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // Register wbemprox.dll exports
    ldr.registerExport("wbemprox.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));
    ldr.registerExport("wbemprox.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("wbemprox.dll", "DllRegisterServer", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("wbemprox.dll", "DllUnregisterServer", reinterpret_cast<void*>(DllUnregisterServer));

    // Register fastprox.dll exports
    ldr.registerExport("fastprox.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));
    ldr.registerExport("fastprox.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("fastprox.dll", "DllRegisterServer", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("fastprox.dll", "DllUnregisterServer", reinterpret_cast<void*>(DllUnregisterServer));

    // Register COM Class Factory for CLSID_WbemLocator in ole32::ComRuntime
    static bool s_registered = false;
    if (!s_registered) {
        auto* factory = new WbemLocatorClassFactory();
        uint32_t regCookie = 0;
        ole32::CoRegisterClassObject(CLSID_WbemLocator, factory, 1 /* CLSCTX_INPROC_SERVER */, 0, &regCookie);
        factory->Release();
        s_registered = true;
    }
}

} // namespace micant::wbem
