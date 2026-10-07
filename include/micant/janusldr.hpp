#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <optional>
#include <stack>
#include <span>
#include <mutex>
#include <cstring>
#include <algorithm>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "pe.hpp"
#include "ldr.hpp"

namespace micant::janus {

// ============================================================================
// Standard PE Delay-Load Descriptors & Flags (Microsoft Win32 Specification)
// ============================================================================

inline constexpr uint32_t DLATTR_RVA = 0x00000001; // RVAs used instead of VAs

#pragma pack(push, 4)
struct ImgDelayDescr {
    uint32_t grAttrs;        // Attributes (1 = dlattrRva)
    uint32_t rvaDLLName;     // RVA to DLL name string
    uint32_t rvaHmod;        // RVA to HMODULE storage in image
    uint32_t rvaIAT;         // RVA to delay Import Address Table (IAT)
    uint32_t rvaINT;         // RVA to delay Import Name Table (INT)
    uint32_t rvaBoundIAT;    // RVA to bound IAT
    uint32_t rvaUnloadIAT;   // RVA to unload IAT
    uint32_t dwTimeStamp;    // Date/time stamp if bound
};
#pragma pack(pop)

// Delay-Load Hook Notification Events
inline constexpr uint32_t dliStartProcessing       = 0;
inline constexpr uint32_t dliNotePreLoadLibrary    = 1;
inline constexpr uint32_t dliNotePreGetProcAddress = 2;
inline constexpr uint32_t dliFailLoadLib           = 3;
inline constexpr uint32_t dliFailGetProc           = 4;
inline constexpr uint32_t dliNoteEndProcessing     = 5;

struct DelayLoadInfo {
    uint32_t cb;
    const ImgDelayDescr* pidd;
    void** ppfn;
    const char* szDll;
    struct {
        uint32_t fImportByName;
        union {
            const char* szProcName;
            uint32_t dwOrdinal;
        };
    } dlp;
    uintptr_t hmodCur;
    void* pfnCur;
    uint32_t dwLastError;
};

using PfnDelayHook = void* (*)(uint32_t dliNotify, DelayLoadInfo* pdli);

// ============================================================================
// Side-by-Side (SxS) Manifest & Activation Context Constants & Types
// ============================================================================

inline constexpr uint32_t ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID = 0x0001;
inline constexpr uint32_t ACTCTX_FLAG_LANGID_VALID                 = 0x0002;
inline constexpr uint32_t ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID     = 0x0004;
inline constexpr uint32_t ACTCTX_FLAG_RESOURCE_NAME_VALID          = 0x0008;
inline constexpr uint32_t ACTCTX_FLAG_SET_PROCESS_DEFAULT          = 0x0010;
inline constexpr uint32_t ACTCTX_FLAG_APPLICATION_NAME_VALID       = 0x0020;
inline constexpr uint32_t ACTCTX_FLAG_HMODULE_VALID                = 0x0080;

struct ACTCTXW {
    uint32_t cbSize{sizeof(ACTCTXW)};
    uint32_t dwFlags{0};
    const wchar_t* lpSource{nullptr};
    uint16_t wProcessorArchitecture{0};
    uint16_t wLangId{0};
    const wchar_t* lpAssemblyDirectory{nullptr};
    const wchar_t* lpResourceName{nullptr};
    const wchar_t* lpApplicationName{nullptr};
    uintptr_t hModule{0};
};

// ============================================================================
// 1. Side-by-Side (SxS) Assembly & Manifest Representation
// ============================================================================

struct AssemblyIdentity {
    std::wstring name;
    std::wstring version;
    std::wstring processorArchitecture{L"*"};
    std::wstring publicKeyToken;
    std::wstring type{L"win32"};
};

struct AssemblyRedirection {
    std::wstring dllName;
    std::wstring targetPath;
    std::wstring version;
};

class ActivationContext {
public:
    uintptr_t handle{0};
    std::wstring sourcePath;
    std::wstring appDirectory;
    AssemblyIdentity identity;
    std::vector<AssemblyIdentity> dependencies;
    std::unordered_map<std::wstring, AssemblyRedirection> fileRedirections;
    bool isValid{true};

    static std::shared_ptr<ActivationContext> parseFromXml(std::string_view xmlContent, std::wstring_view source = L"") {
        auto ctx = std::make_shared<ActivationContext>();
        ctx->sourcePath = source;

        // Clean-room naive XML tag extractor for <assemblyIdentity> and <file>
        auto findAttr = [](std::string_view tag, std::string_view attr) -> std::string {
            std::string needle = std::string(attr) + "=\"";
            size_t pos = tag.find(needle);
            if (pos == std::string_view::npos) return "";
            size_t start = pos + needle.size();
            size_t end = tag.find('"', start);
            if (end == std::string_view::npos) return "";
            return std::string(tag.substr(start, end - start));
        };

        auto toWString = [](std::string_view str) -> std::wstring {
            return std::wstring(str.begin(), str.end());
        };

        // Extract primary assembly identity
        size_t identPos = xmlContent.find("<assemblyIdentity");
        if (identPos != std::string_view::npos) {
            size_t tagEnd = xmlContent.find('>', identPos);
            if (tagEnd != std::string_view::npos) {
                std::string_view tag = xmlContent.substr(identPos, tagEnd - identPos + 1);
                ctx->identity.name = toWString(findAttr(tag, "name"));
                ctx->identity.version = toWString(findAttr(tag, "version"));
                ctx->identity.processorArchitecture = toWString(findAttr(tag, "processorArchitecture"));
                ctx->identity.publicKeyToken = toWString(findAttr(tag, "publicKeyToken"));
            }
        }

        // Extract dependent assemblies
        size_t depPos = 0;
        while ((depPos = xmlContent.find("<dependentAssembly", depPos)) != std::string_view::npos) {
            size_t depEnd = xmlContent.find("</dependentAssembly>", depPos);
            if (depEnd == std::string_view::npos) break;

            std::string_view depBlock = xmlContent.substr(depPos, depEnd - depPos);
            size_t subIdent = depBlock.find("<assemblyIdentity");
            if (subIdent != std::string_view::npos) {
                size_t subEnd = depBlock.find('>', subIdent);
                if (subEnd != std::string_view::npos) {
                    std::string_view tag = depBlock.substr(subIdent, subEnd - subIdent + 1);
                    AssemblyIdentity depId;
                    depId.name = toWString(findAttr(tag, "name"));
                    depId.version = toWString(findAttr(tag, "version"));
                    depId.publicKeyToken = toWString(findAttr(tag, "publicKeyToken"));
                    ctx->dependencies.push_back(depId);
                }
            }
            depPos = depEnd + 20;
        }

        // Extract file redirections
        size_t filePos = 0;
        while ((filePos = xmlContent.find("<file", filePos)) != std::string_view::npos) {
            size_t fileEnd = xmlContent.find('>', filePos);
            if (fileEnd == std::string_view::npos) break;

            std::string_view tag = xmlContent.substr(filePos, fileEnd - filePos + 1);
            std::string fileName = findAttr(tag, "name");
            if (!fileName.empty()) {
                AssemblyRedirection redir;
                redir.dllName = toWString(fileName);
                redir.targetPath = redir.dllName;
                ctx->fileRedirections[redir.dllName] = redir;
            }
            filePos = fileEnd + 1;
        }

        return ctx;
    }
};

// ============================================================================
// 2. Export Forwarder Chain Resolver
// ============================================================================

struct ForwarderTarget {
    std::string moduleName;
    std::string functionName;
    uint32_t ordinal{0};
    bool isOrdinal{false};
};

class ForwarderResolver {
public:
    static std::optional<ForwarderTarget> parseForwarderString(std::string_view forwarder) {
        if (forwarder.empty()) return std::nullopt;

        ForwarderTarget target;
        std::string_view dllPart;
        std::string_view funcPart;

        // Check if ".dll." or ".DLL." is present (e.g., "ntdll.dll.RtlEnterCriticalSection")
        size_t dllDot = forwarder.find(".dll.");
        if (dllDot == std::string_view::npos) {
            dllDot = forwarder.find(".DLL.");
        }

        if (dllDot != std::string_view::npos) {
            dllPart = forwarder.substr(0, dllDot);
            funcPart = forwarder.substr(dllDot + 5);
        } else {
            // Find delimiter (. or !)
            size_t sep = forwarder.find_first_of(".!");
            if (sep == std::string_view::npos) return std::nullopt;
            dllPart = forwarder.substr(0, sep);
            funcPart = forwarder.substr(sep + 1);
        }

        // Normalize module name to lower-case with .dll extension
        std::string mod;
        mod.reserve(dllPart.size() + 4);
        for (char c : dllPart) {
            mod.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        if (!mod.ends_with(".dll")) {
            mod += ".dll";
        }
        target.moduleName = std::move(mod);

        if (!funcPart.empty() && funcPart[0] == '#') {
            target.isOrdinal = true;
            try {
                target.ordinal = static_cast<uint32_t>(std::stoul(std::string(funcPart.substr(1))));
            } catch (...) {
                return std::nullopt;
            }
        } else {
            target.functionName = std::string(funcPart);
        }

        return target;
    }

    static void* resolveForwarderChain(
        std::string_view initialForwarder,
        std::unordered_map<std::string, std::string>& forwarderMap,
        std::unordered_map<std::string, void*>& exportMap,
        size_t maxDepth = 16
    ) {
        std::string current(initialForwarder);

        for (size_t depth = 0; depth < maxDepth; ++depth) {
            auto parsed = parseForwarderString(current);
            if (!parsed) return nullptr;

            std::string exportKey = parsed->moduleName + "!" + (parsed->isOrdinal ? ("#" + std::to_string(parsed->ordinal)) : parsed->functionName);

            // Check if further forwarded in the forwarder map (multi-hop chain)
            auto fwdIt = forwarderMap.find(exportKey);
            if (fwdIt != forwarderMap.end()) {
                current = fwdIt->second;
                continue;
            }

            // Check if final implementation exists in exportMap
            auto expIt = exportMap.find(exportKey);
            if (expIt != exportMap.end()) {
                return expIt->second;
            }

            // Fallback query to DynamicLoader export registry
            std::string targetFunc = parsed->isOrdinal ? ("#" + std::to_string(parsed->ordinal)) : parsed->functionName;
            void* dynamicExp = ldr::DynamicLoader::get().getExport(parsed->moduleName, targetFunc);
            if (dynamicExp) {
                return dynamicExp;
            }

            break;
        }

        return nullptr;
    }
};

// ============================================================================
// 3. Sovereign Janus Dynamic Executable Linker Engine
// ============================================================================

class JanusDynamicLinker {
public:
    static JanusDynamicLinker& get() {
        static JanusDynamicLinker instance;
        return instance;
    }

    // ------------------------------------------------------------------------
    // Delay-Load Helper Thunk Resolution (__delayLoadHelper2 Parity)
    // ------------------------------------------------------------------------
    void* resolveDelayLoad(
        uintptr_t imageBase,
        const ImgDelayDescr* pidd,
        void** ppfnIATEntry,
        PfnDelayHook hook = nullptr
    ) {
        if (!pidd || !ppfnIATEntry) return nullptr;

        const char* dllName = reinterpret_cast<const char*>(imageBase + pidd->rvaDLLName);
        auto* pIAT = reinterpret_cast<void**>(imageBase + pidd->rvaIAT);
        auto* pINT = reinterpret_cast<uintptr_t*>(imageBase + pidd->rvaINT);

        size_t index = static_cast<size_t>(ppfnIATEntry - pIAT);
        uintptr_t intEntry = pINT[index];

        DelayLoadInfo dli{};
        dli.cb = sizeof(DelayLoadInfo);
        dli.pidd = pidd;
        dli.ppfn = ppfnIATEntry;
        dli.szDll = dllName;

        const char* procName = nullptr;
        uint32_t ordinal = 0;
        if ((intEntry & pe::IMAGE_ORDINAL_FLAG64) != 0) {
            dli.dlp.fImportByName = 0;
            ordinal = static_cast<uint32_t>(intEntry & 0xFFFF);
            dli.dlp.dwOrdinal = ordinal;
        } else {
            dli.dlp.fImportByName = 1;
            // Name table entry: 2 bytes hint + ASCII name
            procName = reinterpret_cast<const char*>(imageBase + intEntry + 2);
            dli.dlp.szProcName = procName;
        }

        // 1. Notify Start Processing
        if (hook) hook(dliStartProcessing, &dli);

        // 2. Resolve Module Handle
        uintptr_t hmod = 0;
        if (hook) {
            hmod = reinterpret_cast<uintptr_t>(hook(dliNotePreLoadLibrary, &dli));
        }

        if (!hmod) {
            std::wstring wDllName(dllName, dllName + std::strlen(dllName));
            UnicodeString uDllName(wDllName.c_str());
            NtStatus st = ldr::LdrLoadDll(nullptr, nullptr, &uDllName, &hmod);
            if (!NT_SUCCESS(st)) {
                if (hook) hook(dliFailLoadLib, &dli);
                return nullptr;
            }
        }

        dli.hmodCur = hmod;

        // Write loaded module handle to image delay descriptor storage
        if (pidd->rvaHmod) {
            *reinterpret_cast<uintptr_t*>(imageBase + pidd->rvaHmod) = hmod;
        }

        // 3. Resolve Procedure Address
        void* pfn = nullptr;
        if (hook) {
            pfn = hook(dliNotePreGetProcAddress, &dli);
        }

        if (!pfn) {
            NtStatus st = ldr::LdrGetProcedureAddress(hmod, procName, ordinal, &pfn);
            if (!NT_SUCCESS(st)) {
                if (hook) hook(dliFailGetProc, &dli);
                return nullptr;
            }
        }

        dli.pfnCur = pfn;

        // 4. Patch IAT Entry directly to resolved function
        *ppfnIATEntry = pfn;

        // 5. Notify End Processing
        if (hook) hook(dliNoteEndProcessing, &dli);

        return pfn;
    }

    // ------------------------------------------------------------------------
    // Export Forwarder Registration & Resolution
    // ------------------------------------------------------------------------
    static std::string normalizeModuleKey(std::string_view moduleName, std::string_view functionName) {
        std::string mod;
        mod.reserve(moduleName.size() + 1 + functionName.size());
        for (char c : moduleName) {
            mod.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        if (!mod.ends_with(".dll")) {
            mod += ".dll";
        }
        mod.push_back('!');
        mod.append(functionName);
        return mod;
    }

    void registerForwarder(std::string_view fromModule, std::string_view fromFunc, std::string_view targetForwarder) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = normalizeModuleKey(fromModule, fromFunc);
        forwarderMap_[key] = std::string(targetForwarder);
    }

    void* resolveExport(std::string_view moduleName, std::string_view functionName) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = normalizeModuleKey(moduleName, functionName);

        // 1. Forwarder Chain Resolution takes precedence if an explicit forwarder is defined
        auto it = forwarderMap_.find(key);
        if (it != forwarderMap_.end()) {
            std::unordered_map<std::string, void*> exportMap;
            return ForwarderResolver::resolveForwarderChain(it->second, forwarderMap_, exportMap);
        }

        // 2. Direct Export Table
        void* addr = ldr::DynamicLoader::get().getExport(moduleName, functionName);
        if (addr) return addr;

        return nullptr;
    }

    // ------------------------------------------------------------------------
    // Side-by-Side (SxS) Activation Context Management
    // ------------------------------------------------------------------------
    uintptr_t createActivationContext(const ACTCTXW* pActCtx) {
        if (!pActCtx || pActCtx->cbSize < sizeof(ACTCTXW)) return 0;
        std::lock_guard<std::mutex> lock(mutex_);

        auto ctx = std::make_shared<ActivationContext>();
        ctx->handle = nextActCtxHandle_++;
        if (pActCtx->lpSource) ctx->sourcePath = pActCtx->lpSource;
        if (pActCtx->lpAssemblyDirectory) ctx->appDirectory = pActCtx->lpAssemblyDirectory;

        actContexts_[ctx->handle] = ctx;
        return ctx->handle;
    }

    uintptr_t registerParsedContext(std::shared_ptr<ActivationContext> ctx) {
        if (!ctx) return 0;
        std::lock_guard<std::mutex> lock(mutex_);
        ctx->handle = nextActCtxHandle_++;
        actContexts_[ctx->handle] = ctx;
        return ctx->handle;
    }

    bool activateContext(uintptr_t hActCtx, uintptr_t* pCookie) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = actContexts_.find(hActCtx);
        if (it == actContexts_.end()) return false;

        uintptr_t cookie = actContextStack_.size() + 1;
        actContextStack_.push(it->second);
        if (pCookie) *pCookie = cookie;
        return true;
    }

    bool deactivateContext([[maybe_unused]] uint32_t dwFlags, uintptr_t cookie) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (actContextStack_.empty()) return false;
        if (cookie != actContextStack_.size()) return false;

        actContextStack_.pop();
        return true;
    }

    bool releaseContext(uintptr_t hActCtx) {
        std::lock_guard<std::mutex> lock(mutex_);
        return actContexts_.erase(hActCtx) > 0;
    }

    std::shared_ptr<ActivationContext> getActiveContext() {
        std::lock_guard<std::mutex> lock(mutex_);
        return actContextStack_.empty() ? nullptr : actContextStack_.top();
    }

    std::optional<std::wstring> resolveAssemblyRedirection(std::wstring_view dllName) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (actContextStack_.empty()) return std::nullopt;

        auto active = actContextStack_.top();
        auto it = active->fileRedirections.find(std::wstring(dllName));
        if (it != active->fileRedirections.end()) {
            return it->second.targetPath;
        }

        return std::nullopt;
    }

private:
    std::mutex mutex_;
    uintptr_t nextActCtxHandle_{0x8000};
    std::unordered_map<std::string, std::string> forwarderMap_;
    std::unordered_map<uintptr_t, std::shared_ptr<ActivationContext>> actContexts_;
    std::stack<std::shared_ptr<ActivationContext>> actContextStack_;

    JanusDynamicLinker() = default;
};

// ============================================================================
// 4. Standard Win32 Activation Context (SxS) API Signatures
// ============================================================================

inline uintptr_t CreateActCtxW(const ACTCTXW* pActCtx) {
    return JanusDynamicLinker::get().createActivationContext(pActCtx);
}

inline bool ActivateActCtx(uintptr_t hActCtx, uintptr_t* lpCookie) {
    return JanusDynamicLinker::get().activateContext(hActCtx, lpCookie);
}

inline bool DeactivateActCtx(uint32_t dwFlags, uintptr_t ulCookie) {
    return JanusDynamicLinker::get().deactivateContext(dwFlags, ulCookie);
}

inline void ReleaseActCtx(uintptr_t hActCtx) {
    JanusDynamicLinker::get().releaseContext(hActCtx);
}

inline void* __delayLoadHelper2(
    const ImgDelayDescr* pidd,
    void** ppfnIATEntry
) {
    return JanusDynamicLinker::get().resolveDelayLoad(0, pidd, ppfnIATEntry, nullptr);
}

} // namespace micant::janus
