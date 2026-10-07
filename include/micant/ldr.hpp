#pragma once

#include <cstdint>
#include <cctype>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <string>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ps.hpp"
#include "heap.hpp"
#include "dispatcher.hpp"

namespace micant::ldr {

/**
 * @brief Doubly-linked list node (Win32 LIST_ENTRY).
 */
struct ListEntry {
    ListEntry* flink{nullptr};
    ListEntry* blink{nullptr};

    void initialize() noexcept {
        flink = this;
        blink = this;
    }

    void insertTail(ListEntry* entry) noexcept {
        entry->flink = this;
        entry->blink = this->blink;
        this->blink->flink = entry;
        this->blink = entry;
    }

    [[nodiscard]] bool isEmpty() const noexcept {
        return flink == this;
    }
};

/**
 * @brief Dynamic Link Library Data Table Entry (LDR_DATA_TABLE_ENTRY).
 */
struct LdrDataTableEntry {
    ListEntry inLoadOrderLinks{};
    ListEntry inMemoryOrderLinks{};
    ListEntry inInitializationOrderLinks{};
    uintptr_t dllBase{0};
    uintptr_t entryPoint{0};
    uint32_t  sizeOfImage{0};
    UnicodeString fullDllName{};
    UnicodeString baseDllName{};
    uint32_t  flags{0};
    uint16_t  loadCount{1};
    uint16_t  tlsIndex{0};
    std::wstring storedFullName{};
    std::wstring storedBaseName{};
};

/**
 * @brief Process Environment Block Loader Data (PEB_LDR_DATA).
 */
struct PebLdrData {
    uint32_t length{sizeof(PebLdrData)};
    uint8_t  initialized{0};
    uintptr_t ssHandle{0};
    ListEntry inLoadOrderModuleList{};
    ListEntry inMemoryOrderModuleList{};
    ListEntry inInitializationOrderModuleList{};
    uintptr_t entryInProgress{0};
    uint8_t  shutdownInProgress{0};
    uintptr_t shutdownThreadId{0};

    void initialize() noexcept {
        inLoadOrderModuleList.initialize();
        inMemoryOrderModuleList.initialize();
        inInitializationOrderModuleList.initialize();
        initialized = 1;
    }
};

/**
 * @brief Standard RTL User Process Parameters (RTL_USER_PROCESS_PARAMETERS).
 */
struct RtlUserProcessParameters {
    uint32_t maximumLength{sizeof(RtlUserProcessParameters)};
    uint32_t length{sizeof(RtlUserProcessParameters)};
    uint32_t flags{0};
    uint32_t debugFlags{0};
    Handle consoleHandle{0};
    Handle consoleFlags{0};
    Handle standardInput{0x10};
    Handle standardOutput{0x14};
    Handle standardError{0x18};
    UnicodeString currentDirectory{L"C:\\Windows\\System32"};
    UnicodeString dllPath{L"C:\\Windows\\System32"};
    UnicodeString imagePathName{};
    UnicodeString commandLine{};
};

/**
 * @brief Userland Dynamic Loader and Module Registry.
 */
class DynamicLoader {
public:
    static DynamicLoader& get() {
        static DynamicLoader instance;
        return instance;
    }

    static std::string normalizeKey(std::string_view moduleName, std::string_view functionName) {
        std::string key;
        key.reserve(moduleName.size() + 1 + functionName.size());
        for (char c : moduleName) {
            key.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        key.push_back('!');
        key.append(functionName);
        return key;
    }

    void registerExport(std::string_view moduleName, std::string_view functionName, void* address) {
        exportRegistry_[normalizeKey(moduleName, functionName)] = address;
    }

    [[nodiscard]] void* getExport(std::string_view moduleName, std::string_view functionName) const {
        auto it = exportRegistry_.find(normalizeKey(moduleName, functionName));
        if (it != exportRegistry_.end()) {
            return it->second;
        }

        // Standard Windows ApiSet schema and forwarder resolution
        std::string modLower;
        modLower.reserve(moduleName.size());
        for (char c : moduleName) {
            modLower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }

        if (modLower.starts_with("api-ms-win-crt-") || modLower == "ucrtbase.dll" || modLower == "ucrtbase") {
            auto itCrt = exportRegistry_.find(normalizeKey("msvcrt.dll", functionName));
            if (itCrt != exportRegistry_.end()) {
                return itCrt->second;
            }
        } else if (modLower.starts_with("api-ms-win-core-") || modLower == "kernelbase.dll" || modLower == "kernelbase") {
            auto itK32 = exportRegistry_.find(normalizeKey("kernel32.dll", functionName));
            if (itK32 != exportRegistry_.end()) {
                return itK32->second;
            }
        }
        return nullptr;
    }

    [[nodiscard]] void* findExport(std::string_view functionName) const {
        std::string suffix = "!";
        suffix.append(functionName);
        for (const auto& [key, addr] : exportRegistry_) {
            if (key.size() >= suffix.size() &&
                key.compare(key.size() - suffix.size(), suffix.size(), suffix) == 0) {
                return addr;
            }
        }
        return nullptr;
    }

    void clear() {
        exportRegistry_.clear();
        loadedModules_.clear();
    }

    [[nodiscard]] size_t getLoadedModuleCount() const noexcept {
        return loadedModules_.size();
    }

    void addLoadedModule(std::shared_ptr<LdrDataTableEntry> mod) {
        loadedModules_.push_back(std::move(mod));
    }

    [[nodiscard]] const std::vector<std::shared_ptr<LdrDataTableEntry>>& getLoadedModules() const noexcept {
        return loadedModules_;
    }

private:
    DynamicLoader() = default;
    std::unordered_map<std::string, void*> exportRegistry_;
    std::vector<std::shared_ptr<LdrDataTableEntry>> loadedModules_;
};

/**
 * @brief NTDLL Userland Entry Thunk (LdrInitializeThunk).
 * Invoked by the kernel to initialize user mode runtime before executing the application entry point.
 */
inline NtStatus LdrInitializeThunk(
    ps::Peb* peb,
    ps::Teb* teb,
    uintptr_t entryPoint,
    std::wstring_view imagePath = L"C:\\Windows\\System32\\micant_app.exe"
) {
    if (!peb || !teb) {
        return NtStatus::InvalidParameter;
    }

    // 0. Ensure Central Syscall Dispatcher Table is ready
    sys::SyscallDispatcher::get().initializeStandardTable();

    // 1. Establish TEB <-> PEB link
    teb->processEnvironmentBlock = reinterpret_cast<uint64_t>(peb);
    teb->ntTib.self = reinterpret_cast<uint64_t>(teb);
    teb->ntTib.stackBase = teb->ntTib.stackBase ? teb->ntTib.stackBase : 0x00007FFFFFF00000ULL;
    teb->ntTib.stackLimit = teb->ntTib.stackLimit ? teb->ntTib.stackLimit : 0x00007FFFFFE00000ULL;

    // 2. Initialize Default Process Heap if not already created
    if (peb->processHeap == 0) {
        void* heapHandle = heap::RtlCreateHeap(
            heap::HEAP_GROWABLE,
            nullptr,
            1024 * 1024, // 1 MB reserve
            64 * 1024,   // 64 KB initial commit
            nullptr,
            nullptr
        );
        peb->processHeap = reinterpret_cast<uint64_t>(heapHandle);
    }

    // 3. Initialize Process Loader Data (PEB_LDR_DATA)
    if (peb->ldr == 0) {
        auto* ldrData = new PebLdrData();
        ldrData->initialize();
        peb->ldr = reinterpret_cast<uint64_t>(ldrData);

        // Register ntdll.dll as primary module in load order
        auto ntdllEntry = std::make_shared<LdrDataTableEntry>();
        ntdllEntry->dllBase = 0x00007FF800000000ULL;
        ntdllEntry->entryPoint = 0x00007FF800010000ULL;
        ntdllEntry->sizeOfImage = 0x200000;
        ntdllEntry->storedFullName = L"C:\\Windows\\System32\\ntdll.dll";
        ntdllEntry->storedBaseName = L"ntdll.dll";
        ntdllEntry->fullDllName = UnicodeString(ntdllEntry->storedFullName.c_str());
        ntdllEntry->baseDllName = UnicodeString(ntdllEntry->storedBaseName.c_str());
        ntdllEntry->flags = 0x00000004; // Loaded / Initialized

        ldrData->inLoadOrderModuleList.insertTail(&ntdllEntry->inLoadOrderLinks);
        DynamicLoader::get().addLoadedModule(ntdllEntry);

        // Register application executable module
        auto appEntry = std::make_shared<LdrDataTableEntry>();
        appEntry->dllBase = peb->imageBaseAddress ? peb->imageBaseAddress : 0x0000000140000000ULL;
        appEntry->entryPoint = entryPoint;
        appEntry->sizeOfImage = 0x100000;
        appEntry->storedFullName = std::wstring(imagePath);
        size_t lastSlash = appEntry->storedFullName.find_last_of(L"\\/");
        appEntry->storedBaseName = (lastSlash != std::wstring::npos) 
            ? appEntry->storedFullName.substr(lastSlash + 1) 
            : appEntry->storedFullName;
        appEntry->fullDllName = UnicodeString(appEntry->storedFullName.c_str());
        appEntry->baseDllName = UnicodeString(appEntry->storedBaseName.c_str());
        appEntry->flags = 0x00000004;

        ldrData->inLoadOrderModuleList.insertTail(&appEntry->inLoadOrderLinks);
        DynamicLoader::get().addLoadedModule(appEntry);
    }

    // 4. Initialize Process Parameters (RTL_USER_PROCESS_PARAMETERS)
    if (peb->processParameters == 0) {
        auto* params = new RtlUserProcessParameters();
        params->imagePathName = UnicodeString(imagePath.data());
        params->commandLine = UnicodeString(imagePath.data());
        peb->processParameters = reinterpret_cast<uint64_t>(params);
    }

    return NtStatus::Success;
}

/**
 * @brief Dynamic Library Loading (LdrLoadDll).
 */
inline NtStatus LdrLoadDll(
    const wchar_t* /*dllPath*/,
    uint32_t* /*flags*/,
    const UnicodeString* moduleFileName,
    uintptr_t* moduleHandle
) {
    if (!moduleFileName || !moduleHandle) {
        return NtStatus::InvalidParameter;
    }

    std::wstring name(moduleFileName->view());
    for (const auto& mod : DynamicLoader::get().getLoadedModules()) {
        if (mod->storedBaseName == name || mod->storedFullName == name) {
            *moduleHandle = mod->dllBase;
            return NtStatus::Success;
        }
    }

    // Allocate simulated base address for loaded DLL
    uintptr_t base = 0x00007FF810000000ULL + (DynamicLoader::get().getLoadedModuleCount() * 0x100000ULL);
    auto newMod = std::make_shared<LdrDataTableEntry>();
    newMod->dllBase = base;
    newMod->entryPoint = base + 0x1000;
    newMod->sizeOfImage = 0x100000;
    newMod->storedFullName = name;
    newMod->storedBaseName = name;
    newMod->fullDllName = UnicodeString(newMod->storedFullName.c_str());
    newMod->baseDllName = UnicodeString(newMod->storedBaseName.c_str());
    newMod->flags = 0x00000004;

    DynamicLoader::get().addLoadedModule(newMod);
    *moduleHandle = base;
    return NtStatus::Success;
}

/**
 * @brief Symbol Address Lookup (LdrGetProcedureAddress).
 */
inline NtStatus LdrGetProcedureAddress(
    uintptr_t moduleHandle,
    const char* procedureName,
    uint32_t /*ordinal*/,
    void** functionAddress
) {
    if (!procedureName || !functionAddress) {
        return NtStatus::InvalidParameter;
    }

    // Look up module in loaded table
    std::string modName = "ntdll.dll";
    for (const auto& mod : DynamicLoader::get().getLoadedModules()) {
        if (mod->dllBase == moduleHandle) {
            modName.clear();
            for (wchar_t c : mod->storedBaseName) {
                modName.push_back(static_cast<char>(c));
            }
            break;
        }
    }

    void* addr = DynamicLoader::get().getExport(modName, procedureName);
    if (!addr) {
        // Fallback search across all modules
        addr = DynamicLoader::get().getExport("ntdll.dll", procedureName);
    }
    if (!addr) {
        addr = DynamicLoader::get().findExport(procedureName);
    }

    if (addr) {
        *functionAddress = addr;
        return NtStatus::Success;
    }

    return NtStatus::ProcedureNotFound;
}

} // namespace micant::ldr
