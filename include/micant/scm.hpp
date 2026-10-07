#pragma once

/**
 * @file scm.hpp
 * @brief MicaNT Service Control Manager (services.exe / SCM) & Service Host (svchost.exe).
 *
 * Implements the core Windows NT Service subsystem daemon, maintaining the service
 * database, topological dependency resolution, service state transitions, service
 * host grouping (svchost.exe -k <group>), kernel driver service loading, and
 * transactional RPC server over \\.\pipe\ntsvcs.
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <functional>
#include <algorithm>
#include <sstream>
#include <cstring>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "driver.hpp"
#include "npfs.hpp"
#include "kernel32.hpp"

namespace micant::scm {

// ============================================================================
// 1. Windows SCM Constants & Enumerations
// ============================================================================

// Service Types
inline constexpr uint32_t SERVICE_KERNEL_DRIVER       = 0x00000001;
inline constexpr uint32_t SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002;
inline constexpr uint32_t SERVICE_ADAPTER             = 0x00000004;
inline constexpr uint32_t SERVICE_RECOGNIZER_DRIVER   = 0x00000008;
inline constexpr uint32_t SERVICE_DRIVER              = (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER);
inline constexpr uint32_t SERVICE_WIN32_OWN_PROCESS   = 0x00000010;
inline constexpr uint32_t SERVICE_WIN32_SHARE_PROCESS = 0x00000020;
inline constexpr uint32_t SERVICE_WIN32               = (SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS);
inline constexpr uint32_t SERVICE_INTERACTIVE_PROCESS = 0x00000100;
inline constexpr uint32_t SERVICE_TYPE_ALL            = (SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS);

// Service Start Types
inline constexpr uint32_t SERVICE_BOOT_START   = 0x00000000;
inline constexpr uint32_t SERVICE_SYSTEM_START = 0x00000001;
inline constexpr uint32_t SERVICE_AUTO_START   = 0x00000002;
inline constexpr uint32_t SERVICE_DEMAND_START = 0x00000003;
inline constexpr uint32_t SERVICE_DISABLED     = 0x00000004;

// Service Error Control
inline constexpr uint32_t SERVICE_ERROR_IGNORE   = 0x00000000;
inline constexpr uint32_t SERVICE_ERROR_NORMAL   = 0x00000001;
inline constexpr uint32_t SERVICE_ERROR_SEVERE   = 0x00000002;
inline constexpr uint32_t SERVICE_ERROR_CRITICAL = 0x00000003;

// Service Current States
inline constexpr uint32_t SERVICE_STOPPED          = 0x00000001;
inline constexpr uint32_t SERVICE_START_PENDING    = 0x00000002;
inline constexpr uint32_t SERVICE_STOP_PENDING     = 0x00000003;
inline constexpr uint32_t SERVICE_RUNNING          = 0x00000004;
inline constexpr uint32_t SERVICE_CONTINUE_PENDING = 0x00000005;
inline constexpr uint32_t SERVICE_PAUSE_PENDING    = 0x00000006;
inline constexpr uint32_t SERVICE_PAUSED           = 0x00000007;

// Controls Accepted
inline constexpr uint32_t SERVICE_ACCEPT_STOP                  = 0x00000001;
inline constexpr uint32_t SERVICE_ACCEPT_PAUSE_CONTINUE        = 0x00000002;
inline constexpr uint32_t SERVICE_ACCEPT_SHUTDOWN              = 0x00000004;
inline constexpr uint32_t SERVICE_ACCEPT_PARAMCHANGE           = 0x00000008;
inline constexpr uint32_t SERVICE_ACCEPT_NETBINDCHANGE         = 0x00000010;
inline constexpr uint32_t SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020;
inline constexpr uint32_t SERVICE_ACCEPT_POWEREVENT            = 0x00000040;
inline constexpr uint32_t SERVICE_ACCEPT_SESSIONCHANGE         = 0x00000080;
inline constexpr uint32_t SERVICE_ACCEPT_PRESHUTDOWN           = 0x00000100;
inline constexpr uint32_t SERVICE_ACCEPT_TIMECHANGE            = 0x00000200;
inline constexpr uint32_t SERVICE_ACCEPT_TRIGGEREVENT          = 0x00000400;

// Service Control Codes
inline constexpr uint32_t SERVICE_CONTROL_STOP                  = 0x00000001;
inline constexpr uint32_t SERVICE_CONTROL_PAUSE                 = 0x00000002;
inline constexpr uint32_t SERVICE_CONTROL_CONTINUE              = 0x00000003;
inline constexpr uint32_t SERVICE_CONTROL_INTERROGATE           = 0x00000004;
inline constexpr uint32_t SERVICE_CONTROL_SHUTDOWN              = 0x00000005;
inline constexpr uint32_t SERVICE_CONTROL_PARAMCHANGE           = 0x00000006;
inline constexpr uint32_t SERVICE_CONTROL_NETBINDADD           = 0x00000007;
inline constexpr uint32_t SERVICE_CONTROL_NETBINDREMOVE        = 0x00000008;
inline constexpr uint32_t SERVICE_CONTROL_NETBINDENABLE        = 0x00000009;
inline constexpr uint32_t SERVICE_CONTROL_NETBINDDISABLE       = 0x0000000A;
inline constexpr uint32_t SERVICE_CONTROL_DEVICEEVENT           = 0x0000000B;
inline constexpr uint32_t SERVICE_CONTROL_HARDWAREPROFILECHANGE = 0x0000000C;
inline constexpr uint32_t SERVICE_CONTROL_POWEREVENT            = 0x0000000D;
inline constexpr uint32_t SERVICE_CONTROL_SESSIONCHANGE         = 0x0000000E;
inline constexpr uint32_t SERVICE_CONTROL_PRESHUTDOWN           = 0x0000000F;
inline constexpr uint32_t SERVICE_CONTROL_TIMECHANGE            = 0x00000010;

// SCManager Access Rights
inline constexpr uint32_t SC_MANAGER_CONNECT             = 0x0001;
inline constexpr uint32_t SC_MANAGER_CREATE_SERVICE      = 0x0002;
inline constexpr uint32_t SC_MANAGER_ENUMERATE_SERVICE   = 0x0004;
inline constexpr uint32_t SC_MANAGER_LOCK                = 0x0008;
inline constexpr uint32_t SC_MANAGER_QUERY_LOCK_STATUS   = 0x0010;
inline constexpr uint32_t SC_MANAGER_MODIFY_BOOT_CONFIG  = 0x0020;
inline constexpr uint32_t SC_MANAGER_ALL_ACCESS          = 0xF003F;

// Service Access Rights
inline constexpr uint32_t SERVICE_QUERY_CONFIG           = 0x0001;
inline constexpr uint32_t SERVICE_CHANGE_CONFIG          = 0x0002;
inline constexpr uint32_t SERVICE_QUERY_STATUS           = 0x0004;
inline constexpr uint32_t SERVICE_ENUMERATE_DEPENDENTS   = 0x0008;
inline constexpr uint32_t SERVICE_START                  = 0x0010;
inline constexpr uint32_t SERVICE_STOP                   = 0x0020;
inline constexpr uint32_t SERVICE_PAUSE_CONTINUE         = 0x0040;
inline constexpr uint32_t SERVICE_INTERROGATE            = 0x0080;
inline constexpr uint32_t SERVICE_USER_DEFINED_CONTROL   = 0x0100;
inline constexpr uint32_t SERVICE_ALL_ACCESS             = 0xF01FF;

// SCM Win32 Error Codes
inline constexpr uint32_t ERROR_SUCCESS                            = 0;
inline constexpr uint32_t ERROR_FILE_NOT_FOUND                     = 2;
inline constexpr uint32_t ERROR_ACCESS_DENIED                      = 5;
inline constexpr uint32_t ERROR_INVALID_HANDLE                     = 6;
inline constexpr uint32_t ERROR_INVALID_PARAMETER                  = 87;
inline constexpr uint32_t ERROR_INSUFFICIENT_BUFFER                = 122;
inline constexpr uint32_t ERROR_DEPENDENT_SERVICES_RUNNING         = 1051;
inline constexpr uint32_t ERROR_INVALID_SERVICE_CONTROL            = 1052;
inline constexpr uint32_t ERROR_SERVICE_REQUEST_TIMEOUT            = 1053;
inline constexpr uint32_t ERROR_SERVICE_NO_THREAD                  = 1054;
inline constexpr uint32_t ERROR_SERVICE_DATABASE_LOCKED            = 1055;
inline constexpr uint32_t ERROR_SERVICE_ALREADY_RUNNING            = 1056;
inline constexpr uint32_t ERROR_INVALID_SERVICE_ACCOUNT            = 1057;
inline constexpr uint32_t ERROR_SERVICE_DISABLED                  = 1058;
inline constexpr uint32_t ERROR_CIRCULAR_DEPENDENCY                = 1059;
inline constexpr uint32_t ERROR_SERVICE_DOES_NOT_EXIST             = 1060;
inline constexpr uint32_t ERROR_SERVICE_CANNOT_ACCEPT_CTRL         = 1061;
inline constexpr uint32_t ERROR_SERVICE_NOT_ACTIVE                 = 1062;
inline constexpr uint32_t ERROR_FAILED_SERVICE_CONTROLLER_CONNECT  = 1063;
inline constexpr uint32_t ERROR_EXCEPTION_IN_SERVICE               = 1064;
inline constexpr uint32_t ERROR_DATABASE_DOES_NOT_EXIST            = 1065;
inline constexpr uint32_t ERROR_SERVICE_SPECIFIC_ERROR             = 1066;
inline constexpr uint32_t ERROR_SERVICE_MARKED_FOR_DELETE          = 1072;
inline constexpr uint32_t ERROR_SERVICE_EXISTS                     = 1073;
inline constexpr uint32_t ERROR_DUPLICATE_SERVICE_NAME             = 1078;

// ============================================================================
// 2. Struct Definitions
// ============================================================================

struct SERVICE_STATUS {
    uint32_t dwServiceType{0};
    uint32_t dwCurrentState{SERVICE_STOPPED};
    uint32_t dwControlsAccepted{0};
    uint32_t dwWin32ExitCode{0};
    uint32_t dwServiceSpecificExitCode{0};
    uint32_t dwCheckPoint{0};
    uint32_t dwWaitHint{0};
};

struct SERVICE_STATUS_PROCESS {
    uint32_t dwServiceType{0};
    uint32_t dwCurrentState{SERVICE_STOPPED};
    uint32_t dwControlsAccepted{0};
    uint32_t dwWin32ExitCode{0};
    uint32_t dwServiceSpecificExitCode{0};
    uint32_t dwCheckPoint{0};
    uint32_t dwWaitHint{0};
    uint32_t dwProcessId{0};
    uint32_t dwServiceFlags{0};
};

struct ENUM_SERVICE_STATUS_PROCESSW {
    std::wstring lpServiceName;
    std::wstring lpDisplayName;
    SERVICE_STATUS_PROCESS ServiceStatusProcess;
};

struct QUERY_SERVICE_CONFIGW {
    uint32_t dwServiceType{0};
    uint32_t dwStartType{0};
    uint32_t dwErrorControl{0};
    std::wstring lpBinaryPathName;
    std::wstring lpLoadOrderGroup;
    uint32_t dwTagId{0};
    std::vector<std::wstring> lpDependencies;
    std::wstring lpServiceStartName;
    std::wstring lpDisplayName;
};

// Callback Signatures
using HandlerFunction = void (*)(uint32_t control);
using HandlerFunctionEx = uint32_t (*)(uint32_t control, uint32_t eventType, void* eventData, void* context);
using ServiceMainFunction = void (*)(uint32_t argc, const wchar_t** argv);

// ============================================================================
// 3. Service Record Representation
// ============================================================================

class ServiceRecord {
public:
    std::wstring serviceName;
    std::wstring displayName;
    uint32_t serviceType{SERVICE_WIN32_OWN_PROCESS};
    uint32_t startType{SERVICE_DEMAND_START};
    uint32_t errorControl{SERVICE_ERROR_NORMAL};
    std::wstring binaryPath;
    std::wstring loadOrderGroup;
    std::vector<std::wstring> dependencies;
    std::wstring serviceStartName{L"LocalSystem"};

    // Runtime state
    SERVICE_STATUS_PROCESS status{};
    bool markedForDelete{false};
    std::string svchostGroup;
    driver::DriverEntryRoutine driverEntry{nullptr};
    HandlerFunction handler{nullptr};
    HandlerFunctionEx handlerEx{nullptr};
    void* handlerContext{nullptr};
    ServiceMainFunction mainFunc{nullptr};

    std::vector<uint32_t> controlHistory;

    ServiceRecord() {
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
    }

    [[nodiscard]] bool isRunning() const noexcept {
        return status.dwCurrentState == SERVICE_RUNNING;
    }

    [[nodiscard]] bool isPaused() const noexcept {
        return status.dwCurrentState == SERVICE_PAUSED;
    }

    [[nodiscard]] bool isStopped() const noexcept {
        return status.dwCurrentState == SERVICE_STOPPED;
    }
};

// ============================================================================
// 4. Service Host (svchost.exe) Grouping Engine
// ============================================================================

struct SvcHostGroup {
    std::string groupName;
    uint32_t processId{0};
    std::vector<std::wstring> hostedServices;
};

class SvcHostManager {
public:
    static SvcHostManager& get() {
        static SvcHostManager instance;
        return instance;
    }

    uint32_t getOrCreateGroupProcess(const std::string& groupName) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(groupName);
        if (it != groups_.end()) {
            return it->second.processId;
        }

        SvcHostGroup grp;
        grp.groupName = groupName;
        // Allocate deterministic host PID: 1000 + 100 * count
        grp.processId = 1000 + static_cast<uint32_t>(groups_.size() + 1) * 100;
        groups_[groupName] = grp;
        return grp.processId;
    }

    void assignService(const std::string& groupName, const std::wstring& serviceName) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& grp = groups_[groupName];
        if (grp.processId == 0) {
            grp.groupName = groupName;
            grp.processId = 1000 + static_cast<uint32_t>(groups_.size()) * 100;
        }
        if (std::find(grp.hostedServices.begin(), grp.hostedServices.end(), serviceName) == grp.hostedServices.end()) {
            grp.hostedServices.push_back(serviceName);
        }
    }

    [[nodiscard]] std::vector<std::wstring> getServicesInGroup(const std::string& groupName) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(groupName);
        if (it != groups_.end()) {
            return it->second.hostedServices;
        }
        return {};
    }

    [[nodiscard]] uint32_t getGroupPid(const std::string& groupName) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(groupName);
        if (it != groups_.end()) {
            return it->second.processId;
        }
        return 0;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        groups_.clear();
    }

private:
    SvcHostManager() = default;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, SvcHostGroup> groups_;
};

// ============================================================================
// 5. Named Pipe RPC Protocol Framing (\\.\pipe\ntsvcs)
// ============================================================================

#pragma pack(push, 1)
struct ScmRpcHeader {
    uint32_t magic;      // 'SCM1' (Request: 0x314D4353) or 'SCM2' (Response: 0x324D4353)
    uint32_t opCode;     // SCM RPC Opcode
    uint32_t dataLength; // Length of payload
};

inline constexpr uint32_t SCM_RPC_REQ_MAGIC = 0x314D4353;
inline constexpr uint32_t SCM_RPC_RESP_MAGIC = 0x324D4353;

// RPC Opcodes
inline constexpr uint32_t SCM_RPC_OPEN_SCM       = 1;
inline constexpr uint32_t SCM_RPC_CREATE_SERVICE = 2;
inline constexpr uint32_t SCM_RPC_OPEN_SERVICE   = 3;
inline constexpr uint32_t SCM_RPC_START_SERVICE  = 4;
inline constexpr uint32_t SCM_RPC_CONTROL_SERVICE= 5;
inline constexpr uint32_t SCM_RPC_QUERY_STATUS   = 6;
inline constexpr uint32_t SCM_RPC_DELETE_SERVICE = 7;
inline constexpr uint32_t SCM_RPC_ENUM_SERVICES  = 8;

struct ScmRpcRequestPayload {
    wchar_t serviceName[64]{};
    uint32_t param1{0}; // e.g. controlCode or desiredAccess or startType
    uint32_t param2{0}; // e.g. serviceType
};

struct ScmRpcResponsePayload {
    uint32_t win32Error{0};
    uint32_t currentState{0};
    uint32_t controlsAccepted{0};
    uint32_t processId{0};
};
#pragma pack(pop)

// ============================================================================
// 6. Service Control Manager Core Engine
// ============================================================================

class ServiceControlManager {
public:
    static ServiceControlManager& get() {
        static ServiceControlManager instance;
        return instance;
    }

    void initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) return;

        services_.clear();
        handleMap_.clear();
        nextHandleId_ = 0x5C000100;

        // Populate Core Windows System Services
        populateSystemServices();

        // Register SCM Named Pipe RPC Endpoint: \\.\pipe\ntsvcs
        setupRpcPipe();

        initialized_ = true;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        services_.clear();
        handleMap_.clear();
        nextHandleId_ = 0x5C000100;
        initialized_ = false;
        SvcHostManager::get().reset();
    }

    // --- SCM API Implementations ---

    uint32_t openSCManager(
        const std::wstring& machineName,
        const std::wstring& databaseName,
        uint32_t desiredAccess,
        uintptr_t& scmHandle
    ) {
        (void)machineName;
        (void)databaseName;
        if ((desiredAccess & SC_MANAGER_CONNECT) == 0 && (desiredAccess & SC_MANAGER_ALL_ACCESS) == 0) {
            return ERROR_ACCESS_DENIED;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        scmHandle = ++nextHandleId_;
        handleMap_[scmHandle] = HandleInfo{
            .isManager = true,
            .access = desiredAccess,
            .serviceName = L""
        };
        return ERROR_SUCCESS;
    }

    uint32_t createService(
        uintptr_t scmHandle,
        const std::wstring& serviceName,
        const std::wstring& displayName,
        uint32_t desiredAccess,
        uint32_t serviceType,
        uint32_t startType,
        uint32_t errorControl,
        const std::wstring& binaryPath,
        const std::wstring& loadOrderGroup,
        const std::vector<std::wstring>& dependencies,
        const std::wstring& serviceStartName,
        uintptr_t& serviceHandle
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto itH = handleMap_.find(scmHandle);
        if (itH == handleMap_.end() || !itH->second.isManager) {
            return ERROR_INVALID_HANDLE;
        }
        if ((itH->second.access & SC_MANAGER_CREATE_SERVICE) == 0 && (itH->second.access & SC_MANAGER_ALL_ACCESS) == 0) {
            return ERROR_ACCESS_DENIED;
        }

        if (serviceName.empty()) return ERROR_INVALID_PARAMETER;
        if (services_.contains(serviceName)) {
            return ERROR_SERVICE_EXISTS;
        }

        auto rec = std::make_shared<ServiceRecord>();
        rec->serviceName = serviceName;
        rec->displayName = displayName.empty() ? serviceName : displayName;
        rec->serviceType = serviceType;
        rec->startType = startType;
        rec->errorControl = errorControl;
        rec->binaryPath = binaryPath;
        rec->loadOrderGroup = loadOrderGroup;
        rec->dependencies = dependencies;
        rec->serviceStartName = serviceStartName.empty() ? L"LocalSystem" : serviceStartName;
        rec->status.dwServiceType = serviceType;
        rec->status.dwCurrentState = SERVICE_STOPPED;
        rec->status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;

        // Auto-assign svchost group if sharing process
        if (serviceType & SERVICE_WIN32_SHARE_PROCESS) {
            std::string grp = "netsvcs";
            if (!loadOrderGroup.empty()) {
                grp.clear();
                for (wchar_t wc : loadOrderGroup) {
                    grp.push_back(static_cast<char>(wc & 0x7F));
                }
            }
            rec->svchostGroup = grp;
        }

        services_[serviceName] = rec;

        serviceHandle = ++nextHandleId_;
        handleMap_[serviceHandle] = HandleInfo{
            .isManager = false,
            .access = desiredAccess,
            .serviceName = serviceName
        };

        return ERROR_SUCCESS;
    }

    uint32_t openService(
        uintptr_t scmHandle,
        const std::wstring& serviceName,
        uint32_t desiredAccess,
        uintptr_t& serviceHandle
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto itH = handleMap_.find(scmHandle);
        if (itH == handleMap_.end() || !itH->second.isManager) {
            return ERROR_INVALID_HANDLE;
        }

        auto it = services_.find(serviceName);
        if (it == services_.end()) {
            return ERROR_SERVICE_DOES_NOT_EXIST;
        }

        if (it->second->markedForDelete) {
            return ERROR_SERVICE_MARKED_FOR_DELETE;
        }

        serviceHandle = ++nextHandleId_;
        handleMap_[serviceHandle] = HandleInfo{
            .isManager = false,
            .access = desiredAccess,
            .serviceName = serviceName
        };

        return ERROR_SUCCESS;
    }

    uint32_t startService(
        uintptr_t serviceHandle,
        const std::vector<std::wstring>& args = {}
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto itH = handleMap_.find(serviceHandle);
        if (itH == handleMap_.end() || itH->second.isManager) {
            return ERROR_INVALID_HANDLE;
        }

        auto it = services_.find(itH->second.serviceName);
        if (it == services_.end()) {
            return ERROR_SERVICE_DOES_NOT_EXIST;
        }

        return startServiceInternal(it->second, args);
    }

    uint32_t controlService(
        uintptr_t serviceHandle,
        uint32_t control,
        SERVICE_STATUS& outStatus
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto itH = handleMap_.find(serviceHandle);
        if (itH == handleMap_.end() || itH->second.isManager) {
            return ERROR_INVALID_HANDLE;
        }

        auto it = services_.find(itH->second.serviceName);
        if (it == services_.end()) {
            return ERROR_SERVICE_DOES_NOT_EXIST;
        }

        auto rec = it->second;

        // Check if service is active
        if (rec->status.dwCurrentState == SERVICE_STOPPED) {
            return ERROR_SERVICE_NOT_ACTIVE;
        }

        // Check if control is accepted
        uint32_t acceptBit = 0;
        if (control == SERVICE_CONTROL_STOP) acceptBit = SERVICE_ACCEPT_STOP;
        else if (control == SERVICE_CONTROL_PAUSE || control == SERVICE_CONTROL_CONTINUE) acceptBit = SERVICE_ACCEPT_PAUSE_CONTINUE;
        else if (control == SERVICE_CONTROL_SHUTDOWN) acceptBit = SERVICE_ACCEPT_SHUTDOWN;

        if (acceptBit != 0 && (rec->status.dwControlsAccepted & acceptBit) == 0) {
            return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
        }

        rec->controlHistory.push_back(control);

        if (control == SERVICE_CONTROL_STOP) {
            // Check for dependent running services
            for (const auto& [name, s] : services_) {
                if (s->isRunning() && s != rec) {
                    for (const auto& dep : s->dependencies) {
                        if (dep == rec->serviceName) {
                            return ERROR_DEPENDENT_SERVICES_RUNNING;
                        }
                    }
                }
            }

            rec->status.dwCurrentState = SERVICE_STOP_PENDING;
            if (rec->handler) rec->handler(SERVICE_CONTROL_STOP);
            if (rec->handlerEx) rec->handlerEx(SERVICE_CONTROL_STOP, 0, nullptr, rec->handlerContext);
            rec->status.dwCurrentState = SERVICE_STOPPED;
            rec->status.dwProcessId = 0;
        } else if (control == SERVICE_CONTROL_PAUSE) {
            rec->status.dwCurrentState = SERVICE_PAUSE_PENDING;
            if (rec->handler) rec->handler(SERVICE_CONTROL_PAUSE);
            if (rec->handlerEx) rec->handlerEx(SERVICE_CONTROL_PAUSE, 0, nullptr, rec->handlerContext);
            rec->status.dwCurrentState = SERVICE_PAUSED;
        } else if (control == SERVICE_CONTROL_CONTINUE) {
            rec->status.dwCurrentState = SERVICE_CONTINUE_PENDING;
            if (rec->handler) rec->handler(SERVICE_CONTROL_CONTINUE);
            if (rec->handlerEx) rec->handlerEx(SERVICE_CONTROL_CONTINUE, 0, nullptr, rec->handlerContext);
            rec->status.dwCurrentState = SERVICE_RUNNING;
        } else if (control == SERVICE_CONTROL_INTERROGATE) {
            if (rec->handler) rec->handler(SERVICE_CONTROL_INTERROGATE);
            if (rec->handlerEx) rec->handlerEx(SERVICE_CONTROL_INTERROGATE, 0, nullptr, rec->handlerContext);
        }

        outStatus = toServiceStatus(rec->status);
        return ERROR_SUCCESS;
    }

    uint32_t queryServiceStatus(
        uintptr_t serviceHandle,
        SERVICE_STATUS_PROCESS& outStatus
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto itH = handleMap_.find(serviceHandle);
        if (itH == handleMap_.end() || itH->second.isManager) {
            return ERROR_INVALID_HANDLE;
        }

        auto it = services_.find(itH->second.serviceName);
        if (it == services_.end()) {
            return ERROR_SERVICE_DOES_NOT_EXIST;
        }

        outStatus = it->second->status;
        return ERROR_SUCCESS;
    }

    uint32_t deleteService(uintptr_t serviceHandle) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto itH = handleMap_.find(serviceHandle);
        if (itH == handleMap_.end() || itH->second.isManager) {
            return ERROR_INVALID_HANDLE;
        }

        auto it = services_.find(itH->second.serviceName);
        if (it == services_.end()) {
            return ERROR_SERVICE_DOES_NOT_EXIST;
        }

        if (it->second->isRunning()) {
            it->second->markedForDelete = true;
            return ERROR_SUCCESS;
        }

        services_.erase(it);
        return ERROR_SUCCESS;
    }

    uint32_t closeServiceHandle(uintptr_t handle) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto itH = handleMap_.find(handle);
        if (itH == handleMap_.end()) {
            return ERROR_INVALID_HANDLE;
        }
        handleMap_.erase(itH);
        return ERROR_SUCCESS;
    }

    uint32_t enumServicesStatus(
        uint32_t serviceType,
        uint32_t serviceState,
        std::vector<ENUM_SERVICE_STATUS_PROCESSW>& services
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        services.clear();

        for (const auto& [name, rec] : services_) {
            if (rec->markedForDelete) continue;

            if (serviceType != SERVICE_TYPE_ALL && (rec->serviceType & serviceType) == 0) {
                continue;
            }

            if (serviceState == 1 && rec->status.dwCurrentState != SERVICE_RUNNING) { // SERVICE_ACTIVE
                continue;
            } else if (serviceState == 2 && rec->status.dwCurrentState != SERVICE_STOPPED) { // SERVICE_INACTIVE
                continue;
            }

            ENUM_SERVICE_STATUS_PROCESSW item;
            item.lpServiceName = rec->serviceName;
            item.lpDisplayName = rec->displayName;
            item.ServiceStatusProcess = rec->status;
            services.push_back(std::move(item));
        }

        return ERROR_SUCCESS;
    }

    // --- Direct Introspection Helpers ---

    void registerServiceRecord(std::shared_ptr<ServiceRecord> rec) {
        if (!rec) return;
        std::lock_guard<std::mutex> lock(mutex_);
        services_[rec->serviceName] = rec;
    }

    std::shared_ptr<ServiceRecord> getServiceRecord(const std::wstring& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = services_.find(name);
        return (it != services_.end()) ? it->second : nullptr;
    }

    [[nodiscard]] size_t getServiceCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return services_.size();
    }

    // Dependency Resolution (Topological sort)
    uint32_t resolveDependencies(
        const std::wstring& rootService,
        std::vector<std::wstring>& resolvedOrder
    ) {
        std::unordered_set<std::wstring> visited;
        std::unordered_set<std::wstring> visiting;
        resolvedOrder.clear();

        std::function<uint32_t(const std::wstring&)> dfs = [&](const std::wstring& svc) -> uint32_t {
            if (visiting.contains(svc)) {
                return ERROR_CIRCULAR_DEPENDENCY;
            }
            if (visited.contains(svc)) {
                return ERROR_SUCCESS;
            }

            auto it = services_.find(svc);
            if (it == services_.end()) {
                return ERROR_SERVICE_DOES_NOT_EXIST;
            }

            visiting.insert(svc);
            for (const auto& dep : it->second->dependencies) {
                uint32_t err = dfs(dep);
                if (err != ERROR_SUCCESS) return err;
            }
            visiting.erase(svc);
            visited.insert(svc);
            resolvedOrder.push_back(svc);
            return ERROR_SUCCESS;
        };

        return dfs(rootService);
    }

    // Process an RPC Request frame over \\.\pipe\ntsvcs
    std::vector<uint8_t> processRpcRequest(const uint8_t* reqBytes, size_t reqSize) {
        if (!reqBytes || reqSize < sizeof(ScmRpcHeader)) {
            return makeRpcError(ERROR_INVALID_PARAMETER);
        }

        const auto* hdr = reinterpret_cast<const ScmRpcHeader*>(reqBytes);
        if (hdr->magic != SCM_RPC_REQ_MAGIC) {
            return makeRpcError(ERROR_INVALID_PARAMETER);
        }

        if (reqSize < sizeof(ScmRpcHeader) + sizeof(ScmRpcRequestPayload)) {
            return makeRpcError(ERROR_INSUFFICIENT_BUFFER);
        }

        const auto* payload = reinterpret_cast<const ScmRpcRequestPayload*>(reqBytes + sizeof(ScmRpcHeader));
        std::wstring svcName(payload->serviceName);

        ScmRpcResponsePayload respPayload{};
        respPayload.win32Error = ERROR_SUCCESS;

        switch (hdr->opCode) {
            case SCM_RPC_OPEN_SCM: {
                uintptr_t handle = 0;
                respPayload.win32Error = openSCManager(L"", L"", payload->param1, handle);
                respPayload.processId = static_cast<uint32_t>(handle);
                break;
            }
            case SCM_RPC_OPEN_SERVICE: {
                uintptr_t handle = 0;
                respPayload.win32Error = openService(payload->param1, svcName, payload->param2, handle);
                respPayload.processId = static_cast<uint32_t>(handle);
                break;
            }
            case SCM_RPC_START_SERVICE: {
                uintptr_t handle = payload->param1;
                respPayload.win32Error = startService(handle);
                break;
            }
            case SCM_RPC_CONTROL_SERVICE: {
                uintptr_t handle = payload->param1;
                SERVICE_STATUS st{};
                respPayload.win32Error = controlService(handle, payload->param2, st);
                respPayload.currentState = st.dwCurrentState;
                respPayload.controlsAccepted = st.dwControlsAccepted;
                break;
            }
            case SCM_RPC_QUERY_STATUS: {
                uintptr_t handle = payload->param1;
                SERVICE_STATUS_PROCESS st{};
                respPayload.win32Error = queryServiceStatus(handle, st);
                respPayload.currentState = st.dwCurrentState;
                respPayload.controlsAccepted = st.dwControlsAccepted;
                respPayload.processId = st.dwProcessId;
                break;
            }
            case SCM_RPC_DELETE_SERVICE: {
                uintptr_t handle = payload->param1;
                respPayload.win32Error = deleteService(handle);
                break;
            }
            default:
                respPayload.win32Error = ERROR_INVALID_PARAMETER;
                break;
        }

        std::vector<uint8_t> out(sizeof(ScmRpcHeader) + sizeof(ScmRpcResponsePayload));
        auto* respHdr = reinterpret_cast<ScmRpcHeader*>(out.data());
        respHdr->magic = SCM_RPC_RESP_MAGIC;
        respHdr->opCode = hdr->opCode;
        respHdr->dataLength = sizeof(ScmRpcResponsePayload);
        std::memcpy(out.data() + sizeof(ScmRpcHeader), &respPayload, sizeof(ScmRpcResponsePayload));
        return out;
    }

private:
    struct HandleInfo {
        bool isManager{false};
        uint32_t access{0};
        std::wstring serviceName;
    };

    ServiceControlManager() = default;

    static SERVICE_STATUS toServiceStatus(const SERVICE_STATUS_PROCESS& ssp) {
        return SERVICE_STATUS{
            .dwServiceType = ssp.dwServiceType,
            .dwCurrentState = ssp.dwCurrentState,
            .dwControlsAccepted = ssp.dwControlsAccepted,
            .dwWin32ExitCode = ssp.dwWin32ExitCode,
            .dwServiceSpecificExitCode = ssp.dwServiceSpecificExitCode,
            .dwCheckPoint = ssp.dwCheckPoint,
            .dwWaitHint = ssp.dwWaitHint
        };
    }

    std::vector<uint8_t> makeRpcError(uint32_t err) {
        std::vector<uint8_t> out(sizeof(ScmRpcHeader) + sizeof(ScmRpcResponsePayload));
        auto* respHdr = reinterpret_cast<ScmRpcHeader*>(out.data());
        respHdr->magic = SCM_RPC_RESP_MAGIC;
        respHdr->opCode = 0;
        respHdr->dataLength = sizeof(ScmRpcResponsePayload);
        ScmRpcResponsePayload pl{};
        pl.win32Error = err;
        std::memcpy(out.data() + sizeof(ScmRpcHeader), &pl, sizeof(ScmRpcResponsePayload));
        return out;
    }

    uint32_t startServiceInternal(const std::shared_ptr<ServiceRecord>& rec, const std::vector<std::wstring>& args) {
        if (rec->status.dwCurrentState == SERVICE_RUNNING) {
            return ERROR_SERVICE_ALREADY_RUNNING;
        }
        if (rec->startType == SERVICE_DISABLED) {
            return ERROR_SERVICE_DISABLED;
        }

        // 1. Resolve & start dependencies first
        std::vector<std::wstring> order;
        uint32_t depErr = resolveDependencies(rec->serviceName, order);
        if (depErr != ERROR_SUCCESS) {
            return depErr;
        }

        for (const auto& depName : order) {
            if (depName == rec->serviceName) continue;
            auto depRec = services_[depName];
            if (depRec && !depRec->isRunning()) {
                uint32_t sErr = startSingleService(depRec, {});
                if (sErr != ERROR_SUCCESS) return sErr;
            }
        }

        return startSingleService(rec, args);
    }

    uint32_t startSingleService(const std::shared_ptr<ServiceRecord>& rec, const std::vector<std::wstring>& args) {
        rec->status.dwCurrentState = SERVICE_START_PENDING;

        if (rec->serviceType & SERVICE_DRIVER) {
            // Load Driver via Ring 0 DriverManager
            if (rec->driverEntry) {
                NtStatus st = driver::DriverManager::get().loadDriver(
                    rec->serviceName,
                    rec->driverEntry,
                    rec->binaryPath
                );
                if (!NT_SUCCESS(st)) {
                    rec->status.dwCurrentState = SERVICE_STOPPED;
                    return ERROR_SERVICE_SPECIFIC_ERROR;
                }
            }
            rec->status.dwProcessId = 4; // 'System' kernel process
        } else if (rec->serviceType & SERVICE_WIN32_SHARE_PROCESS) {
            // Assign to svchost group
            std::string grp = rec->svchostGroup.empty() ? "netsvcs" : rec->svchostGroup;
            uint32_t pid = SvcHostManager::get().getOrCreateGroupProcess(grp);
            SvcHostManager::get().assignService(grp, rec->serviceName);
            rec->status.dwProcessId = pid;
        } else {
            // Own Process: allocate unique PID
            static uint32_t nextOwnPid = 2000;
            rec->status.dwProcessId = ++nextOwnPid;
        }

        if (rec->mainFunc) {
            std::vector<const wchar_t*> argvPointers;
            argvPointers.push_back(rec->serviceName.c_str());
            for (const auto& a : args) {
                argvPointers.push_back(a.c_str());
            }
            rec->mainFunc(static_cast<uint32_t>(argvPointers.size()), argvPointers.data());
        }

        rec->status.dwCurrentState = SERVICE_RUNNING;
        return ERROR_SUCCESS;
    }

    void setupRpcPipe() {
        auto& vfs = fs::VirtualFileSystem::get();
        std::shared_ptr<fs::FileObject> pipeObj;
        vfs.createOrOpenFile(
            L"\\\\.\\pipe\\ntsvcs",
            fs::FILE_GENERIC_READ | fs::FILE_GENERIC_WRITE,
            fs::FILE_OPEN_IF,
            pipeObj
        );
    }

    void populateSystemServices() {
        // 1. RpcSs: Remote Procedure Call Subsystem
        auto rpcSs = std::make_shared<ServiceRecord>();
        rpcSs->serviceName = L"RpcSs";
        rpcSs->displayName = L"Remote Procedure Call (RPC)";
        rpcSs->serviceType = SERVICE_WIN32_SHARE_PROCESS;
        rpcSs->startType = SERVICE_AUTO_START;
        rpcSs->svchostGroup = "DcomLaunch";
        rpcSs->binaryPath = L"C:\\Windows\\system32\\svchost.exe -k DcomLaunch";
        rpcSs->serviceStartName = L"NT AUTHORITY\\NetworkService";
        rpcSs->status.dwServiceType = rpcSs->serviceType;
        rpcSs->status.dwCurrentState = SERVICE_RUNNING;
        rpcSs->status.dwProcessId = SvcHostManager::get().getOrCreateGroupProcess("DcomLaunch");
        SvcHostManager::get().assignService("DcomLaunch", rpcSs->serviceName);
        services_[rpcSs->serviceName] = rpcSs;

        // 2. EventLog: Windows Event Log
        auto evLog = std::make_shared<ServiceRecord>();
        evLog->serviceName = L"EventLog";
        evLog->displayName = L"Windows Event Log";
        evLog->serviceType = SERVICE_WIN32_SHARE_PROCESS;
        evLog->startType = SERVICE_AUTO_START;
        evLog->svchostGroup = "LocalService";
        evLog->binaryPath = L"C:\\Windows\\system32\\svchost.exe -k LocalService";
        evLog->serviceStartName = L"NT AUTHORITY\\LocalService";
        evLog->status.dwServiceType = evLog->serviceType;
        evLog->status.dwCurrentState = SERVICE_RUNNING;
        evLog->status.dwProcessId = SvcHostManager::get().getOrCreateGroupProcess("LocalService");
        SvcHostManager::get().assignService("LocalService", evLog->serviceName);
        services_[evLog->serviceName] = evLog;

        // 3. Tcpip: TCP/IP Protocol Driver
        auto tcpip = std::make_shared<ServiceRecord>();
        tcpip->serviceName = L"Tcpip";
        tcpip->displayName = L"TCP/IP Protocol Driver";
        tcpip->serviceType = SERVICE_KERNEL_DRIVER;
        tcpip->startType = SERVICE_BOOT_START;
        tcpip->binaryPath = L"System32\\drivers\\tcpip.sys";
        tcpip->status.dwServiceType = tcpip->serviceType;
        tcpip->status.dwCurrentState = SERVICE_RUNNING;
        tcpip->status.dwProcessId = 4;
        services_[tcpip->serviceName] = tcpip;

        // 4. Dhcp: DHCP Client (depends on Tcpip)
        auto dhcp = std::make_shared<ServiceRecord>();
        dhcp->serviceName = L"Dhcp";
        dhcp->displayName = L"DHCP Client";
        dhcp->serviceType = SERVICE_WIN32_SHARE_PROCESS;
        dhcp->startType = SERVICE_AUTO_START;
        dhcp->svchostGroup = "netsvcs";
        dhcp->binaryPath = L"C:\\Windows\\system32\\svchost.exe -k netsvcs";
        dhcp->dependencies = {L"Tcpip"};
        dhcp->status.dwServiceType = dhcp->serviceType;
        dhcp->status.dwCurrentState = SERVICE_RUNNING;
        dhcp->status.dwProcessId = SvcHostManager::get().getOrCreateGroupProcess("netsvcs");
        SvcHostManager::get().assignService("netsvcs", dhcp->serviceName);
        services_[dhcp->serviceName] = dhcp;

        // 5. Dnscache: DNS Client (depends on Tcpip)
        auto dns = std::make_shared<ServiceRecord>();
        dns->serviceName = L"Dnscache";
        dns->displayName = L"DNS Client";
        dns->serviceType = SERVICE_WIN32_SHARE_PROCESS;
        dns->startType = SERVICE_AUTO_START;
        dns->svchostGroup = "netsvcs";
        dns->binaryPath = L"C:\\Windows\\system32\\svchost.exe -k netsvcs";
        dns->dependencies = {L"Tcpip"};
        dns->status.dwServiceType = dns->serviceType;
        dns->status.dwCurrentState = SERVICE_RUNNING;
        dns->status.dwProcessId = SvcHostManager::get().getOrCreateGroupProcess("netsvcs");
        SvcHostManager::get().assignService("netsvcs", dns->serviceName);
        services_[dns->serviceName] = dns;

        // 6. LanmanWorkstation: Workstation Service (depends on RpcSs and Tcpip)
        auto wrk = std::make_shared<ServiceRecord>();
        wrk->serviceName = L"LanmanWorkstation";
        wrk->displayName = L"Workstation";
        wrk->serviceType = SERVICE_WIN32_SHARE_PROCESS;
        wrk->startType = SERVICE_AUTO_START;
        wrk->svchostGroup = "netsvcs";
        wrk->binaryPath = L"C:\\Windows\\system32\\svchost.exe -k netsvcs";
        wrk->dependencies = {L"RpcSs", L"Tcpip"};
        wrk->status.dwServiceType = wrk->serviceType;
        wrk->status.dwCurrentState = SERVICE_RUNNING;
        wrk->status.dwProcessId = SvcHostManager::get().getOrCreateGroupProcess("netsvcs");
        SvcHostManager::get().assignService("netsvcs", wrk->serviceName);
        services_[wrk->serviceName] = wrk;

        // 7. MicaSec: Clean-Room Security Guard
        auto sec = std::make_shared<ServiceRecord>();
        sec->serviceName = L"MicaSec";
        sec->displayName = L"MicaNT Clean-Room Zero-Telemetry Security Guard";
        sec->serviceType = SERVICE_WIN32_OWN_PROCESS;
        sec->startType = SERVICE_AUTO_START;
        sec->binaryPath = L"C:\\Windows\\system32\\mcasec.exe";
        sec->status.dwServiceType = sec->serviceType;
        sec->status.dwCurrentState = SERVICE_RUNNING;
        sec->status.dwProcessId = 1800;
        services_[sec->serviceName] = sec;
    }

    mutable std::mutex mutex_;
    bool initialized_{false};
    uintptr_t nextHandleId_{0x5C000100};
    std::unordered_map<uintptr_t, HandleInfo> handleMap_;
    std::unordered_map<std::wstring, std::shared_ptr<ServiceRecord>> services_;
};

} // namespace micant::scm
