// ============================================================================
// MicaNT: Windows Task Scheduler 2.0 Subsystem
// (taskschd.dll, mstask.dll & schtasks CLI Engine)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Provides complete Task Scheduler 2.0 COM object hierarchy:
// - ITaskService, ITaskFolder, ITaskFolderCollection
// - ITaskDefinition, IRegistrationInfo, ITaskSettings, IPrincipal
// - ITriggerCollection, ITrigger, ITimeTrigger, IDailyTrigger, IBootTrigger, ILogonTrigger
// - IRepetitionPattern
// - IActionCollection, IAction, IExecAction
// - IRegisteredTask, IRegisteredTaskCollection
// - IRunningTask, IRunningTaskCollection
// - Task XML serialization / deserialization engine
// - Background job scheduler & executor with built-in Windows system tasks
// - Dynamic loader exports for taskschd.dll and COM activation (CLSID_TaskScheduler)
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <chrono>

#include "ntdef.hpp"
#include "kernel32.hpp"
#include "ole32.hpp"
#include "oleaut32.hpp"
#include "ldr.hpp"

namespace micant::taskschd {

using namespace micant::ole32;
using namespace micant::oleaut32;

// OLE Automation DATE type & Win32 basic types
using DATE = double;
using LONG = int32_t;
using INT = int32_t;
using DWORD = uint32_t;
using BOOL = int32_t;

#ifndef HRESULT_FROM_WIN32
inline constexpr HRESULT HRESULT_FROM_WIN32(uint32_t x) noexcept {
    return (x <= 0 ? static_cast<HRESULT>(x) : static_cast<HRESULT>((x & 0x0000FFFF) | (7 << 16) | 0x80000000));
}
#endif

inline constexpr uint32_t SCHED_ERROR_FILE_NOT_FOUND = 2;

// ============================================================================
// 1. Task Scheduler 2.0 CLSIDs, IIDs, Enums & Status Codes
// ============================================================================

// CLSID_TaskScheduler: {0f87369f-a4e5-4cfc-bd3e-73e6154572dd}
inline constexpr GUID CLSID_TaskScheduler = {
    0x0F87369F, 0xA4E5, 0x4CFC, { 0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD }
};

// IID_ITaskService: {2faba4c7-4da9-4013-9697-20cc3fd40f85}
inline constexpr GUID IID_ITaskService = {
    0x2FABA4C7, 0x4DA9, 0x4013, { 0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85 }
};

// IID_ITaskFolder: {8cfac062-a080-4c15-9a88-aa7c2af80dfc}
inline constexpr GUID IID_ITaskFolder = {
    0x8CFAC062, 0xA080, 0x4C15, { 0x9A, 0x88, 0xAA, 0x7C, 0x2A, 0xF8, 0x0D, 0xFC }
};

// IID_ITaskFolderCollection: {79184a66-8664-423f-97f1-637356a5d812}
inline constexpr GUID IID_ITaskFolderCollection = {
    0x79184A66, 0x8664, 0x423F, { 0x97, 0xF1, 0x63, 0x73, 0x56, 0xA5, 0xD8, 0x12 }
};

// IID_ITaskDefinition: {f5bc8fc5-536d-4f77-b852-fbc1356fdeb6}
inline constexpr GUID IID_ITaskDefinition = {
    0xF5BC8FC5, 0x536D, 0x4F77, { 0xB8, 0x52, 0xFB, 0xC1, 0x35, 0x6F, 0xDE, 0xB6 }
};

// IID_IRegistrationInfo: {416d8b73-cb41-4ea1-805c-9be9a5ac4a74}
inline constexpr GUID IID_IRegistrationInfo = {
    0x416D8B73, 0xCB41, 0x4EA1, { 0x80, 0x5C, 0x9B, 0xE9, 0xA5, 0xAC, 0x4A, 0x74 }
};

// IID_ITaskSettings: {8fd4711d-2d02-4c8c-87e3-eff699de127e}
inline constexpr GUID IID_ITaskSettings = {
    0x8FD4711D, 0x2D02, 0x4C8C, { 0x87, 0xE3, 0xEF, 0xF6, 0x99, 0xDE, 0x12, 0x7E }
};

// IID_ITriggerCollection: {85df5081-1b24-4f32-878a-d9d14df4cb77}
inline constexpr GUID IID_ITriggerCollection = {
    0x85DF5081, 0x1B24, 0x4F32, { 0x87, 0x8A, 0xD9, 0xD1, 0x4D, 0xF4, 0xCB, 0x77 }
};

// IID_ITrigger: {09941815-ea89-4b5b-89e0-2a773801fac3}
inline constexpr GUID IID_ITrigger = {
    0x09941815, 0xEA89, 0x4B5B, { 0x89, 0xE0, 0x2A, 0x77, 0x38, 0x01, 0xFA, 0xC3 }
};

// IID_ITimeTrigger: {b45747e0-eba7-4276-9f29-85c5bb300006}
inline constexpr GUID IID_ITimeTrigger = {
    0xB45747E0, 0xEBA7, 0x4276, { 0x9F, 0x29, 0x85, 0xC5, 0xBB, 0x30, 0x00, 0x06 }
};

// IID_IDailyTrigger: {126c5cd8-b288-41d5-8dbf-e491446adc5c}
inline constexpr GUID IID_IDailyTrigger = {
    0x126C5CD8, 0xB288, 0x41D5, { 0x8D, 0xBF, 0xE4, 0x91, 0x44, 0x6A, 0xDC, 0x5C }
};

// IID_IBootTrigger: {2a9c35da-d357-41f4-bbc1-207ac1b1f3cb}
inline constexpr GUID IID_IBootTrigger = {
    0x2A9C35DA, 0xD357, 0x41F4, { 0xBB, 0xC1, 0x20, 0x7A, 0xC1, 0xB1, 0xF3, 0xCB }
};

// IID_ILogonTrigger: {72dade38-fae4-4b3e-baf4-5d009af02b1c}
inline constexpr GUID IID_ILogonTrigger = {
    0x72DADE38, 0xFAE4, 0x4B3E, { 0xBA, 0xF4, 0x5D, 0x00, 0x9A, 0xF0, 0x2B, 0x1C }
};

// IID_IActionCollection: {02820e19-7b98-4ed2-b2e8-fdccceff619b}
inline constexpr GUID IID_IActionCollection = {
    0x02820E19, 0x7B98, 0x4ED2, { 0xB2, 0xE8, 0xFD, 0xCC, 0xCE, 0xFF, 0x61, 0x9B }
};

// IID_IAction: {bae54997-48b1-4cbe-9965-d6be263ebea4}
inline constexpr GUID IID_IAction = {
    0xBAE54997, 0x48B1, 0x4CBE, { 0x99, 0x65, 0xD6, 0xBE, 0x26, 0x3E, 0xBE, 0xA4 }
};

// IID_IExecAction: {4c3d624d-fd6b-49a3-b9b7-09cb3cd3f047}
inline constexpr GUID IID_IExecAction = {
    0x4C3D624D, 0xFD6B, 0x49A3, { 0xB9, 0xB7, 0x09, 0xCB, 0x3C, 0xD3, 0xF0, 0x47 }
};

// IID_IPrincipal: {d98d51e5-c9b4-496a-a9c1-18980261cf0f}
inline constexpr GUID IID_IPrincipal = {
    0xD98D51E5, 0xC9B4, 0x496A, { 0xA9, 0xC1, 0x18, 0x98, 0x02, 0x61, 0xCF, 0x0F }
};

// IID_IRegisteredTask: {9c86f320-dee3-4dd1-b972-a303f26b061e}
inline constexpr GUID IID_IRegisteredTask = {
    0x9C86F320, 0xDEE3, 0x4DD1, { 0xB9, 0x72, 0xA3, 0x03, 0xF2, 0x6B, 0x06, 0x1E }
};

// IID_IRegisteredTaskCollection: {86627eb4-42a7-41e4-a4d9-ac33a72f2d52}
inline constexpr GUID IID_IRegisteredTaskCollection = {
    0x86627EB4, 0x42A7, 0x41E4, { 0xA4, 0xD9, 0xAC, 0x33, 0xA7, 0x2F, 0x2D, 0x52 }
};

// IID_IRunningTask: {653758fb-7b9a-4f1e-a471-beeb8e9b834e}
inline constexpr GUID IID_IRunningTask = {
    0x653758FB, 0x7B9A, 0x4F1E, { 0xA4, 0x71, 0xBE, 0xEB, 0x8E, 0x9B, 0x83, 0x4E }
};

// IID_IRunningTaskCollection: {6a67614b-6828-4fec-aa54-6d52e8f1f2db}
inline constexpr GUID IID_IRunningTaskCollection = {
    0x6A67614B, 0x6828, 0x4FEC, { 0xAA, 0x54, 0x6D, 0x52, 0xE8, 0xF1, 0xF2, 0xDB }
};

// IID_IRepetitionPattern: {7fb9acf1-26be-400e-85b5-294b9c75dfd6}
inline constexpr GUID IID_IRepetitionPattern = {
    0x7FB9ACF1, 0x26BE, 0x400E, { 0x85, 0xB5, 0x29, 0x4B, 0x9C, 0x75, 0xDF, 0xD6 }
};

// Task Scheduler Enumerations (from win32metadata)
enum _TASK_STATE {
    TASK_STATE_UNKNOWN   = 0,
    TASK_STATE_DISABLED  = 1,
    TASK_STATE_QUEUED    = 2,
    TASK_STATE_READY     = 3,
    TASK_STATE_RUNNING   = 4
};
using TASK_STATE = _TASK_STATE;

enum _TASK_TRIGGER_TYPE2 {
    TASK_TRIGGER_EVENT                 = 0,
    TASK_TRIGGER_TIME                  = 1,
    TASK_TRIGGER_DAILY                 = 2,
    TASK_TRIGGER_WEEKLY                = 3,
    TASK_TRIGGER_MONTHLY               = 4,
    TASK_TRIGGER_MONTHLYDOW            = 5,
    TASK_TRIGGER_IDLE                  = 6,
    TASK_TRIGGER_REGISTRATION          = 7,
    TASK_TRIGGER_BOOT                  = 8,
    TASK_TRIGGER_LOGON                 = 9,
    TASK_TRIGGER_SESSION_STATE_CHANGE  = 11,
    TASK_TRIGGER_CUSTOM_TRIGGER_01     = 12
};
using TASK_TRIGGER_TYPE2 = _TASK_TRIGGER_TYPE2;

enum _TASK_ACTION_TYPE {
    TASK_ACTION_EXEC         = 0,
    TASK_ACTION_COM_HANDLER  = 5,
    TASK_ACTION_SEND_EMAIL   = 6,
    TASK_ACTION_SHOW_MESSAGE = 7
};
using TASK_ACTION_TYPE = _TASK_ACTION_TYPE;

enum _TASK_LOGON_TYPE {
    TASK_LOGON_NONE                           = 0,
    TASK_LOGON_PASSWORD                       = 1,
    TASK_LOGON_S4U                            = 2,
    TASK_LOGON_INTERACTIVE_TOKEN              = 3,
    TASK_LOGON_GROUP                          = 4,
    TASK_LOGON_SERVICE_ACCOUNT                = 5,
    TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD  = 6
};
using TASK_LOGON_TYPE = _TASK_LOGON_TYPE;

enum _TASK_CREATION {
    TASK_VALIDATE_ONLY                 = 0x1,
    TASK_CREATE                        = 0x2,
    TASK_UPDATE                        = 0x4,
    TASK_CREATE_OR_UPDATE              = (TASK_CREATE | TASK_UPDATE),
    TASK_DISABLE                       = 0x8,
    TASK_DONT_ADD_PRINCIPAL_ACE        = 0x10,
    TASK_IGNORE_REGISTRATION_TRIGGERS  = 0x20
};
using TASK_CREATION = _TASK_CREATION;

enum _TASK_INSTANCES_POLICY {
    TASK_INSTANCES_PARALLEL      = 0,
    TASK_INSTANCES_QUEUE         = 1,
    TASK_INSTANCES_IGNORE_NEW    = 2,
    TASK_INSTANCES_STOP_EXISTING = 3
};
using TASK_INSTANCES_POLICY = _TASK_INSTANCES_POLICY;

enum _TASK_RUN_FLAGS {
    TASK_RUN_NO_FLAGS            = 0,
    TASK_RUN_AS_SELF             = 1,
    TASK_RUN_IGNORE_CONSTRAINTS  = 2,
    TASK_RUN_USE_SESSION_ID      = 4,
    TASK_RUN_USER_SID            = 8
};
using TASK_RUN_FLAGS = _TASK_RUN_FLAGS;

enum _TASK_ENUM_FLAGS {
    TASK_ENUM_HIDDEN = 0x1
};
using TASK_ENUM_FLAGS = _TASK_ENUM_FLAGS;

// Status & Error HRESULT Codes
inline constexpr HRESULT SCHED_S_TASK_READY               = static_cast<HRESULT>(0x00041300);
inline constexpr HRESULT SCHED_S_TASK_RUNNING             = static_cast<HRESULT>(0x00041301);
inline constexpr HRESULT SCHED_S_TASK_DISABLED            = static_cast<HRESULT>(0x00041302);
inline constexpr HRESULT SCHED_S_TASK_HAS_NOT_RUN         = static_cast<HRESULT>(0x00041303);
inline constexpr HRESULT SCHED_S_TASK_NO_MORE_RUNS        = static_cast<HRESULT>(0x00041304);
inline constexpr HRESULT SCHED_S_TASK_NOT_SCHEDULED       = static_cast<HRESULT>(0x00041305);
inline constexpr HRESULT SCHED_S_TASK_TERMINATED          = static_cast<HRESULT>(0x00041306);
inline constexpr HRESULT SCHED_S_TASK_NO_VALID_TRIGGERS   = static_cast<HRESULT>(0x00041307);
inline constexpr HRESULT SCHED_S_EVENT_TRIGGER            = static_cast<HRESULT>(0x00041308);

inline constexpr HRESULT SCHED_E_TASK_NOT_READY           = static_cast<HRESULT>(0x80041300);
inline constexpr HRESULT SCHED_E_TASK_NOT_RUNNING         = static_cast<HRESULT>(0x80041301);
inline constexpr HRESULT SCHED_E_SERVICE_NOT_INSTALLED    = static_cast<HRESULT>(0x80041302);
inline constexpr HRESULT SCHED_E_CANNOT_OPEN_TASK         = static_cast<HRESULT>(0x80041303);
inline constexpr HRESULT SCHED_E_INVALID_TASK             = static_cast<HRESULT>(0x80041304);
inline constexpr HRESULT SCHED_E_ACCOUNT_INFORMATION_NOT_SET = static_cast<HRESULT>(0x80041305);
inline constexpr HRESULT SCHED_E_ACCOUNT_NAME_NOT_FOUND   = static_cast<HRESULT>(0x80041306);
inline constexpr HRESULT SCHED_E_TRIGGER_NOT_FOUND        = static_cast<HRESULT>(0x8004130B);
inline constexpr HRESULT SCHED_E_SERVICE_NOT_AVAILABLE    = static_cast<HRESULT>(0x8004130D);
inline constexpr HRESULT SCHED_E_SERVICE_NOT_RUNNING      = static_cast<HRESULT>(0x8004130E);
inline constexpr HRESULT SCHED_E_ALREADY_EXISTS           = static_cast<HRESULT>(0x80041318);
inline constexpr HRESULT SCHED_E_TASK_NOT_FOUND           = static_cast<HRESULT>(0x80041319);

// Forward Declarations
class ITaskService;
class ITaskFolder;
class ITaskFolderCollection;
class ITaskDefinition;
class IRegistrationInfo;
class ITaskSettings;
class IPrincipal;
class ITriggerCollection;
class ITrigger;
class ITimeTrigger;
class IDailyTrigger;
class IBootTrigger;
class ILogonTrigger;
class IRepetitionPattern;
class IActionCollection;
class IAction;
class IExecAction;
class IRegisteredTask;
class IRegisteredTaskCollection;
class IRunningTask;
class IRunningTaskCollection;

// ============================================================================
// 2. Pure Virtual COM Interfaces
// ============================================================================

class IRepetitionPattern : public IDispatch {
public:
    virtual HRESULT __stdcall get_Interval(BSTR* pInterval) = 0;
    virtual HRESULT __stdcall put_Interval(BSTR interval) = 0;
    virtual HRESULT __stdcall get_Duration(BSTR* pDuration) = 0;
    virtual HRESULT __stdcall put_Duration(BSTR duration) = 0;
    virtual HRESULT __stdcall get_StopAtDurationEnd(VARIANT_BOOL* pStop) = 0;
    virtual HRESULT __stdcall put_StopAtDurationEnd(VARIANT_BOOL stop) = 0;
};

class ITrigger : public IDispatch {
public:
    virtual HRESULT __stdcall get_Type(TASK_TRIGGER_TYPE2* pType) = 0;
    virtual HRESULT __stdcall get_Id(BSTR* pId) = 0;
    virtual HRESULT __stdcall put_Id(BSTR id) = 0;
    virtual HRESULT __stdcall get_Repetition(IRepetitionPattern** ppRepetition) = 0;
    virtual HRESULT __stdcall put_Repetition(IRepetitionPattern* pRepetition) = 0;
    virtual HRESULT __stdcall get_ExecutionTimeLimit(BSTR* pLimit) = 0;
    virtual HRESULT __stdcall put_ExecutionTimeLimit(BSTR limit) = 0;
    virtual HRESULT __stdcall get_StartBoundary(BSTR* pStart) = 0;
    virtual HRESULT __stdcall put_StartBoundary(BSTR start) = 0;
    virtual HRESULT __stdcall get_EndBoundary(BSTR* pEnd) = 0;
    virtual HRESULT __stdcall put_EndBoundary(BSTR end) = 0;
    virtual HRESULT __stdcall get_Enabled(VARIANT_BOOL* pEnabled) = 0;
    virtual HRESULT __stdcall put_Enabled(VARIANT_BOOL enabled) = 0;
};

class ITimeTrigger : public ITrigger {
public:
    virtual HRESULT __stdcall get_RandomDelay(BSTR* pRandomDelay) = 0;
    virtual HRESULT __stdcall put_RandomDelay(BSTR randomDelay) = 0;
};

class IDailyTrigger : public ITrigger {
public:
    virtual HRESULT __stdcall get_DaysInterval(short* pDays) = 0;
    virtual HRESULT __stdcall put_DaysInterval(short days) = 0;
    virtual HRESULT __stdcall get_RandomDelay(BSTR* pRandomDelay) = 0;
    virtual HRESULT __stdcall put_RandomDelay(BSTR randomDelay) = 0;
};

class IBootTrigger : public ITrigger {
public:
    virtual HRESULT __stdcall get_Delay(BSTR* pDelay) = 0;
    virtual HRESULT __stdcall put_Delay(BSTR delay) = 0;
};

class ILogonTrigger : public ITrigger {
public:
    virtual HRESULT __stdcall get_Delay(BSTR* pDelay) = 0;
    virtual HRESULT __stdcall put_Delay(BSTR delay) = 0;
    virtual HRESULT __stdcall get_UserId(BSTR* pUser) = 0;
    virtual HRESULT __stdcall put_UserId(BSTR user) = 0;
};

class ITriggerCollection : public IDispatch {
public:
    virtual HRESULT __stdcall get_Count(LONG* pCount) = 0;
    virtual HRESULT __stdcall get_Item(LONG index, ITrigger** ppTrigger) = 0;
    virtual HRESULT __stdcall get__NewEnum(IUnknown** ppEnum) = 0;
    virtual HRESULT __stdcall Create(TASK_TRIGGER_TYPE2 type, ITrigger** ppTrigger) = 0;
    virtual HRESULT __stdcall Remove(VARIANT index) = 0;
    virtual HRESULT __stdcall Clear() = 0;
};

class IAction : public IDispatch {
public:
    virtual HRESULT __stdcall get_Id(BSTR* pId) = 0;
    virtual HRESULT __stdcall put_Id(BSTR id) = 0;
    virtual HRESULT __stdcall get_Type(TASK_ACTION_TYPE* pType) = 0;
};

class IExecAction : public IAction {
public:
    virtual HRESULT __stdcall get_Path(BSTR* pPath) = 0;
    virtual HRESULT __stdcall put_Path(BSTR path) = 0;
    virtual HRESULT __stdcall get_Arguments(BSTR* pArguments) = 0;
    virtual HRESULT __stdcall put_Arguments(BSTR arguments) = 0;
    virtual HRESULT __stdcall get_WorkingDirectory(BSTR* pWorkingDirectory) = 0;
    virtual HRESULT __stdcall put_WorkingDirectory(BSTR workingDirectory) = 0;
};

class IActionCollection : public IDispatch {
public:
    virtual HRESULT __stdcall get_Count(LONG* pCount) = 0;
    virtual HRESULT __stdcall get_Item(LONG index, IAction** ppAction) = 0;
    virtual HRESULT __stdcall get__NewEnum(IUnknown** ppEnum) = 0;
    virtual HRESULT __stdcall get_XmlText(BSTR* pXml) = 0;
    virtual HRESULT __stdcall put_XmlText(BSTR xml) = 0;
    virtual HRESULT __stdcall Create(TASK_ACTION_TYPE type, IAction** ppAction) = 0;
    virtual HRESULT __stdcall Remove(VARIANT index) = 0;
    virtual HRESULT __stdcall Clear() = 0;
    virtual HRESULT __stdcall get_Context(BSTR* pContext) = 0;
    virtual HRESULT __stdcall put_Context(BSTR context) = 0;
};

class IPrincipal : public IDispatch {
public:
    virtual HRESULT __stdcall get_Id(BSTR* pId) = 0;
    virtual HRESULT __stdcall put_Id(BSTR id) = 0;
    virtual HRESULT __stdcall get_DisplayName(BSTR* pDisplayName) = 0;
    virtual HRESULT __stdcall put_DisplayName(BSTR displayName) = 0;
    virtual HRESULT __stdcall get_UserId(BSTR* pUserId) = 0;
    virtual HRESULT __stdcall put_UserId(BSTR userId) = 0;
    virtual HRESULT __stdcall get_LogonType(TASK_LOGON_TYPE* pLogonType) = 0;
    virtual HRESULT __stdcall put_LogonType(TASK_LOGON_TYPE logonType) = 0;
    virtual HRESULT __stdcall get_GroupId(BSTR* pGroupId) = 0;
    virtual HRESULT __stdcall put_GroupId(BSTR groupId) = 0;
    virtual HRESULT __stdcall get_RunLevel(LONG* pRunLevel) = 0;
    virtual HRESULT __stdcall put_RunLevel(LONG runLevel) = 0;
};

class IRegistrationInfo : public IDispatch {
public:
    virtual HRESULT __stdcall get_Description(BSTR* pDescription) = 0;
    virtual HRESULT __stdcall put_Description(BSTR description) = 0;
    virtual HRESULT __stdcall get_Author(BSTR* pAuthor) = 0;
    virtual HRESULT __stdcall put_Author(BSTR author) = 0;
    virtual HRESULT __stdcall get_Version(BSTR* pVersion) = 0;
    virtual HRESULT __stdcall put_Version(BSTR version) = 0;
    virtual HRESULT __stdcall get_Date(BSTR* pDate) = 0;
    virtual HRESULT __stdcall put_Date(BSTR date) = 0;
    virtual HRESULT __stdcall get_URI(BSTR* pURI) = 0;
    virtual HRESULT __stdcall put_URI(BSTR uri) = 0;
    virtual HRESULT __stdcall get_SecurityDescriptor(VARIANT* pSecurityDescriptor) = 0;
    virtual HRESULT __stdcall put_SecurityDescriptor(VARIANT securityDescriptor) = 0;
};

class ITaskSettings : public IDispatch {
public:
    virtual HRESULT __stdcall get_AllowDemandStart(VARIANT_BOOL* pAllowDemandStart) = 0;
    virtual HRESULT __stdcall put_AllowDemandStart(VARIANT_BOOL allowDemandStart) = 0;
    virtual HRESULT __stdcall get_RestartInterval(BSTR* pRestartInterval) = 0;
    virtual HRESULT __stdcall put_RestartInterval(BSTR restartInterval) = 0;
    virtual HRESULT __stdcall get_RestartCount(INT* pRestartCount) = 0;
    virtual HRESULT __stdcall put_RestartCount(INT restartCount) = 0;
    virtual HRESULT __stdcall get_MultipleInstances(TASK_INSTANCES_POLICY* pMultipleInstances) = 0;
    virtual HRESULT __stdcall put_MultipleInstances(TASK_INSTANCES_POLICY multipleInstances) = 0;
    virtual HRESULT __stdcall get_StopIfGoingOnBatteries(VARIANT_BOOL* pStop) = 0;
    virtual HRESULT __stdcall put_StopIfGoingOnBatteries(VARIANT_BOOL stop) = 0;
    virtual HRESULT __stdcall get_DisallowStartIfOnBatteries(VARIANT_BOOL* pDisallow) = 0;
    virtual HRESULT __stdcall put_DisallowStartIfOnBatteries(VARIANT_BOOL disallow) = 0;
    virtual HRESULT __stdcall get_AllowHardTerminate(VARIANT_BOOL* pAllow) = 0;
    virtual HRESULT __stdcall put_AllowHardTerminate(VARIANT_BOOL allow) = 0;
    virtual HRESULT __stdcall get_StartWhenAvailable(VARIANT_BOOL* pStart) = 0;
    virtual HRESULT __stdcall put_StartWhenAvailable(VARIANT_BOOL start) = 0;
    virtual HRESULT __stdcall get_XmlText(BSTR* pXml) = 0;
    virtual HRESULT __stdcall put_XmlText(BSTR xml) = 0;
    virtual HRESULT __stdcall get_RunOnlyIfNetworkAvailable(VARIANT_BOOL* pRun) = 0;
    virtual HRESULT __stdcall put_RunOnlyIfNetworkAvailable(VARIANT_BOOL run) = 0;
    virtual HRESULT __stdcall get_ExecutionTimeLimit(BSTR* pExecutionTimeLimit) = 0;
    virtual HRESULT __stdcall put_ExecutionTimeLimit(BSTR executionTimeLimit) = 0;
    virtual HRESULT __stdcall get_Enabled(VARIANT_BOOL* pEnabled) = 0;
    virtual HRESULT __stdcall put_Enabled(VARIANT_BOOL enabled) = 0;
    virtual HRESULT __stdcall get_DeleteExpiredTaskAfter(BSTR* pDeleteExpired) = 0;
    virtual HRESULT __stdcall put_DeleteExpiredTaskAfter(BSTR deleteExpired) = 0;
    virtual HRESULT __stdcall get_Hidden(VARIANT_BOOL* pHidden) = 0;
    virtual HRESULT __stdcall put_Hidden(VARIANT_BOOL hidden) = 0;
};

class ITaskDefinition : public IDispatch {
public:
    virtual HRESULT __stdcall get_RegistrationInfo(IRegistrationInfo** ppRegistrationInfo) = 0;
    virtual HRESULT __stdcall put_RegistrationInfo(IRegistrationInfo* pRegistrationInfo) = 0;
    virtual HRESULT __stdcall get_Triggers(ITriggerCollection** ppTriggers) = 0;
    virtual HRESULT __stdcall put_Triggers(ITriggerCollection* pTriggers) = 0;
    virtual HRESULT __stdcall get_Settings(ITaskSettings** ppSettings) = 0;
    virtual HRESULT __stdcall put_Settings(ITaskSettings* pSettings) = 0;
    virtual HRESULT __stdcall get_Data(BSTR* pData) = 0;
    virtual HRESULT __stdcall put_Data(BSTR data) = 0;
    virtual HRESULT __stdcall get_Principal(IPrincipal** ppPrincipal) = 0;
    virtual HRESULT __stdcall put_Principal(IPrincipal* pPrincipal) = 0;
    virtual HRESULT __stdcall get_Actions(IActionCollection** ppActions) = 0;
    virtual HRESULT __stdcall put_Actions(IActionCollection* pActions) = 0;
    virtual HRESULT __stdcall get_XmlText(BSTR* pXml) = 0;
    virtual HRESULT __stdcall put_XmlText(BSTR xml) = 0;
};

class IRunningTask : public IDispatch {
public:
    virtual HRESULT __stdcall get_Name(BSTR* pName) = 0;
    virtual HRESULT __stdcall get_InstanceGuid(BSTR* pGuid) = 0;
    virtual HRESULT __stdcall get_Path(BSTR* pPath) = 0;
    virtual HRESULT __stdcall get_State(TASK_STATE* pState) = 0;
    virtual HRESULT __stdcall get_CurrentAction(BSTR* pName) = 0;
    virtual HRESULT __stdcall Stop() = 0;
    virtual HRESULT __stdcall Refresh() = 0;
    virtual HRESULT __stdcall get_EnginePID(DWORD* pPID) = 0;
};

class IRunningTaskCollection : public IDispatch {
public:
    virtual HRESULT __stdcall get_Count(LONG* pCount) = 0;
    virtual HRESULT __stdcall get_Item(VARIANT index, IRunningTask** ppRunningTask) = 0;
    virtual HRESULT __stdcall get__NewEnum(IUnknown** ppEnum) = 0;
};

class IRegisteredTask : public IDispatch {
public:
    virtual HRESULT __stdcall get_Name(BSTR* pName) = 0;
    virtual HRESULT __stdcall get_Path(BSTR* pPath) = 0;
    virtual HRESULT __stdcall get_State(TASK_STATE* pState) = 0;
    virtual HRESULT __stdcall get_Enabled(VARIANT_BOOL* pEnabled) = 0;
    virtual HRESULT __stdcall put_Enabled(VARIANT_BOOL enabled) = 0;
    virtual HRESULT __stdcall Run(VARIANT params, IRunningTask** ppRunningTask) = 0;
    virtual HRESULT __stdcall RunEx(VARIANT params, LONG flags, LONG sessionID, BSTR user, IRunningTask** ppRunningTask) = 0;
    virtual HRESULT __stdcall GetInstances(LONG flags, IRunningTaskCollection** ppInstances) = 0;
    virtual HRESULT __stdcall get_LastRunTime(DATE* pLastRunTime) = 0;
    virtual HRESULT __stdcall get_LastTaskResult(LONG* pLastTaskResult) = 0;
    virtual HRESULT __stdcall get_NumberOfMissedRuns(LONG* pNumberOfMissedRuns) = 0;
    virtual HRESULT __stdcall get_NextRunTime(DATE* pNextRunTime) = 0;
    virtual HRESULT __stdcall get_Definition(ITaskDefinition** ppDefinition) = 0;
    virtual HRESULT __stdcall get_Xml(BSTR* pXml) = 0;
    virtual HRESULT __stdcall GetSecurityDescriptor(LONG securityInformation, BSTR* pSddl) = 0;
    virtual HRESULT __stdcall SetSecurityDescriptor(BSTR sddl, LONG flags) = 0;
    virtual HRESULT __stdcall Stop(LONG flags) = 0;
};

class IRegisteredTaskCollection : public IDispatch {
public:
    virtual HRESULT __stdcall get_Count(LONG* pCount) = 0;
    virtual HRESULT __stdcall get_Item(VARIANT index, IRegisteredTask** ppRegisteredTask) = 0;
    virtual HRESULT __stdcall get__NewEnum(IUnknown** ppEnum) = 0;
};

class ITaskFolder : public IDispatch {
public:
    virtual HRESULT __stdcall get_Name(BSTR* pName) = 0;
    virtual HRESULT __stdcall get_Path(BSTR* pPath) = 0;
    virtual HRESULT __stdcall GetFolder(BSTR path, ITaskFolder** ppFolder) = 0;
    virtual HRESULT __stdcall GetFolders(LONG flags, ITaskFolderCollection** ppFolders) = 0;
    virtual HRESULT __stdcall CreateFolder(BSTR subFolderName, VARIANT sddl, ITaskFolder** ppFolder) = 0;
    virtual HRESULT __stdcall DeleteFolder(BSTR subFolderName, LONG flags) = 0;
    virtual HRESULT __stdcall GetTask(BSTR path, IRegisteredTask** ppTask) = 0;
    virtual HRESULT __stdcall GetTasks(LONG flags, IRegisteredTaskCollection** ppTasks) = 0;
    virtual HRESULT __stdcall DeleteTask(BSTR name, LONG flags) = 0;
    virtual HRESULT __stdcall RegisterTask(BSTR path, BSTR xmlText, LONG flags, VARIANT userId, VARIANT password, TASK_LOGON_TYPE logonType, VARIANT sddl, IRegisteredTask** ppTask) = 0;
    virtual HRESULT __stdcall RegisterTaskDefinition(BSTR path, ITaskDefinition* pDefinition, LONG flags, VARIANT userId, VARIANT password, TASK_LOGON_TYPE logonType, VARIANT sddl, IRegisteredTask** ppTask) = 0;
    virtual HRESULT __stdcall GetSecurityDescriptor(LONG securityInformation, BSTR* pSddl) = 0;
    virtual HRESULT __stdcall SetSecurityDescriptor(BSTR sddl, LONG flags) = 0;
};

class ITaskFolderCollection : public IDispatch {
public:
    virtual HRESULT __stdcall get_Count(LONG* pCount) = 0;
    virtual HRESULT __stdcall get_Item(VARIANT index, ITaskFolder** ppFolder) = 0;
    virtual HRESULT __stdcall get__NewEnum(IUnknown** ppEnum) = 0;
};

class ITaskService : public IDispatch {
public:
    virtual HRESULT __stdcall GetFolder(BSTR path, ITaskFolder** ppFolder) = 0;
    virtual HRESULT __stdcall GetRunningTasks(LONG flags, IRunningTaskCollection** ppRunningTasks) = 0;
    virtual HRESULT __stdcall NewTask(DWORD flags, ITaskDefinition** ppDefinition) = 0;
    virtual HRESULT __stdcall Connect(VARIANT serverName, VARIANT user, VARIANT domain, VARIANT password) = 0;
    virtual HRESULT __stdcall get_Connected(VARIANT_BOOL* pConnected) = 0;
    virtual HRESULT __stdcall get_TargetServer(BSTR* pServer) = 0;
    virtual HRESULT __stdcall get_ConnectedUser(BSTR* pUser) = 0;
    virtual HRESULT __stdcall get_ConnectedDomain(BSTR* pDomain) = 0;
    virtual HRESULT __stdcall get_HighestVersion(DWORD* pVersion) = 0;
};

// ============================================================================
// 3. DispatchImpl Template & Concrete Implementations
// ============================================================================

template <typename Interface>
class DispatchImpl : public Interface {
protected:
    std::atomic<uint32_t> m_refCount{1};

public:
    virtual ~DispatchImpl() = default;

    virtual uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t __stdcall Release() override {
        uint32_t cnt = m_refCount.fetch_sub(1) - 1;
        if (cnt == 0) {
            delete this;
        }
        return cnt;
    }

    virtual HRESULT __stdcall GetTypeInfoCount(uint32_t* pctinfo) override {
        if (pctinfo) *pctinfo = 0;
        return S_OK;
    }

    virtual HRESULT __stdcall GetTypeInfo(uint32_t /*iTInfo*/, LCID /*lcid*/, ole32::ITypeInfo** ppTInfo) override {
        if (ppTInfo) *ppTInfo = nullptr;
        return E_NOTIMPL;
    }

    virtual HRESULT __stdcall GetIDsOfNames(REFIID /*riid*/, LPOLESTR* /*rgszNames*/, uint32_t /*cNames*/, LCID /*lcid*/, DISPID* /*rgDispId*/) override {
        return E_NOTIMPL;
    }

    virtual HRESULT __stdcall Invoke(DISPID /*dispIdMember*/, REFIID /*riid*/, LCID /*lcid*/, uint16_t /*wFlags*/, DISPPARAMS* /*pDispParams*/, VARIANT* /*pVarResult*/, EXCEPINFO* /*pExcepInfo*/, uint32_t* /*puArgErr*/) override {
        return E_NOTIMPL;
    }
};

// ----------------------------------------------------------------------------
// TaskRepetitionPattern
// ----------------------------------------------------------------------------
class TaskRepetitionPattern : public DispatchImpl<IRepetitionPattern> {
public:
    std::wstring m_interval;
    std::wstring m_duration;
    VARIANT_BOOL m_stopAtDurationEnd{VARIANT_FALSE};

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IRepetitionPattern) {
            *ppv = static_cast<IRepetitionPattern*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Interval(BSTR* pInterval) override {
        if (!pInterval) return E_POINTER;
        *pInterval = SysAllocString(m_interval.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Interval(BSTR interval) override {
        m_interval = interval ? interval : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_Duration(BSTR* pDuration) override {
        if (!pDuration) return E_POINTER;
        *pDuration = SysAllocString(m_duration.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Duration(BSTR duration) override {
        m_duration = duration ? duration : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_StopAtDurationEnd(VARIANT_BOOL* pStop) override {
        if (!pStop) return E_POINTER;
        *pStop = m_stopAtDurationEnd;
        return S_OK;
    }
    virtual HRESULT __stdcall put_StopAtDurationEnd(VARIANT_BOOL stop) override {
        m_stopAtDurationEnd = stop;
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// Trigger Implementations (Time, Daily, Boot, Logon)
// ----------------------------------------------------------------------------

class TaskTimeTrigger : public DispatchImpl<ITimeTrigger> {
public:
    TASK_TRIGGER_TYPE2 m_type{TASK_TRIGGER_TIME};
    std::wstring m_id;
    std::wstring m_startBoundary;
    std::wstring m_endBoundary;
    std::wstring m_limit;
    std::wstring m_randomDelay;
    VARIANT_BOOL m_enabled{VARIANT_TRUE};
    std::shared_ptr<TaskRepetitionPattern> m_repetition;

    TaskTimeTrigger() : m_repetition(std::make_shared<TaskRepetitionPattern>()) {}

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_ITrigger || riid == IID_ITimeTrigger) {
            *ppv = static_cast<ITimeTrigger*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    // ITrigger
    virtual HRESULT __stdcall get_Type(TASK_TRIGGER_TYPE2* pType) override { if (!pType) return E_POINTER; *pType = m_type; return S_OK; }
    virtual HRESULT __stdcall get_Id(BSTR* pId) override { if (!pId) return E_POINTER; *pId = SysAllocString(m_id.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_Id(BSTR id) override { m_id = id ? id : L""; return S_OK; }
    virtual HRESULT __stdcall get_Repetition(IRepetitionPattern** ppRepetition) override {
        if (!ppRepetition) return E_POINTER;
        *ppRepetition = m_repetition.get();
        m_repetition->AddRef();
        return S_OK;
    }
    virtual HRESULT __stdcall put_Repetition(IRepetitionPattern*) override { return S_OK; }
    virtual HRESULT __stdcall get_ExecutionTimeLimit(BSTR* pLimit) override { if (!pLimit) return E_POINTER; *pLimit = SysAllocString(m_limit.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_ExecutionTimeLimit(BSTR limit) override { m_limit = limit ? limit : L""; return S_OK; }
    virtual HRESULT __stdcall get_StartBoundary(BSTR* pStart) override { if (!pStart) return E_POINTER; *pStart = SysAllocString(m_startBoundary.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_StartBoundary(BSTR start) override { m_startBoundary = start ? start : L""; return S_OK; }
    virtual HRESULT __stdcall get_EndBoundary(BSTR* pEnd) override { if (!pEnd) return E_POINTER; *pEnd = SysAllocString(m_endBoundary.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_EndBoundary(BSTR end) override { m_endBoundary = end ? end : L""; return S_OK; }
    virtual HRESULT __stdcall get_Enabled(VARIANT_BOOL* pEnabled) override { if (!pEnabled) return E_POINTER; *pEnabled = m_enabled; return S_OK; }
    virtual HRESULT __stdcall put_Enabled(VARIANT_BOOL enabled) override { m_enabled = enabled; return S_OK; }

    // ITimeTrigger
    virtual HRESULT __stdcall get_RandomDelay(BSTR* pRandomDelay) override { if (!pRandomDelay) return E_POINTER; *pRandomDelay = SysAllocString(m_randomDelay.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_RandomDelay(BSTR randomDelay) override { m_randomDelay = randomDelay ? randomDelay : L""; return S_OK; }
};

class TaskDailyTrigger : public DispatchImpl<IDailyTrigger> {
public:
    TASK_TRIGGER_TYPE2 m_type{TASK_TRIGGER_DAILY};
    std::wstring m_id;
    std::wstring m_startBoundary;
    std::wstring m_endBoundary;
    std::wstring m_limit;
    std::wstring m_randomDelay;
    short m_daysInterval{1};
    VARIANT_BOOL m_enabled{VARIANT_TRUE};
    std::shared_ptr<TaskRepetitionPattern> m_repetition;

    TaskDailyTrigger() : m_repetition(std::make_shared<TaskRepetitionPattern>()) {}

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_ITrigger || riid == IID_IDailyTrigger) {
            *ppv = static_cast<IDailyTrigger*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    // ITrigger
    virtual HRESULT __stdcall get_Type(TASK_TRIGGER_TYPE2* pType) override { if (!pType) return E_POINTER; *pType = m_type; return S_OK; }
    virtual HRESULT __stdcall get_Id(BSTR* pId) override { if (!pId) return E_POINTER; *pId = SysAllocString(m_id.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_Id(BSTR id) override { m_id = id ? id : L""; return S_OK; }
    virtual HRESULT __stdcall get_Repetition(IRepetitionPattern** ppRepetition) override {
        if (!ppRepetition) return E_POINTER;
        *ppRepetition = m_repetition.get();
        m_repetition->AddRef();
        return S_OK;
    }
    virtual HRESULT __stdcall put_Repetition(IRepetitionPattern*) override { return S_OK; }
    virtual HRESULT __stdcall get_ExecutionTimeLimit(BSTR* pLimit) override { if (!pLimit) return E_POINTER; *pLimit = SysAllocString(m_limit.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_ExecutionTimeLimit(BSTR limit) override { m_limit = limit ? limit : L""; return S_OK; }
    virtual HRESULT __stdcall get_StartBoundary(BSTR* pStart) override { if (!pStart) return E_POINTER; *pStart = SysAllocString(m_startBoundary.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_StartBoundary(BSTR start) override { m_startBoundary = start ? start : L""; return S_OK; }
    virtual HRESULT __stdcall get_EndBoundary(BSTR* pEnd) override { if (!pEnd) return E_POINTER; *pEnd = SysAllocString(m_endBoundary.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_EndBoundary(BSTR end) override { m_endBoundary = end ? end : L""; return S_OK; }
    virtual HRESULT __stdcall get_Enabled(VARIANT_BOOL* pEnabled) override { if (!pEnabled) return E_POINTER; *pEnabled = m_enabled; return S_OK; }
    virtual HRESULT __stdcall put_Enabled(VARIANT_BOOL enabled) override { m_enabled = enabled; return S_OK; }

    // IDailyTrigger
    virtual HRESULT __stdcall get_DaysInterval(short* pDays) override { if (!pDays) return E_POINTER; *pDays = m_daysInterval; return S_OK; }
    virtual HRESULT __stdcall put_DaysInterval(short days) override { m_daysInterval = days; return S_OK; }
    virtual HRESULT __stdcall get_RandomDelay(BSTR* pRandomDelay) override { if (!pRandomDelay) return E_POINTER; *pRandomDelay = SysAllocString(m_randomDelay.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_RandomDelay(BSTR randomDelay) override { m_randomDelay = randomDelay ? randomDelay : L""; return S_OK; }
};

class TaskBootTrigger : public DispatchImpl<IBootTrigger> {
public:
    TASK_TRIGGER_TYPE2 m_type{TASK_TRIGGER_BOOT};
    std::wstring m_id;
    std::wstring m_startBoundary;
    std::wstring m_endBoundary;
    std::wstring m_limit;
    std::wstring m_delay;
    VARIANT_BOOL m_enabled{VARIANT_TRUE};
    std::shared_ptr<TaskRepetitionPattern> m_repetition;

    TaskBootTrigger() : m_repetition(std::make_shared<TaskRepetitionPattern>()) {}

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_ITrigger || riid == IID_IBootTrigger) {
            *ppv = static_cast<IBootTrigger*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    // ITrigger
    virtual HRESULT __stdcall get_Type(TASK_TRIGGER_TYPE2* pType) override { if (!pType) return E_POINTER; *pType = m_type; return S_OK; }
    virtual HRESULT __stdcall get_Id(BSTR* pId) override { if (!pId) return E_POINTER; *pId = SysAllocString(m_id.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_Id(BSTR id) override { m_id = id ? id : L""; return S_OK; }
    virtual HRESULT __stdcall get_Repetition(IRepetitionPattern** ppRepetition) override {
        if (!ppRepetition) return E_POINTER;
        *ppRepetition = m_repetition.get();
        m_repetition->AddRef();
        return S_OK;
    }
    virtual HRESULT __stdcall put_Repetition(IRepetitionPattern*) override { return S_OK; }
    virtual HRESULT __stdcall get_ExecutionTimeLimit(BSTR* pLimit) override { if (!pLimit) return E_POINTER; *pLimit = SysAllocString(m_limit.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_ExecutionTimeLimit(BSTR limit) override { m_limit = limit ? limit : L""; return S_OK; }
    virtual HRESULT __stdcall get_StartBoundary(BSTR* pStart) override { if (!pStart) return E_POINTER; *pStart = SysAllocString(m_startBoundary.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_StartBoundary(BSTR start) override { m_startBoundary = start ? start : L""; return S_OK; }
    virtual HRESULT __stdcall get_EndBoundary(BSTR* pEnd) override { if (!pEnd) return E_POINTER; *pEnd = SysAllocString(m_endBoundary.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_EndBoundary(BSTR end) override { m_endBoundary = end ? end : L""; return S_OK; }
    virtual HRESULT __stdcall get_Enabled(VARIANT_BOOL* pEnabled) override { if (!pEnabled) return E_POINTER; *pEnabled = m_enabled; return S_OK; }
    virtual HRESULT __stdcall put_Enabled(VARIANT_BOOL enabled) override { m_enabled = enabled; return S_OK; }

    // IBootTrigger
    virtual HRESULT __stdcall get_Delay(BSTR* pDelay) override { if (!pDelay) return E_POINTER; *pDelay = SysAllocString(m_delay.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_Delay(BSTR delay) override { m_delay = delay ? delay : L""; return S_OK; }
};

class TaskLogonTrigger : public DispatchImpl<ILogonTrigger> {
public:
    TASK_TRIGGER_TYPE2 m_type{TASK_TRIGGER_LOGON};
    std::wstring m_id;
    std::wstring m_startBoundary;
    std::wstring m_endBoundary;
    std::wstring m_limit;
    std::wstring m_delay;
    std::wstring m_userId;
    VARIANT_BOOL m_enabled{VARIANT_TRUE};
    std::shared_ptr<TaskRepetitionPattern> m_repetition;

    TaskLogonTrigger() : m_repetition(std::make_shared<TaskRepetitionPattern>()) {}

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_ITrigger || riid == IID_ILogonTrigger) {
            *ppv = static_cast<ILogonTrigger*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    // ITrigger
    virtual HRESULT __stdcall get_Type(TASK_TRIGGER_TYPE2* pType) override { if (!pType) return E_POINTER; *pType = m_type; return S_OK; }
    virtual HRESULT __stdcall get_Id(BSTR* pId) override { if (!pId) return E_POINTER; *pId = SysAllocString(m_id.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_Id(BSTR id) override { m_id = id ? id : L""; return S_OK; }
    virtual HRESULT __stdcall get_Repetition(IRepetitionPattern** ppRepetition) override {
        if (!ppRepetition) return E_POINTER;
        *ppRepetition = m_repetition.get();
        m_repetition->AddRef();
        return S_OK;
    }
    virtual HRESULT __stdcall put_Repetition(IRepetitionPattern*) override { return S_OK; }
    virtual HRESULT __stdcall get_ExecutionTimeLimit(BSTR* pLimit) override { if (!pLimit) return E_POINTER; *pLimit = SysAllocString(m_limit.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_ExecutionTimeLimit(BSTR limit) override { m_limit = limit ? limit : L""; return S_OK; }
    virtual HRESULT __stdcall get_StartBoundary(BSTR* pStart) override { if (!pStart) return E_POINTER; *pStart = SysAllocString(m_startBoundary.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_StartBoundary(BSTR start) override { m_startBoundary = start ? start : L""; return S_OK; }
    virtual HRESULT __stdcall get_EndBoundary(BSTR* pEnd) override { if (!pEnd) return E_POINTER; *pEnd = SysAllocString(m_endBoundary.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_EndBoundary(BSTR end) override { m_endBoundary = end ? end : L""; return S_OK; }
    virtual HRESULT __stdcall get_Enabled(VARIANT_BOOL* pEnabled) override { if (!pEnabled) return E_POINTER; *pEnabled = m_enabled; return S_OK; }
    virtual HRESULT __stdcall put_Enabled(VARIANT_BOOL enabled) override { m_enabled = enabled; return S_OK; }

    // ILogonTrigger
    virtual HRESULT __stdcall get_Delay(BSTR* pDelay) override { if (!pDelay) return E_POINTER; *pDelay = SysAllocString(m_delay.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_Delay(BSTR delay) override { m_delay = delay ? delay : L""; return S_OK; }
    virtual HRESULT __stdcall get_UserId(BSTR* pUser) override { if (!pUser) return E_POINTER; *pUser = SysAllocString(m_userId.c_str()); return S_OK; }
    virtual HRESULT __stdcall put_UserId(BSTR user) override { m_userId = user ? user : L""; return S_OK; }
};

// ----------------------------------------------------------------------------
// TaskTriggerCollection
// ----------------------------------------------------------------------------
class TaskTriggerCollection : public DispatchImpl<ITriggerCollection> {
public:
    std::vector<std::shared_ptr<ITrigger>> m_items;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_ITriggerCollection) {
            *ppv = static_cast<ITriggerCollection*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Count(LONG* pCount) override {
        if (!pCount) return E_POINTER;
        *pCount = static_cast<LONG>(m_items.size());
        return S_OK;
    }

    virtual HRESULT __stdcall get_Item(LONG index, ITrigger** ppTrigger) override {
        if (!ppTrigger) return E_POINTER;
        *ppTrigger = nullptr;
        if (index < 1 || static_cast<size_t>(index) > m_items.size()) {
            return E_INVALIDARG;
        }
        auto trigger = m_items[static_cast<size_t>(index - 1)];
        *ppTrigger = trigger.get();
        trigger->AddRef();
        return S_OK;
    }

    virtual HRESULT __stdcall get__NewEnum(IUnknown** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        *ppEnum = nullptr;
        return E_NOTIMPL;
    }

    virtual HRESULT __stdcall Create(TASK_TRIGGER_TYPE2 type, ITrigger** ppTrigger) override {
        if (!ppTrigger) return E_POINTER;
        std::shared_ptr<ITrigger> trig;
        if (type == TASK_TRIGGER_DAILY) {
            trig = std::make_shared<TaskDailyTrigger>();
        } else if (type == TASK_TRIGGER_BOOT) {
            trig = std::make_shared<TaskBootTrigger>();
        } else if (type == TASK_TRIGGER_LOGON) {
            trig = std::make_shared<TaskLogonTrigger>();
        } else {
            trig = std::make_shared<TaskTimeTrigger>();
        }
        m_items.push_back(trig);
        *ppTrigger = trig.get();
        trig->AddRef();
        return S_OK;
    }

    virtual HRESULT __stdcall Remove(VARIANT index) override {
        if (index.vt == VT_I4 && index.lVal >= 1 && static_cast<size_t>(index.lVal) <= m_items.size()) {
            m_items.erase(m_items.begin() + (index.lVal - 1));
            return S_OK;
        }
        return E_INVALIDARG;
    }

    virtual HRESULT __stdcall Clear() override {
        m_items.clear();
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// TaskExecAction
// ----------------------------------------------------------------------------
class TaskExecAction : public DispatchImpl<IExecAction> {
public:
    std::wstring m_id;
    std::wstring m_path;
    std::wstring m_arguments;
    std::wstring m_workingDirectory;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IAction || riid == IID_IExecAction) {
            *ppv = static_cast<IExecAction*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Id(BSTR* pId) override {
        if (!pId) return E_POINTER;
        *pId = SysAllocString(m_id.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Id(BSTR id) override {
        m_id = id ? id : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_Type(TASK_ACTION_TYPE* pType) override {
        if (!pType) return E_POINTER;
        *pType = TASK_ACTION_EXEC;
        return S_OK;
    }
    virtual HRESULT __stdcall get_Path(BSTR* pPath) override {
        if (!pPath) return E_POINTER;
        *pPath = SysAllocString(m_path.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Path(BSTR path) override {
        m_path = path ? path : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_Arguments(BSTR* pArguments) override {
        if (!pArguments) return E_POINTER;
        *pArguments = SysAllocString(m_arguments.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Arguments(BSTR arguments) override {
        m_arguments = arguments ? arguments : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_WorkingDirectory(BSTR* pWorkingDirectory) override {
        if (!pWorkingDirectory) return E_POINTER;
        *pWorkingDirectory = SysAllocString(m_workingDirectory.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_WorkingDirectory(BSTR workingDirectory) override {
        m_workingDirectory = workingDirectory ? workingDirectory : L"";
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// TaskActionCollection
// ----------------------------------------------------------------------------
class TaskActionCollection : public DispatchImpl<IActionCollection> {
public:
    std::vector<std::shared_ptr<TaskExecAction>> m_items;
    std::wstring m_context;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IActionCollection) {
            *ppv = static_cast<IActionCollection*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Count(LONG* pCount) override {
        if (!pCount) return E_POINTER;
        *pCount = static_cast<LONG>(m_items.size());
        return S_OK;
    }

    virtual HRESULT __stdcall get_Item(LONG index, IAction** ppAction) override {
        if (!ppAction) return E_POINTER;
        *ppAction = nullptr;
        if (index < 1 || static_cast<size_t>(index) > m_items.size()) {
            return E_INVALIDARG;
        }
        auto act = m_items[static_cast<size_t>(index - 1)];
        *ppAction = static_cast<IExecAction*>(act.get());
        act->AddRef();
        return S_OK;
    }

    virtual HRESULT __stdcall get__NewEnum(IUnknown** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        *ppEnum = nullptr;
        return E_NOTIMPL;
    }

    virtual HRESULT __stdcall get_XmlText(BSTR* pXml) override {
        if (!pXml) return E_POINTER;
        *pXml = SysAllocString(L"<Actions/>");
        return S_OK;
    }

    virtual HRESULT __stdcall put_XmlText(BSTR /*xml*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall Create(TASK_ACTION_TYPE type, IAction** ppAction) override {
        if (!ppAction) return E_POINTER;
        if (type != TASK_ACTION_EXEC) {
            return E_NOTIMPL;
        }
        auto act = std::make_shared<TaskExecAction>();
        m_items.push_back(act);
        *ppAction = static_cast<IExecAction*>(act.get());
        act->AddRef();
        return S_OK;
    }

    virtual HRESULT __stdcall Remove(VARIANT index) override {
        if (index.vt == VT_I4 && index.lVal >= 1 && static_cast<size_t>(index.lVal) <= m_items.size()) {
            m_items.erase(m_items.begin() + (index.lVal - 1));
            return S_OK;
        }
        return E_INVALIDARG;
    }

    virtual HRESULT __stdcall Clear() override {
        m_items.clear();
        return S_OK;
    }

    virtual HRESULT __stdcall get_Context(BSTR* pContext) override {
        if (!pContext) return E_POINTER;
        *pContext = SysAllocString(m_context.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall put_Context(BSTR context) override {
        m_context = context ? context : L"";
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// TaskPrincipal
// ----------------------------------------------------------------------------
class TaskPrincipal : public DispatchImpl<IPrincipal> {
public:
    std::wstring m_id;
    std::wstring m_displayName;
    std::wstring m_userId{L"SYSTEM"};
    std::wstring m_groupId;
    TASK_LOGON_TYPE m_logonType{TASK_LOGON_INTERACTIVE_TOKEN};
    LONG m_runLevel{0};

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IPrincipal) {
            *ppv = static_cast<IPrincipal*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Id(BSTR* pId) override {
        if (!pId) return E_POINTER;
        *pId = SysAllocString(m_id.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Id(BSTR id) override {
        m_id = id ? id : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_DisplayName(BSTR* pDisplayName) override {
        if (!pDisplayName) return E_POINTER;
        *pDisplayName = SysAllocString(m_displayName.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_DisplayName(BSTR displayName) override {
        m_displayName = displayName ? displayName : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_UserId(BSTR* pUserId) override {
        if (!pUserId) return E_POINTER;
        *pUserId = SysAllocString(m_userId.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_UserId(BSTR userId) override {
        m_userId = userId ? userId : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_LogonType(TASK_LOGON_TYPE* pLogonType) override {
        if (!pLogonType) return E_POINTER;
        *pLogonType = m_logonType;
        return S_OK;
    }
    virtual HRESULT __stdcall put_LogonType(TASK_LOGON_TYPE logonType) override {
        m_logonType = logonType;
        return S_OK;
    }
    virtual HRESULT __stdcall get_GroupId(BSTR* pGroupId) override {
        if (!pGroupId) return E_POINTER;
        *pGroupId = SysAllocString(m_groupId.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_GroupId(BSTR groupId) override {
        m_groupId = groupId ? groupId : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_RunLevel(LONG* pRunLevel) override {
        if (!pRunLevel) return E_POINTER;
        *pRunLevel = m_runLevel;
        return S_OK;
    }
    virtual HRESULT __stdcall put_RunLevel(LONG runLevel) override {
        m_runLevel = runLevel;
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// TaskRegistrationInfo
// ----------------------------------------------------------------------------
class TaskRegistrationInfo : public DispatchImpl<IRegistrationInfo> {
public:
    std::wstring m_author{L"Microsoft Corporation"};
    std::wstring m_description;
    std::wstring m_version{L"1.0"};
    std::wstring m_date;
    std::wstring m_uri;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IRegistrationInfo) {
            *ppv = static_cast<IRegistrationInfo*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Description(BSTR* pDescription) override {
        if (!pDescription) return E_POINTER;
        *pDescription = SysAllocString(m_description.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Description(BSTR description) override {
        m_description = description ? description : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_Author(BSTR* pAuthor) override {
        if (!pAuthor) return E_POINTER;
        *pAuthor = SysAllocString(m_author.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Author(BSTR author) override {
        m_author = author ? author : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_Version(BSTR* pVersion) override {
        if (!pVersion) return E_POINTER;
        *pVersion = SysAllocString(m_version.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Version(BSTR version) override {
        m_version = version ? version : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_Date(BSTR* pDate) override {
        if (!pDate) return E_POINTER;
        *pDate = SysAllocString(m_date.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Date(BSTR date) override {
        m_date = date ? date : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_URI(BSTR* pURI) override {
        if (!pURI) return E_POINTER;
        *pURI = SysAllocString(m_uri.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_URI(BSTR uri) override {
        m_uri = uri ? uri : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_SecurityDescriptor(VARIANT* pSecurityDescriptor) override {
        if (!pSecurityDescriptor) return E_POINTER;
        pSecurityDescriptor->vt = VT_EMPTY;
        return S_OK;
    }
    virtual HRESULT __stdcall put_SecurityDescriptor(VARIANT /*securityDescriptor*/) override {
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// TaskSettings
// ----------------------------------------------------------------------------
class TaskSettings : public DispatchImpl<ITaskSettings> {
public:
    VARIANT_BOOL m_allowDemandStart{VARIANT_TRUE};
    std::wstring m_restartInterval;
    INT m_restartCount{0};
    TASK_INSTANCES_POLICY m_multipleInstances{TASK_INSTANCES_IGNORE_NEW};
    VARIANT_BOOL m_stopIfGoingOnBatteries{VARIANT_TRUE};
    VARIANT_BOOL m_disallowStartIfOnBatteries{VARIANT_TRUE};
    VARIANT_BOOL m_allowHardTerminate{VARIANT_TRUE};
    VARIANT_BOOL m_startWhenAvailable{VARIANT_FALSE};
    VARIANT_BOOL m_runOnlyIfNetworkAvailable{VARIANT_FALSE};
    std::wstring m_executionTimeLimit{L"PT72H"};
    VARIANT_BOOL m_enabled{VARIANT_TRUE};
    std::wstring m_deleteExpiredTaskAfter;
    VARIANT_BOOL m_hidden{VARIANT_FALSE};

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_ITaskSettings) {
            *ppv = static_cast<ITaskSettings*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_AllowDemandStart(VARIANT_BOOL* pAllowDemandStart) override {
        if (!pAllowDemandStart) return E_POINTER;
        *pAllowDemandStart = m_allowDemandStart;
        return S_OK;
    }
    virtual HRESULT __stdcall put_AllowDemandStart(VARIANT_BOOL allowDemandStart) override {
        m_allowDemandStart = allowDemandStart;
        return S_OK;
    }
    virtual HRESULT __stdcall get_RestartInterval(BSTR* pRestartInterval) override {
        if (!pRestartInterval) return E_POINTER;
        *pRestartInterval = SysAllocString(m_restartInterval.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_RestartInterval(BSTR restartInterval) override {
        m_restartInterval = restartInterval ? restartInterval : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_RestartCount(INT* pRestartCount) override {
        if (!pRestartCount) return E_POINTER;
        *pRestartCount = m_restartCount;
        return S_OK;
    }
    virtual HRESULT __stdcall put_RestartCount(INT restartCount) override {
        m_restartCount = restartCount;
        return S_OK;
    }
    virtual HRESULT __stdcall get_MultipleInstances(TASK_INSTANCES_POLICY* pMultipleInstances) override {
        if (!pMultipleInstances) return E_POINTER;
        *pMultipleInstances = m_multipleInstances;
        return S_OK;
    }
    virtual HRESULT __stdcall put_MultipleInstances(TASK_INSTANCES_POLICY multipleInstances) override {
        m_multipleInstances = multipleInstances;
        return S_OK;
    }
    virtual HRESULT __stdcall get_StopIfGoingOnBatteries(VARIANT_BOOL* pStop) override {
        if (!pStop) return E_POINTER;
        *pStop = m_stopIfGoingOnBatteries;
        return S_OK;
    }
    virtual HRESULT __stdcall put_StopIfGoingOnBatteries(VARIANT_BOOL stop) override {
        m_stopIfGoingOnBatteries = stop;
        return S_OK;
    }
    virtual HRESULT __stdcall get_DisallowStartIfOnBatteries(VARIANT_BOOL* pDisallow) override {
        if (!pDisallow) return E_POINTER;
        *pDisallow = m_disallowStartIfOnBatteries;
        return S_OK;
    }
    virtual HRESULT __stdcall put_DisallowStartIfOnBatteries(VARIANT_BOOL disallow) override {
        m_disallowStartIfOnBatteries = disallow;
        return S_OK;
    }
    virtual HRESULT __stdcall get_AllowHardTerminate(VARIANT_BOOL* pAllow) override {
        if (!pAllow) return E_POINTER;
        *pAllow = m_allowHardTerminate;
        return S_OK;
    }
    virtual HRESULT __stdcall put_AllowHardTerminate(VARIANT_BOOL allow) override {
        m_allowHardTerminate = allow;
        return S_OK;
    }
    virtual HRESULT __stdcall get_StartWhenAvailable(VARIANT_BOOL* pStart) override {
        if (!pStart) return E_POINTER;
        *pStart = m_startWhenAvailable;
        return S_OK;
    }
    virtual HRESULT __stdcall put_StartWhenAvailable(VARIANT_BOOL start) override {
        m_startWhenAvailable = start;
        return S_OK;
    }
    virtual HRESULT __stdcall get_XmlText(BSTR* pXml) override {
        if (!pXml) return E_POINTER;
        *pXml = SysAllocString(L"<Settings/>");
        return S_OK;
    }
    virtual HRESULT __stdcall put_XmlText(BSTR /*xml*/) override {
        return S_OK;
    }
    virtual HRESULT __stdcall get_RunOnlyIfNetworkAvailable(VARIANT_BOOL* pRun) override {
        if (!pRun) return E_POINTER;
        *pRun = m_runOnlyIfNetworkAvailable;
        return S_OK;
    }
    virtual HRESULT __stdcall put_RunOnlyIfNetworkAvailable(VARIANT_BOOL run) override {
        m_runOnlyIfNetworkAvailable = run;
        return S_OK;
    }
    virtual HRESULT __stdcall get_ExecutionTimeLimit(BSTR* pExecutionTimeLimit) override {
        if (!pExecutionTimeLimit) return E_POINTER;
        *pExecutionTimeLimit = SysAllocString(m_executionTimeLimit.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_ExecutionTimeLimit(BSTR executionTimeLimit) override {
        m_executionTimeLimit = executionTimeLimit ? executionTimeLimit : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_Enabled(VARIANT_BOOL* pEnabled) override {
        if (!pEnabled) return E_POINTER;
        *pEnabled = m_enabled;
        return S_OK;
    }
    virtual HRESULT __stdcall put_Enabled(VARIANT_BOOL enabled) override {
        m_enabled = enabled;
        return S_OK;
    }
    virtual HRESULT __stdcall get_DeleteExpiredTaskAfter(BSTR* pDeleteExpired) override {
        if (!pDeleteExpired) return E_POINTER;
        *pDeleteExpired = SysAllocString(m_deleteExpiredTaskAfter.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_DeleteExpiredTaskAfter(BSTR deleteExpired) override {
        m_deleteExpiredTaskAfter = deleteExpired ? deleteExpired : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_Hidden(VARIANT_BOOL* pHidden) override {
        if (!pHidden) return E_POINTER;
        *pHidden = m_hidden;
        return S_OK;
    }
    virtual HRESULT __stdcall put_Hidden(VARIANT_BOOL hidden) override {
        m_hidden = hidden;
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// TaskDefinition
// ----------------------------------------------------------------------------
class TaskDefinition : public DispatchImpl<ITaskDefinition> {
public:
    std::shared_ptr<TaskRegistrationInfo> m_regInfo;
    std::shared_ptr<TaskTriggerCollection> m_triggers;
    std::shared_ptr<TaskSettings> m_settings;
    std::shared_ptr<TaskPrincipal> m_principal;
    std::shared_ptr<TaskActionCollection> m_actions;
    std::wstring m_data;

    TaskDefinition() {
        m_regInfo = std::make_shared<TaskRegistrationInfo>();
        m_triggers = std::make_shared<TaskTriggerCollection>();
        m_settings = std::make_shared<TaskSettings>();
        m_principal = std::make_shared<TaskPrincipal>();
        m_actions = std::make_shared<TaskActionCollection>();
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_ITaskDefinition) {
            *ppv = static_cast<ITaskDefinition*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_RegistrationInfo(IRegistrationInfo** ppRegistrationInfo) override {
        if (!ppRegistrationInfo) return E_POINTER;
        *ppRegistrationInfo = m_regInfo.get();
        m_regInfo->AddRef();
        return S_OK;
    }
    virtual HRESULT __stdcall put_RegistrationInfo(IRegistrationInfo* /*pRegistrationInfo*/) override {
        return S_OK;
    }
    virtual HRESULT __stdcall get_Triggers(ITriggerCollection** ppTriggers) override {
        if (!ppTriggers) return E_POINTER;
        *ppTriggers = m_triggers.get();
        m_triggers->AddRef();
        return S_OK;
    }
    virtual HRESULT __stdcall put_Triggers(ITriggerCollection* /*pTriggers*/) override {
        return S_OK;
    }
    virtual HRESULT __stdcall get_Settings(ITaskSettings** ppSettings) override {
        if (!ppSettings) return E_POINTER;
        *ppSettings = m_settings.get();
        m_settings->AddRef();
        return S_OK;
    }
    virtual HRESULT __stdcall put_Settings(ITaskSettings* /*pSettings*/) override {
        return S_OK;
    }
    virtual HRESULT __stdcall get_Data(BSTR* pData) override {
        if (!pData) return E_POINTER;
        *pData = SysAllocString(m_data.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall put_Data(BSTR data) override {
        m_data = data ? data : L"";
        return S_OK;
    }
    virtual HRESULT __stdcall get_Principal(IPrincipal** ppPrincipal) override {
        if (!ppPrincipal) return E_POINTER;
        *ppPrincipal = m_principal.get();
        m_principal->AddRef();
        return S_OK;
    }
    virtual HRESULT __stdcall put_Principal(IPrincipal* /*pPrincipal*/) override {
        return S_OK;
    }
    virtual HRESULT __stdcall get_Actions(IActionCollection** ppActions) override {
        if (!ppActions) return E_POINTER;
        *ppActions = m_actions.get();
        m_actions->AddRef();
        return S_OK;
    }
    virtual HRESULT __stdcall put_Actions(IActionCollection* /*pActions*/) override {
        return S_OK;
    }

    std::wstring SerializeToXml() const {
        std::wstringstream wss;
        wss << L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
            << L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
            << L"  <RegistrationInfo>\n"
            << L"    <Author>" << m_regInfo->m_author << L"</Author>\n"
            << L"    <Description>" << m_regInfo->m_description << L"</Description>\n"
            << L"    <URI>" << m_regInfo->m_uri << L"</URI>\n"
            << L"  </RegistrationInfo>\n"
            << L"  <Triggers>\n";

        for (const auto& trig : m_triggers->m_items) {
            TASK_TRIGGER_TYPE2 ttype{};
            trig->get_Type(&ttype);
            VARIANT_BOOL bEnabled = VARIANT_TRUE;
            trig->get_Enabled(&bEnabled);

            if (ttype == TASK_TRIGGER_BOOT) {
                wss << L"    <BootTrigger>\n"
                    << L"      <Enabled>" << (bEnabled ? L"true" : L"false") << L"</Enabled>\n"
                    << L"    </BootTrigger>\n";
            } else if (ttype == TASK_TRIGGER_LOGON) {
                wss << L"    <LogonTrigger>\n"
                    << L"      <Enabled>" << (bEnabled ? L"true" : L"false") << L"</Enabled>\n"
                    << L"    </LogonTrigger>\n";
            } else if (ttype == TASK_TRIGGER_DAILY) {
                BSTR startB = nullptr;
                trig->get_StartBoundary(&startB);
                std::wstring sStart = startB ? startB : L"";
                if (startB) SysFreeString(startB);

                wss << L"    <CalendarTrigger>\n"
                    << L"      <StartBoundary>" << sStart << L"</StartBoundary>\n"
                    << L"      <Enabled>" << (bEnabled ? L"true" : L"false") << L"</Enabled>\n"
                    << L"    </CalendarTrigger>\n";
            } else {
                BSTR startB = nullptr;
                trig->get_StartBoundary(&startB);
                std::wstring sStart = startB ? startB : L"";
                if (startB) SysFreeString(startB);

                wss << L"    <TimeTrigger>\n"
                    << L"      <StartBoundary>" << sStart << L"</StartBoundary>\n"
                    << L"      <Enabled>" << (bEnabled ? L"true" : L"false") << L"</Enabled>\n"
                    << L"    </TimeTrigger>\n";
            }
        }

        wss << L"  </Triggers>\n"
            << L"  <Principals>\n"
            << L"    <Principal id=\"Author\">\n"
            << L"      <UserId>" << m_principal->m_userId << L"</UserId>\n"
            << L"      <LogonType>" << (m_principal->m_logonType == TASK_LOGON_INTERACTIVE_TOKEN ? L"InteractiveToken" : L"Password") << L"</LogonType>\n"
            << L"    </Principal>\n"
            << L"  </Principals>\n"
            << L"  <Settings>\n"
            << L"    <Enabled>" << (m_settings->m_enabled ? L"true" : L"false") << L"</Enabled>\n"
            << L"    <AllowDemandStart>" << (m_settings->m_allowDemandStart ? L"true" : L"false") << L"</AllowDemandStart>\n"
            << L"    <Hidden>" << (m_settings->m_hidden ? L"true" : L"false") << L"</Hidden>\n"
            << L"  </Settings>\n"
            << L"  <Actions Context=\"Author\">\n";

        for (const auto& act : m_actions->m_items) {
            wss << L"    <Exec>\n"
                << L"      <Command>" << act->m_path << L"</Command>\n";
            if (!act->m_arguments.empty()) {
                wss << L"      <Arguments>" << act->m_arguments << L"</Arguments>\n";
            }
            if (!act->m_workingDirectory.empty()) {
                wss << L"      <WorkingDirectory>" << act->m_workingDirectory << L"</WorkingDirectory>\n";
            }
            wss << L"    </Exec>\n";
        }

        wss << L"  </Actions>\n"
            << L"</Task>\n";
        return wss.str();
    }

    void DeserializeFromXml(std::wstring_view xml) {
        auto extractTag = [&](std::wstring_view openTag, std::wstring_view closeTag) -> std::wstring {
            size_t start = xml.find(openTag);
            if (start == std::wstring_view::npos) return L"";
            start += openTag.length();
            size_t end = xml.find(closeTag, start);
            if (end == std::wstring_view::npos) return L"";
            return std::wstring(xml.substr(start, end - start));
        };

        std::wstring author = extractTag(L"<Author>", L"</Author>");
        if (!author.empty()) m_regInfo->m_author = author;

        std::wstring desc = extractTag(L"<Description>", L"</Description>");
        if (!desc.empty()) m_regInfo->m_description = desc;

        std::wstring uri = extractTag(L"<URI>", L"</URI>");
        if (!uri.empty()) m_regInfo->m_uri = uri;

        std::wstring cmd = extractTag(L"<Command>", L"</Command>");
        std::wstring args = extractTag(L"<Arguments>", L"</Arguments>");
        std::wstring workDir = extractTag(L"<WorkingDirectory>", L"</WorkingDirectory>");

        if (!cmd.empty()) {
            m_actions->Clear();
            auto act = std::make_shared<TaskExecAction>();
            act->m_path = cmd;
            act->m_arguments = args;
            act->m_workingDirectory = workDir;
            m_actions->m_items.push_back(act);
        }

        if (xml.find(L"<BootTrigger>") != std::wstring_view::npos) {
            ITrigger* trig = nullptr;
            m_triggers->Create(TASK_TRIGGER_BOOT, &trig);
            if (trig) trig->Release();
        } else if (xml.find(L"<LogonTrigger>") != std::wstring_view::npos) {
            ITrigger* trig = nullptr;
            m_triggers->Create(TASK_TRIGGER_LOGON, &trig);
            if (trig) trig->Release();
        } else if (xml.find(L"<TimeTrigger>") != std::wstring_view::npos) {
            ITrigger* trig = nullptr;
            m_triggers->Create(TASK_TRIGGER_TIME, &trig);
            if (trig) {
                std::wstring sb = extractTag(L"<StartBoundary>", L"</StartBoundary>");
                BSTR bSb = SysAllocString(sb.c_str());
                trig->put_StartBoundary(bSb);
                SysFreeString(bSb);
                trig->Release();
            }
        } else if (xml.find(L"<CalendarTrigger>") != std::wstring_view::npos) {
            ITrigger* trig = nullptr;
            m_triggers->Create(TASK_TRIGGER_DAILY, &trig);
            if (trig) {
                std::wstring sb = extractTag(L"<StartBoundary>", L"</StartBoundary>");
                BSTR bSb = SysAllocString(sb.c_str());
                trig->put_StartBoundary(bSb);
                SysFreeString(bSb);
                trig->Release();
            }
        }
    }

    virtual HRESULT __stdcall get_XmlText(BSTR* pXml) override {
        if (!pXml) return E_POINTER;
        std::wstring xml = SerializeToXml();
        *pXml = SysAllocString(xml.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall put_XmlText(BSTR xml) override {
        if (!xml) return E_INVALIDARG;
        DeserializeFromXml(xml);
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// RunningTask
// ----------------------------------------------------------------------------
class RunningTask : public DispatchImpl<IRunningTask> {
public:
    std::wstring m_name;
    std::wstring m_path;
    std::wstring m_instanceGuid;
    TASK_STATE m_state{TASK_STATE_RUNNING};
    std::wstring m_currentAction;
    DWORD m_pid{0};

    RunningTask(std::wstring_view name, std::wstring_view path, std::wstring_view action, DWORD pid)
        : m_name(name), m_path(path), m_currentAction(action), m_pid(pid)
    {
        GUID g{};
        ole32::CoCreateGuid(&g);
        wchar_t buf[64]{};
        swprintf_s(buf, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
            g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
        m_instanceGuid = buf;
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IRunningTask) {
            *ppv = static_cast<IRunningTask*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Name(BSTR* pName) override {
        if (!pName) return E_POINTER;
        *pName = SysAllocString(m_name.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall get_InstanceGuid(BSTR* pGuid) override {
        if (!pGuid) return E_POINTER;
        *pGuid = SysAllocString(m_instanceGuid.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall get_Path(BSTR* pPath) override {
        if (!pPath) return E_POINTER;
        *pPath = SysAllocString(m_path.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall get_State(TASK_STATE* pState) override {
        if (!pState) return E_POINTER;
        *pState = m_state;
        return S_OK;
    }
    virtual HRESULT __stdcall get_CurrentAction(BSTR* pName) override {
        if (!pName) return E_POINTER;
        *pName = SysAllocString(m_currentAction.c_str());
        return S_OK;
    }
    virtual HRESULT __stdcall Stop() override {
        m_state = TASK_STATE_READY;
        return S_OK;
    }
    virtual HRESULT __stdcall Refresh() override {
        return S_OK;
    }
    virtual HRESULT __stdcall get_EnginePID(DWORD* pPID) override {
        if (!pPID) return E_POINTER;
        *pPID = m_pid;
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// RunningTaskCollection
// ----------------------------------------------------------------------------
class RunningTaskCollection : public DispatchImpl<IRunningTaskCollection> {
public:
    std::vector<std::shared_ptr<RunningTask>> m_tasks;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IRunningTaskCollection) {
            *ppv = static_cast<IRunningTaskCollection*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Count(LONG* pCount) override {
        if (!pCount) return E_POINTER;
        *pCount = static_cast<LONG>(m_tasks.size());
        return S_OK;
    }

    virtual HRESULT __stdcall get_Item(VARIANT index, IRunningTask** ppRunningTask) override {
        if (!ppRunningTask) return E_POINTER;
        *ppRunningTask = nullptr;

        if (index.vt == VT_I4) {
            if (index.lVal < 1 || static_cast<size_t>(index.lVal) > m_tasks.size()) {
                return E_INVALIDARG;
            }
            auto rt = m_tasks[static_cast<size_t>(index.lVal - 1)];
            *ppRunningTask = rt.get();
            rt->AddRef();
            return S_OK;
        }
        return E_INVALIDARG;
    }

    virtual HRESULT __stdcall get__NewEnum(IUnknown** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        *ppEnum = nullptr;
        return E_NOTIMPL;
    }
};

// ----------------------------------------------------------------------------
// RegisteredTask
// ----------------------------------------------------------------------------
class RegisteredTask : public DispatchImpl<IRegisteredTask> {
public:
    std::wstring m_name;
    std::wstring m_path;
    TASK_STATE m_state{TASK_STATE_READY};
    VARIANT_BOOL m_enabled{VARIANT_TRUE};
    std::shared_ptr<TaskDefinition> m_definition;
    DATE m_lastRunTime{0.0};
    LONG m_lastTaskResult{0};
    LONG m_numberOfMissedRuns{0};
    DATE m_nextRunTime{0.0};
    std::shared_ptr<RunningTask> m_activeInstance;
    std::mutex m_taskMutex;

    RegisteredTask(std::wstring_view name, std::wstring_view path, std::shared_ptr<TaskDefinition> def)
        : m_name(name), m_path(path), m_definition(def)
    {
        if (m_definition && m_definition->m_settings) {
            m_enabled = m_definition->m_settings->m_enabled;
        }
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IRegisteredTask) {
            *ppv = static_cast<IRegisteredTask*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Name(BSTR* pName) override {
        if (!pName) return E_POINTER;
        *pName = SysAllocString(m_name.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall get_Path(BSTR* pPath) override {
        if (!pPath) return E_POINTER;
        *pPath = SysAllocString(m_path.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall get_State(TASK_STATE* pState) override {
        if (!pState) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_taskMutex);
        if (!m_enabled) {
            *pState = TASK_STATE_DISABLED;
        } else {
            *pState = m_state;
        }
        return S_OK;
    }

    virtual HRESULT __stdcall get_Enabled(VARIANT_BOOL* pEnabled) override {
        if (!pEnabled) return E_POINTER;
        *pEnabled = m_enabled;
        return S_OK;
    }

    virtual HRESULT __stdcall put_Enabled(VARIANT_BOOL enabled) override {
        std::lock_guard<std::mutex> lock(m_taskMutex);
        m_enabled = enabled;
        if (!enabled) {
            m_state = TASK_STATE_DISABLED;
        } else {
            m_state = TASK_STATE_READY;
        }
        return S_OK;
    }

    virtual HRESULT __stdcall Run(VARIANT /*params*/, IRunningTask** ppRunningTask) override {
        std::lock_guard<std::mutex> lock(m_taskMutex);
        if (!m_enabled) {
            return SCHED_E_TASK_NOT_READY;
        }

        m_state = TASK_STATE_RUNNING;
        m_lastRunTime = 46298.5; // Represents current date
        m_lastTaskResult = 0;

        std::wstring currentAction = L"Action Execution";
        if (m_definition && m_definition->m_actions && !m_definition->m_actions->m_items.empty()) {
            currentAction = m_definition->m_actions->m_items[0]->m_path;
        }

        static std::atomic<DWORD> s_pidCounter{1000};
        DWORD assignedPid = s_pidCounter.fetch_add(4);

        m_activeInstance = std::make_shared<RunningTask>(m_name, m_path, currentAction, assignedPid);
        if (ppRunningTask) {
            *ppRunningTask = m_activeInstance.get();
            m_activeInstance->AddRef();
        }

        return S_OK;
    }

    virtual HRESULT __stdcall RunEx(VARIANT params, LONG /*flags*/, LONG /*sessionID*/, BSTR /*user*/, IRunningTask** ppRunningTask) override {
        return Run(params, ppRunningTask);
    }

    virtual HRESULT __stdcall GetInstances(LONG /*flags*/, IRunningTaskCollection** ppInstances) override {
        if (!ppInstances) return E_POINTER;
        auto* coll = new RunningTaskCollection();
        if (m_state == TASK_STATE_RUNNING && m_activeInstance) {
            coll->m_tasks.push_back(m_activeInstance);
        }
        *ppInstances = coll;
        return S_OK;
    }

    virtual HRESULT __stdcall get_LastRunTime(DATE* pLastRunTime) override {
        if (!pLastRunTime) return E_POINTER;
        *pLastRunTime = m_lastRunTime;
        return S_OK;
    }

    virtual HRESULT __stdcall get_LastTaskResult(LONG* pLastTaskResult) override {
        if (!pLastTaskResult) return E_POINTER;
        *pLastTaskResult = m_lastTaskResult;
        return S_OK;
    }

    virtual HRESULT __stdcall get_NumberOfMissedRuns(LONG* pNumberOfMissedRuns) override {
        if (!pNumberOfMissedRuns) return E_POINTER;
        *pNumberOfMissedRuns = m_numberOfMissedRuns;
        return S_OK;
    }

    virtual HRESULT __stdcall get_NextRunTime(DATE* pNextRunTime) override {
        if (!pNextRunTime) return E_POINTER;
        *pNextRunTime = m_nextRunTime;
        return S_OK;
    }

    virtual HRESULT __stdcall get_Definition(ITaskDefinition** ppDefinition) override {
        if (!ppDefinition) return E_POINTER;
        *ppDefinition = m_definition.get();
        if (m_definition) m_definition->AddRef();
        return S_OK;
    }

    virtual HRESULT __stdcall get_Xml(BSTR* pXml) override {
        if (!pXml) return E_POINTER;
        if (m_definition) {
            return m_definition->get_XmlText(pXml);
        }
        *pXml = SysAllocString(L"");
        return S_OK;
    }

    virtual HRESULT __stdcall GetSecurityDescriptor(LONG /*securityInformation*/, BSTR* pSddl) override {
        if (!pSddl) return E_POINTER;
        *pSddl = SysAllocString(L"D:(A;;GA;;;BA)(A;;GA;;;SY)");
        return S_OK;
    }

    virtual HRESULT __stdcall SetSecurityDescriptor(BSTR /*sddl*/, LONG /*flags*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall Stop(LONG /*flags*/) override {
        std::lock_guard<std::mutex> lock(m_taskMutex);
        if (m_state == TASK_STATE_RUNNING) {
            m_state = TASK_STATE_READY;
            if (m_activeInstance) {
                m_activeInstance->Stop();
                m_activeInstance.reset();
            }
            return S_OK;
        }
        return SCHED_E_TASK_NOT_RUNNING;
    }
};

// ----------------------------------------------------------------------------
// RegisteredTaskCollection
// ----------------------------------------------------------------------------
class RegisteredTaskCollection : public DispatchImpl<IRegisteredTaskCollection> {
public:
    std::vector<std::shared_ptr<RegisteredTask>> m_tasks;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IRegisteredTaskCollection) {
            *ppv = static_cast<IRegisteredTaskCollection*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Count(LONG* pCount) override {
        if (!pCount) return E_POINTER;
        *pCount = static_cast<LONG>(m_tasks.size());
        return S_OK;
    }

    virtual HRESULT __stdcall get_Item(VARIANT index, IRegisteredTask** ppRegisteredTask) override {
        if (!ppRegisteredTask) return E_POINTER;
        *ppRegisteredTask = nullptr;

        if (index.vt == VT_I4) {
            if (index.lVal < 1 || static_cast<size_t>(index.lVal) > m_tasks.size()) {
                return E_INVALIDARG;
            }
            auto task = m_tasks[static_cast<size_t>(index.lVal - 1)];
            *ppRegisteredTask = task.get();
            task->AddRef();
            return S_OK;
        } else if (index.vt == VT_BSTR && index.bstrVal) {
            std::wstring searchName(index.bstrVal);
            for (const auto& task : m_tasks) {
                if (task->m_name == searchName || task->m_path == searchName) {
                    *ppRegisteredTask = task.get();
                    task->AddRef();
                    return S_OK;
                }
            }
            return SCHED_E_TASK_NOT_FOUND;
        }
        return E_INVALIDARG;
    }

    virtual HRESULT __stdcall get__NewEnum(IUnknown** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        *ppEnum = nullptr;
        return E_NOTIMPL;
    }
};

// ----------------------------------------------------------------------------
// TaskFolderCollection
// ----------------------------------------------------------------------------
class TaskFolderCollection : public DispatchImpl<ITaskFolderCollection> {
public:
    std::vector<std::shared_ptr<ITaskFolder>> m_folders;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_ITaskFolderCollection) {
            *ppv = static_cast<ITaskFolderCollection*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Count(LONG* pCount) override {
        if (!pCount) return E_POINTER;
        *pCount = static_cast<LONG>(m_folders.size());
        return S_OK;
    }

    virtual HRESULT __stdcall get_Item(VARIANT index, ITaskFolder** ppFolder) override {
        if (!ppFolder) return E_POINTER;
        *ppFolder = nullptr;
        if (index.vt == VT_I4) {
            if (index.lVal < 1 || static_cast<size_t>(index.lVal) > m_folders.size()) {
                return E_INVALIDARG;
            }
            auto f = m_folders[static_cast<size_t>(index.lVal - 1)];
            *ppFolder = f.get();
            f->AddRef();
            return S_OK;
        }
        return E_INVALIDARG;
    }

    virtual HRESULT __stdcall get__NewEnum(IUnknown** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        *ppEnum = nullptr;
        return E_NOTIMPL;
    }
};

// ----------------------------------------------------------------------------
// TaskFolder
// ----------------------------------------------------------------------------
class TaskFolder : public DispatchImpl<ITaskFolder> {
public:
    std::wstring m_name;
    std::wstring m_path;
    std::map<std::wstring, std::shared_ptr<TaskFolder>> m_subFolders;
    std::map<std::wstring, std::shared_ptr<RegisteredTask>> m_tasks;
    std::mutex m_folderMutex;

    TaskFolder(std::wstring_view name, std::wstring_view path)
        : m_name(name), m_path(path) {}

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_ITaskFolder) {
            *ppv = static_cast<ITaskFolder*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall get_Name(BSTR* pName) override {
        if (!pName) return E_POINTER;
        *pName = SysAllocString(m_name.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall get_Path(BSTR* pPath) override {
        if (!pPath) return E_POINTER;
        *pPath = SysAllocString(m_path.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall GetFolder(BSTR path, ITaskFolder** ppFolder) override {
        if (!ppFolder) return E_POINTER;
        *ppFolder = nullptr;
        if (!path || path[0] == L'\0' || wcscmp(path, L"\\") == 0) {
            *ppFolder = this;
            AddRef();
            return S_OK;
        }

        std::wstring targetPath = path;
        if (targetPath.front() == L'\\') targetPath.erase(targetPath.begin());

        std::lock_guard<std::mutex> lock(m_folderMutex);
        size_t slashPos = targetPath.find(L'\\');
        std::wstring firstComponent = (slashPos == std::wstring::npos) ? targetPath : targetPath.substr(0, slashPos);
        std::wstring remaining = (slashPos == std::wstring::npos) ? L"" : targetPath.substr(slashPos + 1);

        auto it = m_subFolders.find(firstComponent);
        if (it == m_subFolders.end()) {
            return HRESULT_FROM_WIN32(SCHED_ERROR_FILE_NOT_FOUND);
        }

        if (remaining.empty()) {
            *ppFolder = it->second.get();
            it->second->AddRef();
            return S_OK;
        } else {
            BSTR bstrRemaining = SysAllocString(remaining.c_str());
            HRESULT hr = it->second->GetFolder(bstrRemaining, ppFolder);
            SysFreeString(bstrRemaining);
            return hr;
        }
    }

    virtual HRESULT __stdcall GetFolders(LONG /*flags*/, ITaskFolderCollection** ppFolders) override {
        if (!ppFolders) return E_POINTER;
        auto* coll = new TaskFolderCollection();
        std::lock_guard<std::mutex> lock(m_folderMutex);
        for (const auto& [_, f] : m_subFolders) {
            coll->m_folders.push_back(f);
        }
        *ppFolders = coll;
        return S_OK;
    }

    virtual HRESULT __stdcall CreateFolder(BSTR subFolderName, VARIANT /*sddl*/, ITaskFolder** ppFolder) override {
        if (!subFolderName) return E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_folderMutex);

        std::wstring name = subFolderName;
        if (m_subFolders.find(name) != m_subFolders.end()) {
            return SCHED_E_ALREADY_EXISTS;
        }

        std::wstring fullPath = (m_path == L"\\") ? (m_path + name) : (m_path + L"\\" + name);
        auto newFolder = std::make_shared<TaskFolder>(name, fullPath);
        m_subFolders[name] = newFolder;

        if (ppFolder) {
            *ppFolder = newFolder.get();
            newFolder->AddRef();
        }
        return S_OK;
    }

    virtual HRESULT __stdcall DeleteFolder(BSTR subFolderName, LONG /*flags*/) override {
        if (!subFolderName) return E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_folderMutex);
        auto it = m_subFolders.find(subFolderName);
        if (it == m_subFolders.end()) {
            return HRESULT_FROM_WIN32(SCHED_ERROR_FILE_NOT_FOUND);
        }
        m_subFolders.erase(it);
        return S_OK;
    }

    virtual HRESULT __stdcall GetTask(BSTR path, IRegisteredTask** ppTask) override {
        if (!ppTask) return E_POINTER;
        *ppTask = nullptr;
        if (!path) return E_INVALIDARG;

        std::wstring target = path;
        size_t lastSlash = target.find_last_of(L'\\');
        if (lastSlash != std::wstring::npos) {
            std::wstring folderPart = target.substr(0, lastSlash);
            std::wstring taskName = target.substr(lastSlash + 1);
            BSTR bstrFolder = SysAllocString(folderPart.c_str());
            ITaskFolder* subF = nullptr;
            HRESULT hr = GetFolder(bstrFolder, &subF);
            SysFreeString(bstrFolder);
            if (hr != S_OK || !subF) return SCHED_E_TASK_NOT_FOUND;

            BSTR bstrName = SysAllocString(taskName.c_str());
            hr = subF->GetTask(bstrName, ppTask);
            SysFreeString(bstrName);
            subF->Release();
            return hr;
        }

        std::lock_guard<std::mutex> lock(m_folderMutex);
        auto it = m_tasks.find(target);
        if (it == m_tasks.end()) {
            return SCHED_E_TASK_NOT_FOUND;
        }

        *ppTask = it->second.get();
        it->second->AddRef();
        return S_OK;
    }

    virtual HRESULT __stdcall GetTasks(LONG /*flags*/, IRegisteredTaskCollection** ppTasks) override {
        if (!ppTasks) return E_POINTER;
        auto* coll = new RegisteredTaskCollection();
        std::lock_guard<std::mutex> lock(m_folderMutex);
        for (const auto& [_, t] : m_tasks) {
            coll->m_tasks.push_back(t);
        }
        *ppTasks = coll;
        return S_OK;
    }

    virtual HRESULT __stdcall DeleteTask(BSTR name, LONG /*flags*/) override {
        if (!name) return E_INVALIDARG;
        std::wstring target = name;
        if (target.empty()) return E_INVALIDARG;

        size_t lastSlash = target.find_last_of(L'\\');
        if (lastSlash != std::wstring::npos) {
            std::wstring folderPart = target.substr(0, lastSlash);
            std::wstring taskName = target.substr(lastSlash + 1);

            BSTR bstrFolder = SysAllocString(folderPart.c_str());
            ITaskFolder* subF = nullptr;
            HRESULT hr = GetFolder(bstrFolder, &subF);
            SysFreeString(bstrFolder);
            if (hr != S_OK || !subF) return SCHED_E_TASK_NOT_FOUND;

            BSTR bstrName = SysAllocString(taskName.c_str());
            hr = subF->DeleteTask(bstrName, 0);
            SysFreeString(bstrName);
            subF->Release();
            return hr;
        }

        std::lock_guard<std::mutex> lock(m_folderMutex);
        auto it = m_tasks.find(target);
        if (it == m_tasks.end()) {
            return SCHED_E_TASK_NOT_FOUND;
        }
        m_tasks.erase(it);
        return S_OK;
    }

    virtual HRESULT __stdcall RegisterTask(
        BSTR path, BSTR xmlText, LONG flags,
        VARIANT /*userId*/, VARIANT /*password*/, TASK_LOGON_TYPE /*logonType*/,
        VARIANT /*sddl*/, IRegisteredTask** ppTask) override
    {
        if (!path || !xmlText) return E_INVALIDARG;

        auto def = std::make_shared<TaskDefinition>();
        def->DeserializeFromXml(xmlText);
        return RegisterTaskDefinition(path, def.get(), flags, {}, {}, TASK_LOGON_INTERACTIVE_TOKEN, {}, ppTask);
    }

    virtual HRESULT __stdcall RegisterTaskDefinition(
        BSTR path, ITaskDefinition* pDefinition, LONG flags,
        VARIANT /*userId*/, VARIANT /*password*/, TASK_LOGON_TYPE /*logonType*/,
        VARIANT /*sddl*/, IRegisteredTask** ppTask) override
    {
        if (!path || !pDefinition) return E_INVALIDARG;

        std::wstring name = path;
        if (name.front() == L'\\') name.erase(name.begin());

        size_t slashPos = name.find_last_of(L'\\');
        if (slashPos != std::wstring::npos) {
            std::wstring folderPart = name.substr(0, slashPos);
            std::wstring taskName = name.substr(slashPos + 1);

            BSTR bstrFolder = SysAllocString(folderPart.c_str());
            ITaskFolder* subF = nullptr;
            HRESULT hr = GetFolder(bstrFolder, &subF);
            if (hr != S_OK || !subF) {
                hr = CreateFolder(bstrFolder, {}, &subF);
            }
            SysFreeString(bstrFolder);
            if (hr != S_OK || !subF) return hr;

            BSTR bstrName = SysAllocString(taskName.c_str());
            hr = subF->RegisterTaskDefinition(bstrName, pDefinition, flags, {}, {}, TASK_LOGON_INTERACTIVE_TOKEN, {}, ppTask);
            SysFreeString(bstrName);
            subF->Release();
            return hr;
        }

        std::lock_guard<std::mutex> lock(m_folderMutex);
        auto it = m_tasks.find(name);
        if (it != m_tasks.end()) {
            if (!(flags & TASK_UPDATE) && !(flags & TASK_CREATE_OR_UPDATE)) {
                return SCHED_E_ALREADY_EXISTS;
            }
        } else {
            if (!(flags & TASK_CREATE) && !(flags & TASK_CREATE_OR_UPDATE)) {
                return SCHED_E_TASK_NOT_FOUND;
            }
        }

        auto taskDef = std::make_shared<TaskDefinition>();
        BSTR xml = nullptr;
        if (pDefinition->get_XmlText(&xml) == S_OK && xml) {
            taskDef->DeserializeFromXml(xml);
            SysFreeString(xml);
        }

        std::wstring fullPath = (m_path == L"\\") ? (m_path + name) : (m_path + L"\\" + name);
        auto task = std::make_shared<RegisteredTask>(name, fullPath, taskDef);
        m_tasks[name] = task;

        if (ppTask) {
            *ppTask = task.get();
            task->AddRef();
        }
        return S_OK;
    }

    virtual HRESULT __stdcall GetSecurityDescriptor(LONG /*securityInformation*/, BSTR* pSddl) override {
        if (!pSddl) return E_POINTER;
        *pSddl = SysAllocString(L"D:(A;;GA;;;BA)(A;;GA;;;SY)");
        return S_OK;
    }

    virtual HRESULT __stdcall SetSecurityDescriptor(BSTR /*sddl*/, LONG /*flags*/) override {
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// TaskService
// ----------------------------------------------------------------------------
class TaskService : public DispatchImpl<ITaskService> {
public:
    bool m_connected{false};
    std::wstring m_targetServer{L"localhost"};
    std::wstring m_user{L"SYSTEM"};
    std::wstring m_domain{L"WORKGROUP"};
    std::shared_ptr<TaskFolder> m_rootFolder;

    TaskService() {
        m_rootFolder = std::make_shared<TaskFolder>(L"", L"\\");
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_ITaskService) {
            *ppv = static_cast<ITaskService*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall Connect(VARIANT serverName, VARIANT user, VARIANT domain, VARIANT /*password*/) override {
        if (serverName.vt == VT_BSTR && serverName.bstrVal) {
            m_targetServer = serverName.bstrVal;
        } else {
            m_targetServer = L"localhost";
        }
        if (user.vt == VT_BSTR && user.bstrVal) {
            m_user = user.bstrVal;
        } else {
            m_user = L"SYSTEM";
        }
        if (domain.vt == VT_BSTR && domain.bstrVal) {
            m_domain = domain.bstrVal;
        } else {
            m_domain = L"WORKGROUP";
        }
        m_connected = true;
        return S_OK;
    }

    virtual HRESULT __stdcall GetFolder(BSTR path, ITaskFolder** ppFolder) override {
        if (!m_connected) return SCHED_E_SERVICE_NOT_RUNNING;
        if (!ppFolder) return E_POINTER;
        return m_rootFolder->GetFolder(path, ppFolder);
    }

    virtual HRESULT __stdcall GetRunningTasks(LONG /*flags*/, IRunningTaskCollection** ppRunningTasks) override {
        if (!m_connected) return SCHED_E_SERVICE_NOT_RUNNING;
        if (!ppRunningTasks) return E_POINTER;
        auto* coll = new RunningTaskCollection();

        auto collectRunning = [&](auto& self, const std::shared_ptr<TaskFolder>& f) -> void {
            std::lock_guard<std::mutex> lock(f->m_folderMutex);
            for (const auto& [_, t] : f->m_tasks) {
                if (t->m_state == TASK_STATE_RUNNING && t->m_activeInstance) {
                    coll->m_tasks.push_back(t->m_activeInstance);
                }
            }
            for (const auto& [_, sub] : f->m_subFolders) {
                self(self, sub);
            }
        };
        collectRunning(collectRunning, m_rootFolder);

        *ppRunningTasks = coll;
        return S_OK;
    }

    virtual HRESULT __stdcall NewTask(DWORD /*flags*/, ITaskDefinition** ppDefinition) override {
        if (!ppDefinition) return E_POINTER;
        auto* def = new TaskDefinition();
        *ppDefinition = def;
        return S_OK;
    }

    virtual HRESULT __stdcall get_Connected(VARIANT_BOOL* pConnected) override {
        if (!pConnected) return E_POINTER;
        *pConnected = m_connected ? VARIANT_TRUE : VARIANT_FALSE;
        return S_OK;
    }

    virtual HRESULT __stdcall get_TargetServer(BSTR* pServer) override {
        if (!pServer) return E_POINTER;
        *pServer = SysAllocString(m_targetServer.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall get_ConnectedUser(BSTR* pUser) override {
        if (!pUser) return E_POINTER;
        *pUser = SysAllocString(m_user.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall get_ConnectedDomain(BSTR* pDomain) override {
        if (!pDomain) return E_POINTER;
        *pDomain = SysAllocString(m_domain.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall get_HighestVersion(DWORD* pVersion) override {
        if (!pVersion) return E_POINTER;
        *pVersion = 0x00010002;
        return S_OK;
    }
};

// ============================================================================
// 4. Global Task Scheduler Engine & Repository
// ============================================================================

class TaskSchedulerEngine {
private:
    std::shared_ptr<TaskService> m_service;
    std::mutex m_engineMutex;
    bool m_initialized{false};

    TaskSchedulerEngine() {
        m_service = std::make_shared<TaskService>();
        m_service->Connect({}, {}, {}, {});
        PreseedDefaultSystemTasks();
        m_initialized = true;
    }

    void PreseedDefaultSystemTasks() {
        auto root = m_service->m_rootFolder;

        ITaskFolder* pMs = nullptr;
        BSTR bstrMs = SysAllocString(L"Microsoft");
        root->CreateFolder(bstrMs, {}, &pMs);
        SysFreeString(bstrMs);

        ITaskFolder* pWin = nullptr;
        if (pMs) {
            BSTR bstrWin = SysAllocString(L"Windows");
            pMs->CreateFolder(bstrWin, {}, &pWin);
            SysFreeString(bstrWin);
            pMs->Release();
        }

        if (pWin) {
            // 1. Defrag\ScheduledDefrag
            ITaskFolder* pDefrag = nullptr;
            BSTR bstrDef = SysAllocString(L"Defrag");
            pWin->CreateFolder(bstrDef, {}, &pDefrag);
            SysFreeString(bstrDef);
            if (pDefrag) {
                auto def = std::make_shared<TaskDefinition>();
                def->m_regInfo->m_author = L"Microsoft Corporation";
                def->m_regInfo->m_description = L"Scheduled Disk Defragmentation";
                def->m_regInfo->m_uri = L"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag";
                ITrigger* trig = nullptr;
                def->m_triggers->Create(TASK_TRIGGER_TIME, &trig);
                if (trig) {
                    BSTR bSt = SysAllocString(L"2026-01-01T01:00:00");
                    trig->put_StartBoundary(bSt);
                    SysFreeString(bSt);
                    trig->Release();
                }
                auto act = std::make_shared<TaskExecAction>();
                act->m_path = L"defrag.exe";
                act->m_arguments = L"-c -h -k";
                def->m_actions->m_items.push_back(act);

                BSTR bstrName = SysAllocString(L"ScheduledDefrag");
                pDefrag->RegisterTaskDefinition(bstrName, def.get(), TASK_CREATE_OR_UPDATE, {}, {}, TASK_LOGON_INTERACTIVE_TOKEN, {}, nullptr);
                SysFreeString(bstrName);
                pDefrag->Release();
            }

            // 2. DiskCleanup\SilentCleanup
            ITaskFolder* pCleanup = nullptr;
            BSTR bstrClean = SysAllocString(L"DiskCleanup");
            pWin->CreateFolder(bstrClean, {}, &pCleanup);
            SysFreeString(bstrClean);
            if (pCleanup) {
                auto def = std::make_shared<TaskDefinition>();
                def->m_regInfo->m_author = L"Microsoft Corporation";
                def->m_regInfo->m_description = L"Automated Silent Disk Cleanup";
                def->m_regInfo->m_uri = L"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup";
                ITrigger* trig = nullptr;
                def->m_triggers->Create(TASK_TRIGGER_DAILY, &trig);
                if (trig) trig->Release();
                auto act = std::make_shared<TaskExecAction>();
                act->m_path = L"cleanmgr.exe";
                act->m_arguments = L"/autoclean /d C:";
                def->m_actions->m_items.push_back(act);

                BSTR bstrName = SysAllocString(L"SilentCleanup");
                pCleanup->RegisterTaskDefinition(bstrName, def.get(), TASK_CREATE_OR_UPDATE, {}, {}, TASK_LOGON_INTERACTIVE_TOKEN, {}, nullptr);
                SysFreeString(bstrName);
                pCleanup->Release();
            }

            // 3. TimeSynchronization\SynchronizeTime
            ITaskFolder* pTime = nullptr;
            BSTR bstrTime = SysAllocString(L"TimeSynchronization");
            pWin->CreateFolder(bstrTime, {}, &pTime);
            SysFreeString(bstrTime);
            if (pTime) {
                auto def = std::make_shared<TaskDefinition>();
                def->m_regInfo->m_author = L"Microsoft Corporation";
                def->m_regInfo->m_description = L"Synchronize system time with NTP server";
                def->m_regInfo->m_uri = L"\\Microsoft\\Windows\\TimeSynchronization\\SynchronizeTime";
                ITrigger* trig = nullptr;
                def->m_triggers->Create(TASK_TRIGGER_BOOT, &trig);
                if (trig) trig->Release();
                auto act = std::make_shared<TaskExecAction>();
                act->m_path = L"w32tm.exe";
                act->m_arguments = L"/resync";
                def->m_actions->m_items.push_back(act);

                BSTR bstrName = SysAllocString(L"SynchronizeTime");
                pTime->RegisterTaskDefinition(bstrName, def.get(), TASK_CREATE_OR_UPDATE, {}, {}, TASK_LOGON_INTERACTIVE_TOKEN, {}, nullptr);
                SysFreeString(bstrName);
                pTime->Release();
            }

            // 4. Maintenance\WinSAT
            ITaskFolder* pMaint = nullptr;
            BSTR bstrMaint = SysAllocString(L"Maintenance");
            pWin->CreateFolder(bstrMaint, {}, &pMaint);
            SysFreeString(bstrMaint);
            if (pMaint) {
                auto def = std::make_shared<TaskDefinition>();
                def->m_regInfo->m_author = L"Microsoft Corporation";
                def->m_regInfo->m_description = L"System Assessment & Benchmark Scheduler";
                def->m_regInfo->m_uri = L"\\Microsoft\\Windows\\Maintenance\\WinSAT";
                ITrigger* trig = nullptr;
                def->m_triggers->Create(TASK_TRIGGER_TIME, &trig);
                if (trig) {
                    BSTR bSt = SysAllocString(L"2026-01-01T03:00:00");
                    trig->put_StartBoundary(bSt);
                    SysFreeString(bSt);
                    trig->Release();
                }
                auto act = std::make_shared<TaskExecAction>();
                act->m_path = L"winsat.exe";
                act->m_arguments = L"formal";
                def->m_actions->m_items.push_back(act);

                BSTR bstrName = SysAllocString(L"WinSAT");
                pMaint->RegisterTaskDefinition(bstrName, def.get(), TASK_CREATE_OR_UPDATE, {}, {}, TASK_LOGON_INTERACTIVE_TOKEN, {}, nullptr);
                SysFreeString(bstrName);
                pMaint->Release();
            }

            // 5. Registry\RegIdleBackup
            ITaskFolder* pReg = nullptr;
            BSTR bstrReg = SysAllocString(L"Registry");
            pWin->CreateFolder(bstrReg, {}, &pReg);
            SysFreeString(bstrReg);
            if (pReg) {
                auto def = std::make_shared<TaskDefinition>();
                def->m_regInfo->m_author = L"Microsoft Corporation";
                def->m_regInfo->m_description = L"Registry Hive Idle Snapshot & Backup";
                def->m_regInfo->m_uri = L"\\Microsoft\\Windows\\Registry\\RegIdleBackup";
                ITrigger* trig = nullptr;
                def->m_triggers->Create(TASK_TRIGGER_IDLE, &trig);
                if (trig) trig->Release();
                auto act = std::make_shared<TaskExecAction>();
                act->m_path = L"reg.exe";
                act->m_arguments = L"save HKLM\\SYSTEM C:\\Windows\\System32\\config\\RegBack\\SYSTEM";
                def->m_actions->m_items.push_back(act);

                BSTR bstrName = SysAllocString(L"RegIdleBackup");
                pReg->RegisterTaskDefinition(bstrName, def.get(), TASK_CREATE_OR_UPDATE, {}, {}, TASK_LOGON_INTERACTIVE_TOKEN, {}, nullptr);
                SysFreeString(bstrName);
                pReg->Release();
            }

            pWin->Release();
        }
    }

public:
    static TaskSchedulerEngine& Instance() {
        static TaskSchedulerEngine s_instance;
        return s_instance;
    }

    std::shared_ptr<TaskService> GetService() {
        return m_service;
    }

    TaskService* CreateNewServiceSession() {
        auto* svc = new TaskService();
        svc->m_rootFolder = m_service->m_rootFolder;
        return svc;
    }

    void TriggerBootTasks() {
        std::lock_guard<std::mutex> lock(m_engineMutex);
        auto checkBoot = [&](auto& self, const std::shared_ptr<TaskFolder>& f) -> void {
            std::lock_guard<std::mutex> fLock(f->m_folderMutex);
            for (const auto& [_, t] : f->m_tasks) {
                if (!t->m_enabled || !t->m_definition) continue;
                for (const auto& trig : t->m_definition->m_triggers->m_items) {
                    TASK_TRIGGER_TYPE2 tt{};
                    trig->get_Type(&tt);
                    VARIANT_BOOL en = VARIANT_TRUE;
                    trig->get_Enabled(&en);
                    if (tt == TASK_TRIGGER_BOOT && en) {
                        t->Run({}, nullptr);
                        break;
                    }
                }
            }
            for (const auto& [_, sub] : f->m_subFolders) {
                self(self, sub);
            }
        };
        checkBoot(checkBoot, m_service->m_rootFolder);
    }

    std::vector<std::shared_ptr<RegisteredTask>> GetAllTasks() {
        std::vector<std::shared_ptr<RegisteredTask>> result;
        auto collect = [&](auto& self, const std::shared_ptr<TaskFolder>& f) -> void {
            std::lock_guard<std::mutex> lock(f->m_folderMutex);
            for (const auto& [_, t] : f->m_tasks) {
                result.push_back(t);
            }
            for (const auto& [_, sub] : f->m_subFolders) {
                self(self, sub);
            }
        };
        collect(collect, m_service->m_rootFolder);
        return result;
    }
};

// ----------------------------------------------------------------------------
// TaskSchedulerClassFactory (CLSID_TaskScheduler)
// ----------------------------------------------------------------------------
class TaskSchedulerClassFactory : public IClassFactory {
private:
    std::atomic<uint32_t> m_refCount{1};

public:
    virtual ~TaskSchedulerClassFactory() = default;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t __stdcall Release() override {
        uint32_t cnt = m_refCount.fetch_sub(1) - 1;
        if (cnt == 0) {
            delete this;
        }
        return cnt;
    }

    virtual HRESULT __stdcall CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override {
        if (pUnkOuter != nullptr) return CLASS_E_NOAGGREGATION;
        if (!ppv) return E_POINTER;

        auto* svc = TaskSchedulerEngine::Instance().CreateNewServiceSession();
        HRESULT hr = svc->QueryInterface(riid, ppv);
        svc->Release();
        return hr;
    }

    virtual HRESULT __stdcall LockServer(win32::BOOL /*fLock*/) override {
        return S_OK;
    }
};

// ============================================================================
// 5. Dynamic Loader & COM Exports (taskschd.dll)
// ============================================================================

extern "C" inline HRESULT __stdcall TaskSchd_DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (rclsid == CLSID_TaskScheduler) {
        static TaskSchedulerClassFactory factory;
        return factory.QueryInterface(riid, ppv);
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

extern "C" inline HRESULT __stdcall TaskSchd_DllCanUnloadNow() {
    return S_FALSE;
}

extern "C" inline HRESULT __stdcall TaskSchd_DllRegisterServer() {
    return S_OK;
}

extern "C" inline HRESULT __stdcall TaskSchd_DllUnregisterServer() {
    return S_OK;
}

inline void InitializeTaskSchedulerSubsystemExports() {
    static std::atomic<bool> s_initialized{false};
    if (s_initialized.exchange(true)) return;

    TaskSchedulerEngine::Instance();

    auto& ldr = ldr::DynamicLoader::get();

    // Register taskschd.dll exports
    ldr.registerExport("taskschd.dll", "DllGetClassObject", reinterpret_cast<void*>(TaskSchd_DllGetClassObject));
    ldr.registerExport("taskschd.dll", "DllCanUnloadNow", reinterpret_cast<void*>(TaskSchd_DllCanUnloadNow));
    ldr.registerExport("taskschd.dll", "DllRegisterServer", reinterpret_cast<void*>(TaskSchd_DllRegisterServer));
    ldr.registerExport("taskschd.dll", "DllUnregisterServer", reinterpret_cast<void*>(TaskSchd_DllUnregisterServer));

    // Register mstask.dll exports for legacy compatibility
    ldr.registerExport("mstask.dll", "DllGetClassObject", reinterpret_cast<void*>(TaskSchd_DllGetClassObject));
    ldr.registerExport("mstask.dll", "DllCanUnloadNow", reinterpret_cast<void*>(TaskSchd_DllCanUnloadNow));
    ldr.registerExport("mstask.dll", "DllRegisterServer", reinterpret_cast<void*>(TaskSchd_DllRegisterServer));
    ldr.registerExport("mstask.dll", "DllUnregisterServer", reinterpret_cast<void*>(TaskSchd_DllUnregisterServer));

    // Register CLSID_TaskScheduler in COM Runtime
    auto* factory = new TaskSchedulerClassFactory();
    uint32_t regCookie = 0;
    ole32::CoRegisterClassObject(CLSID_TaskScheduler, factory, 1 /* CLSCTX_INPROC_SERVER */, 0, &regCookie);
}

} // namespace micant::taskschd
