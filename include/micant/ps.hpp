#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <atomic>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ob.hpp"
#include "mm.hpp"
#include "se.hpp"

namespace micant::ps {

/**
 * @brief Thread Execution State.
 */
enum class ThreadState : uint32_t {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting
};

/**
 * @brief x86-64 Machine Architecture Context Frame.
 */
struct ContextFrame {
    uint64_t rip{0};
    uint64_t rsp{0};
    uint64_t rflags{0x202}; // IF (Interrupt Flag) enabled
    uint64_t rax{0};
    uint64_t rcx{0};
    uint64_t rdx{0};
    uint64_t rbx{0};
    uint64_t rbp{0};
    uint64_t rsi{0};
    uint64_t rdi{0};
    uint64_t r8{0};
    uint64_t r9{0};
    uint64_t r10{0};
    uint64_t r11{0};
    uint64_t r12{0};
    uint64_t r13{0};
    uint64_t r14{0};
    uint64_t r15{0};
    uint16_t cs{0x33}; // User code segment (Ring 3 64-bit)
    uint16_t ss{0x2B}; // User data segment (Ring 3)
};

/**
 * @brief Process Environment Block (PEB).
 * Standard userland structure pointed to by TEB->ProcessEnvironmentBlock.
 */
struct Peb {
    uint8_t  inheritedAddressSpace{0};
    uint8_t  readImageFileExecOptions{0};
    uint8_t  beingDebugged{0};
    uint8_t  bitField{0};
    uint64_t mutant{0};
    uint64_t imageBaseAddress{0};
    uint64_t ldr{0};
    uint64_t processParameters{0};
    uint64_t subSystemData{0};
    uint64_t processHeap{0};
    uint64_t fastPebLock{0};
    uint32_t numberOfProcessors{1};
    uint32_t ntGlobalFlag{0};
    uint16_t osMajorVersion{10};
    uint16_t osMinorVersion{0};
    uint16_t osBuildNumber{26100}; // Modern Windows 11 base build
    uint16_t osCsdVersion{0};
    uint32_t osPlatformId{2};      // VER_PLATFORM_WIN32_NT
    uint32_t imageSubsystem{3};    // IMAGE_SUBSYSTEM_WINDOWS_CUI
    uint32_t imageSubsystemMajorVersion{10};
    uint32_t imageSubsystemMinorVersion{0};
};

/**
 * @brief Thread Environment Block (TEB).
 * Standard userland per-thread block mapped at GS:[0x30] on x86_64.
 */
struct Teb {
    struct {
        uint64_t exceptionList{0};
        uint64_t stackBase{0};
        uint64_t stackLimit{0};
        uint64_t subSystemTib{0};
        uint64_t fiberData{0};
        uint64_t arbitraryUserPointer{0};
        uint64_t self{0}; // Points to TEB itself
    } ntTib;

    uint64_t environmentPointer{0};
    ClientId clientId{};
    uint64_t activeRpcHandle{0};
    uint64_t threadLocalStoragePointer{0};
    uint64_t processEnvironmentBlock{0}; // Pointer to PEB
    uint32_t lastErrorValue{0};
    uint32_t countOfOwnedCriticalSections{0};
};

class EProcess;

/**
 * @brief Executive Thread (ETHREAD).
 * Represents a single execution thread within a process.
 */
class EThread {
public:
    EThread(Handle tid, EProcess* owner, uintptr_t entryPoint, uintptr_t stackBase, uintptr_t stackLimit)
        : tid_(tid), owner_(owner), stackBase_(stackBase), stackLimit_(stackLimit), state_(ThreadState::Initialized) {
        context_.rip = entryPoint;
        context_.rsp = stackBase - 0x28; // Standard 32-byte shadow space + return address align
    }

    [[nodiscard]] Handle getTid() const noexcept { return tid_; }
    [[nodiscard]] EProcess* getOwnerProcess() const noexcept { return owner_; }
    [[nodiscard]] ThreadState getState() const noexcept { return state_; }
    void setState(ThreadState s) noexcept { state_ = s; }

    [[nodiscard]] ContextFrame& getContext() noexcept { return context_; }
    [[nodiscard]] const ContextFrame& getContext() const noexcept { return context_; }

    [[nodiscard]] uintptr_t getStackBase() const noexcept { return stackBase_; }
    [[nodiscard]] uintptr_t getStackLimit() const noexcept { return stackLimit_; }
    [[nodiscard]] uintptr_t getTebAddress() const noexcept { return tebAddress_; }
    void setTebAddress(uintptr_t addr) noexcept { tebAddress_ = addr; }

private:
    Handle tid_{0};
    EProcess* owner_{nullptr};
    uintptr_t stackBase_{0};
    uintptr_t stackLimit_{0};
    uintptr_t tebAddress_{0};
    ThreadState state_{ThreadState::Initialized};
    ContextFrame context_{};
};

/**
 * @brief Executive Process (EPROCESS).
 * The primary container for address space, handles, and threads.
 */
class EProcess {
public:
    EProcess(Handle pid, std::wstring imageFileName)
        : pid_(pid), imageFileName_(std::move(imageFileName)), exitStatus_(NtStatus::Success), terminated_(false) {}

    [[nodiscard]] Handle getPid() const noexcept { return pid_; }
    [[nodiscard]] const std::wstring& getImageFileName() const noexcept { return imageFileName_; }

    [[nodiscard]] mm::ProcessAddressSpace& getAddressSpace() noexcept { return addressSpace_; }
    [[nodiscard]] ob::HandleTable& getHandleTable() noexcept { return handleTable_; }

    [[nodiscard]] uintptr_t getImageBase() const noexcept { return imageBase_; }
    void setImageBase(uintptr_t base) noexcept { imageBase_ = base; }

    [[nodiscard]] uintptr_t getEntryPoint() const noexcept { return entryPoint_; }
    void setEntryPoint(uintptr_t ep) noexcept { entryPoint_ = ep; }

    [[nodiscard]] uintptr_t getPebAddress() const noexcept { return pebAddress_; }
    void setPebAddress(uintptr_t addr) noexcept { pebAddress_ = addr; }

    [[nodiscard]] bool isTerminated() const noexcept { return terminated_; }
    [[nodiscard]] NtStatus getExitStatus() const noexcept { return exitStatus_; }

    void terminate(NtStatus status) noexcept {
        exitStatus_ = status;
        terminated_ = true;
        for (auto& t : threads_) {
            t->setState(ThreadState::Terminated);
        }
    }

    std::shared_ptr<EThread> createThread(uintptr_t entryPoint, size_t stackSize = 1024 * 1024) {
        Handle tid = static_cast<Handle>(nextTid_++);
        
        // Allocate stack in process address space
        uintptr_t stackBase = 0;
        addressSpace_.allocate(stackBase, stackSize, mm::MEM_RESERVE | mm::MEM_COMMIT, mm::PAGE_READWRITE);
        uintptr_t stackTop = stackBase + stackSize;

        auto thread = std::make_shared<EThread>(tid, this, entryPoint, stackTop, stackBase);
        threads_.push_back(thread);
        return thread;
    }

    [[nodiscard]] std::shared_ptr<se::TokenObject> getToken() const noexcept { return token_; }
    void setToken(std::shared_ptr<se::TokenObject> token) noexcept { token_ = std::move(token); }

    [[nodiscard]] const std::vector<std::shared_ptr<EThread>>& getThreads() const noexcept {
        return threads_;
    }

private:
    Handle pid_{0};
    std::wstring imageFileName_;
    mm::ProcessAddressSpace addressSpace_;
    ob::HandleTable handleTable_;
    std::shared_ptr<se::TokenObject> token_;
    uintptr_t imageBase_{0};
    uintptr_t entryPoint_{0};
    uintptr_t pebAddress_{0};
    NtStatus exitStatus_{NtStatus::Success};
    bool terminated_{false};
    uint32_t nextTid_{1};
    std::vector<std::shared_ptr<EThread>> threads_;
};

/**
 * @brief Process Manager Factory & Registry.
 */
class ProcessManager {
public:
    static ProcessManager& get() {
        static ProcessManager instance;
        return instance;
    }

    std::shared_ptr<EProcess> createProcess(std::wstring_view imageName, std::shared_ptr<se::TokenObject> token = nullptr) {
        Handle pid = static_cast<Handle>(nextPid_++);
        auto proc = std::make_shared<EProcess>(pid, std::wstring(imageName));

        // Allocate and setup PEB at standard base
        uintptr_t pebAddr = 0x00007FFDF0000000ULL;
        proc->getAddressSpace().allocate(pebAddr, sizeof(Peb), mm::MEM_COMMIT | mm::MEM_RESERVE, mm::PAGE_READWRITE);
        proc->setPebAddress(pebAddr);

        if (token) {
            proc->setToken(std::move(token));
        } else {
            proc->setToken(se::TokenObject::createSystemToken());
        }

        processes_[pid] = proc;
        return proc;
    }

    [[nodiscard]] std::shared_ptr<EProcess> getProcess(Handle pid) const {
        auto it = processes_.find(pid);
        if (it != processes_.end()) return it->second;
        return nullptr;
    }

    [[nodiscard]] size_t getActiveProcessCount() const noexcept {
        return processes_.size();
    }

private:
    ProcessManager() : nextPid_(1000) {}
    uint32_t nextPid_;
    std::unordered_map<Handle, std::shared_ptr<EProcess>> processes_;
};

} // namespace micant::ps
