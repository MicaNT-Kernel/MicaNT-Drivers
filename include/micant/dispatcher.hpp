#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <string_view>
#include <span>
#include "ntstatus.hpp"
#include "syscalls.hpp"

namespace micant::sys {

struct SyscallFrame {
    uint32_t ssn;        // System Service Number (from EAX)
    uint64_t arg1;       // R10 / RCX
    uint64_t arg2;       // RDX
    uint64_t arg3;       // R8
    uint64_t arg4;       // R9
    const uint64_t* stackArgs{nullptr}; // Arguments passed on user stack
    size_t stackArgCount{0};
};

using SyscallHandler = std::function<NtStatus(const SyscallFrame&)>;

struct SyscallDescriptor {
    std::string_view name;
    uint32_t ssn;
    uint32_t argumentCount;
    SyscallHandler handler;
};

/**
 * @brief KiSystemCall64 Central Dispatch Table
 */
class SyscallDispatcher {
public:
    static SyscallDispatcher& get() {
        static SyscallDispatcher instance;
        return instance;
    }

    void registerSyscall(uint32_t ssn, std::string_view name, uint32_t argCount, SyscallHandler handler) {
        table_[ssn] = SyscallDescriptor{
            .name = name,
            .ssn = ssn,
            .argumentCount = argCount,
            .handler = std::move(handler)
        };
    }

    [[nodiscard]] NtStatus dispatch(const SyscallFrame& frame) const {
        auto it = table_.find(frame.ssn);
        if (it == table_.end()) {
            return NtStatus::InvalidDeviceRequest;
        }
        return it->second.handler(frame);
    }

    [[nodiscard]] const SyscallDescriptor* lookup(uint32_t ssn) const {
        auto it = table_.find(ssn);
        if (it != table_.end()) return &it->second;
        return nullptr;
    }

    [[nodiscard]] size_t getRegisteredCount() const noexcept {
        return table_.size();
    }

    void initializeStandardTable();

private:
    SyscallDispatcher() {
        initializeStandardTable();
    }
    std::unordered_map<uint32_t, SyscallDescriptor> table_;
};

} // namespace micant::sys
