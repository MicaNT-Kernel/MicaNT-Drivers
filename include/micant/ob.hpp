#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <unordered_map>
#include <atomic>
#include "ntdef.hpp"

namespace micant::ob {

enum class ObjectTypeId : uint32_t {
    Type,
    Directory,
    SymbolicLink,
    Device,
    Driver,
    Process,
    Thread,
    Section,
    File,
    Event,
    Mutant,
    Semaphore,
    Key,
    IoCompletion,
    Job
};

struct ObjectHeader;

/**
 * @brief Representation of an Object Type in the Object Manager.
 */
struct ObjectType {
    std::wstring typeName;
    ObjectTypeId typeId;
    uint32_t totalNumberOfObjects{0};
    uint32_t totalNumberOfHandles{0};
    uint32_t validAccessMask{0x001FFFFF};
};

/**
 * @brief Object Header prepended to every allocated kernel object body.
 */
struct ObjectHeader {
    std::atomic<int32_t> pointerCount{1};
    std::atomic<int32_t> handleCount{0};
    const ObjectType* type{nullptr};
    std::wstring objectName;
    ObjectHeader* parentDirectory{nullptr};
    uint32_t attributes{0};

    [[nodiscard]] void* getBody() noexcept {
        return reinterpret_cast<void*>(this + 1);
    }

    template<typename T>
    [[nodiscard]] T* as() noexcept {
        return reinterpret_cast<T*>(getBody());
    }

    void addReference() noexcept {
        pointerCount.fetch_add(1, std::memory_order_relaxed);
    }

    bool releaseReference() noexcept {
        return pointerCount.fetch_sub(1, std::memory_order_acq_rel) == 1;
    }
};

/**
 * @brief Directory Object representing folders in the NT Object Namespace.
 */
class DirectoryObject {
public:
    explicit DirectoryObject(std::wstring name) : name_(std::move(name)) {}

    NtStatus insertObject(std::wstring_view name, ObjectHeader* object) {
        if (!object) return NtStatus::InvalidParameter;
        std::wstring key(name);
        if (entries_.contains(key)) {
            return NtStatus::ObjectNameCollision;
        }
        object->addReference();
        entries_[key] = object;
        return NtStatus::Success;
    }

    [[nodiscard]] ObjectHeader* lookup(std::wstring_view name) const {
        auto it = entries_.find(std::wstring(name));
        if (it != entries_.end()) {
            return it->second;
        }
        return nullptr;
    }

    [[nodiscard]] const std::wstring& getName() const noexcept { return name_; }
    [[nodiscard]] size_t getEntryCount() const noexcept { return entries_.size(); }

private:
    std::wstring name_;
    std::unordered_map<std::wstring, ObjectHeader*> entries_;
};

/**
 * @brief Per-Process Handle Table.
 * Maps opaque userland `Handle` (values 4, 8, 12...) to ObjectHeader pointers.
 */
class HandleTable {
public:
    static constexpr size_t MaxHandles = 4096;

    HandleTable() {
        table_.resize(MaxHandles, nullptr);
    }

    NtStatus createHandle(ObjectHeader* object, Handle& outHandle) {
        if (!object) return NtStatus::InvalidParameter;

        // NT Handles start at 4 and increment by 4
        for (size_t i = 1; i < table_.size(); ++i) {
            if (table_[i] == nullptr) {
                object->addReference();
                object->handleCount.fetch_add(1, std::memory_order_relaxed);
                table_[i] = object;
                outHandle = static_cast<Handle>(i * 4);
                return NtStatus::Success;
            }
        }
        return NtStatus::NoMemory;
    }

    [[nodiscard]] ObjectHeader* lookup(Handle handle) const {
        size_t index = static_cast<size_t>(handle) / 4;
        if (index == 0 || index >= table_.size()) return nullptr;
        return table_[index];
    }

    NtStatus closeHandle(Handle handle) {
        size_t index = static_cast<size_t>(handle) / 4;
        if (index == 0 || index >= table_.size() || table_[index] == nullptr) {
            return NtStatus::InvalidHandle;
        }

        ObjectHeader* obj = table_[index];
        table_[index] = nullptr;
        obj->handleCount.fetch_sub(1, std::memory_order_relaxed);
        obj->releaseReference();
        return NtStatus::Success;
    }

private:
    std::vector<ObjectHeader*> table_;
};

} // namespace micant::ob
