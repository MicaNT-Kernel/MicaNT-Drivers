#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <memory>
#include <variant>
#include <span>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ob.hpp"

namespace micant::cm {

// Standard Registry Value Types
enum class RegType : uint32_t {
    None = 0,
    Sz = 1,                 // Null-terminated Unicode string
    ExpandSz = 2,
    Binary = 3,             // Free form binary
    Dword = 4,              // 32-bit integer
    DwordBigEndian = 5,
    Link = 6,
    MultiSz = 7,
    Qword = 11              // 64-bit integer
};

struct KeyValue {
    RegType type{RegType::None};
    std::vector<uint8_t> data;

    [[nodiscard]] std::wstring asString() const {
        if (type != RegType::Sz || data.empty()) return {};
        return std::wstring(reinterpret_cast<const wchar_t*>(data.data()), data.size() / sizeof(wchar_t));
    }

    [[nodiscard]] uint32_t asDword() const {
        if (data.size() < sizeof(uint32_t)) return 0;
        return *reinterpret_cast<const uint32_t*>(data.data());
    }

    [[nodiscard]] uint64_t asQword() const {
        if (data.size() < sizeof(uint64_t)) return 0;
        return *reinterpret_cast<const uint64_t*>(data.data());
    }
};

/**
 * @brief Registry Key Object.
 * In NT, keys are represented in the Object Manager hierarchy under \Registry.
 */
class KeyObject {
public:
    explicit KeyObject(std::wstring name) : name_(std::move(name)) {}

    [[nodiscard]] const std::wstring& getName() const noexcept { return name_; }

    std::shared_ptr<KeyObject> createSubkey(std::wstring_view name) {
        std::wstring key(name);
        auto it = subkeys_.find(key);
        if (it != subkeys_.end()) return it->second;

        auto sub = std::make_shared<KeyObject>(key);
        subkeys_[key] = sub;
        return sub;
    }

    [[nodiscard]] std::shared_ptr<KeyObject> openSubkey(std::wstring_view name) const {
        auto it = subkeys_.find(std::wstring(name));
        if (it != subkeys_.end()) return it->second;
        return nullptr;
    }

    void setValueString(std::wstring_view valName, std::wstring_view val) {
        std::vector<uint8_t> bytes(val.size() * sizeof(wchar_t));
        std::memcpy(bytes.data(), val.data(), bytes.size());
        values_[std::wstring(valName)] = KeyValue{ .type = RegType::Sz, .data = std::move(bytes) };
    }

    void setValueDword(std::wstring_view valName, uint32_t val) {
        std::vector<uint8_t> bytes(sizeof(uint32_t));
        std::memcpy(bytes.data(), &val, sizeof(uint32_t));
        values_[std::wstring(valName)] = KeyValue{ .type = RegType::Dword, .data = std::move(bytes) };
    }

    void setValueQword(std::wstring_view valName, uint64_t val) {
        std::vector<uint8_t> bytes(sizeof(uint64_t));
        std::memcpy(bytes.data(), &val, sizeof(uint64_t));
        values_[std::wstring(valName)] = KeyValue{ .type = RegType::Qword, .data = std::move(bytes) };
    }

    [[nodiscard]] const KeyValue* getValue(std::wstring_view valName) const {
        auto it = values_.find(std::wstring(valName));
        if (it != values_.end()) return &it->second;
        return nullptr;
    }

    [[nodiscard]] size_t getSubkeyCount() const noexcept { return subkeys_.size(); }
    [[nodiscard]] size_t getValueCount() const noexcept { return values_.size(); }

private:
    std::wstring name_;
    std::unordered_map<std::wstring, std::shared_ptr<KeyObject>> subkeys_;
    std::unordered_map<std::wstring, KeyValue> values_;
};

/**
 * @brief Configuration Manager (CM) Subsystem.
 */
class ConfigurationManager {
public:
    static ConfigurationManager& get() {
        static ConfigurationManager instance;
        return instance;
    }

    void initialize() {
        rootKey_ = std::make_shared<KeyObject>(L"\\Registry");
        
        // Create standard NT Registry Hives:
        // \Registry\Machine\SYSTEM
        // \Registry\Machine\SOFTWARE
        // \Registry\User
        auto machine = rootKey_->createSubkey(L"Machine");
        auto user = rootKey_->createSubkey(L"User");
        
        auto system = machine->createSubkey(L"SYSTEM");
        machine->createSubkey(L"SOFTWARE");

        auto ccs = system->createSubkey(L"CurrentControlSet");
        auto control = ccs->createSubkey(L"Control");
        auto session = control->createSubkey(L"Session Manager");
        
        session->setValueString(L"OSName", L"MicaNT Modern C++23 Clean-Room Executive");
        session->setValueDword(L"OSBuild", 26100);
        session->setValueDword(L"ZeroTelemetryEnabled", 1);
    }

    std::shared_ptr<KeyObject> resolvePath(std::wstring_view path) {
        if (path.starts_with(L"\\Registry")) {
            path.remove_prefix(9); // Strip \Registry
        }
        if (path.starts_with(L"\\")) {
            path.remove_prefix(1);
        }

        std::shared_ptr<KeyObject> current = rootKey_;
        size_t start = 0;
        while (start < path.size()) {
            size_t slash = path.find(L'\\', start);
            std::wstring_view part = (slash == std::wstring_view::npos) 
                ? path.substr(start) 
                : path.substr(start, slash - start);

            if (!part.empty()) {
                current = current->openSubkey(part);
                if (!current) return nullptr;
            }

            if (slash == std::wstring_view::npos) break;
            start = slash + 1;
        }
        return current;
    }

    [[nodiscard]] std::shared_ptr<KeyObject> getRootKey() const noexcept { return rootKey_; }

private:
    ConfigurationManager() { initialize(); }
    std::shared_ptr<KeyObject> rootKey_;
};

} // namespace micant::cm
