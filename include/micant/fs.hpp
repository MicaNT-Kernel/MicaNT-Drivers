#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <span>
#include <cstring>
#include <algorithm>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "io.hpp"
#include "ob.hpp"
#include "storage.hpp"
#include "fat32.hpp"
#include "npfs.hpp"
#include "ntfs.hpp"

namespace micant::fs {

// Standard NT File Access Rights
inline constexpr uint32_t FILE_READ_DATA        = 0x0001;
inline constexpr uint32_t FILE_WRITE_DATA       = 0x0002;
inline constexpr uint32_t FILE_APPEND_DATA      = 0x0004;
inline constexpr uint32_t FILE_EXECUTE         = 0x0020;
inline constexpr uint32_t FILE_GENERIC_READ     = 0x00120089;
inline constexpr uint32_t FILE_GENERIC_WRITE    = 0x00120116;
inline constexpr uint32_t FILE_GENERIC_EXECUTE  = 0x001200A0;
inline constexpr uint32_t FILE_ALL_ACCESS       = 0x001F01FF;

// File Creation / Open Dispositions
inline constexpr uint32_t FILE_SUPERSEDE        = 0x00000000;
inline constexpr uint32_t FILE_OPEN             = 0x00000001;
inline constexpr uint32_t FILE_CREATE           = 0x00000002;
inline constexpr uint32_t FILE_OPEN_IF          = 0x00000003;
inline constexpr uint32_t FILE_OVERWRITE        = 0x00000004;
inline constexpr uint32_t FILE_OVERWRITE_IF     = 0x00000005;

// File Attributes
inline constexpr uint32_t FILE_ATTRIBUTE_READONLY  = 0x00000001;
inline constexpr uint32_t FILE_ATTRIBUTE_HIDDEN    = 0x00000002;
inline constexpr uint32_t FILE_ATTRIBUTE_SYSTEM    = 0x00000004;
inline constexpr uint32_t FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
inline constexpr uint32_t FILE_ATTRIBUTE_NORMAL    = 0x00000080;

// File Object Flags
inline constexpr uint32_t FO_SYNCHRONOUS_IO    = 0x00000010;
inline constexpr uint32_t FO_ALERTABLE_IO      = 0x00000020;
inline constexpr uint32_t FO_NO_INTERMEDIATE_BUFFERING = 0x00000040;

/**
 * @brief NT File Object (FILE_OBJECT)
 * Clean-room modern C++23 representation of an open file instance.
 */
class FileObject {
public:
    FileObject(
        io::DeviceObject* device,
        std::wstring_view fileName,
        uint32_t accessMask,
        uint32_t flags = FO_SYNCHRONOUS_IO
    ) : deviceObject_(device),
        fileName_(fileName),
        accessMask_(accessMask),
        flags_(flags) {}

    [[nodiscard]] io::DeviceObject* getDeviceObject() const noexcept { return deviceObject_; }
    [[nodiscard]] const std::wstring& getFileName() const noexcept { return fileName_; }
    [[nodiscard]] uint32_t getAccessMask() const noexcept { return accessMask_; }
    [[nodiscard]] uint32_t getFlags() const noexcept { return flags_; }
    [[nodiscard]] int64_t getCurrentByteOffset() const noexcept { return currentByteOffset_; }

    void setCurrentByteOffset(int64_t offset) noexcept { currentByteOffset_ = offset; }
    void advanceByteOffset(int64_t bytes) noexcept { currentByteOffset_ += bytes; }

    [[nodiscard]] bool isDirectory() const noexcept { return isDirectory_; }
    void setDirectory(bool isDir) noexcept { isDirectory_ = isDir; }

    [[nodiscard]] size_t getFileSize() const noexcept { return data_.size(); }
    [[nodiscard]] const std::vector<uint8_t>& getData() const noexcept { return data_; }
    std::vector<uint8_t>& getData() noexcept { return data_; }

    void writeData(size_t offset, std::span<const uint8_t> bytes) {
        if (offset + bytes.size() > data_.size()) {
            data_.resize(offset + bytes.size());
        }
        std::memcpy(data_.data() + offset, bytes.data(), bytes.size());
    }

    [[nodiscard]] void* getFsContext() const noexcept { return fsContext_; }
    void setFsContext(void* ctx) noexcept { fsContext_ = ctx; }

    [[nodiscard]] void* getFsContext2() const noexcept { return fsContext2_; }
    void setFsContext2(void* ctx) noexcept { fsContext2_ = ctx; }

private:
    io::DeviceObject* deviceObject_{nullptr};
    std::wstring fileName_;
    uint32_t accessMask_{0};
    uint32_t flags_{FO_SYNCHRONOUS_IO};
    int64_t currentByteOffset_{0};
    bool isDirectory_{false};
    std::vector<uint8_t> data_;
    void* fsContext_{nullptr};
    void* fsContext2_{nullptr};
};

/**
 * @brief Clean-Room FAT32 / VFS In-Memory Directory Entry
 */
struct VfsEntry {
    std::wstring name;
    uint32_t attributes{FILE_ATTRIBUTE_NORMAL};
    std::vector<uint8_t> content;
    std::unordered_map<std::wstring, std::shared_ptr<VfsEntry>> children;
    bool isDirectory{false};
};

/**
 * @brief Helper to invoke a device driver with an IRP.
 */
inline NtStatus IoCallDriver(io::DeviceObject* device, io::Irp* irp) {
    if (!device || !device->driverObject || !irp) {
        return NtStatus::InvalidDeviceRequest;
    }
    irp->deviceObject = device;
    return device->driverObject->dispatch(device, irp);
}

/**
 * @brief Fastfat / Virtual File System Driver
 * Clean-room NT driver supporting mounting, partition navigation, and file operations.
 */
class VirtualFileSystem {
public:
    static VirtualFileSystem& get() {
        static VirtualFileSystem instance;
        return instance;
    }

    void initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) return;

        // Register FastFAT driver object
        fastFatDriver_ = std::make_unique<io::DriverObject>();
        fastFatDriver_->driverName = L"\\Driver\\Fastfat";

        // Setup dispatch routines
        fastFatDriver_->setDispatch(io::IRP_MJ_CREATE, &VirtualFileSystem::dispatchCreate);
        fastFatDriver_->setDispatch(io::IRP_MJ_READ, &VirtualFileSystem::dispatchRead);
        fastFatDriver_->setDispatch(io::IRP_MJ_WRITE, &VirtualFileSystem::dispatchWrite);
        fastFatDriver_->setDispatch(io::IRP_MJ_CLOSE, &VirtualFileSystem::dispatchClose);

        // Create partition device node
        partitionDevice_ = io::IoManager::get().createDevice(
            fastFatDriver_.get(),
            L"\\Device\\Harddisk0\\Partition1",
            io::DeviceType::FileSystem
        );

        // Initialize IPC File Systems
        npfs::NamedPipeFileSystem::get().initialize();
        npfs::MailslotFileSystem::get().initialize();

        // Initialize root directory hierarchy
        rootEntry_ = std::make_shared<VfsEntry>();
        rootEntry_->name = L"";
        rootEntry_->isDirectory = true;
        rootEntry_->attributes = FILE_ATTRIBUTE_DIRECTORY;

        // Populate standard system directories
        createDirectoryInternal(L"Windows");
        createDirectoryInternal(L"Windows\\System32");
        createDirectoryInternal(L"Windows\\System32\\drivers");
        createDirectoryInternal(L"Windows\\System32\\config");
        createDirectoryInternal(L"Program Files");
        createDirectoryInternal(L"Users");
        createDirectoryInternal(L"Users\\Default");

        // Seed core NT system image stubs into System32
        std::string ntdllStub = "MZ-MICANT-NTDLL64-CLEANROOM-CORE-EXPORTS";
        std::vector<uint8_t> ntdllBytes(ntdllStub.begin(), ntdllStub.end());
        createFileInternal(L"Windows\\System32\\ntdll.dll", ntdllBytes);

        std::string kernel32Stub = "MZ-MICANT-KERNEL32-CLEANROOM-STUB";
        std::vector<uint8_t> kernel32Bytes(kernel32Stub.begin(), kernel32Stub.end());
        createFileInternal(L"Windows\\System32\\kernel32.dll", kernel32Bytes);

        std::string systemHiveStub = "regf-MICANT-SYSTEM-HIVE-V1";
        std::vector<uint8_t> hiveBytes(systemHiveStub.begin(), systemHiveStub.end());
        createFileInternal(L"Windows\\System32\\config\\SYSTEM", hiveBytes);

        initialized_ = true;
    }

    [[nodiscard]] io::DeviceObject* getPartitionDevice() const noexcept {
        return partitionDevice_.get();
    }

    NtStatus mountBlockDevice(std::shared_ptr<storage::IBlockDevice> device) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!device) return NtStatus::InvalidParameter;
        mountedDevice_ = device;
        fat32Fs_ = std::make_shared<fat32::Fat32FileSystem>();
        NtStatus st = fat32Fs_->mount(mountedDevice_);
        if (!NT_SUCCESS(st)) {
            fat32Fs_.reset();
            mountedDevice_.reset();
            return st;
        }
        return NtStatus::Success;
    }

    [[nodiscard]] std::shared_ptr<fat32::Fat32FileSystem> getMountedFat32() const noexcept {
        return fat32Fs_;
    }

    [[nodiscard]] std::shared_ptr<storage::IBlockDevice> getMountedBlockDevice() const noexcept {
        return mountedDevice_;
    }

    NtStatus mountNtfs(std::shared_ptr<storage::IBlockDevice> device) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!device) return NtStatus::InvalidParameter;
        ntfsFs_ = std::make_shared<ntfs::NtfsFileSystem>();
        NtStatus st = ntfsFs_->mount(device);
        if (!NT_SUCCESS(st)) {
            ntfsFs_.reset();
            return st;
        }
        return NtStatus::Success;
    }

    void setMountedNtfs(std::shared_ptr<ntfs::NtfsFileSystem> ntfs) {
        std::lock_guard<std::mutex> lock(mutex_);
        ntfsFs_ = ntfs;
    }

    [[nodiscard]] std::shared_ptr<ntfs::NtfsFileSystem> getMountedNtfs() const noexcept {
        return ntfsFs_;
    }

    NtStatus createOrOpenFile(
        std::wstring_view path,
        uint32_t desiredAccess,
        uint32_t disposition,
        std::shared_ptr<FileObject>& outFileObj
    ) {
        std::lock_guard<std::mutex> lock(mutex_);

        // 0. Check for Named Pipe path
        if (path.starts_with(L"\\\\.\\pipe\\") ||
            path.starts_with(L"\\??\\pipe\\") ||
            path.starts_with(L"\\DosDevices\\pipe\\") ||
            path.starts_with(L"\\Device\\NamedPipe\\") ||
            path.starts_with(L"pipe\\")) {
            
            std::shared_ptr<npfs::NamedPipeInstance> pipeInst;
            NtStatus st = npfs::NamedPipeFileSystem::get().openClientPipe(
                path, desiredAccess, 0, pipeInst
            );
            if (!NT_SUCCESS(st)) return st;

            outFileObj = std::make_shared<FileObject>(
                npfs::NamedPipeFileSystem::get().getDevice(),
                path, desiredAccess
            );
            outFileObj->setFsContext(pipeInst.get());
            outFileObj->setFsContext2(reinterpret_cast<void*>(static_cast<uintptr_t>(0))); // Client end
            openFiles_[outFileObj.get()] = nullptr;
            openPipeInstances_[outFileObj.get()] = pipeInst;
            return NtStatus::Success;
        }

        // 0.1 Check for Mailslot path
        if (path.starts_with(L"\\\\.\\mailslot\\") ||
            path.starts_with(L"\\??\\mailslot\\") ||
            path.starts_with(L"\\DosDevices\\mailslot\\") ||
            path.starts_with(L"\\Device\\Mailslot\\") ||
            path.starts_with(L"mailslot\\")) {

            auto slot = npfs::MailslotFileSystem::get().lookupMailslot(path);
            if (!slot) return NtStatus::MailslotNotFound;

            outFileObj = std::make_shared<FileObject>(
                npfs::MailslotFileSystem::get().getDevice(),
                path, desiredAccess
            );
            outFileObj->setFsContext(slot.get());
            outFileObj->setFsContext2(reinterpret_cast<void*>(static_cast<uintptr_t>(0))); // Client writer
            openFiles_[outFileObj.get()] = nullptr;
            openMailslots_[outFileObj.get()] = slot;
            return NtStatus::Success;
        }

        // 0.2 Check for NTFS Volume or Alternate Data Stream (ADS)
        std::wstring sPath(path);
        std::wstring streamName;
        size_t colonPos = sPath.find(L':', 3); // Skip drive letter e.g. C: or D:
        if (colonPos != std::wstring::npos) {
            streamName = sPath.substr(colonPos + 1);
            sPath = sPath.substr(0, colonPos);
        }

        if (ntfsFs_ && (path.starts_with(L"D:") || path.starts_with(L"d:") ||
                        path.starts_with(L"\\DosDevices\\D:") || path.starts_with(L"\\??\\D:") ||
                        path.starts_with(L"\\Device\\Harddisk0\\Partition2") || !streamName.empty())) {
            std::wstring normNtfs = normalizePath(sPath);
            if (normNtfs.starts_with(L"D:\\") || normNtfs.starts_with(L"d:\\")) {
                normNtfs = normNtfs.substr(3);
            }
            uint64_t recNum = 0;
            NtStatus lookupSt = ntfsFs_->lookupPath(normNtfs, recNum);
            if (!NT_SUCCESS(lookupSt)) {
                if (disposition == FILE_CREATE || disposition == FILE_OPEN_IF || disposition == FILE_OVERWRITE_IF) {
                    NtStatus crSt = ntfsFs_->createFile(normNtfs, FILE_ATTRIBUTE_NORMAL, recNum);
                    if (!NT_SUCCESS(crSt)) return crSt;
                } else {
                    return NtStatus::NoSuchFile;
                }
            }

            outFileObj = std::make_shared<FileObject>(partitionDevice_.get(), path, desiredAccess);
            openNtfsFiles_[outFileObj.get()] = { recNum, streamName };
            return NtStatus::Success;
        }

        // 1. Check if path targets a registered device node in \Device
        auto directDevice = io::IoManager::get().lookupDevice(path);
        if (directDevice) {
            outFileObj = std::make_shared<FileObject>(directDevice.get(), path, desiredAccess);
            openFiles_[outFileObj.get()] = nullptr; // Device handle
            
            io::Irp createIrp{};
            createIrp.majorFunction = io::IRP_MJ_CREATE;
            createIrp.deviceObject = directDevice.get();
            return IoCallDriver(directDevice.get(), &createIrp);
        }

        std::wstring normalized = normalizePath(path);

        auto entry = findEntry(normalized);
        if (entry) {
            // File exists
            if (disposition == FILE_CREATE) {
                return NtStatus::ObjectNameCollision;
            }
            if (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF || disposition == FILE_SUPERSEDE) {
                entry->content.clear();
            }

            outFileObj = std::make_shared<FileObject>(partitionDevice_.get(), normalized, desiredAccess);
            outFileObj->setDirectory(entry->isDirectory);
            outFileObj->getData() = entry->content;
            openFiles_[outFileObj.get()] = entry;
            return NtStatus::Success;
        }

        // File does not exist
        if (disposition == FILE_OPEN || disposition == FILE_OVERWRITE) {
            return NtStatus::NoSuchFile;
        }

        // Create new file
        auto newEntry = createPathEntries(normalized, false);
        if (!newEntry) {
            return NtStatus::ObjectPathNotFound;
        }

        outFileObj = std::make_shared<FileObject>(partitionDevice_.get(), normalized, desiredAccess);
        openFiles_[outFileObj.get()] = newEntry;
        return NtStatus::Success;
    }

    NtStatus readFile(
        FileObject* fileObj,
        void* buffer,
        uint32_t length,
        LargeInteger* byteOffset,
        uint32_t& bytesRead
    ) {
        if (!fileObj || !buffer) return NtStatus::InvalidParameter;
        std::lock_guard<std::mutex> lock(mutex_);

        if (fileObj->getFsContext()) {
            auto itP = openPipeInstances_.find(fileObj);
            if (itP != openPipeInstances_.end() && itP->second) {
                bool isServer = (reinterpret_cast<uintptr_t>(fileObj->getFsContext2()) == 1);
                return itP->second->read(isServer, buffer, length, bytesRead);
            }
            auto itM = openMailslots_.find(fileObj);
            if (itM != openMailslots_.end() && itM->second) {
                return itM->second->read(buffer, length, bytesRead, itM->second->getReadTimeout());
            }
        }

        auto itNtfs = openNtfsFiles_.find(fileObj);
        if (itNtfs != openNtfsFiles_.end() && ntfsFs_) {
            int64_t offset = byteOffset ? byteOffset->quadPart : fileObj->getCurrentByteOffset();
            if (offset < 0) offset = 0;
            uint64_t ntfsBytes = 0;
            NtStatus st = ntfsFs_->readFile(itNtfs->second.first, itNtfs->second.second, buffer, length, static_cast<uint64_t>(offset), ntfsBytes);
            bytesRead = static_cast<uint32_t>(ntfsBytes);
            if (NT_SUCCESS(st) && !byteOffset) {
                fileObj->advanceByteOffset(bytesRead);
            }
            return st;
        }

        auto it = openFiles_.find(fileObj);
        if (it == openFiles_.end() || !it->second) return NtStatus::InvalidHandle;

        auto entry = it->second;
        int64_t offset = byteOffset ? byteOffset->quadPart : fileObj->getCurrentByteOffset();
        if (offset < 0 || static_cast<size_t>(offset) >= entry->content.size()) {
            bytesRead = 0;
            return (entry->content.empty() && offset == 0) ? NtStatus::Success : NtStatus::EndOfFile;
        }

        size_t available = entry->content.size() - static_cast<size_t>(offset);
        size_t toRead = std::min<size_t>(length, available);
        std::memcpy(buffer, entry->content.data() + offset, toRead);
        bytesRead = static_cast<uint32_t>(toRead);

        if (!byteOffset) {
            fileObj->advanceByteOffset(toRead);
        }

        return NtStatus::Success;
    }

    NtStatus writeFile(
        FileObject* fileObj,
        const void* buffer,
        uint32_t length,
        LargeInteger* byteOffset,
        uint32_t& bytesWritten
    ) {
        if (!fileObj || !buffer) return NtStatus::InvalidParameter;
        std::lock_guard<std::mutex> lock(mutex_);

        if (fileObj->getFsContext()) {
            auto itP = openPipeInstances_.find(fileObj);
            if (itP != openPipeInstances_.end() && itP->second) {
                bool isServer = (reinterpret_cast<uintptr_t>(fileObj->getFsContext2()) == 1);
                return itP->second->write(isServer, buffer, length, bytesWritten);
            }
            auto itM = openMailslots_.find(fileObj);
            if (itM != openMailslots_.end() && itM->second) {
                bytesWritten = length;
                return itM->second->write(buffer, length);
            }
        }

        auto itNtfs = openNtfsFiles_.find(fileObj);
        if (itNtfs != openNtfsFiles_.end() && ntfsFs_) {
            int64_t offset = byteOffset ? byteOffset->quadPart : fileObj->getCurrentByteOffset();
            if (offset < 0) offset = 0;
            uint64_t ntfsBytes = 0;
            NtStatus st = ntfsFs_->writeFile(itNtfs->second.first, itNtfs->second.second, buffer, length, static_cast<uint64_t>(offset), ntfsBytes);
            bytesWritten = static_cast<uint32_t>(ntfsBytes);
            if (NT_SUCCESS(st) && !byteOffset) {
                fileObj->advanceByteOffset(bytesWritten);
            }
            return st;
        }

        auto it = openFiles_.find(fileObj);
        if (it == openFiles_.end() || !it->second) return NtStatus::InvalidHandle;

        auto entry = it->second;
        int64_t offset = byteOffset ? byteOffset->quadPart : fileObj->getCurrentByteOffset();
        if (offset < 0) offset = 0;

        size_t requiredSize = static_cast<size_t>(offset) + length;
        if (requiredSize > entry->content.size()) {
            entry->content.resize(requiredSize);
        }

        std::memcpy(entry->content.data() + offset, buffer, length);
        bytesWritten = length;

        if (!byteOffset) {
            fileObj->advanceByteOffset(length);
        }

        // Synchronize in-memory file object data
        fileObj->getData() = entry->content;
        return NtStatus::Success;
    }

    void closeFile(FileObject* fileObj) {
        if (!fileObj) return;
        std::lock_guard<std::mutex> lock(mutex_);
        auto itP = openPipeInstances_.find(fileObj);
        if (itP != openPipeInstances_.end()) {
            if (itP->second) {
                bool isServer = (reinterpret_cast<uintptr_t>(fileObj->getFsContext2()) == 1);
                if (isServer) {
                    itP->second->disconnectServer();
                } else {
                    itP->second->clientClose();
                }
            }
            openPipeInstances_.erase(itP);
        }
        openMailslots_.erase(fileObj);
        openNtfsFiles_.erase(fileObj);
        openFiles_.erase(fileObj);
    }

    std::shared_ptr<FileObject> registerServerPipe(
        std::shared_ptr<npfs::NamedPipeInstance> pipeInst,
        uint32_t desiredAccess
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto fileObj = std::make_shared<FileObject>(
            npfs::NamedPipeFileSystem::get().getDevice(),
            pipeInst->getName(), desiredAccess
        );
        fileObj->setFsContext(pipeInst.get());
        fileObj->setFsContext2(reinterpret_cast<void*>(static_cast<uintptr_t>(1))); // Server end
        openFiles_[fileObj.get()] = nullptr;
        openPipeInstances_[fileObj.get()] = pipeInst;
        return fileObj;
    }

    std::shared_ptr<FileObject> registerServerMailslot(
        std::shared_ptr<npfs::Mailslot> slot
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto fileObj = std::make_shared<FileObject>(
            npfs::MailslotFileSystem::get().getDevice(),
            slot->getName(), FILE_GENERIC_READ
        );
        fileObj->setFsContext(slot.get());
        fileObj->setFsContext2(reinterpret_cast<void*>(static_cast<uintptr_t>(1))); // Server reader
        openFiles_[fileObj.get()] = nullptr;
        openMailslots_[fileObj.get()] = slot;
        return fileObj;
    }

    std::shared_ptr<npfs::NamedPipeInstance> getPipeInstance(FileObject* fileObj) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = openPipeInstances_.find(fileObj);
        if (it != openPipeInstances_.end()) return it->second;
        return nullptr;
    }

    std::shared_ptr<npfs::Mailslot> getMailslot(FileObject* fileObj) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = openMailslots_.find(fileObj);
        if (it != openMailslots_.end()) return it->second;
        return nullptr;
    }

    struct DirectoryEntry {
        std::wstring name;
        uint32_t attributes{0};
        size_t size{0};
        bool isDirectory{false};
    };

    NtStatus createDirectory(std::wstring_view path) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring norm = normalizePath(path);
        if (findEntry(norm)) return NtStatus::ObjectNameCollision;
        auto entry = createPathEntries(norm, true);
        return entry ? NtStatus::Success : NtStatus::ObjectPathNotFound;
    }

    NtStatus deleteFile(std::wstring_view path) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring norm = normalizePath(path);
        size_t lastSlash = norm.find_last_of(L'\\');
        std::wstring parentPath = (lastSlash == std::wstring::npos) ? L"" : norm.substr(0, lastSlash);
        std::wstring fileName = (lastSlash == std::wstring::npos) ? norm : norm.substr(lastSlash + 1);

        auto parent = findEntry(parentPath);
        if (!parent || !parent->isDirectory) return NtStatus::ObjectPathNotFound;

        auto it = parent->children.find(fileName);
        if (it == parent->children.end()) return NtStatus::NoSuchFile;
        if (it->second->isDirectory) return NtStatus::FileIsADirectory;

        parent->children.erase(it);
        return NtStatus::Success;
    }

    NtStatus removeDirectory(std::wstring_view path) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring norm = normalizePath(path);
        size_t lastSlash = norm.find_last_of(L'\\');
        std::wstring parentPath = (lastSlash == std::wstring::npos) ? L"" : norm.substr(0, lastSlash);
        std::wstring dirName = (lastSlash == std::wstring::npos) ? norm : norm.substr(lastSlash + 1);

        auto parent = findEntry(parentPath);
        if (!parent || !parent->isDirectory) return NtStatus::ObjectPathNotFound;

        auto it = parent->children.find(dirName);
        if (it == parent->children.end()) return NtStatus::NoSuchFile;
        if (!it->second->isDirectory) return NtStatus::NotADirectory;
        if (!it->second->children.empty()) return NtStatus::DirectoryNotEmpty;

        parent->children.erase(it);
        return NtStatus::Success;
    }

    NtStatus removeDirectoryRecursive(std::wstring_view path) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring norm = normalizePath(path);
        size_t lastSlash = norm.find_last_of(L'\\');
        std::wstring parentPath = (lastSlash == std::wstring::npos) ? L"" : norm.substr(0, lastSlash);
        std::wstring dirName = (lastSlash == std::wstring::npos) ? norm : norm.substr(lastSlash + 1);

        auto parent = findEntry(parentPath);
        if (!parent || !parent->isDirectory) return NtStatus::ObjectPathNotFound;

        auto it = parent->children.find(dirName);
        if (it == parent->children.end()) return NtStatus::NoSuchFile;
        if (!it->second->isDirectory) return NtStatus::NotADirectory;

        parent->children.erase(it);
        return NtStatus::Success;
    }

    NtStatus queryFileAttributes(std::wstring_view path, uint32_t& attributes) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring norm = normalizePath(path);
        auto entry = findEntry(norm);
        if (!entry) return NtStatus::NoSuchFile;
        attributes = entry->attributes;
        return NtStatus::Success;
    }

    NtStatus setFileAttributes(std::wstring_view path, uint32_t attributes) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring norm = normalizePath(path);
        auto entry = findEntry(norm);
        if (!entry) return NtStatus::NoSuchFile;
        entry->attributes = attributes;
        return NtStatus::Success;
    }

    NtStatus queryDirectory(std::wstring_view path, std::vector<DirectoryEntry>& entries) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring norm = normalizePath(path);
        auto entry = findEntry(norm);
        if (!entry) return NtStatus::NoSuchFile;
        if (!entry->isDirectory) return NtStatus::NotADirectory;

        entries.clear();
        for (const auto& [name, child] : entry->children) {
            entries.push_back(DirectoryEntry{
                .name = name,
                .attributes = child->attributes,
                .size = child->content.size(),
                .isDirectory = child->isDirectory
            });
        }
        return NtStatus::Success;
    }


private:
    VirtualFileSystem() = default;

    static NtStatus dispatchCreate(io::DeviceObject* dev, io::Irp* irp) {
        if (!irp) return NtStatus::InvalidDeviceRequest;
        irp->ioStatus.status = NtStatus::Success;
        irp->ioStatus.information = 1; // FILE_OPENED
        return NtStatus::Success;
    }

    static NtStatus dispatchRead(io::DeviceObject* dev, io::Irp* irp) {
        if (!irp || !irp->userBuffer) return NtStatus::InvalidParameter;
        irp->ioStatus.status = NtStatus::Success;
        return NtStatus::Success;
    }

    static NtStatus dispatchWrite(io::DeviceObject* dev, io::Irp* irp) {
        if (!irp || !irp->userBuffer) return NtStatus::InvalidParameter;
        irp->ioStatus.status = NtStatus::Success;
        return NtStatus::Success;
    }

    static NtStatus dispatchClose(io::DeviceObject* dev, io::Irp* irp) {
        if (!irp) return NtStatus::InvalidParameter;
        irp->ioStatus.status = NtStatus::Success;
        return NtStatus::Success;
    }

    std::wstring normalizePath(std::wstring_view path) const {
        std::wstring res(path);
        // Strip DOS drive prefix like DosDevices/C: or ??/C: or C:
        if (res.starts_with(L"\\DosDevices\\C:\\")) {
            res = res.substr(14);
        } else if (res.starts_with(L"\\??\\C:\\")) {
            res = res.substr(7);
        } else if (res.starts_with(L"C:\\") || res.starts_with(L"c:\\")) {
            res = res.substr(3);
        } else if (res.starts_with(L"\\")) {
            res = res.substr(1);
        }
        return res;
    }

    std::shared_ptr<VfsEntry> findEntry(std::wstring_view path) const {
        if (path.empty() || path == L".") return rootEntry_;

        std::shared_ptr<VfsEntry> current = rootEntry_;
        size_t start = 0;
        while (start < path.size()) {
            size_t nextSlash = path.find(L'\\', start);
            std::wstring part = (nextSlash == std::wstring_view::npos) 
                ? std::wstring(path.substr(start)) 
                : std::wstring(path.substr(start, nextSlash - start));

            if (!part.empty()) {
                auto it = current->children.find(part);
                if (it == current->children.end()) return nullptr;
                current = it->second;
            }

            if (nextSlash == std::wstring_view::npos) break;
            start = nextSlash + 1;
        }
        return current;
    }

    std::shared_ptr<VfsEntry> createPathEntries(std::wstring_view path, bool isDir) {
        std::shared_ptr<VfsEntry> current = rootEntry_;
        size_t start = 0;
        while (start < path.size()) {
            size_t nextSlash = path.find(L'\\', start);
            std::wstring part = (nextSlash == std::wstring_view::npos) 
                ? std::wstring(path.substr(start)) 
                : std::wstring(path.substr(start, nextSlash - start));

            bool isLast = (nextSlash == std::wstring_view::npos);
            if (!part.empty()) {
                auto it = current->children.find(part);
                if (it == current->children.end()) {
                    auto newEntry = std::make_shared<VfsEntry>();
                    newEntry->name = part;
                    newEntry->isDirectory = isLast ? isDir : true;
                    newEntry->attributes = newEntry->isDirectory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
                    current->children[part] = newEntry;
                    current = newEntry;
                } else {
                    current = it->second;
                }
            }

            if (nextSlash == std::wstring_view::npos) break;
            start = nextSlash + 1;
        }
        return current;
    }

    void createDirectoryInternal(std::wstring_view path) {
        createPathEntries(path, true);
    }

    void createFileInternal(std::wstring_view path, std::span<const uint8_t> data) {
        auto entry = createPathEntries(path, false);
        if (entry) {
            entry->content.assign(data.begin(), data.end());
        }
    }

    bool initialized_{false};
    std::mutex mutex_;
    std::unique_ptr<io::DriverObject> fastFatDriver_;
    std::shared_ptr<io::DeviceObject> partitionDevice_;
    std::shared_ptr<VfsEntry> rootEntry_;
    std::unordered_map<FileObject*, std::shared_ptr<VfsEntry>> openFiles_;
    std::unordered_map<FileObject*, std::shared_ptr<npfs::NamedPipeInstance>> openPipeInstances_;
    std::unordered_map<FileObject*, std::shared_ptr<npfs::Mailslot>> openMailslots_;
    std::shared_ptr<storage::IBlockDevice> mountedDevice_;
    std::shared_ptr<fat32::Fat32FileSystem> fat32Fs_;
    std::shared_ptr<ntfs::NtfsFileSystem> ntfsFs_;
    std::unordered_map<FileObject*, std::pair<uint64_t, std::wstring>> openNtfsFiles_;
};

} // namespace micant::fs
