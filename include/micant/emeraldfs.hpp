// ============================================================================
// MicaNT: EmeraldFS - Sovereign Clean-Room Storage & File System Architecture
// 
// Named in tribute to Dave Cutler's VMS Files-11 heritage and Microsoft's 1991
// Cairo Object File System (OFS) project (internally codenamed "Emerald").
//
// Strict Clean-Room Implementation in modern ISO C++23.
// Zero proprietary code or leaked markers. References open public NTFS/FAT specs.
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "storage.hpp"
#include "ntfs.hpp"
#include "fat32.hpp"
#include "fs.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <optional>

namespace micant::emeraldfs {

// ============================================================================
// 1. EmeraldFS Type Aliases & Core Contracts
// ============================================================================

using FileSystem        = ntfs::NtfsFileSystem;
using FileRecord        = ntfs::NtfsFileRecord;
using Journal           = ntfs::LogFileJournal;
using LogOperation      = ntfs::LogOperation;
using BootRecord        = ntfs::NtfsBootRecord;
using IBlockDevice      = storage::IBlockDevice;
using RamDiskDevice     = storage::RamDiskDevice;

enum class FileSystemType : uint8_t {
    Unknown = 0,
    EmeraldNTFS,
    EmeraldFAT32
};

struct StreamInfo {
    std::wstring name;
    uint64_t size{0};
};

struct FileMetadata {
    uint64_t recordNumber{0};
    std::wstring path;
    uint32_t attributes{0};
    uint64_t primarySize{0};
    bool isDirectory{false};
    std::vector<StreamInfo> alternateStreams;
};

// ============================================================================
// 2. EmeraldVolumeManager - Unified Sovereign Volume Engine
// ============================================================================

class EmeraldVolumeManager {
public:
    static EmeraldVolumeManager& get() {
        static EmeraldVolumeManager instance;
        return instance;
    }

    /**
     * @brief Formats a block device with EmeraldFS (NTFS MFT format).
     */
    NtStatus formatEmeraldFS(
        IBlockDevice& device,
        uint32_t clusterSize = ntfs::DEFAULT_CLUSTER_SIZE,
        std::wstring_view volumeLabel = L"EmeraldFS Volume"
    ) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto fs = std::make_unique<FileSystem>();
        NtStatus st = fs->format(device, clusterSize, volumeLabel);
        if (NT_SUCCESS(st)) {
            m_ntfsInstance = std::move(fs);
            m_fsType = FileSystemType::EmeraldNTFS;
        }
        return st;
    }

    /**
     * @brief Mounts an existing volume and auto-detects EmeraldFS (NTFS) or FAT32.
     */
    NtStatus mountVolume(std::shared_ptr<IBlockDevice> device) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (!device) return NtStatus::InvalidParameter;

        m_device = device;
        std::vector<uint8_t> sector0(device->getBlockSize(), 0);
        NtStatus st = device->readBlocks(0, 1, sector0.data());
        if (!NT_SUCCESS(st)) return st;

        // 1. Probe for NTFS / EmeraldFS signature
        if (std::memcmp(sector0.data() + 3, "NTFS    ", 8) == 0) {
            if (!m_ntfsInstance) {
                m_ntfsInstance = std::make_unique<FileSystem>();
            }
            NtStatus stMount = m_ntfsInstance->mount(device);
            if (NT_SUCCESS(stMount)) {
                m_fsType = FileSystemType::EmeraldNTFS;
                return NtStatus::Success;
            }
        }

        // 2. Probe for FAT32
        if (std::memcmp(sector0.data() + 82, "FAT32   ", 8) == 0) {
            m_fsType = FileSystemType::EmeraldFAT32;
            return NtStatus::Success;
        }

        m_fsType = FileSystemType::Unknown;
        return NtStatus::UnrecognizedVolume;
    }

    [[nodiscard]] FileSystemType getMountedType() const noexcept {
        return m_fsType;
    }

    // ========================================================================
    // High-Level Stream & File Operations
    // ========================================================================

    /**
     * @brief Creates a file on the mounted EmeraldFS volume.
     */
    NtStatus createFile(std::wstring_view path, uint32_t attributes, uint64_t& outRecordNumber) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (m_fsType != FileSystemType::EmeraldNTFS || !m_ntfsInstance) {
            return NtStatus::VolumeNotMounted;
        }
        return m_ntfsInstance->createFile(path, attributes, outRecordNumber);
    }

    /**
     * @brief Creates a directory on the mounted EmeraldFS volume.
     */
    NtStatus createDirectory(std::wstring_view path, uint64_t& outRecordNumber) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (m_fsType != FileSystemType::EmeraldNTFS || !m_ntfsInstance) {
            return NtStatus::VolumeNotMounted;
        }
        return m_ntfsInstance->createDirectory(path, outRecordNumber);
    }

    /**
     * @brief Writes data to the primary unnamed $DATA stream of a file.
     */
    NtStatus writePrimaryStream(
        uint64_t recordNumber,
        const void* buffer,
        uint64_t length,
        uint64_t offset,
        uint64_t& bytesWritten
    ) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (m_fsType != FileSystemType::EmeraldNTFS || !m_ntfsInstance) {
            return NtStatus::VolumeNotMounted;
        }
        return m_ntfsInstance->writeFile(recordNumber, L"", buffer, length, offset, bytesWritten);
    }

    /**
     * @brief Reads data from the primary unnamed $DATA stream of a file.
     */
    NtStatus readPrimaryStream(
        uint64_t recordNumber,
        void* buffer,
        uint64_t length,
        uint64_t offset,
        uint64_t& bytesRead
    ) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (m_fsType != FileSystemType::EmeraldNTFS || !m_ntfsInstance) {
            return NtStatus::VolumeNotMounted;
        }
        return m_ntfsInstance->readFile(recordNumber, L"", buffer, length, offset, bytesRead);
    }

    /**
     * @brief Writes data to an Alternate Data Stream (ADS) (e.g. file.txt:Zone.Identifier).
     */
    NtStatus writeAlternateStream(
        uint64_t recordNumber,
        std::wstring_view streamName,
        const void* buffer,
        uint64_t length,
        uint64_t offset,
        uint64_t& bytesWritten
    ) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (m_fsType != FileSystemType::EmeraldNTFS || !m_ntfsInstance) {
            return NtStatus::VolumeNotMounted;
        }
        if (streamName.empty()) return NtStatus::InvalidParameter;
        return m_ntfsInstance->writeFile(recordNumber, streamName, buffer, length, offset, bytesWritten);
    }

    /**
     * @brief Reads data from an Alternate Data Stream (ADS).
     */
    NtStatus readAlternateStream(
        uint64_t recordNumber,
        std::wstring_view streamName,
        void* buffer,
        uint64_t length,
        uint64_t offset,
        uint64_t& bytesRead
    ) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (m_fsType != FileSystemType::EmeraldNTFS || !m_ntfsInstance) {
            return NtStatus::VolumeNotMounted;
        }
        if (streamName.empty()) return NtStatus::InvalidParameter;
        return m_ntfsInstance->readFile(recordNumber, streamName, buffer, length, offset, bytesRead);
    }

    /**
     * @brief Resolves file path to record number.
     */
    NtStatus lookupPath(std::wstring_view path, uint64_t& outRecordNumber) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (m_fsType != FileSystemType::EmeraldNTFS || !m_ntfsInstance) {
            return NtStatus::VolumeNotMounted;
        }
        return m_ntfsInstance->lookupPath(path, outRecordNumber);
    }

    /**
     * @brief Retrieves detailed metadata for a file, including all alternate streams.
     */
    NtStatus getFileMetadata(uint64_t recordNumber, FileMetadata& outMetadata) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (m_fsType != FileSystemType::EmeraldNTFS || !m_ntfsInstance) {
            return NtStatus::VolumeNotMounted;
        }

        const auto* rec = m_ntfsInstance->getRecord(recordNumber);
        if (!rec || !(rec->flags & ntfs::MFT_RECORD_IN_USE)) {
            return NtStatus::NoSuchFile;
        }

        outMetadata.recordNumber = recordNumber;
        outMetadata.path = rec->fileName;
        outMetadata.attributes = rec->stdInfo.dosPermissions;
        outMetadata.primarySize = rec->primaryData.size();
        outMetadata.isDirectory = (rec->flags & ntfs::MFT_RECORD_DIRECTORY) != 0;

        outMetadata.alternateStreams.clear();
        for (const auto& [name, data] : rec->alternateStreams) {
            outMetadata.alternateStreams.push_back({ name, data.size() });
        }
        return NtStatus::Success;
    }

    /**
     * @brief Returns the underlying journal for auditing and transaction verification.
     */
    Journal* getJournal() noexcept {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return m_ntfsInstance ? m_ntfsInstance->getJournal() : nullptr;
    }

private:
    EmeraldVolumeManager() = default;

    mutable std::recursive_mutex mutex_;
    std::shared_ptr<IBlockDevice> m_device;
    std::unique_ptr<FileSystem> m_ntfsInstance;
    FileSystemType m_fsType{ FileSystemType::Unknown };
};

} // namespace micant::emeraldfs
