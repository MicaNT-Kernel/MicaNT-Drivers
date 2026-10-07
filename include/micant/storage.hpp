#pragma once

/**
 * @file storage.hpp
 * @brief Clean-Room Block Device & Partition Storage Subsystem (storage / disk / partmgr).
 *
 * Implements the standard Windows NT storage stack abstractions:
 * - IBlockDevice (Abstract block I/O contract)
 * - RamDiskDevice (In-memory block device)
 * - PartitionDevice (Slice-based sub-device wrapper)
 * - MBR (Master Boot Record) & GPT (GUID Partition Table) parsers
 *
 * References: Microsoft Learn Storage Driver Architecture & UEFI Specification.
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <span>
#include <cstring>
#include <algorithm>
#include "ntdef.hpp"
#include "ntstatus.hpp"

namespace micant::storage {

// Standard Sector Sizing
inline constexpr uint32_t SECTOR_SIZE_512 = 512;
inline constexpr uint32_t SECTOR_SIZE_4K  = 4096;

// MBR Partition Types
inline constexpr uint8_t MBR_TYPE_EMPTY       = 0x00;
inline constexpr uint8_t MBR_TYPE_FAT12       = 0x01;
inline constexpr uint8_t MBR_TYPE_FAT16_SM    = 0x04;
inline constexpr uint8_t MBR_TYPE_EXTENDED    = 0x05;
inline constexpr uint8_t MBR_TYPE_FAT16       = 0x06;
inline constexpr uint8_t MBR_TYPE_NTFS_EXFAT  = 0x07;
inline constexpr uint8_t MBR_TYPE_FAT32_CHS   = 0x0B;
inline constexpr uint8_t MBR_TYPE_FAT32_LBA   = 0x0C;
inline constexpr uint8_t MBR_TYPE_FAT16_LBA   = 0x0E;
inline constexpr uint8_t MBR_TYPE_GPT_PROTECT = 0xEE;

inline constexpr uint16_t MBR_SIGNATURE       = 0xAA55;
inline constexpr uint64_t GPT_SIGNATURE       = 0x5452415020494645ULL; // "EFI PART"

/**
 * @brief Abstract Block Device Interface (IBlockDevice).
 */
class IBlockDevice {
public:
    virtual ~IBlockDevice() = default;

    [[nodiscard]] virtual NtStatus readBlocks(uint64_t lba, uint32_t count, void* buffer) = 0;
    [[nodiscard]] virtual NtStatus writeBlocks(uint64_t lba, uint32_t count, const void* buffer) = 0;
    [[nodiscard]] virtual uint32_t getBlockSize() const noexcept = 0;
    [[nodiscard]] virtual uint64_t getTotalBlocks() const noexcept = 0;
    [[nodiscard]] virtual uint64_t getTotalBytes() const noexcept {
        return getTotalBlocks() * getBlockSize();
    }
    [[nodiscard]] virtual const std::wstring& getDeviceName() const noexcept = 0;
};

/**
 * @brief RamDisk Block Device.
 * High-speed in-memory block storage simulating physical disk media.
 */
class RamDiskDevice : public IBlockDevice {
public:
    RamDiskDevice(std::wstring_view name, uint64_t totalBytes, uint32_t blockSize = SECTOR_SIZE_512)
        : name_(name), blockSize_(blockSize) {
        if (blockSize_ == 0) blockSize_ = SECTOR_SIZE_512;
        totalBlocks_ = (totalBytes + blockSize_ - 1) / blockSize_;
        storage_.resize(static_cast<size_t>(totalBlocks_ * blockSize_), 0);
    }

    [[nodiscard]] NtStatus readBlocks(uint64_t lba, uint32_t count, void* buffer) override {
        if (!buffer || count == 0) return NtStatus::InvalidParameter;
        if (lba + count > totalBlocks_) return NtStatus::EndOfFile;

        std::lock_guard<std::mutex> lock(mutex_);
        size_t byteOffset = static_cast<size_t>(lba * blockSize_);
        size_t byteCount = static_cast<size_t>(count * blockSize_);
        std::memcpy(buffer, storage_.data() + byteOffset, byteCount);
        return NtStatus::Success;
    }

    [[nodiscard]] NtStatus writeBlocks(uint64_t lba, uint32_t count, const void* buffer) override {
        if (!buffer || count == 0) return NtStatus::InvalidParameter;
        if (lba + count > totalBlocks_) return NtStatus::DiskFull;

        std::lock_guard<std::mutex> lock(mutex_);
        size_t byteOffset = static_cast<size_t>(lba * blockSize_);
        size_t byteCount = static_cast<size_t>(count * blockSize_);
        std::memcpy(storage_.data() + byteOffset, buffer, byteCount);
        return NtStatus::Success;
    }

    [[nodiscard]] uint32_t getBlockSize() const noexcept override { return blockSize_; }
    [[nodiscard]] uint64_t getTotalBlocks() const noexcept override { return totalBlocks_; }
    [[nodiscard]] const std::wstring& getDeviceName() const noexcept override { return name_; }

    [[nodiscard]] uint8_t* rawData() noexcept { return storage_.data(); }
    [[nodiscard]] const uint8_t* rawData() const noexcept { return storage_.data(); }

private:
    std::wstring name_;
    uint32_t blockSize_{SECTOR_SIZE_512};
    uint64_t totalBlocks_{0};
    std::vector<uint8_t> storage_;
    mutable std::mutex mutex_;
};

/**
 * @brief Partition Device.
 * Wraps an offset slice of a parent block device representing a disk partition.
 */
class PartitionDevice : public IBlockDevice {
public:
    PartitionDevice(
        std::wstring_view name,
        std::shared_ptr<IBlockDevice> parentDevice,
        uint64_t startLba,
        uint64_t blockCount
    ) : name_(name),
        parentDevice_(std::move(parentDevice)),
        startLba_(startLba),
        blockCount_(blockCount) {}

    [[nodiscard]] NtStatus readBlocks(uint64_t lba, uint32_t count, void* buffer) override {
        if (!parentDevice_) return NtStatus::DeviceNotReady;
        if (lba + count > blockCount_) return NtStatus::EndOfFile;
        return parentDevice_->readBlocks(startLba_ + lba, count, buffer);
    }

    [[nodiscard]] NtStatus writeBlocks(uint64_t lba, uint32_t count, const void* buffer) override {
        if (!parentDevice_) return NtStatus::DeviceNotReady;
        if (lba + count > blockCount_) return NtStatus::DiskFull;
        return parentDevice_->writeBlocks(startLba_ + lba, count, buffer);
    }

    [[nodiscard]] uint32_t getBlockSize() const noexcept override {
        return parentDevice_ ? parentDevice_->getBlockSize() : SECTOR_SIZE_512;
    }

    [[nodiscard]] uint64_t getTotalBlocks() const noexcept override { return blockCount_; }
    [[nodiscard]] uint64_t getStartLba() const noexcept { return startLba_; }
    [[nodiscard]] const std::wstring& getDeviceName() const noexcept override { return name_; }

private:
    std::wstring name_;
    std::shared_ptr<IBlockDevice> parentDevice_;
    uint64_t startLba_{0};
    uint64_t blockCount_{0};
};

#pragma pack(push, 1)

/**
 * @brief MBR 16-byte Partition Table Entry.
 */
struct MbrPartitionEntry {
    uint8_t  bootIndicator;    // 0x80 = Active / Bootable
    uint8_t  startHead;
    uint8_t  startSector : 6;
    uint8_t  startCylinderHigh : 2;
    uint8_t  startCylinderLow;
    uint8_t  partitionType;    // 0x0B/0x0C = FAT32, 0x07 = NTFS/exFAT
    uint8_t  endHead;
    uint8_t  endSector : 6;
    uint8_t  endCylinderHigh : 2;
    uint8_t  endCylinderLow;
    uint32_t startLba;
    uint32_t sectorCount;
};

/**
 * @brief Master Boot Record (Sector 0).
 */
struct MasterBootRecord {
    uint8_t bootstrapCode[446];
    MbrPartitionEntry partitions[4];
    uint16_t signature; // 0xAA55
};

/**
 * @brief GPT Header (LBA 1).
 */
struct GptHeader {
    uint64_t signature; // "EFI PART" (0x5452415020494645ULL)
    uint32_t revision;
    uint32_t headerSize;
    uint32_t headerCrc32;
    uint32_t reserved;
    uint64_t currentLba;
    uint64_t backupLba;
    uint64_t firstUsableLba;
    uint64_t lastUsableLba;
    uint8_t  diskGuid[16];
    uint64_t partitionEntryLba;
    uint32_t numPartitionEntries;
    uint32_t sizeOfPartitionEntry;
    uint32_t partitionEntryArrayCrc32;
};

/**
 * @brief GPT 128-byte Partition Entry.
 */
struct GptPartitionEntry {
    uint8_t  partitionTypeGuid[16];
    uint8_t  uniquePartitionGuid[16];
    uint64_t startingLba;
    uint64_t endingLba;
    uint64_t attributes;
    wchar_t  partitionName[36];
};

#pragma pack(pop)

/**
 * @brief Partition Manager Utilities.
 */
class PartitionManager {
public:
    static NtStatus parseMbr(IBlockDevice& device, std::vector<MbrPartitionEntry>& outPartitions) {
        outPartitions.clear();
        if (device.getBlockSize() < sizeof(MasterBootRecord)) {
            return NtStatus::InvalidParameter;
        }

        std::vector<uint8_t> sector(device.getBlockSize());
        NtStatus st = device.readBlocks(0, 1, sector.data());
        if (!NT_SUCCESS(st)) return st;

        const auto* mbr = reinterpret_cast<const MasterBootRecord*>(sector.data());
        if (mbr->signature != MBR_SIGNATURE) {
            return NtStatus::UnrecognizedVolume;
        }

        for (int i = 0; i < 4; ++i) {
            const auto& p = mbr->partitions[i];
            if (p.partitionType != MBR_TYPE_EMPTY && p.sectorCount > 0) {
                outPartitions.push_back(p);
            }
        }
        return NtStatus::Success;
    }

    static NtStatus writeMbr(IBlockDevice& device, const std::vector<MbrPartitionEntry>& partitions) {
        if (partitions.size() > 4) return NtStatus::InvalidParameter;
        if (device.getBlockSize() < sizeof(MasterBootRecord)) return NtStatus::InvalidParameter;

        std::vector<uint8_t> sector(device.getBlockSize(), 0);
        auto* mbr = reinterpret_cast<MasterBootRecord*>(sector.data());
        mbr->signature = MBR_SIGNATURE;

        for (size_t i = 0; i < partitions.size(); ++i) {
            mbr->partitions[i] = partitions[i];
        }

        return device.writeBlocks(0, 1, sector.data());
    }

    static NtStatus parseGpt(IBlockDevice& device, std::vector<GptPartitionEntry>& outEntries) {
        outEntries.clear();
        if (device.getBlockSize() < sizeof(GptHeader)) return NtStatus::InvalidParameter;

        std::vector<uint8_t> sector(device.getBlockSize());
        NtStatus st = device.readBlocks(1, 1, sector.data()); // GPT is at LBA 1
        if (!NT_SUCCESS(st)) return st;

        const auto* hdr = reinterpret_cast<const GptHeader*>(sector.data());
        if (hdr->signature != GPT_SIGNATURE) {
            return NtStatus::UnrecognizedVolume;
        }

        uint32_t entrySize = hdr->sizeOfPartitionEntry;
        if (entrySize < sizeof(GptPartitionEntry)) entrySize = sizeof(GptPartitionEntry);
        uint32_t totalEntries = hdr->numPartitionEntries;
        uint32_t entriesPerSector = device.getBlockSize() / entrySize;
        if (entriesPerSector == 0) return NtStatus::InvalidParameter;

        uint32_t sectorsToRead = (totalEntries + entriesPerSector - 1) / entriesPerSector;
        std::vector<uint8_t> entryBuffer(sectorsToRead * device.getBlockSize());
        st = device.readBlocks(hdr->partitionEntryLba, sectorsToRead, entryBuffer.data());
        if (!NT_SUCCESS(st)) return st;

        for (uint32_t i = 0; i < totalEntries; ++i) {
            const auto* entry = reinterpret_cast<const GptPartitionEntry*>(entryBuffer.data() + (i * entrySize));
            // Check if partition GUID is non-zero
            bool isZero = true;
            for (int b = 0; b < 16; ++b) {
                if (entry->partitionTypeGuid[b] != 0) { isZero = false; break; }
            }
            if (!isZero && entry->endingLba >= entry->startingLba) {
                outEntries.push_back(*entry);
            }
        }

        return NtStatus::Success;
    }
};

} // namespace micant::storage
