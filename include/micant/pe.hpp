#pragma once

#include <cstdint>
#include <string_view>
#include <string>
#include <span>
#include <vector>
#include <optional>
#include "ntstatus.hpp"
#include "mm.hpp"

namespace micant::pe {

inline constexpr uint16_t DOS_MAGIC = 0x5A4D; // 'MZ'
inline constexpr uint32_t NT_SIGNATURE = 0x00004550; // 'PE\0\0'
inline constexpr uint16_t MACHINE_AMD64 = 0x8664;
inline constexpr uint16_t MACHINE_I386  = 0x014C;
inline constexpr uint16_t PE32PLUS_MAGIC = 0x020B; // 64-bit Optional Header
inline constexpr uint16_t PE32_MAGIC     = 0x010B; // 32-bit Optional Header

// Standard PE Signatures & File Header Characteristics
inline constexpr uint16_t IMAGE_DOS_SIGNATURE           = DOS_MAGIC;
inline constexpr uint32_t IMAGE_NT_SIGNATURE            = NT_SIGNATURE;
inline constexpr uint16_t IMAGE_FILE_MACHINE_AMD64      = MACHINE_AMD64;
inline constexpr uint16_t IMAGE_FILE_MACHINE_I386       = MACHINE_I386;
inline constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = PE32PLUS_MAGIC;
inline constexpr uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = PE32_MAGIC;
inline constexpr uint16_t IMAGE_FILE_EXECUTABLE_IMAGE   = 0x0002;
inline constexpr uint16_t IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020;
inline constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_GUI   = 2;
inline constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_CUI   = 3;
inline constexpr uint32_t IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

// Standard Data Directory Indices
inline constexpr uint32_t IMAGE_DIRECTORY_ENTRY_EXPORT    = 0;
inline constexpr uint32_t IMAGE_DIRECTORY_ENTRY_IMPORT    = 1;
inline constexpr uint32_t IMAGE_DIRECTORY_ENTRY_RESOURCE  = 2;
inline constexpr uint32_t IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
inline constexpr uint32_t IMAGE_DIRECTORY_ENTRY_SECURITY  = 4;
inline constexpr uint32_t IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
inline constexpr uint32_t IMAGE_DIRECTORY_ENTRY_DEBUG     = 6;
inline constexpr uint32_t IMAGE_DIRECTORY_ENTRY_IAT       = 12;

// Import Ordinal Flags
inline constexpr uint64_t IMAGE_ORDINAL_FLAG64 = 0x8000000000000000ULL;
inline constexpr uint32_t IMAGE_ORDINAL_FLAG32 = 0x80000000U;

// Base Relocation Types
inline constexpr uint16_t IMAGE_REL_BASED_ABSOLUTE = 0;
inline constexpr uint16_t IMAGE_REL_BASED_HIGH     = 1;
inline constexpr uint16_t IMAGE_REL_BASED_LOW      = 2;
inline constexpr uint16_t IMAGE_REL_BASED_HIGHLOW  = 3;
inline constexpr uint16_t IMAGE_REL_BASED_HIGHADJ  = 4;
inline constexpr uint16_t IMAGE_REL_BASED_DIR64    = 10;

#pragma pack(push, 1)

struct ImageDosHeader {
    uint16_t e_magic;      // Magic number ('MZ')
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;     // Offset to NT headers
};

struct ImageFileHeader {
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};

struct ImageDataDirectory {
    uint32_t virtualAddress;
    uint32_t size;
};

struct ImageOptionalHeader64 {
    uint16_t magic;
    uint8_t  majorLinkerVersion;
    uint8_t  minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUninitializedData;
    uint32_t addressOfEntryPoint;
    uint32_t baseOfCode;
    uint64_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOperatingSystemVersion;
    uint16_t minorOperatingSystemVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t checkSum;
    uint16_t subsystem;
    uint16_t dllCharacteristics;
    uint64_t sizeOfStackReserve;
    uint64_t sizeOfStackCommit;
    uint64_t sizeOfHeapReserve;
    uint64_t sizeOfHeapCommit;
    uint32_t loaderFlags;
    uint32_t numberOfRvaAndSizes;
    ImageDataDirectory dataDirectory[16];
};

struct ImageNtHeaders64 {
    uint32_t signature;
    ImageFileHeader fileHeader;
    ImageOptionalHeader64 optionalHeader;
};

struct ImageOptionalHeader32 {
    uint16_t magic;
    uint8_t  majorLinkerVersion;
    uint8_t  minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUninitializedData;
    uint32_t addressOfEntryPoint;
    uint32_t baseOfCode;
    uint32_t baseOfData;
    uint32_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOperatingSystemVersion;
    uint16_t minorOperatingSystemVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t checkSum;
    uint16_t subsystem;
    uint16_t dllCharacteristics;
    uint32_t sizeOfStackReserve;
    uint32_t sizeOfStackCommit;
    uint32_t sizeOfHeapReserve;
    uint32_t sizeOfHeapCommit;
    uint32_t loaderFlags;
    uint32_t numberOfRvaAndSizes;
    ImageDataDirectory dataDirectory[16];
};

struct ImageNtHeaders32 {
    uint32_t signature;
    ImageFileHeader fileHeader;
    ImageOptionalHeader32 optionalHeader;
};

struct ImageSectionHeader {
    uint8_t  name[8];
    union {
        uint32_t physicalAddress;
        uint32_t virtualSize;
    } misc;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t pointerToRelocations;
    uint32_t pointerToLinenumbers;
    uint16_t numberOfRelocations;
    uint16_t numberOfLinenumbers;
    uint32_t characteristics;

    [[nodiscard]] std::string_view getName() const noexcept {
        size_t len = 0;
        while (len < 8 && name[len] != 0) len++;
        return std::string_view(reinterpret_cast<const char*>(name), len);
    }
};

struct ImageImportDescriptor {
    union {
        uint32_t characteristics;
        uint32_t originalFirstThunk; // RVA to Import Lookup Table (INT)
    };
    uint32_t timeDateStamp;
    uint32_t forwarderChain;
    uint32_t name; // RVA to null-terminated DLL name
    uint32_t firstThunk; // RVA to Import Address Table (IAT)
};

struct ImageImportByName {
    uint16_t hint;
    char name[1]; // Null-terminated ASCII symbol name
};

struct ImageBaseRelocation {
    uint32_t virtualAddress;
    uint32_t sizeOfBlock;
};

#pragma pack(pop)

struct ImportedSymbol {
    std::string name;
    uint16_t ordinal{0};
    bool isOrdinal{false};
    uint32_t iatRva{0}; // RVA in loaded image where function pointer is written
};

struct ImportedLibrary {
    std::string libraryName;
    std::vector<ImportedSymbol> symbols;
};

// Section Characteristics
inline constexpr uint32_t IMAGE_SCN_MEM_EXECUTE   = 0x20000000;
inline constexpr uint32_t IMAGE_SCN_MEM_READ      = 0x40000000;
inline constexpr uint32_t IMAGE_SCN_MEM_WRITE     = 0x80000000;
inline constexpr uint32_t IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;

/**
 * @brief Clean-room 64-bit PE Image Parser & Loader.
 */
class PeLoader {
public:
    static NtStatus inspect(std::span<const uint8_t> bytes, ImageNtHeaders64& outHeaders, std::vector<ImageSectionHeader>& outSections) {
        if (bytes.size() < sizeof(ImageDosHeader)) {
            return NtStatus::InvalidParameter;
        }

        const auto* dos = reinterpret_cast<const ImageDosHeader*>(bytes.data());
        if (dos->e_magic != DOS_MAGIC) {
            return NtStatus::InvalidParameter;
        }

        if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(ImageNtHeaders64) > bytes.size()) {
            return NtStatus::InvalidParameter;
        }

        const auto* nt = reinterpret_cast<const ImageNtHeaders64*>(bytes.data() + dos->e_lfanew);
        if (nt->signature != NT_SIGNATURE || nt->fileHeader.machine != MACHINE_AMD64 || nt->optionalHeader.magic != PE32PLUS_MAGIC) {
            return NtStatus::InvalidParameter;
        }

        outHeaders = *nt;

        const auto* section = reinterpret_cast<const ImageSectionHeader*>(
            bytes.data() + dos->e_lfanew + sizeof(uint32_t) + sizeof(ImageFileHeader) + nt->fileHeader.sizeOfOptionalHeader
        );

        outSections.clear();
        for (uint16_t i = 0; i < nt->fileHeader.numberOfSections; ++i) {
            outSections.push_back(section[i]);
        }

        return NtStatus::Success;
    }

    static NtStatus inspect32(std::span<const uint8_t> bytes, ImageNtHeaders32& outHeaders, std::vector<ImageSectionHeader>& outSections) {
        if (bytes.size() < sizeof(ImageDosHeader)) {
            return NtStatus::InvalidParameter;
        }

        const auto* dos = reinterpret_cast<const ImageDosHeader*>(bytes.data());
        if (dos->e_magic != DOS_MAGIC) {
            return NtStatus::InvalidParameter;
        }

        if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(ImageNtHeaders32) > bytes.size()) {
            return NtStatus::InvalidParameter;
        }

        const auto* nt = reinterpret_cast<const ImageNtHeaders32*>(bytes.data() + dos->e_lfanew);
        if (nt->signature != NT_SIGNATURE || nt->fileHeader.machine != MACHINE_I386 || nt->optionalHeader.magic != PE32_MAGIC) {
            return NtStatus::InvalidParameter;
        }

        outHeaders = *nt;

        const auto* section = reinterpret_cast<const ImageSectionHeader*>(
            bytes.data() + dos->e_lfanew + sizeof(uint32_t) + sizeof(ImageFileHeader) + nt->fileHeader.sizeOfOptionalHeader
        );

        outSections.clear();
        for (uint16_t i = 0; i < nt->fileHeader.numberOfSections; ++i) {
            outSections.push_back(section[i]);
        }

        return NtStatus::Success;
    }

    [[nodiscard]] static std::optional<size_t> rvaToOffset(
        uint32_t rva,
        const std::vector<ImageSectionHeader>& sections
    ) noexcept {
        for (const auto& sec : sections) {
            uint32_t secSize = sec.misc.virtualSize ? sec.misc.virtualSize : sec.sizeOfRawData;
            if (rva >= sec.virtualAddress && rva < sec.virtualAddress + secSize) {
                return sec.pointerToRawData + (rva - sec.virtualAddress);
            }
        }
        return std::nullopt;
    }

    static NtStatus mapImage(
        std::span<const uint8_t> fileBytes,
        const ImageNtHeaders64& headers,
        const std::vector<ImageSectionHeader>& sections,
        uint8_t* destinationBuffer,
        size_t destinationSize
    ) {
        if (!destinationBuffer || destinationSize < headers.optionalHeader.sizeOfImage) {
            return NtStatus::InvalidParameter;
        }

        std::memset(destinationBuffer, 0, destinationSize);

        // Copy Headers
        if (headers.optionalHeader.sizeOfHeaders > fileBytes.size() ||
            headers.optionalHeader.sizeOfHeaders > destinationSize) {
            return NtStatus::InvalidParameter;
        }
        std::memcpy(destinationBuffer, fileBytes.data(), headers.optionalHeader.sizeOfHeaders);

        // Copy Sections
        for (const auto& sec : sections) {
            if (sec.virtualAddress + sec.sizeOfRawData > destinationSize) {
                return NtStatus::InvalidParameter;
            }
            if (sec.pointerToRawData + sec.sizeOfRawData > fileBytes.size()) {
                return NtStatus::InvalidParameter;
            }
            if (sec.sizeOfRawData > 0) {
                std::memcpy(destinationBuffer + sec.virtualAddress,
                            fileBytes.data() + sec.pointerToRawData,
                            sec.sizeOfRawData);
            }
        }

        return NtStatus::Success;
    }

    static NtStatus parseImports(
        std::span<const uint8_t> bytes,
        const ImageNtHeaders64& headers,
        const std::vector<ImageSectionHeader>& sections,
        std::vector<ImportedLibrary>& outImports
    ) {
        outImports.clear();
        if (headers.optionalHeader.numberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) {
            return NtStatus::Success;
        }

        const auto& dir = headers.optionalHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.virtualAddress == 0 || dir.size == 0) {
            return NtStatus::Success; // No imports
        }

        auto offsetOpt = rvaToOffset(dir.virtualAddress, sections);
        if (!offsetOpt || *offsetOpt + sizeof(ImageImportDescriptor) > bytes.size()) {
            return NtStatus::InvalidParameter;
        }

        const auto* desc = reinterpret_cast<const ImageImportDescriptor*>(bytes.data() + *offsetOpt);
        while (desc->name != 0 && desc->firstThunk != 0) {
            auto nameOffset = rvaToOffset(desc->name, sections);
            if (!nameOffset || *nameOffset >= bytes.size()) {
                break;
            }

            const char* dllNameStr = reinterpret_cast<const char*>(bytes.data() + *nameOffset);
            ImportedLibrary lib;
            lib.libraryName = dllNameStr;

            // Use originalFirstThunk (INT) if present, else fallback to firstThunk (IAT)
            uint32_t thunkRva = desc->originalFirstThunk ? desc->originalFirstThunk : desc->firstThunk;
            auto thunkOffset = rvaToOffset(thunkRva, sections);
            if (thunkOffset) {
                const auto* thunkArray = reinterpret_cast<const uint64_t*>(bytes.data() + *thunkOffset);
                size_t idx = 0;
                while (thunkArray[idx] != 0) {
                    uint64_t val = thunkArray[idx];
                    ImportedSymbol sym;
                    sym.iatRva = desc->firstThunk + static_cast<uint32_t>(idx * sizeof(uint64_t));

                    if (val & IMAGE_ORDINAL_FLAG64) {
                        sym.isOrdinal = true;
                        sym.ordinal = static_cast<uint16_t>(val & 0xFFFF);
                    } else {
                        auto byNameOffset = rvaToOffset(static_cast<uint32_t>(val & 0xFFFFFFFF), sections);
                        if (byNameOffset && *byNameOffset + 2 < bytes.size()) {
                            const auto* ibn = reinterpret_cast<const ImageImportByName*>(bytes.data() + *byNameOffset);
                            sym.isOrdinal = false;
                            sym.name = ibn->name;
                        }
                    }
                    lib.symbols.push_back(sym);
                    idx++;
                }
            }

            outImports.push_back(lib);
            desc++;
        }

        return NtStatus::Success;
    }

    template <typename ResolverFunc>
    static size_t bindImports(
        uint8_t* loadedImageBase,
        const std::vector<ImportedLibrary>& imports,
        ResolverFunc&& resolver,
        bool is64Bit = true
    ) {
        if (!loadedImageBase) return 0;
        size_t resolvedCount = 0;

        for (const auto& lib : imports) {
            for (const auto& sym : lib.symbols) {
                void* fnPtr = nullptr;
                if (sym.isOrdinal) {
                    fnPtr = resolver(lib.libraryName, "", sym.ordinal);
                } else {
                    fnPtr = resolver(lib.libraryName, sym.name, 0);
                }

                if (fnPtr) {
                    if (is64Bit) {
                        *reinterpret_cast<uint64_t*>(loadedImageBase + sym.iatRva) = reinterpret_cast<uint64_t>(fnPtr);
                    } else {
                        *reinterpret_cast<uint32_t*>(loadedImageBase + sym.iatRva) = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(fnPtr));
                    }
                    resolvedCount++;
                }
            }
        }

        return resolvedCount;
    }

    static NtStatus applyRelocations(
        uint8_t* loadedImageBase,
        size_t imageSize,
        const ImageNtHeaders64& headers,
        uintptr_t actualBaseAddress
    ) {
        if (!loadedImageBase) return NtStatus::InvalidParameter;

        int64_t delta = static_cast<int64_t>(actualBaseAddress) - static_cast<int64_t>(headers.optionalHeader.imageBase);
        if (delta == 0) return NtStatus::Success; // Loaded at preferred base, no relocations needed

        if (headers.optionalHeader.numberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            return NtStatus::Success;
        }

        const auto& dir = headers.optionalHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir.virtualAddress == 0 || dir.size == 0) {
            return NtStatus::Success;
        }

        if (dir.virtualAddress + dir.size > imageSize) {
            return NtStatus::InvalidParameter;
        }

        uint32_t currentOffset = dir.virtualAddress;
        uint32_t endOffset = dir.virtualAddress + dir.size;

        while (currentOffset < endOffset) {
            const auto* block = reinterpret_cast<const ImageBaseRelocation*>(loadedImageBase + currentOffset);
            if (block->sizeOfBlock < sizeof(ImageBaseRelocation)) break;

            uint32_t entryCount = (block->sizeOfBlock - sizeof(ImageBaseRelocation)) / sizeof(uint16_t);
            const auto* entries = reinterpret_cast<const uint16_t*>(block + 1);

            for (uint32_t i = 0; i < entryCount; ++i) {
                uint16_t type = entries[i] >> 12;
                uint16_t offset = entries[i] & 0x0FFF;
                uint32_t targetRva = block->virtualAddress + offset;

                if (type == IMAGE_REL_BASED_DIR64 && targetRva + sizeof(uint64_t) <= imageSize) {
                    *reinterpret_cast<uint64_t*>(loadedImageBase + targetRva) += delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW && targetRva + sizeof(uint32_t) <= imageSize) {
                    *reinterpret_cast<uint32_t*>(loadedImageBase + targetRva) += static_cast<uint32_t>(delta);
                }
            }

            currentOffset += block->sizeOfBlock;
        }

        return NtStatus::Success;
    }
};

} // namespace micant::pe
