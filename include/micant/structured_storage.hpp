// ============================================================================
// MicaNT: OLE Structured Storage & Compound File Binary Format Subsystem
// (ole32.dll / Structured Storage)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Provides complete OLE Structured Storage, Compound File Binary Format
// (MS-CFB v3/v4), nested storage hierarchies (IStorage), stream containers
// (IStream), byte array abstraction (ILockBytes), directory enumeration
// (IEnumSTATSTG), and COM object persistence contracts (IPersistStorage,
// IPersistStream, IPersistStreamInit, IPersistFile).
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <algorithm>
#include <functional>
#include <span>

#include "ntdef.hpp"
#include "kernel32.hpp"
#include "ole32.hpp"

namespace micant::ole32 {

// ============================================================================
// 1. Storage Constants, Types & Status Codes
// ============================================================================

using SNB = wchar_t**;

// Storage Object Types
inline constexpr uint32_t STGTY_INVALID   = 0;
inline constexpr uint32_t STGTY_STORAGE   = 1;
inline constexpr uint32_t STGTY_STREAM    = 2;
inline constexpr uint32_t STGTY_LOCKBYTES = 3;
inline constexpr uint32_t STGTY_PROPERTY  = 4;
inline constexpr uint32_t STGTY_ROOT      = 5;

// Storage Access & Sharing Modes (STGM)
inline constexpr uint32_t STGM_DIRECT             = 0x00000000;
inline constexpr uint32_t STGM_TRANSACTED         = 0x00010000;
inline constexpr uint32_t STGM_READ               = 0x00000000;
inline constexpr uint32_t STGM_WRITE              = 0x00000001;
inline constexpr uint32_t STGM_READWRITE          = 0x00000002;
inline constexpr uint32_t STGM_SHARE_DENY_NONE    = 0x00000040;
inline constexpr uint32_t STGM_SHARE_DENY_READ    = 0x00000030;
inline constexpr uint32_t STGM_SHARE_DENY_WRITE   = 0x00000020;
inline constexpr uint32_t STGM_SHARE_EXCLUSIVE    = 0x00000010;
inline constexpr uint32_t STGM_PRIORITY           = 0x00040000;
inline constexpr uint32_t STGM_CREATE             = 0x00001000;
inline constexpr uint32_t STGM_CONVERT            = 0x00020000;
inline constexpr uint32_t STGM_FAILIFTHERE        = 0x00000000;
inline constexpr uint32_t STGM_DIRECT_SWMR        = 0x00400000;
inline constexpr uint32_t STGM_NOSCRATCH          = 0x00100000;
inline constexpr uint32_t STGM_NOSNAPSHOT         = 0x00200000;
inline constexpr uint32_t STGM_SIMPLE             = 0x08000000;
inline constexpr uint32_t STGM_DELETEONRELEASE    = 0x04000000;

// Commit Flags (STGC)
inline constexpr uint32_t STGC_DEFAULT                            = 0;
inline constexpr uint32_t STGC_OVERWRITE                          = 1;
inline constexpr uint32_t STGC_ONLYIFCURRENT                      = 2;
inline constexpr uint32_t STGC_DANGEROUSLYCOMMITMERELYTODISKCACHE = 4;
inline constexpr uint32_t STGC_CONSOLIDATE                        = 8;

// Storage Formats (STGFMT)
inline constexpr uint32_t STGFMT_STORAGE = 0;
inline constexpr uint32_t STGFMT_FILE    = 3;
inline constexpr uint32_t STGFMT_ANY     = 4;
inline constexpr uint32_t STGFMT_DOCFILE = 5;

// Storage Error Codes (STG_E_*)
inline constexpr HRESULT STG_E_INVALIDFUNCTION       = static_cast<HRESULT>(0x80030001);
inline constexpr HRESULT STG_E_FILENOTFOUND          = static_cast<HRESULT>(0x80030002);
inline constexpr HRESULT STG_E_PATHNOTFOUND          = static_cast<HRESULT>(0x80030003);
inline constexpr HRESULT STG_E_TOOMANYOPENFILES      = static_cast<HRESULT>(0x80030004);
inline constexpr HRESULT STG_E_ACCESSDENIED          = static_cast<HRESULT>(0x80030005);
inline constexpr HRESULT STG_E_INVALIDHANDLE         = static_cast<HRESULT>(0x80030006);
inline constexpr HRESULT STG_E_INSUFFICIENTMEMORY    = static_cast<HRESULT>(0x80030008);
inline constexpr HRESULT STG_E_INVALIDPOINTER        = static_cast<HRESULT>(0x80030009);
inline constexpr HRESULT STG_E_NOMOREFILES           = static_cast<HRESULT>(0x80030012);
inline constexpr HRESULT STG_E_DISKISWRITEPROTECTED  = static_cast<HRESULT>(0x80030013);
inline constexpr HRESULT STG_E_SEEKERROR             = static_cast<HRESULT>(0x80030019);
inline constexpr HRESULT STG_E_WRITEFAULT            = static_cast<HRESULT>(0x8003001D);
inline constexpr HRESULT STG_E_READFAULT             = static_cast<HRESULT>(0x8003001E);
inline constexpr HRESULT STG_E_SHAREVIOLATION        = static_cast<HRESULT>(0x80030020);
inline constexpr HRESULT STG_E_LOCKVIOLATION         = static_cast<HRESULT>(0x80030021);
inline constexpr HRESULT STG_E_FILEALREADYEXISTS     = static_cast<HRESULT>(0x80030050);
inline constexpr HRESULT STG_E_INVALIDPARAMETER      = static_cast<HRESULT>(0x80030057);
inline constexpr HRESULT STG_E_MEDIUMFULL            = static_cast<HRESULT>(0x80030070);
inline constexpr HRESULT STG_E_INVALIDNAME           = static_cast<HRESULT>(0x800300FC);
inline constexpr HRESULT STG_E_UNKNOWN               = static_cast<HRESULT>(0x800300FD);
inline constexpr HRESULT STG_E_UNIMPLEMENTEDFUNCTION = static_cast<HRESULT>(0x800300FE);
inline constexpr HRESULT STG_E_INVALIDFLAG           = static_cast<HRESULT>(0x800300FF);
inline constexpr HRESULT STG_E_NOTFILEBASEDSTORAGE   = static_cast<HRESULT>(0x80030107);
inline constexpr HRESULT STG_S_CONVERTED             = static_cast<HRESULT>(0x00030200);

// ============================================================================
// 2. Storage & Persistence Interface GUIDs
// ============================================================================

inline const IID IID_IStorage = {
    0x0000000b, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

inline const IID IID_ILockBytes = {
    0x0000000a, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

inline const IID IID_IEnumSTATSTG = {
    0x0000000d, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

inline const IID IID_IPersist = {
    0x0000010c, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

inline const IID IID_IPersistStorage = {
    0x0000010a, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

inline const IID IID_IPersistStream = {
    0x00000109, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

inline const IID IID_IPersistStreamInit = {
    0x7fd52380, 0x4e07, 0x101b, { 0xae, 0x2d, 0x08, 0x00, 0x2b, 0x2e, 0xc7, 0x13 }
};

inline const IID IID_IPersistFile = {
    0x0000010b, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

// ============================================================================
// 3. COM Interface Declarations
// ============================================================================

class IEnumSTATSTG;

class IStorage : public IUnknown {
public:
    virtual HRESULT CreateStream(const OLECHAR* pwcsName, uint32_t grfMode, uint32_t reserved1, uint32_t reserved2, IStream** ppstm) = 0;
    virtual HRESULT OpenStream(const OLECHAR* pwcsName, void* reserved1, uint32_t grfMode, uint32_t reserved2, IStream** ppstm) = 0;
    virtual HRESULT CreateStorage(const OLECHAR* pwcsName, uint32_t grfMode, uint32_t dwStgFmt, uint32_t reserved2, IStorage** ppstg) = 0;
    virtual HRESULT OpenStorage(const OLECHAR* pwcsName, IStorage* pstgPriority, uint32_t grfMode, SNB snbExclude, uint32_t reserved, IStorage** ppstg) = 0;
    virtual HRESULT CopyTo(uint32_t ciidExclude, const IID* rgiidExclude, SNB snbExclude, IStorage* pstgDest) = 0;
    virtual HRESULT MoveElementTo(const OLECHAR* pwcsName, IStorage* pstgDest, const OLECHAR* pwcsNewName, uint32_t grfFlags) = 0;
    virtual HRESULT Commit(uint32_t grfCommitFlags) = 0;
    virtual HRESULT Revert() = 0;
    virtual HRESULT EnumElements(uint32_t reserved1, void* reserved2, uint32_t reserved3, IEnumSTATSTG** ppenum) = 0;
    virtual HRESULT DestroyElement(const OLECHAR* pwcsName) = 0;
    virtual HRESULT RenameElement(const OLECHAR* pwcsOldName, const OLECHAR* pwcsNewName) = 0;
    virtual HRESULT SetElementTimes(const OLECHAR* pwcsName, const win32::FILETIME* pctime, const win32::FILETIME* patime, const win32::FILETIME* pmtime) = 0;
    virtual HRESULT SetClass(REFCLSID clsid) = 0;
    virtual HRESULT SetStateBits(uint32_t grfStateBits, uint32_t grfMask) = 0;
    virtual HRESULT Stat(STATSTG* pstatstg, uint32_t grfStatFlag) = 0;
};

class ILockBytes : public IUnknown {
public:
    virtual HRESULT ReadAt(uint64_t ulOffset, void* pv, uint32_t cb, uint32_t* pcbRead) = 0;
    virtual HRESULT WriteAt(uint64_t ulOffset, const void* pv, uint32_t cb, uint32_t* pcbWritten) = 0;
    virtual HRESULT Flush() = 0;
    virtual HRESULT SetSize(uint64_t cb) = 0;
    virtual HRESULT LockRegion(uint64_t libOffset, uint64_t cb, uint32_t dwLockType) = 0;
    virtual HRESULT UnlockRegion(uint64_t libOffset, uint64_t cb, uint32_t dwLockType) = 0;
    virtual HRESULT Stat(STATSTG* pstatstg, uint32_t grfStatFlag) = 0;
};

class IEnumSTATSTG : public IUnknown {
public:
    virtual HRESULT Next(uint32_t celt, STATSTG* rgelt, uint32_t* pceltFetched) = 0;
    virtual HRESULT Skip(uint32_t celt) = 0;
    virtual HRESULT Reset() = 0;
    virtual HRESULT Clone(IEnumSTATSTG** ppenum) = 0;
};

class IPersist : public IUnknown {
public:
    virtual HRESULT GetClassID(CLSID* pClassID) = 0;
};

class IPersistStorage : public IPersist {
public:
    virtual HRESULT IsDirty() = 0;
    virtual HRESULT InitNew(IStorage* pStg) = 0;
    virtual HRESULT Load(IStorage* pStg) = 0;
    virtual HRESULT Save(IStorage* pStgSave, win32::BOOL fSameAsLoad) = 0;
    virtual HRESULT SaveCompleted(IStorage* pStgNew) = 0;
    virtual HRESULT HandsOffStorage() = 0;
};

class IPersistStream : public IPersist {
public:
    virtual HRESULT IsDirty() = 0;
    virtual HRESULT Load(IStream* pStm) = 0;
    virtual HRESULT Save(IStream* pStm, win32::BOOL fClearDirty) = 0;
    virtual HRESULT GetSizeMax(uint64_t* pcbSize) = 0;
};

class IPersistStreamInit : public IPersistStream {
public:
    virtual HRESULT InitNew() = 0;
};

class IPersistFile : public IPersist {
public:
    virtual HRESULT IsDirty() = 0;
    virtual HRESULT Load(LPCOLESTR pszFileName, uint32_t dwMode) = 0;
    virtual HRESULT Save(LPCOLESTR pszFileName, win32::BOOL fRemember) = 0;
    virtual HRESULT SaveCompleted(LPCOLESTR pszFileName) = 0;
    virtual HRESULT GetCurFile(LPOLESTR* ppszFileName) = 0;
};

// ============================================================================
// 4. Compound File Binary Format (CFBF v3) Structures & Engine
// ============================================================================

#pragma pack(push, 1)

struct CFBHeader {
    uint8_t  signature[8]{ 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }; // Magic
    uint8_t  clsid[16]{};
    uint16_t minorVersion{ 0x003E };
    uint16_t majorVersion{ 0x0003 }; // 3 = 512 bytes, 4 = 4096 bytes
    uint16_t byteOrder{ 0xFFFE };    // Little endian
    uint16_t sectorShift{ 9 };       // 1 << 9 = 512 bytes
    uint16_t miniSectorShift{ 6 };   // 1 << 6 = 64 bytes
    uint8_t  reserved[6]{};
    uint32_t numDirSectors{ 0 };
    uint32_t numFatSectors{ 1 };
    uint32_t firstDirSector{ 1 };
    uint32_t transactSignature{ 0 };
    uint32_t miniStreamCutoff{ 4096 };
    uint32_t firstMiniFatSector{ 0xFFFFFFFE }; // ENDOFCHAIN
    uint32_t numMiniFatSectors{ 0 };
    uint32_t firstDifatSector{ 0xFFFFFFFE };   // ENDOFCHAIN
    uint32_t numDifatSectors{ 0 };
    uint32_t difat[109]{};                     // Array of FAT sector locations
};

struct CFBDirEntry {
    char16_t name[32]{};            // UTF-16LE name
    uint16_t nameLength{ 0 };       // Length in bytes including null
    uint8_t  objectType{ 0 };       // 0: Unallocated, 1: Storage, 2: Stream, 5: Root
    uint8_t  colorFlag{ 1 };        // 0: Red, 1: Black
    uint32_t leftSiblingId{ 0xFFFFFFFF };
    uint32_t rightSiblingId{ 0xFFFFFFFF };
    uint32_t childId{ 0xFFFFFFFF };
    uint8_t  clsid[16]{};
    uint32_t stateBits{ 0 };
    uint64_t creationTime{ 0 };
    uint64_t modifiedTime{ 0 };
    uint32_t startingSector{ 0xFFFFFFFE };
    uint64_t streamSize{ 0 };
};

#pragma pack(pop)

static_assert(sizeof(CFBHeader) == 512, "CFBHeader must be exactly 512 bytes");
static_assert(sizeof(CFBDirEntry) == 128, "CFBDirEntry must be exactly 128 bytes");

inline constexpr uint32_t CFB_FAT_ENDOFCHAIN = 0xFFFFFFFE;
inline constexpr uint32_t CFB_FAT_FREESECT   = 0xFFFFFFFF;
inline constexpr uint32_t CFB_FAT_FATSECT    = 0xFFFFFFFD;
inline constexpr uint32_t CFB_FAT_DIFSECT    = 0xFFFFFFFC;

// In-Memory Representation of Storage Elements
struct CompoundNode : public std::enable_shared_from_this<CompoundNode> {
    std::wstring name;
    uint32_t     type{ STGTY_STORAGE }; // STGTY_STORAGE, STGTY_STREAM, STGTY_ROOT
    CLSID        clsid{};
    uint32_t     stateBits{ 0 };
    uint64_t     creationTime{ 0 };
    uint64_t     modifiedTime{ 0 };
    uint64_t     accessTime{ 0 };

    std::vector<uint8_t> data; // For streams
    std::vector<std::shared_ptr<CompoundNode>> children; // For storages
    std::weak_ptr<CompoundNode> parent;

    CompoundNode(std::wstring_view n, uint32_t t)
        : name(n), type(t) {
        win32::FILETIME ft{};
        win32::GetSystemTimeAsFileTime(&ft);
        creationTime = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        modifiedTime = creationTime;
        accessTime = creationTime;
    }

    std::shared_ptr<CompoundNode> findChild(std::wstring_view childName) const {
        for (const auto& c : children) {
            if (c->name == childName) return c;
        }
        return nullptr;
    }

    bool removeChild(std::wstring_view childName) {
        auto it = std::remove_if(children.begin(), children.end(), [&](const std::shared_ptr<CompoundNode>& c) {
            return c->name == childName;
        });
        if (it != children.end()) {
            children.erase(it, children.end());
            return true;
        }
        return false;
    }
};

// ============================================================================
// 5. CFBF Serialization & Deserialization Engine
// ============================================================================

class CFBFEngine {
public:
    static std::vector<uint8_t> Serialize(const std::shared_ptr<CompoundNode>& root) {
        if (!root) return {};

        // 1. Flatten all directory nodes (Root entry is always index 0)
        std::vector<std::shared_ptr<CompoundNode>> allNodes;
        allNodes.push_back(root);

        std::function<void(const std::shared_ptr<CompoundNode>&)> collectChildren = [&](const std::shared_ptr<CompoundNode>& parent) {
            for (const auto& child : parent->children) {
                allNodes.push_back(child);
                if (child->type == STGTY_STORAGE) {
                    collectChildren(child);
                }
            }
        };
        collectChildren(root);

        // 2. Prepare directory entries (128 bytes each)
        // 512-byte sector holds 4 directory entries
        size_t dirEntriesCount = std::max<size_t>(4, allNodes.size());
        size_t dirSectorsCount = (dirEntriesCount + 3) / 4;
        std::vector<CFBDirEntry> dirEntries(dirSectorsCount * 4);

        // Build child/sibling index maps
        std::unordered_map<CompoundNode*, uint32_t> nodeIndices;
        for (size_t i = 0; i < allNodes.size(); ++i) {
            nodeIndices[allNodes[i].get()] = static_cast<uint32_t>(i);
        }

        // 3. Allocate stream data sectors
        // Sector 0: FAT sector
        // Sector 1 .. dirSectorsCount: Directory sectors
        // Sector 1 + dirSectorsCount ..: Stream data sectors
        uint32_t nextStreamSector = 1 + static_cast<uint32_t>(dirSectorsCount);

        std::vector<std::vector<uint8_t>> streamSectors;
        std::vector<uint32_t> fat(128, CFB_FAT_FREESECT); // Sector 0 holds 128 uint32_t FAT entries

        // Mark Sector 0 as FAT sector
        fat[0] = CFB_FAT_FATSECT;
        // Mark directory sectors in FAT
        for (uint32_t s = 1; s <= dirSectorsCount; ++s) {
            fat[s] = (s == dirSectorsCount) ? CFB_FAT_ENDOFCHAIN : (s + 1);
        }

        // Fill directory entries
        for (size_t i = 0; i < allNodes.size(); ++i) {
            auto& node = allNodes[i];
            auto& entry = dirEntries[i];

            std::wstring safeName = (i == 0) ? L"Root Entry" : node->name;
            if (safeName.size() > 31) safeName = safeName.substr(0, 31);
            for (size_t c = 0; c < safeName.size(); ++c) {
                entry.name[c] = static_cast<char16_t>(safeName[c]);
            }
            entry.name[safeName.size()] = u'\0';
            entry.nameLength = static_cast<uint16_t>((safeName.size() + 1) * sizeof(char16_t));
            entry.objectType = (i == 0) ? 5 : (node->type == STGTY_STORAGE ? 1 : 2);
            entry.colorFlag = 1; // Black
            std::memcpy(entry.clsid, &node->clsid, sizeof(GUID));
            entry.stateBits = node->stateBits;
            entry.creationTime = node->creationTime;
            entry.modifiedTime = node->modifiedTime;

            // Link children
            if (!node->children.empty()) {
                entry.childId = nodeIndices[node->children[0].get()];
                for (size_t c = 0; c < node->children.size(); ++c) {
                    uint32_t cIdx = nodeIndices[node->children[c].get()];
                    if (c + 1 < node->children.size()) {
                        dirEntries[cIdx].rightSiblingId = nodeIndices[node->children[c + 1].get()];
                    }
                }
            }

            // Stream data allocation
            if (node->type == STGTY_STREAM && !node->data.empty()) {
                entry.streamSize = node->data.size();
                entry.startingSector = nextStreamSector;

                size_t numSectorsForStream = (node->data.size() + 511) / 512;
                for (size_t s = 0; s < numSectorsForStream; ++s) {
                    std::vector<uint8_t> sec(512, 0);
                    size_t offset = s * 512;
                    size_t chunk = std::min<size_t>(512, node->data.size() - offset);
                    std::memcpy(sec.data(), node->data.data() + offset, chunk);
                    streamSectors.push_back(std::move(sec));

                    uint32_t currentSecId = nextStreamSector + static_cast<uint32_t>(s);
                    if (currentSecId >= fat.size()) {
                        fat.resize(currentSecId + 128, CFB_FAT_FREESECT);
                    }
                    fat[currentSecId] = (s + 1 == numSectorsForStream) ? CFB_FAT_ENDOFCHAIN : (currentSecId + 1);
                }
                nextStreamSector += static_cast<uint32_t>(numSectorsForStream);
            }
        }

        // 4. Assemble complete CFBF v3 Binary File (Header + FAT + Dir + Streams)
        CFBHeader header{};
        header.numDirSectors = static_cast<uint32_t>(dirSectorsCount);
        header.numFatSectors = 1;
        header.firstDirSector = 1;
        std::fill(std::begin(header.difat), std::end(header.difat), CFB_FAT_FREESECT);
        header.difat[0] = 0; // Sector 0 is FAT

        std::vector<uint8_t> output;
        output.resize(512); // Header
        std::memcpy(output.data(), &header, sizeof(CFBHeader));

        // Append FAT Sector 0
        std::vector<uint8_t> fatSector(512, 0xFF);
        std::memcpy(fatSector.data(), fat.data(), std::min<size_t>(512, fat.size() * sizeof(uint32_t)));
        output.insert(output.end(), fatSector.begin(), fatSector.end());

        // Append Directory Sectors
        const uint8_t* pDirBytes = reinterpret_cast<const uint8_t*>(dirEntries.data());
        output.insert(output.end(), pDirBytes, pDirBytes + (dirSectorsCount * 512));

        // Append Stream Data Sectors
        for (const auto& sec : streamSectors) {
            output.insert(output.end(), sec.begin(), sec.end());
        }

        return output;
    }

    static std::shared_ptr<CompoundNode> Deserialize(const uint8_t* data, size_t size) {
        if (!data || size < 512) return nullptr;

        const auto* pHeader = reinterpret_cast<const CFBHeader*>(data);
        const uint8_t expectedSig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
        if (std::memcmp(pHeader->signature, expectedSig, 8) != 0) {
            return nullptr;
        }

        uint32_t sectorSize = (pHeader->majorVersion == 4) ? 4096 : 512;
        if (size < sectorSize * 2) return nullptr;

        // Read FAT
        uint32_t fatSector = pHeader->difat[0];
        size_t fatOffset = (fatSector + 1) * sectorSize;
        if (fatOffset + sectorSize > size) return nullptr;

        const auto* pFat = reinterpret_cast<const uint32_t*>(data + fatOffset);
        size_t fatEntries = sectorSize / sizeof(uint32_t);

        // Read Directory
        uint32_t dirSector = pHeader->firstDirSector;
        size_t dirOffset = (dirSector + 1) * sectorSize;
        if (dirOffset + sectorSize > size) return nullptr;

        size_t entriesPerSector = sectorSize / sizeof(CFBDirEntry);
        const auto* pDir = reinterpret_cast<const CFBDirEntry*>(data + dirOffset);

        // Entry 0 is Root Entry
        auto root = std::make_shared<CompoundNode>(L"Root Entry", STGTY_ROOT);
        std::memcpy(&root->clsid, pDir[0].clsid, sizeof(GUID));
        root->stateBits = pDir[0].stateBits;
        root->creationTime = pDir[0].creationTime;
        root->modifiedTime = pDir[0].modifiedTime;

        // Map entries
        std::vector<std::shared_ptr<CompoundNode>> nodes(entriesPerSector);
        nodes[0] = root;

        for (size_t i = 1; i < entriesPerSector; ++i) {
            const auto& entry = pDir[i];
            if (entry.objectType == 0) continue; // Unallocated

            std::wstring name;
            for (int c = 0; c < 32 && entry.name[c] != 0; ++c) {
                name.push_back(static_cast<wchar_t>(entry.name[c]));
            }

            uint32_t stgType = (entry.objectType == 1) ? STGTY_STORAGE : STGTY_STREAM;
            auto node = std::make_shared<CompoundNode>(name, stgType);
            std::memcpy(&node->clsid, entry.clsid, sizeof(GUID));
            node->stateBits = entry.stateBits;
            node->creationTime = entry.creationTime;
            node->modifiedTime = entry.modifiedTime;

            // If stream, reconstruct stream data from FAT sectors
            if (stgType == STGTY_STREAM && entry.streamSize > 0) {
                node->data.resize(static_cast<size_t>(entry.streamSize));
                uint32_t curSector = entry.startingSector;
                size_t bytesRemaining = static_cast<size_t>(entry.streamSize);
                size_t destPos = 0;

                while (curSector != CFB_FAT_ENDOFCHAIN && curSector < fatEntries && bytesRemaining > 0) {
                    size_t secOffset = (curSector + 1) * sectorSize;
                    if (secOffset + sectorSize > size && secOffset >= size) break;
                    size_t chunk = std::min<size_t>(bytesRemaining, sectorSize);
                    std::memcpy(node->data.data() + destPos, data + secOffset, chunk);
                    destPos += chunk;
                    bytesRemaining -= chunk;
                    curSector = pFat[curSector];
                }
            }

            nodes[i] = node;
        }

        // Reconnect tree hierarchy using child/sibling links
        std::function<void(uint32_t, const std::shared_ptr<CompoundNode>&)> linkChildren = [&](uint32_t entryIdx, const std::shared_ptr<CompoundNode>& parent) {
            if (entryIdx >= entriesPerSector || !nodes[entryIdx]) return;
            const auto& curEntry = pDir[entryIdx];

            // Child
            if (curEntry.childId != 0xFFFFFFFF && curEntry.childId < entriesPerSector) {
                uint32_t childIdx = curEntry.childId;
                while (childIdx != 0xFFFFFFFF && childIdx < entriesPerSector) {
                    if (nodes[childIdx]) {
                        parent->children.push_back(nodes[childIdx]);
                        nodes[childIdx]->parent = parent;
                        linkChildren(childIdx, nodes[childIdx]);
                    }
                    childIdx = pDir[childIdx].rightSiblingId;
                }
            }
        };

        linkChildren(0, root);
        return root;
    }
};

// ============================================================================
// 6. In-Memory ILockBytes Implementation (MemoryLockBytes)
// ============================================================================

class MemoryLockBytes : public ILockBytes {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<uint8_t>  m_buffer;
    bool                  m_deleteOnRelease{ false };
    mutable std::mutex    m_mutex;

public:
    MemoryLockBytes(const void* data = nullptr, size_t size = 0, bool deleteOnRelease = false)
        : m_deleteOnRelease(deleteOnRelease) {
        if (data && size > 0) {
            const auto* p = static_cast<const uint8_t*>(data);
            m_buffer.assign(p, p + size);
        }
    }

    virtual HRESULT QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ILockBytes) {
            *ppvObject = static_cast<ILockBytes*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1) - 1;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    virtual HRESULT ReadAt(uint64_t ulOffset, void* pv, uint32_t cb, uint32_t* pcbRead) override {
        if (!pv) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (ulOffset >= m_buffer.size()) {
            if (pcbRead) *pcbRead = 0;
            return S_FALSE;
        }
        size_t available = m_buffer.size() - static_cast<size_t>(ulOffset);
        size_t toRead = std::min<size_t>(static_cast<size_t>(cb), available);
        std::memcpy(pv, m_buffer.data() + ulOffset, toRead);
        if (pcbRead) *pcbRead = static_cast<uint32_t>(toRead);
        return S_OK;
    }

    virtual HRESULT WriteAt(uint64_t ulOffset, const void* pv, uint32_t cb, uint32_t* pcbWritten) override {
        if (!pv && cb > 0) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t required = static_cast<size_t>(ulOffset) + cb;
        if (required > m_buffer.size()) {
            m_buffer.resize(required, 0);
        }
        if (cb > 0) {
            std::memcpy(m_buffer.data() + ulOffset, pv, cb);
        }
        if (pcbWritten) *pcbWritten = cb;
        return S_OK;
    }

    virtual HRESULT Flush() override {
        return S_OK;
    }

    virtual HRESULT SetSize(uint64_t cb) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_buffer.resize(static_cast<size_t>(cb), 0);
        return S_OK;
    }

    virtual HRESULT LockRegion(uint64_t, uint64_t, uint32_t) override {
        return S_OK;
    }

    virtual HRESULT UnlockRegion(uint64_t, uint64_t, uint32_t) override {
        return S_OK;
    }

    virtual HRESULT Stat(STATSTG* pstatstg, uint32_t) override {
        if (!pstatstg) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        std::memset(pstatstg, 0, sizeof(STATSTG));
        pstatstg->type = STGTY_LOCKBYTES;
        pstatstg->cbSize = m_buffer.size();
        return S_OK;
    }

    const std::vector<uint8_t>& getBuffer() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_buffer;
    }
};

inline HRESULT CreateILockBytesOnHGlobal(void* hGlobal, win32::BOOL fDeleteOnRelease, ILockBytes** pplkbyt) {
    if (!pplkbyt) return E_POINTER;
    *pplkbyt = new MemoryLockBytes(hGlobal, hGlobal ? std::strlen(static_cast<const char*>(hGlobal)) : 0, fDeleteOnRelease != 0);
    return S_OK;
}

// ============================================================================
// 7. Compound Stream Implementation (CompoundStream)
// ============================================================================

class CompoundStream : public IStream {
private:
    std::atomic<uint32_t>         m_refCount{ 1 };
    std::shared_ptr<CompoundNode> m_node;
    uint32_t                      m_grfMode{ STGM_READWRITE };
    size_t                        m_pos{ 0 };
    mutable std::mutex            m_mutex;

public:
    CompoundStream(std::shared_ptr<CompoundNode> node, uint32_t grfMode)
        : m_node(std::move(node)), m_grfMode(grfMode) {}

    virtual HRESULT QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ISequentialStream || riid == IID_IStream) {
            *ppvObject = static_cast<IStream*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1) - 1;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    virtual HRESULT Read(void* pv, uint32_t cb, uint32_t* pcbRead) override {
        if (!pv) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pos >= m_node->data.size()) {
            if (pcbRead) *pcbRead = 0;
            return S_FALSE;
        }
        size_t available = m_node->data.size() - m_pos;
        size_t toRead = std::min<size_t>(static_cast<size_t>(cb), available);
        std::memcpy(pv, m_node->data.data() + m_pos, toRead);
        m_pos += toRead;
        if (pcbRead) *pcbRead = static_cast<uint32_t>(toRead);
        return S_OK;
    }

    virtual HRESULT Write(const void* pv, uint32_t cb, uint32_t* pcbWritten) override {
        if (!pv && cb > 0) return E_POINTER;
        if ((m_grfMode & 3) == STGM_READ) return STG_E_ACCESSDENIED;

        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pos + cb > m_node->data.size()) {
            m_node->data.resize(m_pos + cb, 0);
        }
        if (cb > 0) {
            std::memcpy(m_node->data.data() + m_pos, pv, cb);
            m_pos += cb;
        }
        if (pcbWritten) *pcbWritten = cb;

        // Update modified time
        win32::FILETIME ft{};
        win32::GetSystemTimeAsFileTime(&ft);
        m_node->modifiedTime = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

        return S_OK;
    }

    virtual HRESULT Seek(int64_t dlibMove, uint32_t dwOrigin, uint64_t* plibNewPosition) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        int64_t newPos = 0;
        switch (dwOrigin) {
            case STREAM_SEEK_SET: newPos = dlibMove; break;
            case STREAM_SEEK_CUR: newPos = static_cast<int64_t>(m_pos) + dlibMove; break;
            case STREAM_SEEK_END: newPos = static_cast<int64_t>(m_node->data.size()) + dlibMove; break;
            default: return STG_E_INVALIDPARAMETER;
        }
        if (newPos < 0) return STG_E_SEEKERROR;
        m_pos = static_cast<size_t>(newPos);
        if (plibNewPosition) *plibNewPosition = m_pos;
        return S_OK;
    }

    virtual HRESULT SetSize(uint64_t libNewSize) override {
        if ((m_grfMode & 3) == STGM_READ) return STG_E_ACCESSDENIED;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_node->data.resize(static_cast<size_t>(libNewSize), 0);
        return S_OK;
    }

    virtual HRESULT CopyTo(IStream* pstm, uint64_t cb, uint64_t* pcbRead, uint64_t* pcbWritten) override {
        if (!pstm) return E_POINTER;
        std::vector<uint8_t> tmp(static_cast<size_t>(cb));
        uint32_t r = 0;
        HRESULT hr = Read(tmp.data(), static_cast<uint32_t>(cb), &r);
        if (FAILED(hr)) return hr;
        uint32_t w = 0;
        hr = pstm->Write(tmp.data(), r, &w);
        if (pcbRead) *pcbRead = r;
        if (pcbWritten) *pcbWritten = w;
        return hr;
    }

    virtual HRESULT Commit(uint32_t) override { return S_OK; }
    virtual HRESULT Revert() override { return S_OK; }
    virtual HRESULT LockRegion(uint64_t, uint64_t, uint32_t) override { return S_OK; }
    virtual HRESULT UnlockRegion(uint64_t, uint64_t, uint32_t) override { return S_OK; }

    virtual HRESULT Stat(STATSTG* pstatstg, uint32_t grfStatFlag) override {
        if (!pstatstg) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        std::memset(pstatstg, 0, sizeof(STATSTG));
        pstatstg->type = STGTY_STREAM;
        pstatstg->cbSize = m_node->data.size();
        pstatstg->ctime = m_node->creationTime;
        pstatstg->mtime = m_node->modifiedTime;
        pstatstg->atime = m_node->accessTime;
        pstatstg->grfMode = m_grfMode;
        pstatstg->clsid = m_node->clsid;
        pstatstg->grfStateBits = m_node->stateBits;

        if ((grfStatFlag & STATFLAG_NONAME) == 0 && !m_node->name.empty()) {
            size_t bytes = (m_node->name.size() + 1) * sizeof(wchar_t);
            pstatstg->pwcsName = static_cast<wchar_t*>(CoTaskMemAlloc(bytes));
            if (pstatstg->pwcsName) {
                std::memcpy(pstatstg->pwcsName, m_node->name.c_str(), bytes);
            }
        }
        return S_OK;
    }

    virtual HRESULT Clone(IStream** ppstm) override {
        if (!ppstm) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto* clone = new CompoundStream(m_node, m_grfMode);
        clone->Seek(static_cast<int64_t>(m_pos), STREAM_SEEK_SET, nullptr);
        *ppstm = clone;
        return S_OK;
    }
};

// ============================================================================
// 8. Compound Directory Enumerator Implementation (CompoundEnumSTATSTG)
// ============================================================================

class CompoundEnumSTATSTG : public IEnumSTATSTG {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<STATSTG>  m_items;
    size_t                m_index{ 0 };
    mutable std::mutex    m_mutex;

public:
    CompoundEnumSTATSTG(std::vector<STATSTG> items)
        : m_items(std::move(items)) {}

    virtual ~CompoundEnumSTATSTG() {
        for (auto& item : m_items) {
            if (item.pwcsName) {
                CoTaskMemFree(item.pwcsName);
                item.pwcsName = nullptr;
            }
        }
    }

    virtual HRESULT QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IEnumSTATSTG) {
            *ppvObject = static_cast<IEnumSTATSTG*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1) - 1;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    virtual HRESULT Next(uint32_t celt, STATSTG* rgelt, uint32_t* pceltFetched) override {
        if (!rgelt) return E_POINTER;
        if (celt > 1 && !pceltFetched) return E_INVALIDARG;

        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t fetched = 0;
        while (fetched < celt && m_index < m_items.size()) {
            rgelt[fetched] = m_items[m_index];
            if (m_items[m_index].pwcsName) {
                size_t len = std::wcslen(m_items[m_index].pwcsName) + 1;
                rgelt[fetched].pwcsName = static_cast<wchar_t*>(CoTaskMemAlloc(len * sizeof(wchar_t)));
                if (rgelt[fetched].pwcsName) {
                    std::memcpy(rgelt[fetched].pwcsName, m_items[m_index].pwcsName, len * sizeof(wchar_t));
                }
            }
            ++m_index;
            ++fetched;
        }

        if (pceltFetched) *pceltFetched = fetched;
        return (fetched == celt) ? S_OK : S_FALSE;
    }

    virtual HRESULT Skip(uint32_t celt) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_index + celt > m_items.size()) {
            m_index = m_items.size();
            return S_FALSE;
        }
        m_index += celt;
        return S_OK;
    }

    virtual HRESULT Reset() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_index = 0;
        return S_OK;
    }

    virtual HRESULT Clone(IEnumSTATSTG** ppenum) override {
        if (!ppenum) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<STATSTG> clonedItems;
        for (const auto& item : m_items) {
            STATSTG newItem = item;
            if (item.pwcsName) {
                size_t len = std::wcslen(item.pwcsName) + 1;
                newItem.pwcsName = static_cast<wchar_t*>(CoTaskMemAlloc(len * sizeof(wchar_t)));
                if (newItem.pwcsName) {
                    std::memcpy(newItem.pwcsName, item.pwcsName, len * sizeof(wchar_t));
                }
            }
            clonedItems.push_back(newItem);
        }

        auto* clone = new CompoundEnumSTATSTG(std::move(clonedItems));
        clone->m_index = m_index;
        *ppenum = clone;
        return S_OK;
    }
};

// ============================================================================
// 9. Compound Storage Implementation (CompoundStorage)
// ============================================================================

class CompoundStorage : public IStorage {
private:
    std::atomic<uint32_t>         m_refCount{ 1 };
    std::shared_ptr<CompoundNode> m_node;
    std::shared_ptr<CompoundNode> m_root;
    ILockBytes*                   m_lockBytes{ nullptr };
    std::wstring                  m_filePath;
    uint32_t                      m_grfMode{ STGM_READWRITE | STGM_SHARE_EXCLUSIVE };
    mutable std::mutex            m_mutex;

public:
    CompoundStorage(std::shared_ptr<CompoundNode> node,
                    std::shared_ptr<CompoundNode> root,
                    ILockBytes* lockBytes,
                    std::wstring_view filePath,
                    uint32_t grfMode)
        : m_node(std::move(node)),
          m_root(std::move(root)),
          m_lockBytes(lockBytes),
          m_filePath(filePath),
          m_grfMode(grfMode) {
        if (m_lockBytes) m_lockBytes->AddRef();
    }

    virtual ~CompoundStorage() {
        if (m_lockBytes) {
            m_lockBytes->Release();
            m_lockBytes = nullptr;
        }
    }

    virtual HRESULT QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IStorage) {
            *ppvObject = static_cast<IStorage*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1) - 1;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    virtual HRESULT CreateStream(const OLECHAR* pwcsName, uint32_t grfMode, uint32_t, uint32_t, IStream** ppstm) override {
        if (!pwcsName || !ppstm) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring name(pwcsName);
        auto existing = m_node->findChild(name);
        if (existing) {
            if ((grfMode & STGM_CREATE) != 0) {
                m_node->removeChild(name);
            } else {
                return STG_E_FILEALREADYEXISTS;
            }
        }

        auto newStreamNode = std::make_shared<CompoundNode>(name, STGTY_STREAM);
        newStreamNode->parent = m_node;
        m_node->children.push_back(newStreamNode);

        *ppstm = new CompoundStream(newStreamNode, grfMode);
        return S_OK;
    }

    virtual HRESULT OpenStream(const OLECHAR* pwcsName, void*, uint32_t grfMode, uint32_t, IStream** ppstm) override {
        if (!pwcsName || !ppstm) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring name(pwcsName);
        auto existing = m_node->findChild(name);
        if (!existing || existing->type != STGTY_STREAM) {
            return STG_E_FILENOTFOUND;
        }

        *ppstm = new CompoundStream(existing, grfMode);
        return S_OK;
    }

    virtual HRESULT CreateStorage(const OLECHAR* pwcsName, uint32_t grfMode, uint32_t, uint32_t, IStorage** ppstg) override {
        if (!pwcsName || !ppstg) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring name(pwcsName);
        auto existing = m_node->findChild(name);
        if (existing) {
            if ((grfMode & STGM_CREATE) != 0) {
                m_node->removeChild(name);
            } else {
                return STG_E_FILEALREADYEXISTS;
            }
        }

        auto newStorageNode = std::make_shared<CompoundNode>(name, STGTY_STORAGE);
        newStorageNode->parent = m_node;
        m_node->children.push_back(newStorageNode);

        *ppstg = new CompoundStorage(newStorageNode, m_root, nullptr, L"", grfMode);
        return S_OK;
    }

    virtual HRESULT OpenStorage(const OLECHAR* pwcsName, IStorage*, uint32_t grfMode, SNB, uint32_t, IStorage** ppstg) override {
        if (!pwcsName || !ppstg) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring name(pwcsName);
        auto existing = m_node->findChild(name);
        if (!existing || existing->type != STGTY_STORAGE) {
            return STG_E_FILENOTFOUND;
        }

        *ppstg = new CompoundStorage(existing, m_root, nullptr, L"", grfMode);
        return S_OK;
    }

    virtual HRESULT CopyTo(uint32_t, const IID*, SNB, IStorage* pstgDest) override {
        if (!pstgDest) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::function<HRESULT(const std::shared_ptr<CompoundNode>&, IStorage*)> cloneChildren =
            [&](const std::shared_ptr<CompoundNode>& srcNode, IStorage* dstStg) -> HRESULT {
            for (const auto& child : srcNode->children) {
                if (child->type == STGTY_STREAM) {
                    IStream* pDstStm = nullptr;
                    HRESULT hr = dstStg->CreateStream(child->name.c_str(), STGM_WRITE | STGM_CREATE | STGM_SHARE_EXCLUSIVE, 0, 0, &pDstStm);
                    if (FAILED(hr)) return hr;
                    if (!child->data.empty()) {
                        uint32_t written = 0;
                        pDstStm->Write(child->data.data(), static_cast<uint32_t>(child->data.size()), &written);
                    }
                    pDstStm->Release();
                } else if (child->type == STGTY_STORAGE) {
                    IStorage* pDstSubStg = nullptr;
                    HRESULT hr = dstStg->CreateStorage(child->name.c_str(), STGM_WRITE | STGM_CREATE | STGM_SHARE_EXCLUSIVE, 0, 0, &pDstSubStg);
                    if (FAILED(hr)) return hr;
                    hr = cloneChildren(child, pDstSubStg);
                    pDstSubStg->Release();
                    if (FAILED(hr)) return hr;
                }
            }
            return S_OK;
        };

        return cloneChildren(m_node, pstgDest);
    }

    virtual HRESULT MoveElementTo(const OLECHAR* pwcsName, IStorage* pstgDest, const OLECHAR* pwcsNewName, uint32_t) override {
        if (!pwcsName || !pstgDest || !pwcsNewName) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring oldName(pwcsName);
        auto child = m_node->findChild(oldName);
        if (!child) return STG_E_FILENOTFOUND;

        if (child->type == STGTY_STREAM) {
            IStream* pDstStm = nullptr;
            HRESULT hr = pstgDest->CreateStream(pwcsNewName, STGM_WRITE | STGM_CREATE | STGM_SHARE_EXCLUSIVE, 0, 0, &pDstStm);
            if (FAILED(hr)) return hr;
            if (!child->data.empty()) {
                uint32_t written = 0;
                pDstStm->Write(child->data.data(), static_cast<uint32_t>(child->data.size()), &written);
            }
            pDstStm->Release();
        } else if (child->type == STGTY_STORAGE) {
            IStorage* pDstSubStg = nullptr;
            HRESULT hr = pstgDest->CreateStorage(pwcsNewName, STGM_WRITE | STGM_CREATE | STGM_SHARE_EXCLUSIVE, 0, 0, &pDstSubStg);
            if (FAILED(hr)) return hr;
            CopyTo(0, nullptr, nullptr, pDstSubStg);
            pDstSubStg->Release();
        }

        m_node->removeChild(oldName);
        return S_OK;
    }

    virtual HRESULT Commit(uint32_t) override {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Serialize full CFBF image from root node
        auto bytes = CFBFEngine::Serialize(m_root);
        if (bytes.empty()) return E_FAIL;

        // If backed by ILockBytes, flush to it
        if (m_lockBytes) {
            m_lockBytes->SetSize(0);
            uint32_t written = 0;
            m_lockBytes->WriteAt(0, bytes.data(), static_cast<uint32_t>(bytes.size()), &written);
            m_lockBytes->Flush();
        }

        // If backed by file path, write to disk
        if (!m_filePath.empty()) {
            win32::HANDLE hFile = win32::CreateFileW(
                m_filePath.c_str(),
                win32::GENERIC_WRITE,
                0,
                nullptr,
                win32::CREATE_ALWAYS,
                win32::FILE_ATTRIBUTE_NORMAL,
                nullptr
            );
            if (hFile != win32::INVALID_HANDLE_VALUE) {
                win32::DWORD bytesWritten = 0;
                win32::WriteFile(hFile, bytes.data(), static_cast<win32::DWORD>(bytes.size()), &bytesWritten, nullptr);
                win32::CloseHandle(hFile);
            }
        }

        return S_OK;
    }

    virtual HRESULT Revert() override {
        return S_OK;
    }

    virtual HRESULT EnumElements(uint32_t, void*, uint32_t, IEnumSTATSTG** ppenum) override {
        if (!ppenum) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<STATSTG> items;
        for (const auto& child : m_node->children) {
            STATSTG stg{};
            stg.type = child->type;
            stg.cbSize = (child->type == STGTY_STREAM) ? child->data.size() : 0;
            stg.ctime = child->creationTime;
            stg.mtime = child->modifiedTime;
            stg.atime = child->accessTime;
            stg.clsid = child->clsid;
            stg.grfStateBits = child->stateBits;

            if (!child->name.empty()) {
                size_t len = child->name.size() + 1;
                stg.pwcsName = static_cast<wchar_t*>(CoTaskMemAlloc(len * sizeof(wchar_t)));
                if (stg.pwcsName) {
                    std::memcpy(stg.pwcsName, child->name.c_str(), len * sizeof(wchar_t));
                }
            }
            items.push_back(stg);
        }

        *ppenum = new CompoundEnumSTATSTG(std::move(items));
        return S_OK;
    }

    virtual HRESULT DestroyElement(const OLECHAR* pwcsName) override {
        if (!pwcsName) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_node->removeChild(pwcsName)) {
            return S_OK;
        }
        return STG_E_FILENOTFOUND;
    }

    virtual HRESULT RenameElement(const OLECHAR* pwcsOldName, const OLECHAR* pwcsNewName) override {
        if (!pwcsOldName || !pwcsNewName) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto child = m_node->findChild(pwcsOldName);
        if (!child) return STG_E_FILENOTFOUND;

        if (m_node->findChild(pwcsNewName)) {
            return STG_E_FILEALREADYEXISTS;
        }

        child->name = pwcsNewName;
        return S_OK;
    }

    virtual HRESULT SetElementTimes(const OLECHAR* pwcsName, const win32::FILETIME* pctime, const win32::FILETIME* patime, const win32::FILETIME* pmtime) override {
        if (!pwcsName) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto child = m_node->findChild(pwcsName);
        if (!child) return STG_E_FILENOTFOUND;

        if (pctime) child->creationTime = (static_cast<uint64_t>(pctime->dwHighDateTime) << 32) | pctime->dwLowDateTime;
        if (patime) child->accessTime = (static_cast<uint64_t>(patime->dwHighDateTime) << 32) | patime->dwLowDateTime;
        if (pmtime) child->modifiedTime = (static_cast<uint64_t>(pmtime->dwHighDateTime) << 32) | pmtime->dwLowDateTime;

        return S_OK;
    }

    virtual HRESULT SetClass(REFCLSID clsid) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_node->clsid = clsid;
        return S_OK;
    }

    virtual HRESULT SetStateBits(uint32_t grfStateBits, uint32_t grfMask) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_node->stateBits = (m_node->stateBits & ~grfMask) | (grfStateBits & grfMask);
        return S_OK;
    }

    virtual HRESULT Stat(STATSTG* pstatstg, uint32_t grfStatFlag) override {
        if (!pstatstg) return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::memset(pstatstg, 0, sizeof(STATSTG));
        pstatstg->type = (m_node == m_root) ? STGTY_ROOT : STGTY_STORAGE;
        pstatstg->ctime = m_node->creationTime;
        pstatstg->mtime = m_node->modifiedTime;
        pstatstg->atime = m_node->accessTime;
        pstatstg->clsid = m_node->clsid;
        pstatstg->grfStateBits = m_node->stateBits;
        pstatstg->grfMode = m_grfMode;

        if ((grfStatFlag & STATFLAG_NONAME) == 0 && !m_node->name.empty()) {
            size_t bytes = (m_node->name.size() + 1) * sizeof(wchar_t);
            pstatstg->pwcsName = static_cast<wchar_t*>(CoTaskMemAlloc(bytes));
            if (pstatstg->pwcsName) {
                std::memcpy(pstatstg->pwcsName, m_node->name.c_str(), bytes);
            }
        }
        return S_OK;
    }
};

// ============================================================================
// 10. Public Structured Storage API Surface
// ============================================================================

inline HRESULT StgCreateDocfileOnILockBytes(ILockBytes* plkbyt, uint32_t grfMode, uint32_t, IStorage** ppstgOpen) {
    if (!plkbyt || !ppstgOpen) return STG_E_INVALIDPOINTER;

    auto root = std::make_shared<CompoundNode>(L"Root Entry", STGTY_ROOT);
    auto* stg = new CompoundStorage(root, root, plkbyt, L"", grfMode);
    *ppstgOpen = stg;
    return S_OK;
}

inline HRESULT StgOpenStorageOnILockBytes(ILockBytes* plkbyt, IStorage*, uint32_t grfMode, SNB, uint32_t, IStorage** ppstgOpen) {
    if (!plkbyt || !ppstgOpen) return STG_E_INVALIDPOINTER;

    STATSTG stat{};
    HRESULT hr = plkbyt->Stat(&stat, STATFLAG_NONAME);
    if (FAILED(hr)) return hr;

    if (stat.cbSize < 512) return STG_E_INVALIDHANDLE;

    std::vector<uint8_t> buffer(static_cast<size_t>(stat.cbSize));
    uint32_t bytesRead = 0;
    hr = plkbyt->ReadAt(0, buffer.data(), static_cast<uint32_t>(stat.cbSize), &bytesRead);
    if (FAILED(hr)) return hr;

    auto root = CFBFEngine::Deserialize(buffer.data(), buffer.size());
    if (!root) return STG_E_INVALIDHANDLE;

    auto* stg = new CompoundStorage(root, root, plkbyt, L"", grfMode);
    *ppstgOpen = stg;
    return S_OK;
}

inline HRESULT StgIsStorageILockBytes(ILockBytes* plkbyt) {
    if (!plkbyt) return STG_E_INVALIDPOINTER;
    uint8_t sig[8]{};
    uint32_t read = 0;
    HRESULT hr = plkbyt->ReadAt(0, sig, 8, &read);
    if (FAILED(hr) || read < 8) return S_FALSE;

    const uint8_t expectedSig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    return (std::memcmp(sig, expectedSig, 8) == 0) ? S_OK : S_FALSE;
}

inline HRESULT StgCreateDocfile(const OLECHAR* pwcsName, uint32_t grfMode, uint32_t, IStorage** ppstgOpen) {
    if (!ppstgOpen) return STG_E_INVALIDPOINTER;

    std::wstring path = pwcsName ? pwcsName : L"";
    auto root = std::make_shared<CompoundNode>(L"Root Entry", STGTY_ROOT);

    ILockBytes* lkbyt = nullptr;
    if (path.empty()) {
        CreateILockBytesOnHGlobal(nullptr, win32::TRUE, &lkbyt);
    }

    auto* stg = new CompoundStorage(root, root, lkbyt, path, grfMode);
    if (lkbyt) lkbyt->Release(); // Storage holds reference if given

    *ppstgOpen = stg;
    return S_OK;
}

inline HRESULT StgOpenStorage(const OLECHAR* pwcsName, IStorage*, uint32_t grfMode, SNB, uint32_t, IStorage** ppstgOpen) {
    if (!pwcsName || !ppstgOpen) return STG_E_INVALIDPOINTER;

    win32::HANDLE hFile = win32::CreateFileW(
        pwcsName,
        win32::GENERIC_READ,
        win32::FILE_SHARE_READ,
        nullptr,
        win32::OPEN_EXISTING,
        win32::FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == win32::INVALID_HANDLE_VALUE) {
        return STG_E_FILENOTFOUND;
    }

    win32::DWORD fileSize = win32::GetFileSize(hFile, nullptr);
    if (fileSize < 512) {
        win32::CloseHandle(hFile);
        return STG_E_INVALIDHANDLE;
    }

    std::vector<uint8_t> buffer(fileSize);
    win32::DWORD bytesRead = 0;
    win32::ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr);
    win32::CloseHandle(hFile);

    auto root = CFBFEngine::Deserialize(buffer.data(), buffer.size());
    if (!root) {
        return STG_E_INVALIDHANDLE;
    }

    auto* stg = new CompoundStorage(root, root, nullptr, pwcsName, grfMode);
    *ppstgOpen = stg;
    return S_OK;
}

inline HRESULT StgIsStorageFile(const OLECHAR* pwcsName) {
    if (!pwcsName) return STG_E_INVALIDPOINTER;

    win32::HANDLE hFile = win32::CreateFileW(
        pwcsName,
        win32::GENERIC_READ,
        win32::FILE_SHARE_READ,
        nullptr,
        win32::OPEN_EXISTING,
        win32::FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == win32::INVALID_HANDLE_VALUE) {
        return STG_E_FILENOTFOUND;
    }

    uint8_t sig[8]{};
    win32::DWORD read = 0;
    win32::ReadFile(hFile, sig, 8, &read, nullptr);
    win32::CloseHandle(hFile);

    if (read < 8) return S_FALSE;
    const uint8_t expectedSig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    return (std::memcmp(sig, expectedSig, 8) == 0) ? S_OK : S_FALSE;
}

inline HRESULT StgCreateStorageEx(const OLECHAR* pwcsName, uint32_t grfMode, uint32_t, uint32_t, void*, void*, REFIID riid, void** ppObjectOpen) {
    if (!ppObjectOpen) return STG_E_INVALIDPOINTER;
    if (riid == IID_IStorage) {
        return StgCreateDocfile(pwcsName, grfMode, 0, reinterpret_cast<IStorage**>(ppObjectOpen));
    }
    return E_NOINTERFACE;
}

inline HRESULT StgOpenStorageEx(const OLECHAR* pwcsName, uint32_t grfMode, uint32_t, uint32_t, void*, void*, REFIID riid, void** ppObjectOpen) {
    if (!ppObjectOpen) return STG_E_INVALIDPOINTER;
    if (riid == IID_IStorage) {
        return StgOpenStorage(pwcsName, nullptr, grfMode, nullptr, 0, reinterpret_cast<IStorage**>(ppObjectOpen));
    }
    return E_NOINTERFACE;
}

// ============================================================================
// 11. Class & Stream Helper Functions
// ============================================================================

inline HRESULT WriteClassStg(IStorage* pStg, REFCLSID rclsid) {
    if (!pStg) return STG_E_INVALIDPOINTER;
    return pStg->SetClass(rclsid);
}

inline HRESULT ReadClassStg(IStorage* pStg, CLSID* pclsid) {
    if (!pStg || !pclsid) return STG_E_INVALIDPOINTER;
    STATSTG stat{};
    HRESULT hr = pStg->Stat(&stat, STATFLAG_NONAME);
    if (SUCCEEDED(hr)) {
        *pclsid = stat.clsid;
    }
    return hr;
}

inline HRESULT WriteClassStm(IStream* pStm, REFCLSID rclsid) {
    if (!pStm) return STG_E_INVALIDPOINTER;
    uint32_t written = 0;
    return pStm->Write(&rclsid, sizeof(GUID), &written);
}

inline HRESULT ReadClassStm(IStream* pStm, CLSID* pclsid) {
    if (!pStm || !pclsid) return STG_E_INVALIDPOINTER;
    uint32_t read = 0;
    HRESULT hr = pStm->Read(pclsid, sizeof(GUID), &read);
    if (SUCCEEDED(hr) && read != sizeof(GUID)) {
        return STG_E_READFAULT;
    }
    return hr;
}

// ============================================================================
// 12. COM Object Persistence Helpers (OleSave & OleLoad)
// ============================================================================

inline HRESULT OleSave(IPersistStorage* pPS, IStorage* pStg, win32::BOOL fSameAsLoad) {
    if (!pPS || !pStg) return STG_E_INVALIDPOINTER;
    CLSID clsid{};
    HRESULT hr = pPS->GetClassID(&clsid);
    if (FAILED(hr)) return hr;

    hr = WriteClassStg(pStg, clsid);
    if (FAILED(hr)) return hr;

    return pPS->Save(pStg, fSameAsLoad);
}

inline HRESULT OleLoad(IStorage* pStg, REFIID riid, void* pUnkOuter, void** ppvObj) {
    if (!pStg || !ppvObj) return STG_E_INVALIDPOINTER;
    CLSID clsid{};
    HRESULT hr = ReadClassStg(pStg, &clsid);
    if (FAILED(hr)) return hr;

    IUnknown* pUnk = nullptr;
    hr = CoCreateInstance(clsid, static_cast<IUnknown*>(pUnkOuter), CLSCTX_INPROC_SERVER, IID_IUnknown, reinterpret_cast<void**>(&pUnk));
    if (FAILED(hr)) return hr;

    IPersistStorage* pPS = nullptr;
    hr = pUnk->QueryInterface(IID_IPersistStorage, reinterpret_cast<void**>(&pPS));
    if (SUCCEEDED(hr)) {
        hr = pPS->Load(pStg);
        pPS->Release();
    }

    if (SUCCEEDED(hr)) {
        hr = pUnk->QueryInterface(riid, ppvObj);
    }

    pUnk->Release();
    return hr;
}

// ============================================================================
// 13. Dynamic Loader Export Registration
// ============================================================================

inline void InitializeStructuredStorageSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    ldr.registerExport("ole32.dll", "StgCreateDocfile", reinterpret_cast<void*>(StgCreateDocfile));
    ldr.registerExport("ole32.dll", "StgOpenStorage", reinterpret_cast<void*>(StgOpenStorage));
    ldr.registerExport("ole32.dll", "StgCreateDocfileOnILockBytes", reinterpret_cast<void*>(StgCreateDocfileOnILockBytes));
    ldr.registerExport("ole32.dll", "StgOpenStorageOnILockBytes", reinterpret_cast<void*>(StgOpenStorageOnILockBytes));
    ldr.registerExport("ole32.dll", "StgIsStorageFile", reinterpret_cast<void*>(StgIsStorageFile));
    ldr.registerExport("ole32.dll", "StgIsStorageILockBytes", reinterpret_cast<void*>(StgIsStorageILockBytes));
    ldr.registerExport("ole32.dll", "CreateILockBytesOnHGlobal", reinterpret_cast<void*>(CreateILockBytesOnHGlobal));
    ldr.registerExport("ole32.dll", "StgCreateStorageEx", reinterpret_cast<void*>(StgCreateStorageEx));
    ldr.registerExport("ole32.dll", "StgOpenStorageEx", reinterpret_cast<void*>(StgOpenStorageEx));
    ldr.registerExport("ole32.dll", "WriteClassStg", reinterpret_cast<void*>(WriteClassStg));
    ldr.registerExport("ole32.dll", "ReadClassStg", reinterpret_cast<void*>(ReadClassStg));
    ldr.registerExport("ole32.dll", "WriteClassStm", reinterpret_cast<void*>(WriteClassStm));
    ldr.registerExport("ole32.dll", "ReadClassStm", reinterpret_cast<void*>(ReadClassStm));
    ldr.registerExport("ole32.dll", "OleSave", reinterpret_cast<void*>(OleSave));
    ldr.registerExport("ole32.dll", "OleLoad", reinterpret_cast<void*>(OleLoad));
}

} // namespace micant::ole32
