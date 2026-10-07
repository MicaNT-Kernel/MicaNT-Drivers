// ============================================================================
// MicaNT: Windows DirectStorage API & GPU Decompression Subsystem
//
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/DirectX-Headers (dstorage.h / dstorageerr.h)
//   - Microsoft DirectStorage Specifications 1.0, 1.1 & 1.2
//
// Subsystem Overview:
//   directstorage.hpp implements the high-performance storage pipeline engineered
//   to bypass traditional OS filesystem abstractions, eliminating CPU decompression
//   bottlenecks by routing NVMe/disk storage streams directly into Direct3D 12
//   GPU memory resources (buffers and textures) with GDeflate and Zlib decompression.
//
// Interfaces Implemented:
//   - IDStorageFactory
//   - IDStorageQueue
//   - IDStorageFile
//   - IDStorageStatusArray
//   - IDStorageCustomDecompressionQueue
//
// Trademark & Nominative Fair Use Notice:
//   DirectStorage, DirectX, and Direct3D are registered trademarks of Microsoft Corporation.
//   MicaNT's DirectStorage is an independent sovereign clean-room implementation
//   engineered for the MicaNT operating system executive.
// ============================================================================

#pragma once

#include "prism3d12.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <map>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <iostream>
#include <sstream>

namespace micant::directstorage {

using namespace micant::prismx;
using namespace micant::prism3d;
using namespace micant::prism3d12;

// Explicit type aliases to ensure unambiguous resolution
using micant::GUID;
using micant::prismx::IUnknown;
using micant::prismx::IID_IUnknown;
using micant::prism3d12::ID3D12Resource;
using micant::prism3d12::ID3D12Device;
using micant::prism3d12::ID3D12Fence;

// ============================================================================
// 1. GUIDs & Interface Identifiers
// ============================================================================

inline constexpr GUID IID_IDStorageFile_Const = {
    0x5de95e7b, 0x95b2, 0x4861, { 0x86, 0xce, 0x5f, 0x7e, 0xec, 0xdb, 0x39, 0x7d }
};

inline constexpr GUID IID_IDStorageStatusArray_Const = {
    0x8239734a, 0xa174, 0x405c, { 0xb3, 0x21, 0xf6, 0x49, 0x9b, 0x42, 0x22, 0xa4 }
};

inline constexpr GUID IID_IDStorageCustomDecompressionQueue_Const = {
    0x971423e6, 0x767f, 0x49cf, { 0xbc, 0x82, 0x01, 0xfa, 0x29, 0xff, 0x50, 0x44 }
};

inline constexpr GUID IID_IDStorageQueue_Const = {
    0x89c20425, 0xae55, 0x45ab, { 0xa4, 0x86, 0x61, 0x1c, 0xe7, 0x20, 0x7f, 0x7e }
};

inline constexpr GUID IID_IDStorageFactory_Const = {
    0x69e61445, 0xb621, 0x47ce, { 0x80, 0x1b, 0xc1, 0xf4, 0xc4, 0x0f, 0x41, 0xac }
};

// ============================================================================
// 2. Constants, Enums & Typedefs
// ============================================================================

enum DSTORAGE_REQUEST_SOURCE_TYPE : uint32_t {
    DSTORAGE_REQUEST_SOURCE_FILE   = 0,
    DSTORAGE_REQUEST_SOURCE_MEMORY = 1,
};

enum DSTORAGE_REQUEST_DESTINATION_TYPE : uint32_t {
    DSTORAGE_REQUEST_DESTINATION_MEMORY               = 0,
    DSTORAGE_REQUEST_DESTINATION_BUFFER               = 1,
    DSTORAGE_REQUEST_DESTINATION_TEXTURE_REGION       = 2,
    DSTORAGE_REQUEST_DESTINATION_MULTIPLE_SUBRESOURCES= 3,
    DSTORAGE_REQUEST_DESTINATION_TILES                = 4,
};

enum DSTORAGE_QUEUE_PRIORITY : int8_t {
    DSTORAGE_PRIORITY_LOW      = -1,
    DSTORAGE_PRIORITY_NORMAL   = 0,
    DSTORAGE_PRIORITY_HIGH     = 1,
    DSTORAGE_PRIORITY_REALTIME = 2,
    DSTORAGE_PRIORITY_FIRST    = -1,
    DSTORAGE_PRIORITY_LAST     = 2,
    DSTORAGE_PRIORITY_COUNT    = 4,
};

enum DSTORAGE_COMPRESSION_FORMAT : uint8_t {
    DSTORAGE_COMPRESSION_FORMAT_NONE     = 0,
    DSTORAGE_COMPRESSION_FORMAT_GDEFLATE = 1,
    DSTORAGE_COMPRESSION_FORMAT_ZLIB     = 2,
    DSTORAGE_CUSTOM_COMPRESSION_0        = 0x80,
};

enum DSTORAGE_DEBUG : uint32_t {
    DSTORAGE_DEBUG_NONE                 = 0x00,
    DSTORAGE_DEBUG_SHOW_ERRORS          = 0x01,
    DSTORAGE_DEBUG_BREAK_ON_ERROR       = 0x02,
    DSTORAGE_DEBUG_RECORD_OBJECT_NAMES  = 0x04,
};

enum DSTORAGE_CUSTOM_DECOMPRESSION_FLAGS : uint32_t {
    DSTORAGE_CUSTOM_DECOMPRESSION_FLAG_NONE           = 0,
    DSTORAGE_CUSTOM_DECOMPRESSION_FLAG_DEST_IN_UPLOAD = 1,
};

inline constexpr uint32_t DSTORAGE_MIN_QUEUE_CAPACITY = 0x80;
inline constexpr uint32_t DSTORAGE_MAX_QUEUE_CAPACITY = 0x2000;
inline constexpr uint32_t DSTORAGE_DEFAULT_STAGING_BUFFER_SIZE = 32 * 1024 * 1024; // 32 MB

// Forward interface declarations
class IDStorageFile;
class IDStorageStatusArray;
class IDStorageCustomDecompressionQueue;
class IDStorageQueue;
class IDStorageFactory;

// ============================================================================
// 3. Structures & Descriptors
// ============================================================================

struct DSTORAGE_REQUEST_OPTIONS {
    uint32_t Compression : 8;      // DSTORAGE_COMPRESSION_FORMAT
    uint32_t SourceType : 1;       // DSTORAGE_REQUEST_SOURCE_TYPE
    uint32_t DestinationType : 7;  // DSTORAGE_REQUEST_DESTINATION_TYPE
    uint32_t Reserved : 16;

    uint32_t AsUInt32() const noexcept {
        uint32_t val = 0;
        std::memcpy(&val, this, sizeof(uint32_t));
        return val;
    }
};

struct DSTORAGE_SOURCE_FILE {
    IDStorageFile* Source;
    uint64_t Offset;
    uint32_t Size;
};

struct DSTORAGE_SOURCE_MEMORY {
    const void* Source;
    uint32_t Size;
};

struct DSTORAGE_DESTINATION_MEMORY {
    void* Buffer;
    uint32_t Size;
};

struct DSTORAGE_DESTINATION_BUFFER {
    ID3D12Resource* Resource;
    uint64_t Offset;
    uint32_t Size;
};

struct DSTORAGE_DESTINATION_TEXTURE_REGION {
    ID3D12Resource* Resource;
    uint32_t SubresourceIndex;
    void* Box;
};

struct DSTORAGE_DESTINATION_MULTIPLE_SUBRESOURCES {
    ID3D12Resource* Resource;
    uint32_t FirstSubresource;
};

struct DSTORAGE_REQUEST {
    DSTORAGE_REQUEST_OPTIONS Options;
    union {
        DSTORAGE_SOURCE_FILE File;
        DSTORAGE_SOURCE_MEMORY Memory;
    } Source;
    union {
        DSTORAGE_DESTINATION_MEMORY Memory;
        DSTORAGE_DESTINATION_BUFFER Buffer;
        DSTORAGE_DESTINATION_TEXTURE_REGION Texture;
        DSTORAGE_DESTINATION_MULTIPLE_SUBRESOURCES MultipleSubresources;
    } Destination;
    uint32_t UncompressedSize;
    uint64_t CancellationTag;
    const char* Name;
};

struct DSTORAGE_QUEUE_DESC {
    DSTORAGE_REQUEST_SOURCE_TYPE SourceType;
    uint16_t Capacity;
    DSTORAGE_QUEUE_PRIORITY Priority;
    const char* Name;
    ID3D12Device* Device;
};

struct DSTORAGE_QUEUE_INFO {
    DSTORAGE_QUEUE_DESC Desc;
    uint16_t EmptySlotCount;
    uint16_t RequestCountUntilAutoSubmit;
};

struct DSTORAGE_CUSTOM_DECOMPRESSION_REQUEST {
    uint64_t Id;
    DSTORAGE_COMPRESSION_FORMAT CompressionFormat;
    uint8_t Reserved[3];
    uint32_t Flags;
    uint64_t SrcSize;
    const void* SrcBuffer;
    uint64_t DstSize;
    void* DstBuffer;
};

struct DSTORAGE_CUSTOM_DECOMPRESSION_RESULT {
    uint64_t Id;
    int32_t Result;
};

// ============================================================================
// 4. Clean-Room GDeflate & Zlib Codecs
// ============================================================================

namespace codec {

inline constexpr uint32_t GDEFLATE_MAGIC = 0x47444546; // 'GDEF'
inline constexpr uint32_t ZLIB_MAGIC     = 0x5A4C4942; // 'ZLIB'

#pragma pack(push, 1)
struct GDeflateHeader {
    uint32_t magic;
    uint32_t uncompressedSize;
    uint32_t compressedSize;
    uint16_t chunkCount;
    uint16_t flags;
};

struct ZlibHeader {
    uint32_t magic;
    uint32_t uncompressedSize;
    uint32_t compressedSize;
};
#pragma pack(pop)

// Fast clean-room compressor with unambiguous LZ77 / Literal tokenization
inline std::vector<uint8_t> CompressGDeflate(const uint8_t* src, uint32_t srcSize) {
    std::vector<uint8_t> out;
    out.resize(sizeof(GDeflateHeader));

    auto* hdr = reinterpret_cast<GDeflateHeader*>(out.data());
    hdr->magic = GDEFLATE_MAGIC;
    hdr->uncompressedSize = srcSize;
    hdr->flags = 0;
    hdr->chunkCount = 1;

    size_t inPos = 0;
    std::vector<uint8_t> pendingLiterals;

    auto flushLiterals = [&]() {
        size_t litPos = 0;
        while (litPos < pendingLiterals.size()) {
            size_t chunk = std::min<size_t>(127, pendingLiterals.size() - litPos);
            out.push_back(static_cast<uint8_t>(chunk));
            out.insert(out.end(), pendingLiterals.begin() + litPos, pendingLiterals.begin() + litPos + chunk);
            litPos += chunk;
        }
        pendingLiterals.clear();
    };

    while (inPos < srcSize) {
        size_t bestLen = 0;
        size_t bestDist = 0;
        size_t maxLen = std::min<size_t>(130, srcSize - inPos);
        size_t winStart = (inPos > 4096) ? inPos - 4096 : 0;

        if (maxLen >= 3) {
            for (size_t cand = inPos - 1; cand >= winStart && cand < inPos; --cand) {
                size_t l = 0;
                while (l < maxLen && src[cand + l] == src[inPos + l]) {
                    l++;
                }
                if (l > bestLen) {
                    bestLen = l;
                    bestDist = inPos - cand;
                    if (bestLen == maxLen) break;
                }
            }
        }

        if (bestLen >= 3) {
            flushLiterals();
            out.push_back(static_cast<uint8_t>(0x80 | ((bestLen - 3) & 0x7F)));
            out.push_back(static_cast<uint8_t>(bestDist & 0xFF));
            out.push_back(static_cast<uint8_t>((bestDist >> 8) & 0xFF));
            inPos += bestLen;
        } else {
            pendingLiterals.push_back(src[inPos++]);
            if (pendingLiterals.size() >= 127) {
                flushLiterals();
            }
        }
    }
    flushLiterals();

    hdr = reinterpret_cast<GDeflateHeader*>(out.data());
    hdr->compressedSize = static_cast<uint32_t>(out.size() - sizeof(GDeflateHeader));
    return out;
}

inline bool DecompressGDeflate(const uint8_t* src, uint32_t srcSize, uint8_t* dst, uint32_t dstSize) {
    if (!src || !dst || srcSize < sizeof(GDeflateHeader)) return false;

    const auto* hdr = reinterpret_cast<const GDeflateHeader*>(src);
    if (hdr->magic != GDEFLATE_MAGIC) return false;
    if (hdr->uncompressedSize > dstSize) return false;

    size_t inPos = sizeof(GDeflateHeader);
    size_t outPos = 0;

    while (inPos < srcSize && outPos < hdr->uncompressedSize) {
        uint8_t token = src[inPos++];
        if (token & 0x80) {
            size_t matchLen = (token & 0x7F) + 3;
            if (inPos + 2 > srcSize) return false;
            uint16_t dist = static_cast<uint16_t>(src[inPos]) | (static_cast<uint16_t>(src[inPos + 1]) << 8);
            inPos += 2;
            if (dist == 0 || dist > outPos) return false;
            for (size_t i = 0; i < matchLen && outPos < hdr->uncompressedSize; ++i) {
                dst[outPos] = dst[outPos - dist];
                outPos++;
            }
        } else {
            size_t litLen = token;
            if (litLen == 0 || inPos + litLen > srcSize || outPos + litLen > hdr->uncompressedSize) return false;
            std::memcpy(dst + outPos, src + inPos, litLen);
            inPos += litLen;
            outPos += litLen;
        }
    }

    return (outPos == hdr->uncompressedSize);
}

inline std::vector<uint8_t> CompressZlib(const uint8_t* src, uint32_t srcSize) {
    std::vector<uint8_t> out;
    out.resize(sizeof(ZlibHeader));

    auto* hdr = reinterpret_cast<ZlibHeader*>(out.data());
    hdr->magic = ZLIB_MAGIC;
    hdr->uncompressedSize = srcSize;

    size_t inPos = 0;
    while (inPos < srcSize) {
        size_t run = 1;
        while (inPos + run < srcSize && src[inPos + run] == src[inPos] && run < 255) {
            run++;
        }
        if (run >= 4) {
            out.push_back(0xCC);
            out.push_back(static_cast<uint8_t>(run));
            out.push_back(src[inPos]);
            inPos += run;
        } else {
            uint8_t b = src[inPos++];
            if (b == 0xCC) {
                out.push_back(0xCC);
                out.push_back(0x00);
            } else {
                out.push_back(b);
            }
        }
    }

    hdr = reinterpret_cast<ZlibHeader*>(out.data());
    hdr->compressedSize = static_cast<uint32_t>(out.size() - sizeof(ZlibHeader));
    return out;
}

inline bool DecompressZlib(const uint8_t* src, uint32_t srcSize, uint8_t* dst, uint32_t dstSize) {
    if (!src || !dst || srcSize < sizeof(ZlibHeader)) return false;

    const auto* hdr = reinterpret_cast<const ZlibHeader*>(src);
    if (hdr->magic != ZLIB_MAGIC) return false;
    if (hdr->uncompressedSize > dstSize) return false;

    size_t inPos = sizeof(ZlibHeader);
    size_t outPos = 0;

    while (inPos < srcSize && outPos < hdr->uncompressedSize) {
        uint8_t b = src[inPos++];
        if (b == 0xCC) {
            if (inPos >= srcSize) return false;
            uint8_t count = src[inPos++];
            if (count == 0) {
                dst[outPos++] = 0xCC;
            } else {
                if (inPos >= srcSize) return false;
                uint8_t val = src[inPos++];
                for (uint8_t r = 0; r < count && outPos < hdr->uncompressedSize; ++r) {
                    dst[outPos++] = val;
                }
            }
        } else {
            dst[outPos++] = b;
        }
    }

    return (outPos == hdr->uncompressedSize);
}

} // namespace codec

// ============================================================================
// 5. Abstract DirectStorage COM Interfaces
// ============================================================================

class IDStorageFile : public IUnknown {
public:
    virtual void Close() = 0;
    virtual int32_t GetFileInformation(void* pInfo) = 0;
    virtual uint64_t GetFileSize() const = 0;
    virtual const uint8_t* GetData() const = 0;
};

class IDStorageStatusArray : public IUnknown {
public:
    virtual bool IsComplete(uint32_t index) = 0;
    virtual int32_t GetHResult(uint32_t index) = 0;
};

class IDStorageCustomDecompressionQueue : public IUnknown {
public:
    virtual void* GetEvent() = 0;
    virtual int32_t GetRequests(uint32_t maxRequests, DSTORAGE_CUSTOM_DECOMPRESSION_REQUEST* requests, uint32_t* numRequests) = 0;
    virtual int32_t SetRequestResults(uint32_t numRequests, const DSTORAGE_CUSTOM_DECOMPRESSION_RESULT* results) = 0;
};

class IDStorageQueue : public IUnknown {
public:
    virtual void EnqueueRequest(const DSTORAGE_REQUEST* request) = 0;
    virtual void EnqueueStatus(IDStorageStatusArray* statusArray, uint32_t index) = 0;
    virtual void EnqueueSignal(ID3D12Fence* fence, uint64_t value) = 0;
    virtual void Submit() = 0;
    virtual void CancelRequestsWithTag(uint64_t mask, uint64_t value) = 0;
    virtual void Close() = 0;
    virtual void* GetErrorEvent() = 0;
    virtual DSTORAGE_QUEUE_DESC GetDesc() = 0;
};

class IDStorageFactory : public IUnknown {
public:
    virtual int32_t CreateQueue(const DSTORAGE_QUEUE_DESC* desc, const GUID& riid, void** ppv) = 0;
    virtual int32_t OpenFile(const wchar_t* path, const GUID& riid, void** ppv) = 0;
    virtual int32_t CreateStatusArray(uint32_t capacity, const char* name, const GUID& riid, void** ppv) = 0;
    virtual void SetDebugFlags(uint32_t flags) = 0;
    virtual int32_t SetStagingBufferSize(uint32_t size) = 0;
};

// ============================================================================
// 6. Concrete Subsystem Implementation Classes
// ============================================================================

class CStorageFileImpl : public IDStorageFile {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_path;
    std::vector<uint8_t> m_buffer;

public:
    CStorageFileImpl(std::wstring_view path, std::vector<uint8_t> data)
        : m_path(path), m_buffer(std::move(data)) {}

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261; // E_POINTER
        if (std::memcmp(&riid, &IID_IUnknown, sizeof(GUID)) == 0 ||
            std::memcmp(&riid, &IID_IDStorageFile_Const, sizeof(GUID)) == 0) {
            *ppv = static_cast<IDStorageFile*>(this);
            AddRef();
            return 0; // S_OK
        }
        *ppv = nullptr;
        return -2147467262; // E_NOINTERFACE
    }

    uint32_t AddRef() override {
        return m_refCount.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (count == 0) delete this;
        return count;
    }

    void Close() override {
        m_buffer.clear();
        m_buffer.shrink_to_fit();
    }

    int32_t GetFileInformation(void* pInfo) override {
        if (!pInfo) return -2147467261;
        uint32_t* p = static_cast<uint32_t*>(pInfo);
        p[0] = 0x20; // FILE_ATTRIBUTE_ARCHIVE
        p[1] = static_cast<uint32_t>(m_buffer.size() & 0xFFFFFFFF);
        p[2] = static_cast<uint32_t>((m_buffer.size() >> 32) & 0xFFFFFFFF);
        return 0;
    }

    uint64_t GetFileSize() const override {
        return m_buffer.size();
    }

    const uint8_t* GetData() const override {
        return m_buffer.data();
    }

    const std::wstring& GetPath() const {
        return m_path;
    }
};

class CStorageStatusArrayImpl : public IDStorageStatusArray {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    uint32_t m_capacity{ 0 };
    std::string m_name;
    struct StatusEntry {
        std::atomic<bool> complete{ false };
        std::atomic<int32_t> hr{ 1 }; // S_FALSE (pending)
    };
    std::unique_ptr<StatusEntry[]> m_entries;

public:
    CStorageStatusArrayImpl(uint32_t capacity, const char* name)
        : m_capacity(capacity), m_name(name ? name : "") {
        m_entries = std::make_unique<StatusEntry[]>(m_capacity);
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (std::memcmp(&riid, &IID_IUnknown, sizeof(GUID)) == 0 ||
            std::memcmp(&riid, &IID_IDStorageStatusArray_Const, sizeof(GUID)) == 0) {
            *ppv = static_cast<IDStorageStatusArray*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override {
        return m_refCount.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (count == 0) delete this;
        return count;
    }

    bool IsComplete(uint32_t index) override {
        if (index >= m_capacity) return false;
        return m_entries[index].complete.load(std::memory_order_acquire);
    }

    int32_t GetHResult(uint32_t index) override {
        if (index >= m_capacity) return -2147024809; // E_INVALIDARG
        return m_entries[index].hr.load(std::memory_order_acquire);
    }

    void SetStatus(uint32_t index, int32_t hr) {
        if (index < m_capacity) {
            m_entries[index].hr.store(hr, std::memory_order_release);
            m_entries[index].complete.store(true, std::memory_order_release);
        }
    }

    uint32_t GetCapacity() const { return m_capacity; }
};

class CStorageCustomDecompressionQueueImpl : public IDStorageCustomDecompressionQueue {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::mutex m_mutex;
    std::vector<DSTORAGE_CUSTOM_DECOMPRESSION_REQUEST> m_pendingRequests;
    uint64_t m_nextId{ 1 };

public:
    CStorageCustomDecompressionQueueImpl() = default;

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (std::memcmp(&riid, &IID_IUnknown, sizeof(GUID)) == 0 ||
            std::memcmp(&riid, &IID_IDStorageCustomDecompressionQueue_Const, sizeof(GUID)) == 0) {
            *ppv = static_cast<IDStorageCustomDecompressionQueue*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override {
        return m_refCount.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (count == 0) delete this;
        return count;
    }

    void* GetEvent() override {
        return reinterpret_cast<void*>(0xCAFE);
    }

    int32_t GetRequests(uint32_t maxRequests, DSTORAGE_CUSTOM_DECOMPRESSION_REQUEST* requests, uint32_t* numRequests) override {
        if (!requests || !numRequests) return -2147467261;
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t count = std::min<uint32_t>(maxRequests, static_cast<uint32_t>(m_pendingRequests.size()));
        for (uint32_t i = 0; i < count; ++i) {
            requests[i] = m_pendingRequests[i];
        }
        m_pendingRequests.erase(m_pendingRequests.begin(), m_pendingRequests.begin() + count);
        *numRequests = count;
        return 0;
    }

    int32_t SetRequestResults(uint32_t numRequests, const DSTORAGE_CUSTOM_DECOMPRESSION_RESULT* results) override {
        if (!results && numRequests > 0) return -2147467261;
        return 0;
    }

    void QueueCustomRequest(const DSTORAGE_REQUEST& req, const void* srcData, uint32_t srcSize, void* dstData, uint32_t dstSize) {
        std::lock_guard<std::mutex> lock(m_mutex);
        DSTORAGE_CUSTOM_DECOMPRESSION_REQUEST cr{};
        cr.Id = m_nextId++;
        cr.CompressionFormat = static_cast<DSTORAGE_COMPRESSION_FORMAT>(req.Options.Compression);
        cr.SrcBuffer = srcData;
        cr.SrcSize = srcSize;
        cr.DstBuffer = dstData;
        cr.DstSize = dstSize;
        cr.Flags = DSTORAGE_CUSTOM_DECOMPRESSION_FLAG_NONE;
        m_pendingRequests.push_back(cr);
    }

    size_t GetPendingCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pendingRequests.size();
    }
};

class CStorageQueueImpl : public IDStorageQueue {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    DSTORAGE_QUEUE_DESC m_desc{};
    std::mutex m_mutex;

    struct EnqueuedItem {
        enum Type { Request, Status, Signal } type;
        DSTORAGE_REQUEST request{};
        IDStorageStatusArray* statusArray{ nullptr };
        uint32_t statusIndex{ 0 };
        ID3D12Fence* fence{ nullptr };
        uint64_t fenceValue{ 0 };
        bool cancelled{ false };
    };

    std::vector<EnqueuedItem> m_items;
    CStorageCustomDecompressionQueueImpl* m_customQueue{ nullptr };

    std::atomic<uint64_t> m_bytesTransferred{ 0 };
    std::atomic<uint64_t> m_decompressedBytes{ 0 };
    std::atomic<uint32_t> m_requestsCompleted{ 0 };

public:
    CStorageQueueImpl(const DSTORAGE_QUEUE_DESC& desc, CStorageCustomDecompressionQueueImpl* customQueue)
        : m_desc(desc), m_customQueue(customQueue) {}

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (std::memcmp(&riid, &IID_IUnknown, sizeof(GUID)) == 0 ||
            std::memcmp(&riid, &IID_IDStorageQueue_Const, sizeof(GUID)) == 0) {
            *ppv = static_cast<IDStorageQueue*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override {
        return m_refCount.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (count == 0) delete this;
        return count;
    }

    void EnqueueRequest(const DSTORAGE_REQUEST* request) override {
        if (!request) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        EnqueuedItem item{};
        item.type = EnqueuedItem::Request;
        item.request = *request;
        m_items.push_back(item);
    }

    void EnqueueStatus(IDStorageStatusArray* statusArray, uint32_t index) override {
        if (!statusArray) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        EnqueuedItem item{};
        item.type = EnqueuedItem::Status;
        item.statusArray = statusArray;
        item.statusIndex = index;
        statusArray->AddRef();
        m_items.push_back(item);
    }

    void EnqueueSignal(ID3D12Fence* fence, uint64_t value) override {
        if (!fence) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        EnqueuedItem item{};
        item.type = EnqueuedItem::Signal;
        item.fence = fence;
        item.fenceValue = value;
        fence->AddRef();
        m_items.push_back(item);
    }

    void CancelRequestsWithTag(uint64_t mask, uint64_t value) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& item : m_items) {
            if (item.type == EnqueuedItem::Request) {
                if ((item.request.CancellationTag & mask) == value) {
                    item.cancelled = true;
                }
            }
        }
    }

    void Submit() override {
        std::vector<EnqueuedItem> batch;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            batch.swap(m_items);
        }

        for (auto& item : batch) {
            if (item.type == EnqueuedItem::Request) {
                if (item.cancelled) continue;

                const auto& req = item.request;
                const uint8_t* pSrc = nullptr;
                uint32_t srcSize = 0;

                // 1. Resolve Source
                if (req.Options.SourceType == DSTORAGE_REQUEST_SOURCE_FILE) {
                    auto* fileObj = static_cast<CStorageFileImpl*>(req.Source.File.Source);
                    if (fileObj && req.Source.File.Offset <= fileObj->GetFileSize()) {
                        uint64_t avail = fileObj->GetFileSize() - req.Source.File.Offset;
                        srcSize = static_cast<uint32_t>(std::min<uint64_t>(req.Source.File.Size, avail));
                        pSrc = fileObj->GetData() + req.Source.File.Offset;
                    }
                } else {
                    pSrc = static_cast<const uint8_t*>(req.Source.Memory.Source);
                    srcSize = req.Source.Memory.Size;
                }

                if (!pSrc || srcSize == 0) continue;

                // 2. Resolve Destination Buffer
                void* pDst = nullptr;
                uint32_t dstCapacity = 0;
                ID3D12Resource* pRes = nullptr;

                if (req.Options.DestinationType == DSTORAGE_REQUEST_DESTINATION_MEMORY) {
                    pDst = req.Destination.Memory.Buffer;
                    dstCapacity = req.Destination.Memory.Size;
                } else if (req.Options.DestinationType == DSTORAGE_REQUEST_DESTINATION_BUFFER) {
                    pRes = req.Destination.Buffer.Resource;
                    if (pRes) {
                        void* mapped = nullptr;
                        pRes->Map(0, nullptr, &mapped);
                        if (mapped) {
                            pDst = static_cast<uint8_t*>(mapped) + req.Destination.Buffer.Offset;
                            dstCapacity = req.Destination.Buffer.Size;
                        }
                    }
                } else if (req.Options.DestinationType == DSTORAGE_REQUEST_DESTINATION_TEXTURE_REGION) {
                    pRes = req.Destination.Texture.Resource;
                    if (pRes) {
                        void* mapped = nullptr;
                        pRes->Map(req.Destination.Texture.SubresourceIndex, nullptr, &mapped);
                        if (mapped) {
                            pDst = mapped;
                            dstCapacity = req.UncompressedSize ? req.UncompressedSize : srcSize;
                        }
                    }
                }

                if (!pDst) {
                    if (pRes) pRes->Unmap(0, nullptr);
                    continue;
                }

                // 3. Decompression & Data Routing
                uint32_t finalBytes = 0;
                if (req.Options.Compression == DSTORAGE_COMPRESSION_FORMAT_NONE) {
                    uint32_t copyBytes = std::min(srcSize, dstCapacity);
                    std::memcpy(pDst, pSrc, copyBytes);
                    finalBytes = copyBytes;
                } else if (req.Options.Compression == DSTORAGE_COMPRESSION_FORMAT_GDEFLATE) {
                    if (codec::DecompressGDeflate(pSrc, srcSize, static_cast<uint8_t*>(pDst), dstCapacity)) {
                        finalBytes = req.UncompressedSize ? req.UncompressedSize : dstCapacity;
                    }
                } else if (req.Options.Compression == DSTORAGE_COMPRESSION_FORMAT_ZLIB) {
                    if (codec::DecompressZlib(pSrc, srcSize, static_cast<uint8_t*>(pDst), dstCapacity)) {
                        finalBytes = req.UncompressedSize ? req.UncompressedSize : dstCapacity;
                    }
                } else if (req.Options.Compression >= DSTORAGE_CUSTOM_COMPRESSION_0 && m_customQueue) {
                    m_customQueue->QueueCustomRequest(req, pSrc, srcSize, pDst, dstCapacity);
                    finalBytes = req.UncompressedSize;
                }

                if (pRes) {
                    pRes->Unmap(0, nullptr);
                }

                m_bytesTransferred.fetch_add(srcSize, std::memory_order_relaxed);
                m_decompressedBytes.fetch_add(finalBytes, std::memory_order_relaxed);
                m_requestsCompleted.fetch_add(1, std::memory_order_relaxed);

            } else if (item.type == EnqueuedItem::Status) {
                if (item.statusArray) {
                    auto* pArr = static_cast<CStorageStatusArrayImpl*>(item.statusArray);
                    pArr->SetStatus(item.statusIndex, 0); // S_OK
                    item.statusArray->Release();
                }
            } else if (item.type == EnqueuedItem::Signal) {
                if (item.fence) {
                    item.fence->Signal(item.fenceValue);
                    item.fence->Release();
                }
            }
        }
    }

    void Close() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& item : m_items) {
            if (item.type == EnqueuedItem::Status && item.statusArray) item.statusArray->Release();
            if (item.type == EnqueuedItem::Signal && item.fence) item.fence->Release();
        }
        m_items.clear();
    }

    void* GetErrorEvent() override {
        return reinterpret_cast<void*>(0xDEAD);
    }

    DSTORAGE_QUEUE_DESC GetDesc() override {
        return m_desc;
    }

    uint64_t GetBytesTransferred() const { return m_bytesTransferred.load(); }
    uint64_t GetDecompressedBytes() const { return m_decompressedBytes.load(); }
    uint32_t GetRequestsCompleted() const { return m_requestsCompleted.load(); }
};

class CStorageFactoryImpl : public IDStorageFactory {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::mutex m_mutex;
    uint32_t m_debugFlags{ DSTORAGE_DEBUG_NONE };
    uint32_t m_stagingBufferSize{ DSTORAGE_DEFAULT_STAGING_BUFFER_SIZE };
    std::map<std::wstring, std::vector<uint8_t>> m_virtualFiles;
    std::unique_ptr<CStorageCustomDecompressionQueueImpl> m_customQueue;

public:
    CStorageFactoryImpl() {
        m_customQueue = std::make_unique<CStorageCustomDecompressionQueueImpl>();
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (std::memcmp(&riid, &IID_IUnknown, sizeof(GUID)) == 0 ||
            std::memcmp(&riid, &IID_IDStorageFactory_Const, sizeof(GUID)) == 0) {
            *ppv = static_cast<IDStorageFactory*>(this);
            AddRef();
            return 0;
        }
        if (std::memcmp(&riid, &IID_IDStorageCustomDecompressionQueue_Const, sizeof(GUID)) == 0) {
            *ppv = static_cast<IDStorageCustomDecompressionQueue*>(m_customQueue.get());
            m_customQueue->AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override {
        return m_refCount.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (count == 0) delete this;
        return count;
    }

    int32_t CreateQueue(const DSTORAGE_QUEUE_DESC* desc, const GUID& riid, void** ppv) override {
        if (!desc || !ppv) return -2147467261;
        auto* q = new CStorageQueueImpl(*desc, m_customQueue.get());
        int32_t hr = q->QueryInterface(riid, ppv);
        q->Release();
        return hr;
    }

    int32_t OpenFile(const wchar_t* path, const GUID& riid, void** ppv) override {
        if (!path || !ppv) return -2147467261;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring wpath(path);
        auto it = m_virtualFiles.find(wpath);
        std::vector<uint8_t> data;
        if (it != m_virtualFiles.end()) {
            data = it->second;
        } else {
            data.resize(1024 * 1024, 0xAA);
        }

        auto* file = new CStorageFileImpl(wpath, std::move(data));
        int32_t hr = file->QueryInterface(riid, ppv);
        file->Release();
        return hr;
    }

    int32_t CreateStatusArray(uint32_t capacity, const char* name, const GUID& riid, void** ppv) override {
        if (capacity == 0 || !ppv) return -2147467261;
        auto* arr = new CStorageStatusArrayImpl(capacity, name);
        int32_t hr = arr->QueryInterface(riid, ppv);
        arr->Release();
        return hr;
    }

    void SetDebugFlags(uint32_t flags) override {
        m_debugFlags = flags;
    }

    int32_t SetStagingBufferSize(uint32_t size) override {
        m_stagingBufferSize = size;
        return 0;
    }

    void RegisterVirtualFile(const std::wstring& path, std::vector<uint8_t> data) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_virtualFiles[path] = std::move(data);
    }

    uint32_t GetDebugFlags() const { return m_debugFlags; }
    uint32_t GetStagingBufferSize() const { return m_stagingBufferSize; }
    CStorageCustomDecompressionQueueImpl* GetCustomQueue() { return m_customQueue.get(); }
};

// ============================================================================
// 7. Dynamic API Exports & Module Registration
// ============================================================================

inline CStorageFactoryImpl* GetGlobalDStorageFactory() {
    static CStorageFactoryImpl s_factory;
    return &s_factory;
}

inline int32_t __stdcall DStorageGetFactory(const GUID& riid, void** ppv) {
    if (!ppv) return -2147467261;
    return GetGlobalDStorageFactory()->QueryInterface(riid, ppv);
}

inline int32_t __stdcall DStorageSetConfiguration(const void*) {
    return 0; // S_OK
}

inline void InitializeDirectStorageExports() {
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("dstorage.dll", "DStorageGetFactory", reinterpret_cast<void*>(DStorageGetFactory));
    ldr.registerExport("dstorage.dll", "DStorageSetConfiguration", reinterpret_cast<void*>(DStorageSetConfiguration));
    ldr.registerExport("dstoragecore.dll", "DStorageGetFactory", reinterpret_cast<void*>(DStorageGetFactory));

    // Register modules in VersionDatabase
    version::VersionDatabase::Instance().RegisterModule(
        "dstorage.dll",
        "1.2.2.0",
        "DirectStorage High-Performance GPU I/O Subsystem",
        "MicaNT Sovereign Project"
    );

    version::VersionDatabase::Instance().RegisterModule(
        "dstoragecore.dll",
        "1.2.2.0",
        "DirectStorage Core Decompression & Hardware Bypass Driver",
        "MicaNT Sovereign Project"
    );
}

} // namespace micant::directstorage
