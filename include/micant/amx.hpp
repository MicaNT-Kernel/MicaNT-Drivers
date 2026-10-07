// ============================================================================
// MicaNT Clean-Room Kernel - Intel AMX & Arm SME Matrix Accelerator Subsystem
// File: include/micant/amx.hpp
//
// Provenance & Clean-Room Statement:
// Authored strictly from public processor architecture manuals and open
// specifications:
//   - Intel 64 and IA-32 Architectures Software Developer's Manual (SDM):
//     Volume 1 Chapter 3, Volume 2 Chapter 5, Volume 3 Chapter 13 (AMX, XSAVE)
//   - Intel Advanced Matrix Extensions (Intel AMX) Architecture Specification:
//     AMX-TILE, AMX-INT8, AMX-BF16, AMX-FP16, and TMUL Matrix Multiplication
//   - Arm Architecture Reference Manual Armv9-A:
//     Scalable Matrix Extension (SME / SME2) & Streaming SVE Mode
//   - Microsoft Open Specifications & win32metadata:
//     Extended Processor State (XState / XSAVE) and Tile State Management
//
// Sovereign Codename: TitanMatrix / NexusAMX
// Strict ISO C++23, zero external dependencies, 100% offline, zero telemetry.
// ============================================================================

#ifndef MICANT_AMX_HPP
#define MICANT_AMX_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <cmath>
#include "ntstatus.hpp"
#include "scm.hpp"
#include "version.hpp"

namespace micant::amx {

// Common NTSTATUS codes
#ifndef STATUS_SUCCESS
constexpr int32_t STATUS_SUCCESS = 0x00000000;
#endif
#ifndef STATUS_UNSUCCESSFUL
constexpr int32_t STATUS_UNSUCCESSFUL = static_cast<int32_t>(0xC0000001);
#endif
#ifndef STATUS_ACCESS_VIOLATION
constexpr int32_t STATUS_ACCESS_VIOLATION = static_cast<int32_t>(0xC0000005);
#endif
#ifndef STATUS_INVALID_PARAMETER
constexpr int32_t STATUS_INVALID_PARAMETER = static_cast<int32_t>(0xC000000D);
#endif
#ifndef STATUS_ILLEGAL_INSTRUCTION
constexpr int32_t STATUS_ILLEGAL_INSTRUCTION = static_cast<int32_t>(0xC000001D);
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
constexpr int32_t STATUS_BUFFER_TOO_SMALL = static_cast<int32_t>(0xC0000023);
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
constexpr int32_t STATUS_INSUFFICIENT_RESOURCES = static_cast<int32_t>(0xC000009A);
#endif
#ifndef STATUS_DEVICE_NOT_READY
constexpr int32_t STATUS_DEVICE_NOT_READY = static_cast<int32_t>(0xC00000A3);
#endif

// XState Component Masks for Intel AMX (XCR0)
constexpr uint64_t XFEATURE_MASK_XTILECFG  = (1ULL << 17);
constexpr uint64_t XFEATURE_MASK_XTILEDATA = (1ULL << 18);
constexpr uint64_t XFEATURE_MASK_AMX       = (XFEATURE_MASK_XTILECFG | XFEATURE_MASK_XTILEDATA);

// AMX Constants
constexpr uint32_t AMX_PALETTE_ID_NONE     = 0;
constexpr uint32_t AMX_PALETTE_ID_1        = 1;
constexpr uint32_t AMX_MAX_TILES           = 8;    // TMM0 .. TMM7
constexpr uint32_t AMX_MAX_ROWS            = 16;   // Max rows per tile in Palette 1
constexpr uint32_t AMX_MAX_COLS_BYTES      = 64;   // Max bytes per row (64 bytes = 512 bits)
constexpr uint32_t AMX_TILE_BYTES          = 1024; // 1 KB per tile
constexpr uint32_t AMX_TOTAL_TILE_BYTES    = 8192; // 8 KB total register file

// Arm SME Constants
constexpr uint32_t ARM_SME_DEFAULT_SVL_BITS = 512; // Streaming Vector Length (bits)
constexpr uint32_t ARM_SME_MAX_TILES        = 8;   // ZA0 .. ZA7

#pragma pack(push, 1)
// 64-byte Tile Configuration Structure (Intel AMX SDM §3.2 TILECFG)
struct TileConfig {
    uint8_t  paletteId;             // Byte 0: Palette ID (0=init, 1=valid)
    uint8_t  startRow;              // Byte 1: Start row for restartable load/store
    uint8_t  reserved0[14];         // Bytes 2-15: Reserved (must be 0)
    uint16_t colsb[AMX_MAX_TILES];  // Bytes 16-31: Bytes per row for TMM0..TMM7 (max 64)
    uint8_t  rows[AMX_MAX_TILES];   // Bytes 32-39: Number of rows for TMM0..TMM7 (max 16)
    uint8_t  reserved1[24];         // Bytes 40-63: Reserved (must be 0)
};
static_assert(sizeof(TileConfig) == 64, "TileConfig must be exactly 64 bytes");

// 1 KB Tile Register Structure
struct TileRegister {
    uint8_t data[AMX_MAX_ROWS][AMX_MAX_COLS_BYTES]; // 16 rows x 64 bytes = 1024 bytes
};
static_assert(sizeof(TileRegister) == 1024, "TileRegister must be exactly 1024 bytes");

// 8 KB Tile Register File (TMM0 .. TMM7)
struct TileRegisterFile {
    TileRegister tiles[AMX_MAX_TILES];
};
static_assert(sizeof(TileRegisterFile) == 8192, "TileRegisterFile must be exactly 8192 bytes");
#pragma pack(pop)

// Matrix Precision Type
enum class MatrixPrecision : uint32_t {
    Int8      = 0,  // TDPBUSD / TDPBSUD / TDPBSSD / TDPBUUD (INT8 dot product into INT32)
    BFloat16  = 1,  // TDPBF16PS (BF16 pairs into FP32)
    Float16   = 2,  // TDPFP16PS (IEEE FP16 pairs into FP32)
    Float32   = 3   // Direct FP32 (SME FMOPA)
};

// Hardware Capabilities
struct AmxCapabilities {
    bool hasAmxTile{true};
    bool hasAmxInt8{true};
    bool hasAmxBf16{true};
    bool hasAmxFp16{true};
    bool hasArmSme{true};
    uint32_t maxTiles{AMX_MAX_TILES};
    uint32_t maxRows{AMX_MAX_ROWS};
    uint32_t maxColsBytes{AMX_MAX_COLS_BYTES};
    uint32_t totalTileFileBytes{AMX_TOTAL_TILE_BYTES};
    uint32_t smeSvlBits{ARM_SME_DEFAULT_SVL_BITS};
};

// Telemetry & Statistics
struct AmxTelemetry {
    uint64_t totalTileLoads{0};
    uint64_t totalTileStores{0};
    uint64_t totalInt8Ops{0};
    uint64_t totalBf16Ops{0};
    uint64_t totalFp16Ops{0};
    uint64_t totalArmSmeOps{0};
    uint64_t totalTilesReleased{0};
    uint64_t totalTileConfigSwitches{0};
    uint64_t totalExceptionsTrapped{0};
};

// Arm SME State
struct ArmSmeState {
    bool streamingMode{false};       // PSTATE.SM = 1
    bool zaStorageEnabled{false};    // PSTATE.ZA = 1
    uint32_t svlBits{ARM_SME_DEFAULT_SVL_BITS};
    uint32_t activeZaTiles{0};
};

// Helper: BF16 to float converter
inline float Bf16ToFloat(uint16_t b) {
    uint32_t u = static_cast<uint32_t>(b) << 16;
    float f = 0.0f;
    std::memcpy(&f, &u, sizeof(float));
    return f;
}

// Helper: Float to BF16 converter
inline uint16_t FloatToBf16(float f) {
    uint32_t u = 0;
    std::memcpy(&u, &f, sizeof(float));
    return static_cast<uint16_t>(u >> 16);
}

// Helper: FP16 to float converter (IEEE 754 half-precision)
inline float Fp16ToFloat(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x0001;
    uint32_t exp  = (h >> 10) & 0x001F;
    uint32_t mant = h & 0x03FF;

    if (exp == 0) {
        if (mant == 0) {
            uint32_t val = (sign << 31);
            float f = 0.0f;
            std::memcpy(&f, &val, sizeof(float));
            return f;
        }
        while (!(mant & 0x0400)) {
            mant <<= 1;
            exp--;
        }
        exp++;
        mant &= ~0x0400;
    } else if (exp == 31) {
        uint32_t val = (sign << 31) | 0x7F800000 | (mant << 13);
        float f = 0.0f;
        std::memcpy(&f, &val, sizeof(float));
        return f;
    }

    exp = exp + (127 - 15);
    mant = mant << 13;
    uint32_t val = (sign << 31) | (exp << 23) | mant;
    float f = 0.0f;
    std::memcpy(&f, &val, sizeof(float));
    return f;
}

// Helper: Float to FP16 converter
inline uint16_t FloatToFp16(float f) {
    uint32_t u = 0;
    std::memcpy(&u, &f, sizeof(float));
    uint32_t sign = (u >> 31) & 0x0001;
    int32_t  exp  = ((u >> 23) & 0x00FF) - 127 + 15;
    uint32_t mant = (u & 0x007FFFFF) >> 13;

    if (exp <= 0) {
        return static_cast<uint16_t>(sign << 15);
    } else if (exp >= 31) {
        return static_cast<uint16_t>((sign << 15) | 0x7C00);
    }
    return static_cast<uint16_t>((sign << 15) | (exp << 10) | mant);
}

// ============================================================================
// TitanMatrix Accelerator Subsystem Engine
// ============================================================================
class TitanMatrixSubsystem {
public:
    static TitanMatrixSubsystem& Instance() {
        static TitanMatrixSubsystem instance;
        return instance;
    }

    bool initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) return true;

        caps_.hasAmxTile = true;
        caps_.hasAmxInt8 = true;
        caps_.hasAmxBf16 = true;
        caps_.hasAmxFp16 = true;
        caps_.hasArmSme  = true;
        caps_.maxTiles   = AMX_MAX_TILES;
        caps_.maxRows    = AMX_MAX_ROWS;
        caps_.maxColsBytes = AMX_MAX_COLS_BYTES;
        caps_.totalTileFileBytes = AMX_TOTAL_TILE_BYTES;
        caps_.smeSvlBits = ARM_SME_DEFAULT_SVL_BITS;

        // Reset configuration and registers
        std::memset(&currentConfig_, 0, sizeof(currentConfig_));
        std::memset(&tileFile_, 0, sizeof(tileFile_));

        // Arm SME initial state
        smeState_.streamingMode = false;
        smeState_.zaStorageEnabled = false;
        smeState_.svlBits = ARM_SME_DEFAULT_SVL_BITS;
        smeState_.activeZaTiles = 0;

        initialized_ = true;
        registerScmDrivers();
        registerVersionDatabase();
        return true;
    }

    const AmxCapabilities& getCapabilities() const {
        return caps_;
    }

    const AmxTelemetry& getTelemetry() const {
        return telemetry_;
    }

    const TileConfig& getCurrentConfig() const {
        return currentConfig_;
    }

    const ArmSmeState& getSmeState() const {
        return smeState_;
    }

    // Configure Tile Palette (LDTILECFG emulation)
    int32_t configurePalette(const TileConfig& config) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return STATUS_DEVICE_NOT_READY;

        if (config.paletteId != AMX_PALETTE_ID_1 && config.paletteId != AMX_PALETTE_ID_NONE) {
            telemetry_.totalExceptionsTrapped++;
            return STATUS_INVALID_PARAMETER; // #UD or invalid palette
        }

        if (config.paletteId == AMX_PALETTE_ID_NONE) {
            // Tilerelease
            std::memset(&currentConfig_, 0, sizeof(currentConfig_));
            std::memset(&tileFile_, 0, sizeof(tileFile_));
            telemetry_.totalTilesReleased++;
            return STATUS_SUCCESS;
        }

        // Validate Palette 1 constraints
        for (uint32_t i = 0; i < AMX_MAX_TILES; ++i) {
            if (config.rows[i] > AMX_MAX_ROWS) {
                telemetry_.totalExceptionsTrapped++;
                return STATUS_INVALID_PARAMETER;
            }
            if (config.colsb[i] > AMX_MAX_COLS_BYTES) {
                telemetry_.totalExceptionsTrapped++;
                return STATUS_INVALID_PARAMETER;
            }
            // If rows > 0, colsb must be > 0 and vice-versa
            if ((config.rows[i] > 0 && config.colsb[i] == 0) ||
                (config.rows[i] == 0 && config.colsb[i] > 0)) {
                telemetry_.totalExceptionsTrapped++;
                return STATUS_INVALID_PARAMETER;
            }
        }

        currentConfig_ = config;
        telemetry_.totalTileConfigSwitches++;
        return STATUS_SUCCESS;
    }

    // Release all tiles (TILERELEASE)
    int32_t releaseTiles() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return STATUS_DEVICE_NOT_READY;

        std::memset(&currentConfig_, 0, sizeof(currentConfig_));
        std::memset(&tileFile_, 0, sizeof(tileFile_));
        telemetry_.totalTilesReleased++;
        return STATUS_SUCCESS;
    }

    // Load data from memory into a tile register (TILELOADD / TILELOADDT1)
    int32_t loadTile(uint32_t tileIndex, const void* baseAddress, size_t strideBytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return STATUS_DEVICE_NOT_READY;
        if (tileIndex >= AMX_MAX_TILES) return STATUS_INVALID_PARAMETER;
        if (currentConfig_.paletteId != AMX_PALETTE_ID_1) return STATUS_ILLEGAL_INSTRUCTION;
        if (baseAddress == nullptr) return STATUS_ACCESS_VIOLATION;

        uint32_t rows = currentConfig_.rows[tileIndex];
        uint32_t colsb = currentConfig_.colsb[tileIndex];
        if (rows == 0 || colsb == 0) return STATUS_INVALID_PARAMETER;
        if (strideBytes < colsb) return STATUS_INVALID_PARAMETER;

        const uint8_t* src = static_cast<const uint8_t*>(baseAddress);
        for (uint32_t r = 0; r < rows; ++r) {
            std::memcpy(tileFile_.tiles[tileIndex].data[r], src + (r * strideBytes), colsb);
            // Zero out unused columns in the 64-byte row
            if (colsb < AMX_MAX_COLS_BYTES) {
                std::memset(tileFile_.tiles[tileIndex].data[r] + colsb, 0, AMX_MAX_COLS_BYTES - colsb);
            }
        }
        // Zero out unused rows in the tile
        for (uint32_t r = rows; r < AMX_MAX_ROWS; ++r) {
            std::memset(tileFile_.tiles[tileIndex].data[r], 0, AMX_MAX_COLS_BYTES);
        }

        telemetry_.totalTileLoads++;
        return STATUS_SUCCESS;
    }

    // Store tile register data into memory (TILESTORED)
    int32_t storeTile(uint32_t tileIndex, void* baseAddress, size_t strideBytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return STATUS_DEVICE_NOT_READY;
        if (tileIndex >= AMX_MAX_TILES) return STATUS_INVALID_PARAMETER;
        if (currentConfig_.paletteId != AMX_PALETTE_ID_1) return STATUS_ILLEGAL_INSTRUCTION;
        if (baseAddress == nullptr) return STATUS_ACCESS_VIOLATION;

        uint32_t rows = currentConfig_.rows[tileIndex];
        uint32_t colsb = currentConfig_.colsb[tileIndex];
        if (rows == 0 || colsb == 0) return STATUS_INVALID_PARAMETER;
        if (strideBytes < colsb) return STATUS_INVALID_PARAMETER;

        uint8_t* dst = static_cast<uint8_t*>(baseAddress);
        for (uint32_t r = 0; r < rows; ++r) {
            std::memcpy(dst + (r * strideBytes), tileFile_.tiles[tileIndex].data[r], colsb);
        }

        telemetry_.totalTileStores++;
        return STATUS_SUCCESS;
    }

    // INT8 Dot Product Matrix Multiplication (TDPBUSD / TDPBSSD)
    // Computes: dstTile += src1Tile * src2Tile
    // dstTile: M rows x N columns (elements are int32_t, each column is 4 bytes -> colsb = N*4)
    // src1Tile: M rows x K bytes (int8 elements)
    // src2Tile: K rows x N columns (elements are 4-byte packed int8 tuples or transposed columns)
    int32_t multiplyInt8(uint32_t dstTile, uint32_t src1Tile, uint32_t src2Tile, bool src1Signed, bool src2Signed, uint32_t* pLatencyNs = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return STATUS_DEVICE_NOT_READY;
        if (dstTile >= AMX_MAX_TILES || src1Tile >= AMX_MAX_TILES || src2Tile >= AMX_MAX_TILES) {
            return STATUS_INVALID_PARAMETER;
        }
        if (currentConfig_.paletteId != AMX_PALETTE_ID_1) return STATUS_ILLEGAL_INSTRUCTION;

        uint32_t m = currentConfig_.rows[dstTile];
        uint32_t nColsBytes = currentConfig_.colsb[dstTile];
        uint32_t nDwords = nColsBytes / 4; // INT32 elements per row in dst

        uint32_t m1 = currentConfig_.rows[src1Tile];
        uint32_t kBytes1 = currentConfig_.colsb[src1Tile];

        uint32_t kRows2 = currentConfig_.rows[src2Tile];
        uint32_t nColsBytes2 = currentConfig_.colsb[src2Tile];

        // Dimension validation:
        // dst rows (m) must match src1 rows (m1)
        // dst colsb must match src2 colsb
        // src1 colsb must be 4 * src2 rows (since src2 contains 4 bytes per row-entry for dot product)
        if (m != m1) return STATUS_INVALID_PARAMETER;
        if (nColsBytes != nColsBytes2) return STATUS_INVALID_PARAMETER;
        if (kBytes1 != kRows2 * 4) return STATUS_INVALID_PARAMETER;

        // Perform dot-product accumulation
        for (uint32_t i = 0; i < m; ++i) {
            int32_t* dstRow = reinterpret_cast<int32_t*>(tileFile_.tiles[dstTile].data[i]);
            for (uint32_t j = 0; j < nDwords; ++j) {
                int32_t sum = 0;
                for (uint32_t k = 0; k < kRows2; ++k) {
                    for (uint32_t byteIdx = 0; byteIdx < 4; ++byteIdx) {
                        int32_t a = 0, b = 0;
                        uint8_t rawA = tileFile_.tiles[src1Tile].data[i][k * 4 + byteIdx];
                        uint8_t rawB = tileFile_.tiles[src2Tile].data[k][j * 4 + byteIdx];

                        if (src1Signed) {
                            a = static_cast<int8_t>(rawA);
                        } else {
                            a = static_cast<uint8_t>(rawA);
                        }

                        if (src2Signed) {
                            b = static_cast<int8_t>(rawB);
                        } else {
                            b = static_cast<uint8_t>(rawB);
                        }

                        sum += a * b;
                    }
                }
                dstRow[j] += sum;
            }
        }

        telemetry_.totalInt8Ops++;
        if (pLatencyNs) *pLatencyNs = 14; // Typical ~14ns AMX systolic cycle
        return STATUS_SUCCESS;
    }

    // BFloat16 Dot Product Matrix Multiplication (TDPBF16PS)
    // Computes: dstTile += src1Tile * src2Tile (FP32 accumulation)
    // dstTile: M rows x N columns (elements are float32, colsb = N*4)
    // src1Tile: M rows x K pairs (elements are bf16 pairs = 4 bytes per pair)
    // src2Tile: K rows x N columns (elements are bf16 pairs = 4 bytes per pair)
    int32_t multiplyBf16(uint32_t dstTile, uint32_t src1Tile, uint32_t src2Tile, uint32_t* pLatencyNs = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return STATUS_DEVICE_NOT_READY;
        if (dstTile >= AMX_MAX_TILES || src1Tile >= AMX_MAX_TILES || src2Tile >= AMX_MAX_TILES) {
            return STATUS_INVALID_PARAMETER;
        }
        if (currentConfig_.paletteId != AMX_PALETTE_ID_1) return STATUS_ILLEGAL_INSTRUCTION;

        uint32_t m = currentConfig_.rows[dstTile];
        uint32_t nColsBytes = currentConfig_.colsb[dstTile];
        uint32_t nFloats = nColsBytes / 4;

        uint32_t m1 = currentConfig_.rows[src1Tile];
        uint32_t kBytes1 = currentConfig_.colsb[src1Tile];

        uint32_t kRows2 = currentConfig_.rows[src2Tile];
        uint32_t nColsBytes2 = currentConfig_.colsb[src2Tile];

        if (m != m1) return STATUS_INVALID_PARAMETER;
        if (nColsBytes != nColsBytes2) return STATUS_INVALID_PARAMETER;
        if (kBytes1 != kRows2 * 4) return STATUS_INVALID_PARAMETER;

        for (uint32_t i = 0; i < m; ++i) {
            float* dstRow = reinterpret_cast<float*>(tileFile_.tiles[dstTile].data[i]);
            for (uint32_t j = 0; j < nFloats; ++j) {
                float sum = 0.0f;
                for (uint32_t k = 0; k < kRows2; ++k) {
                    const uint16_t* src1Pair = reinterpret_cast<const uint16_t*>(&tileFile_.tiles[src1Tile].data[i][k * 4]);
                    const uint16_t* src2Pair = reinterpret_cast<const uint16_t*>(&tileFile_.tiles[src2Tile].data[k][j * 4]);

                    float a0 = Bf16ToFloat(src1Pair[0]);
                    float a1 = Bf16ToFloat(src1Pair[1]);
                    float b0 = Bf16ToFloat(src2Pair[0]);
                    float b1 = Bf16ToFloat(src2Pair[1]);

                    sum += (a0 * b0) + (a1 * b1);
                }
                dstRow[j] += sum;
            }
        }

        telemetry_.totalBf16Ops++;
        if (pLatencyNs) *pLatencyNs = 16;
        return STATUS_SUCCESS;
    }

    // FP16 Dot Product Matrix Multiplication (TDPFP16PS)
    // Computes: dstTile += src1Tile * src2Tile (IEEE FP16 pairs into FP32)
    int32_t multiplyFp16(uint32_t dstTile, uint32_t src1Tile, uint32_t src2Tile, uint32_t* pLatencyNs = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return STATUS_DEVICE_NOT_READY;
        if (dstTile >= AMX_MAX_TILES || src1Tile >= AMX_MAX_TILES || src2Tile >= AMX_MAX_TILES) {
            return STATUS_INVALID_PARAMETER;
        }
        if (currentConfig_.paletteId != AMX_PALETTE_ID_1) return STATUS_ILLEGAL_INSTRUCTION;

        uint32_t m = currentConfig_.rows[dstTile];
        uint32_t nColsBytes = currentConfig_.colsb[dstTile];
        uint32_t nFloats = nColsBytes / 4;

        uint32_t m1 = currentConfig_.rows[src1Tile];
        uint32_t kBytes1 = currentConfig_.colsb[src1Tile];

        uint32_t kRows2 = currentConfig_.rows[src2Tile];
        uint32_t nColsBytes2 = currentConfig_.colsb[src2Tile];

        if (m != m1) return STATUS_INVALID_PARAMETER;
        if (nColsBytes != nColsBytes2) return STATUS_INVALID_PARAMETER;
        if (kBytes1 != kRows2 * 4) return STATUS_INVALID_PARAMETER;

        for (uint32_t i = 0; i < m; ++i) {
            float* dstRow = reinterpret_cast<float*>(tileFile_.tiles[dstTile].data[i]);
            for (uint32_t j = 0; j < nFloats; ++j) {
                float sum = 0.0f;
                for (uint32_t k = 0; k < kRows2; ++k) {
                    const uint16_t* src1Pair = reinterpret_cast<const uint16_t*>(&tileFile_.tiles[src1Tile].data[i][k * 4]);
                    const uint16_t* src2Pair = reinterpret_cast<const uint16_t*>(&tileFile_.tiles[src2Tile].data[k][j * 4]);

                    float a0 = Fp16ToFloat(src1Pair[0]);
                    float a1 = Fp16ToFloat(src1Pair[1]);
                    float b0 = Fp16ToFloat(src2Pair[0]);
                    float b1 = Fp16ToFloat(src2Pair[1]);

                    sum += (a0 * b0) + (a1 * b1);
                }
                dstRow[j] += sum;
            }
        }

        telemetry_.totalFp16Ops++;
        if (pLatencyNs) *pLatencyNs = 16;
        return STATUS_SUCCESS;
    }

    // Arm SME Mode Control (SMSTART / SMSTOP)
    int32_t setSmeStreamingMode(bool enableSm, bool enableZa) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return STATUS_DEVICE_NOT_READY;

        smeState_.streamingMode = enableSm;
        smeState_.zaStorageEnabled = enableZa;
        if (!enableZa) {
            smeState_.activeZaTiles = 0;
        } else {
            smeState_.activeZaTiles = ARM_SME_MAX_TILES;
        }

        telemetry_.totalArmSmeOps++;
        return STATUS_SUCCESS;
    }

    // Arm SME Outer Product Accumulation (SMOPA / FMOPA)
    int32_t smeOuterProduct(uint32_t zaTileIndex, const float* vectorA, const float* vectorB, uint32_t dim, uint32_t* pLatencyNs = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return STATUS_DEVICE_NOT_READY;
        if (!smeState_.streamingMode || !smeState_.zaStorageEnabled) return STATUS_ILLEGAL_INSTRUCTION;
        if (zaTileIndex >= ARM_SME_MAX_TILES) return STATUS_INVALID_PARAMETER;
        if (vectorA == nullptr || vectorB == nullptr) return STATUS_ACCESS_VIOLATION;
        if (dim == 0 || dim > 16) return STATUS_INVALID_PARAMETER;

        // Perform outer product: ZA += A outer_product B
        for (uint32_t i = 0; i < dim; ++i) {
            float* row = reinterpret_cast<float*>(tileFile_.tiles[zaTileIndex].data[i]);
            for (uint32_t j = 0; j < dim; ++j) {
                row[j] += vectorA[i] * vectorB[j];
            }
        }

        telemetry_.totalArmSmeOps++;
        if (pLatencyNs) *pLatencyNs = 12;
        return STATUS_SUCCESS;
    }

    // Read raw tile data directly for unit testing
    const TileRegister& getTileRaw(uint32_t tileIndex) const {
        static TileRegister dummy{};
        if (tileIndex >= AMX_MAX_TILES) return dummy;
        return tileFile_.tiles[tileIndex];
    }

private:
    TitanMatrixSubsystem() = default;

    void registerScmDrivers() {
        auto& scm = scm::ServiceControlManager::get();

        auto svcAmx = std::make_shared<scm::ServiceRecord>();
        svcAmx->serviceName = L"intel_amx";
        svcAmx->displayName = L"Intel AMX & Matrix Accelerator Driver (intel_amx.sys)";
        svcAmx->serviceType = scm::SERVICE_KERNEL_DRIVER;
        svcAmx->startType = scm::SERVICE_BOOT_START;
        svcAmx->errorControl = scm::SERVICE_ERROR_CRITICAL;
        svcAmx->binaryPath = L"C:\\Windows\\System32\\drivers\\intel_amx.sys";
        svcAmx->status.dwCurrentState = scm::SERVICE_RUNNING;
        scm.registerServiceRecord(svcAmx);

        auto svcSme = std::make_shared<scm::ServiceRecord>();
        svcSme->serviceName = L"arm_sme";
        svcSme->displayName = L"Arm Scalable Matrix Extension Port Driver (arm_sme.sys)";
        svcSme->serviceType = scm::SERVICE_KERNEL_DRIVER;
        svcSme->startType = scm::SERVICE_SYSTEM_START;
        svcSme->errorControl = scm::SERVICE_ERROR_NORMAL;
        svcSme->binaryPath = L"C:\\Windows\\System32\\drivers\\arm_sme.sys";
        svcSme->status.dwCurrentState = scm::SERVICE_RUNNING;
        scm.registerServiceRecord(svcSme);

        auto svcMat = std::make_shared<scm::ServiceRecord>();
        svcMat->serviceName = L"matrix_accel";
        svcMat->displayName = L"MicaNT Sovereign Matrix Compute Service (matrix_accel.sys)";
        svcMat->serviceType = scm::SERVICE_KERNEL_DRIVER;
        svcMat->startType = scm::SERVICE_SYSTEM_START;
        svcMat->errorControl = scm::SERVICE_ERROR_NORMAL;
        svcMat->binaryPath = L"C:\\Windows\\System32\\drivers\\matrix_accel.sys";
        svcMat->status.dwCurrentState = scm::SERVICE_RUNNING;
        scm.registerServiceRecord(svcMat);
    }

    void registerVersionDatabase() {
        auto& verDb = version::VersionDatabase::Instance();
        verDb.RegisterModule("intel_amx.sys", "10.0.26100.1", "Intel AMX TMUL Driver");
        verDb.RegisterModule("arm_sme.sys", "10.0.26100.1", "Arm Scalable Matrix Extension Port Driver");
        verDb.RegisterModule("matrix_accel.sys", "10.0.26100.1", "MicaNT Sovereign Matrix Compute Service");
    }

    mutable std::mutex mutex_;
    bool initialized_{false};
    AmxCapabilities caps_{};
    AmxTelemetry telemetry_{};
    TileConfig currentConfig_{};
    TileRegisterFile tileFile_{};
    ArmSmeState smeState_{};
};

// ============================================================================
// Standard C ABI Exports for Kernel & Device Drivers
// ============================================================================
extern "C" {

inline int32_t AmxInitialize() {
    return TitanMatrixSubsystem::Instance().initialize() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

inline int32_t AmxGetVersion(uint32_t* pMajor, uint32_t* pMinor, uint32_t* pBuild) {
    if (!pMajor || !pMinor || !pBuild) return STATUS_INVALID_PARAMETER;
    *pMajor = 10;
    *pMinor = 0;
    *pBuild = 26100;
    return STATUS_SUCCESS;
}

inline int32_t AmxGetCapabilities(AmxCapabilities* pCaps) {
    if (!pCaps) return STATUS_INVALID_PARAMETER;
    *pCaps = TitanMatrixSubsystem::Instance().getCapabilities();
    return STATUS_SUCCESS;
}

inline int32_t AmxConfigurePalette(const TileConfig* pConfig) {
    if (!pConfig) return STATUS_INVALID_PARAMETER;
    return TitanMatrixSubsystem::Instance().configurePalette(*pConfig);
}

inline int32_t AmxReleaseTiles() {
    return TitanMatrixSubsystem::Instance().releaseTiles();
}

inline int32_t AmxLoadTile(uint32_t tileIndex, const void* baseAddress, size_t strideBytes) {
    return TitanMatrixSubsystem::Instance().loadTile(tileIndex, baseAddress, strideBytes);
}

inline int32_t AmxStoreTile(uint32_t tileIndex, void* baseAddress, size_t strideBytes) {
    return TitanMatrixSubsystem::Instance().storeTile(tileIndex, baseAddress, strideBytes);
}

inline int32_t AmxMultiplyInt8(uint32_t dstTile, uint32_t src1Tile, uint32_t src2Tile, bool src1Signed, bool src2Signed, uint32_t* pLatencyNs) {
    return TitanMatrixSubsystem::Instance().multiplyInt8(dstTile, src1Tile, src2Tile, src1Signed, src2Signed, pLatencyNs);
}

inline int32_t AmxMultiplyBf16(uint32_t dstTile, uint32_t src1Tile, uint32_t src2Tile, uint32_t* pLatencyNs) {
    return TitanMatrixSubsystem::Instance().multiplyBf16(dstTile, src1Tile, src2Tile, pLatencyNs);
}

inline int32_t AmxMultiplyFp16(uint32_t dstTile, uint32_t src1Tile, uint32_t src2Tile, uint32_t* pLatencyNs) {
    return TitanMatrixSubsystem::Instance().multiplyFp16(dstTile, src1Tile, src2Tile, pLatencyNs);
}

inline int32_t AmxGetTelemetry(AmxTelemetry* pTelem) {
    if (!pTelem) return STATUS_INVALID_PARAMETER;
    *pTelem = TitanMatrixSubsystem::Instance().getTelemetry();
    return STATUS_SUCCESS;
}

} // extern "C"

} // namespace micant::amx

#endif // MICANT_AMX_HPP
