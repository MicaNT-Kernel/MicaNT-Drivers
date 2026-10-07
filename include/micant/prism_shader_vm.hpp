// ============================================================================
// MicaNT: PrismShaderVM - Sovereign Programmable Shader Bytecode Virtual Machine
// 
// Strict Clean-Room Implementation
//
// Subsystem Overview:
//   PrismShaderVM provides an independent, register-based RISC SIMD bytecode
//   execution engine for Vertex Shaders (VS) and Pixel Shaders (PS).
//   It executes 4-component single-precision floating point vector instructions,
//   supporting matrix transformations, lighting evaluation, UV texture sampling,
//   and color modulation without external dependencies.
// ============================================================================

#pragma once

#include "prismx.hpp"
#include "prism3d.hpp"
#include <cstdint>
#include <vector>
#include <array>
#include <cmath>
#include <algorithm>
#include <functional>
#include <string>
#include <sstream>
#include <cstring>

namespace micant::prism_vm {

using namespace micant::prism3d;

// ============================================================================
// 1. VM Opcodes & Register Enums
// ============================================================================

enum Opcode : uint8_t {
    OP_NOP   = 0,
    OP_MOV   = 1,   // dst = src0
    OP_ADD   = 2,   // dst = src0 + src1
    OP_SUB   = 3,   // dst = src0 - src1
    OP_MUL   = 4,   // dst = src0 * src1
    OP_MAD   = 5,   // dst = src0 * src1 + src2
    OP_DP3   = 6,   // dst = dot3(src0, src1)
    OP_DP4   = 7,   // dst = dot4(src0, src1)
    OP_MIN   = 8,   // dst = min(src0, src1)
    OP_MAX   = 9,   // dst = max(src0, src1)
    OP_SLT   = 10,  // dst = (src0 < src1) ? 1.0 : 0.0
    OP_SGE   = 11,  // dst = (src0 >= src1) ? 1.0 : 0.0
    OP_RCP   = 12,  // dst = 1.0 / src0
    OP_RSQ   = 13,  // dst = 1.0 / sqrt(src0)
    OP_CLAMP = 14,  // dst = clamp(src0, src1, src2)
    OP_TEX   = 15,  // dst = sample_texture(src0.xy, samplerId)
    OP_RET   = 16   // Return
};

enum RegisterType : uint8_t {
    REG_TEMP   = 0, // r0 - r7 (Temporary working registers)
    REG_INPUT  = 1, // v0 - v3 (Input attributes: Position, Color, UV, Normal)
    REG_CONST  = 2, // c0 - c15 (Constant Buffer float4 parameters)
    REG_OUTPUT = 3  // o0 - o1 (o0 = Position/Clip, o1 = Color)
};

struct RegisterRef {
    RegisterType type;
    uint8_t index;
    uint8_t swizzle[4];        // Component mapping: 0=x, 1=y, 2=z, 3=w
    uint8_t writeMask{ 0x0F }; // Component write mask: bit 0=x, 1=y, 2=z, 3=w

    static RegisterRef Temp(uint8_t idx, uint8_t mask = 0x0F) {
        return { REG_TEMP, idx, { 0, 1, 2, 3 }, mask };
    }
    static RegisterRef Input(uint8_t idx) {
        return { REG_INPUT, idx, { 0, 1, 2, 3 }, 0x0F };
    }
    static RegisterRef Const(uint8_t idx) {
        return { REG_CONST, idx, { 0, 1, 2, 3 }, 0x0F };
    }
    static RegisterRef Output(uint8_t idx, uint8_t mask = 0x0F) {
        return { REG_OUTPUT, idx, { 0, 1, 2, 3 }, mask };
    }

    RegisterRef Mask(uint8_t m) const {
        RegisterRef copy = *this;
        copy.writeMask = m;
        return copy;
    }

    RegisterRef Swizzle(uint8_t x, uint8_t y, uint8_t z, uint8_t w) const {
        return { type, index, { x, y, z, w }, writeMask };
    }
};

struct Instruction {
    Opcode op;
    RegisterRef dst;
    RegisterRef src0;
    RegisterRef src1;
    RegisterRef src2;
    uint8_t samplerSlot{ 0 };
};

// 4-component vector register
struct VectorRegister {
    float v[4]{ 0.0f, 0.0f, 0.0f, 0.0f };

    float& x() { return v[0]; }
    float& y() { return v[1]; }
    float& z() { return v[2]; }
    float& w() { return v[3]; }

    float x() const { return v[0]; }
    float y() const { return v[1]; }
    float z() const { return v[2]; }
    float w() const { return v[3]; }

    VectorRegister() = default;
    VectorRegister(float x, float y, float z, float w) {
        v[0] = x; v[1] = y; v[2] = z; v[3] = w;
    }
};

// ============================================================================
// 2. VM Execution Context & Shader Program
// ============================================================================

using TextureSamplerFn = std::function<VectorRegister(uint8_t slot, float u, float v)>;

class ShaderProgram {
private:
    std::vector<Instruction> m_instructions;

public:
    void Add(const Instruction& inst) {
        m_instructions.push_back(inst);
    }

    const std::vector<Instruction>& GetInstructions() const {
        return m_instructions;
    }

    size_t InstructionCount() const {
        return m_instructions.size();
    }
};

class PrismShaderVM {
public:
    static VectorRegister ReadRegister(
        const RegisterRef& reg,
        const std::array<VectorRegister, 8>& temps,
        const std::array<VectorRegister, 4>& inputs,
        const std::array<VectorRegister, 16>& consts,
        const std::array<VectorRegister, 2>& outputs
    ) {
        VectorRegister src{};
        switch (reg.type) {
            case REG_TEMP:   src = (reg.index < temps.size())   ? temps[reg.index]   : VectorRegister{}; break;
            case REG_INPUT:  src = (reg.index < inputs.size())  ? inputs[reg.index]  : VectorRegister{}; break;
            case REG_CONST:  src = (reg.index < consts.size())  ? consts[reg.index]  : VectorRegister{}; break;
            case REG_OUTPUT: src = (reg.index < outputs.size()) ? outputs[reg.index] : VectorRegister{}; break;
        }

        // Apply swizzle
        return VectorRegister{
            src.v[reg.swizzle[0] & 3],
            src.v[reg.swizzle[1] & 3],
            src.v[reg.swizzle[2] & 3],
            src.v[reg.swizzle[3] & 3]
        };
    }

    static void WriteRegister(
        const RegisterRef& reg,
        const VectorRegister& val,
        std::array<VectorRegister, 8>& temps,
        std::array<VectorRegister, 2>& outputs
    ) {
        VectorRegister* target = nullptr;
        if (reg.type == REG_TEMP && reg.index < temps.size()) {
            target = &temps[reg.index];
        } else if (reg.type == REG_OUTPUT && reg.index < outputs.size()) {
            target = &outputs[reg.index];
        }
        if (!target) return;

        uint8_t mask = reg.writeMask;
        if (mask & 0x1) target->v[0] = val.v[0];
        if (mask & 0x2) target->v[1] = val.v[1];
        if (mask & 0x4) target->v[2] = val.v[2];
        if (mask & 0x8) target->v[3] = val.v[3];
    }

    // Execute Vertex Shader Program
    static void ExecuteVertexShader(
        const ShaderProgram& program,
        const VectorRegister& inPosition,
        const VectorRegister& inColor,
        const VectorRegister& inUV,
        const VectorRegister& inNormal,
        const std::array<VectorRegister, 16>& constBuffers,
        VectorRegister& outPosition,
        VectorRegister& outColor
    ) {
        std::array<VectorRegister, 8> temps{};
        std::array<VectorRegister, 4> inputs{ inPosition, inColor, inUV, inNormal };
        std::array<VectorRegister, 2> outputs{ inPosition, inColor };

        for (const auto& inst : program.GetInstructions()) {
            if (inst.op == OP_RET) break;

            VectorRegister s0 = ReadRegister(inst.src0, temps, inputs, constBuffers, outputs);
            VectorRegister s1 = ReadRegister(inst.src1, temps, inputs, constBuffers, outputs);
            VectorRegister s2 = ReadRegister(inst.src2, temps, inputs, constBuffers, outputs);
            VectorRegister result{};

            switch (inst.op) {
                case OP_MOV:
                    result = s0;
                    break;
                case OP_ADD:
                    result = VectorRegister{ s0.x() + s1.x(), s0.y() + s1.y(), s0.z() + s1.z(), s0.w() + s1.w() };
                    break;
                case OP_SUB:
                    result = VectorRegister{ s0.x() - s1.x(), s0.y() - s1.y(), s0.z() - s1.z(), s0.w() - s1.w() };
                    break;
                case OP_MUL:
                    result = VectorRegister{ s0.x() * s1.x(), s0.y() * s1.y(), s0.z() * s1.z(), s0.w() * s1.w() };
                    break;
                case OP_MAD:
                    result = VectorRegister{
                        s0.x() * s1.x() + s2.x(),
                        s0.y() * s1.y() + s2.y(),
                        s0.z() * s1.z() + s2.z(),
                        s0.w() * s1.w() + s2.w()
                    };
                    break;
                case OP_DP3: {
                    float dot = s0.x() * s1.x() + s0.y() * s1.y() + s0.z() * s1.z();
                    result = VectorRegister{ dot, dot, dot, dot };
                    break;
                }
                case OP_DP4: {
                    float dot = s0.x() * s1.x() + s0.y() * s1.y() + s0.z() * s1.z() + s0.w() * s1.w();
                    result = VectorRegister{ dot, dot, dot, dot };
                    break;
                }
                case OP_MIN:
                    result = VectorRegister{ std::min(s0.x(), s1.x()), std::min(s0.y(), s1.y()), std::min(s0.z(), s1.z()), std::min(s0.w(), s1.w()) };
                    break;
                case OP_MAX:
                    result = VectorRegister{ std::max(s0.x(), s1.x()), std::max(s0.y(), s1.y()), std::max(s0.z(), s1.z()), std::max(s0.w(), s1.w()) };
                    break;
                case OP_SLT:
                    result = VectorRegister{ (s0.x() < s1.x()) ? 1.0f : 0.0f, (s0.y() < s1.y()) ? 1.0f : 0.0f, (s0.z() < s1.z()) ? 1.0f : 0.0f, (s0.w() < s1.w()) ? 1.0f : 0.0f };
                    break;
                case OP_SGE:
                    result = VectorRegister{ (s0.x() >= s1.x()) ? 1.0f : 0.0f, (s0.y() >= s1.y()) ? 1.0f : 0.0f, (s0.z() >= s1.z()) ? 1.0f : 0.0f, (s0.w() >= s1.w()) ? 1.0f : 0.0f };
                    break;
                case OP_RCP:
                    result = VectorRegister{ (std::abs(s0.x()) > 1e-6f) ? (1.0f / s0.x()) : 0.0f,
                                            (std::abs(s0.y()) > 1e-6f) ? (1.0f / s0.y()) : 0.0f,
                                            (std::abs(s0.z()) > 1e-6f) ? (1.0f / s0.z()) : 0.0f,
                                            (std::abs(s0.w()) > 1e-6f) ? (1.0f / s0.w()) : 0.0f };
                    break;
                case OP_RSQ:
                    result = VectorRegister{ (s0.x() > 1e-6f) ? (1.0f / std::sqrt(s0.x())) : 0.0f,
                                            (s0.y() > 1e-6f) ? (1.0f / std::sqrt(s0.y())) : 0.0f,
                                            (s0.z() > 1e-6f) ? (1.0f / std::sqrt(s0.z())) : 0.0f,
                                            (s0.w() > 1e-6f) ? (1.0f / std::sqrt(s0.w())) : 0.0f };
                    break;
                case OP_CLAMP:
                    result = VectorRegister{
                        std::clamp(s0.x(), s1.x(), s2.x()),
                        std::clamp(s0.y(), s1.y(), s2.y()),
                        std::clamp(s0.z(), s1.z(), s2.z()),
                        std::clamp(s0.w(), s1.w(), s2.w())
                    };
                    break;
                default:
                    break;
            }

            WriteRegister(inst.dst, result, temps, outputs);
        }

        outPosition = outputs[0];
        outColor = outputs[1];
    }

    // Execute Pixel Shader Program
    static void ExecutePixelShader(
        const ShaderProgram& program,
        const VectorRegister& inPosition,
        const VectorRegister& inColor,
        const VectorRegister& inUV,
        const VectorRegister& inNormal,
        const std::array<VectorRegister, 16>& constBuffers,
        const TextureSamplerFn& sampler,
        VectorRegister& outColor
    ) {
        std::array<VectorRegister, 8> temps{};
        std::array<VectorRegister, 4> inputs{ inPosition, inColor, inUV, inNormal };
        std::array<VectorRegister, 2> outputs{ inPosition, inColor };

        for (const auto& inst : program.GetInstructions()) {
            if (inst.op == OP_RET) break;

            VectorRegister s0 = ReadRegister(inst.src0, temps, inputs, constBuffers, outputs);
            VectorRegister s1 = ReadRegister(inst.src1, temps, inputs, constBuffers, outputs);
            VectorRegister s2 = ReadRegister(inst.src2, temps, inputs, constBuffers, outputs);
            VectorRegister result{};

            switch (inst.op) {
                case OP_MOV:
                    result = s0;
                    break;
                case OP_ADD:
                    result = VectorRegister{ s0.x() + s1.x(), s0.y() + s1.y(), s0.z() + s1.z(), s0.w() + s1.w() };
                    break;
                case OP_SUB:
                    result = VectorRegister{ s0.x() - s1.x(), s0.y() - s1.y(), s0.z() - s1.z(), s0.w() - s1.w() };
                    break;
                case OP_MUL:
                    result = VectorRegister{ s0.x() * s1.x(), s0.y() * s1.y(), s0.z() * s1.z(), s0.w() * s1.w() };
                    break;
                case OP_MAD:
                    result = VectorRegister{
                        s0.x() * s1.x() + s2.x(),
                        s0.y() * s1.y() + s2.y(),
                        s0.z() * s1.z() + s2.z(),
                        s0.w() * s1.w() + s2.w()
                    };
                    break;
                case OP_DP3: {
                    float dot = s0.x() * s1.x() + s0.y() * s1.y() + s0.z() * s1.z();
                    result = VectorRegister{ dot, dot, dot, dot };
                    break;
                }
                case OP_DP4: {
                    float dot = s0.x() * s1.x() + s0.y() * s1.y() + s0.z() * s1.z() + s0.w() * s1.w();
                    result = VectorRegister{ dot, dot, dot, dot };
                    break;
                }
                case OP_MIN:
                    result = VectorRegister{ std::min(s0.x(), s1.x()), std::min(s0.y(), s1.y()), std::min(s0.z(), s1.z()), std::min(s0.w(), s1.w()) };
                    break;
                case OP_MAX:
                    result = VectorRegister{ std::max(s0.x(), s1.x()), std::max(s0.y(), s1.y()), std::max(s0.z(), s1.z()), std::max(s0.w(), s1.w()) };
                    break;
                case OP_CLAMP:
                    result = VectorRegister{
                        std::clamp(s0.x(), s1.x(), s2.x()),
                        std::clamp(s0.y(), s1.y(), s2.y()),
                        std::clamp(s0.z(), s1.z(), s2.z()),
                        std::clamp(s0.w(), s1.w(), s2.w())
                    };
                    break;
                case OP_TEX:
                    if (sampler) {
                        result = sampler(inst.samplerSlot, s0.x(), s0.y());
                    }
                    break;
                default:
                    break;
            }

            WriteRegister(inst.dst, result, temps, outputs);
        }

        outColor = outputs[1];
    }

    // ========================================================================
    // Standard Factory Shaders
    // ========================================================================

    // Standard MVP Matrix Transform Vertex Shader
    // c0, c1, c2, c3 = Column vectors of 4x4 MVP Matrix
    // o0.x = dot4(v0, c0), o0.y = dot4(v0, c1), o0.z = dot4(v0, c2), o0.w = dot4(v0, c3)
    // o1 = v1 (color pass-through)
    static ShaderProgram BuildMVPTransformVS() {
        ShaderProgram prog;
        Instruction inst{};

        // r0.x = dot4(v0, c0) (mask 0x1)
        inst = { OP_DP4, RegisterRef::Temp(0, 0x1), RegisterRef::Input(0), RegisterRef::Const(0), {} };
        prog.Add(inst);
        // r0.y = dot4(v0, c1) (mask 0x2)
        inst = { OP_DP4, RegisterRef::Temp(0, 0x2), RegisterRef::Input(0), RegisterRef::Const(1), {} };
        prog.Add(inst);
        // r0.z = dot4(v0, c2) (mask 0x4)
        inst = { OP_DP4, RegisterRef::Temp(0, 0x4), RegisterRef::Input(0), RegisterRef::Const(2), {} };
        prog.Add(inst);
        // r0.w = dot4(v0, c3) (mask 0x8)
        inst = { OP_DP4, RegisterRef::Temp(0, 0x8), RegisterRef::Input(0), RegisterRef::Const(3), {} };
        prog.Add(inst);

        // o0 = r0 (output position)
        inst = { OP_MOV, RegisterRef::Output(0), RegisterRef::Temp(0), {}, {} };
        prog.Add(inst);

        // o1 = v1 (output color)
        inst = { OP_MOV, RegisterRef::Output(1), RegisterRef::Input(1), {}, {} };
        prog.Add(inst);

        prog.Add({ OP_RET, {}, {}, {}, {} });
        return prog;
    }

    // Standard Textured Shaded Pixel Shader
    // r0 = sample_texture(v2.xy, slot 0)
    // o1 = r0 * v1 (texture modulate by vertex color)
    static ShaderProgram BuildTexturedModulatePS() {
        ShaderProgram prog;
        Instruction inst{};

        // r0 = sample(slot 0, v2)
        inst = { OP_TEX, RegisterRef::Temp(0), RegisterRef::Input(2), {}, {}, 0 };
        prog.Add(inst);

        // o1 = r0 * v1
        inst = { OP_MUL, RegisterRef::Output(1), RegisterRef::Temp(0), RegisterRef::Input(1), {} };
        prog.Add(inst);

        prog.Add({ OP_RET, {}, {}, {}, {} });
        return prog;
    }

    // Directional Lighting Shaded Pixel Shader
    // c0 = Light Direction (Normalized float4)
    // c1 = Light Ambient (float4)
    // c2 = Light Diffuse (float4)
    // Computes: o1 = v1 * (c1 + c2 * max(dot3(v3, c0), 0.0))
    static ShaderProgram BuildDirectionalLightingPS() {
        ShaderProgram prog;
        Instruction inst{};

        // r0.x = dot3(v3, c0)
        inst = { OP_DP3, RegisterRef::Temp(0), RegisterRef::Input(3), RegisterRef::Const(0), {} };
        prog.Add(inst);

        // r0.x = max(r0.x, 0.0)
        inst = { OP_MAX, RegisterRef::Temp(0), RegisterRef::Temp(0), RegisterRef::Const(4) /* 0,0,0,0 */, {} };
        prog.Add(inst);

        // r1 = c2 * r0.xxxx (Diffuse contribution)
        inst = { OP_MUL, RegisterRef::Temp(1), RegisterRef::Const(2), RegisterRef::Temp(0).Swizzle(0, 0, 0, 0), {} };
        prog.Add(inst);

        // r2 = r1 + c1 (Ambient + Diffuse)
        inst = { OP_ADD, RegisterRef::Temp(2), RegisterRef::Temp(1), RegisterRef::Const(1), {} };
        prog.Add(inst);

        // o1 = v1 * r2 (Surface color modulated by lighting)
        inst = { OP_MUL, RegisterRef::Output(1), RegisterRef::Input(1), RegisterRef::Temp(2), {} };
        prog.Add(inst);

        prog.Add({ OP_RET, {}, {}, {}, {} });
        return prog;
    }
};

// ============================================================================
// 4. Standard Direct3D DXBC Container Format & Bytecode Interoperability
// ============================================================================

inline constexpr uint32_t FOURCC_DXBC = 0x43425844; // 'DXBC'
inline constexpr uint32_t FOURCC_ISGN = 0x4E475349; // 'ISGN'
inline constexpr uint32_t FOURCC_OSGN = 0x4E47534F; // 'OSGN'
inline constexpr uint32_t FOURCC_SHDR = 0x52444853; // 'SHDR'
inline constexpr uint32_t FOURCC_SHEX = 0x58454853; // 'SHEX'
inline constexpr uint32_t FOURCC_RDEF = 0x46454452; // 'RDEF'
inline constexpr uint32_t FOURCC_STAT = 0x54415453; // 'STAT'

#pragma pack(push, 1)
struct DxbcHeader {
    uint32_t magic;       // FOURCC_DXBC
    uint32_t checksum[4]; // 16 bytes hash
    uint32_t one;         // 1
    uint32_t totalSize;   // Size of entire DXBC stream
    uint32_t chunkCount;  // Number of chunks
};

struct DxbcChunkHeader {
    uint32_t fourCc;
    uint32_t chunkSize;
};
#pragma pack(pop)

struct DxbcChunk {
    uint32_t fourCc{ 0 };
    std::vector<uint8_t> data;
};

class DxbcContainer {
public:
    uint32_t programType{ 1 }; // 1 = VertexShader, 0 = PixelShader
    uint8_t majorVersion{ 5 };
    uint8_t minorVersion{ 0 };
    std::vector<DxbcChunk> chunks;

    static bool IsDxbc(const void* data, size_t size) {
        if (!data || size < sizeof(DxbcHeader)) return false;
        const auto* hdr = reinterpret_cast<const DxbcHeader*>(data);
        return hdr->magic == FOURCC_DXBC && hdr->totalSize <= size;
    }

    static bool Parse(const void* data, size_t size, DxbcContainer& out) {
        if (!IsDxbc(data, size)) return false;
        const auto* hdr = reinterpret_cast<const DxbcHeader*>(data);
        const auto* bytePtr = reinterpret_cast<const uint8_t*>(data);

        size_t headerAndOffsets = sizeof(DxbcHeader) + hdr->chunkCount * sizeof(uint32_t);
        if (size < headerAndOffsets) return false;

        const auto* offsets = reinterpret_cast<const uint32_t*>(bytePtr + sizeof(DxbcHeader));
        out.chunks.clear();

        for (uint32_t i = 0; i < hdr->chunkCount; ++i) {
            uint32_t offset = offsets[i];
            if (offset + sizeof(DxbcChunkHeader) > size) return false;

            const auto* chunkHdr = reinterpret_cast<const DxbcChunkHeader*>(bytePtr + offset);
            if (offset + sizeof(DxbcChunkHeader) + chunkHdr->chunkSize > size) return false;

            DxbcChunk chunk;
            chunk.fourCc = chunkHdr->fourCc;
            const uint8_t* chunkPayload = bytePtr + offset + sizeof(DxbcChunkHeader);
            chunk.data.assign(chunkPayload, chunkPayload + chunkHdr->chunkSize);

            if (chunk.fourCc == FOURCC_SHDR || chunk.fourCc == FOURCC_SHEX) {
                if (chunk.data.size() >= sizeof(uint32_t)) {
                    uint32_t verToken = *reinterpret_cast<const uint32_t*>(chunk.data.data());
                    out.programType = (verToken >> 16) & 0xFFFF;
                    out.majorVersion = static_cast<uint8_t>((verToken >> 8) & 0xFF);
                    out.minorVersion = static_cast<uint8_t>(verToken & 0xFF);
                }
            }

            out.chunks.push_back(std::move(chunk));
        }

        return true;
    }

    static std::vector<uint8_t> BuildContainer(
        uint32_t programType,
        uint8_t majorVersion,
        uint8_t minorVersion,
        const ShaderProgram& prog
    ) {
        // Build SHDR chunk
        std::vector<uint32_t> shdrTokens;
        uint32_t versionToken = ((programType & 0xFFFF) << 16) | ((majorVersion & 0xFF) << 8) | (minorVersion & 0xFF);
        shdrTokens.push_back(versionToken);

        // Instruction tokens
        for (const auto& inst : prog.GetInstructions()) {
            uint32_t opToken = (static_cast<uint32_t>(inst.op) & 0x7FF) | (5U << 24); // 5 dwords length
            shdrTokens.push_back(opToken);
            shdrTokens.push_back(static_cast<uint32_t>(inst.dst.type) | (inst.dst.index << 8) | (inst.dst.writeMask << 16));
            shdrTokens.push_back(static_cast<uint32_t>(inst.src0.type) | (inst.src0.index << 8));
            shdrTokens.push_back(static_cast<uint32_t>(inst.src1.type) | (inst.src1.index << 8));
            shdrTokens.push_back(static_cast<uint32_t>(inst.src2.type) | (inst.src2.index << 8) | (inst.samplerSlot << 16));
        }

        uint32_t shdrPayloadBytes = static_cast<uint32_t>(shdrTokens.size() * sizeof(uint32_t));

        // Build ISGN chunk (input signature header)
        std::vector<uint8_t> isgnData = {
            0x02, 0x00, 0x00, 0x00, // 2 elements
            0x08, 0x00, 0x00, 0x00  // signature payload
        };
        // Build OSGN chunk (output signature header)
        std::vector<uint8_t> osgnData = {
            0x02, 0x00, 0x00, 0x00, // 2 elements
            0x08, 0x00, 0x00, 0x00
        };

        uint32_t chunkCount = 3;
        uint32_t headerSize = static_cast<uint32_t>(sizeof(DxbcHeader) + chunkCount * sizeof(uint32_t));

        uint32_t offsetISGN = headerSize;
        uint32_t sizeISGN = static_cast<uint32_t>(sizeof(DxbcChunkHeader) + isgnData.size());

        uint32_t offsetOSGN = offsetISGN + sizeISGN;
        uint32_t sizeOSGN = static_cast<uint32_t>(sizeof(DxbcChunkHeader) + osgnData.size());

        uint32_t offsetSHDR = offsetOSGN + sizeOSGN;
        uint32_t sizeSHDR = static_cast<uint32_t>(sizeof(DxbcChunkHeader) + shdrPayloadBytes);

        uint32_t totalSize = offsetSHDR + sizeSHDR;

        std::vector<uint8_t> buffer(totalSize, 0);
        auto* hdr = reinterpret_cast<DxbcHeader*>(buffer.data());
        hdr->magic = FOURCC_DXBC;
        hdr->checksum[0] = 0xAA55AA55;
        hdr->checksum[1] = 0x12345678;
        hdr->checksum[2] = 0x9ABCDEF0;
        hdr->checksum[3] = 0xDEADBEEF;
        hdr->one = 1;
        hdr->totalSize = totalSize;
        hdr->chunkCount = chunkCount;

        auto* offsets = reinterpret_cast<uint32_t*>(buffer.data() + sizeof(DxbcHeader));
        offsets[0] = offsetISGN;
        offsets[1] = offsetOSGN;
        offsets[2] = offsetSHDR;

        // Write ISGN
        auto* chISGN = reinterpret_cast<DxbcChunkHeader*>(buffer.data() + offsetISGN);
        chISGN->fourCc = FOURCC_ISGN;
        chISGN->chunkSize = static_cast<uint32_t>(isgnData.size());
        std::memcpy(buffer.data() + offsetISGN + sizeof(DxbcChunkHeader), isgnData.data(), isgnData.size());

        // Write OSGN
        auto* chOSGN = reinterpret_cast<DxbcChunkHeader*>(buffer.data() + offsetOSGN);
        chOSGN->fourCc = FOURCC_OSGN;
        chOSGN->chunkSize = static_cast<uint32_t>(osgnData.size());
        std::memcpy(buffer.data() + offsetOSGN + sizeof(DxbcChunkHeader), osgnData.data(), osgnData.size());

        // Write SHDR
        auto* chSHDR = reinterpret_cast<DxbcChunkHeader*>(buffer.data() + offsetSHDR);
        chSHDR->fourCc = FOURCC_SHDR;
        chSHDR->chunkSize = shdrPayloadBytes;
        std::memcpy(buffer.data() + offsetSHDR + sizeof(DxbcChunkHeader), shdrTokens.data(), shdrPayloadBytes);

        return buffer;
    }

    ShaderProgram DecodeToProgram() const {
        for (const auto& chunk : chunks) {
            if (chunk.fourCc == FOURCC_SHDR || chunk.fourCc == FOURCC_SHEX) {
                if (chunk.data.size() < sizeof(uint32_t)) continue;
                const auto* tokens = reinterpret_cast<const uint32_t*>(chunk.data.data());
                size_t dwordCount = chunk.data.size() / sizeof(uint32_t);

                ShaderProgram prog;
                size_t idx = 1; // Skip version token
                while (idx + 4 < dwordCount) {
                    uint32_t opToken = tokens[idx];
                    uint8_t op = static_cast<uint8_t>(opToken & 0x7FF);
                    uint32_t dwordLen = (opToken >> 24) & 0x7F;
                    if (dwordLen == 0) dwordLen = 5;

                    uint32_t tDst = tokens[idx + 1];
                    uint32_t tSrc0 = tokens[idx + 2];
                    uint32_t tSrc1 = tokens[idx + 3];
                    uint32_t tSrc2 = tokens[idx + 4];

                    Instruction inst{};
                    inst.op = static_cast<Opcode>(op);
                    inst.dst = { static_cast<RegisterType>(tDst & 0xFF), static_cast<uint8_t>((tDst >> 8) & 0xFF), { 0, 1, 2, 3 }, static_cast<uint8_t>((tDst >> 16) & 0xFF) };
                    inst.src0 = { static_cast<RegisterType>(tSrc0 & 0xFF), static_cast<uint8_t>((tSrc0 >> 8) & 0xFF), { 0, 1, 2, 3 }, 0x0F };
                    inst.src1 = { static_cast<RegisterType>(tSrc1 & 0xFF), static_cast<uint8_t>((tSrc1 >> 8) & 0xFF), { 0, 1, 2, 3 }, 0x0F };
                    inst.src2 = { static_cast<RegisterType>(tSrc2 & 0xFF), static_cast<uint8_t>((tSrc2 >> 8) & 0xFF), { 0, 1, 2, 3 }, 0x0F };
                    inst.samplerSlot = static_cast<uint8_t>((tSrc2 >> 16) & 0xFF);

                    prog.Add(inst);
                    idx += dwordLen;
                    if (inst.op == OP_RET) break;
                }
                return prog;
            }
        }
        return {};
    }

    static std::string DisassembleBlob(const void* data, size_t size, const char* szComments) {
        DxbcContainer container;
        std::ostringstream ss;
        if (szComments && *szComments) {
            ss << "// " << szComments << "\n";
        }
        ss << "// MicaNT Sovereign Direct3D Shader Disassembler\n";

        if (!Parse(data, size, container)) {
            ss << "// Error: Invalid DXBC container format\n";
            return ss.str();
        }

        std::string targetProfile = (container.programType == 1) ? "vs_" : "ps_";
        targetProfile += std::to_string(container.majorVersion) + "_" + std::to_string(container.minorVersion);
        ss << targetProfile << "\n";

        ShaderProgram prog = container.DecodeToProgram();
        for (const auto& inst : prog.GetInstructions()) {
            switch (inst.op) {
                case OP_NOP: ss << "  nop\n"; break;
                case OP_MOV: ss << "  mov " << FormatReg(inst.dst) << ", " << FormatReg(inst.src0) << "\n"; break;
                case OP_ADD: ss << "  add " << FormatReg(inst.dst) << ", " << FormatReg(inst.src0) << ", " << FormatReg(inst.src1) << "\n"; break;
                case OP_SUB: ss << "  sub " << FormatReg(inst.dst) << ", " << FormatReg(inst.src0) << ", " << FormatReg(inst.src1) << "\n"; break;
                case OP_MUL: ss << "  mul " << FormatReg(inst.dst) << ", " << FormatReg(inst.src0) << ", " << FormatReg(inst.src1) << "\n"; break;
                case OP_MAD: ss << "  mad " << FormatReg(inst.dst) << ", " << FormatReg(inst.src0) << ", " << FormatReg(inst.src1) << ", " << FormatReg(inst.src2) << "\n"; break;
                case OP_DP3: ss << "  dp3 " << FormatReg(inst.dst) << ", " << FormatReg(inst.src0) << ", " << FormatReg(inst.src1) << "\n"; break;
                case OP_DP4: ss << "  dp4 " << FormatReg(inst.dst) << ", " << FormatReg(inst.src0) << ", " << FormatReg(inst.src1) << "\n"; break;
                case OP_MIN: ss << "  min " << FormatReg(inst.dst) << ", " << FormatReg(inst.src0) << ", " << FormatReg(inst.src1) << "\n"; break;
                case OP_MAX: ss << "  max " << FormatReg(inst.dst) << ", " << FormatReg(inst.src0) << ", " << FormatReg(inst.src1) << "\n"; break;
                case OP_TEX: ss << "  sample " << FormatReg(inst.dst) << ", " << FormatReg(inst.src0) << ", s" << static_cast<int>(inst.samplerSlot) << "\n"; break;
                case OP_RET: ss << "  ret\n"; break;
                default: ss << "  custom_op_" << static_cast<int>(inst.op) << "\n"; break;
            }
        }
        return ss.str();
    }

private:
    static std::string FormatReg(const RegisterRef& r) {
        std::string s;
        switch (r.type) {
            case REG_TEMP: s = "r" + std::to_string(r.index); break;
            case REG_INPUT: s = "v" + std::to_string(r.index); break;
            case REG_CONST: s = "c" + std::to_string(r.index); break;
            case REG_OUTPUT: s = "o" + std::to_string(r.index); break;
        }
        if (r.writeMask != 0x0F) {
            s += ".";
            if (r.writeMask & 0x1) s += "x";
            if (r.writeMask & 0x2) s += "y";
            if (r.writeMask & 0x4) s += "z";
            if (r.writeMask & 0x8) s += "w";
        }
        return s;
    }
};

} // namespace micant::prism_vm
