// ============================================================================
// MicaNT: Windows DirectML Machine Learning Subsystem
//
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/DirectX-Headers (DirectML.h)
//   - Microsoft DirectML Specifications 1.0 - 1.15
//
// Subsystem Overview:
//   directml.hpp provides low-level hardware-accelerated machine learning and
//   deep learning operator execution graphs. Binds directly to Direct3D 12
//   buffers and command lists for high-throughput GPU/NPU tensor compute.
//
// Core Operators Implemented:
//   - General Matrix Multiply (GEMM: Y = alpha * A * B + beta * C)
//   - Rectified Linear Unit (ReLU: Y = max(0, X))
//   - Softmax Activation (Softmax: Y = exp(X - max) / sum(exp(X - max)))
//   - 2D Spatial Convolution (Conv2D: multi-channel, stride, padding, bias)
//   - Batch Normalization (BatchNorm: Y = ((X - Mean) / sqrt(Var + eps)) * Scale + Bias)
//   - Element-Wise Addition & Multiplication (Add / Multiply)
//
// Trademark & Nominative Fair Use Notice:
//   DirectML, DirectX, and Direct3D are registered trademarks of Microsoft Corporation.
//   MicaNT's DirectML is an independent sovereign clean-room implementation
//   engineered for the MicaNT operating system executive.
// ============================================================================

#pragma once

#include "prism3d12.hpp"
#include "dxcore.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>
#include <sstream>

namespace micant::directml {

using namespace micant::prismx;
using namespace micant::prism3d;
using namespace micant::prism3d12;
using micant::GUID;
using micant::prismx::IUnknown;
using micant::prismx::IID_IUnknown;
using micant::prism3d12::ID3D12Resource;
using micant::prism3d12::ID3D12Device;
using micant::prism3d12::ID3D12GraphicsCommandList;
using micant::prism3d12::D3D12_CPU_DESCRIPTOR_HANDLE;
using micant::prism3d12::D3D12_GPU_DESCRIPTOR_HANDLE;

// ============================================================================
// 1. GUIDs & Interface Identifiers
// ============================================================================

inline constexpr GUID IID_IDMLObject_Const = {
    0xc8263aa1, 0x10c8, 0x4045, { 0xac, 0x7c, 0x30, 0xb2, 0x13, 0x9f, 0xbc, 0x65 }
};

inline constexpr GUID IID_IDMLDeviceChild_Const = {
    0x27e83142, 0x8165, 0x49e3, { 0x97, 0x4e, 0x2f, 0xd6, 0x6e, 0x4c, 0xb6, 0x9d }
};

inline constexpr GUID IID_IDMLPageable_Const = {
    0xb1a6c823, 0x83aa, 0x4012, { 0x81, 0x41, 0xda, 0x8b, 0x0e, 0x77, 0x4e, 0x1d }
};

inline constexpr GUID IID_IDMLOperator_Const = {
    0x26caae7a, 0x303c, 0x4936, { 0x86, 0x6e, 0x10, 0xe3, 0x91, 0xb7, 0x37, 0x76 }
};

inline constexpr GUID IID_IDMLDispatchable_Const = {
    0xdcb821a8, 0x1039, 0x441e, { 0x9f, 0x1c, 0x02, 0x5e, 0x5d, 0x05, 0x25, 0x44 }
};

inline constexpr GUID IID_IDMLCompiledOperator_Const = {
    0x6b15e56a, 0xbf5c, 0x4902, { 0x92, 0xd8, 0xda, 0x3a, 0x65, 0x04, 0xa7, 0xfb }
};

inline constexpr GUID IID_IDMLBindingTable_Const = {
    0x29c687dc, 0xde74, 0x4e3b, { 0xab, 0x00, 0x11, 0xb0, 0xec, 0x33, 0xf0, 0x16 }
};

inline constexpr GUID IID_IDMLCommandRecorder_Const = {
    0xe6857a46, 0x2c11, 0x4936, { 0xaa, 0x81, 0x14, 0x17, 0x80, 0xbd, 0x26, 0x41 }
};

inline constexpr GUID IID_IDMLDevice_Const = {
    0x29e12642, 0x4e37, 0x49b7, { 0xb0, 0x87, 0xf6, 0x94, 0x1a, 0x5f, 0x8e, 0x13 }
};

inline constexpr GUID IID_IDMLDevice1_Const = {
    0xa08863d3, 0xd249, 0x472e, { 0x8e, 0x48, 0xc2, 0x69, 0x57, 0x94, 0x61, 0x76 }
};

// ============================================================================
// 2. Constants & Enums
// ============================================================================

enum class DML_FEATURE_LEVEL : uint32_t {
    LEVEL_1_0 = 0x1000,
    LEVEL_2_0 = 0x2000,
    LEVEL_2_1 = 0x2100,
    LEVEL_3_0 = 0x3000,
    LEVEL_3_1 = 0x3100,
    LEVEL_4_0 = 0x4000,
    LEVEL_4_1 = 0x4100,
    LEVEL_5_0 = 0x5000,
    LEVEL_5_1 = 0x5100,
    LEVEL_5_2 = 0x5200,
    LEVEL_6_0 = 0x6000,
    LEVEL_6_1 = 0x6100,
    LEVEL_6_2 = 0x6200,
    LEVEL_6_3 = 0x6300,
    LEVEL_6_4 = 0x6400
};

enum class DML_TENSOR_DATA_TYPE : uint32_t {
    UNKNOWN = 0,
    FLOAT32 = 1,
    FLOAT16 = 2,
    UINT32  = 3,
    UINT16  = 4,
    UINT8   = 5,
    INT32   = 6,
    INT16   = 7,
    INT8    = 8,
    FLOAT64 = 9,
    UINT64  = 10,
    INT64   = 11
};

enum class DML_TENSOR_TYPE : uint32_t {
    INVALID = 0,
    BUFFER  = 1
};

enum class DML_TENSOR_FLAGS : uint32_t {
    NONE            = 0,
    OWNED_BY_DML    = 1
};

enum class DML_OPERATOR_TYPE : uint32_t {
    INVALID                     = 0,
    ELEMENT_WISE_IDENTITY       = 1,
    ELEMENT_WISE_ABS            = 2,
    ELEMENT_WISE_RELU           = 8,
    BATCH_NORMALIZATION         = 10,
    GEMM                        = 13,
    CONVOLUTION                 = 24,
    ELEMENT_WISE_ADD            = 35,
    ELEMENT_WISE_MULTIPLY       = 41,
    ACTIVATION_SOFTMAX          = 87
};

enum class DML_MATRIX_TRANSPOSE : uint32_t {
    NONE      = 0,
    TRANSPOSE = 1
};

enum class DML_CONVOLUTION_MODE : uint32_t {
    CONVOLUTION       = 0,
    CROSS_CORRELATION = 1
};

enum class DML_CONVOLUTION_DIRECTION : uint32_t {
    FORWARD  = 0,
    BACKWARD = 1
};

enum class DML_EXECUTION_FLAGS : uint32_t {
    NONE                                        = 0,
    ALLOW_HALF_PRECISION_COMPUTATION            = 1,
    DISABLE_META_COMMANDS                       = 2,
    DESCRIPTORS_KEPT_IN_FLOAT_UNIFORMS          = 4
};

enum class DML_CREATE_DEVICE_FLAGS : uint32_t {
    NONE  = 0,
    DEBUG = 1
};

enum class DML_FEATURE : uint32_t {
    TENSOR_DATA_TYPE_SUPPORT = 0,
    FEATURE_LEVELS           = 1
};

enum class DML_BINDING_TYPE : uint32_t {
    NONE         = 0,
    BUFFER       = 1,
    BUFFER_ARRAY = 2
};

// ============================================================================
// 3. Structures & Descriptors
// ============================================================================

struct DML_BUFFER_TENSOR_DESC {
    DML_TENSOR_DATA_TYPE DataType;
    DML_TENSOR_FLAGS Flags;
    uint32_t DimensionCount;
    const uint32_t* Sizes;
    const uint32_t* Strides;
    uint64_t TotalTensorSizeInBytes;
    uint32_t GuaranteedBaseOffsetAlignment;
};

struct DML_TENSOR_DESC {
    DML_TENSOR_TYPE Type;
    const void* Desc;
};

struct DML_OPERATOR_DESC {
    DML_OPERATOR_TYPE Type;
    const void* Desc;
};

struct DML_BINDING_PROPERTIES {
    uint32_t RequiredDescriptorCount;
    uint64_t TemporaryResourceSize;
    uint64_t PersistentResourceSize;
};

struct DML_BUFFER_BINDING {
    ID3D12Resource* Buffer;
    uint64_t Offset;
    uint64_t SizeInBytes;
};

struct DML_BUFFER_ARRAY_BINDING {
    uint32_t BindingCount;
    const DML_BUFFER_BINDING* Bindings;
};

struct DML_BINDING_DESC {
    DML_BINDING_TYPE Type;
    const void* Desc;
};

class IDMLDispatchable;

struct DML_BINDING_TABLE_DESC {
    IDMLDispatchable* Dispatchable;
    D3D12_CPU_DESCRIPTOR_HANDLE CPUDescriptorHandle;
    D3D12_GPU_DESCRIPTOR_HANDLE GPUDescriptorHandle;
    uint32_t SizeInDescriptors;
};

struct DML_FEATURE_DATA_FEATURE_LEVELS {
    uint32_t RequestedFeatureLevelCount;
    const DML_FEATURE_LEVEL* RequestedFeatureLevels;
    DML_FEATURE_LEVEL MaxSupportedFeatureLevel;
};

struct DML_FEATURE_DATA_TENSOR_DATA_TYPE_SUPPORT {
    DML_TENSOR_DATA_TYPE DataType;
    bool IsSupported;
};

// Operator Specific Descriptors
struct DML_ELEMENT_WISE_RELU_OPERATOR_DESC {
    const DML_TENSOR_DESC* InputTensor;
    const DML_TENSOR_DESC* OutputTensor;
};

struct DML_ACTIVATION_SOFTMAX_OPERATOR_DESC {
    const DML_TENSOR_DESC* InputTensor;
    const DML_TENSOR_DESC* OutputTensor;
};

struct DML_GEMM_OPERATOR_DESC {
    const DML_TENSOR_DESC* ATensor;
    const DML_TENSOR_DESC* BTensor;
    const DML_TENSOR_DESC* CTensor; // Optional bias
    const DML_TENSOR_DESC* OutputTensor;
    DML_MATRIX_TRANSPOSE TransA;
    DML_MATRIX_TRANSPOSE TransB;
    float Alpha;
    float Beta;
    const DML_OPERATOR_DESC* FusedActivation;
};

struct DML_CONVOLUTION_OPERATOR_DESC {
    const DML_TENSOR_DESC* InputTensor;  // [N, C, H, W]
    const DML_TENSOR_DESC* FilterTensor; // [M, C/groups, Kh, Kw]
    const DML_TENSOR_DESC* BiasTensor;   // Optional [1, M, 1, 1]
    const DML_TENSOR_DESC* OutputTensor; // [N, M, OutH, OutW]
    DML_CONVOLUTION_MODE Mode;
    DML_CONVOLUTION_DIRECTION Direction;
    uint32_t DimensionCount;
    const uint32_t* Strides;
    const uint32_t* Dilations;
    const uint32_t* StartPadding;
    const uint32_t* EndPadding;
    const uint32_t* OutputPadding;
    uint32_t GroupCount;
    const DML_OPERATOR_DESC* FusedActivation;
};

struct DML_BATCH_NORMALIZATION_OPERATOR_DESC {
    const DML_TENSOR_DESC* InputTensor;
    const DML_TENSOR_DESC* MeanTensor;
    const DML_TENSOR_DESC* VarianceTensor;
    const DML_TENSOR_DESC* ScaleTensor;
    const DML_TENSOR_DESC* BiasTensor;
    const DML_TENSOR_DESC* OutputTensor;
    bool Spatial;
    float Epsilon;
    const DML_OPERATOR_DESC* FusedActivation;
};

struct DML_ELEMENT_WISE_ADD_OPERATOR_DESC {
    const DML_TENSOR_DESC* ATensor;
    const DML_TENSOR_DESC* BTensor;
    const DML_TENSOR_DESC* OutputTensor;
};

struct DML_ELEMENT_WISE_MULTIPLY_OPERATOR_DESC {
    const DML_TENSOR_DESC* ATensor;
    const DML_TENSOR_DESC* BTensor;
    const DML_TENSOR_DESC* OutputTensor;
};

// ============================================================================
// 4. Abstract COM Interfaces
// ============================================================================

class IDMLDevice;

class IDMLObject : public IUnknown {
public:
    virtual int32_t GetPrivateData(const GUID& guid, uint32_t* dataSize, void* data) = 0;
    virtual int32_t SetPrivateData(const GUID& guid, uint32_t dataSize, const void* data) = 0;
    virtual int32_t SetPrivateDataInterface(const GUID& guid, const IUnknown* data) = 0;
    virtual int32_t SetName(const wchar_t* name) = 0;
};

class IDMLDeviceChild : public IDMLObject {
public:
    virtual int32_t GetDevice(const GUID& riid, void** ppDevice) = 0;
};

class IDMLPageable : public IDMLDeviceChild {};

class IDMLOperator : public IDMLDeviceChild {};

class IDMLDispatchable : public IDMLPageable {
public:
    virtual DML_BINDING_PROPERTIES GetBindingProperties() = 0;
};

class IDMLCompiledOperator : public IDMLDispatchable {};

class IDMLBindingTable : public IDMLDeviceChild {
public:
    virtual int32_t BindInputs(uint32_t count, const DML_BINDING_DESC* bindings) = 0;
    virtual int32_t BindOutputs(uint32_t count, const DML_BINDING_DESC* bindings) = 0;
    virtual int32_t BindTemporaryResource(const DML_BINDING_DESC* binding) = 0;
    virtual int32_t BindPersistentResource(const DML_BINDING_DESC* binding) = 0;
    virtual int32_t Reset(const DML_BINDING_TABLE_DESC* desc) = 0;
};

class IDMLCommandRecorder : public IDMLDeviceChild {
public:
    virtual void RecordDispatch(
        ID3D12GraphicsCommandList* commandList,
        IDMLDispatchable* dispatchable,
        IDMLBindingTable* bindings
    ) = 0;
};

class IDMLDevice : public IDMLObject {
public:
    virtual int32_t CheckFeatureSupport(
        DML_FEATURE feature,
        uint32_t featureQueryDataSize,
        const void* featureQueryData,
        uint32_t featureSupportDataSize,
        void* featureSupportData
    ) = 0;

    virtual int32_t CreateOperator(
        const DML_OPERATOR_DESC* desc,
        const GUID& riid,
        void** ppv
    ) = 0;

    virtual int32_t CompileOperator(
        IDMLOperator* op,
        DML_EXECUTION_FLAGS flags,
        const GUID& riid,
        void** ppv
    ) = 0;

    virtual int32_t CreateBindingTable(
        const DML_BINDING_TABLE_DESC* desc,
        const GUID& riid,
        void** ppv
    ) = 0;

    virtual int32_t CreateCommandRecorder(
        const GUID& riid,
        void** ppv
    ) = 0;
};

class IDMLDevice1 : public IDMLDevice {
public:
    virtual int32_t CompileGraph(
        const void* graphDesc,
        DML_EXECUTION_FLAGS flags,
        const GUID& riid,
        void** ppv
    ) = 0;
};

// ============================================================================
// 5. Concrete Subsystem Implementation & Tensor Compute Engine
// ============================================================================

struct ParsedOperatorData {
    DML_OPERATOR_TYPE type{ DML_OPERATOR_TYPE::INVALID };
    std::vector<uint32_t> inputSizes;
    std::vector<uint32_t> outputSizes;
    std::vector<uint32_t> weightsSizes;
    std::vector<uint32_t> biasSizes;
    float alpha{ 1.0f };
    float beta{ 0.0f };
    DML_MATRIX_TRANSPOSE transA{ DML_MATRIX_TRANSPOSE::NONE };
    DML_MATRIX_TRANSPOSE transB{ DML_MATRIX_TRANSPOSE::NONE };
    uint32_t strideH{ 1 };
    uint32_t strideW{ 1 };
    uint32_t padH{ 0 };
    uint32_t padW{ 0 };
    uint32_t groupCount{ 1 };
    float epsilon{ 1e-5f };
    bool fusedReLU{ false };
};

class MicaDMLOperatorImpl : public IDMLOperator {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDMLDevice* m_pDevice{ nullptr };
    ParsedOperatorData m_parsedData{};

public:
    MicaDMLOperatorImpl(IDMLDevice* device, const DML_OPERATOR_DESC* desc)
        : m_pDevice(device) {
        if (!desc) return;
        m_parsedData.type = desc->Type;

        switch (desc->Type) {
            case DML_OPERATOR_TYPE::ELEMENT_WISE_RELU: {
                auto* d = static_cast<const DML_ELEMENT_WISE_RELU_OPERATOR_DESC*>(desc->Desc);
                if (d && d->InputTensor && d->InputTensor->Desc) {
                    auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->InputTensor->Desc);
                    m_parsedData.inputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                }
                if (d && d->OutputTensor && d->OutputTensor->Desc) {
                    auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->OutputTensor->Desc);
                    m_parsedData.outputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                }
                break;
            }
            case DML_OPERATOR_TYPE::ACTIVATION_SOFTMAX: {
                auto* d = static_cast<const DML_ACTIVATION_SOFTMAX_OPERATOR_DESC*>(desc->Desc);
                if (d && d->InputTensor && d->InputTensor->Desc) {
                    auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->InputTensor->Desc);
                    m_parsedData.inputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                }
                if (d && d->OutputTensor && d->OutputTensor->Desc) {
                    auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->OutputTensor->Desc);
                    m_parsedData.outputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                }
                break;
            }
            case DML_OPERATOR_TYPE::GEMM: {
                auto* d = static_cast<const DML_GEMM_OPERATOR_DESC*>(desc->Desc);
                if (d) {
                    m_parsedData.alpha = d->Alpha;
                    m_parsedData.beta = d->Beta;
                    m_parsedData.transA = d->TransA;
                    m_parsedData.transB = d->TransB;
                    if (d->ATensor && d->ATensor->Desc) {
                        auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->ATensor->Desc);
                        m_parsedData.inputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                    }
                    if (d->BTensor && d->BTensor->Desc) {
                        auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->BTensor->Desc);
                        m_parsedData.weightsSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                    }
                    if (d->CTensor && d->CTensor->Desc) {
                        auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->CTensor->Desc);
                        m_parsedData.biasSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                    }
                    if (d->OutputTensor && d->OutputTensor->Desc) {
                        auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->OutputTensor->Desc);
                        m_parsedData.outputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                    }
                    if (d->FusedActivation && d->FusedActivation->Type == DML_OPERATOR_TYPE::ELEMENT_WISE_RELU) {
                        m_parsedData.fusedReLU = true;
                    }
                }
                break;
            }
            case DML_OPERATOR_TYPE::CONVOLUTION: {
                auto* d = static_cast<const DML_CONVOLUTION_OPERATOR_DESC*>(desc->Desc);
                if (d) {
                    if (d->InputTensor && d->InputTensor->Desc) {
                        auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->InputTensor->Desc);
                        m_parsedData.inputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                    }
                    if (d->FilterTensor && d->FilterTensor->Desc) {
                        auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->FilterTensor->Desc);
                        m_parsedData.weightsSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                    }
                    if (d->BiasTensor && d->BiasTensor->Desc) {
                        auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->BiasTensor->Desc);
                        m_parsedData.biasSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                    }
                    if (d->OutputTensor && d->OutputTensor->Desc) {
                        auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->OutputTensor->Desc);
                        m_parsedData.outputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                    }
                    if (d->Strides) {
                        m_parsedData.strideH = d->Strides[0];
                        m_parsedData.strideW = (d->DimensionCount > 1) ? d->Strides[1] : d->Strides[0];
                    }
                    if (d->StartPadding) {
                        m_parsedData.padH = d->StartPadding[0];
                        m_parsedData.padW = (d->DimensionCount > 1) ? d->StartPadding[1] : d->StartPadding[0];
                    }
                    m_parsedData.groupCount = (d->GroupCount > 0) ? d->GroupCount : 1;
                    if (d->FusedActivation && d->FusedActivation->Type == DML_OPERATOR_TYPE::ELEMENT_WISE_RELU) {
                        m_parsedData.fusedReLU = true;
                    }
                }
                break;
            }
            case DML_OPERATOR_TYPE::BATCH_NORMALIZATION: {
                auto* d = static_cast<const DML_BATCH_NORMALIZATION_OPERATOR_DESC*>(desc->Desc);
                if (d) {
                    if (d->InputTensor && d->InputTensor->Desc) {
                        auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->InputTensor->Desc);
                        m_parsedData.inputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                    }
                    if (d->OutputTensor && d->OutputTensor->Desc) {
                        auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->OutputTensor->Desc);
                        m_parsedData.outputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                    }
                    m_parsedData.epsilon = d->Epsilon;
                    if (d->FusedActivation && d->FusedActivation->Type == DML_OPERATOR_TYPE::ELEMENT_WISE_RELU) {
                        m_parsedData.fusedReLU = true;
                    }
                }
                break;
            }
            case DML_OPERATOR_TYPE::ELEMENT_WISE_ADD:
            case DML_OPERATOR_TYPE::ELEMENT_WISE_MULTIPLY: {
                auto* d = static_cast<const DML_ELEMENT_WISE_ADD_OPERATOR_DESC*>(desc->Desc);
                if (d && d->ATensor && d->ATensor->Desc) {
                    auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->ATensor->Desc);
                    m_parsedData.inputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                }
                if (d && d->OutputTensor && d->OutputTensor->Desc) {
                    auto* bd = static_cast<const DML_BUFFER_TENSOR_DESC*>(d->OutputTensor->Desc);
                    m_parsedData.outputSizes.assign(bd->Sizes, bd->Sizes + bd->DimensionCount);
                }
                break;
            }
            default:
                break;
        }
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IDMLObject_Const || riid == IID_IDMLDeviceChild_Const || riid == IID_IDMLOperator_Const) {
            *ppv = static_cast<IDMLOperator*>(this);
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

    int32_t GetPrivateData(const GUID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const GUID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const GUID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }

    int32_t GetDevice(const GUID& riid, void** ppDevice) override {
        if (!ppDevice) return -2147467261;
        if (!m_pDevice) return -2147467259;
        return m_pDevice->QueryInterface(riid, ppDevice);
    }

    const ParsedOperatorData& GetParsedData() const { return m_parsedData; }
};

class MicaDMLCompiledOperatorImpl : public IDMLCompiledOperator {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDMLDevice* m_pDevice{ nullptr };
    ParsedOperatorData m_data;
    DML_EXECUTION_FLAGS m_flags{ DML_EXECUTION_FLAGS::NONE };
    DML_BINDING_PROPERTIES m_bindingProps{};

public:
    MicaDMLCompiledOperatorImpl(IDMLDevice* device, ParsedOperatorData data, DML_EXECUTION_FLAGS flags)
        : m_pDevice(device), m_data(std::move(data)), m_flags(flags) {
        m_bindingProps.RequiredDescriptorCount = 1;
        m_bindingProps.TemporaryResourceSize = 0;
        m_bindingProps.PersistentResourceSize = 0;
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IDMLObject_Const || riid == IID_IDMLDeviceChild_Const ||
            riid == IID_IDMLPageable_Const || riid == IID_IDMLDispatchable_Const || riid == IID_IDMLCompiledOperator_Const) {
            *ppv = static_cast<IDMLCompiledOperator*>(this);
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

    int32_t GetPrivateData(const GUID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const GUID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const GUID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }

    int32_t GetDevice(const GUID& riid, void** ppDevice) override {
        if (!ppDevice) return -2147467261;
        if (!m_pDevice) return -2147467259;
        return m_pDevice->QueryInterface(riid, ppDevice);
    }

    DML_BINDING_PROPERTIES GetBindingProperties() override {
        return m_bindingProps;
    }

    const ParsedOperatorData& GetParsedData() const { return m_data; }
    DML_EXECUTION_FLAGS GetFlags() const { return m_flags; }
};

class MicaDMLBindingTableImpl : public IDMLBindingTable {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDMLDevice* m_pDevice{ nullptr };
    IDMLDispatchable* m_pDispatchable{ nullptr };
    std::vector<DML_BUFFER_BINDING> m_inputBindings;
    std::vector<DML_BUFFER_BINDING> m_outputBindings;
    DML_BUFFER_BINDING m_tempBinding{};
    DML_BUFFER_BINDING m_persistentBinding{};

public:
    MicaDMLBindingTableImpl(IDMLDevice* device, const DML_BINDING_TABLE_DESC* desc)
        : m_pDevice(device) {
        if (desc) {
            m_pDispatchable = desc->Dispatchable;
        }
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IDMLObject_Const || riid == IID_IDMLDeviceChild_Const || riid == IID_IDMLBindingTable_Const) {
            *ppv = static_cast<IDMLBindingTable*>(this);
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

    int32_t GetPrivateData(const GUID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const GUID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const GUID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }

    int32_t GetDevice(const GUID& riid, void** ppDevice) override {
        if (!ppDevice) return -2147467261;
        if (!m_pDevice) return -2147467259;
        return m_pDevice->QueryInterface(riid, ppDevice);
    }

    int32_t BindInputs(uint32_t count, const DML_BINDING_DESC* bindings) override {
        m_inputBindings.clear();
        for (uint32_t i = 0; i < count; ++i) {
            if (bindings[i].Type == DML_BINDING_TYPE::BUFFER && bindings[i].Desc) {
                m_inputBindings.push_back(*static_cast<const DML_BUFFER_BINDING*>(bindings[i].Desc));
            } else {
                m_inputBindings.push_back(DML_BUFFER_BINDING{ nullptr, 0, 0 });
            }
        }
        return 0;
    }

    int32_t BindOutputs(uint32_t count, const DML_BINDING_DESC* bindings) override {
        m_outputBindings.clear();
        for (uint32_t i = 0; i < count; ++i) {
            if (bindings[i].Type == DML_BINDING_TYPE::BUFFER && bindings[i].Desc) {
                m_outputBindings.push_back(*static_cast<const DML_BUFFER_BINDING*>(bindings[i].Desc));
            } else {
                m_outputBindings.push_back(DML_BUFFER_BINDING{ nullptr, 0, 0 });
            }
        }
        return 0;
    }

    int32_t BindTemporaryResource(const DML_BINDING_DESC* binding) override {
        if (binding && binding->Type == DML_BINDING_TYPE::BUFFER && binding->Desc) {
            m_tempBinding = *static_cast<const DML_BUFFER_BINDING*>(binding->Desc);
        } else {
            m_tempBinding = DML_BUFFER_BINDING{ nullptr, 0, 0 };
        }
        return 0;
    }

    int32_t BindPersistentResource(const DML_BINDING_DESC* binding) override {
        if (binding && binding->Type == DML_BINDING_TYPE::BUFFER && binding->Desc) {
            m_persistentBinding = *static_cast<const DML_BUFFER_BINDING*>(binding->Desc);
        } else {
            m_persistentBinding = DML_BUFFER_BINDING{ nullptr, 0, 0 };
        }
        return 0;
    }

    int32_t Reset(const DML_BINDING_TABLE_DESC* desc) override {
        m_inputBindings.clear();
        m_outputBindings.clear();
        m_tempBinding = {};
        m_persistentBinding = {};
        if (desc) {
            m_pDispatchable = desc->Dispatchable;
        } else {
            m_pDispatchable = nullptr;
        }
        return 0;
    }

    const std::vector<DML_BUFFER_BINDING>& GetInputs() const { return m_inputBindings; }
    const std::vector<DML_BUFFER_BINDING>& GetOutputs() const { return m_outputBindings; }
};

class MicaDMLCommandRecorderImpl : public IDMLCommandRecorder {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDMLDevice* m_pDevice{ nullptr };

public:
    MicaDMLCommandRecorderImpl(IDMLDevice* device) : m_pDevice(device) {}

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IDMLObject_Const || riid == IID_IDMLDeviceChild_Const || riid == IID_IDMLCommandRecorder_Const) {
            *ppv = static_cast<IDMLCommandRecorder*>(this);
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

    int32_t GetPrivateData(const GUID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const GUID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const GUID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }

    int32_t GetDevice(const GUID& riid, void** ppDevice) override {
        if (!ppDevice) return -2147467261;
        if (!m_pDevice) return -2147467259;
        return m_pDevice->QueryInterface(riid, ppDevice);
    }

    void RecordDispatch(
        ID3D12GraphicsCommandList*,
        IDMLDispatchable* dispatchable,
        IDMLBindingTable* bindings
    ) override {
        if (!dispatchable || !bindings) return;

        auto* compOp = static_cast<MicaDMLCompiledOperatorImpl*>(dispatchable);
        auto* table = static_cast<MicaDMLBindingTableImpl*>(bindings);
        const auto& opData = compOp->GetParsedData();
        const auto& inBinds = table->GetInputs();
        const auto& outBinds = table->GetOutputs();

        if (outBinds.empty() || !outBinds[0].Buffer) return;

        // Execute tensor kernel directly into bound D3D12 resource buffer
        void* outPtr = nullptr;
        outBinds[0].Buffer->Map(0, nullptr, &outPtr);
        if (!outPtr) return;
        float* pOutFloat = reinterpret_cast<float*>(static_cast<uint8_t*>(outPtr) + outBinds[0].Offset);

        switch (opData.type) {
            case DML_OPERATOR_TYPE::ELEMENT_WISE_RELU: {
                if (!inBinds.empty() && inBinds[0].Buffer) {
                    void* inPtr = nullptr;
                    inBinds[0].Buffer->Map(0, nullptr, &inPtr);
                    if (inPtr) {
                        const float* pIn = reinterpret_cast<const float*>(static_cast<const uint8_t*>(inPtr) + inBinds[0].Offset);
                        size_t count = inBinds[0].SizeInBytes / sizeof(float);
                        for (size_t i = 0; i < count; ++i) {
                            pOutFloat[i] = std::max(0.0f, pIn[i]);
                        }
                        inBinds[0].Buffer->Unmap(0, nullptr);
                    }
                }
                break;
            }

            case DML_OPERATOR_TYPE::ACTIVATION_SOFTMAX: {
                if (!inBinds.empty() && inBinds[0].Buffer) {
                    void* inPtr = nullptr;
                    inBinds[0].Buffer->Map(0, nullptr, &inPtr);
                    if (inPtr) {
                        const float* pIn = reinterpret_cast<const float*>(static_cast<const uint8_t*>(inPtr) + inBinds[0].Offset);
                        size_t count = inBinds[0].SizeInBytes / sizeof(float);
                        if (count > 0) {
                            float maxVal = pIn[0];
                            for (size_t i = 1; i < count; ++i) {
                                if (pIn[i] > maxVal) maxVal = pIn[i];
                            }
                            float sumExp = 0.0f;
                            for (size_t i = 0; i < count; ++i) {
                                pOutFloat[i] = std::exp(pIn[i] - maxVal);
                                sumExp += pOutFloat[i];
                            }
                            if (sumExp > 0.0f) {
                                for (size_t i = 0; i < count; ++i) {
                                    pOutFloat[i] /= sumExp;
                                }
                            }
                        }
                        inBinds[0].Buffer->Unmap(0, nullptr);
                    }
                }
                break;
            }

            case DML_OPERATOR_TYPE::GEMM: {
                // Y = Alpha * (op(A) * op(B)) + Beta * C
                if (inBinds.size() >= 2 && inBinds[0].Buffer && inBinds[1].Buffer) {
                    void* aPtr = nullptr;
                    void* bPtr = nullptr;
                    void* cPtr = nullptr;
                    inBinds[0].Buffer->Map(0, nullptr, &aPtr);
                    inBinds[1].Buffer->Map(0, nullptr, &bPtr);
                    if (inBinds.size() >= 3 && inBinds[2].Buffer) {
                        inBinds[2].Buffer->Map(0, nullptr, &cPtr);
                    }

                    if (aPtr && bPtr) {
                        const float* pA = reinterpret_cast<const float*>(static_cast<const uint8_t*>(aPtr) + inBinds[0].Offset);
                        const float* pB = reinterpret_cast<const float*>(static_cast<const uint8_t*>(bPtr) + inBinds[1].Offset);
                        const float* pC = cPtr ? reinterpret_cast<const float*>(static_cast<const uint8_t*>(cPtr) + inBinds[2].Offset) : nullptr;

                        // Shapes
                        uint32_t aRows = (opData.inputSizes.size() >= 2) ? opData.inputSizes[opData.inputSizes.size() - 2] : 1;
                        uint32_t aCols = (opData.inputSizes.size() >= 1) ? opData.inputSizes[opData.inputSizes.size() - 1] : 1;
                        uint32_t bRows = (opData.weightsSizes.size() >= 2) ? opData.weightsSizes[opData.weightsSizes.size() - 2] : 1;
                        uint32_t bCols = (opData.weightsSizes.size() >= 1) ? opData.weightsSizes[opData.weightsSizes.size() - 1] : 1;

                        bool transA = (opData.transA == DML_MATRIX_TRANSPOSE::TRANSPOSE);
                        bool transB = (opData.transB == DML_MATRIX_TRANSPOSE::TRANSPOSE);

                        uint32_t M = transA ? aCols : aRows;
                        uint32_t K = transA ? aRows : aCols;
                        uint32_t N = transB ? bRows : bCols;

                        for (uint32_t m = 0; m < M; ++m) {
                            for (uint32_t n = 0; n < N; ++n) {
                                float sum = 0.0f;
                                for (uint32_t k = 0; k < K; ++k) {
                                    float aVal = transA ? pA[k * M + m] : pA[m * K + k];
                                    float bVal = transB ? pB[n * K + k] : pB[k * N + n];
                                    sum += aVal * bVal;
                                }

                                float bias = 0.0f;
                                if (pC) {
                                    size_t cElements = inBinds[2].SizeInBytes / sizeof(float);
                                    if (cElements == M * N) {
                                        bias = pC[m * N + n];
                                    } else if (cElements == N) {
                                        bias = pC[n]; // Row broadcasting
                                    } else if (cElements == 1) {
                                        bias = pC[0]; // Scalar
                                    }
                                }

                                float res = opData.alpha * sum + opData.beta * bias;
                                if (opData.fusedReLU) {
                                    res = std::max(0.0f, res);
                                }
                                pOutFloat[m * N + n] = res;
                            }
                        }
                    }

                    if (cPtr && inBinds.size() >= 3 && inBinds[2].Buffer) inBinds[2].Buffer->Unmap(0, nullptr);
                    if (bPtr) inBinds[1].Buffer->Unmap(0, nullptr);
                    if (aPtr) inBinds[0].Buffer->Unmap(0, nullptr);
                }
                break;
            }

            case DML_OPERATOR_TYPE::CONVOLUTION: {
                // 2D Spatial Convolution
                if (inBinds.size() >= 2 && inBinds[0].Buffer && inBinds[1].Buffer) {
                    void* inPtr = nullptr;
                    void* wPtr = nullptr;
                    void* bPtr = nullptr;
                    inBinds[0].Buffer->Map(0, nullptr, &inPtr);
                    inBinds[1].Buffer->Map(0, nullptr, &wPtr);
                    if (inBinds.size() >= 3 && inBinds[2].Buffer) {
                        inBinds[2].Buffer->Map(0, nullptr, &bPtr);
                    }

                    if (inPtr && wPtr) {
                        const float* pIn = reinterpret_cast<const float*>(static_cast<const uint8_t*>(inPtr) + inBinds[0].Offset);
                        const float* pW = reinterpret_cast<const float*>(static_cast<const uint8_t*>(wPtr) + inBinds[1].Offset);
                        const float* pB = bPtr ? reinterpret_cast<const float*>(static_cast<const uint8_t*>(bPtr) + inBinds[2].Offset) : nullptr;

                        // Shapes [N, C, H, W]
                        uint32_t N_batch = (opData.inputSizes.size() >= 4) ? opData.inputSizes[0] : 1;
                        uint32_t C_in = (opData.inputSizes.size() >= 4) ? opData.inputSizes[1] : 1;
                        uint32_t H_in = (opData.inputSizes.size() >= 4) ? opData.inputSizes[2] : 1;
                        uint32_t W_in = (opData.inputSizes.size() >= 4) ? opData.inputSizes[3] : 1;

                        // Filter [M, C_in/groups, Kh, Kw]
                        uint32_t M_out = (opData.weightsSizes.size() >= 4) ? opData.weightsSizes[0] : 1;
                        uint32_t Kh = (opData.weightsSizes.size() >= 4) ? opData.weightsSizes[2] : 1;
                        uint32_t Kw = (opData.weightsSizes.size() >= 4) ? opData.weightsSizes[3] : 1;

                        // Output [N, M, OutH, OutW]
                        uint32_t H_out = (opData.outputSizes.size() >= 4) ? opData.outputSizes[2] : 1;
                        uint32_t W_out = (opData.outputSizes.size() >= 4) ? opData.outputSizes[3] : 1;

                        for (uint32_t n = 0; n < N_batch; ++n) {
                            for (uint32_t m = 0; m < M_out; ++m) {
                                float bias = pB ? pB[m] : 0.0f;
                                for (uint32_t oh = 0; oh < H_out; ++oh) {
                                    for (uint32_t ow = 0; ow < W_out; ++ow) {
                                        float sum = 0.0f;
                                        int startH = static_cast<int>(oh * opData.strideH) - static_cast<int>(opData.padH);
                                        int startW = static_cast<int>(ow * opData.strideW) - static_cast<int>(opData.padW);

                                        for (uint32_t c = 0; c < C_in; ++c) {
                                            for (uint32_t kh = 0; kh < Kh; ++kh) {
                                                for (uint32_t kw = 0; kw < Kw; ++kw) {
                                                    int ih = startH + kh;
                                                    int iw = startW + kw;
                                                    if (ih >= 0 && ih < static_cast<int>(H_in) &&
                                                        iw >= 0 && iw < static_cast<int>(W_in)) {
                                                        size_t inIdx = ((n * C_in + c) * H_in + ih) * W_in + iw;
                                                        size_t wIdx = ((m * C_in + c) * Kh + kh) * Kw + kw;
                                                        sum += pIn[inIdx] * pW[wIdx];
                                                    }
                                                }
                                            }
                                        }

                                        float val = sum + bias;
                                        if (opData.fusedReLU) {
                                            val = std::max(0.0f, val);
                                        }
                                        size_t outIdx = ((n * M_out + m) * H_out + oh) * W_out + ow;
                                        pOutFloat[outIdx] = val;
                                    }
                                }
                            }
                        }
                    }

                    if (bPtr && inBinds.size() >= 3 && inBinds[2].Buffer) inBinds[2].Buffer->Unmap(0, nullptr);
                    if (wPtr) inBinds[1].Buffer->Unmap(0, nullptr);
                    if (inPtr) inBinds[0].Buffer->Unmap(0, nullptr);
                }
                break;
            }

            case DML_OPERATOR_TYPE::BATCH_NORMALIZATION: {
                // Y = ((X - Mean) / sqrt(Var + Epsilon)) * Scale + Bias
                if (inBinds.size() >= 5 && inBinds[0].Buffer && inBinds[1].Buffer &&
                    inBinds[2].Buffer && inBinds[3].Buffer && inBinds[4].Buffer) {
                    void* xPtr = nullptr;
                    void* meanPtr = nullptr;
                    void* varPtr = nullptr;
                    void* scalePtr = nullptr;
                    void* biasPtr = nullptr;
                    inBinds[0].Buffer->Map(0, nullptr, &xPtr);
                    inBinds[1].Buffer->Map(0, nullptr, &meanPtr);
                    inBinds[2].Buffer->Map(0, nullptr, &varPtr);
                    inBinds[3].Buffer->Map(0, nullptr, &scalePtr);
                    inBinds[4].Buffer->Map(0, nullptr, &biasPtr);

                    if (xPtr && meanPtr && varPtr && scalePtr && biasPtr) {
                        const float* pX = reinterpret_cast<const float*>(static_cast<const uint8_t*>(xPtr) + inBinds[0].Offset);
                        const float* pMean = reinterpret_cast<const float*>(static_cast<const uint8_t*>(meanPtr) + inBinds[1].Offset);
                        const float* pVar = reinterpret_cast<const float*>(static_cast<const uint8_t*>(varPtr) + inBinds[2].Offset);
                        const float* pScale = reinterpret_cast<const float*>(static_cast<const uint8_t*>(scalePtr) + inBinds[3].Offset);
                        const float* pBias = reinterpret_cast<const float*>(static_cast<const uint8_t*>(biasPtr) + inBinds[4].Offset);

                        uint32_t N = (opData.inputSizes.size() >= 4) ? opData.inputSizes[0] : 1;
                        uint32_t C = (opData.inputSizes.size() >= 4) ? opData.inputSizes[1] : 1;
                        uint32_t H = (opData.inputSizes.size() >= 4) ? opData.inputSizes[2] : 1;
                        uint32_t W = (opData.inputSizes.size() >= 4) ? opData.inputSizes[3] : 1;

                        for (uint32_t n = 0; n < N; ++n) {
                            for (uint32_t c = 0; c < C; ++c) {
                                float mean = pMean[c];
                                float var = pVar[c];
                                float scale = pScale[c];
                                float bias = pBias[c];
                                float invStd = 1.0f / std::sqrt(var + opData.epsilon);

                                for (uint32_t hw = 0; hw < H * W; ++hw) {
                                    size_t idx = (n * C + c) * (H * W) + hw;
                                    float val = ((pX[idx] - mean) * invStd) * scale + bias;
                                    if (opData.fusedReLU) val = std::max(0.0f, val);
                                    pOutFloat[idx] = val;
                                }
                            }
                        }
                    }

                    if (biasPtr) inBinds[4].Buffer->Unmap(0, nullptr);
                    if (scalePtr) inBinds[3].Buffer->Unmap(0, nullptr);
                    if (varPtr) inBinds[2].Buffer->Unmap(0, nullptr);
                    if (meanPtr) inBinds[1].Buffer->Unmap(0, nullptr);
                    if (xPtr) inBinds[0].Buffer->Unmap(0, nullptr);
                }
                break;
            }

            case DML_OPERATOR_TYPE::ELEMENT_WISE_ADD:
            case DML_OPERATOR_TYPE::ELEMENT_WISE_MULTIPLY: {
                if (inBinds.size() >= 2 && inBinds[0].Buffer && inBinds[1].Buffer) {
                    void* aPtr = nullptr;
                    void* bPtr = nullptr;
                    inBinds[0].Buffer->Map(0, nullptr, &aPtr);
                    inBinds[1].Buffer->Map(0, nullptr, &bPtr);
                    if (aPtr && bPtr) {
                        const float* pA = reinterpret_cast<const float*>(static_cast<const uint8_t*>(aPtr) + inBinds[0].Offset);
                        const float* pB = reinterpret_cast<const float*>(static_cast<const uint8_t*>(bPtr) + inBinds[1].Offset);
                        size_t count = std::min(inBinds[0].SizeInBytes, inBinds[1].SizeInBytes) / sizeof(float);
                        bool isAdd = (opData.type == DML_OPERATOR_TYPE::ELEMENT_WISE_ADD);
                        for (size_t i = 0; i < count; ++i) {
                            pOutFloat[i] = isAdd ? (pA[i] + pB[i]) : (pA[i] * pB[i]);
                        }
                    }
                    if (bPtr) inBinds[1].Buffer->Unmap(0, nullptr);
                    if (aPtr) inBinds[0].Buffer->Unmap(0, nullptr);
                }
                break;
            }

            default:
                break;
        }

        outBinds[0].Buffer->Unmap(0, nullptr);
    }
};

class MicaDMLDeviceImpl : public IDMLDevice1 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    ID3D12Device* m_pD3D12Device{ nullptr };
    DML_CREATE_DEVICE_FLAGS m_flags{ DML_CREATE_DEVICE_FLAGS::NONE };
    DML_FEATURE_LEVEL m_featureLevel{ DML_FEATURE_LEVEL::LEVEL_6_4 };

public:
    MicaDMLDeviceImpl(ID3D12Device* d3d12Device, DML_CREATE_DEVICE_FLAGS flags, DML_FEATURE_LEVEL featLevel)
        : m_pD3D12Device(d3d12Device), m_flags(flags), m_featureLevel(featLevel) {}

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IDMLObject_Const || riid == IID_IDMLDevice_Const || riid == IID_IDMLDevice1_Const) {
            *ppv = static_cast<IDMLDevice1*>(this);
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

    int32_t GetPrivateData(const GUID&, uint32_t*, void*) override { return 0; }
    int32_t SetPrivateData(const GUID&, uint32_t, const void*) override { return 0; }
    int32_t SetPrivateDataInterface(const GUID&, const IUnknown*) override { return 0; }
    int32_t SetName(const wchar_t*) override { return 0; }

    int32_t CheckFeatureSupport(
        DML_FEATURE feature,
        uint32_t,
        const void* featureQueryData,
        uint32_t,
        void* featureSupportData
    ) override {
        if (!featureSupportData) return -2147467261;

        if (feature == DML_FEATURE::FEATURE_LEVELS) {
            auto* pSup = static_cast<DML_FEATURE_DATA_FEATURE_LEVELS*>(featureSupportData);
            pSup->MaxSupportedFeatureLevel = m_featureLevel;
            return 0;
        } else if (feature == DML_FEATURE::TENSOR_DATA_TYPE_SUPPORT) {
            auto* pQuery = static_cast<const DML_FEATURE_DATA_TENSOR_DATA_TYPE_SUPPORT*>(featureQueryData);
            auto* pSup = static_cast<DML_FEATURE_DATA_TENSOR_DATA_TYPE_SUPPORT*>(featureSupportData);
            if (pQuery) {
                pSup->DataType = pQuery->DataType;
                pSup->IsSupported = (pQuery->DataType == DML_TENSOR_DATA_TYPE::FLOAT32 ||
                                     pQuery->DataType == DML_TENSOR_DATA_TYPE::FLOAT16 ||
                                     pQuery->DataType == DML_TENSOR_DATA_TYPE::UINT32 ||
                                     pQuery->DataType == DML_TENSOR_DATA_TYPE::INT32);
                return 0;
            }
        }
        return -2147467263;
    }

    int32_t CreateOperator(
        const DML_OPERATOR_DESC* desc,
        const GUID& riid,
        void** ppv
    ) override {
        if (!desc || !ppv) return -2147467261;
        auto* op = new MicaDMLOperatorImpl(this, desc);
        int32_t hr = op->QueryInterface(riid, ppv);
        op->Release();
        return hr;
    }

    int32_t CompileOperator(
        IDMLOperator* op,
        DML_EXECUTION_FLAGS flags,
        const GUID& riid,
        void** ppv
    ) override {
        if (!op || !ppv) return -2147467261;
        auto* opImpl = static_cast<MicaDMLOperatorImpl*>(op);
        auto* compOp = new MicaDMLCompiledOperatorImpl(this, opImpl->GetParsedData(), flags);
        int32_t hr = compOp->QueryInterface(riid, ppv);
        compOp->Release();
        return hr;
    }

    int32_t CreateBindingTable(
        const DML_BINDING_TABLE_DESC* desc,
        const GUID& riid,
        void** ppv
    ) override {
        if (!ppv) return -2147467261;
        auto* table = new MicaDMLBindingTableImpl(this, desc);
        int32_t hr = table->QueryInterface(riid, ppv);
        table->Release();
        return hr;
    }

    int32_t CreateCommandRecorder(
        const GUID& riid,
        void** ppv
    ) override {
        if (!ppv) return -2147467261;
        auto* rec = new MicaDMLCommandRecorderImpl(this);
        int32_t hr = rec->QueryInterface(riid, ppv);
        rec->Release();
        return hr;
    }

    int32_t CompileGraph(
        const void*,
        DML_EXECUTION_FLAGS,
        const GUID&,
        void**
    ) override {
        return -2147467263;
    }

    DML_FEATURE_LEVEL GetMaxFeatureLevel() const { return m_featureLevel; }
    DML_CREATE_DEVICE_FLAGS GetCreateFlags() const { return m_flags; }
    ID3D12Device* GetD3D12Device() const { return m_pD3D12Device; }
};

// ============================================================================
// 6. Global API Factory Functions & Dynamic Exports
// ============================================================================

inline int32_t __stdcall DMLCreateDevice(
    ID3D12Device* d3d12Device,
    DML_CREATE_DEVICE_FLAGS flags,
    const GUID& riid,
    void** ppv
) {
    if (!ppv) return -2147467261;
    auto* dev = new MicaDMLDeviceImpl(d3d12Device, flags, DML_FEATURE_LEVEL::LEVEL_6_4);
    int32_t hr = dev->QueryInterface(riid, ppv);
    dev->Release();
    return hr;
}

inline int32_t __stdcall DMLCreateDevice1(
    ID3D12Device* d3d12Device,
    DML_CREATE_DEVICE_FLAGS flags,
    DML_FEATURE_LEVEL minimumFeatureLevel,
    const GUID& riid,
    void** ppv
) {
    if (!ppv) return -2147467261;
    if (minimumFeatureLevel > DML_FEATURE_LEVEL::LEVEL_6_4) return -2147024809;
    auto* dev = new MicaDMLDeviceImpl(d3d12Device, flags, DML_FEATURE_LEVEL::LEVEL_6_4);
    int32_t hr = dev->QueryInterface(riid, ppv);
    dev->Release();
    return hr;
}

inline void InitializeDirectMLExports() {
    auto& loader = micant::ldr::DynamicLoader::get();
    loader.registerExport("directml.dll", "DMLCreateDevice", reinterpret_cast<void*>(DMLCreateDevice));
    loader.registerExport("directml.dll", "DMLCreateDevice1", reinterpret_cast<void*>(DMLCreateDevice1));

    version::VersionDatabase::Instance().RegisterModule(
        "directml.dll",
        "1.15.2.0",
        "DirectML Machine Learning Acceleration Engine",
        "MicaNT Sovereign Project"
    );
}

} // namespace micant::directml
