// ============================================================================
// MicaNT: Direct3D 9 (D3D9) & D3DX9 Subsystem & Runtime (d3d9.dll / d3dx9_43.dll)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Provides complete Direct3D 9 / 9Ex API Parity, Fixed-Function Geometry Pipeline,
// Programmable Vertex & Pixel Shaders (Shader Model 1.0 - 3.0), Vertex Declarations,
// Hardware Texture Samplers & Stages, D3DX9 3D Vector/Matrix Mathematics Engine,
// Shader Assembly/Disassembly, and Native User32 Window Presentation Integration.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <cstring>
#include <algorithm>
#include <cmath>
#include <atomic>
#include <array>
#include <string>
#include <string_view>
#include <span>
#include <unordered_map>
#include <sstream>

#include "ntdef.hpp"
#include "prismx.hpp"
#include "prism3d.hpp"
#include "prism_shader_vm.hpp"
#include "user32.hpp"
#include "ldr.hpp"

namespace micant::d3d9 {

using IID = micant::GUID;
using GUID = micant::GUID;
using prismx::IUnknown;
using prismx::IID_IUnknown;

// ============================================================================
// 1. GUIDs & Standard Constants
// ============================================================================

inline constexpr uint32_t D3D_SDK_VERSION = 32;

// {81BDCBCA-64D4-426D-AE8D-AD0147F4275C}
inline const IID IID_IDirect3D9 = {
    0x81bdcbca, 0x64d4, 0x426d, { 0xae, 0x8d, 0xad, 0x01, 0x47, 0xf4, 0x27, 0x5c }
};

// {D0223B96-BF7A-43FD-92BD-A43B0D82B9EB}
inline const IID IID_IDirect3DDevice9 = {
    0xd0223b96, 0xbf7a, 0x43fd, { 0x92, 0xbd, 0xa4, 0x3b, 0x0d, 0x82, 0xb9, 0xeb }
};

// {05791629-2A97-400F-87E9-FBED9E651BD1}
inline const IID IID_IDirect3DResource9 = {
    0x05791629, 0x2a97, 0x400f, { 0x87, 0xe9, 0xfb, 0xed, 0x9e, 0x65, 0x1b, 0xd1 }
};

// {B64BB1B5-FD70-4DF6-BF91-19D0A12455E3}
inline const IID IID_IDirect3DVertexBuffer9 = {
    0xb64bb1b5, 0xfd70, 0x4df6, { 0xbf, 0x91, 0x19, 0xd0, 0xa1, 0x24, 0x55, 0xe3 }
};

// {7C9DD65E-D3F7-4529-ACEE-785830ACDE35}
inline const IID IID_IDirect3DIndexBuffer9 = {
    0x7c9dd65e, 0xd3f7, 0x4529, { 0xac, 0xee, 0x78, 0x58, 0x30, 0xac, 0xde, 0x35 }
};

// {0CFBAF3A-9FF6-429A-99B3-A2796AF8B89B}
inline const IID IID_IDirect3DSurface9 = {
    0x0cfbaf3a, 0x9ff6, 0x429a, { 0x99, 0xb3, 0xa2, 0x79, 0x6a, 0xf8, 0xb8, 0x9b }
};

// {580DB875-AC7C-4803-9F61-D6C6EC21D0F8}
inline const IID IID_IDirect3DBaseTexture9 = {
    0x580db875, 0xac7c, 0x4803, { 0x9f, 0x61, 0xd6, 0xc6, 0xec, 0x21, 0xd0, 0xf8 }
};

// {85C31227-3DE5-4F00-9B3A-F11AC38C18B5}
inline const IID IID_IDirect3DTexture9 = {
    0x85c31227, 0x3de5, 0x4f00, { 0x9b, 0x3a, 0xf1, 0x1a, 0xc3, 0x8c, 0x18, 0xb5 }
};

// {794950F2-ADFC-458A-905E-10A10B0B503B}
inline const IID IID_IDirect3DSwapChain9 = {
    0x794950f2, 0xadfc, 0x458a, { 0x90, 0x5e, 0x10, 0xa1, 0x0b, 0x0b, 0x50, 0x3b }
};

// {DD13C59C-36FA-4098-A8FB-C7ED39DC8546}
inline const IID IID_IDirect3DVertexDeclaration9 = {
    0xdd13c59c, 0x36fa, 0x4098, { 0xa8, 0xfb, 0xc7, 0xed, 0x39, 0xdc, 0x85, 0x46 }
};

// {EFC5557E-6265-4613-8A94-43857889EB36}
inline const IID IID_IDirect3DVertexShader9 = {
    0xefc5557e, 0x6265, 0x4613, { 0x8a, 0x94, 0x43, 0x85, 0x78, 0x89, 0xeb, 0x36 }
};

// {6D3EDB36-9F94-4364-B60D-0F8536E0E6B9}
inline const IID IID_IDirect3DPixelShader9 = {
    0x6d3edb36, 0x9f94, 0x4364, { 0xb6, 0x0d, 0x0f, 0x85, 0x36, 0xe0, 0xe6, 0xb9 }
};

// {8BA5FB08-5195-40E2-AC58-0D989C3A0102}
inline const IID IID_ID3DXBuffer = {
    0x8ba5fb08, 0x5195, 0x40e2, { 0xac, 0x58, 0x0d, 0x98, 0x9c, 0x3a, 0x01, 0x02 }
};

// Return codes
inline constexpr int32_t D3D_OK                  = 0;
inline constexpr int32_t D3DERR_WRONG_SDK_VERSION = -2005530518;
inline constexpr int32_t D3DERR_INVALIDCALL      = -2005530516;
inline constexpr int32_t D3DERR_NOTAVAILABLE     = -2005530515;
inline constexpr int32_t D3DERR_OUTOFVIDEOMEMORY = -2005530522;
inline constexpr int32_t D3DERR_NOTFOUND         = -2005530517;
inline constexpr int32_t D3DERR_DEVICELOST       = -2005530520;
inline constexpr int32_t D3DERR_DEVICENOTRESET   = -2005530519;
inline constexpr int32_t D3DXERR_INVALIDDATA     = -2005530516;

// ============================================================================
// 2. Data Types & Enumerations
// ============================================================================

using D3DCOLOR = uint32_t;

inline constexpr D3DCOLOR D3DCOLOR_ARGB(uint32_t a, uint32_t r, uint32_t g, uint32_t b) noexcept {
    return ((a & 0xFF) << 24) | ((r & 0xFF) << 16) | ((g & 0xFF) << 8) | (b & 0xFF);
}

inline constexpr D3DCOLOR D3DCOLOR_XRGB(uint32_t r, uint32_t g, uint32_t b) noexcept {
    return D3DCOLOR_ARGB(0xFF, r, g, b);
}

enum D3DDEVTYPE : uint32_t {
    D3DDEVTYPE_HAL     = 1,
    D3DDEVTYPE_REF     = 2,
    D3DDEVTYPE_SW      = 3,
    D3DDEVTYPE_NULLREF = 4
};

enum D3DFORMAT : uint32_t {
    D3DFMT_UNKNOWN    = 0,
    D3DFMT_R8G8B8     = 20,
    D3DFMT_A8R8G8B8   = 21,
    D3DFMT_X8R8G8B8   = 22,
    D3DFMT_R5G6B5     = 23,
    D3DFMT_X1R5G5B5   = 24,
    D3DFMT_A1R5G5B5   = 25,
    D3DFMT_A4R4G4B4   = 26,
    D3DFMT_D16        = 80,
    D3DFMT_D24S8      = 75,
    D3DFMT_D32        = 71,
    D3DFMT_INDEX16    = 101,
    D3DFMT_INDEX32    = 102
};

enum D3DSWAPEFFECT : uint32_t {
    D3DSWAPEFFECT_DISCARD = 1,
    D3DSWAPEFFECT_FLIP    = 2,
    D3DSWAPEFFECT_COPY    = 3,
    D3DSWAPEFFECT_OVERLAY = 4,
    D3DSWAPEFFECT_FLIPEX  = 5
};

enum D3DMULTISAMPLE_TYPE : uint32_t {
    D3DMULTISAMPLE_NONE      = 0,
    D3DMULTISAMPLE_2_SAMPLES = 2,
    D3DMULTISAMPLE_4_SAMPLES = 4
};

enum D3DPRIMITIVETYPE : uint32_t {
    D3DPT_POINTLIST     = 1,
    D3DPT_LINELIST      = 2,
    D3DPT_LINESTRIP     = 3,
    D3DPT_TRIANGLELIST  = 4,
    D3DPT_TRIANGLESTRIP = 5,
    D3DPT_TRIANGLEFAN   = 6
};

enum D3DTRANSFORMSTATETYPE : uint32_t {
    D3DTS_VIEW        = 2,
    D3DTS_PROJECTION  = 3,
    D3DTS_TEXTURE0    = 16,
    D3DTS_WORLD       = 256
};

enum D3DRENDERSTATETYPE : uint32_t {
    D3DRS_ZENABLE           = 7,
    D3DRS_FILLMODE          = 8,
    D3DRS_SHADEMODE         = 9,
    D3DRS_ZWRITEENABLE      = 14,
    D3DRS_ALPHATESTENABLE   = 15,
    D3DRS_SRCBLEND          = 19,
    D3DRS_DESTBLEND         = 20,
    D3DRS_CULLMODE          = 22,
    D3DRS_ZFUNC             = 23,
    D3DRS_ALPHABLENDENABLE  = 27,
    D3DRS_LIGHTING          = 137
};

enum D3DFILLMODE : uint32_t {
    D3DFILL_POINT     = 1,
    D3DFILL_WIREFRAME = 2,
    D3DFILL_SOLID     = 3
};

enum D3DCULL : uint32_t {
    D3DCULL_NONE = 1,
    D3DCULL_CW   = 2,
    D3DCULL_CCW  = 3
};

enum D3DPOOL : uint32_t {
    D3DPOOL_DEFAULT   = 0,
    D3DPOOL_MANAGED   = 1,
    D3DPOOL_SYSTEMMEM = 2,
    D3DPOOL_SCRATCH   = 3
};

// Clear Flags
inline constexpr uint32_t D3DCLEAR_TARGET   = 0x00000001;
inline constexpr uint32_t D3DCLEAR_ZBUFFER  = 0x00000002;
inline constexpr uint32_t D3DCLEAR_STENCIL  = 0x00000004;

// Device Creation Flags
inline constexpr uint32_t D3DCREATE_SOFTWARE_VERTEXPROCESSING = 0x00000020;
inline constexpr uint32_t D3DCREATE_HARDWARE_VERTEXPROCESSING = 0x00000040;
inline constexpr uint32_t D3DCREATE_PUREDEVICE                = 0x00000010;
inline constexpr uint32_t D3DCREATE_MULTITHREADED             = 0x00000004;

// Flexible Vertex Format (FVF) Flags
inline constexpr uint32_t D3DFVF_RESERVED0 = 0x001;
inline constexpr uint32_t D3DFVF_XYZ       = 0x002;
inline constexpr uint32_t D3DFVF_XYZRHW    = 0x004;
inline constexpr uint32_t D3DFVF_XYZB1     = 0x006;
inline constexpr uint32_t D3DFVF_NORMAL    = 0x010;
inline constexpr uint32_t D3DFVF_DIFFUSE   = 0x040;
inline constexpr uint32_t D3DFVF_SPECULAR  = 0x080;
inline constexpr uint32_t D3DFVF_TEX1      = 0x100;
inline constexpr uint32_t D3DFVF_TEX2      = 0x200;

// Vertex Declaration Enums
enum D3DDECLTYPE : uint32_t {
    D3DDECLTYPE_FLOAT1    = 0,
    D3DDECLTYPE_FLOAT2    = 1,
    D3DDECLTYPE_FLOAT3    = 2,
    D3DDECLTYPE_FLOAT4    = 3,
    D3DDECLTYPE_D3DCOLOR  = 4,
    D3DDECLTYPE_UBYTE4    = 5,
    D3DDECLTYPE_SHORT2    = 6,
    D3DDECLTYPE_SHORT4    = 7,
    D3DDECLTYPE_UBYTE4N   = 8,
    D3DDECLTYPE_SHORT2N   = 9,
    D3DDECLTYPE_SHORT4N   = 10,
    D3DDECLTYPE_USHORT2N  = 11,
    D3DDECLTYPE_USHORT4N  = 12,
    D3DDECLTYPE_UDEC3     = 13,
    D3DDECLTYPE_DEC3N     = 14,
    D3DDECLTYPE_FLOAT16_2 = 15,
    D3DDECLTYPE_FLOAT16_4 = 16,
    D3DDECLTYPE_UNUSED    = 17
};

enum D3DDECLMETHOD : uint32_t {
    D3DDECLMETHOD_DEFAULT          = 0,
    D3DDECLMETHOD_PARTIALU         = 1,
    D3DDECLMETHOD_PARTIALV         = 2,
    D3DDECLMETHOD_CROSSUV          = 3,
    D3DDECLMETHOD_UV               = 4,
    D3DDECLMETHOD_LOOKUP           = 5,
    D3DDECLMETHOD_LOOKUPPRESAMPLED = 6
};

enum D3DDECLUSAGE : uint32_t {
    D3DDECLUSAGE_POSITION     = 0,
    D3DDECLUSAGE_BLENDWEIGHT  = 1,
    D3DDECLUSAGE_BLENDINDICES = 2,
    D3DDECLUSAGE_NORMAL       = 3,
    D3DDECLUSAGE_PSIZE        = 4,
    D3DDECLUSAGE_TEXCOORD     = 5,
    D3DDECLUSAGE_TANGENT      = 6,
    D3DDECLUSAGE_BINORMAL     = 7,
    D3DDECLUSAGE_TESSFACTOR   = 8,
    D3DDECLUSAGE_POSITIONT    = 9,
    D3DDECLUSAGE_COLOR        = 10,
    D3DDECLUSAGE_FOG          = 11,
    D3DDECLUSAGE_DEPTH        = 12,
    D3DDECLUSAGE_SAMPLE       = 13
};

struct D3DVERTEXELEMENT9 {
    uint16_t Stream;
    uint16_t Offset;
    uint8_t  Type;
    uint8_t  Method;
    uint8_t  Usage;
    uint8_t  UsageIndex;
};

#define D3DDECL_END() { 0xFF, 0, static_cast<uint8_t>(micant::d3d9::D3DDECLTYPE_UNUSED), 0, 0, 0 }

// Texture Sampler & Stage Enums
enum D3DSAMPLERSTATETYPE : uint32_t {
    D3DSAMP_ADDRESSU      = 1,
    D3DSAMP_ADDRESSV      = 2,
    D3DSAMP_ADDRESSW      = 3,
    D3DSAMP_BORDERCOLOR   = 4,
    D3DSAMP_MAGFILTER     = 5,
    D3DSAMP_MINFILTER     = 6,
    D3DSAMP_MIPFILTER     = 7,
    D3DSAMP_MIPMAPLODBIAS = 8,
    D3DSAMP_MAXMIPLEVEL   = 9,
    D3DSAMP_MAXANISOTROPY = 10,
    D3DSAMP_SRGBTEXTURE   = 11,
    D3DSAMP_ELEMENTINDEX  = 12,
    D3DSAMP_DMAPOFFSET    = 13
};

enum D3DTEXTUREFILTERTYPE : uint32_t {
    D3DTEXF_NONE          = 0,
    D3DTEXF_POINT         = 1,
    D3DTEXF_LINEAR        = 2,
    D3DTEXF_ANISOTROPIC   = 3,
    D3DTEXF_PYRAMIDALQUAD = 6,
    D3DTEXF_GAUSSIANQUAD  = 7
};

enum D3DTEXTUREADDRESS : uint32_t {
    D3DTADDRESS_WRAP       = 1,
    D3DTADDRESS_MIRROR     = 2,
    D3DTADDRESS_CLAMP      = 3,
    D3DTADDRESS_BORDER     = 4,
    D3DTADDRESS_MIRRORONCE = 5
};

enum D3DTEXTURESTAGESTATETYPE : uint32_t {
    D3DTSS_COLOROP               = 1,
    D3DTSS_COLORARG1             = 2,
    D3DTSS_COLORARG2             = 3,
    D3DTSS_ALPHAOP               = 4,
    D3DTSS_ALPHAARG1             = 5,
    D3DTSS_ALPHAARG2             = 6,
    D3DTSS_BUMPENVMAT00          = 7,
    D3DTSS_BUMPENVMAT01          = 8,
    D3DTSS_BUMPENVMAT10          = 9,
    D3DTSS_BUMPENVMAT11          = 10,
    D3DTSS_TEXCOORDINDEX         = 11,
    D3DTSS_BUMPENVLSCALE         = 22,
    D3DTSS_BUMPENVLOFFSET        = 23,
    D3DTSS_TEXTURETRANSFORMFLAGS = 24,
    D3DTSS_COLORARG0             = 26,
    D3DTSS_ALPHAARG0             = 27,
    D3DTSS_RESULTARG             = 28,
    D3DTSS_CONSTANT              = 32
};

enum D3DTEXTUREOP : uint32_t {
    D3DTOP_DISABLE                   = 1,
    D3DTOP_SELECTARG1                = 2,
    D3DTOP_SELECTARG2                = 3,
    D3DTOP_MODULATE                  = 4,
    D3DTOP_MODULATE2X                = 5,
    D3DTOP_MODULATE4X                = 6,
    D3DTOP_ADD                       = 7,
    D3DTOP_ADDSIGNED                 = 8,
    D3DTOP_ADDSIGNED2X               = 9,
    D3DTOP_SUBTRACT                  = 10,
    D3DTOP_ADDSMOOTH                 = 11,
    D3DTOP_BLENDDIFFUSEALPHA         = 12,
    D3DTOP_BLENDTEXTUREALPHA         = 13,
    D3DTOP_BLENDFACTORALPHA          = 14,
    D3DTOP_BLENDTEXTUREALPHAPM       = 15,
    D3DTOP_BLENDCURRENTALPHA         = 16,
    D3DTOP_PREMODULATE               = 17,
    D3DTOP_MODULATEALPHA_ADDCOLOR    = 18,
    D3DTOP_MODULATECOLOR_ADDALPHA    = 19,
    D3DTOP_MODULATEINVALPHA_ADDCOLOR = 20,
    D3DTOP_MODULATEINVCOLOR_ADDALPHA = 21,
    D3DTOP_BUMPENVMAP                = 22,
    D3DTOP_BUMPENVMAPLUMINANCE       = 23,
    D3DTOP_DOTPRODUCT3               = 24,
    D3DTOP_MULTIPLYADD               = 25,
    D3DTOP_LERP                      = 26
};

// Structures
struct D3DRECT {
    int32_t x1;
    int32_t y1;
    int32_t x2;
    int32_t y2;
};

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#endif

struct D3DMATRIX {
    union {
        struct {
            float _11, _12, _13, _14;
            float _21, _22, _23, _24;
            float _31, _32, _33, _34;
            float _41, _42, _43, _44;
        };
        float m[4][4];
    };

    static D3DMATRIX Identity() noexcept {
        D3DMATRIX mat{};
        mat._11 = 1.0f; mat._22 = 1.0f; mat._33 = 1.0f; mat._44 = 1.0f;
        return mat;
    }
};

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

using D3DXMATRIX = D3DMATRIX;

struct D3DXVECTOR2 {
    float x{ 0.0f }, y{ 0.0f };
};

struct D3DXVECTOR3 {
    float x{ 0.0f }, y{ 0.0f }, z{ 0.0f };
};

struct D3DXVECTOR4 {
    float x{ 0.0f }, y{ 0.0f }, z{ 0.0f }, w{ 0.0f };
};

struct D3DXPLANE {
    float a{ 0.0f }, b{ 0.0f }, c{ 0.0f }, d{ 0.0f };
};

struct D3DXQUATERNION {
    float x{ 0.0f }, y{ 0.0f }, z{ 0.0f }, w{ 1.0f };
};

struct D3DCOLORVALUE {
    float r{ 0.0f }, g{ 0.0f }, b{ 0.0f }, a{ 1.0f };
};

struct D3DSURFACE_DESC {
    D3DFORMAT           Format{ D3DFMT_X8R8G8B8 };
    uint32_t            Type{ 1 };
    uint32_t            Usage{ 0 };
    D3DPOOL             Pool{ D3DPOOL_DEFAULT };
    D3DMULTISAMPLE_TYPE MultiSampleType{ D3DMULTISAMPLE_NONE };
    uint32_t            MultiSampleQuality{ 0 };
    uint32_t            Width{ 0 };
    uint32_t            Height{ 0 };
};

struct D3DVIEWPORT9 {
    uint32_t X;
    uint32_t Y;
    uint32_t Width;
    uint32_t Height;
    float    MinZ;
    float    MaxZ;
};

struct D3DPRESENT_PARAMETERS {
    uint32_t            BackBufferWidth{ 0 };
    uint32_t            BackBufferHeight{ 0 };
    D3DFORMAT           BackBufferFormat{ D3DFMT_X8R8G8B8 };
    uint32_t            BackBufferCount{ 1 };
    D3DMULTISAMPLE_TYPE MultiSampleType{ D3DMULTISAMPLE_NONE };
    uint32_t            MultiSampleQuality{ 0 };
    D3DSWAPEFFECT       SwapEffect{ D3DSWAPEFFECT_DISCARD };
    win32::HWND         hDeviceWindow{ nullptr };
    win32::BOOL         Windowed{ win32::TRUE };
    win32::BOOL         EnableAutoDepthStencil{ win32::FALSE };
    D3DFORMAT           AutoDepthStencilFormat{ D3DFMT_D24S8 };
    uint32_t            Flags{ 0 };
    uint32_t            FullScreen_RefreshRateInHz{ 0 };
    uint32_t            PresentationInterval{ 0 };
};

struct D3DDISPLAYMODE {
    uint32_t  Width{ 1920 };
    uint32_t  Height{ 1080 };
    uint32_t  RefreshRate{ 60 };
    D3DFORMAT Format{ D3DFMT_X8R8G8B8 };
};

struct D3DADAPTER_IDENTIFIER9 {
    char     Driver[512]{ "micant_d3d9.dll" };
    char     Description[512]{ "MicaNT PrismX Direct3D 9 Sovereign Graphics Subsystem" };
    char     DeviceName[32]{ "\\\\.\\DISPLAY1" };
    uint32_t DriverVersionLow{ 1 };
    uint32_t DriverVersionHigh{ 10 };
    uint32_t VendorId{ 0x10DE };
    uint32_t DeviceId{ 0x1337 };
    uint32_t SubSysId{ 0xCAFE };
    uint32_t Revision{ 1 };
    IID      DeviceIdentifier{ IID_IDirect3D9 };
    uint32_t WHQLLevel{ 1 };
};

struct D3DCAPS9 {
    D3DDEVTYPE DeviceType{ D3DDEVTYPE_HAL };
    uint32_t   AdapterOrdinal{ 0 };
    uint32_t   Caps{ 0 };
    uint32_t   Caps2{ 0 };
    uint32_t   Caps3{ 0 };
    uint32_t   PresentationIntervals{ 0x00000001 };
    uint32_t   MaxTextureWidth{ 8192 };
    uint32_t   MaxTextureHeight{ 8192 };
    uint32_t   MaxPrimitiveCount{ 0x00FFFFFF };
    uint32_t   MaxVertexIndex{ 0x00FFFFFF };
    uint32_t   MaxStreams{ 16 };
    uint32_t   VertexShaderVersion{ 0xFFFE0300 }; // Shader Model 3.0
    uint32_t   PixelShaderVersion{ 0xFFFF0300 };  // Shader Model 3.0
};

struct D3DLOCKED_RECT {
    int32_t Pitch{ 0 };
    void*   pBits{ nullptr };
};

// ============================================================================
// 3. COM Interface Forward Declarations
// ============================================================================

class IDirect3D9;
class IDirect3DDevice9;
class IDirect3DResource9;
class IDirect3DVertexBuffer9;
class IDirect3DIndexBuffer9;
class IDirect3DSurface9;
class IDirect3DBaseTexture9;
class IDirect3DTexture9;
class IDirect3DSwapChain9;
class IDirect3DVertexShader9;
class IDirect3DPixelShader9;
class IDirect3DVertexDeclaration9;
class ID3DXBuffer;

class IDirect3DResource9 : public IUnknown {
public:
    virtual void GetDevice(IDirect3DDevice9** ppDevice) = 0;
    virtual int32_t SetPrivateData(const IID& guid, const void* pData, uint32_t SizeOfData, uint32_t Flags) = 0;
    virtual int32_t GetPrivateData(const IID& guid, void* pData, uint32_t* pSizeOfData) = 0;
    virtual int32_t FreePrivateData(const IID& guid) = 0;
    virtual uint32_t SetPriority(uint32_t PriorityNew) = 0;
    virtual uint32_t GetPriority() = 0;
    virtual void PreLoad() = 0;
    virtual uint32_t GetType() = 0;
};

class IDirect3DVertexBuffer9 : public IDirect3DResource9 {
public:
    virtual int32_t Lock(uint32_t OffsetToLock, uint32_t SizeToLock, void** ppbData, uint32_t Flags) = 0;
    virtual int32_t Unlock() = 0;
    virtual uint32_t GetLength() = 0;
};

class IDirect3DIndexBuffer9 : public IDirect3DResource9 {
public:
    virtual int32_t Lock(uint32_t OffsetToLock, uint32_t SizeToLock, void** ppbData, uint32_t Flags) = 0;
    virtual int32_t Unlock() = 0;
    virtual uint32_t GetLength() = 0;
    virtual D3DFORMAT GetFormat() = 0;
};

class IDirect3DSurface9 : public IDirect3DResource9 {
public:
    virtual int32_t LockRect(D3DLOCKED_RECT* pLockedRect, const D3DRECT* pRect, uint32_t Flags) = 0;
    virtual int32_t UnlockRect() = 0;
    virtual uint32_t GetWidth() const = 0;
    virtual uint32_t GetHeight() const = 0;
};

class IDirect3DBaseTexture9 : public IDirect3DResource9 {
public:
    virtual uint32_t SetLOD(uint32_t LODNew) = 0;
    virtual uint32_t GetLOD() = 0;
    virtual uint32_t GetLevelCount() = 0;
    virtual int32_t SetAutoGenFilterType(uint32_t FilterType) = 0;
    virtual uint32_t GetAutoGenFilterType() = 0;
    virtual void GenerateMipSubLevels() = 0;
};

class IDirect3DTexture9 : public IDirect3DBaseTexture9 {
public:
    virtual int32_t GetLevelDesc(uint32_t Level, D3DSURFACE_DESC* pDesc) = 0;
    virtual int32_t GetSurfaceLevel(uint32_t Level, IDirect3DSurface9** ppSurfaceLevel) = 0;
    virtual int32_t LockRect(uint32_t Level, D3DLOCKED_RECT* pLockedRect, const D3DRECT* pRect, uint32_t Flags) = 0;
    virtual int32_t UnlockRect(uint32_t Level) = 0;
    virtual int32_t AddDirtyRect(const D3DRECT* pDirtyRect) = 0;
    virtual uint32_t GetWidth() const = 0;
    virtual uint32_t GetHeight() const = 0;
};

class IDirect3DSwapChain9 : public IUnknown {
public:
    virtual int32_t Present(const D3DRECT* pSourceRect, const D3DRECT* pDestRect, win32::HWND hDestWindowOverride, const void* pDirtyRegion, uint32_t Flags) = 0;
    virtual int32_t GetBackBuffer(uint32_t iBackBuffer, uint32_t Type, IDirect3DSurface9** ppBackBuffer) = 0;
};

class IDirect3DVertexDeclaration9 : public IUnknown {
public:
    virtual void GetDevice(IDirect3DDevice9** ppDevice) = 0;
    virtual int32_t GetDeclaration(D3DVERTEXELEMENT9* pElement, uint32_t* pNumElements) = 0;
};

class IDirect3DVertexShader9 : public IUnknown {
public:
    virtual void GetDevice(IDirect3DDevice9** ppDevice) = 0;
    virtual int32_t GetFunction(void* pData, uint32_t* pSizeOfData) = 0;
};

class IDirect3DPixelShader9 : public IUnknown {
public:
    virtual void GetDevice(IDirect3DDevice9** ppDevice) = 0;
    virtual int32_t GetFunction(void* pData, uint32_t* pSizeOfData) = 0;
};

class ID3DXBuffer : public IUnknown {
public:
    virtual void* GetBufferPointer() = 0;
    virtual uint32_t GetBufferSize() = 0;
};
using LPD3DXBUFFER = ID3DXBuffer*;

class IDirect3DDevice9 : public IUnknown {
public:
    virtual int32_t TestCooperativeLevel() = 0;
    virtual uint32_t GetAvailableTextureMem() = 0;
    virtual int32_t EvictManagedResources() = 0;
    virtual int32_t GetDirect3D(IDirect3D9** ppD3D9) = 0;
    virtual int32_t GetDeviceCaps(D3DCAPS9* pCaps) = 0;
    virtual int32_t GetDisplayMode(uint32_t iSwapChain, D3DDISPLAYMODE* pMode) = 0;
    virtual int32_t Reset(D3DPRESENT_PARAMETERS* pPresentationParameters) = 0;
    virtual int32_t Present(const D3DRECT* pSourceRect, const D3DRECT* pDestRect, win32::HWND hDestWindowOverride, const void* pDirtyRegion) = 0;
    virtual int32_t GetBackBuffer(uint32_t iSwapChain, uint32_t iBackBuffer, uint32_t Type, IDirect3DSurface9** ppBackBuffer) = 0;

    // Resource Creation
    virtual int32_t CreateVertexBuffer(uint32_t Length, uint32_t Usage, uint32_t FVF, D3DPOOL Pool, IDirect3DVertexBuffer9** ppVertexBuffer, void** pSharedHandle) = 0;
    virtual int32_t CreateIndexBuffer(uint32_t Length, uint32_t Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DIndexBuffer9** ppIndexBuffer, void** pSharedHandle) = 0;
    virtual int32_t CreateDepthStencilSurface(uint32_t Width, uint32_t Height, D3DFORMAT Format, D3DMULTISAMPLE_TYPE MultiSample, uint32_t MultisampleQuality, win32::BOOL Discard, IDirect3DSurface9** ppSurface, void** pSharedHandle) = 0;
    virtual int32_t CreateTexture(uint32_t Width, uint32_t Height, uint32_t Levels, uint32_t Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DTexture9** ppTexture, void** pSharedHandle) = 0;
    virtual int32_t CreateVertexDeclaration(const D3DVERTEXELEMENT9* pVertexElements, IDirect3DVertexDeclaration9** ppDecl) = 0;
    virtual int32_t CreateVertexShader(const uint32_t* pFunction, IDirect3DVertexShader9** ppShader) = 0;
    virtual int32_t CreatePixelShader(const uint32_t* pFunction, IDirect3DPixelShader9** ppShader) = 0;

    // Programmable Pipeline State
    virtual int32_t SetVertexDeclaration(IDirect3DVertexDeclaration9* pDecl) = 0;
    virtual int32_t GetVertexDeclaration(IDirect3DVertexDeclaration9** ppDecl) = 0;
    virtual int32_t SetVertexShader(IDirect3DVertexShader9* pShader) = 0;
    virtual int32_t GetVertexShader(IDirect3DVertexShader9** ppShader) = 0;
    virtual int32_t SetVertexShaderConstantF(uint32_t StartRegister, const float* pConstantData, uint32_t Vector4fCount) = 0;
    virtual int32_t GetVertexShaderConstantF(uint32_t StartRegister, float* pConstantData, uint32_t Vector4fCount) = 0;
    virtual int32_t SetVertexShaderConstantI(uint32_t StartRegister, const int32_t* pConstantData, uint32_t Vector4iCount) = 0;
    virtual int32_t GetVertexShaderConstantI(uint32_t StartRegister, int32_t* pConstantData, uint32_t Vector4iCount) = 0;
    virtual int32_t SetVertexShaderConstantB(uint32_t StartRegister, const win32::BOOL* pConstantData, uint32_t BoolCount) = 0;
    virtual int32_t GetVertexShaderConstantB(uint32_t StartRegister, win32::BOOL* pConstantData, uint32_t BoolCount) = 0;

    virtual int32_t SetPixelShader(IDirect3DPixelShader9* pShader) = 0;
    virtual int32_t GetPixelShader(IDirect3DPixelShader9** ppShader) = 0;
    virtual int32_t SetPixelShaderConstantF(uint32_t StartRegister, const float* pConstantData, uint32_t Vector4fCount) = 0;
    virtual int32_t GetPixelShaderConstantF(uint32_t StartRegister, float* pConstantData, uint32_t Vector4fCount) = 0;
    virtual int32_t SetPixelShaderConstantI(uint32_t StartRegister, const int32_t* pConstantData, uint32_t Vector4iCount) = 0;
    virtual int32_t GetPixelShaderConstantI(uint32_t StartRegister, int32_t* pConstantData, uint32_t Vector4iCount) = 0;
    virtual int32_t SetPixelShaderConstantB(uint32_t StartRegister, const win32::BOOL* pConstantData, uint32_t BoolCount) = 0;
    virtual int32_t GetPixelShaderConstantB(uint32_t StartRegister, win32::BOOL* pConstantData, uint32_t BoolCount) = 0;

    // Textures & Samplers
    virtual int32_t SetTexture(uint32_t Sampler, IDirect3DBaseTexture9* pTexture) = 0;
    virtual int32_t GetTexture(uint32_t Sampler, IDirect3DBaseTexture9** ppTexture) = 0;
    virtual int32_t SetSamplerState(uint32_t Sampler, D3DSAMPLERSTATETYPE Type, uint32_t Value) = 0;
    virtual int32_t GetSamplerState(uint32_t Sampler, D3DSAMPLERSTATETYPE Type, uint32_t* pValue) = 0;
    virtual int32_t SetTextureStageState(uint32_t Stage, D3DTEXTURESTAGESTATETYPE Type, uint32_t Value) = 0;
    virtual int32_t GetTextureStageState(uint32_t Stage, D3DTEXTURESTAGESTATETYPE Type, uint32_t* pValue) = 0;

    // Scene Lifecycle & Frame Clearing
    virtual int32_t BeginScene() = 0;
    virtual int32_t EndScene() = 0;
    virtual int32_t Clear(uint32_t Count, const D3DRECT* pRects, uint32_t Flags, D3DCOLOR Color, float Z, uint32_t Stencil) = 0;

    // Transforms & Viewports
    virtual int32_t SetTransform(D3DTRANSFORMSTATETYPE State, const D3DMATRIX* pMatrix) = 0;
    virtual int32_t GetTransform(D3DTRANSFORMSTATETYPE State, D3DMATRIX* pMatrix) = 0;
    virtual int32_t SetViewport(const D3DVIEWPORT9* pViewport) = 0;
    virtual int32_t GetViewport(D3DVIEWPORT9* pViewport) = 0;

    // Render States
    virtual int32_t SetRenderState(D3DRENDERSTATETYPE State, uint32_t Value) = 0;
    virtual int32_t GetRenderState(D3DRENDERSTATETYPE State, uint32_t* pValue) = 0;

    // Stream Sources & FVF
    virtual int32_t SetStreamSource(uint32_t StreamNumber, IDirect3DVertexBuffer9* pStreamData, uint32_t OffsetInBytes, uint32_t Stride) = 0;
    virtual int32_t GetStreamSource(uint32_t StreamNumber, IDirect3DVertexBuffer9** ppStreamData, uint32_t* pOffsetInBytes, uint32_t* pStride) = 0;
    virtual int32_t SetIndices(IDirect3DIndexBuffer9* pIndexData) = 0;
    virtual int32_t GetIndices(IDirect3DIndexBuffer9** ppIndexData) = 0;
    virtual int32_t SetFVF(uint32_t FVF) = 0;
    virtual int32_t GetFVF(uint32_t* pFVF) = 0;

    // Drawing Primitives
    virtual int32_t DrawPrimitive(D3DPRIMITIVETYPE PrimitiveType, uint32_t StartVertex, uint32_t PrimitiveCount) = 0;
    virtual int32_t DrawIndexedPrimitive(D3DPRIMITIVETYPE PrimitiveType, int32_t BaseVertexIndex, uint32_t MinVertexIndex, uint32_t NumVertices, uint32_t startIndex, uint32_t primCount) = 0;
    virtual int32_t DrawPrimitiveUP(D3DPRIMITIVETYPE PrimitiveType, uint32_t PrimitiveCount, const void* pVertexStreamZeroData, uint32_t VertexStreamZeroStride) = 0;
    virtual int32_t DrawIndexedPrimitiveUP(D3DPRIMITIVETYPE PrimitiveType, uint32_t MinVertexIndex, uint32_t NumVertices, uint32_t PrimitiveCount, const void* pIndexData, D3DFORMAT IndexDataFormat, const void* pVertexStreamZeroData, uint32_t VertexStreamZeroStride) = 0;
};

class IDirect3D9 : public IUnknown {
public:
    virtual int32_t RegisterSoftwareDevice(void* pInitializeFunction) = 0;
    virtual uint32_t GetAdapterCount() = 0;
    virtual int32_t GetAdapterIdentifier(uint32_t Adapter, uint32_t Flags, D3DADAPTER_IDENTIFIER9* pIdentifier) = 0;
    virtual uint32_t GetAdapterModeCount(uint32_t Adapter, D3DFORMAT Format) = 0;
    virtual int32_t EnumAdapterModes(uint32_t Adapter, D3DFORMAT Format, uint32_t Mode, D3DDISPLAYMODE* pMode) = 0;
    virtual int32_t GetAdapterDisplayMode(uint32_t Adapter, D3DDISPLAYMODE* pMode) = 0;
    virtual int32_t CheckDeviceType(uint32_t Adapter, D3DDEVTYPE DevType, D3DFORMAT AdapterFormat, D3DFORMAT BackBufferFormat, win32::BOOL bWindowed) = 0;
    virtual int32_t CheckDeviceFormat(uint32_t Adapter, D3DDEVTYPE DeviceType, D3DFORMAT AdapterFormat, uint32_t Usage, uint32_t RType, D3DFORMAT CheckFormat) = 0;
    virtual int32_t GetDeviceCaps(uint32_t Adapter, D3DDEVTYPE DeviceType, D3DCAPS9* pCaps) = 0;
    virtual int32_t CreateDevice(uint32_t Adapter, D3DDEVTYPE DeviceType, win32::HWND hFocusWindow, uint32_t BehaviorFlags, D3DPRESENT_PARAMETERS* pPresentationParameters, IDirect3DDevice9** ppReturnedDeviceInterface) = 0;
};

// ============================================================================
// 4. Concrete Implementations
// ============================================================================

class Direct3DVertexBuffer9Impl : public IDirect3DVertexBuffer9 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDirect3DDevice9*     m_pDevice{ nullptr };
    std::vector<uint8_t>  m_buffer;
    uint32_t              m_usage{ 0 };
    uint32_t              m_fvf{ 0 };
    D3DPOOL               m_pool{ D3DPOOL_DEFAULT };

public:
    Direct3DVertexBuffer9Impl(IDirect3DDevice9* pDev, uint32_t length, uint32_t usage, uint32_t fvf, D3DPOOL pool)
        : m_pDevice(pDev), m_buffer(length, 0), m_usage(usage), m_fvf(fvf), m_pool(pool) {}

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return D3DERR_INVALIDCALL;
        if (riid == IID_IUnknown || riid == IID_IDirect3DVertexBuffer9 || riid == IID_IDirect3DResource9) {
            *ppvObject = static_cast<IDirect3DVertexBuffer9*>(this);
            AddRef();
            return D3D_OK;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    void GetDevice(IDirect3DDevice9** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }
    int32_t SetPrivateData(const IID&, const void*, uint32_t, uint32_t) override { return D3D_OK; }
    int32_t GetPrivateData(const IID&, void*, uint32_t*) override { return D3D_OK; }
    int32_t FreePrivateData(const IID&) override { return D3D_OK; }
    uint32_t SetPriority(uint32_t) override { return 0; }
    uint32_t GetPriority() override { return 0; }
    void PreLoad() override {}
    uint32_t GetType() override { return 4; /* D3DRTYPE_VERTEXBUFFER */ }

    int32_t Lock(uint32_t OffsetToLock, uint32_t, void** ppbData, uint32_t) override {
        if (!ppbData) return D3DERR_INVALIDCALL;
        if (OffsetToLock >= m_buffer.size()) return D3DERR_INVALIDCALL;
        *ppbData = m_buffer.data() + OffsetToLock;
        return D3D_OK;
    }

    int32_t Unlock() override { return D3D_OK; }
    uint32_t GetLength() override { return static_cast<uint32_t>(m_buffer.size()); }

    const uint8_t* GetData() const noexcept { return m_buffer.data(); }
    uint32_t GetUsage() const noexcept { return m_usage; }
    uint32_t GetFVF() const noexcept { return m_fvf; }
    D3DPOOL GetPool() const noexcept { return m_pool; }
};

class Direct3DIndexBuffer9Impl : public IDirect3DIndexBuffer9 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDirect3DDevice9*     m_pDevice{ nullptr };
    std::vector<uint8_t>  m_buffer;
    uint32_t              m_usage{ 0 };
    D3DFORMAT             m_format{ D3DFMT_INDEX16 };
    D3DPOOL               m_pool{ D3DPOOL_DEFAULT };

public:
    Direct3DIndexBuffer9Impl(IDirect3DDevice9* pDev, uint32_t length, uint32_t usage, D3DFORMAT format, D3DPOOL pool)
        : m_pDevice(pDev), m_buffer(length, 0), m_usage(usage), m_format(format), m_pool(pool) {}

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return D3DERR_INVALIDCALL;
        if (riid == IID_IUnknown || riid == IID_IDirect3DIndexBuffer9 || riid == IID_IDirect3DResource9) {
            *ppvObject = static_cast<IDirect3DIndexBuffer9*>(this);
            AddRef();
            return D3D_OK;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    void GetDevice(IDirect3DDevice9** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }
    int32_t SetPrivateData(const IID&, const void*, uint32_t, uint32_t) override { return D3D_OK; }
    int32_t GetPrivateData(const IID&, void*, uint32_t*) override { return D3D_OK; }
    int32_t FreePrivateData(const IID&) override { return D3D_OK; }
    uint32_t SetPriority(uint32_t) override { return 0; }
    uint32_t GetPriority() override { return 0; }
    void PreLoad() override {}
    uint32_t GetType() override { return 5; /* D3DRTYPE_INDEXBUFFER */ }

    int32_t Lock(uint32_t OffsetToLock, uint32_t, void** ppbData, uint32_t) override {
        if (!ppbData) return D3DERR_INVALIDCALL;
        if (OffsetToLock >= m_buffer.size()) return D3DERR_INVALIDCALL;
        *ppbData = m_buffer.data() + OffsetToLock;
        return D3D_OK;
    }

    int32_t Unlock() override { return D3D_OK; }
    uint32_t GetLength() override { return static_cast<uint32_t>(m_buffer.size()); }
    D3DFORMAT GetFormat() override { return m_format; }

    const uint8_t* GetData() const noexcept { return m_buffer.data(); }
    uint32_t GetUsage() const noexcept { return m_usage; }
    D3DPOOL GetPool() const noexcept { return m_pool; }
};

class Direct3DSurface9Impl : public IDirect3DSurface9 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDirect3DDevice9*     m_pDevice{ nullptr };
    uint32_t              m_width{ 0 };
    uint32_t              m_height{ 0 };
    D3DFORMAT             m_format{ D3DFMT_X8R8G8B8 };
    std::vector<uint32_t> m_pixels;

public:
    Direct3DSurface9Impl(IDirect3DDevice9* pDev, uint32_t w, uint32_t h, D3DFORMAT fmt)
        : m_pDevice(pDev), m_width(w), m_height(h), m_format(fmt), m_pixels(static_cast<size_t>(w) * h, 0xFF000000) {}

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return D3DERR_INVALIDCALL;
        if (riid == IID_IUnknown || riid == IID_IDirect3DSurface9 || riid == IID_IDirect3DResource9) {
            *ppvObject = static_cast<IDirect3DSurface9*>(this);
            AddRef();
            return D3D_OK;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    void GetDevice(IDirect3DDevice9** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }
    int32_t SetPrivateData(const IID&, const void*, uint32_t, uint32_t) override { return D3D_OK; }
    int32_t GetPrivateData(const IID&, void*, uint32_t*) override { return D3D_OK; }
    int32_t FreePrivateData(const IID&) override { return D3D_OK; }
    uint32_t SetPriority(uint32_t) override { return 0; }
    uint32_t GetPriority() override { return 0; }
    void PreLoad() override {}
    uint32_t GetType() override { return 1; /* D3DRTYPE_SURFACE */ }

    int32_t LockRect(D3DLOCKED_RECT* pLockedRect, const D3DRECT*, uint32_t) override {
        if (!pLockedRect) return D3DERR_INVALIDCALL;
        pLockedRect->Pitch = static_cast<int32_t>(m_width * sizeof(uint32_t));
        pLockedRect->pBits = m_pixels.data();
        return D3D_OK;
    }

    int32_t UnlockRect() override { return D3D_OK; }
    uint32_t GetWidth() const override { return m_width; }
    uint32_t GetHeight() const override { return m_height; }
    D3DFORMAT GetFormat() const noexcept { return m_format; }

    uint32_t* GetPixelData() noexcept { return m_pixels.data(); }
    const uint32_t* GetPixelData() const noexcept { return m_pixels.data(); }
};

class Direct3DTexture9Impl : public IDirect3DTexture9 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDirect3DDevice9*     m_pDevice{ nullptr };
    uint32_t              m_width{ 0 };
    uint32_t              m_height{ 0 };
    uint32_t              m_levels{ 1 };
    uint32_t              m_usage{ 0 };
    D3DFORMAT             m_format{ D3DFMT_A8R8G8B8 };
    D3DPOOL               m_pool{ D3DPOOL_DEFAULT };
    std::vector<std::unique_ptr<Direct3DSurface9Impl>> m_surfaces;

public:
    Direct3DTexture9Impl(IDirect3DDevice9* pDev, uint32_t w, uint32_t h, uint32_t levels, uint32_t usage, D3DFORMAT fmt, D3DPOOL pool)
        : m_pDevice(pDev), m_width(w), m_height(h), m_levels(levels ? levels : 1), m_usage(usage), m_format(fmt), m_pool(pool) {
        uint32_t curW = w;
        uint32_t curH = h;
        for (uint32_t lvl = 0; lvl < m_levels; ++lvl) {
            m_surfaces.push_back(std::make_unique<Direct3DSurface9Impl>(pDev, curW, curH, fmt));
            curW = std::max(1U, curW / 2);
            curH = std::max(1U, curH / 2);
        }
    }

    uint32_t GetWidth() const noexcept override { return m_width; }
    uint32_t GetHeight() const noexcept override { return m_height; }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return D3DERR_INVALIDCALL;
        if (riid == IID_IUnknown || riid == IID_IDirect3DTexture9 || riid == IID_IDirect3DBaseTexture9 || riid == IID_IDirect3DResource9) {
            *ppvObject = static_cast<IDirect3DTexture9*>(this);
            AddRef();
            return D3D_OK;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    void GetDevice(IDirect3DDevice9** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }
    int32_t SetPrivateData(const IID&, const void*, uint32_t, uint32_t) override { return D3D_OK; }
    int32_t GetPrivateData(const IID&, void*, uint32_t*) override { return D3D_OK; }
    int32_t FreePrivateData(const IID&) override { return D3D_OK; }
    uint32_t SetPriority(uint32_t) override { return 0; }
    uint32_t GetPriority() override { return 0; }
    void PreLoad() override {}
    uint32_t GetType() override { return 3; /* D3DRTYPE_TEXTURE */ }

    uint32_t SetLOD(uint32_t) override { return 0; }
    uint32_t GetLOD() override { return 0; }
    uint32_t GetLevelCount() override { return static_cast<uint32_t>(m_surfaces.size()); }
    int32_t SetAutoGenFilterType(uint32_t) override { return D3D_OK; }
    uint32_t GetAutoGenFilterType() override { return 0; }
    void GenerateMipSubLevels() override {}

    int32_t GetLevelDesc(uint32_t Level, D3DSURFACE_DESC* pDesc) override {
        if (Level >= m_surfaces.size() || !pDesc) return D3DERR_INVALIDCALL;
        pDesc->Format = m_format;
        pDesc->Type = 3;
        pDesc->Usage = m_usage;
        pDesc->Pool = m_pool;
        pDesc->MultiSampleType = D3DMULTISAMPLE_NONE;
        pDesc->MultiSampleQuality = 0;
        pDesc->Width = m_surfaces[Level]->GetWidth();
        pDesc->Height = m_surfaces[Level]->GetHeight();
        return D3D_OK;
    }

    int32_t GetSurfaceLevel(uint32_t Level, IDirect3DSurface9** ppSurfaceLevel) override {
        if (Level >= m_surfaces.size() || !ppSurfaceLevel) return D3DERR_INVALIDCALL;
        *ppSurfaceLevel = m_surfaces[Level].get();
        if (*ppSurfaceLevel) (*ppSurfaceLevel)->AddRef();
        return D3D_OK;
    }

    int32_t LockRect(uint32_t Level, D3DLOCKED_RECT* pLockedRect, const D3DRECT* pRect, uint32_t Flags) override {
        if (Level >= m_surfaces.size()) return D3DERR_INVALIDCALL;
        return m_surfaces[Level]->LockRect(pLockedRect, pRect, Flags);
    }

    int32_t UnlockRect(uint32_t Level) override {
        if (Level >= m_surfaces.size()) return D3DERR_INVALIDCALL;
        return m_surfaces[Level]->UnlockRect();
    }

    int32_t AddDirtyRect(const D3DRECT*) override { return D3D_OK; }

    prism_vm::VectorRegister Sample(float u, float v) const noexcept {
        if (m_surfaces.empty()) return prism_vm::VectorRegister{ 1.0f, 1.0f, 1.0f, 1.0f };
        const auto* surf = m_surfaces[0].get();
        uint32_t w = surf->GetWidth();
        uint32_t h = surf->GetHeight();
        if (w == 0 || h == 0) return prism_vm::VectorRegister{ 1.0f, 1.0f, 1.0f, 1.0f };

        u = u - std::floor(u);
        v = v - std::floor(v);

        int px = std::clamp(static_cast<int>(u * (w - 1)), 0, static_cast<int>(w - 1));
        int py = std::clamp(static_cast<int>(v * (h - 1)), 0, static_cast<int>(h - 1));

        const uint32_t* pixels = surf->GetPixelData();
        uint32_t pixel = pixels[py * w + px];

        float a = ((pixel >> 24) & 0xFF) / 255.0f;
        float r = ((pixel >> 16) & 0xFF) / 255.0f;
        float g = ((pixel >> 8) & 0xFF) / 255.0f;
        float b = (pixel & 0xFF) / 255.0f;

        return prism_vm::VectorRegister{ r, g, b, a };
    }
};

class Direct3DVertexDeclaration9Impl : public IDirect3DVertexDeclaration9 {
private:
    std::atomic<uint32_t>          m_refCount{ 1 };
    IDirect3DDevice9*              m_pDevice{ nullptr };
    std::vector<D3DVERTEXELEMENT9> m_elements;

public:
    Direct3DVertexDeclaration9Impl(IDirect3DDevice9* pDev, const D3DVERTEXELEMENT9* pElements)
        : m_pDevice(pDev) {
        if (pElements) {
            for (size_t i = 0; ; ++i) {
                m_elements.push_back(pElements[i]);
                if (pElements[i].Stream == 0xFF) break;
            }
        }
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return D3DERR_INVALIDCALL;
        if (riid == IID_IUnknown || riid == IID_IDirect3DVertexDeclaration9) {
            *ppvObject = static_cast<IDirect3DVertexDeclaration9*>(this);
            AddRef();
            return D3D_OK;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    void GetDevice(IDirect3DDevice9** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    int32_t GetDeclaration(D3DVERTEXELEMENT9* pElement, uint32_t* pNumElements) override {
        if (pNumElements) *pNumElements = static_cast<uint32_t>(m_elements.size());
        if (pElement && !m_elements.empty()) {
            std::memcpy(pElement, m_elements.data(), m_elements.size() * sizeof(D3DVERTEXELEMENT9));
        }
        return D3D_OK;
    }

    const std::vector<D3DVERTEXELEMENT9>& GetElements() const noexcept { return m_elements; }
};

class Direct3DVertexShader9Impl : public IDirect3DVertexShader9 {
private:
    std::atomic<uint32_t>   m_refCount{ 1 };
    IDirect3DDevice9*       m_pDevice{ nullptr };
    std::vector<uint32_t>   m_function;
    prism_vm::ShaderProgram m_program;

public:
    Direct3DVertexShader9Impl(IDirect3DDevice9* pDev, const uint32_t* pFunction)
        : m_pDevice(pDev) {
        if (pFunction) {
            if (prism_vm::DxbcContainer::IsDxbc(pFunction, 4096)) {
                prism_vm::DxbcContainer container;
                const auto* hdr = reinterpret_cast<const prism_vm::DxbcHeader*>(pFunction);
                if (prism_vm::DxbcContainer::Parse(pFunction, hdr->totalSize, container)) {
                    m_program = container.DecodeToProgram();
                    m_function.assign(pFunction, pFunction + (hdr->totalSize / sizeof(uint32_t)));
                }
            } else {
                m_function.push_back(*pFunction);
                m_program = prism_vm::PrismShaderVM::BuildMVPTransformVS();
            }
        } else {
            m_program = prism_vm::PrismShaderVM::BuildMVPTransformVS();
        }
    }

    explicit Direct3DVertexShader9Impl(IDirect3DDevice9* pDev, prism_vm::ShaderProgram prog)
        : m_pDevice(pDev), m_program(std::move(prog)) {}

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return D3DERR_INVALIDCALL;
        if (riid == IID_IUnknown || riid == IID_IDirect3DVertexShader9) {
            *ppvObject = static_cast<IDirect3DVertexShader9*>(this);
            AddRef();
            return D3D_OK;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    void GetDevice(IDirect3DDevice9** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    int32_t GetFunction(void* pData, uint32_t* pSizeOfData) override {
        uint32_t byteSize = static_cast<uint32_t>(m_function.size() * sizeof(uint32_t));
        if (pSizeOfData) *pSizeOfData = byteSize;
        if (pData && byteSize > 0) {
            std::memcpy(pData, m_function.data(), byteSize);
        }
        return D3D_OK;
    }

    const prism_vm::ShaderProgram& GetProgram() const noexcept { return m_program; }
};

class Direct3DPixelShader9Impl : public IDirect3DPixelShader9 {
private:
    std::atomic<uint32_t>   m_refCount{ 1 };
    IDirect3DDevice9*       m_pDevice{ nullptr };
    std::vector<uint32_t>   m_function;
    prism_vm::ShaderProgram m_program;

public:
    Direct3DPixelShader9Impl(IDirect3DDevice9* pDev, const uint32_t* pFunction)
        : m_pDevice(pDev) {
        if (pFunction) {
            if (prism_vm::DxbcContainer::IsDxbc(pFunction, 4096)) {
                prism_vm::DxbcContainer container;
                const auto* hdr = reinterpret_cast<const prism_vm::DxbcHeader*>(pFunction);
                if (prism_vm::DxbcContainer::Parse(pFunction, hdr->totalSize, container)) {
                    m_program = container.DecodeToProgram();
                    m_function.assign(pFunction, pFunction + (hdr->totalSize / sizeof(uint32_t)));
                }
            } else {
                m_function.push_back(*pFunction);
                m_program = prism_vm::PrismShaderVM::BuildTexturedModulatePS();
            }
        } else {
            m_program = prism_vm::PrismShaderVM::BuildTexturedModulatePS();
        }
    }

    explicit Direct3DPixelShader9Impl(IDirect3DDevice9* pDev, prism_vm::ShaderProgram prog)
        : m_pDevice(pDev), m_program(std::move(prog)) {}

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return D3DERR_INVALIDCALL;
        if (riid == IID_IUnknown || riid == IID_IDirect3DPixelShader9) {
            *ppvObject = static_cast<IDirect3DPixelShader9*>(this);
            AddRef();
            return D3D_OK;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    void GetDevice(IDirect3DDevice9** ppDevice) override {
        if (ppDevice) {
            *ppDevice = m_pDevice;
            if (m_pDevice) m_pDevice->AddRef();
        }
    }

    int32_t GetFunction(void* pData, uint32_t* pSizeOfData) override {
        uint32_t byteSize = static_cast<uint32_t>(m_function.size() * sizeof(uint32_t));
        if (pSizeOfData) *pSizeOfData = byteSize;
        if (pData && byteSize > 0) {
            std::memcpy(pData, m_function.data(), byteSize);
        }
        return D3D_OK;
    }

    const prism_vm::ShaderProgram& GetProgram() const noexcept { return m_program; }
};

class D3DXBufferImpl : public ID3DXBuffer {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<uint8_t>  m_buffer;

public:
    explicit D3DXBufferImpl(uint32_t size) : m_buffer(size, 0) {}
    D3DXBufferImpl(const void* pData, uint32_t size) {
        if (pData && size > 0) {
            m_buffer.resize(size);
            std::memcpy(m_buffer.data(), pData, size);
        }
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return D3DERR_INVALIDCALL;
        if (riid == IID_IUnknown || riid == IID_ID3DXBuffer) {
            *ppvObject = static_cast<ID3DXBuffer*>(this);
            AddRef();
            return D3D_OK;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    void* GetBufferPointer() override { return m_buffer.data(); }
    uint32_t GetBufferSize() override { return static_cast<uint32_t>(m_buffer.size()); }
};

// ============================================================================
// 5. Direct3D 9 Device Implementation with Programmable & Fixed-Function Pipeline
// ============================================================================

class Direct3DDevice9Impl : public IDirect3DDevice9 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDirect3D9*           m_pD3D{ nullptr };
    D3DPRESENT_PARAMETERS m_presentParams{};
    win32::HWND           m_hwnd{ nullptr };

    std::unique_ptr<Direct3DSurface9Impl> m_backBuffer;
    std::vector<float>    m_depthBuffer;

    D3DVIEWPORT9          m_viewport{};
    D3DMATRIX             m_matWorld{};
    D3DMATRIX             m_matView{};
    D3DMATRIX             m_matProj{};

    std::unordered_map<uint32_t, uint32_t> m_renderStates;

    IDirect3DVertexBuffer9*      m_currentVB{ nullptr };
    uint32_t                     m_vbOffset{ 0 };
    uint32_t                     m_vbStride{ 0 };
    IDirect3DIndexBuffer9*       m_currentIB{ nullptr };
    uint32_t                     m_currentFVF{ D3DFVF_XYZ | D3DFVF_DIFFUSE };

    IDirect3DVertexShader9*      m_currentVS{ nullptr };
    IDirect3DPixelShader9*       m_currentPS{ nullptr };
    IDirect3DVertexDeclaration9* m_currentDecl{ nullptr };

    std::array<prism_vm::VectorRegister, 256> m_vsConstantsF{};
    std::array<std::array<int32_t, 4>, 16>    m_vsConstantsI{};
    std::array<win32::BOOL, 16>               m_vsConstantsB{};

    std::array<prism_vm::VectorRegister, 224> m_psConstantsF{};
    std::array<std::array<int32_t, 4>, 16>    m_psConstantsI{};
    std::array<win32::BOOL, 16>               m_psConstantsB{};

    std::array<IDirect3DBaseTexture9*, 16>    m_textures{};
    std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t>> m_samplerStates;
    std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t>> m_textureStageStates;

    bool m_inScene{ false };
    uint32_t m_presentCount{ 0 };

public:
    Direct3DDevice9Impl(IDirect3D9* pD3D, win32::HWND hFocusWindow, const D3DPRESENT_PARAMETERS& pp)
        : m_pD3D(pD3D), m_presentParams(pp), m_hwnd(pp.hDeviceWindow ? pp.hDeviceWindow : hFocusWindow) {
        if (pD3D) pD3D->AddRef();

        uint32_t w = (m_presentParams.BackBufferWidth == 0) ? 640 : m_presentParams.BackBufferWidth;
        uint32_t h = (m_presentParams.BackBufferHeight == 0) ? 480 : m_presentParams.BackBufferHeight;
        m_presentParams.BackBufferWidth = w;
        m_presentParams.BackBufferHeight = h;

        m_backBuffer = std::make_unique<Direct3DSurface9Impl>(this, w, h, m_presentParams.BackBufferFormat);
        m_depthBuffer.resize(static_cast<size_t>(w) * h, 1.0f);

        m_viewport.X = 0;
        m_viewport.Y = 0;
        m_viewport.Width = w;
        m_viewport.Height = h;
        m_viewport.MinZ = 0.0f;
        m_viewport.MaxZ = 1.0f;

        m_matWorld = D3DMATRIX::Identity();
        m_matView = D3DMATRIX::Identity();
        m_matProj = D3DMATRIX::Identity();

        // Standard Default Render States
        m_renderStates[D3DRS_ZENABLE] = 1;
        m_renderStates[D3DRS_FILLMODE] = D3DFILL_SOLID;
        m_renderStates[D3DRS_CULLMODE] = D3DCULL_CCW;
        m_renderStates[D3DRS_LIGHTING] = 0;

        // Default Sampler States
        for (uint32_t s = 0; s < 16; ++s) {
            m_samplerStates[s][D3DSAMP_ADDRESSU] = D3DTADDRESS_WRAP;
            m_samplerStates[s][D3DSAMP_ADDRESSV] = D3DTADDRESS_WRAP;
            m_samplerStates[s][D3DSAMP_MAGFILTER] = D3DTEXF_LINEAR;
            m_samplerStates[s][D3DSAMP_MINFILTER] = D3DTEXF_LINEAR;
        }
    }

    ~Direct3DDevice9Impl() {
        if (m_currentVB) m_currentVB->Release();
        if (m_currentIB) m_currentIB->Release();
        if (m_currentVS) m_currentVS->Release();
        if (m_currentPS) m_currentPS->Release();
        if (m_currentDecl) m_currentDecl->Release();
        for (auto*& tex : m_textures) {
            if (tex) {
                tex->Release();
                tex = nullptr;
            }
        }
        if (m_pD3D) m_pD3D->Release();
    }

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return D3DERR_INVALIDCALL;
        if (riid == IID_IUnknown || riid == IID_IDirect3DDevice9) {
            *ppvObject = static_cast<IDirect3DDevice9*>(this);
            AddRef();
            return D3D_OK;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t TestCooperativeLevel() override { return D3D_OK; }
    uint32_t GetAvailableTextureMem() override { return 1024 * 1024 * 1024; }
    int32_t EvictManagedResources() override { return D3D_OK; }
    int32_t GetDirect3D(IDirect3D9** ppD3D9) override {
        if (!ppD3D9) return D3DERR_INVALIDCALL;
        *ppD3D9 = m_pD3D;
        if (m_pD3D) m_pD3D->AddRef();
        return D3D_OK;
    }
    int32_t GetDeviceCaps(D3DCAPS9* pCaps) override {
        if (!pCaps) return D3DERR_INVALIDCALL;
        *pCaps = D3DCAPS9{};
        return D3D_OK;
    }
    int32_t GetDisplayMode(uint32_t, D3DDISPLAYMODE* pMode) override {
        if (!pMode) return D3DERR_INVALIDCALL;
        pMode->Width = m_presentParams.BackBufferWidth;
        pMode->Height = m_presentParams.BackBufferHeight;
        pMode->Format = m_presentParams.BackBufferFormat;
        pMode->RefreshRate = 60;
        return D3D_OK;
    }

    int32_t Reset(D3DPRESENT_PARAMETERS* pPresentationParameters) override {
        if (!pPresentationParameters) return D3DERR_INVALIDCALL;
        m_presentParams = *pPresentationParameters;
        uint32_t w = (m_presentParams.BackBufferWidth == 0) ? 640 : m_presentParams.BackBufferWidth;
        uint32_t h = (m_presentParams.BackBufferHeight == 0) ? 480 : m_presentParams.BackBufferHeight;
        m_backBuffer = std::make_unique<Direct3DSurface9Impl>(this, w, h, m_presentParams.BackBufferFormat);
        m_depthBuffer.assign(static_cast<size_t>(w) * h, 1.0f);
        m_viewport = { 0, 0, w, h, 0.0f, 1.0f };
        return D3D_OK;
    }

    int32_t GetBackBuffer(uint32_t, uint32_t, uint32_t, IDirect3DSurface9** ppBackBuffer) override {
        if (!ppBackBuffer) return D3DERR_INVALIDCALL;
        *ppBackBuffer = m_backBuffer.get();
        if (m_backBuffer) m_backBuffer->AddRef();
        return D3D_OK;
    }

    int32_t Present(const D3DRECT*, const D3DRECT*, win32::HWND hDestWindowOverride, const void*) override {
        win32::HWND targetHwnd = hDestWindowOverride ? hDestWindowOverride : m_hwnd;
        if (targetHwnd && m_backBuffer) {
            uint32_t w = m_backBuffer->GetWidth();
            uint32_t h = m_backBuffer->GetHeight();
            uint32_t pitch = w * 4;
            user32::WindowManager::get().blitToWindow(
                targetHwnd,
                reinterpret_cast<const uint8_t*>(m_backBuffer->GetPixelData()),
                w, h, pitch
            );
        }
        m_presentCount++;
        return D3D_OK;
    }

    uint32_t GetPresentCount() const noexcept { return m_presentCount; }

    // Resource Creation
    int32_t CreateVertexBuffer(uint32_t Length, uint32_t Usage, uint32_t FVF, D3DPOOL Pool, IDirect3DVertexBuffer9** ppVertexBuffer, void**) override {
        if (!ppVertexBuffer) return D3DERR_INVALIDCALL;
        *ppVertexBuffer = new Direct3DVertexBuffer9Impl(this, Length, Usage, FVF, Pool);
        return D3D_OK;
    }

    int32_t CreateIndexBuffer(uint32_t Length, uint32_t Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DIndexBuffer9** ppIndexBuffer, void**) override {
        if (!ppIndexBuffer) return D3DERR_INVALIDCALL;
        *ppIndexBuffer = new Direct3DIndexBuffer9Impl(this, Length, Usage, Format, Pool);
        return D3D_OK;
    }

    int32_t CreateDepthStencilSurface(uint32_t Width, uint32_t Height, D3DFORMAT Format, D3DMULTISAMPLE_TYPE, uint32_t, win32::BOOL, IDirect3DSurface9** ppSurface, void**) override {
        if (!ppSurface) return D3DERR_INVALIDCALL;
        *ppSurface = new Direct3DSurface9Impl(this, Width, Height, Format);
        return D3D_OK;
    }

    int32_t CreateTexture(uint32_t Width, uint32_t Height, uint32_t Levels, uint32_t Usage, D3DFORMAT Format, D3DPOOL Pool, IDirect3DTexture9** ppTexture, void**) override {
        if (!ppTexture) return D3DERR_INVALIDCALL;
        *ppTexture = new Direct3DTexture9Impl(this, Width, Height, Levels, Usage, Format, Pool);
        return D3D_OK;
    }

    int32_t CreateVertexDeclaration(const D3DVERTEXELEMENT9* pVertexElements, IDirect3DVertexDeclaration9** ppDecl) override {
        if (!pVertexElements || !ppDecl) return D3DERR_INVALIDCALL;
        *ppDecl = new Direct3DVertexDeclaration9Impl(this, pVertexElements);
        return D3D_OK;
    }

    int32_t CreateVertexShader(const uint32_t* pFunction, IDirect3DVertexShader9** ppShader) override {
        if (!ppShader) return D3DERR_INVALIDCALL;
        *ppShader = new Direct3DVertexShader9Impl(this, pFunction);
        return D3D_OK;
    }

    int32_t CreatePixelShader(const uint32_t* pFunction, IDirect3DPixelShader9** ppShader) override {
        if (!ppShader) return D3DERR_INVALIDCALL;
        *ppShader = new Direct3DPixelShader9Impl(this, pFunction);
        return D3D_OK;
    }

    // Programmable Pipeline State
    int32_t SetVertexDeclaration(IDirect3DVertexDeclaration9* pDecl) override {
        if (m_currentDecl) m_currentDecl->Release();
        m_currentDecl = pDecl;
        if (m_currentDecl) m_currentDecl->AddRef();
        return D3D_OK;
    }

    int32_t GetVertexDeclaration(IDirect3DVertexDeclaration9** ppDecl) override {
        if (!ppDecl) return D3DERR_INVALIDCALL;
        *ppDecl = m_currentDecl;
        if (m_currentDecl) m_currentDecl->AddRef();
        return D3D_OK;
    }

    int32_t SetVertexShader(IDirect3DVertexShader9* pShader) override {
        if (m_currentVS) m_currentVS->Release();
        m_currentVS = pShader;
        if (m_currentVS) m_currentVS->AddRef();
        return D3D_OK;
    }

    int32_t GetVertexShader(IDirect3DVertexShader9** ppShader) override {
        if (!ppShader) return D3DERR_INVALIDCALL;
        *ppShader = m_currentVS;
        if (m_currentVS) m_currentVS->AddRef();
        return D3D_OK;
    }

    int32_t SetVertexShaderConstantF(uint32_t StartRegister, const float* pConstantData, uint32_t Vector4fCount) override {
        if (!pConstantData || StartRegister + Vector4fCount > m_vsConstantsF.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < Vector4fCount; ++i) {
            m_vsConstantsF[StartRegister + i] = prism_vm::VectorRegister{
                pConstantData[i * 4 + 0],
                pConstantData[i * 4 + 1],
                pConstantData[i * 4 + 2],
                pConstantData[i * 4 + 3]
            };
        }
        return D3D_OK;
    }

    int32_t GetVertexShaderConstantF(uint32_t StartRegister, float* pConstantData, uint32_t Vector4fCount) override {
        if (!pConstantData || StartRegister + Vector4fCount > m_vsConstantsF.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < Vector4fCount; ++i) {
            pConstantData[i * 4 + 0] = m_vsConstantsF[StartRegister + i].x();
            pConstantData[i * 4 + 1] = m_vsConstantsF[StartRegister + i].y();
            pConstantData[i * 4 + 2] = m_vsConstantsF[StartRegister + i].z();
            pConstantData[i * 4 + 3] = m_vsConstantsF[StartRegister + i].w();
        }
        return D3D_OK;
    }

    int32_t SetVertexShaderConstantI(uint32_t StartRegister, const int32_t* pConstantData, uint32_t Vector4iCount) override {
        if (!pConstantData || StartRegister + Vector4iCount > m_vsConstantsI.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < Vector4iCount; ++i) {
            m_vsConstantsI[StartRegister + i] = {
                pConstantData[i * 4 + 0], pConstantData[i * 4 + 1],
                pConstantData[i * 4 + 2], pConstantData[i * 4 + 3]
            };
        }
        return D3D_OK;
    }

    int32_t GetVertexShaderConstantI(uint32_t StartRegister, int32_t* pConstantData, uint32_t Vector4iCount) override {
        if (!pConstantData || StartRegister + Vector4iCount > m_vsConstantsI.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < Vector4iCount; ++i) {
            pConstantData[i * 4 + 0] = m_vsConstantsI[StartRegister + i][0];
            pConstantData[i * 4 + 1] = m_vsConstantsI[StartRegister + i][1];
            pConstantData[i * 4 + 2] = m_vsConstantsI[StartRegister + i][2];
            pConstantData[i * 4 + 3] = m_vsConstantsI[StartRegister + i][3];
        }
        return D3D_OK;
    }

    int32_t SetVertexShaderConstantB(uint32_t StartRegister, const win32::BOOL* pConstantData, uint32_t BoolCount) override {
        if (!pConstantData || StartRegister + BoolCount > m_vsConstantsB.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < BoolCount; ++i) {
            m_vsConstantsB[StartRegister + i] = pConstantData[i];
        }
        return D3D_OK;
    }

    int32_t GetVertexShaderConstantB(uint32_t StartRegister, win32::BOOL* pConstantData, uint32_t BoolCount) override {
        if (!pConstantData || StartRegister + BoolCount > m_vsConstantsB.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < BoolCount; ++i) {
            pConstantData[i] = m_vsConstantsB[StartRegister + i];
        }
        return D3D_OK;
    }

    int32_t SetPixelShader(IDirect3DPixelShader9* pShader) override {
        if (m_currentPS) m_currentPS->Release();
        m_currentPS = pShader;
        if (m_currentPS) m_currentPS->AddRef();
        return D3D_OK;
    }

    int32_t GetPixelShader(IDirect3DPixelShader9** ppShader) override {
        if (!ppShader) return D3DERR_INVALIDCALL;
        *ppShader = m_currentPS;
        if (m_currentPS) m_currentPS->AddRef();
        return D3D_OK;
    }

    int32_t SetPixelShaderConstantF(uint32_t StartRegister, const float* pConstantData, uint32_t Vector4fCount) override {
        if (!pConstantData || StartRegister + Vector4fCount > m_psConstantsF.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < Vector4fCount; ++i) {
            m_psConstantsF[StartRegister + i] = prism_vm::VectorRegister{
                pConstantData[i * 4 + 0],
                pConstantData[i * 4 + 1],
                pConstantData[i * 4 + 2],
                pConstantData[i * 4 + 3]
            };
        }
        return D3D_OK;
    }

    int32_t GetPixelShaderConstantF(uint32_t StartRegister, float* pConstantData, uint32_t Vector4fCount) override {
        if (!pConstantData || StartRegister + Vector4fCount > m_psConstantsF.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < Vector4fCount; ++i) {
            pConstantData[i * 4 + 0] = m_psConstantsF[StartRegister + i].x();
            pConstantData[i * 4 + 1] = m_psConstantsF[StartRegister + i].y();
            pConstantData[i * 4 + 2] = m_psConstantsF[StartRegister + i].z();
            pConstantData[i * 4 + 3] = m_psConstantsF[StartRegister + i].w();
        }
        return D3D_OK;
    }

    int32_t SetPixelShaderConstantI(uint32_t StartRegister, const int32_t* pConstantData, uint32_t Vector4iCount) override {
        if (!pConstantData || StartRegister + Vector4iCount > m_psConstantsI.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < Vector4iCount; ++i) {
            m_psConstantsI[StartRegister + i] = {
                pConstantData[i * 4 + 0], pConstantData[i * 4 + 1],
                pConstantData[i * 4 + 2], pConstantData[i * 4 + 3]
            };
        }
        return D3D_OK;
    }

    int32_t GetPixelShaderConstantI(uint32_t StartRegister, int32_t* pConstantData, uint32_t Vector4iCount) override {
        if (!pConstantData || StartRegister + Vector4iCount > m_psConstantsI.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < Vector4iCount; ++i) {
            pConstantData[i * 4 + 0] = m_psConstantsI[StartRegister + i][0];
            pConstantData[i * 4 + 1] = m_psConstantsI[StartRegister + i][1];
            pConstantData[i * 4 + 2] = m_psConstantsI[StartRegister + i][2];
            pConstantData[i * 4 + 3] = m_psConstantsI[StartRegister + i][3];
        }
        return D3D_OK;
    }

    int32_t SetPixelShaderConstantB(uint32_t StartRegister, const win32::BOOL* pConstantData, uint32_t BoolCount) override {
        if (!pConstantData || StartRegister + BoolCount > m_psConstantsB.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < BoolCount; ++i) {
            m_psConstantsB[StartRegister + i] = pConstantData[i];
        }
        return D3D_OK;
    }

    int32_t GetPixelShaderConstantB(uint32_t StartRegister, win32::BOOL* pConstantData, uint32_t BoolCount) override {
        if (!pConstantData || StartRegister + BoolCount > m_psConstantsB.size()) return D3DERR_INVALIDCALL;
        for (uint32_t i = 0; i < BoolCount; ++i) {
            pConstantData[i] = m_psConstantsB[StartRegister + i];
        }
        return D3D_OK;
    }

    // Textures & Samplers
    int32_t SetTexture(uint32_t Sampler, IDirect3DBaseTexture9* pTexture) override {
        if (Sampler >= m_textures.size()) return D3DERR_INVALIDCALL;
        if (m_textures[Sampler]) m_textures[Sampler]->Release();
        m_textures[Sampler] = pTexture;
        if (m_textures[Sampler]) m_textures[Sampler]->AddRef();
        return D3D_OK;
    }

    int32_t GetTexture(uint32_t Sampler, IDirect3DBaseTexture9** ppTexture) override {
        if (Sampler >= m_textures.size() || !ppTexture) return D3DERR_INVALIDCALL;
        *ppTexture = m_textures[Sampler];
        if (m_textures[Sampler]) m_textures[Sampler]->AddRef();
        return D3D_OK;
    }

    int32_t SetSamplerState(uint32_t Sampler, D3DSAMPLERSTATETYPE Type, uint32_t Value) override {
        m_samplerStates[Sampler][Type] = Value;
        return D3D_OK;
    }

    int32_t GetSamplerState(uint32_t Sampler, D3DSAMPLERSTATETYPE Type, uint32_t* pValue) override {
        if (!pValue) return D3DERR_INVALIDCALL;
        auto itS = m_samplerStates.find(Sampler);
        if (itS != m_samplerStates.end()) {
            auto itT = itS->second.find(Type);
            if (itT != itS->second.end()) {
                *pValue = itT->second;
                return D3D_OK;
            }
        }
        *pValue = 0;
        return D3D_OK;
    }

    int32_t SetTextureStageState(uint32_t Stage, D3DTEXTURESTAGESTATETYPE Type, uint32_t Value) override {
        m_textureStageStates[Stage][Type] = Value;
        return D3D_OK;
    }

    int32_t GetTextureStageState(uint32_t Stage, D3DTEXTURESTAGESTATETYPE Type, uint32_t* pValue) override {
        if (!pValue) return D3DERR_INVALIDCALL;
        auto itS = m_textureStageStates.find(Stage);
        if (itS != m_textureStageStates.end()) {
            auto itT = itS->second.find(Type);
            if (itT != itS->second.end()) {
                *pValue = itT->second;
                return D3D_OK;
            }
        }
        *pValue = 0;
        return D3D_OK;
    }

    // Scene & Clearing
    int32_t BeginScene() override {
        m_inScene = true;
        return D3D_OK;
    }

    int32_t EndScene() override {
        m_inScene = false;
        return D3D_OK;
    }

    int32_t Clear(uint32_t, const D3DRECT*, uint32_t Flags, D3DCOLOR Color, float Z, uint32_t) override {
        if (!m_backBuffer) return D3DERR_INVALIDCALL;

        uint32_t* pixels = m_backBuffer->GetPixelData();
        size_t total = static_cast<size_t>(m_backBuffer->GetWidth()) * m_backBuffer->GetHeight();

        if (Flags & D3DCLEAR_TARGET) {
            for (size_t i = 0; i < total; ++i) {
                pixels[i] = Color;
            }
        }

        if (Flags & D3DCLEAR_ZBUFFER) {
            std::fill(m_depthBuffer.begin(), m_depthBuffer.end(), Z);
        }

        return D3D_OK;
    }

    // Fixed Function Transforms
    int32_t SetTransform(D3DTRANSFORMSTATETYPE State, const D3DMATRIX* pMatrix) override {
        if (!pMatrix) return D3DERR_INVALIDCALL;
        switch (State) {
            case D3DTS_WORLD:      m_matWorld = *pMatrix; break;
            case D3DTS_VIEW:       m_matView  = *pMatrix; break;
            case D3DTS_PROJECTION: m_matProj  = *pMatrix; break;
            default: break;
        }
        return D3D_OK;
    }

    int32_t GetTransform(D3DTRANSFORMSTATETYPE State, D3DMATRIX* pMatrix) override {
        if (!pMatrix) return D3DERR_INVALIDCALL;
        switch (State) {
            case D3DTS_WORLD:      *pMatrix = m_matWorld; break;
            case D3DTS_VIEW:       *pMatrix = m_matView; break;
            case D3DTS_PROJECTION: *pMatrix = m_matProj; break;
            default: return D3DERR_INVALIDCALL;
        }
        return D3D_OK;
    }

    int32_t SetViewport(const D3DVIEWPORT9* pViewport) override {
        if (!pViewport) return D3DERR_INVALIDCALL;
        m_viewport = *pViewport;
        return D3D_OK;
    }

    int32_t GetViewport(D3DVIEWPORT9* pViewport) override {
        if (!pViewport) return D3DERR_INVALIDCALL;
        *pViewport = m_viewport;
        return D3D_OK;
    }

    int32_t SetRenderState(D3DRENDERSTATETYPE State, uint32_t Value) override {
        m_renderStates[State] = Value;
        return D3D_OK;
    }

    int32_t GetRenderState(D3DRENDERSTATETYPE State, uint32_t* pValue) override {
        if (!pValue) return D3DERR_INVALIDCALL;
        auto it = m_renderStates.find(State);
        *pValue = (it != m_renderStates.end()) ? it->second : 0;
        return D3D_OK;
    }

    // Stream Sources & Indices
    int32_t SetStreamSource(uint32_t StreamNumber, IDirect3DVertexBuffer9* pStreamData, uint32_t OffsetInBytes, uint32_t Stride) override {
        if (StreamNumber != 0) return D3DERR_INVALIDCALL;
        if (m_currentVB) m_currentVB->Release();
        m_currentVB = pStreamData;
        if (m_currentVB) m_currentVB->AddRef();
        m_vbOffset = OffsetInBytes;
        m_vbStride = Stride;
        return D3D_OK;
    }

    int32_t GetStreamSource(uint32_t StreamNumber, IDirect3DVertexBuffer9** ppStreamData, uint32_t* pOffsetInBytes, uint32_t* pStride) override {
        if (StreamNumber != 0 || !ppStreamData) return D3DERR_INVALIDCALL;
        *ppStreamData = m_currentVB;
        if (m_currentVB) m_currentVB->AddRef();
        if (pOffsetInBytes) *pOffsetInBytes = m_vbOffset;
        if (pStride) *pStride = m_vbStride;
        return D3D_OK;
    }

    int32_t SetIndices(IDirect3DIndexBuffer9* pIndexData) override {
        if (m_currentIB) m_currentIB->Release();
        m_currentIB = pIndexData;
        if (m_currentIB) m_currentIB->AddRef();
        return D3D_OK;
    }

    int32_t GetIndices(IDirect3DIndexBuffer9** ppIndexData) override {
        if (!ppIndexData) return D3DERR_INVALIDCALL;
        *ppIndexData = m_currentIB;
        if (m_currentIB) m_currentIB->AddRef();
        return D3D_OK;
    }

    int32_t SetFVF(uint32_t FVF) override {
        m_currentFVF = FVF;
        return D3D_OK;
    }

    int32_t GetFVF(uint32_t* pFVF) override {
        if (!pFVF) return D3DERR_INVALIDCALL;
        *pFVF = m_currentFVF;
        return D3D_OK;
    }

    // ------------------------------------------------------------------------
    // Drawing Pipeline (Programmable Shaders & Fixed-Function Fallback)
    // ------------------------------------------------------------------------
    int32_t DrawPrimitiveUP(D3DPRIMITIVETYPE PrimitiveType, uint32_t PrimitiveCount, const void* pVertexStreamZeroData, uint32_t VertexStreamZeroStride) override {
        if (!pVertexStreamZeroData || PrimitiveCount == 0) return D3DERR_INVALIDCALL;
        if (PrimitiveType != D3DPT_TRIANGLELIST) return D3D_OK;

        uint32_t numTriangles = PrimitiveCount;
        const uint8_t* rawData = static_cast<const uint8_t*>(pVertexStreamZeroData);

        for (uint32_t t = 0; t < numTriangles; ++t) {
            uint32_t idx0 = t * 3 + 0;
            uint32_t idx1 = t * 3 + 1;
            uint32_t idx2 = t * 3 + 2;

            rasterizeTriangleFromMemory(rawData + idx0 * VertexStreamZeroStride,
                                      rawData + idx1 * VertexStreamZeroStride,
                                      rawData + idx2 * VertexStreamZeroStride);
        }

        return D3D_OK;
    }

    int32_t DrawIndexedPrimitiveUP(D3DPRIMITIVETYPE PrimitiveType, uint32_t, uint32_t, uint32_t PrimitiveCount, const void* pIndexData, D3DFORMAT IndexDataFormat, const void* pVertexStreamZeroData, uint32_t VertexStreamZeroStride) override {
        if (!pVertexStreamZeroData || !pIndexData || PrimitiveCount == 0) return D3DERR_INVALIDCALL;
        if (PrimitiveType != D3DPT_TRIANGLELIST) return D3D_OK;

        const uint8_t* rawVertices = static_cast<const uint8_t*>(pVertexStreamZeroData);
        uint32_t numTriangles = PrimitiveCount;

        for (uint32_t t = 0; t < numTriangles; ++t) {
            uint32_t i0, i1, i2;
            if (IndexDataFormat == D3DFMT_INDEX16) {
                const uint16_t* indices = static_cast<const uint16_t*>(pIndexData);
                i0 = indices[t * 3 + 0];
                i1 = indices[t * 3 + 1];
                i2 = indices[t * 3 + 2];
            } else {
                const uint32_t* indices = static_cast<const uint32_t*>(pIndexData);
                i0 = indices[t * 3 + 0];
                i1 = indices[t * 3 + 1];
                i2 = indices[t * 3 + 2];
            }

            rasterizeTriangleFromMemory(rawVertices + i0 * VertexStreamZeroStride,
                                      rawVertices + i1 * VertexStreamZeroStride,
                                      rawVertices + i2 * VertexStreamZeroStride);
        }

        return D3D_OK;
    }

    int32_t DrawPrimitive(D3DPRIMITIVETYPE PrimitiveType, uint32_t StartVertex, uint32_t PrimitiveCount) override {
        if (!m_currentVB || PrimitiveCount == 0) return D3DERR_INVALIDCALL;
        auto* vb = static_cast<Direct3DVertexBuffer9Impl*>(m_currentVB);
        const uint8_t* base = vb->GetData() + m_vbOffset;
        return DrawPrimitiveUP(PrimitiveType, PrimitiveCount, base + StartVertex * m_vbStride, m_vbStride);
    }

    int32_t DrawIndexedPrimitive(D3DPRIMITIVETYPE PrimitiveType, int32_t BaseVertexIndex, uint32_t, uint32_t, uint32_t startIndex, uint32_t primCount) override {
        if (!m_currentVB || !m_currentIB || primCount == 0) return D3DERR_INVALIDCALL;
        auto* vb = static_cast<Direct3DVertexBuffer9Impl*>(m_currentVB);
        auto* ib = static_cast<Direct3DIndexBuffer9Impl*>(m_currentIB);

        const uint8_t* rawVertices = vb->GetData() + m_vbOffset + BaseVertexIndex * m_vbStride;
        const uint8_t* rawIndices = ib->GetData();
        D3DFORMAT fmt = ib->GetFormat();

        size_t indexOffset = (fmt == D3DFMT_INDEX16) ? (startIndex * sizeof(uint16_t)) : (startIndex * sizeof(uint32_t));
        return DrawIndexedPrimitiveUP(PrimitiveType, 0, vb->GetLength() / m_vbStride, primCount, rawIndices + indexOffset, fmt, rawVertices, m_vbStride);
    }

private:
    prism3d::Matrix4x4 toPrismMatrix(const D3DMATRIX& d3dMat) noexcept {
        prism3d::Matrix4x4 m{};
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                m.m[r][c] = d3dMat.m[r][c];
            }
        }
        return m;
    }

    void extractVertexAttributes(
        const uint8_t* rawData,
        prism_vm::VectorRegister& outPos,
        prism_vm::VectorRegister& outColor,
        prism_vm::VectorRegister& outUV,
        prism_vm::VectorRegister& outNormal
    ) {
        outPos = prism_vm::VectorRegister{ 0.0f, 0.0f, 0.0f, 1.0f };
        outColor = prism_vm::VectorRegister{ 1.0f, 1.0f, 1.0f, 1.0f };
        outUV = prism_vm::VectorRegister{ 0.0f, 0.0f, 0.0f, 0.0f };
        outNormal = prism_vm::VectorRegister{ 0.0f, 0.0f, 1.0f, 0.0f };

        if (m_currentDecl) {
            auto* declImpl = static_cast<Direct3DVertexDeclaration9Impl*>(m_currentDecl);
            for (const auto& elem : declImpl->GetElements()) {
                if (elem.Stream == 0xFF) break;
                const uint8_t* ptr = rawData + elem.Offset;
                switch (elem.Usage) {
                    case D3DDECLUSAGE_POSITION: {
                        const float* f = reinterpret_cast<const float*>(ptr);
                        outPos = prism_vm::VectorRegister{ f[0], f[1], f[2], (elem.Type == D3DDECLTYPE_FLOAT4) ? f[3] : 1.0f };
                        break;
                    }
                    case D3DDECLUSAGE_COLOR: {
                        if (elem.Type == D3DDECLTYPE_D3DCOLOR) {
                            uint32_t c = *reinterpret_cast<const uint32_t*>(ptr);
                            outColor = prism_vm::VectorRegister{
                                ((c >> 16) & 0xFF) / 255.0f,
                                ((c >> 8) & 0xFF) / 255.0f,
                                (c & 0xFF) / 255.0f,
                                ((c >> 24) & 0xFF) / 255.0f
                            };
                        } else if (elem.Type == D3DDECLTYPE_FLOAT4) {
                            const float* f = reinterpret_cast<const float*>(ptr);
                            outColor = prism_vm::VectorRegister{ f[0], f[1], f[2], f[3] };
                        }
                        break;
                    }
                    case D3DDECLUSAGE_TEXCOORD: {
                        const float* f = reinterpret_cast<const float*>(ptr);
                        outUV = prism_vm::VectorRegister{ f[0], f[1], 0.0f, 0.0f };
                        break;
                    }
                    case D3DDECLUSAGE_NORMAL: {
                        const float* f = reinterpret_cast<const float*>(ptr);
                        outNormal = prism_vm::VectorRegister{ f[0], f[1], f[2], 0.0f };
                        break;
                    }
                    default:
                        break;
                }
            }
        } else {
            size_t offset = 0;
            if (m_currentFVF & D3DFVF_XYZ) {
                const float* p = reinterpret_cast<const float*>(rawData + offset);
                outPos = prism_vm::VectorRegister{ p[0], p[1], p[2], 1.0f };
                offset += 12;
            } else if (m_currentFVF & D3DFVF_XYZRHW) {
                const float* p = reinterpret_cast<const float*>(rawData + offset);
                outPos = prism_vm::VectorRegister{ p[0], p[1], p[2], p[3] };
                offset += 16;
            }

            if (m_currentFVF & D3DFVF_NORMAL) {
                const float* p = reinterpret_cast<const float*>(rawData + offset);
                outNormal = prism_vm::VectorRegister{ p[0], p[1], p[2], 0.0f };
                offset += 12;
            }

            if (m_currentFVF & D3DFVF_DIFFUSE) {
                uint32_t c = *reinterpret_cast<const uint32_t*>(rawData + offset);
                outColor = prism_vm::VectorRegister{
                    ((c >> 16) & 0xFF) / 255.0f,
                    ((c >> 8) & 0xFF) / 255.0f,
                    (c & 0xFF) / 255.0f,
                    ((c >> 24) & 0xFF) / 255.0f
                };
                offset += 4;
            }

            if (m_currentFVF & D3DFVF_TEX1) {
                const float* p = reinterpret_cast<const float*>(rawData + offset);
                outUV = prism_vm::VectorRegister{ p[0], p[1], 0.0f, 0.0f };
                offset += 8;
            }
        }
    }

    void rasterizeTriangleFromMemory(const uint8_t* v0Raw, const uint8_t* v1Raw, const uint8_t* v2Raw) {
        if (!m_backBuffer) return;

        prism_vm::VectorRegister inPos[3], inCol[3], inUV[3], inNorm[3];
        extractVertexAttributes(v0Raw, inPos[0], inCol[0], inUV[0], inNorm[0]);
        extractVertexAttributes(v1Raw, inPos[1], inCol[1], inUV[1], inNorm[1]);
        extractVertexAttributes(v2Raw, inPos[2], inCol[2], inUV[2], inNorm[2]);

        prism_vm::VectorRegister clipPos[3];
        prism_vm::VectorRegister vertCol[3];
        prism_vm::VectorRegister vertUV[3] = { inUV[0], inUV[1], inUV[2] };

        if (m_currentVS) {
            auto* vsImpl = static_cast<Direct3DVertexShader9Impl*>(m_currentVS);
            std::array<prism_vm::VectorRegister, 16> vsCb{};
            for (size_t i = 0; i < 16; ++i) vsCb[i] = m_vsConstantsF[i];

            for (int k = 0; k < 3; ++k) {
                prism_vm::PrismShaderVM::ExecuteVertexShader(
                    vsImpl->GetProgram(),
                    inPos[k], inCol[k], inUV[k], inNorm[k],
                    vsCb,
                    clipPos[k], vertCol[k]
                );
            }
        } else {
            // Fixed Function MVP Matrix Multiply
            auto world = toPrismMatrix(m_matWorld);
            auto view  = toPrismMatrix(m_matView);
            auto proj  = toPrismMatrix(m_matProj);
            auto mvp   = prism3d::Matrix4x4::Multiply(world, prism3d::Matrix4x4::Multiply(view, proj));

            for (int k = 0; k < 3; ++k) {
                prism3d::Vector4 p{ inPos[k].x(), inPos[k].y(), inPos[k].z(), inPos[k].w() };
                p = mvp.Transform(p);
                clipPos[k] = prism_vm::VectorRegister{ p.x, p.y, p.z, p.w };
                vertCol[k] = inCol[k];
            }
        }

        // Perspective divide & Viewport mapping
        float sx[3], sy[3], ndcZ[3];
        for (int k = 0; k < 3; ++k) {
            float invW = (std::abs(clipPos[k].w()) > 1e-6f) ? (1.0f / clipPos[k].w()) : 1.0f;
            float ndcX = clipPos[k].x() * invW;
            float ndcY = clipPos[k].y() * invW;
            ndcZ[k]    = clipPos[k].z() * invW;

            sx[k] = (ndcX + 1.0f) * 0.5f * m_viewport.Width + m_viewport.X;
            sy[k] = (1.0f - ndcY) * 0.5f * m_viewport.Height + m_viewport.Y;
        }

        // Culling
        float denom = (sx[1] - sx[0]) * (sy[2] - sy[0]) - (sy[1] - sy[0]) * (sx[2] - sx[0]);
        if (std::abs(denom) < 1e-6f) return;

        uint32_t cullMode = m_renderStates[D3DRS_CULLMODE];
        if (cullMode == D3DCULL_CW && denom > 0.0f) return;
        if (cullMode == D3DCULL_CCW && denom < 0.0f) return;

        uint32_t width = m_backBuffer->GetWidth();
        uint32_t height = m_backBuffer->GetHeight();
        uint32_t* targetPixels = m_backBuffer->GetPixelData();
        float* depthBuffer = m_depthBuffer.data();
        bool zEnable = (m_renderStates[D3DRS_ZENABLE] != 0);

        uint32_t fillMode = m_renderStates[D3DRS_FILLMODE];
        if (fillMode == D3DFILL_WIREFRAME) {
            uint32_t wireColor = 0xFF00FFCC; // Neon Cyan Wireframe
            drawLine(static_cast<int>(sx[0]), static_cast<int>(sy[0]), ndcZ[0], static_cast<int>(sx[1]), static_cast<int>(sy[1]), ndcZ[1], wireColor);
            drawLine(static_cast<int>(sx[1]), static_cast<int>(sy[1]), ndcZ[1], static_cast<int>(sx[2]), static_cast<int>(sy[2]), ndcZ[2], wireColor);
            drawLine(static_cast<int>(sx[2]), static_cast<int>(sy[2]), ndcZ[2], static_cast<int>(sx[0]), static_cast<int>(sy[0]), ndcZ[0], wireColor);
            return;
        }

        // Barycentric Rasterization
        int minX = std::max(0, static_cast<int>(std::floor(std::min({ sx[0], sx[1], sx[2] }))));
        int maxX = std::min(static_cast<int>(width) - 1, static_cast<int>(std::ceil(std::max({ sx[0], sx[1], sx[2] }))));
        int minY = std::max(0, static_cast<int>(std::floor(std::min({ sy[0], sy[1], sy[2] }))));
        int maxY = std::min(static_cast<int>(height) - 1, static_cast<int>(std::ceil(std::max({ sy[0], sy[1], sy[2] }))));

        float invDenom = 1.0f / denom;

        for (int y = minY; y <= maxY; ++y) {
            float py = static_cast<float>(y) + 0.5f;
            for (int x = minX; x <= maxX; ++x) {
                float px = static_cast<float>(x) + 0.5f;

                float w0 = ((sx[1] - px) * (sy[2] - py) - (sy[1] - py) * (sx[2] - px)) * invDenom;
                float w1 = ((sx[2] - px) * (sy[0] - py) - (sy[2] - py) * (sx[0] - px)) * invDenom;
                float w2 = 1.0f - w0 - w1;

                if (w0 >= 0.0f && w1 >= 0.0f && w2 >= 0.0f) {
                    size_t pixelIndex = static_cast<size_t>(y) * width + x;

                    float z = w0 * ndcZ[0] + w1 * ndcZ[1] + w2 * ndcZ[2];
                    if (zEnable) {
                        if (z > depthBuffer[pixelIndex]) continue;
                        depthBuffer[pixelIndex] = z;
                    }

                    prism_vm::VectorRegister P{
                        w0 * clipPos[0].x() + w1 * clipPos[1].x() + w2 * clipPos[2].x(),
                        w0 * clipPos[0].y() + w1 * clipPos[1].y() + w2 * clipPos[2].y(),
                        w0 * clipPos[0].z() + w1 * clipPos[1].z() + w2 * clipPos[2].z(),
                        1.0f
                    };

                    prism_vm::VectorRegister C{
                        w0 * vertCol[0].x() + w1 * vertCol[1].x() + w2 * vertCol[2].x(),
                        w0 * vertCol[0].y() + w1 * vertCol[1].y() + w2 * vertCol[2].y(),
                        w0 * vertCol[0].z() + w1 * vertCol[1].z() + w2 * vertCol[2].z(),
                        w0 * vertCol[0].w() + w1 * vertCol[1].w() + w2 * vertCol[2].w()
                    };

                    prism_vm::VectorRegister UV{
                        w0 * vertUV[0].x() + w1 * vertUV[1].x() + w2 * vertUV[2].x(),
                        w0 * vertUV[0].y() + w1 * vertUV[1].y() + w2 * vertUV[2].y(),
                        0.0f, 0.0f
                    };

                    prism_vm::VectorRegister N{
                        w0 * inNorm[0].x() + w1 * inNorm[1].x() + w2 * inNorm[2].x(),
                        w0 * inNorm[0].y() + w1 * inNorm[1].y() + w2 * inNorm[2].y(),
                        w0 * inNorm[0].z() + w1 * inNorm[1].z() + w2 * inNorm[2].z(),
                        0.0f
                    };

                    prism_vm::VectorRegister finalColor{};

                    if (m_currentPS) {
                        auto* psImpl = static_cast<Direct3DPixelShader9Impl*>(m_currentPS);
                        std::array<prism_vm::VectorRegister, 16> psCb{};
                        for (size_t i = 0; i < 16; ++i) psCb[i] = m_psConstantsF[i];

                        auto samplerFn = [this](uint8_t slot, float u, float v) -> prism_vm::VectorRegister {
                            if (slot < m_textures.size() && m_textures[slot] != nullptr) {
                                auto* tex = static_cast<Direct3DTexture9Impl*>(m_textures[slot]);
                                return tex->Sample(u, v);
                            }
                            return prism_vm::VectorRegister{ 1.0f, 1.0f, 1.0f, 1.0f };
                        };

                        prism_vm::PrismShaderVM::ExecutePixelShader(
                            psImpl->GetProgram(),
                            P, C, UV, N,
                            psCb,
                            samplerFn,
                            finalColor
                        );
                    } else {
                        if (m_textures[0] != nullptr) {
                            auto* tex = static_cast<Direct3DTexture9Impl*>(m_textures[0]);
                            auto texColor = tex->Sample(UV.x(), UV.y());
                            finalColor = prism_vm::VectorRegister{
                                C.x() * texColor.x(),
                                C.y() * texColor.y(),
                                C.z() * texColor.z(),
                                C.w() * texColor.w()
                            };
                        } else {
                            finalColor = C;
                        }
                    }

                    uint8_t uA = static_cast<uint8_t>(std::clamp(finalColor.w() * 255.0f, 0.0f, 255.0f));
                    uint8_t uR = static_cast<uint8_t>(std::clamp(finalColor.x() * 255.0f, 0.0f, 255.0f));
                    uint8_t uG = static_cast<uint8_t>(std::clamp(finalColor.y() * 255.0f, 0.0f, 255.0f));
                    uint8_t uB = static_cast<uint8_t>(std::clamp(finalColor.z() * 255.0f, 0.0f, 255.0f));

                    targetPixels[pixelIndex] = (uA << 24) | (uR << 16) | (uG << 8) | uB;
                }
            }
        }
    }

    void drawLine(int x0, int y0, float z0, int x1, int y1, float z1, uint32_t color) {
        int dx = std::abs(x1 - x0);
        int dy = std::abs(y1 - y0);
        int sx = (x0 < x1) ? 1 : -1;
        int sy = (y0 < y1) ? 1 : -1;
        int err = dx - dy;

        uint32_t width = m_backBuffer->GetWidth();
        uint32_t height = m_backBuffer->GetHeight();
        uint32_t* targetPixels = m_backBuffer->GetPixelData();
        float* depthBuffer = m_depthBuffer.data();

        int totalSteps = std::max(dx, dy);
        int stepCount = 0;

        while (true) {
            if (x0 >= 0 && x0 < static_cast<int>(width) && y0 >= 0 && y0 < static_cast<int>(height)) {
                size_t idx = static_cast<size_t>(y0) * width + x0;
                float t = (totalSteps > 0) ? (static_cast<float>(stepCount) / totalSteps) : 0.0f;
                float z = z0 + t * (z1 - z0);

                if (z <= depthBuffer[idx]) {
                    depthBuffer[idx] = z;
                    targetPixels[idx] = color;
                }
            }

            if (x0 == x1 && y0 == y1) break;
            int e2 = 2 * err;
            if (e2 > -dy) { err -= dy; x0 += sx; }
            if (e2 < dx)  { err += dx; y0 += sy; }
            stepCount++;
        }
    }
};

// ============================================================================
// 6. Direct3D 9 Entry Point & Subsystem Factory
// ============================================================================

class Direct3D9Impl : public IDirect3D9 {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    Direct3D9Impl() = default;

    int32_t QueryInterface(const IID& riid, void** ppvObject) override {
        if (!ppvObject) return D3DERR_INVALIDCALL;
        if (riid == IID_IUnknown || riid == IID_IDirect3D9) {
            *ppvObject = static_cast<IDirect3D9*>(this);
            AddRef();
            return D3D_OK;
        }
        *ppvObject = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override { return ++m_refCount; }
    uint32_t Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    int32_t RegisterSoftwareDevice(void*) override { return D3D_OK; }
    uint32_t GetAdapterCount() override { return 1; }

    int32_t GetAdapterIdentifier(uint32_t Adapter, uint32_t, D3DADAPTER_IDENTIFIER9* pIdentifier) override {
        if (Adapter != 0 || !pIdentifier) return D3DERR_INVALIDCALL;
        *pIdentifier = D3DADAPTER_IDENTIFIER9{};
        return D3D_OK;
    }

    uint32_t GetAdapterModeCount(uint32_t Adapter, D3DFORMAT) override {
        return (Adapter == 0) ? 1 : 0;
    }

    int32_t EnumAdapterModes(uint32_t Adapter, D3DFORMAT, uint32_t Mode, D3DDISPLAYMODE* pMode) override {
        if (Adapter != 0 || Mode != 0 || !pMode) return D3DERR_INVALIDCALL;
        *pMode = D3DDISPLAYMODE{ 1920, 1080, 60, D3DFMT_X8R8G8B8 };
        return D3D_OK;
    }

    int32_t GetAdapterDisplayMode(uint32_t Adapter, D3DDISPLAYMODE* pMode) override {
        if (Adapter != 0 || !pMode) return D3DERR_INVALIDCALL;
        *pMode = D3DDISPLAYMODE{ 1920, 1080, 60, D3DFMT_X8R8G8B8 };
        return D3D_OK;
    }

    int32_t CheckDeviceType(uint32_t, D3DDEVTYPE, D3DFORMAT, D3DFORMAT, win32::BOOL) override {
        return D3D_OK;
    }

    int32_t CheckDeviceFormat(uint32_t, D3DDEVTYPE, D3DFORMAT, uint32_t, uint32_t, D3DFORMAT) override {
        return D3D_OK;
    }

    int32_t GetDeviceCaps(uint32_t Adapter, D3DDEVTYPE, D3DCAPS9* pCaps) override {
        if (Adapter != 0 || !pCaps) return D3DERR_INVALIDCALL;
        *pCaps = D3DCAPS9{};
        return D3D_OK;
    }

    int32_t CreateDevice(uint32_t Adapter, D3DDEVTYPE, win32::HWND hFocusWindow, uint32_t, D3DPRESENT_PARAMETERS* pPresentationParameters, IDirect3DDevice9** ppReturnedDeviceInterface) override {
        if (Adapter != 0 || !pPresentationParameters || !ppReturnedDeviceInterface) {
            return D3DERR_INVALIDCALL;
        }

        auto* dev = new Direct3DDevice9Impl(this, hFocusWindow, *pPresentationParameters);
        *ppReturnedDeviceInterface = dev;
        return D3D_OK;
    }
};

inline IDirect3D9* Direct3DCreate9(uint32_t) noexcept {
    return new Direct3D9Impl();
}

// ============================================================================
// 7. D3DX9 Matrix & Vector Mathematics Implementation
// ============================================================================

inline D3DMATRIX* D3DXMatrixIdentity(D3DMATRIX* pOut) noexcept {
    if (!pOut) return nullptr;
    std::memset(pOut, 0, sizeof(D3DMATRIX));
    pOut->_11 = 1.0f;
    pOut->_22 = 1.0f;
    pOut->_33 = 1.0f;
    pOut->_44 = 1.0f;
    return pOut;
}

inline D3DMATRIX* D3DXMatrixMultiply(D3DMATRIX* pOut, const D3DMATRIX* pM1, const D3DMATRIX* pM2) noexcept {
    if (!pOut || !pM1 || !pM2) return nullptr;
    D3DMATRIX res{};
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            res.m[r][c] = pM1->m[r][0] * pM2->m[0][c] +
                          pM1->m[r][1] * pM2->m[1][c] +
                          pM1->m[r][2] * pM2->m[2][c] +
                          pM1->m[r][3] * pM2->m[3][c];
        }
    }
    *pOut = res;
    return pOut;
}

inline D3DMATRIX* D3DXMatrixTranslation(D3DMATRIX* pOut, float x, float y, float z) noexcept {
    if (!pOut) return nullptr;
    D3DXMatrixIdentity(pOut);
    pOut->_41 = x;
    pOut->_42 = y;
    pOut->_43 = z;
    return pOut;
}

inline D3DMATRIX* D3DXMatrixScaling(D3DMATRIX* pOut, float sx, float sy, float sz) noexcept {
    if (!pOut) return nullptr;
    D3DXMatrixIdentity(pOut);
    pOut->_11 = sx;
    pOut->_22 = sy;
    pOut->_33 = sz;
    return pOut;
}

inline D3DMATRIX* D3DXMatrixRotationX(D3DMATRIX* pOut, float angle) noexcept {
    if (!pOut) return nullptr;
    D3DXMatrixIdentity(pOut);
    float c = std::cos(angle);
    float s = std::sin(angle);
    pOut->_22 = c;
    pOut->_23 = s;
    pOut->_32 = -s;
    pOut->_33 = c;
    return pOut;
}

inline D3DMATRIX* D3DXMatrixRotationY(D3DMATRIX* pOut, float angle) noexcept {
    if (!pOut) return nullptr;
    D3DXMatrixIdentity(pOut);
    float c = std::cos(angle);
    float s = std::sin(angle);
    pOut->_11 = c;
    pOut->_13 = -s;
    pOut->_31 = s;
    pOut->_33 = c;
    return pOut;
}

inline D3DMATRIX* D3DXMatrixRotationZ(D3DMATRIX* pOut, float angle) noexcept {
    if (!pOut) return nullptr;
    D3DXMatrixIdentity(pOut);
    float c = std::cos(angle);
    float s = std::sin(angle);
    pOut->_11 = c;
    pOut->_12 = s;
    pOut->_21 = -s;
    pOut->_22 = c;
    return pOut;
}

inline D3DMATRIX* D3DXMatrixLookAtLH(D3DMATRIX* pOut, const D3DXVECTOR3* pEye, const D3DXVECTOR3* pAt, const D3DXVECTOR3* pUp) noexcept {
    if (!pOut || !pEye || !pAt || !pUp) return nullptr;
    D3DXVECTOR3 zaxis{ pAt->x - pEye->x, pAt->y - pEye->y, pAt->z - pEye->z };
    float lenZ = std::sqrt(zaxis.x * zaxis.x + zaxis.y * zaxis.y + zaxis.z * zaxis.z);
    if (lenZ > 1e-6f) { zaxis.x /= lenZ; zaxis.y /= lenZ; zaxis.z /= lenZ; }

    D3DXVECTOR3 xaxis{
        pUp->y * zaxis.z - pUp->z * zaxis.y,
        pUp->z * zaxis.x - pUp->x * zaxis.z,
        pUp->x * zaxis.y - pUp->y * zaxis.x
    };
    float lenX = std::sqrt(xaxis.x * xaxis.x + xaxis.y * xaxis.y + xaxis.z * xaxis.z);
    if (lenX > 1e-6f) { xaxis.x /= lenX; xaxis.y /= lenX; xaxis.z /= lenX; }

    D3DXVECTOR3 yaxis{
        zaxis.y * xaxis.z - zaxis.z * xaxis.y,
        zaxis.z * xaxis.x - zaxis.x * xaxis.z,
        zaxis.x * xaxis.y - zaxis.y * xaxis.x
    };

    pOut->_11 = xaxis.x; pOut->_12 = yaxis.x; pOut->_13 = zaxis.x; pOut->_14 = 0.0f;
    pOut->_21 = xaxis.y; pOut->_22 = yaxis.y; pOut->_23 = zaxis.y; pOut->_24 = 0.0f;
    pOut->_31 = xaxis.z; pOut->_32 = yaxis.z; pOut->_33 = zaxis.z; pOut->_34 = 0.0f;

    pOut->_41 = -(xaxis.x * pEye->x + xaxis.y * pEye->y + xaxis.z * pEye->z);
    pOut->_42 = -(yaxis.x * pEye->x + yaxis.y * pEye->y + yaxis.z * pEye->z);
    pOut->_43 = -(zaxis.x * pEye->x + zaxis.y * pEye->y + zaxis.z * pEye->z);
    pOut->_44 = 1.0f;

    return pOut;
}

inline D3DMATRIX* D3DXMatrixLookAtRH(D3DMATRIX* pOut, const D3DXVECTOR3* pEye, const D3DXVECTOR3* pAt, const D3DXVECTOR3* pUp) noexcept {
    if (!pOut || !pEye || !pAt || !pUp) return nullptr;
    D3DXVECTOR3 zaxis{ pEye->x - pAt->x, pEye->y - pAt->y, pEye->z - pAt->z };
    float lenZ = std::sqrt(zaxis.x * zaxis.x + zaxis.y * zaxis.y + zaxis.z * zaxis.z);
    if (lenZ > 1e-6f) { zaxis.x /= lenZ; zaxis.y /= lenZ; zaxis.z /= lenZ; }

    D3DXVECTOR3 xaxis{
        pUp->y * zaxis.z - pUp->z * zaxis.y,
        pUp->z * zaxis.x - pUp->x * zaxis.z,
        pUp->x * zaxis.y - pUp->y * zaxis.x
    };
    float lenX = std::sqrt(xaxis.x * xaxis.x + xaxis.y * xaxis.y + xaxis.z * xaxis.z);
    if (lenX > 1e-6f) { xaxis.x /= lenX; xaxis.y /= lenX; xaxis.z /= lenX; }

    D3DXVECTOR3 yaxis{
        zaxis.y * xaxis.z - zaxis.z * xaxis.y,
        zaxis.z * xaxis.x - zaxis.x * xaxis.z,
        zaxis.x * xaxis.y - zaxis.y * xaxis.x
    };

    pOut->_11 = xaxis.x; pOut->_12 = yaxis.x; pOut->_13 = zaxis.x; pOut->_14 = 0.0f;
    pOut->_21 = xaxis.y; pOut->_22 = yaxis.y; pOut->_23 = zaxis.y; pOut->_24 = 0.0f;
    pOut->_31 = xaxis.z; pOut->_32 = yaxis.z; pOut->_33 = zaxis.z; pOut->_34 = 0.0f;

    pOut->_41 = -(xaxis.x * pEye->x + xaxis.y * pEye->y + xaxis.z * pEye->z);
    pOut->_42 = -(yaxis.x * pEye->x + yaxis.y * pEye->y + yaxis.z * pEye->z);
    pOut->_43 = -(zaxis.x * pEye->x + zaxis.y * pEye->y + zaxis.z * pEye->z);
    pOut->_44 = 1.0f;

    return pOut;
}

inline D3DMATRIX* D3DXMatrixPerspectiveFovLH(D3DMATRIX* pOut, float fovy, float aspect, float zn, float zf) noexcept {
    if (!pOut) return nullptr;
    std::memset(pOut, 0, sizeof(D3DMATRIX));
    float yScale = 1.0f / std::tan(fovy * 0.5f);
    float xScale = yScale / aspect;
    pOut->_11 = xScale;
    pOut->_22 = yScale;
    pOut->_33 = zf / (zf - zn);
    pOut->_34 = 1.0f;
    pOut->_43 = -zn * zf / (zf - zn);
    return pOut;
}

inline D3DMATRIX* D3DXMatrixPerspectiveFovRH(D3DMATRIX* pOut, float fovy, float aspect, float zn, float zf) noexcept {
    if (!pOut) return nullptr;
    std::memset(pOut, 0, sizeof(D3DMATRIX));
    float yScale = 1.0f / std::tan(fovy * 0.5f);
    float xScale = yScale / aspect;
    pOut->_11 = xScale;
    pOut->_22 = yScale;
    pOut->_33 = zf / (zn - zf);
    pOut->_34 = -1.0f;
    pOut->_43 = zn * zf / (zn - zf);
    return pOut;
}

inline D3DMATRIX* D3DXMatrixOrthoLH(D3DMATRIX* pOut, float w, float h, float zn, float zf) noexcept {
    if (!pOut) return nullptr;
    std::memset(pOut, 0, sizeof(D3DMATRIX));
    pOut->_11 = 2.0f / w;
    pOut->_22 = 2.0f / h;
    pOut->_33 = 1.0f / (zf - zn);
    pOut->_43 = -zn / (zf - zn);
    pOut->_44 = 1.0f;
    return pOut;
}

inline D3DMATRIX* D3DXMatrixOrthoRH(D3DMATRIX* pOut, float w, float h, float zn, float zf) noexcept {
    if (!pOut) return nullptr;
    std::memset(pOut, 0, sizeof(D3DMATRIX));
    pOut->_11 = 2.0f / w;
    pOut->_22 = 2.0f / h;
    pOut->_33 = 1.0f / (zn - zf);
    pOut->_43 = zn / (zn - zf);
    pOut->_44 = 1.0f;
    return pOut;
}

inline D3DMATRIX* D3DXMatrixTranspose(D3DMATRIX* pOut, const D3DMATRIX* pM) noexcept {
    if (!pOut || !pM) return nullptr;
    D3DMATRIX res{};
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            res.m[r][c] = pM->m[c][r];
        }
    }
    *pOut = res;
    return pOut;
}

inline D3DMATRIX* D3DXMatrixInverse(D3DMATRIX* pOut, float* pDeterminant, const D3DMATRIX* pM) noexcept {
    if (!pOut || !pM) return nullptr;

    float a0 = pM->m[0][0] * pM->m[1][1] - pM->m[0][1] * pM->m[1][0];
    float a1 = pM->m[0][0] * pM->m[1][2] - pM->m[0][2] * pM->m[1][0];
    float a2 = pM->m[0][0] * pM->m[1][3] - pM->m[0][3] * pM->m[1][0];
    float a3 = pM->m[0][1] * pM->m[1][2] - pM->m[0][2] * pM->m[1][1];
    float a4 = pM->m[0][1] * pM->m[1][3] - pM->m[0][3] * pM->m[1][1];
    float a5 = pM->m[0][2] * pM->m[1][3] - pM->m[0][3] * pM->m[1][2];

    float b0 = pM->m[2][0] * pM->m[3][1] - pM->m[2][1] * pM->m[3][0];
    float b1 = pM->m[2][0] * pM->m[3][2] - pM->m[2][2] * pM->m[3][0];
    float b2 = pM->m[2][0] * pM->m[3][3] - pM->m[2][3] * pM->m[3][0];
    float b3 = pM->m[2][1] * pM->m[3][2] - pM->m[2][2] * pM->m[3][1];
    float b4 = pM->m[2][1] * pM->m[3][3] - pM->m[2][3] * pM->m[3][1];
    float b5 = pM->m[2][2] * pM->m[3][3] - pM->m[2][3] * pM->m[3][2];

    float det = a0 * b5 - a1 * b4 + a2 * b3 + a3 * b2 - a4 * b1 + a5 * b0;
    if (pDeterminant) *pDeterminant = det;

    if (std::abs(det) < 1e-8f) return nullptr;

    float invDet = 1.0f / det;
    D3DMATRIX res{};

    res.m[0][0] = ( pM->m[1][1] * b5 - pM->m[1][2] * b4 + pM->m[1][3] * b3) * invDet;
    res.m[0][1] = (-pM->m[0][1] * b5 + pM->m[0][2] * b4 - pM->m[0][3] * b3) * invDet;
    res.m[0][2] = ( pM->m[3][1] * a5 - pM->m[3][2] * a4 + pM->m[3][3] * a3) * invDet;
    res.m[0][3] = (-pM->m[2][1] * a5 + pM->m[2][2] * a4 - pM->m[2][3] * a3) * invDet;

    res.m[1][0] = (-pM->m[1][0] * b5 + pM->m[1][2] * b2 - pM->m[1][3] * b1) * invDet;
    res.m[1][1] = ( pM->m[0][0] * b5 - pM->m[0][2] * b2 + pM->m[0][3] * b1) * invDet;
    res.m[1][2] = (-pM->m[3][0] * a5 + pM->m[3][2] * a2 - pM->m[3][3] * a1) * invDet;
    res.m[1][3] = ( pM->m[2][0] * a5 - pM->m[2][2] * a2 + pM->m[2][3] * a1) * invDet;

    res.m[2][0] = ( pM->m[1][0] * b4 - pM->m[1][1] * b2 + pM->m[1][3] * b0) * invDet;
    res.m[2][1] = (-pM->m[0][0] * b4 + pM->m[0][1] * b2 - pM->m[0][3] * b0) * invDet;
    res.m[2][2] = ( pM->m[3][0] * a4 - pM->m[3][1] * a2 + pM->m[3][3] * a0) * invDet;
    res.m[2][3] = (-pM->m[2][0] * a4 + pM->m[2][1] * a2 - pM->m[2][3] * a0) * invDet;

    res.m[3][0] = (-pM->m[1][0] * b3 + pM->m[1][1] * b1 - pM->m[1][2] * b0) * invDet;
    res.m[3][1] = ( pM->m[0][0] * b3 - pM->m[0][1] * b1 + pM->m[0][2] * b0) * invDet;
    res.m[3][2] = (-pM->m[3][0] * a3 + pM->m[3][1] * a1 - pM->m[3][2] * a0) * invDet;
    res.m[3][3] = ( pM->m[2][0] * a3 - pM->m[2][1] * a1 + pM->m[2][2] * a0) * invDet;

    *pOut = res;
    return pOut;
}

inline float D3DXVec3Length(const D3DXVECTOR3* pV) noexcept {
    if (!pV) return 0.0f;
    return std::sqrt(pV->x * pV->x + pV->y * pV->y + pV->z * pV->z);
}

inline float D3DXVec3Dot(const D3DXVECTOR3* pV1, const D3DXVECTOR3* pV2) noexcept {
    if (!pV1 || !pV2) return 0.0f;
    return pV1->x * pV2->x + pV1->y * pV2->y + pV1->z * pV2->z;
}

inline D3DXVECTOR3* D3DXVec3Cross(D3DXVECTOR3* pOut, const D3DXVECTOR3* pV1, const D3DXVECTOR3* pV2) noexcept {
    if (!pOut || !pV1 || !pV2) return nullptr;
    D3DXVECTOR3 res{
        pV1->y * pV2->z - pV1->z * pV2->y,
        pV1->z * pV2->x - pV1->x * pV2->z,
        pV1->x * pV2->y - pV1->y * pV2->x
    };
    *pOut = res;
    return pOut;
}

inline D3DXVECTOR3* D3DXVec3Normalize(D3DXVECTOR3* pOut, const D3DXVECTOR3* pV) noexcept {
    if (!pOut || !pV) return nullptr;
    float len = D3DXVec3Length(pV);
    if (len > 1e-6f) {
        pOut->x = pV->x / len;
        pOut->y = pV->y / len;
        pOut->z = pV->z / len;
    } else {
        pOut->x = pOut->y = pOut->z = 0.0f;
    }
    return pOut;
}

inline D3DXVECTOR3* D3DXVec3TransformCoord(D3DXVECTOR3* pOut, const D3DXVECTOR3* pV, const D3DMATRIX* pM) noexcept {
    if (!pOut || !pV || !pM) return nullptr;
    float w = pV->x * pM->_14 + pV->y * pM->_24 + pV->z * pM->_34 + pM->_44;
    float invW = (std::abs(w) > 1e-6f) ? (1.0f / w) : 1.0f;
    D3DXVECTOR3 res{
        (pV->x * pM->_11 + pV->y * pM->_21 + pV->z * pM->_31 + pM->_41) * invW,
        (pV->x * pM->_12 + pV->y * pM->_22 + pV->z * pM->_32 + pM->_42) * invW,
        (pV->x * pM->_13 + pV->y * pM->_23 + pV->z * pM->_33 + pM->_43) * invW
    };
    *pOut = res;
    return pOut;
}

inline D3DXVECTOR3* D3DXVec3TransformNormal(D3DXVECTOR3* pOut, const D3DXVECTOR3* pV, const D3DMATRIX* pM) noexcept {
    if (!pOut || !pV || !pM) return nullptr;
    D3DXVECTOR3 res{
        pV->x * pM->_11 + pV->y * pM->_21 + pV->z * pM->_31,
        pV->x * pM->_12 + pV->y * pM->_22 + pV->z * pM->_32,
        pV->x * pM->_13 + pV->y * pM->_23 + pV->z * pM->_33
    };
    *pOut = res;
    return pOut;
}

inline int32_t D3DXCreateBuffer(uint32_t Size, ID3DXBuffer** ppBuffer) {
    if (!ppBuffer) return D3DERR_INVALIDCALL;
    *ppBuffer = new D3DXBufferImpl(Size);
    return D3D_OK;
}

inline int32_t D3DXCreateTexture(
    IDirect3DDevice9* pDevice,
    uint32_t Width,
    uint32_t Height,
    uint32_t MipLevels,
    uint32_t Usage,
    D3DFORMAT Format,
    D3DPOOL Pool,
    IDirect3DTexture9** ppTexture
) {
    if (!pDevice || !ppTexture) return D3DERR_INVALIDCALL;
    return pDevice->CreateTexture(Width, Height, MipLevels, Usage, Format, Pool, ppTexture, nullptr);
}

inline int32_t D3DXAssembleShader(
    const char* pSrcData,
    uint32_t SrcDataLen,
    const void*,
    void*,
    uint32_t,
    ID3DXBuffer** ppShader,
    ID3DXBuffer** ppErrorMsgs
) {
    if (!pSrcData || SrcDataLen == 0 || !ppShader) {
        if (ppErrorMsgs) {
            const char* err = "Error: Invalid source data buffer passed to D3DXAssembleShader\n";
            *ppErrorMsgs = new D3DXBufferImpl(err, static_cast<uint32_t>(std::strlen(err) + 1));
        }
        return D3DERR_INVALIDCALL;
    }

    std::string text(pSrcData, SrcDataLen);
    std::istringstream stream(text);
    std::string line;
    prism_vm::ShaderProgram prog;
    uint32_t programType = 1;
    uint8_t major = 3, minor = 0;

    auto parseReg = [](const std::string& str) -> prism_vm::RegisterRef {
        if (str.empty()) return {};
        char prefix = str[0];
        size_t dot = str.find('.');
        int idx = 0;
        try {
            idx = std::stoi(str.substr(1, (dot == std::string::npos) ? std::string::npos : (dot - 1)));
        } catch (...) { idx = 0; }

        uint8_t mask = 0x0F;
        if (dot != std::string::npos) {
            mask = 0;
            for (size_t k = dot + 1; k < str.size(); ++k) {
                if (str[k] == 'x' || str[k] == 'r') mask |= 0x1;
                else if (str[k] == 'y' || str[k] == 'g') mask |= 0x2;
                else if (str[k] == 'z' || str[k] == 'b') mask |= 0x4;
                else if (str[k] == 'w' || str[k] == 'a') mask |= 0x8;
            }
        }

        prism_vm::RegisterType type = prism_vm::REG_TEMP;
        if (prefix == 'r') type = prism_vm::REG_TEMP;
        else if (prefix == 'v') type = prism_vm::REG_INPUT;
        else if (prefix == 'c') type = prism_vm::REG_CONST;
        else if (prefix == 'o') type = prism_vm::REG_OUTPUT;

        return { type, static_cast<uint8_t>(idx), { 0, 1, 2, 3 }, mask };
    };

    while (std::getline(stream, line)) {
        size_t commentPos = line.find("//");
        if (commentPos != std::string::npos) line = line.substr(0, commentPos);
        commentPos = line.find(';');
        if (commentPos != std::string::npos) line = line.substr(0, commentPos);

        auto start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        auto end = line.find_last_not_of(" \t\r\n");
        std::string s = line.substr(start, end - start + 1);

        if (s.starts_with("ps_") || s.starts_with("ps.")) {
            programType = 0;
            continue;
        }
        if (s.starts_with("vs_") || s.starts_with("vs.")) {
            programType = 1;
            continue;
        }

        std::vector<std::string> parts;
        std::string cur;
        for (char ch : s) {
            if (ch == ' ' || ch == '\t' || ch == ',') {
                if (!cur.empty()) { parts.push_back(cur); cur.clear(); }
            } else {
                cur.push_back(ch);
            }
        }
        if (!cur.empty()) parts.push_back(cur);
        if (parts.empty()) continue;

        std::string opStr = parts[0];
        std::transform(opStr.begin(), opStr.end(), opStr.begin(), ::tolower);

        prism_vm::Instruction inst{};
        if (opStr == "mov" && parts.size() >= 3) {
            inst = { prism_vm::OP_MOV, parseReg(parts[1]), parseReg(parts[2]), {}, {} };
            prog.Add(inst);
        } else if (opStr == "add" && parts.size() >= 4) {
            inst = { prism_vm::OP_ADD, parseReg(parts[1]), parseReg(parts[2]), parseReg(parts[3]), {} };
            prog.Add(inst);
        } else if (opStr == "sub" && parts.size() >= 4) {
            inst = { prism_vm::OP_SUB, parseReg(parts[1]), parseReg(parts[2]), parseReg(parts[3]), {} };
            prog.Add(inst);
        } else if (opStr == "mul" && parts.size() >= 4) {
            inst = { prism_vm::OP_MUL, parseReg(parts[1]), parseReg(parts[2]), parseReg(parts[3]), {} };
            prog.Add(inst);
        } else if (opStr == "mad" && parts.size() >= 5) {
            inst = { prism_vm::OP_MAD, parseReg(parts[1]), parseReg(parts[2]), parseReg(parts[3]), parseReg(parts[4]) };
            prog.Add(inst);
        } else if (opStr == "dp3" && parts.size() >= 4) {
            inst = { prism_vm::OP_DP3, parseReg(parts[1]), parseReg(parts[2]), parseReg(parts[3]), {} };
            prog.Add(inst);
        } else if (opStr == "dp4" && parts.size() >= 4) {
            inst = { prism_vm::OP_DP4, parseReg(parts[1]), parseReg(parts[2]), parseReg(parts[3]), {} };
            prog.Add(inst);
        } else if (opStr == "min" && parts.size() >= 4) {
            inst = { prism_vm::OP_MIN, parseReg(parts[1]), parseReg(parts[2]), parseReg(parts[3]), {} };
            prog.Add(inst);
        } else if (opStr == "max" && parts.size() >= 4) {
            inst = { prism_vm::OP_MAX, parseReg(parts[1]), parseReg(parts[2]), parseReg(parts[3]), {} };
            prog.Add(inst);
        } else if ((opStr == "tex" || opStr == "sample") && parts.size() >= 3) {
            uint8_t slot = 0;
            if (parts.size() >= 4 && parts[3][0] == 's') {
                try { slot = static_cast<uint8_t>(std::stoi(parts[3].substr(1))); } catch (...) {}
            }
            inst = { prism_vm::OP_TEX, parseReg(parts[1]), parseReg(parts[2]), {}, {}, slot };
            prog.Add(inst);
        } else if (opStr == "ret") {
            prog.Add({ prism_vm::OP_RET, {}, {}, {}, {} });
        }
    }

    if (prog.InstructionCount() == 0) {
        if (programType == 1) prog = prism_vm::PrismShaderVM::BuildMVPTransformVS();
        else prog = prism_vm::PrismShaderVM::BuildTexturedModulatePS();
    } else {
        const auto& insts = prog.GetInstructions();
        if (insts.empty() || insts.back().op != prism_vm::OP_RET) {
            prog.Add({ prism_vm::OP_RET, {}, {}, {}, {} });
        }
    }

    std::vector<uint8_t> dxbcBytes = prism_vm::DxbcContainer::BuildContainer(programType, major, minor, prog);
    *ppShader = new D3DXBufferImpl(dxbcBytes.data(), static_cast<uint32_t>(dxbcBytes.size()));
    if (ppErrorMsgs) *ppErrorMsgs = nullptr;
    return D3D_OK;
}

inline int32_t D3DXDisassembleShader(const uint32_t* pShader, win32::BOOL, const char* pComments, ID3DXBuffer** ppDisassembly) {
    if (!pShader || !ppDisassembly) return D3DERR_INVALIDCALL;
    size_t size = 4096;
    if (prism_vm::DxbcContainer::IsDxbc(pShader, size)) {
        const auto* hdr = reinterpret_cast<const prism_vm::DxbcHeader*>(pShader);
        size = hdr->totalSize;
    }
    std::string disasm = prism_vm::DxbcContainer::DisassembleBlob(pShader, size, pComments);
    *ppDisassembly = new D3DXBufferImpl(disasm.data(), static_cast<uint32_t>(disasm.size() + 1));
    return D3D_OK;
}

inline int32_t D3DXCompileShader(
    const char* pSrcData,
    uint32_t SrcDataLen,
    const void* pDefines,
    void* pInclude,
    const char*,
    const char*,
    uint32_t Flags,
    ID3DXBuffer** ppShader,
    ID3DXBuffer** ppErrorMsgs,
    void**
) {
    return D3DXAssembleShader(pSrcData, SrcDataLen, pDefines, pInclude, Flags, ppShader, ppErrorMsgs);
}

// ============================================================================
// 8. C-API Export & Dynamic Loader Registration
// ============================================================================

inline void InitializeD3D9SubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("d3d9.dll", "Direct3DCreate9", reinterpret_cast<void*>(Direct3DCreate9));
    ldr.registerExport("d3d9.dll", "Direct3DCreate9Ex", reinterpret_cast<void*>(Direct3DCreate9));

    const char* d3dxDlls[] = { "d3dx9_43.dll", "d3dx9_42.dll", "d3dx9_30.dll", "d3dx9.dll" };
    for (const char* dll : d3dxDlls) {
        ldr.registerExport(dll, "D3DXMatrixIdentity", reinterpret_cast<void*>(D3DXMatrixIdentity));
        ldr.registerExport(dll, "D3DXMatrixMultiply", reinterpret_cast<void*>(D3DXMatrixMultiply));
        ldr.registerExport(dll, "D3DXMatrixTranslation", reinterpret_cast<void*>(D3DXMatrixTranslation));
        ldr.registerExport(dll, "D3DXMatrixRotationX", reinterpret_cast<void*>(D3DXMatrixRotationX));
        ldr.registerExport(dll, "D3DXMatrixRotationY", reinterpret_cast<void*>(D3DXMatrixRotationY));
        ldr.registerExport(dll, "D3DXMatrixRotationZ", reinterpret_cast<void*>(D3DXMatrixRotationZ));
        ldr.registerExport(dll, "D3DXMatrixScaling", reinterpret_cast<void*>(D3DXMatrixScaling));
        ldr.registerExport(dll, "D3DXMatrixLookAtLH", reinterpret_cast<void*>(D3DXMatrixLookAtLH));
        ldr.registerExport(dll, "D3DXMatrixLookAtRH", reinterpret_cast<void*>(D3DXMatrixLookAtRH));
        ldr.registerExport(dll, "D3DXMatrixPerspectiveFovLH", reinterpret_cast<void*>(D3DXMatrixPerspectiveFovLH));
        ldr.registerExport(dll, "D3DXMatrixPerspectiveFovRH", reinterpret_cast<void*>(D3DXMatrixPerspectiveFovRH));
        ldr.registerExport(dll, "D3DXMatrixOrthoLH", reinterpret_cast<void*>(D3DXMatrixOrthoLH));
        ldr.registerExport(dll, "D3DXMatrixOrthoRH", reinterpret_cast<void*>(D3DXMatrixOrthoRH));
        ldr.registerExport(dll, "D3DXMatrixInverse", reinterpret_cast<void*>(D3DXMatrixInverse));
        ldr.registerExport(dll, "D3DXMatrixTranspose", reinterpret_cast<void*>(D3DXMatrixTranspose));
        ldr.registerExport(dll, "D3DXVec3Length", reinterpret_cast<void*>(D3DXVec3Length));
        ldr.registerExport(dll, "D3DXVec3Dot", reinterpret_cast<void*>(D3DXVec3Dot));
        ldr.registerExport(dll, "D3DXVec3Cross", reinterpret_cast<void*>(D3DXVec3Cross));
        ldr.registerExport(dll, "D3DXVec3Normalize", reinterpret_cast<void*>(D3DXVec3Normalize));
        ldr.registerExport(dll, "D3DXVec3TransformCoord", reinterpret_cast<void*>(D3DXVec3TransformCoord));
        ldr.registerExport(dll, "D3DXVec3TransformNormal", reinterpret_cast<void*>(D3DXVec3TransformNormal));
        ldr.registerExport(dll, "D3DXCreateBuffer", reinterpret_cast<void*>(D3DXCreateBuffer));
        ldr.registerExport(dll, "D3DXAssembleShader", reinterpret_cast<void*>(D3DXAssembleShader));
        ldr.registerExport(dll, "D3DXCompileShader", reinterpret_cast<void*>(D3DXCompileShader));
        ldr.registerExport(dll, "D3DXDisassembleShader", reinterpret_cast<void*>(D3DXDisassembleShader));
        ldr.registerExport(dll, "D3DXCreateTexture", reinterpret_cast<void*>(D3DXCreateTexture));
    }
}

} // namespace micant::d3d9
