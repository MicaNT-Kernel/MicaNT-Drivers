#pragma once

/**
 * @file version.hpp
 * @brief MicaNT Windows Version Information Subsystem (version.dll) Clean-Room Implementation.
 *
 * Implements Microsoft Windows Version Management APIs:
 * - GetFileVersionInfoSizeA(), GetFileVersionInfoSizeW(): queries byte size needed for version blob.
 * - GetFileVersionInfoA(), GetFileVersionInfoW(): extracts full version data structure.
 * - VerQueryValueA(), VerQueryValueW(): parses sub-blocks including root VS_FIXEDFILEINFO,
 *   \VarFileInfo\Translation tables, and \StringFileInfo\040904B0 string tables (FileDescription,
 *   FileVersion, CompanyName, ProductName, ProductVersion, LegalCopyright, OriginalFilename).
 * - VerLanguageNameA(), VerLanguageNameW(): converts LCID / language ID to string description.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <algorithm>
#include <memory>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ldr.hpp"

namespace micant::version {

// ============================================================================
// 1. Version Constants & Fixed File Info Structure
// ============================================================================

inline constexpr uint32_t VS_FFI_SIGNATURE    = 0xFEEF04BD;
inline constexpr uint32_t VS_FFI_STRUCVERSION = 0x00010000;
inline constexpr uint32_t VS_FFI_FILEFLAGSMASK= 0x0000003F;

// File Flags
inline constexpr uint32_t VS_FF_DEBUG         = 0x00000001;
inline constexpr uint32_t VS_FF_PRERELEASE    = 0x00000002;
inline constexpr uint32_t VS_FF_PATCHED       = 0x00000004;
inline constexpr uint32_t VS_FF_PRIVATEBUILD  = 0x00000008;
inline constexpr uint32_t VS_FF_INFOINFERRED  = 0x00000010;
inline constexpr uint32_t VS_FF_SPECIALBUILD  = 0x00000020;

// Target Operating Systems
inline constexpr uint32_t VOS_UNKNOWN         = 0x00000000;
inline constexpr uint32_t VOS_DOS             = 0x00010000;
inline constexpr uint32_t VOS_NT              = 0x00040000;
inline constexpr uint32_t VOS_WINDOWS32       = 0x00000004;
inline constexpr uint32_t VOS_NT_WINDOWS32    = 0x00040004;

// File Types
inline constexpr uint32_t VFT_UNKNOWN         = 0x00000000;
inline constexpr uint32_t VFT_APP             = 0x00000001;
inline constexpr uint32_t VFT_DLL             = 0x00000002;
inline constexpr uint32_t VFT_DRV             = 0x00000003;
inline constexpr uint32_t VFT_FONT            = 0x00000004;
inline constexpr uint32_t VFT_VXD             = 0x00000005;
inline constexpr uint32_t VFT_STATIC_LIB      = 0x00000007;

#pragma pack(push, 1)

struct VS_FIXEDFILEINFO {
    uint32_t dwSignature;        // 0xFEEF04BD
    uint32_t dwStrucVersion;     // 0x00010000
    uint32_t dwFileVersionMS;    // e.g., 0x000A0000 (10.0)
    uint32_t dwFileVersionLS;    // e.g., 0x58650001 (22629.1)
    uint32_t dwProductVersionMS;
    uint32_t dwProductVersionLS;
    uint32_t dwFileFlagsMask;
    uint32_t dwFileFlags;
    uint32_t dwFileOS;           // VOS_NT_WINDOWS32
    uint32_t dwFileType;         // VFT_DLL or VFT_APP
    uint32_t dwFileSubtype;      // VFT2_UNKNOWN
    uint32_t dwFileDateMS;
    uint32_t dwFileDateLS;
};

#pragma pack(pop)

// ============================================================================
// 2. Version Resource Model & Database
// ============================================================================

struct ModuleVersionInfo {
    std::string moduleName;
    VS_FIXEDFILEINFO fixedInfo{};
    uint16_t langId{ 0x0409 }; // US English
    uint16_t codePage{ 0x04B0 }; // Unicode / 1200
    std::map<std::string, std::string> stringTable;

    // Serializes module version data into standard Win32 binary blob
    std::vector<uint8_t> BuildBinaryResource() const {
        std::vector<uint8_t> blob;
        blob.reserve(2048);

        // Header: VS_VERSIONINFO magic header & VS_FIXEDFILEINFO
        // Structure header:
        // uint16_t wLength
        // uint16_t wValueLength
        // uint16_t wType (1 = text, 0 = binary)
        // wchar_t szKey[] = L"VS_VERSION_INFO"
        // VS_FIXEDFILEINFO Value

        blob.resize(sizeof(VS_FIXEDFILEINFO) + 128, 0);
        auto* pFixed = reinterpret_cast<VS_FIXEDFILEINFO*>(blob.data() + 64);
        *pFixed = fixedInfo;

        // Append translation info
        uint32_t trans = (static_cast<uint32_t>(codePage) << 16) | langId;
        size_t transOffset = blob.size();
        blob.resize(transOffset + sizeof(uint32_t));
        *reinterpret_cast<uint32_t*>(blob.data() + transOffset) = trans;

        // Append strings in a recognizable table
        for (const auto& [k, v] : stringTable) {
            std::string entry = k + "=" + v;
            entry.push_back('\0');
            blob.insert(blob.end(), entry.begin(), entry.end());
        }

        *reinterpret_cast<uint16_t*>(blob.data()) = static_cast<uint16_t>(blob.size());
        return blob;
    }
};

class VersionDatabase {
private:
    std::map<std::string, ModuleVersionInfo> m_database;

    static std::string normalizeName(std::string_view name) {
        size_t lastSlash = name.find_last_of("/\\");
        if (lastSlash != std::string_view::npos) {
            name = name.substr(lastSlash + 1);
        }
        std::string lower;
        for (char c : name) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        return lower;
    }

    void registerModule(const ModuleVersionInfo& info) {
        m_database[normalizeName(info.moduleName)] = info;
    }

    VersionDatabase() {
        // 1. kernel32.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "kernel32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileFlagsMask = VS_FFI_FILEFLAGSMASK;
            mod.fixedInfo.dwFileFlags = 0;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows NT BASE API Client Dynamic Link Library";
            mod.stringTable["FileVersion"] = "10.0.22621.1 (WinBuild.160101.0800)";
            mod.stringTable["InternalName"] = "kernel32";
            mod.stringTable["LegalCopyright"] = "© 2026 MicaNT Sovereign Contributors.";
            mod.stringTable["OriginalFilename"] = "kernel32.dll";
            mod.stringTable["ProductName"] = "MicaNT Operating System";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // 2. user32.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "user32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileFlagsMask = VS_FFI_FILEFLAGSMASK;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Multi-User Windows USER API Client DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "user32";
            mod.stringTable["OriginalFilename"] = "user32.dll";
            mod.stringTable["ProductName"] = "MicaNT Operating System";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // 3. gdi32.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "gdi32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "GDI Client DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["OriginalFilename"] = "gdi32.dll";
            registerModule(mod);
        }

        // 4. d3d9.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "d3d9.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (9 << 16) | 29;
            mod.fixedInfo.dwFileVersionLS = (952 << 16) | 3111;
            mod.fixedInfo.dwProductVersionMS = (9 << 16) | 29;
            mod.fixedInfo.dwProductVersionLS = (952 << 16) | 3111;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT PrismX Graphics";
            mod.stringTable["FileDescription"] = "Direct3D 9 Runtime (Prism3D Accelerated)";
            mod.stringTable["FileVersion"] = "9.29.952.3111";
            mod.stringTable["InternalName"] = "d3d9";
            mod.stringTable["OriginalFilename"] = "d3d9.dll";
            mod.stringTable["ProductName"] = "DirectX 9.0c / PrismX";
            registerModule(mod);
        }

        // 5. dsound.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "dsound.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "DirectSound Audio Subsystem Dynamic Link Library";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "dsound";
            mod.stringTable["OriginalFilename"] = "dsound.dll";
            mod.stringTable["ProductName"] = "DirectX Audio / PrismAudio";
            registerModule(mod);
        }

        // 6. winmm.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "winmm.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "MCI API and MultiMedia System DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "winmm";
            mod.stringTable["OriginalFilename"] = "winmm.dll";
            mod.stringTable["ProductName"] = "MicaNT Windows Multimedia";
            registerModule(mod);
        }

        // 7. micant_kernel.exe
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "micant_kernel.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (1 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (66 << 16) | 0;
            mod.fixedInfo.dwProductVersionMS = (1 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (66 << 16) | 0;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "MicaNT Sovereign Operating System Kernel";
            mod.stringTable["FileVersion"] = "1.0.66.0";
            mod.stringTable["InternalName"] = "micant";
            mod.stringTable["OriginalFilename"] = "micant_kernel.exe";
            mod.stringTable["ProductName"] = "MicaNT Operating System";
            mod.stringTable["ProductVersion"] = "1.0.66.0";
            registerModule(mod);
        }

        // 8. opengl32.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "opengl32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "Silicon Graphics / MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "OpenGL Client DLL (PrismGL Accelerated)";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "opengl32";
            mod.stringTable["OriginalFilename"] = "opengl32.dll";
            mod.stringTable["ProductName"] = "OpenGL 1.4 / PrismGL";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // 9. glu32.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "glu32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "OpenGL Utility Library DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "glu32";
            mod.stringTable["OriginalFilename"] = "glu32.dll";
            mod.stringTable["ProductName"] = "OpenGL Utility Library";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // 10. wininet.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wininet.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (11 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (11 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Internet Extensions for Win32";
            mod.stringTable["FileVersion"] = "11.00.22621.1";
            mod.stringTable["InternalName"] = "wininet";
            mod.stringTable["OriginalFilename"] = "wininet.dll";
            mod.stringTable["ProductName"] = "MicaNT Windows Internet Subsystem";
            mod.stringTable["ProductVersion"] = "11.00.22621.1";
            registerModule(mod);
        }

        // 11. urlmon.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "urlmon.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (11 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (11 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "OLE32 Extensions for Win32 (URL Monikers)";
            mod.stringTable["FileVersion"] = "11.00.22621.1";
            mod.stringTable["InternalName"] = "urlmon";
            mod.stringTable["OriginalFilename"] = "urlmon.dll";
            mod.stringTable["ProductName"] = "MicaNT URL Moniker Subsystem";
            mod.stringTable["ProductVersion"] = "11.00.22621.1";
            registerModule(mod);
        }

        // 12. bcrypt.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "bcrypt.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Cryptographic Primitives Library";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "bcrypt";
            mod.stringTable["OriginalFilename"] = "bcrypt.dll";
            mod.stringTable["ProductName"] = "MicaNT CNG Cryptographic Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // 13. ncrypt.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "ncrypt.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Key Storage Provider Router";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "ncrypt";
            mod.stringTable["OriginalFilename"] = "ncrypt.dll";
            mod.stringTable["ProductName"] = "MicaNT Key Storage Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // 14. crypt32.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "crypt32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Crypto API32";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "crypt32";
            mod.stringTable["OriginalFilename"] = "crypt32.dll";
            mod.stringTable["ProductName"] = "MicaNT Certificate and Data Protection Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // 15. secur32.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "secur32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Security Support Provider Interface";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "secur32";
            mod.stringTable["OriginalFilename"] = "secur32.dll";
            mod.stringTable["ProductName"] = "MicaNT Security Support Provider Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // 16. sspicli.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "sspicli.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Security Support Provider Interface Client DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "sspicli";
            mod.stringTable["OriginalFilename"] = "sspicli.dll";
            mod.stringTable["ProductName"] = "MicaNT Security Support Provider Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // 17. schannel.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "schannel.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "TLS / SSL Security Provider";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "schannel";
            mod.stringTable["OriginalFilename"] = "schannel.dll";
            mod.stringTable["ProductName"] = "MicaNT Secure Channel Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // rpcrt4.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "rpcrt4.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Remote Procedure Call Runtime";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "rpcrt4";
            mod.stringTable["OriginalFilename"] = "rpcrt4.dll";
            mod.stringTable["ProductName"] = "MicaNT Remote Procedure Call Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // ole32.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "ole32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft OLE for Windows";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "ole32";
            mod.stringTable["OriginalFilename"] = "ole32.dll";
            mod.stringTable["ProductName"] = "MicaNT Component Object Model Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // oleaut32.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "oleaut32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "OLE Automation Client DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "oleaut32";
            mod.stringTable["OriginalFilename"] = "oleaut32.dll";
            mod.stringTable["ProductName"] = "MicaNT OLE Automation Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // setupapi.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "setupapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Setup API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "setupapi";
            mod.stringTable["OriginalFilename"] = "setupapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Device Installation Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wevtapi.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wevtapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Event Log API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wevtapi";
            mod.stringTable["OriginalFilename"] = "wevtapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Event Log Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wbemprox.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wbemprox.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "WMI Administrative Tool";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wbemprox";
            mod.stringTable["OriginalFilename"] = "wbemprox.dll";
            mod.stringTable["ProductName"] = "MicaNT WMI Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // fastprox.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "fastprox.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "WMI Custom Marshaler";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "fastprox";
            mod.stringTable["OriginalFilename"] = "fastprox.dll";
            mod.stringTable["ProductName"] = "MicaNT WMI Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // taskschd.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "taskschd.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Task Scheduler 2.0 Engine";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "taskschd";
            mod.stringTable["OriginalFilename"] = "taskschd.dll";
            mod.stringTable["ProductName"] = "MicaNT Task Scheduler Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // mstask.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "mstask.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Task Scheduler 1.0 Legacy Bridge";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "mstask";
            mod.stringTable["OriginalFilename"] = "mstask.dll";
            mod.stringTable["ProductName"] = "MicaNT Task Scheduler Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // qmgr.dll (Background Intelligent Transfer Service Queue Manager)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "qmgr.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Background Intelligent Transfer Service (BITS) Queue Manager";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "qmgr";
            mod.stringTable["OriginalFilename"] = "qmgr.dll";
            mod.stringTable["ProductName"] = "MicaNT BITS Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // bitsprx.dll (BITS Proxy / Stub)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "bitsprx.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Background Intelligent Transfer Service Proxy";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "bitsprx";
            mod.stringTable["OriginalFilename"] = "bitsprx.dll";
            mod.stringTable["ProductName"] = "MicaNT BITS Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // vssapi.dll (Volume Shadow Copy Service API)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "vssapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft Volume Shadow Copy Service API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "vssapi";
            mod.stringTable["OriginalFilename"] = "vssapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Volume Shadow Copy Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // vss_ps.dll (VSS Proxy / Stub)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "vss_ps.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Volume Snapshot Service Proxy/Stub";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "vss_ps";
            mod.stringTable["OriginalFilename"] = "vss_ps.dll";
            mod.stringTable["ProductName"] = "MicaNT Volume Shadow Copy Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wer.dll (Windows Error Reporting Client DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wer.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Error Reporting Client DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wer";
            mod.stringTable["OriginalFilename"] = "wer.dll";
            mod.stringTable["ProductName"] = "MicaNT Windows Error Reporting Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // faultrep.dll (Windows Error Reporting Fault Reporting DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "faultrep.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Error Reporting Fault Reporting DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "faultrep";
            mod.stringTable["OriginalFilename"] = "faultrep.dll";
            mod.stringTable["ProductName"] = "MicaNT Windows Error Reporting Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // werfault.exe (Windows Error Reporting Diagnostic Agent)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "werfault.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Error Reporting Diagnostic Agent";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "werfault";
            mod.stringTable["OriginalFilename"] = "werfault.exe";
            mod.stringTable["ProductName"] = "MicaNT Windows Error Reporting Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // dwmapi.dll (Desktop Window Manager API DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "dwmapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft Desktop Window Manager API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "dwmapi";
            mod.stringTable["OriginalFilename"] = "dwmapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Desktop Window Manager Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // dwm.exe (Desktop Window Manager Executable)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "dwm.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Desktop Window Manager";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "dwm";
            mod.stringTable["OriginalFilename"] = "dwm.exe";
            mod.stringTable["ProductName"] = "MicaNT Desktop Window Manager Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // mmdevapi.dll (Multimedia Device API DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "mmdevapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "MMDevice API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "mmdevapi";
            mod.stringTable["OriginalFilename"] = "mmdevapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Core Audio Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // audiosrv.dll (Windows Audio Service DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "audiosrv.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Audio Service";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "audiosrv";
            mod.stringTable["OriginalFilename"] = "audiosrv.dll";
            mod.stringTable["ProductName"] = "MicaNT Core Audio Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // dismapi.dll (DISM API Subsystem)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "dismapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Deployment Image Servicing and Management API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "dismapi";
            mod.stringTable["OriginalFilename"] = "dismapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Component-Based Servicing";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // cbsapi.dll (Component-Based Servicing API)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "cbsapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Component-Based Servicing API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "cbsapi";
            mod.stringTable["OriginalFilename"] = "cbsapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Component-Based Servicing";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // dism.exe (Deployment Image Servicing and Management Tool)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "dism.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Deployment Image Servicing and Management Tool";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "dism";
            mod.stringTable["OriginalFilename"] = "dism.exe";
            mod.stringTable["ProductName"] = "MicaNT Component-Based Servicing";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // trustedinstaller.exe (Windows Modules Installer)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "trustedinstaller.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Modules Installer";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "TrustedInstaller";
            mod.stringTable["OriginalFilename"] = "TrustedInstaller.exe";
            mod.stringTable["ProductName"] = "MicaNT Operating System";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wdi.dll (Windows Diagnostic Infrastructure Core)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wdi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Diagnostic Infrastructure Core";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wdi";
            mod.stringTable["OriginalFilename"] = "wdi.dll";
            mod.stringTable["ProductName"] = "MicaNT Diagnostic Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // diagperf.dll (Windows Diagnostic Performance Collector)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "diagperf.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Diagnostic Performance Collector";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "diagperf";
            mod.stringTable["OriginalFilename"] = "diagperf.dll";
            mod.stringTable["ProductName"] = "MicaNT Diagnostic Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // msdt.exe (Microsoft Support Diagnostic Tool)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "msdt.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft Support Diagnostic Tool";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "msdt";
            mod.stringTable["OriginalFilename"] = "msdt.exe";
            mod.stringTable["ProductName"] = "MicaNT Diagnostic Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // pdh.dll (Windows Performance Data Helper)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "pdh.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Performance Data Helper";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "pdh";
            mod.stringTable["OriginalFilename"] = "pdh.dll";
            mod.stringTable["ProductName"] = "MicaNT Performance Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // perflib.dll (Windows Performance Counter Infrastructure)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "perflib.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Performance Counter Infrastructure";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "perflib";
            mod.stringTable["OriginalFilename"] = "perflib.dll";
            mod.stringTable["ProductName"] = "MicaNT Performance Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // perfmon.exe (Performance Monitor)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "perfmon.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Performance Monitor";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "perfmon";
            mod.stringTable["OriginalFilename"] = "perfmon.exe";
            mod.stringTable["ProductName"] = "MicaNT Performance Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // typeperf.exe (Performance Counter Command Line Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "typeperf.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Performance Counter Command Line Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "typeperf";
            mod.stringTable["OriginalFilename"] = "typeperf.exe";
            mod.stringTable["ProductName"] = "MicaNT Performance Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // logman.exe (Performance & Trace Log Manager CLI)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "logman.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Performance & Event Trace Session Manager";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "logman";
            mod.stringTable["OriginalFilename"] = "logman.exe";
            mod.stringTable["ProductName"] = "MicaNT Diagnostic Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // tracerpt.exe (Event Trace Report Generator)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "tracerpt.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Event Trace Dump and Report Tool";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "tracerpt";
            mod.stringTable["OriginalFilename"] = "tracerpt.exe";
            mod.stringTable["ProductName"] = "MicaNT Diagnostic Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // tracelog.exe (Event Trace Control Engine)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "tracelog.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Event Trace Controller Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "tracelog";
            mod.stringTable["OriginalFilename"] = "tracelog.exe";
            mod.stringTable["ProductName"] = "MicaNT Diagnostic Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // auditpol.exe (Security Auditing Policy Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "auditpol.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Security Audit Policy Tool";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "auditpol";
            mod.stringTable["OriginalFilename"] = "auditpol.exe";
            mod.stringTable["ProductName"] = "MicaNT Security Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // icacls.exe (Access Control List Tool)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "icacls.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "NT Access Control List Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "icacls";
            mod.stringTable["OriginalFilename"] = "icacls.exe";
            mod.stringTable["ProductName"] = "MicaNT Security Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // netapi32.dll (Network Management DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "netapi32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Net Win32 API DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "netapi32";
            mod.stringTable["OriginalFilename"] = "netapi32.dll";
            mod.stringTable["ProductName"] = "MicaNT Networking Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // srvcli.dll (Server Service Client DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "srvcli.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Server Service Client DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "srvcli";
            mod.stringTable["OriginalFilename"] = "srvcli.dll";
            mod.stringTable["ProductName"] = "MicaNT Networking Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wkscli.dll (Workstation Service Client DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wkscli.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Workstation Service Client DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wkscli";
            mod.stringTable["OriginalFilename"] = "wkscli.dll";
            mod.stringTable["ProductName"] = "MicaNT Networking Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // net.exe (Network Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "net.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "MicaNT Network Command Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "net";
            mod.stringTable["OriginalFilename"] = "net.exe";
            mod.stringTable["ProductName"] = "MicaNT Networking Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wldap32.dll (Lightweight Directory Access Protocol Client DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wldap32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft LDAP API Client DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wldap32";
            mod.stringTable["OriginalFilename"] = "wldap32.dll";
            mod.stringTable["ProductName"] = "MicaNT Active Directory Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // adsldp.dll (ADSI LDAP Provider DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "adsldp.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "ADSI LDAP Provider DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "adsldp";
            mod.stringTable["OriginalFilename"] = "adsldp.dll";
            mod.stringTable["ProductName"] = "MicaNT Active Directory Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // dsquery.exe (Directory Service Query Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "dsquery.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Directory Service Query Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "dsquery";
            mod.stringTable["OriginalFilename"] = "dsquery.exe";
            mod.stringTable["ProductName"] = "MicaNT Active Directory Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // dsget.exe (Directory Service Get Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "dsget.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Directory Service Get Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "dsget";
            mod.stringTable["OriginalFilename"] = "dsget.exe";
            mod.stringTable["ProductName"] = "MicaNT Active Directory Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wtsapi32.dll (Windows Terminal Server API Client DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wtsapi32.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Remote Desktop Session API DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wtsapi32";
            mod.stringTable["OriginalFilename"] = "wtsapi32.dll";
            mod.stringTable["ProductName"] = "MicaNT Terminal Services Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // termsrv.dll (Terminal Server Service DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "termsrv.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Terminal Server Service DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "termsrv";
            mod.stringTable["OriginalFilename"] = "termsrv.dll";
            mod.stringTable["ProductName"] = "MicaNT Terminal Services Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // mstsc.exe (Remote Desktop Connection Client)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "mstsc.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Remote Desktop Connection";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "mstsc";
            mod.stringTable["OriginalFilename"] = "mstsc.exe";
            mod.stringTable["ProductName"] = "MicaNT Terminal Services Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // qwinsta.exe (Query Window Station / Session Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "qwinsta.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Query Window Station Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "qwinsta";
            mod.stringTable["OriginalFilename"] = "qwinsta.exe";
            mod.stringTable["ProductName"] = "MicaNT Terminal Services Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // rwinsta.exe (Reset Window Station / Session Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "rwinsta.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Reset Window Station Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "rwinsta";
            mod.stringTable["OriginalFilename"] = "rwinsta.exe";
            mod.stringTable["ProductName"] = "MicaNT Terminal Services Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // winspool.drv (Windows Print Spooler Driver)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "winspool.drv";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DRV;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Print Spooler Driver";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "winspool";
            mod.stringTable["OriginalFilename"] = "winspool.drv";
            mod.stringTable["ProductName"] = "MicaNT Print Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // spoolsv.exe (Print Spooler Service)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "spoolsv.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Spooler SubSystem App";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "spoolsv";
            mod.stringTable["OriginalFilename"] = "spoolsv.exe";
            mod.stringTable["ProductName"] = "MicaNT Print Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // prnmngr.vbs / prnmngr.exe (Printer Management Script / Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "prnmngr.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Printer Management Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "prnmngr";
            mod.stringTable["OriginalFilename"] = "prnmngr.exe";
            mod.stringTable["ProductName"] = "MicaNT Print Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // print.exe (Line Printer Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "print.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Print Command Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "print";
            mod.stringTable["OriginalFilename"] = "print.exe";
            mod.stringTable["ProductName"] = "MicaNT Print Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // mciwave.dll (MCI Waveform Audio Device Driver)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "mciwave.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "MCI Waveform Audio Device Driver";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "mciwave";
            mod.stringTable["OriginalFilename"] = "mciwave.dll";
            mod.stringTable["ProductName"] = "MicaNT Windows Multimedia";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // mplayer.exe (Media Player Subsystem Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "mplayer.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Media Player Subsystem Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "mplayer";
            mod.stringTable["OriginalFilename"] = "mplayer.exe";
            mod.stringTable["ProductName"] = "MicaNT Windows Multimedia";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // waveplay.exe (Waveform Audio Playback Utility)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "waveplay.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Waveform Audio Playback Utility";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "waveplay";
            mod.stringTable["OriginalFilename"] = "waveplay.exe";
            mod.stringTable["ProductName"] = "MicaNT Windows Multimedia";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // winscard.dll (Microsoft Smart Card API)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "winscard.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft Smart Card API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "winscard";
            mod.stringTable["OriginalFilename"] = "winscard.dll";
            mod.stringTable["ProductName"] = "MicaNT Smart Card Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // scredir.dll (Smart Card Remote Desktop Redirection Library)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "scredir.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Smart Card Remote Desktop Redirection Library";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "scredir";
            mod.stringTable["OriginalFilename"] = "scredir.dll";
            mod.stringTable["ProductName"] = "MicaNT Smart Card Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // certprop.dll (Smart Card Certificate Propagation Service DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "certprop.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Smart Card Certificate Propagation Service DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "certprop";
            mod.stringTable["OriginalFilename"] = "certprop.dll";
            mod.stringTable["ProductName"] = "MicaNT Smart Card Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // certutil.exe (Certificate Utility and Smart Card Tool)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "certutil.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Certificate Utility and Smart Card Tool";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "certutil";
            mod.stringTable["OriginalFilename"] = "certutil.exe";
            mod.stringTable["ProductName"] = "MicaNT Smart Card Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // nlasvc.dll (Network Location Awareness Service DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "nlasvc.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Network Location Awareness Service";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "nlasvc";
            mod.stringTable["OriginalFilename"] = "nlasvc.dll";
            mod.stringTable["ProductName"] = "MicaNT Networking Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // netprofm.dll (Network List Manager)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "netprofm.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Network List Manager";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "netprofm";
            mod.stringTable["OriginalFilename"] = "netprofm.dll";
            mod.stringTable["ProductName"] = "MicaNT Networking Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // ncbservice.dll (Network Connection Broker)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "ncbservice.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Network Connection Broker";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "ncbservice";
            mod.stringTable["OriginalFilename"] = "ncbservice.dll";
            mod.stringTable["ProductName"] = "MicaNT Networking Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // nlaapi.dll (Network Location Awareness API)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "nlaapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Network Location Awareness API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "nlaapi";
            mod.stringTable["OriginalFilename"] = "nlaapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Networking Infrastructure";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wpncore.dll (Windows Push Notifications Platform Core)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wpncore.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Push Notifications Platform Core";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wpncore";
            mod.stringTable["OriginalFilename"] = "wpncore.dll";
            mod.stringTable["ProductName"] = "MicaNT Push Notification Platform";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wpnapps.dll (Windows Push Notifications App Service)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wpnapps.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Push Notifications App Service";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wpnapps";
            mod.stringTable["OriginalFilename"] = "wpnapps.dll";
            mod.stringTable["ProductName"] = "MicaNT Push Notification Platform";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wpnclient.dll (Windows Push Notifications Client API)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wpnclient.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Push Notifications Client API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wpnclient";
            mod.stringTable["OriginalFilename"] = "wpnclient.dll";
            mod.stringTable["ProductName"] = "MicaNT Push Notification Platform";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // locationapi.dll (Windows Location API)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "locationapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Location API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "locationapi";
            mod.stringTable["OriginalFilename"] = "locationapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Location Framework";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // portabledeviceapi.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "portabledeviceapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Portable Device API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "portabledeviceapi";
            mod.stringTable["OriginalFilename"] = "portabledeviceapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Portable Devices Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wpd_ci.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wpd_ci.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Portable Device Class Installer";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wpd_ci";
            mod.stringTable["OriginalFilename"] = "wpd_ci.dll";
            mod.stringTable["ProductName"] = "MicaNT Portable Devices Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // sensorsapi.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "sensorsapi.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Sensors API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "sensorsapi";
            mod.stringTable["OriginalFilename"] = "sensorsapi.dll";
            mod.stringTable["ProductName"] = "MicaNT Sensor Platform";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // sensorsclassextension.dll
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "sensorsclassextension.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Sensor Class Extension";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "sensorsclassextension";
            mod.stringTable["OriginalFilename"] = "sensorsclassextension.dll";
            mod.stringTable["ProductName"] = "MicaNT Sensor Platform";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // winbio.dll (Windows Biometric Framework Client API)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "winbio.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Biometric Framework Client API";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "winbio";
            mod.stringTable["OriginalFilename"] = "winbio.dll";
            mod.stringTable["ProductName"] = "MicaNT Biometrics Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // winbiosrvc.dll (Windows Biometric Service)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "winbiosrvc.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Biometric Service";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "winbiosrvc";
            mod.stringTable["OriginalFilename"] = "winbiosrvc.dll";
            mod.stringTable["ProductName"] = "MicaNT Biometrics Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // bluetoothapis.dll (Bluetooth API Library)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "bluetoothapis.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Bluetooth API Library";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "bluetoothapis";
            mod.stringTable["OriginalFilename"] = "bluetoothapis.dll";
            mod.stringTable["ProductName"] = "MicaNT Bluetooth Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // bthprops.cpl (Bluetooth Control Panel Applet)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "bthprops.cpl";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Bluetooth Control Panel Applet & Property Sheets";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "bthprops";
            mod.stringTable["OriginalFilename"] = "bthprops.cpl";
            mod.stringTable["ProductName"] = "MicaNT Bluetooth Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // msclmd.dll (Microsoft Smart Card Minidriver)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "msclmd.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft Smart Card Minidriver";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "msclmd";
            mod.stringTable["OriginalFilename"] = "msclmd.dll";
            mod.stringTable["ProductName"] = "MicaNT Smart Card Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // basecsp.dll (Base Smart Card Cryptographic Service Provider)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "basecsp.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Base Smart Card Cryptographic Service Provider";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "basecsp";
            mod.stringTable["OriginalFilename"] = "basecsp.dll";
            mod.stringTable["ProductName"] = "MicaNT Smart Card Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // psxdll.dll (POSIX.1 Subsystem Client Library)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "psxdll.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "POSIX.1 Subsystem Client Library";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "psxdll";
            mod.stringTable["OriginalFilename"] = "psxdll.dll";
            mod.stringTable["ProductName"] = "MicaNT POSIX Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // psxss.exe (POSIX.1 Subsystem Server)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "psxss.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "POSIX.1 Subsystem Server";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "psxss";
            mod.stringTable["OriginalFilename"] = "psxss.exe";
            mod.stringTable["ProductName"] = "MicaNT POSIX Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // posix.exe (POSIX Subsystem Application Launcher)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "posix.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "POSIX Subsystem Application Launcher";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "posix";
            mod.stringTable["OriginalFilename"] = "posix.exe";
            mod.stringTable["ProductName"] = "MicaNT POSIX Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // WinHvPlatform.dll (Windows Hypervisor Platform Client DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "WinHvPlatform.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Hypervisor Platform Client DLL";
            mod.stringTable["FileVersion"] = "10.0.26100.1";
            mod.stringTable["InternalName"] = "WinHvPlatform";
            mod.stringTable["OriginalFilename"] = "WinHvPlatform.dll";
            mod.stringTable["ProductName"] = "MicaNT Hypervisor Platform";
            mod.stringTable["ProductVersion"] = "10.0.26100.1";
            registerModule(mod);
        }

        // WinHvEmulation.dll (Windows Hypervisor Instruction Emulation DLL)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "WinHvEmulation.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Hypervisor Instruction Emulation DLL";
            mod.stringTable["FileVersion"] = "10.0.26100.1";
            mod.stringTable["InternalName"] = "WinHvEmulation";
            mod.stringTable["OriginalFilename"] = "WinHvEmulation.dll";
            mod.stringTable["ProductName"] = "MicaNT Hypervisor Platform";
            mod.stringTable["ProductVersion"] = "10.0.26100.1";
            registerModule(mod);
        }

        // vmcompute.exe (Hyper-V Host Compute Service)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "vmcompute.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Hyper-V Host Compute Service";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "vmcompute";
            mod.stringTable["OriginalFilename"] = "vmcompute.exe";
            mod.stringTable["ProductName"] = "MicaNT Hypervisor Platform";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // AppInstaller.dll (Windows Package Manager Client Library)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "AppInstaller.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Package Manager Client Library";
            mod.stringTable["FileVersion"] = "10.0.26100.1";
            mod.stringTable["InternalName"] = "AppInstaller";
            mod.stringTable["OriginalFilename"] = "AppInstaller.dll";
            mod.stringTable["ProductName"] = "MicaNT Operating System";
            mod.stringTable["ProductVersion"] = "10.0.26100.1";
            registerModule(mod);
        }

        // winget.exe (Windows Package Manager CLI)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "winget.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Package Manager CLI";
            mod.stringTable["FileVersion"] = "10.0.26100.1";
            mod.stringTable["InternalName"] = "winget";
            mod.stringTable["OriginalFilename"] = "winget.exe";
            mod.stringTable["ProductName"] = "MicaNT Operating System";
            mod.stringTable["ProductVersion"] = "10.0.26100.1";
            registerModule(mod);
        }

        // DWrite.dll (Microsoft DirectWrite)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "DWrite.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft DirectWrite";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "DWrite";
            mod.stringTable["OriginalFilename"] = "DWrite.dll";
            mod.stringTable["ProductName"] = "MicaNT DirectWrite Typography Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // usp10.dll (Uniscribe Unicode Script Processor)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "usp10.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Uniscribe Unicode Script Processor";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "usp10";
            mod.stringTable["OriginalFilename"] = "usp10.dll";
            mod.stringTable["ProductName"] = "MicaNT Uniscribe Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // mfplat.dll (Microsoft Media Foundation Platform)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "mfplat.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft Media Foundation Platform";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "mfplat";
            mod.stringTable["OriginalFilename"] = "mfplat.dll";
            mod.stringTable["ProductName"] = "MicaNT Media Foundation Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // mf.dll (Media Foundation Core Engine)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "mf.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Media Foundation Core Engine";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "mf";
            mod.stringTable["OriginalFilename"] = "mf.dll";
            mod.stringTable["ProductName"] = "MicaNT Media Foundation Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // mfreadwrite.dll (Media Foundation Source Reader and Sink Writer)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "mfreadwrite.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Media Foundation Source Reader and Sink Writer";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "mfreadwrite";
            mod.stringTable["OriginalFilename"] = "mfreadwrite.dll";
            mod.stringTable["ProductName"] = "MicaNT Media Foundation Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // quartz.dll (DirectShow Runtime & Filter Graph Manager)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "quartz.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "DirectShow Runtime & Filter Graph Manager";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "quartz";
            mod.stringTable["OriginalFilename"] = "quartz.dll";
            mod.stringTable["ProductName"] = "MicaNT DirectShow Runtime";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // devenum.dll (Device Enumerator)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "devenum.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "DirectShow Device Enumerator";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "devenum";
            mod.stringTable["OriginalFilename"] = "devenum.dll";
            mod.stringTable["ProductName"] = "MicaNT Device Enumerator";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // qedit.dll (DirectShow Editing Services & Sample Grabber)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "qedit.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "DirectShow Editing Services & Sample Grabber";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "qedit";
            mod.stringTable["OriginalFilename"] = "qedit.dll";
            mod.stringTable["ProductName"] = "MicaNT DirectShow Editing Services";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wmp.dll (Windows Media Player Core Engine)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wmp.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (12 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (12 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Media Player Core Engine";
            mod.stringTable["FileVersion"] = "12.0.26100.1";
            mod.stringTable["InternalName"] = "wmp";
            mod.stringTable["OriginalFilename"] = "wmp.dll";
            mod.stringTable["ProductName"] = "MicaNT Windows Media Player";
            mod.stringTable["ProductVersion"] = "12.0.26100.1";
            registerModule(mod);
        }

        // amstream.dll (ActiveMovie Multimedia Streaming)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "amstream.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "ActiveMovie Multimedia Streaming";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "amstream";
            mod.stringTable["OriginalFilename"] = "amstream.dll";
            mod.stringTable["ProductName"] = "MicaNT ActiveMovie Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wmplayer.exe (Windows Media Player Application)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wmplayer.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (12 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (12 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (26100 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Media Player";
            mod.stringTable["FileVersion"] = "12.0.26100.1";
            mod.stringTable["InternalName"] = "wmplayer";
            mod.stringTable["OriginalFilename"] = "wmplayer.exe";
            mod.stringTable["ProductName"] = "MicaNT Windows Media Player";
            mod.stringTable["ProductVersion"] = "12.0.26100.1";
            registerModule(mod);
        }

        // gdiplus.dll (Windows GDI+ Subsystem)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "gdiplus.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft GDI+ Windows Modern Subsystem";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "gdiplus";
            mod.stringTable["OriginalFilename"] = "gdiplus.dll";
            mod.stringTable["ProductName"] = "MicaNT GDI+ Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // windowscodecs.dll (Windows Imaging Component)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "windowscodecs.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft Windows Imaging Component (WIC)";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "windowscodecs";
            mod.stringTable["OriginalFilename"] = "windowscodecs.dll";
            mod.stringTable["ProductName"] = "MicaNT Windows Imaging Component";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // mspaint.exe (MicaNT Paint Application)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "mspaint.exe";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_APP;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Paint";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "mspaint";
            mod.stringTable["OriginalFilename"] = "mspaint.exe";
            mod.stringTable["ProductName"] = "MicaNT Paint";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // d2d1.dll (Direct2D Hardware-Accelerated Rendering Subsystem)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "d2d1.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Microsoft Direct2D Vector Graphics Engine";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "d2d1";
            mod.stringTable["OriginalFilename"] = "d2d1.dll";
            mod.stringTable["ProductName"] = "MicaNT Direct2D Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // wmvdecod.dll (Windows Media Video & Audio Decoder Subsystem)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "wmvdecod.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Windows Media Video and Audio Decoder";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "wmvdecod";
            mod.stringTable["OriginalFilename"] = "wmvdecod.dll";
            mod.stringTable["ProductName"] = "MicaNT WMV & WMA Codec Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // evr.dll (Enhanced Video Renderer Subsystem)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "evr.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Enhanced Video Renderer DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "evr";
            mod.stringTable["OriginalFilename"] = "evr.dll";
            mod.stringTable["ProductName"] = "MicaNT Enhanced Video Renderer Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // dxva2.dll (DirectX Video Acceleration 2.0 Subsystem)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "dxva2.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "DirectX Video Acceleration 2.0 DLL";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "dxva2";
            mod.stringTable["OriginalFilename"] = "dxva2.dll";
            mod.stringTable["ProductName"] = "MicaNT DirectX Video Acceleration 2.0 Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }

        // d3d11.dll (Direct3D 11 Video Acceleration & Runtime Subsystem)
        {
            ModuleVersionInfo mod{};
            mod.moduleName = "d3d11.dll";
            mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
            mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
            mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
            mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
            mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
            mod.fixedInfo.dwFileType = VFT_DLL;
            mod.stringTable["CompanyName"] = "MicaNT Sovereign Project";
            mod.stringTable["FileDescription"] = "Direct3D 11 Video Acceleration and Runtime Dynamic Link Library";
            mod.stringTable["FileVersion"] = "10.0.22621.1";
            mod.stringTable["InternalName"] = "d3d11";
            mod.stringTable["OriginalFilename"] = "d3d11.dll";
            mod.stringTable["ProductName"] = "MicaNT Direct3D 11 Video Acceleration Subsystem";
            mod.stringTable["ProductVersion"] = "10.0.22621.1";
            registerModule(mod);
        }
    }

public:
    static VersionDatabase& Instance() {
        static VersionDatabase s_instance;
        return s_instance;
    }

    void RegisterModule(std::string_view name, std::string_view version, std::string_view desc, std::string_view company = "MicaNT Sovereign Project") {
        ModuleVersionInfo mod{};
        mod.moduleName = std::string(name);
        mod.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
        mod.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
        mod.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
        mod.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
        mod.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
        mod.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
        mod.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
        mod.fixedInfo.dwFileType = VFT_DLL;
        mod.stringTable["CompanyName"] = std::string(company);
        mod.stringTable["FileDescription"] = std::string(desc);
        mod.stringTable["FileVersion"] = std::string(version);
        mod.stringTable["OriginalFilename"] = std::string(name);
        mod.stringTable["ProductName"] = "MicaNT Operating System";
        mod.stringTable["ProductVersion"] = std::string(version);
        registerModule(mod);
    }

    const ModuleVersionInfo* GetModuleInfo(std::string_view name) const {
        return FindModule(name);
    }

    const ModuleVersionInfo* FindModule(std::string_view name) const {
        std::string n = normalizeName(name);
        auto it = m_database.find(n);
        if (it != m_database.end()) return &it->second;

        // Fallback for any unknown DLL or EXE requested: provide standard NT-compatible identity
        static ModuleVersionInfo s_fallback{};
        s_fallback.moduleName = std::string(name);
        s_fallback.fixedInfo.dwSignature = VS_FFI_SIGNATURE;
        s_fallback.fixedInfo.dwStrucVersion = VS_FFI_STRUCVERSION;
        s_fallback.fixedInfo.dwFileVersionMS = (10 << 16) | 0;
        s_fallback.fixedInfo.dwFileVersionLS = (22621 << 16) | 1;
        s_fallback.fixedInfo.dwProductVersionMS = (10 << 16) | 0;
        s_fallback.fixedInfo.dwProductVersionLS = (22621 << 16) | 1;
        s_fallback.fixedInfo.dwFileOS = VOS_NT_WINDOWS32;
        s_fallback.fixedInfo.dwFileType = VFT_DLL;
        s_fallback.stringTable["CompanyName"] = "MicaNT Sovereign Project";
        s_fallback.stringTable["FileDescription"] = "MicaNT Windows Subsystem Module";
        s_fallback.stringTable["FileVersion"] = "10.0.22621.1";
        s_fallback.stringTable["OriginalFilename"] = std::string(name);
        s_fallback.stringTable["ProductName"] = "MicaNT Operating System";
        s_fallback.stringTable["ProductVersion"] = "10.0.22621.1";
        return &s_fallback;
    }
};

// ============================================================================
// 3. Win32 Version Standard API Exports
// ============================================================================

inline uint32_t WINAPI GetFileVersionInfoSizeA(const char* lptstrFilename, uint32_t* lpdwHandle) {
    if (lpdwHandle) *lpdwHandle = 0;
    if (!lptstrFilename || !*lptstrFilename) return 0;
    const auto* mod = VersionDatabase::Instance().FindModule(lptstrFilename);
    if (!mod) return 0;
    return static_cast<uint32_t>(mod->BuildBinaryResource().size());
}

inline uint32_t WINAPI GetFileVersionInfoSizeW(const wchar_t* lptstrFilename, uint32_t* lpdwHandle) {
    if (lpdwHandle) *lpdwHandle = 0;
    if (!lptstrFilename || !*lptstrFilename) return 0;
    std::string narrow;
    while (*lptstrFilename) narrow.push_back(static_cast<char>(*lptstrFilename++));
    return GetFileVersionInfoSizeA(narrow.c_str(), lpdwHandle);
}

inline int32_t WINAPI GetFileVersionInfoA(const char* lptstrFilename, uint32_t, uint32_t dwLen, void* lpData) {
    if (!lptstrFilename || !lpData || dwLen == 0) return 0;
    const auto* mod = VersionDatabase::Instance().FindModule(lptstrFilename);
    if (!mod) return 0;
    auto blob = mod->BuildBinaryResource();
    size_t copySize = std::min(size_t(dwLen), blob.size());
    std::memcpy(lpData, blob.data(), copySize);
    return 1;
}

inline int32_t WINAPI GetFileVersionInfoW(const wchar_t* lptstrFilename, uint32_t dwHandle, uint32_t dwLen, void* lpData) {
    if (!lptstrFilename || !lpData || dwLen == 0) return 0;
    std::string narrow;
    while (*lptstrFilename) narrow.push_back(static_cast<char>(*lptstrFilename++));
    return GetFileVersionInfoA(narrow.c_str(), dwHandle, dwLen, lpData);
}

inline int32_t WINAPI VerQueryValueA(const void* pBlock, const char* lpSubBlock, void** lplpBuffer, uint32_t* puLen) {
    if (!pBlock || !lpSubBlock || !lplpBuffer || !puLen) return 0;

    std::string sub(lpSubBlock);

    // Root query: "\\" queries root VS_FIXEDFILEINFO
    if (sub == "\\" || sub.empty()) {
        const uint8_t* bytes = static_cast<const uint8_t*>(pBlock);
        *lplpBuffer = const_cast<void*>(static_cast<const void*>(bytes + 64));
        *puLen = sizeof(VS_FIXEDFILEINFO);
        return 1;
    }

    // Translation table query: "\\VarFileInfo\\Translation"
    if (sub.find("VarFileInfo") != std::string::npos || sub.find("Translation") != std::string::npos) {
        const uint8_t* bytes = static_cast<const uint8_t*>(pBlock);
        size_t transOffset = sizeof(VS_FIXEDFILEINFO) + 128;
        *lplpBuffer = const_cast<void*>(static_cast<const void*>(bytes + transOffset));
        *puLen = sizeof(uint32_t);
        return 1;
    }

    // StringFileInfo query: e.g., "\\StringFileInfo\\040904b0\\FileDescription"
    size_t lastSlash = sub.find_last_of("\\/");
    std::string propName = (lastSlash != std::string::npos) ? sub.substr(lastSlash + 1) : sub;

    uint16_t totalLen = *static_cast<const uint16_t*>(pBlock);
    if (totalLen < 64 || totalLen > 16384) totalLen = 4096;
    const uint8_t* pBytes = static_cast<const uint8_t*>(pBlock);
    std::string targetPrefix = propName + "=";

    for (size_t i = 0; i + targetPrefix.size() <= totalLen; ++i) {
        if (std::memcmp(pBytes + i, targetPrefix.data(), targetPrefix.size()) == 0) {
            const char* val = reinterpret_cast<const char*>(pBytes + i + targetPrefix.size());
            *lplpBuffer = const_cast<void*>(static_cast<const void*>(val));
            *puLen = static_cast<uint32_t>(std::strlen(val) + 1);
            return 1;
        }
    }

    *lplpBuffer = nullptr;
    *puLen = 0;
    return 0;
}

inline int32_t WINAPI VerQueryValueW(const void* pBlock, const wchar_t* lpSubBlock, void** lplpBuffer, uint32_t* puLen) {
    if (!pBlock || !lpSubBlock || !lplpBuffer || !puLen) return 0;
    std::string sub;
    while (*lpSubBlock) sub.push_back(static_cast<char>(*lpSubBlock++));
    return VerQueryValueA(pBlock, sub.c_str(), lplpBuffer, puLen);
}

inline uint32_t WINAPI VerLanguageNameA(uint32_t wLang, char* szLang, uint32_t nSize) {
    if (!szLang || nSize == 0) return 0;
    std::string name;
    switch (wLang & 0xFFFF) {
        case 0x0409: name = "English (United States)"; break;
        case 0x0809: name = "English (United Kingdom)"; break;
        case 0x040C: name = "French (Standard)"; break;
        case 0x0407: name = "German (Standard)"; break;
        case 0x0411: name = "Japanese"; break;
        case 0x0804: name = "Chinese (Simplified)"; break;
        case 0x0000: name = "Language Neutral"; break;
        default:     name = "Custom Language"; break;
    }
    size_t len = std::min(size_t(nSize - 1), name.size());
    std::memcpy(szLang, name.data(), len);
    szLang[len] = '\0';
    return static_cast<uint32_t>(len);
}

inline uint32_t WINAPI VerLanguageNameW(uint32_t wLang, wchar_t* szLang, uint32_t nSize) {
    if (!szLang || nSize == 0) return 0;
    char buf[64]{};
    uint32_t count = VerLanguageNameA(wLang, buf, sizeof(buf));
    for (uint32_t i = 0; i < count && i < nSize - 1; ++i) {
        szLang[i] = static_cast<wchar_t>(buf[i]);
    }
    szLang[std::min(count, nSize - 1)] = 0;
    return count;
}

inline void InitializeVersionExports() {
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("version.dll", "GetFileVersionInfoSizeA", reinterpret_cast<void*>(GetFileVersionInfoSizeA));
    ldr.registerExport("version.dll", "GetFileVersionInfoSizeW", reinterpret_cast<void*>(GetFileVersionInfoSizeW));
    ldr.registerExport("version.dll", "GetFileVersionInfoA", reinterpret_cast<void*>(GetFileVersionInfoA));
    ldr.registerExport("version.dll", "GetFileVersionInfoW", reinterpret_cast<void*>(GetFileVersionInfoW));
    ldr.registerExport("version.dll", "VerQueryValueA", reinterpret_cast<void*>(VerQueryValueA));
    ldr.registerExport("version.dll", "VerQueryValueW", reinterpret_cast<void*>(VerQueryValueW));
    ldr.registerExport("version.dll", "VerLanguageNameA", reinterpret_cast<void*>(VerLanguageNameA));
    ldr.registerExport("version.dll", "VerLanguageNameW", reinterpret_cast<void*>(VerLanguageNameW));
}

} // namespace micant::version
