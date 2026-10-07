// ============================================================================
// MicaNT: Win32 Shell API Subsystem (shell32.dll & shlwapi.dll)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Provides Windows Shell Folders, CSIDL & KNOWNFOLDERID namespaces,
// ShellExecute process activation, CommandLineToArgvW tokenization,
// System Tray Notification Icons (Shell_NotifyIcon), and Lightweight Path APIs.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <string_view>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <cstring>
#include <cwchar>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "user32.hpp"
#include "fs.hpp"
#include "ldr.hpp"

namespace micant::shell32 {

// ============================================================================
// 1. Data Types & Shell Constants
// ============================================================================

using HRESULT = int32_t;
using HWND    = win32::HWND;
using HICON   = win32::HICON;
using HINSTANCE = win32::HINSTANCE;
using HKEY    = win32::HKEY;
using DWORD   = win32::DWORD;
using BOOL    = win32::BOOL;
using UINT    = win32::UINT;
using ULONG   = uint32_t;
using DWORD_PTR = uintptr_t;
using ULONG_PTR = uintptr_t;
using LPCWSTR = const wchar_t*;
using LPCSTR  = const char*;
using LPWSTR  = wchar_t*;
using LPSTR   = char*;
using PCWSTR  = const wchar_t*;
using PCSTR   = const char*;
using PWSTR   = wchar_t*;
using PSTR    = char*;

inline constexpr HRESULT S_OK    = 0;
inline constexpr HRESULT S_FALSE = 1;
inline constexpr HRESULT E_FAIL  = static_cast<HRESULT>(0x80004005);
inline constexpr HRESULT E_INVALIDARG = static_cast<HRESULT>(0x80070057);

// CSIDL (Constant Special Item ID List) Values
inline constexpr int CSIDL_DESKTOP                 = 0x0000;
inline constexpr int CSIDL_INTERNET                = 0x0001;
inline constexpr int CSIDL_PROGRAMS                = 0x0002;
inline constexpr int CSIDL_CONTROLS                = 0x0003;
inline constexpr int CSIDL_PRINTERS                = 0x0004;
inline constexpr int CSIDL_PERSONAL                = 0x0005; // Documents
inline constexpr int CSIDL_FAVORITES               = 0x0006;
inline constexpr int CSIDL_STARTUP                 = 0x0007;
inline constexpr int CSIDL_RECENT                  = 0x0008;
inline constexpr int CSIDL_SENDTO                  = 0x0009;
inline constexpr int CSIDL_BITBUCKET               = 0x000A; // Recycle Bin
inline constexpr int CSIDL_STARTMENU               = 0x000B;
inline constexpr int CSIDL_MYDOCUMENTS             = CSIDL_PERSONAL;
inline constexpr int CSIDL_MYMUSIC                 = 0x000D;
inline constexpr int CSIDL_MYVIDEO                 = 0x000E;
inline constexpr int CSIDL_DESKTOPDIRECTORY        = 0x0010;
inline constexpr int CSIDL_DRIVES                  = 0x0011;
inline constexpr int CSIDL_NETWORK                 = 0x0012;
inline constexpr int CSIDL_NETHOOD                 = 0x0013;
inline constexpr int CSIDL_FONTS                   = 0x0014;
inline constexpr int CSIDL_TEMPLATES               = 0x0015;
inline constexpr int CSIDL_COMMON_STARTMENU        = 0x0016;
inline constexpr int CSIDL_COMMON_PROGRAMS         = 0x0017;
inline constexpr int CSIDL_COMMON_STARTUP          = 0x0018;
inline constexpr int CSIDL_COMMON_DESKTOPDIRECTORY = 0x0019;
inline constexpr int CSIDL_APPDATA                 = 0x001A;
inline constexpr int CSIDL_PRINTHOOD               = 0x001B;
inline constexpr int CSIDL_LOCAL_APPDATA           = 0x001C;
inline constexpr int CSIDL_COMMON_FAVORITES        = 0x001F;
inline constexpr int CSIDL_INTERNET_CACHE          = 0x0020;
inline constexpr int CSIDL_COOKIES                 = 0x0021;
inline constexpr int CSIDL_HISTORY                 = 0x0022;
inline constexpr int CSIDL_COMMON_APPDATA          = 0x0023;
inline constexpr int CSIDL_WINDOWS                 = 0x0024;
inline constexpr int CSIDL_SYSTEM                  = 0x0025;
inline constexpr int CSIDL_PROGRAM_FILES           = 0x0026;
inline constexpr int CSIDL_MYPICTURES              = 0x0027;
inline constexpr int CSIDL_PROFILE                 = 0x0028;
inline constexpr int CSIDL_SYSTEMX86               = 0x0029;
inline constexpr int CSIDL_PROGRAM_FILESX86        = 0x002A;
inline constexpr int CSIDL_PROGRAM_FILES_COMMON    = 0x002B;
inline constexpr int CSIDL_PROGRAM_FILES_COMMONX86 = 0x002C;
inline constexpr int CSIDL_COMMON_TEMPLATES        = 0x002D;
inline constexpr int CSIDL_COMMON_DOCUMENTS        = 0x002E;
inline constexpr int CSIDL_COMMON_ADMINTOOLS       = 0x002F;
inline constexpr int CSIDL_ADMINTOOLS              = 0x0030;

inline constexpr int CSIDL_FLAG_CREATE             = 0x8000;
inline constexpr int CSIDL_FLAG_DONT_VERIFY        = 0x4000;
inline constexpr int CSIDL_FLAG_MASK               = 0xFF00;

// Known Folder GUIDs (KNOWNFOLDERID)
inline const micant::GUID FOLDERID_Desktop = {
    0xB4BFCC3A, 0xDB2C, 0x424C, { 0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41 }
};
inline const micant::GUID FOLDERID_Documents = {
    0xFDD39AD0, 0x238F, 0x46AF, { 0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7 }
};
inline const micant::GUID FOLDERID_Downloads = {
    0x374DE290, 0x123F, 0x4565, { 0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B }
};
inline const micant::GUID FOLDERID_Music = {
    0x4BD8D570, 0x509E, 0x49E5, { 0xAB, 0x78, 0x02, 0x54, 0x33, 0x29, 0xB2, 0xD0 }
};
inline const micant::GUID FOLDERID_Pictures = {
    0x33E28130, 0x4E1E, 0x4676, { 0x83, 0x5A, 0x98, 0x39, 0x5C, 0x3B, 0xC3, 0xBB }
};
inline const micant::GUID FOLDERID_Videos = {
    0x1898EB52, 0x7147, 0x49FA, { 0x9F, 0x50, 0x74, 0x5D, 0x00, 0xE5, 0xDF, 0x0C }
};
inline const micant::GUID FOLDERID_ProgramFiles = {
    0x905E63B6, 0xC1BF, 0x494E, { 0xB2, 0x9C, 0x65, 0xB7, 0x32, 0xD3, 0xD2, 0x1A }
};
inline const micant::GUID FOLDERID_ProgramFilesX86 = {
    0x7C5A40EF, 0xA0FB, 0x4BFC, { 0x87, 0x4A, 0xC0, 0xF2, 0xE0, 0xB9, 0xFA, 0x8E }
};
inline const micant::GUID FOLDERID_Windows = {
    0xF38BF404, 0x1D43, 0x42F2, { 0x93, 0x05, 0x67, 0xDE, 0x0B, 0x28, 0xFC, 0x23 }
};
inline const micant::GUID FOLDERID_System = {
    0x1AC14E77, 0x02E7, 0x4E5D, { 0xB7, 0x44, 0x2E, 0xB1, 0xAE, 0x51, 0x98, 0xB7 }
};
inline const micant::GUID FOLDERID_Profile = {
    0x5E6C858F, 0x0E22, 0x4760, { 0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73 }
};
inline const micant::GUID FOLDERID_LocalAppData = {
    0xF1B32785, 0x6FBA, 0x4FCF, { 0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91 }
};
inline const micant::GUID FOLDERID_RoamingAppData = {
    0x3EB685FD, 0x984F, 0x4E40, { 0xB0, 0x96, 0x18, 0x09, 0xC7, 0x15, 0xF5, 0xF8 }
};

using REFKNOWNFOLDERID = const micant::GUID&;

// Known Folder Flags
inline constexpr DWORD KF_FLAG_DEFAULT         = 0x00000000;
inline constexpr DWORD KF_FLAG_CREATE          = 0x00008000;
inline constexpr DWORD KF_FLAG_DONT_VERIFY     = 0x00004000;
inline constexpr DWORD KF_FLAG_DONT_UNEXPAND   = 0x00002000;
inline constexpr DWORD KF_FLAG_NO_ALIAS        = 0x00001000;
inline constexpr DWORD KF_FLAG_INIT            = 0x00000800;
inline constexpr DWORD KF_FLAG_DEFAULT_PATH    = 0x00000400;

// ShellExecute Mask Flags
inline constexpr ULONG SEE_MASK_DEFAULT        = 0x00000000;
inline constexpr ULONG SEE_MASK_CLASSNAME      = 0x00000001;
inline constexpr ULONG SEE_MASK_CLASSKEY       = 0x00000003;
inline constexpr ULONG SEE_MASK_IDLIST         = 0x00000004;
inline constexpr ULONG SEE_MASK_INVOKEIDLIST   = 0x0000000C;
inline constexpr ULONG SEE_MASK_ICON           = 0x00000010;
inline constexpr ULONG SEE_MASK_HOTKEY         = 0x00000020;
inline constexpr ULONG SEE_MASK_NOCLOSEPROCESS = 0x00000040;
inline constexpr ULONG SEE_MASK_CONNECTNETDRV  = 0x00000080;
inline constexpr ULONG SEE_MASK_NOASYNC        = 0x00000100;
inline constexpr ULONG SEE_MASK_FLAG_NO_UI     = 0x00000400;
inline constexpr ULONG SEE_MASK_UNICODE        = 0x00004000;
inline constexpr ULONG SEE_MASK_NO_CONSOLE     = 0x00008000;

// ShellExecute Structures
struct SHELLEXECUTEINFOW {
    DWORD     cbSize{sizeof(SHELLEXECUTEINFOW)};
    ULONG     fMask{0};
    HWND      hwnd{nullptr};
    LPCWSTR   lpVerb{nullptr};
    LPCWSTR   lpFile{nullptr};
    LPCWSTR   lpParameters{nullptr};
    LPCWSTR   lpDirectory{nullptr};
    int       nShow{1}; // SW_SHOWNORMAL
    HINSTANCE hInstApp{nullptr};
    void*     lpIDList{nullptr};
    LPCWSTR   lpClass{nullptr};
    HKEY      hkeyClass{nullptr};
    DWORD     dwHotKey{0};
    union {
        win32::HANDLE hIcon{nullptr};
        win32::HANDLE hMonitor;
    };
    win32::HANDLE hProcess{nullptr};
};

struct SHELLEXECUTEINFOA {
    DWORD     cbSize{sizeof(SHELLEXECUTEINFOA)};
    ULONG     fMask{0};
    HWND      hwnd{nullptr};
    LPCSTR    lpVerb{nullptr};
    LPCSTR    lpFile{nullptr};
    LPCSTR    lpParameters{nullptr};
    LPCSTR    lpDirectory{nullptr};
    int       nShow{1};
    HINSTANCE hInstApp{nullptr};
    void*     lpIDList{nullptr};
    LPCSTR    lpClass{nullptr};
    HKEY      hkeyClass{nullptr};
    DWORD     dwHotKey{0};
    union {
        win32::HANDLE hIcon{nullptr};
        win32::HANDLE hMonitor;
    };
    win32::HANDLE hProcess{nullptr};
};

// System Tray Notification Icon Messages & Flags
inline constexpr DWORD NIM_ADD        = 0x00000000;
inline constexpr DWORD NIM_MODIFY     = 0x00000001;
inline constexpr DWORD NIM_DELETE     = 0x00000002;
inline constexpr DWORD NIM_SETFOCUS   = 0x00000003;
inline constexpr DWORD NIM_SETVERSION = 0x00000004;

inline constexpr UINT NIF_MESSAGE  = 0x00000001;
inline constexpr UINT NIF_ICON     = 0x00000002;
inline constexpr UINT NIF_TIP      = 0x00000004;
inline constexpr UINT NIF_STATE    = 0x00000008;
inline constexpr UINT NIF_INFO     = 0x00000010;
inline constexpr UINT NIF_GUID     = 0x00000020;
inline constexpr UINT NIF_REALTIME = 0x00000040;
inline constexpr UINT NIF_SHOWTIP  = 0x00000080;

struct NOTIFYICONDATAW {
    DWORD        cbSize{sizeof(NOTIFYICONDATAW)};
    HWND         hWnd{nullptr};
    UINT         uID{0};
    UINT         uFlags{0};
    UINT         uCallbackMessage{0};
    HICON        hIcon{nullptr};
    wchar_t      szTip[128]{};
    DWORD        dwState{0};
    DWORD        dwStateMask{0};
    wchar_t      szInfo[256]{};
    union {
        UINT     uTimeout{0};
        UINT     uVersion;
    };
    wchar_t      szInfoTitle[64]{};
    DWORD        dwInfoFlags{0};
    micant::GUID guidItem{};
    HICON        hBalloonIcon{nullptr};
};

struct NOTIFYICONDATAA {
    DWORD        cbSize{sizeof(NOTIFYICONDATAA)};
    HWND         hWnd{nullptr};
    UINT         uID{0};
    UINT         uFlags{0};
    UINT         uCallbackMessage{0};
    HICON        hIcon{nullptr};
    char         szTip[128]{};
    DWORD        dwState{0};
    DWORD        dwStateMask{0};
    char         szInfo[256]{};
    union {
        UINT     uTimeout{0};
        UINT     uVersion;
    };
    char         szInfoTitle[64]{};
    DWORD        dwInfoFlags{0};
    micant::GUID guidItem{};
    HICON        hBalloonIcon{nullptr};
};

// Shell File Information Flags & Structures
inline constexpr UINT SHGFI_ICON              = 0x000000100;
inline constexpr UINT SHGFI_DISPLAYNAME       = 0x000000200;
inline constexpr UINT SHGFI_TYPENAME          = 0x000000400;
inline constexpr UINT SHGFI_ATTRIBUTES        = 0x000000800;
inline constexpr UINT SHGFI_ICONLOCATION      = 0x000001000;
inline constexpr UINT SHGFI_EXETYPE           = 0x000002000;
inline constexpr UINT SHGFI_SYSICONINDEX      = 0x000004000;
inline constexpr UINT SHGFI_LINKOVERLAY       = 0x000008000;
inline constexpr UINT SHGFI_SELECTED          = 0x000010000;
inline constexpr UINT SHGFI_ATTR_SPECIFIED    = 0x000020000;
inline constexpr UINT SHGFI_LARGEICON         = 0x000000000;
inline constexpr UINT SHGFI_SMALLICON         = 0x000000001;
inline constexpr UINT SHGFI_OPENICON          = 0x000000002;
inline constexpr UINT SHGFI_SHELLICONSIZE     = 0x000000004;
inline constexpr UINT SHGFI_PIDL              = 0x000000008;
inline constexpr UINT SHGFI_USEFILEATTRIBUTES = 0x000000010;

struct SHFILEINFOW {
    HICON   hIcon{nullptr};
    int     iIcon{0};
    DWORD   dwAttributes{0};
    wchar_t szDisplayName[260]{};
    wchar_t szTypeName[80]{};
};

struct SHFILEINFOA {
    HICON   hIcon{nullptr};
    int     iIcon{0};
    DWORD   dwAttributes{0};
    char    szDisplayName[260]{};
    char    szTypeName[80]{};
};

// ============================================================================
// 2. Shell Lightweight Path APIs (shlwapi.dll)
// ============================================================================

inline BOOL PathFileExistsW(LPCWSTR pszPath) noexcept {
    if (!pszPath || !*pszPath) return win32::FALSE;
    return (kernel32::GetFileAttributesW(pszPath) != win32::INVALID_FILE_ATTRIBUTES) ? win32::TRUE : win32::FALSE;
}

inline BOOL PathFileExistsA(LPCSTR pszPath) noexcept {
    if (!pszPath || !*pszPath) return win32::FALSE;
    return (kernel32::GetFileAttributesA(pszPath) != win32::INVALID_FILE_ATTRIBUTES) ? win32::TRUE : win32::FALSE;
}

inline LPWSTR PathCombineW(LPWSTR pszDest, LPCWSTR pszDir, LPCWSTR pszFile) noexcept {
    if (!pszDest) return nullptr;
    std::wstring combined;
    if (pszDir && *pszDir) {
        combined = pszDir;
        if (!combined.ends_with(L'\\') && !combined.ends_with(L'/')) {
            combined.push_back(L'\\');
        }
    }
    if (pszFile && *pszFile) {
        if (*pszFile == L'\\' || *pszFile == L'/') {
            combined = pszFile;
        } else {
            combined += pszFile;
        }
    }
    std::wcsncpy(pszDest, combined.c_str(), 260);
    pszDest[259] = L'\0';
    return pszDest;
}

inline LPSTR PathCombineA(LPSTR pszDest, LPCSTR pszDir, LPCSTR pszFile) noexcept {
    if (!pszDest) return nullptr;
    std::string combined;
    if (pszDir && *pszDir) {
        combined = pszDir;
        if (!combined.ends_with('\\') && !combined.ends_with('/')) {
            combined.push_back('\\');
        }
    }
    if (pszFile && *pszFile) {
        if (*pszFile == '\\' || *pszFile == '/') {
            combined = pszFile;
        } else {
            combined += pszFile;
        }
    }
    std::strncpy(pszDest, combined.c_str(), 260);
    pszDest[259] = '\0';
    return pszDest;
}

inline LPCWSTR PathFindFileNameW(LPCWSTR pszPath) noexcept {
    if (!pszPath) return nullptr;
    const wchar_t* last = pszPath;
    for (const wchar_t* p = pszPath; *p; ++p) {
        if (*p == L'\\' || *p == L'/' || *p == L':') {
            last = p + 1;
        }
    }
    return last;
}

inline LPCSTR PathFindFileNameA(LPCSTR pszPath) noexcept {
    if (!pszPath) return nullptr;
    const char* last = pszPath;
    for (const char* p = pszPath; *p; ++p) {
        if (*p == '\\' || *p == '/' || *p == ':') {
            last = p + 1;
        }
    }
    return last;
}

inline LPCWSTR PathFindExtensionW(LPCWSTR pszPath) noexcept {
    if (!pszPath) return nullptr;
    const wchar_t* dot = nullptr;
    for (const wchar_t* p = pszPath; *p; ++p) {
        if (*p == L'.') {
            dot = p;
        } else if (*p == L'\\' || *p == L'/' || *p == L':') {
            dot = nullptr;
        }
    }
    return dot ? dot : (pszPath + std::wcslen(pszPath));
}

inline LPCSTR PathFindExtensionA(LPCSTR pszPath) noexcept {
    if (!pszPath) return nullptr;
    const char* dot = nullptr;
    for (const char* p = pszPath; *p; ++p) {
        if (*p == '.') {
            dot = p;
        } else if (*p == '\\' || *p == '/' || *p == ':') {
            dot = nullptr;
        }
    }
    return dot ? dot : (pszPath + std::strlen(pszPath));
}

inline BOOL PathRemoveFileSpecW(LPWSTR pszPath) noexcept {
    if (!pszPath || !*pszPath) return win32::FALSE;
    wchar_t* last = nullptr;
    for (wchar_t* p = pszPath; *p; ++p) {
        if (*p == L'\\' || *p == L'/') {
            last = p;
        }
    }
    if (last) {
        if (last == pszPath) {
            *(last + 1) = L'\0';
        } else {
            *last = L'\0';
        }
        return win32::TRUE;
    }
    return win32::FALSE;
}

inline BOOL PathRemoveFileSpecA(LPSTR pszPath) noexcept {
    if (!pszPath || !*pszPath) return win32::FALSE;
    char* last = nullptr;
    for (char* p = pszPath; *p; ++p) {
        if (*p == '\\' || *p == '/') {
            last = p;
        }
    }
    if (last) {
        if (last == pszPath) {
            *(last + 1) = '\0';
        } else {
            *last = '\0';
        }
        return win32::TRUE;
    }
    return win32::FALSE;
}

inline LPWSTR PathAddBackslashW(LPWSTR pszPath) noexcept {
    if (!pszPath) return nullptr;
    size_t len = std::wcslen(pszPath);
    if (len > 0 && pszPath[len - 1] != L'\\' && pszPath[len - 1] != L'/' && len + 1 < 260) {
        pszPath[len] = L'\\';
        pszPath[len + 1] = L'\0';
        return pszPath + len + 1;
    }
    return pszPath + len;
}

inline LPSTR PathAddBackslashA(LPSTR pszPath) noexcept {
    if (!pszPath) return nullptr;
    size_t len = std::strlen(pszPath);
    if (len > 0 && pszPath[len - 1] != '\\' && pszPath[len - 1] != '/' && len + 1 < 260) {
        pszPath[len] = '\\';
        pszPath[len + 1] = '\0';
        return pszPath + len + 1;
    }
    return pszPath + len;
}

inline BOOL PathIsRelativeW(LPCWSTR pszPath) noexcept {
    if (!pszPath || !*pszPath) return win32::TRUE;
    if (pszPath[0] == L'\\' || pszPath[0] == L'/') return win32::FALSE;
    if (std::iswalpha(pszPath[0]) && pszPath[1] == L':') return win32::FALSE;
    return win32::TRUE;
}

inline BOOL PathIsRelativeA(LPCSTR pszPath) noexcept {
    if (!pszPath || !*pszPath) return win32::TRUE;
    if (pszPath[0] == '\\' || pszPath[0] == '/') return win32::FALSE;
    if (std::isalpha(static_cast<unsigned char>(pszPath[0])) && pszPath[1] == ':') return win32::FALSE;
    return win32::TRUE;
}

inline BOOL PathIsDirectoryW(LPCWSTR pszPath) noexcept {
    DWORD attr = kernel32::GetFileAttributesW(pszPath);
    if (attr == win32::INVALID_FILE_ATTRIBUTES) return win32::FALSE;
    return (attr & win32::FILE_ATTRIBUTE_DIRECTORY) ? win32::TRUE : win32::FALSE;
}

inline BOOL PathIsDirectoryA(LPCSTR pszPath) noexcept {
    DWORD attr = kernel32::GetFileAttributesA(pszPath);
    if (attr == win32::INVALID_FILE_ATTRIBUTES) return win32::FALSE;
    return (attr & win32::FILE_ATTRIBUTE_DIRECTORY) ? win32::TRUE : win32::FALSE;
}

// Case-insensitive sub-string and string comparison
inline PCWSTR StrStrIW(PCWSTR pszFirst, PCWSTR pszSrch) noexcept {
    if (!pszFirst || !pszSrch) return nullptr;
    if (!*pszSrch) return pszFirst;
    size_t lenSrch = std::wcslen(pszSrch);
    for (const wchar_t* p = pszFirst; *p; ++p) {
        if (_wcsnicmp(p, pszSrch, lenSrch) == 0) {
            return p;
        }
    }
    return nullptr;
}

inline PCSTR StrStrIA(PCSTR pszFirst, PCSTR pszSrch) noexcept {
    if (!pszFirst || !pszSrch) return nullptr;
    if (!*pszSrch) return pszFirst;
    size_t lenSrch = std::strlen(pszSrch);
    for (const char* p = pszFirst; *p; ++p) {
        if (_strnicmp(p, pszSrch, lenSrch) == 0) {
            return p;
        }
    }
    return nullptr;
}

inline int StrCmpIW(PCWSTR psz1, PCWSTR psz2) noexcept {
    if (!psz1 && !psz2) return 0;
    if (!psz1) return -1;
    if (!psz2) return 1;
    return _wcsicmp(psz1, psz2);
}

inline int StrCmpIA(PCSTR psz1, PCSTR psz2) noexcept {
    if (!psz1 && !psz2) return 0;
    if (!psz1) return -1;
    if (!psz2) return 1;
    return _stricmp(psz1, psz2);
}

// ============================================================================
// 3. Known Folders & Shell Directory Engine
// ============================================================================

class KnownFolderManager {
private:
    std::mutex m_mutex;
    std::unordered_map<int, std::wstring> m_csidlPaths;

    KnownFolderManager() {
        // Initialize canonical MicaNT NT 10.0 userland layout
        m_csidlPaths[CSIDL_WINDOWS]                 = L"C:\\Windows";
        m_csidlPaths[CSIDL_SYSTEM]                  = L"C:\\Windows\\System32";
        m_csidlPaths[CSIDL_SYSTEMX86]               = L"C:\\Windows\\SysWOW64";
        m_csidlPaths[CSIDL_FONTS]                   = L"C:\\Windows\\Fonts";
        m_csidlPaths[CSIDL_PROGRAM_FILES]           = L"C:\\Program Files";
        m_csidlPaths[CSIDL_PROGRAM_FILESX86]        = L"C:\\Program Files (x86)";
        m_csidlPaths[CSIDL_PROGRAM_FILES_COMMON]    = L"C:\\Program Files\\Common Files";
        m_csidlPaths[CSIDL_PROGRAM_FILES_COMMONX86] = L"C:\\Program Files (x86)\\Common Files";
        m_csidlPaths[CSIDL_COMMON_APPDATA]          = L"C:\\ProgramData";
        m_csidlPaths[CSIDL_PROFILE]                 = L"C:\\Users\\admin";
        m_csidlPaths[CSIDL_DESKTOP]                 = L"C:\\Users\\admin\\Desktop";
        m_csidlPaths[CSIDL_DESKTOPDIRECTORY]        = L"C:\\Users\\admin\\Desktop";
        m_csidlPaths[CSIDL_PERSONAL]                = L"C:\\Users\\admin\\Documents";
        m_csidlPaths[CSIDL_MYDOCUMENTS]             = L"C:\\Users\\admin\\Documents";
        m_csidlPaths[CSIDL_MYMUSIC]                 = L"C:\\Users\\admin\\Music";
        m_csidlPaths[CSIDL_MYPICTURES]              = L"C:\\Users\\admin\\Pictures";
        m_csidlPaths[CSIDL_MYVIDEO]                 = L"C:\\Users\\admin\\Videos";
        m_csidlPaths[CSIDL_APPDATA]                 = L"C:\\Users\\admin\\AppData\\Roaming";
        m_csidlPaths[CSIDL_LOCAL_APPDATA]           = L"C:\\Users\\admin\\AppData\\Local";
        m_csidlPaths[CSIDL_STARTMENU]               = L"C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu";
        m_csidlPaths[CSIDL_PROGRAMS]                = L"C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs";
        m_csidlPaths[CSIDL_STARTUP]                 = L"C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        m_csidlPaths[CSIDL_RECENT]                  = L"C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
        m_csidlPaths[CSIDL_SENDTO]                  = L"C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\SendTo";
        m_csidlPaths[CSIDL_FAVORITES]               = L"C:\\Users\\admin\\Favorites";
        m_csidlPaths[CSIDL_COMMON_STARTMENU]        = L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu";
        m_csidlPaths[CSIDL_COMMON_PROGRAMS]         = L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs";
        m_csidlPaths[CSIDL_COMMON_STARTUP]          = L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        m_csidlPaths[CSIDL_COMMON_DESKTOPDIRECTORY] = L"C:\\Users\\Public\\Desktop";
        m_csidlPaths[CSIDL_COMMON_DOCUMENTS]        = L"C:\\Users\\Public\\Documents";
    }

public:
    static KnownFolderManager& get() {
        static KnownFolderManager instance;
        return instance;
    }

    HRESULT getFolderPath(int csidl, bool create, std::wstring& outPath) {
        std::lock_guard<std::mutex> lock(m_mutex);
        int folderId = csidl & ~CSIDL_FLAG_MASK;

        auto it = m_csidlPaths.find(folderId);
        if (it == m_csidlPaths.end()) {
            return E_FAIL;
        }

        outPath = it->second;

        if (create) {
            fs::VirtualFileSystem::get().createDirectory(outPath);
        }

        return S_OK;
    }

    HRESULT getKnownFolderPath(REFKNOWNFOLDERID rfid, DWORD dwFlags, std::wstring& outPath) {
        bool create = (dwFlags & KF_FLAG_CREATE) != 0;

        if (rfid == FOLDERID_Desktop)            return getFolderPath(CSIDL_DESKTOP, create, outPath);
        if (rfid == FOLDERID_Documents)          return getFolderPath(CSIDL_PERSONAL, create, outPath);
        if (rfid == FOLDERID_Downloads) {
            outPath = L"C:\\Users\\admin\\Downloads";
            if (create) fs::VirtualFileSystem::get().createDirectory(outPath);
            return S_OK;
        }
        if (rfid == FOLDERID_Music)              return getFolderPath(CSIDL_MYMUSIC, create, outPath);
        if (rfid == FOLDERID_Pictures)           return getFolderPath(CSIDL_MYPICTURES, create, outPath);
        if (rfid == FOLDERID_Videos)             return getFolderPath(CSIDL_MYVIDEO, create, outPath);
        if (rfid == FOLDERID_ProgramFiles)       return getFolderPath(CSIDL_PROGRAM_FILES, create, outPath);
        if (rfid == FOLDERID_ProgramFilesX86)    return getFolderPath(CSIDL_PROGRAM_FILESX86, create, outPath);
        if (rfid == FOLDERID_Windows)            return getFolderPath(CSIDL_WINDOWS, create, outPath);
        if (rfid == FOLDERID_System)             return getFolderPath(CSIDL_SYSTEM, create, outPath);
        if (rfid == FOLDERID_Profile)            return getFolderPath(CSIDL_PROFILE, create, outPath);
        if (rfid == FOLDERID_LocalAppData)       return getFolderPath(CSIDL_LOCAL_APPDATA, create, outPath);
        if (rfid == FOLDERID_RoamingAppData)     return getFolderPath(CSIDL_APPDATA, create, outPath);

        return E_FAIL;
    }
};

inline HRESULT SHGetFolderPathW(
    HWND /*hwndOwner*/,
    int nFolder,
    win32::HANDLE /*hToken*/,
    DWORD /*dwFlags*/,
    LPWSTR pszPath
) noexcept {
    if (!pszPath) return E_INVALIDARG;
    bool create = (nFolder & CSIDL_FLAG_CREATE) != 0;
    std::wstring path;
    HRESULT hr = KnownFolderManager::get().getFolderPath(nFolder, create, path);
    if (hr == S_OK) {
        std::wcsncpy(pszPath, path.c_str(), 260);
        pszPath[259] = L'\0';
    }
    return hr;
}

inline HRESULT SHGetFolderPathA(
    HWND hwndOwner,
    int nFolder,
    win32::HANDLE hToken,
    DWORD dwFlags,
    LPSTR pszPath
) noexcept {
    if (!pszPath) return E_INVALIDARG;
    wchar_t wbuf[260]{};
    HRESULT hr = SHGetFolderPathW(hwndOwner, nFolder, hToken, dwFlags, wbuf);
    if (hr == S_OK) {
        for (int i = 0; i < 260; ++i) {
            pszPath[i] = static_cast<char>(wbuf[i] & 0x7F);
            if (wbuf[i] == L'\0') break;
        }
    }
    return hr;
}

inline BOOL SHGetSpecialFolderPathW(
    HWND hwndOwner,
    LPWSTR lpszPath,
    int csidl,
    BOOL fCreate
) noexcept {
    int flags = csidl | (fCreate ? CSIDL_FLAG_CREATE : 0);
    return (SHGetFolderPathW(hwndOwner, flags, nullptr, 0, lpszPath) == S_OK) ? win32::TRUE : win32::FALSE;
}

inline BOOL SHGetSpecialFolderPathA(
    HWND hwndOwner,
    LPSTR lpszPath,
    int csidl,
    BOOL fCreate
) noexcept {
    int flags = csidl | (fCreate ? CSIDL_FLAG_CREATE : 0);
    return (SHGetFolderPathA(hwndOwner, flags, nullptr, 0, lpszPath) == S_OK) ? win32::TRUE : win32::FALSE;
}

inline HRESULT SHGetKnownFolderPath(
    REFKNOWNFOLDERID rfid,
    DWORD dwFlags,
    win32::HANDLE /*hToken*/,
    PWSTR* ppszPath
) noexcept {
    if (!ppszPath) return E_INVALIDARG;
    *ppszPath = nullptr;

    std::wstring path;
    HRESULT hr = KnownFolderManager::get().getKnownFolderPath(rfid, dwFlags, path);
    if (hr != S_OK) return hr;

    size_t byteCount = (path.size() + 1) * sizeof(wchar_t);
    wchar_t* mem = static_cast<wchar_t*>(kernel32::LocalAlloc(kernel32::LPTR, byteCount));
    if (!mem) return static_cast<HRESULT>(0x8007000E); // E_OUTOFMEMORY

    std::memcpy(mem, path.c_str(), byteCount);
    *ppszPath = mem;
    return S_OK;
}

// ============================================================================
// 4. Command Line Parser (CommandLineToArgvW)
// ============================================================================

inline LPWSTR* CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs) noexcept {
    if (!pNumArgs) return nullptr;
    *pNumArgs = 0;
    if (!lpCmdLine) return nullptr;

    std::vector<std::wstring> args;
    const wchar_t* p = lpCmdLine;

    while (*p) {
        while (*p && (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n')) {
            ++p;
        }
        if (!*p) break;

        std::wstring arg;
        bool inQuotes = false;

        while (*p) {
            if (*p == L' ' || *p == L'\t') {
                if (!inQuotes) break;
                arg.push_back(*p++);
            } else if (*p == L'"') {
                inQuotes = !inQuotes;
                ++p;
            } else if (*p == L'\\') {
                size_t backslashes = 0;
                while (*p == L'\\') {
                    ++backslashes;
                    ++p;
                }
                if (*p == L'"') {
                    arg.append(backslashes / 2, L'\\');
                    if (backslashes % 2 != 0) {
                        arg.push_back(L'"');
                        ++p;
                    }
                } else {
                    arg.append(backslashes, L'\\');
                }
            } else {
                arg.push_back(*p++);
            }
        }
        args.push_back(std::move(arg));
    }

    if (args.empty()) {
        *pNumArgs = 0;
        return nullptr;
    }

    size_t numArgs = args.size();
    size_t totalChars = 0;
    for (const auto& a : args) {
        totalChars += a.size() + 1;
    }

    size_t totalBytes = (numArgs * sizeof(LPWSTR)) + (totalChars * sizeof(wchar_t));
    uint8_t* block = static_cast<uint8_t*>(kernel32::LocalAlloc(kernel32::LPTR, totalBytes));
    if (!block) return nullptr;

    LPWSTR* argv = reinterpret_cast<LPWSTR*>(block);
    wchar_t* strCursor = reinterpret_cast<wchar_t*>(block + (numArgs * sizeof(LPWSTR)));

    for (size_t i = 0; i < numArgs; ++i) {
        argv[i] = strCursor;
        std::memcpy(strCursor, args[i].c_str(), (args[i].size() + 1) * sizeof(wchar_t));
        strCursor += args[i].size() + 1;
    }

    *pNumArgs = static_cast<int>(numArgs);
    return argv;
}

// ============================================================================
// 5. System Tray Notification Icons (Shell_NotifyIcon)
// ============================================================================

struct TrayNotificationItem {
    HWND         hWnd{nullptr};
    UINT         uID{0};
    UINT         uFlags{0};
    UINT         uCallbackMessage{0};
    HICON        hIcon{nullptr};
    std::wstring szTip;
    std::wstring szInfo;
    std::wstring szInfoTitle;
    micant::GUID guidItem{};
};

class TrayNotificationManager {
private:
    std::mutex m_mutex;
    std::vector<TrayNotificationItem> m_icons;

    TrayNotificationManager() = default;

public:
    static TrayNotificationManager& get() {
        static TrayNotificationManager instance;
        return instance;
    }

    bool addIcon(const NOTIFYICONDATAW* pData) {
        if (!pData) return false;
        std::lock_guard<std::mutex> lock(m_mutex);

        for (const auto& item : m_icons) {
            if (item.hWnd == pData->hWnd && item.uID == pData->uID) {
                return false;
            }
        }

        TrayNotificationItem item{};
        item.hWnd = pData->hWnd;
        item.uID = pData->uID;
        item.uFlags = pData->uFlags;
        item.uCallbackMessage = pData->uCallbackMessage;
        item.hIcon = pData->hIcon;
        if (pData->uFlags & NIF_TIP) {
            item.szTip = pData->szTip;
        }
        if (pData->uFlags & NIF_INFO) {
            item.szInfo = pData->szInfo;
            item.szInfoTitle = pData->szInfoTitle;
        }
        item.guidItem = pData->guidItem;
        m_icons.push_back(std::move(item));
        return true;
    }

    bool modifyIcon(const NOTIFYICONDATAW* pData) {
        if (!pData) return false;
        std::lock_guard<std::mutex> lock(m_mutex);

        for (auto& item : m_icons) {
            if (item.hWnd == pData->hWnd && item.uID == pData->uID) {
                if (pData->uFlags & NIF_MESSAGE) item.uCallbackMessage = pData->uCallbackMessage;
                if (pData->uFlags & NIF_ICON) item.hIcon = pData->hIcon;
                if (pData->uFlags & NIF_TIP) item.szTip = pData->szTip;
                if (pData->uFlags & NIF_INFO) {
                    item.szInfo = pData->szInfo;
                    item.szInfoTitle = pData->szInfoTitle;
                }
                return true;
            }
        }
        return false;
    }

    bool deleteIcon(const NOTIFYICONDATAW* pData) {
        if (!pData) return false;
        std::lock_guard<std::mutex> lock(m_mutex);

        for (auto it = m_icons.begin(); it != m_icons.end(); ++it) {
            if (it->hWnd == pData->hWnd && it->uID == pData->uID) {
                m_icons.erase(it);
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] size_t getIconCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_icons.size();
    }
};

inline BOOL Shell_NotifyIconW(DWORD dwMessage, NOTIFYICONDATAW* lpData) noexcept {
    if (!lpData) return win32::FALSE;
    auto& mgr = TrayNotificationManager::get();

    switch (dwMessage) {
        case NIM_ADD:
            return mgr.addIcon(lpData) ? win32::TRUE : win32::FALSE;
        case NIM_MODIFY:
            return mgr.modifyIcon(lpData) ? win32::TRUE : win32::FALSE;
        case NIM_DELETE:
            return mgr.deleteIcon(lpData) ? win32::TRUE : win32::FALSE;
        case NIM_SETFOCUS:
        case NIM_SETVERSION:
            return win32::TRUE;
        default:
            return win32::FALSE;
    }
}

inline BOOL Shell_NotifyIconA(DWORD dwMessage, NOTIFYICONDATAA* lpData) noexcept {
    if (!lpData) return win32::FALSE;
    NOTIFYICONDATAW dataW{};
    dataW.cbSize = sizeof(dataW);
    dataW.hWnd = lpData->hWnd;
    dataW.uID = lpData->uID;
    dataW.uFlags = lpData->uFlags;
    dataW.uCallbackMessage = lpData->uCallbackMessage;
    dataW.hIcon = lpData->hIcon;
    dataW.guidItem = lpData->guidItem;

    if (lpData->uFlags & NIF_TIP) {
        for (int i = 0; i < 128; ++i) {
            dataW.szTip[i] = static_cast<wchar_t>(lpData->szTip[i]);
            if (!lpData->szTip[i]) break;
        }
    }
    if (lpData->uFlags & NIF_INFO) {
        for (int i = 0; i < 256; ++i) {
            dataW.szInfo[i] = static_cast<wchar_t>(lpData->szInfo[i]);
            if (!lpData->szInfo[i]) break;
        }
        for (int i = 0; i < 64; ++i) {
            dataW.szInfoTitle[i] = static_cast<wchar_t>(lpData->szInfoTitle[i]);
            if (!lpData->szInfoTitle[i]) break;
        }
    }

    return Shell_NotifyIconW(dwMessage, &dataW);
}

// ============================================================================
// 6. Shell Execution Engine (ShellExecute & ShellExecuteEx)
// ============================================================================

inline BOOL ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo) noexcept {
    if (!pExecInfo || pExecInfo->cbSize < sizeof(SHELLEXECUTEINFOW)) return win32::FALSE;
    if (!pExecInfo->lpFile || !*pExecInfo->lpFile) return win32::FALSE;

    std::wstring cmd = pExecInfo->lpFile;
    if (pExecInfo->lpParameters && *pExecInfo->lpParameters) {
        cmd += L" ";
        cmd += pExecInfo->lpParameters;
    }

    win32::STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = 0x00000001; // STARTF_USESHOWWINDOW
    si.wShowWindow = static_cast<uint16_t>(pExecInfo->nShow);

    win32::PROCESS_INFORMATION pi{};
    BOOL ok = kernel32::CreateProcessW(
        pExecInfo->lpFile,
        cmd.data(),
        nullptr,
        nullptr,
        win32::FALSE,
        0,
        nullptr,
        pExecInfo->lpDirectory,
        &si,
        &pi
    );

    if (ok) {
        pExecInfo->hInstApp = reinterpret_cast<HINSTANCE>(42);
        if (pExecInfo->fMask & SEE_MASK_NOCLOSEPROCESS) {
            pExecInfo->hProcess = pi.hProcess;
        } else {
            kernel32::CloseHandle(pi.hProcess);
        }
        kernel32::CloseHandle(pi.hThread);
        return win32::TRUE;
    }

    pExecInfo->hInstApp = reinterpret_cast<HINSTANCE>(2); // ERROR_FILE_NOT_FOUND
    return win32::FALSE;
}

inline BOOL ShellExecuteExA(SHELLEXECUTEINFOA* pExecInfo) noexcept {
    if (!pExecInfo) return win32::FALSE;
    SHELLEXECUTEINFOW seiW{};
    seiW.cbSize = sizeof(seiW);
    seiW.fMask = pExecInfo->fMask;
    seiW.hwnd = pExecInfo->hwnd;
    seiW.nShow = pExecInfo->nShow;

    std::wstring wFile, wVerb, wParams, wDir;
    if (pExecInfo->lpFile) {
        wFile.assign(pExecInfo->lpFile, pExecInfo->lpFile + std::strlen(pExecInfo->lpFile));
        seiW.lpFile = wFile.c_str();
    }
    if (pExecInfo->lpVerb) {
        wVerb.assign(pExecInfo->lpVerb, pExecInfo->lpVerb + std::strlen(pExecInfo->lpVerb));
        seiW.lpVerb = wVerb.c_str();
    }
    if (pExecInfo->lpParameters) {
        wParams.assign(pExecInfo->lpParameters, pExecInfo->lpParameters + std::strlen(pExecInfo->lpParameters));
        seiW.lpParameters = wParams.c_str();
    }
    if (pExecInfo->lpDirectory) {
        wDir.assign(pExecInfo->lpDirectory, pExecInfo->lpDirectory + std::strlen(pExecInfo->lpDirectory));
        seiW.lpDirectory = wDir.c_str();
    }

    BOOL res = ShellExecuteExW(&seiW);
    pExecInfo->hInstApp = seiW.hInstApp;
    pExecInfo->hProcess = seiW.hProcess;
    return res;
}

inline HINSTANCE ShellExecuteW(
    HWND hwnd,
    LPCWSTR lpOperation,
    LPCWSTR lpFile,
    LPCWSTR lpParameters,
    LPCWSTR lpDirectory,
    int nShowCmd
) noexcept {
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.hwnd = hwnd;
    sei.lpVerb = lpOperation;
    sei.lpFile = lpFile;
    sei.lpParameters = lpParameters;
    sei.lpDirectory = lpDirectory;
    sei.nShow = nShowCmd;
    ShellExecuteExW(&sei);
    return sei.hInstApp;
}

inline HINSTANCE ShellExecuteA(
    HWND hwnd,
    LPCSTR lpOperation,
    LPCSTR lpFile,
    LPCSTR lpParameters,
    LPCSTR lpDirectory,
    int nShowCmd
) noexcept {
    SHELLEXECUTEINFOA sei{};
    sei.cbSize = sizeof(sei);
    sei.hwnd = hwnd;
    sei.lpVerb = lpOperation;
    sei.lpFile = lpFile;
    sei.lpParameters = lpParameters;
    sei.lpDirectory = lpDirectory;
    sei.nShow = nShowCmd;
    ShellExecuteExA(&sei);
    return sei.hInstApp;
}

// ============================================================================
// 7. Shell File Information & Icon Extraction
// ============================================================================

inline DWORD_PTR SHGetFileInfoW(
    LPCWSTR pszPath,
    DWORD /*dwFileAttributes*/,
    SHFILEINFOW* psfi,
    UINT cbFileInfo,
    UINT uFlags
) noexcept {
    if (!psfi || cbFileInfo < sizeof(SHFILEINFOW) || !pszPath) return 0;
    std::memset(psfi, 0, sizeof(SHFILEINFOW));

    if (uFlags & SHGFI_DISPLAYNAME) {
        const wchar_t* fn = PathFindFileNameW(pszPath);
        if (fn) {
            std::wcsncpy(psfi->szDisplayName, fn, 260);
        }
    }
    if (uFlags & SHGFI_TYPENAME) {
        const wchar_t* ext = PathFindExtensionW(pszPath);
        if (ext && _wcsicmp(ext, L".exe") == 0) {
            std::wcsncpy(psfi->szTypeName, L"Application", 80);
        } else if (ext && _wcsicmp(ext, L".dll") == 0) {
            std::wcsncpy(psfi->szTypeName, L"Application Extension", 80);
        } else {
            std::wcsncpy(psfi->szTypeName, L"File", 80);
        }
    }
    if (uFlags & SHGFI_ICON) {
        psfi->hIcon = reinterpret_cast<HICON>(0x1001);
    }
    return 1;
}

inline DWORD_PTR SHGetFileInfoA(
    LPCSTR pszPath,
    DWORD dwFileAttributes,
    SHFILEINFOA* psfi,
    UINT cbFileInfo,
    UINT uFlags
) noexcept {
    if (!psfi || cbFileInfo < sizeof(SHFILEINFOA) || !pszPath) return 0;
    std::wstring wPath(pszPath, pszPath + std::strlen(pszPath));
    SHFILEINFOW sfiW{};
    DWORD_PTR res = SHGetFileInfoW(wPath.c_str(), dwFileAttributes, &sfiW, sizeof(sfiW), uFlags);
    if (res) {
        psfi->hIcon = sfiW.hIcon;
        psfi->iIcon = sfiW.iIcon;
        psfi->dwAttributes = sfiW.dwAttributes;
        for (int i = 0; i < 260; ++i) {
            psfi->szDisplayName[i] = static_cast<char>(sfiW.szDisplayName[i] & 0x7F);
            if (!sfiW.szDisplayName[i]) break;
        }
        for (int i = 0; i < 80; ++i) {
            psfi->szTypeName[i] = static_cast<char>(sfiW.szTypeName[i] & 0x7F);
            if (!sfiW.szTypeName[i]) break;
        }
    }
    return res;
}

inline HICON ExtractIconW(HINSTANCE /*hInst*/, LPCWSTR /*lpszExeFileName*/, UINT /*nIconIndex*/) noexcept {
    return reinterpret_cast<HICON>(0x1002);
}

inline HICON ExtractIconA(HINSTANCE hInst, LPCSTR lpszExeFileName, UINT nIconIndex) noexcept {
    if (!lpszExeFileName) return nullptr;
    std::wstring wFile(lpszExeFileName, lpszExeFileName + std::strlen(lpszExeFileName));
    return ExtractIconW(hInst, wFile.c_str(), nIconIndex);
}

// ============================================================================
// 8. Subsystem Export Registration (shell32.dll & shlwapi.dll)
// ============================================================================

inline void InitializeShell32SubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // shell32.dll exports
    ldr.registerExport("shell32.dll", "SHGetFolderPathW", reinterpret_cast<void*>(SHGetFolderPathW));
    ldr.registerExport("shell32.dll", "SHGetFolderPathA", reinterpret_cast<void*>(SHGetFolderPathA));
    ldr.registerExport("shell32.dll", "SHGetSpecialFolderPathW", reinterpret_cast<void*>(SHGetSpecialFolderPathW));
    ldr.registerExport("shell32.dll", "SHGetSpecialFolderPathA", reinterpret_cast<void*>(SHGetSpecialFolderPathA));
    ldr.registerExport("shell32.dll", "SHGetKnownFolderPath", reinterpret_cast<void*>(SHGetKnownFolderPath));
    ldr.registerExport("shell32.dll", "CommandLineToArgvW", reinterpret_cast<void*>(CommandLineToArgvW));
    ldr.registerExport("shell32.dll", "ShellExecuteW", reinterpret_cast<void*>(ShellExecuteW));
    ldr.registerExport("shell32.dll", "ShellExecuteA", reinterpret_cast<void*>(ShellExecuteA));
    ldr.registerExport("shell32.dll", "ShellExecuteExW", reinterpret_cast<void*>(ShellExecuteExW));
    ldr.registerExport("shell32.dll", "ShellExecuteExA", reinterpret_cast<void*>(ShellExecuteExA));
    ldr.registerExport("shell32.dll", "Shell_NotifyIconW", reinterpret_cast<void*>(Shell_NotifyIconW));
    ldr.registerExport("shell32.dll", "Shell_NotifyIconA", reinterpret_cast<void*>(Shell_NotifyIconA));
    ldr.registerExport("shell32.dll", "SHGetFileInfoW", reinterpret_cast<void*>(SHGetFileInfoW));
    ldr.registerExport("shell32.dll", "SHGetFileInfoA", reinterpret_cast<void*>(SHGetFileInfoA));
    ldr.registerExport("shell32.dll", "ExtractIconW", reinterpret_cast<void*>(ExtractIconW));
    ldr.registerExport("shell32.dll", "ExtractIconA", reinterpret_cast<void*>(ExtractIconA));

    // shlwapi.dll exports
    ldr.registerExport("shlwapi.dll", "PathFileExistsW", reinterpret_cast<void*>(PathFileExistsW));
    ldr.registerExport("shlwapi.dll", "PathFileExistsA", reinterpret_cast<void*>(PathFileExistsA));
    ldr.registerExport("shlwapi.dll", "PathCombineW", reinterpret_cast<void*>(PathCombineW));
    ldr.registerExport("shlwapi.dll", "PathCombineA", reinterpret_cast<void*>(PathCombineA));
    ldr.registerExport("shlwapi.dll", "PathFindFileNameW", reinterpret_cast<void*>(PathFindFileNameW));
    ldr.registerExport("shlwapi.dll", "PathFindFileNameA", reinterpret_cast<void*>(PathFindFileNameA));
    ldr.registerExport("shlwapi.dll", "PathFindExtensionW", reinterpret_cast<void*>(PathFindExtensionW));
    ldr.registerExport("shlwapi.dll", "PathFindExtensionA", reinterpret_cast<void*>(PathFindExtensionA));
    ldr.registerExport("shlwapi.dll", "PathRemoveFileSpecW", reinterpret_cast<void*>(PathRemoveFileSpecW));
    ldr.registerExport("shlwapi.dll", "PathRemoveFileSpecA", reinterpret_cast<void*>(PathRemoveFileSpecA));
    ldr.registerExport("shlwapi.dll", "PathAddBackslashW", reinterpret_cast<void*>(PathAddBackslashW));
    ldr.registerExport("shlwapi.dll", "PathAddBackslashA", reinterpret_cast<void*>(PathAddBackslashA));
    ldr.registerExport("shlwapi.dll", "PathIsRelativeW", reinterpret_cast<void*>(PathIsRelativeW));
    ldr.registerExport("shlwapi.dll", "PathIsRelativeA", reinterpret_cast<void*>(PathIsRelativeA));
    ldr.registerExport("shlwapi.dll", "PathIsDirectoryW", reinterpret_cast<void*>(PathIsDirectoryW));
    ldr.registerExport("shlwapi.dll", "PathIsDirectoryA", reinterpret_cast<void*>(PathIsDirectoryA));
    ldr.registerExport("shlwapi.dll", "StrStrIW", reinterpret_cast<void*>(StrStrIW));
    ldr.registerExport("shlwapi.dll", "StrStrIA", reinterpret_cast<void*>(StrStrIA));
    ldr.registerExport("shlwapi.dll", "StrCmpIW", reinterpret_cast<void*>(StrCmpIW));
    ldr.registerExport("shlwapi.dll", "StrCmpIA", reinterpret_cast<void*>(StrCmpIA));
}

} // namespace micant::shell32
