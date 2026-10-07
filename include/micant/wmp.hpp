#pragma once

#include <micant/ntdef.hpp>
#include <micant/ole32.hpp>
#include <micant/oleaut32.hpp>
#include <micant/ldr.hpp>
#include <micant/version.hpp>

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <cstring>
#include <algorithm>
#include <functional>
#include <cmath>
#include <sstream>
#include <iomanip>

namespace micant::wmp {

// ============================================================================
// 1. Windows Media Player Constants, Enums & HRESULT Codes
// ============================================================================

enum WMPPlayState {
    wmppsUndefined      = 0,
    wmppsStopped        = 1,
    wmppsPaused         = 2,
    wmppsPlaying        = 3,
    wmppsScanForward    = 4,
    wmppsScanReverse    = 5,
    wmppsBuffering      = 6,
    wmppsWaiting        = 7,
    wmppsMediaEnded     = 8,
    wmppsTransitioning  = 9,
    wmppsReady          = 10,
    wmppsReconnecting   = 11,
    wmppsLast           = 12
};

enum WMPOpenState {
    wmposUndefined              = 0,
    wmposPlaylistChanging       = 1,
    wmposPlaylistLocating       = 2,
    wmposPlaylistConnecting     = 3,
    wmposPlaylistLoading        = 4,
    wmposPlaylistOpening        = 5,
    wmposPlaylistOpenNoMedia    = 6,
    wmposPlaylistChanged        = 7,
    wmposMediaChanging          = 8,
    wmposMediaLocating          = 9,
    wmposMediaConnecting        = 10,
    wmposMediaLoading           = 11,
    wmposMediaOpening           = 12,
    wmposMediaOpen              = 13,
    wmposBeginCodecAcquisition  = 14,
    wmposEndCodecAcquisition    = 15,
    wmposBeginLicenseAcquisition= 16,
    wmposEndLicenseAcquisition  = 17,
    wmposBeginIndividualization = 18,
    wmposEndIndividualization   = 19,
    wmposMediaWaiting           = 20,
    wmposOpeningUnknownURL      = 21
};

inline const char* WMPPlayStateToString(WMPPlayState s) {
    switch (s) {
        case wmppsUndefined: return "Undefined";
        case wmppsStopped: return "Stopped";
        case wmppsPaused: return "Paused";
        case wmppsPlaying: return "Playing";
        case wmppsScanForward: return "ScanForward";
        case wmppsScanReverse: return "ScanReverse";
        case wmppsBuffering: return "Buffering";
        case wmppsWaiting: return "Waiting";
        case wmppsMediaEnded: return "MediaEnded";
        case wmppsTransitioning: return "Transitioning";
        case wmppsReady: return "Ready";
        case wmppsReconnecting: return "Reconnecting";
        case wmppsLast: return "Last";
        default: return "Unknown";
    }
}

// ActiveMovie Multimedia Stream Constants & Flags
enum STREAM_TYPE {
    STREAMTYPE_READ      = 0,
    STREAMTYPE_WRITE     = 1,
    STREAMTYPE_TRANSFORM = 2
};

enum STREAM_STATE {
    STREAMSTATE_STOP = 0,
    STREAMSTATE_RUN  = 1
};

inline constexpr uint32_t AMMSF_NONSAMPLE        = 0x00000001;
inline constexpr uint32_t AMMSF_RENDERTYPEMASK   = 0x00000003;
inline constexpr uint32_t AMMSF_RENDERALLSTREAMS = 0x00000002;
inline constexpr uint32_t AMMSF_NORENDER         = 0x00000004;
inline constexpr uint32_t AMMSF_NOCLOCK          = 0x00000008;
inline constexpr uint32_t AMMSF_RUN              = 0x00000010;

// Windows Media Player Error Codes
inline constexpr int32_t NS_E_CANNOT_READ_MEDIA       = static_cast<int32_t>(0xC00D0001);
inline constexpr int32_t NS_E_NO_MORE_ITEMS           = static_cast<int32_t>(0xC00D0002);
inline constexpr int32_t NS_E_NOT_AVAILABLE           = static_cast<int32_t>(0xC00D0003);

// ActiveMovie Stream Error Codes
inline constexpr int32_t MS_S_PENDING                 = static_cast<int32_t>(0x00040001);
inline constexpr int32_t MS_S_NOUPDATE                = static_cast<int32_t>(0x00040002);
inline constexpr int32_t MS_S_ENDOFSTREAM             = static_cast<int32_t>(0x00040003);
inline constexpr int32_t MS_E_SAMPLEALLOC             = static_cast<int32_t>(0x80040401);
inline constexpr int32_t MS_E_PURPOSEID               = static_cast<int32_t>(0x80040402);
inline constexpr int32_t MS_E_NOSTREAM                = static_cast<int32_t>(0x80040403);
inline constexpr int32_t MS_E_NOSTREAMS               = static_cast<int32_t>(0x80040404);
inline constexpr int32_t MS_E_INCOMPATIBLE            = static_cast<int32_t>(0x80040405);
inline constexpr int32_t MS_E_BUSY                    = static_cast<int32_t>(0x80040406);
inline constexpr int32_t MS_E_NOTRUNNING              = static_cast<int32_t>(0x80040407);

// ============================================================================
// 2. COM Class & Interface Identifiers (CLSIDs / IIDs)
// ============================================================================

// CLSID_WindowsMediaPlayer = {6BF52A52-394A-11d3-B153-00C04F79FAA6}
inline constexpr GUID CLSID_WindowsMediaPlayer =
    { 0x6BF52A52, 0x394A, 0x11D3, { 0xB1, 0x53, 0x00, 0xC0, 0x4F, 0x79, 0xFA, 0xA6 } };

// IID_IWMPCore = {D8487774-6007-4EB3-A65B-61E14B21337B}
inline constexpr GUID IID_IWMPCore =
    { 0xD8487774, 0x6007, 0x4EB3, { 0xA6, 0x5B, 0x61, 0xE1, 0x4B, 0x21, 0x33, 0x7B } };

// IID_IWMPPlayer = {6BF52A4F-394A-11d3-B153-00C04F79FAA6}
inline constexpr GUID IID_IWMPPlayer =
    { 0x6BF52A4F, 0x394A, 0x11D3, { 0xB1, 0x53, 0x00, 0xC0, 0x4F, 0x79, 0xFA, 0xA6 } };

// IID_IWMPPlayer4 = {6C497D62-8919-4190-822D-FF76218B82A7}
inline constexpr GUID IID_IWMPPlayer4 =
    { 0x6C497D62, 0x8919, 0x4190, { 0x82, 0x2D, 0xFF, 0x76, 0x21, 0x8B, 0x82, 0xA7 } };

// IID_IWMPControls = {743496D0-C4D5-4D56-BE30-F8E30E03E48E}
inline constexpr GUID IID_IWMPControls =
    { 0x743496D0, 0xC4D5, 0x4D56, { 0xBE, 0x30, 0xF8, 0xE3, 0x0E, 0x03, 0xE4, 0x8E } };

// IID_IWMPSettings = {9104D01A-80D9-4261-B570-3B3F1A560F04}
inline constexpr GUID IID_IWMPSettings =
    { 0x9104D01A, 0x80D9, 0x4261, { 0xB5, 0x70, 0x3B, 0x3F, 0x1A, 0x56, 0x0F, 0x04 } };

// IID_IWMPMedia = {94D6D784-AD87-4D30-BE07-E401FF6048BC}
inline constexpr GUID IID_IWMPMedia =
    { 0x94D6D784, 0xAD87, 0x4D30, { 0xBE, 0x07, 0xE4, 0x01, 0xFF, 0x60, 0x48, 0xBC } };

// IID_IWMPPlaylist = {4F217460-FA80-4528-9DD2-1A326EED49FB}
inline constexpr GUID IID_IWMPPlaylist =
    { 0x4F217460, 0xFA80, 0x4528, { 0x9D, 0xD2, 0x1A, 0x32, 0x6E, 0xED, 0x49, 0xFB } };

// IID_IWMPPlaylistArray = {67964AEE-7CBD-436B-96B8-FB793F43A1A4}
inline constexpr GUID IID_IWMPPlaylistArray =
    { 0x67964AEE, 0x7CBD, 0x436B, { 0x96, 0xB8, 0xFB, 0x79, 0x3F, 0x43, 0xA1, 0xA4 } };

// IID_IWMPMediaCollection = {839622D0-087C-41E1-8B73-D45040F33194}
inline constexpr GUID IID_IWMPMediaCollection =
    { 0x839622D0, 0x087C, 0x41E1, { 0x8B, 0x73, 0xD4, 0x50, 0x40, 0xF3, 0x31, 0x94 } };

// IID_IWMPPlaylistCollection = {10A165B6-D365-45BC-96AB-B122B5C62CE0}
inline constexpr GUID IID_IWMPPlaylistCollection =
    { 0x10A165B6, 0xD365, 0x45BC, { 0x96, 0xAB, 0xB1, 0x22, 0xB5, 0xC6, 0x2C, 0xE0 } };

// IID_IWMPCdromCollection = {CFAB6E98-8730-11D3-B388-00C04F68574B}
inline constexpr GUID IID_IWMPCdromCollection =
    { 0xCFAB6E98, 0x8730, 0x11D3, { 0xB3, 0x88, 0x00, 0xC0, 0x4F, 0x68, 0x57, 0x4B } };

// IID_IWMPClosedCaption = {4F217460-FA80-4528-9DD2-1A326EED49FA}
inline constexpr GUID IID_IWMPClosedCaption =
    { 0x4F217460, 0xFA80, 0x4528, { 0x9D, 0xD2, 0x1A, 0x32, 0x6E, 0xED, 0x49, 0xFA } };

// IID_IWMPEvents = {19A6627B-DA9E-47C1-BB23-00B5E668236A}
inline constexpr GUID IID_IWMPEvents =
    { 0x19A6627B, 0xDA9E, 0x47C1, { 0xBB, 0x23, 0x00, 0xB5, 0xE6, 0x68, 0x23, 0x6A } };

// ActiveMovie Multimedia Stream CLSIDs / IIDs
// CLSID_AMMultiMediaStream = {49C47960-2019-11D0-9E16-0000C07632C3}
inline constexpr GUID CLSID_AMMultiMediaStream =
    { 0x49C47960, 0x2019, 0x11D0, { 0x9E, 0x16, 0x00, 0x00, 0xC0, 0x76, 0x32, 0xC3 } };

// IID_IAMMultiMediaStream = {BEBE595C-9A16-11D0-8FDE-00C04FD9189D}
inline constexpr GUID IID_IAMMultiMediaStream =
    { 0xBEBE595C, 0x9A16, 0x11D0, { 0x8F, 0xDE, 0x00, 0xC0, 0x4F, 0xD9, 0x18, 0x9D } };

// IID_IMultiMediaStream = {B502D1BC-9A1D-11D0-8FDE-00C04FD9189D}
inline constexpr GUID IID_IMultiMediaStream =
    { 0xB502D1BC, 0x9A1D, 0x11D0, { 0x8F, 0xDE, 0x00, 0xC0, 0x4F, 0xD9, 0x18, 0x9D } };

// IID_IMediaStream = {B502D1BD-9A1D-11D0-8FDE-00C04FD9189D}
inline constexpr GUID IID_IMediaStream =
    { 0xB502D1BD, 0x9A1D, 0x11D0, { 0x8F, 0xDE, 0x00, 0xC0, 0x4F, 0xD9, 0x18, 0x9D } };

// IID_IDirectDrawMediaStream = {F4104FCE-9A70-11D0-8FDE-00C04FD9189D}
inline constexpr GUID IID_IDirectDrawMediaStream =
    { 0xF4104FCE, 0x9A70, 0x11D0, { 0x8F, 0xDE, 0x00, 0xC0, 0x4F, 0xD9, 0x18, 0x9D } };

// IID_IAudioMediaStream = {F4104FCF-9A70-11D0-8FDE-00C04FD9189D}
inline constexpr GUID IID_IAudioMediaStream =
    { 0xF4104FCF, 0x9A70, 0x11D0, { 0x8F, 0xDE, 0x00, 0xC0, 0x4F, 0xD9, 0x18, 0x9D } };

// IID_IStreamSample = {B502D1BE-9A1D-11D0-8FDE-00C04FD9189D}
inline constexpr GUID IID_IStreamSample =
    { 0xB502D1BE, 0x9A1D, 0x11D0, { 0x8F, 0xDE, 0x00, 0xC0, 0x4F, 0xD9, 0x18, 0x9D } };

// Stream Purpose IDs (MSPID)
inline constexpr GUID MSPID_PrimaryVideo =
    { 0xA35FF56A, 0x9FDA, 0x11D0, { 0x8F, 0xDF, 0x00, 0xC0, 0x4F, 0xD9, 0x18, 0x9D } };

inline constexpr GUID MSPID_PrimaryAudio =
    { 0xA35FF56B, 0x9FDA, 0x11D0, { 0x8F, 0xDF, 0x00, 0xC0, 0x4F, 0xD9, 0x18, 0x9D } };

// ============================================================================
// 3. COM Interface Declarations
// ============================================================================

struct IWMPMedia;
struct IWMPPlaylist;
struct IWMPControls;
struct IWMPSettings;
struct IWMPMediaCollection;
struct IWMPPlaylistCollection;
struct IWMPCdromCollection;
struct IWMPClosedCaption;
struct IMediaStream;
struct IStreamSample;

struct IWMPMedia : public ole32::IDispatch {
    virtual int32_t __stdcall get_isIdentical(IWMPMedia* pIWMPMedia, int32_t* pvbool) = 0;
    virtual int32_t __stdcall get_sourceURL(ole32::BSTR* pbstrSourceURL) = 0;
    virtual int32_t __stdcall get_name(ole32::BSTR* pbstrName) = 0;
    virtual int32_t __stdcall put_name(ole32::BSTR bstrName) = 0;
    virtual int32_t __stdcall get_imageSourceWidth(int32_t* pWidth) = 0;
    virtual int32_t __stdcall get_imageSourceHeight(int32_t* pHeight) = 0;
    virtual int32_t __stdcall get_duration(double* pDuration) = 0;
    virtual int32_t __stdcall get_durationString(ole32::BSTR* pbstrDuration) = 0;
    virtual int32_t __stdcall get_attributeCount(int32_t* plCount) = 0;
    virtual int32_t __stdcall getAttributeName(int32_t lIndex, ole32::BSTR* pbstrItemName) = 0;
    virtual int32_t __stdcall getItemInfo(ole32::BSTR bstrItemName, ole32::BSTR* pbstrVal) = 0;
    virtual int32_t __stdcall setItemInfo(ole32::BSTR bstrItemName, ole32::BSTR bstrVal) = 0;
    virtual int32_t __stdcall getItemInfoByType(ole32::BSTR bstrItemName, ole32::BSTR bstrType, int32_t lLangID, ole32::VARIANT* pvarValue) = 0;
    virtual int32_t __stdcall isMemberOf(IWMPPlaylist* pPlaylist, int32_t* pvarf) = 0;
    virtual int32_t __stdcall isReadOnlyItem(ole32::BSTR bstrItemName, int32_t* pvarf) = 0;
};

struct IWMPPlaylist : public ole32::IDispatch {
    virtual int32_t __stdcall get_count(int32_t* plCount) = 0;
    virtual int32_t __stdcall get_name(ole32::BSTR* pbstrName) = 0;
    virtual int32_t __stdcall put_name(ole32::BSTR bstrName) = 0;
    virtual int32_t __stdcall get_attributeCount(int32_t* plCount) = 0;
    virtual int32_t __stdcall get_attributeName(int32_t lIndex, ole32::BSTR* pbstrAttributeName) = 0;
    virtual int32_t __stdcall get_Item(int32_t lIndex, IWMPMedia** ppIWMPMedia) = 0;
    virtual int32_t __stdcall getItemInfo(ole32::BSTR bstrName, ole32::BSTR* pbstrVal) = 0;
    virtual int32_t __stdcall setItemInfo(ole32::BSTR bstrName, ole32::BSTR bstrValue) = 0;
    virtual int32_t __stdcall get_isIdentical(IWMPPlaylist* pIWMPPlaylist, int32_t* pvbool) = 0;
    virtual int32_t __stdcall clear() = 0;
    virtual int32_t __stdcall insertItem(int32_t lIndex, IWMPMedia* pIWMPMedia) = 0;
    virtual int32_t __stdcall appendItem(IWMPMedia* pIWMPMedia) = 0;
    virtual int32_t __stdcall removeItem(IWMPMedia* pIWMPMedia) = 0;
    virtual int32_t __stdcall moveItem(int32_t lIndexOld, int32_t lIndexNew) = 0;
};

struct IWMPControls : public ole32::IDispatch {
    virtual int32_t __stdcall get_isAvailable(ole32::BSTR bstrItem, int32_t* pIsAvailable) = 0;
    virtual int32_t __stdcall play() = 0;
    virtual int32_t __stdcall stop() = 0;
    virtual int32_t __stdcall pause() = 0;
    virtual int32_t __stdcall fastForward() = 0;
    virtual int32_t __stdcall fastReverse() = 0;
    virtual int32_t __stdcall get_currentPosition(double* pdCurrentPosition) = 0;
    virtual int32_t __stdcall put_currentPosition(double dCurrentPosition) = 0;
    virtual int32_t __stdcall get_currentPositionString(ole32::BSTR* pbstrCurrentPosition) = 0;
    virtual int32_t __stdcall next() = 0;
    virtual int32_t __stdcall previous() = 0;
    virtual int32_t __stdcall get_currentItem(IWMPMedia** ppIWMPMedia) = 0;
    virtual int32_t __stdcall put_currentItem(IWMPMedia* pIWMPMedia) = 0;
    virtual int32_t __stdcall get_currentMarker(int32_t* plMarker) = 0;
    virtual int32_t __stdcall put_currentMarker(int32_t lMarker) = 0;
    virtual int32_t __stdcall playItem(IWMPMedia* pIWMPMedia) = 0;
};

struct IWMPSettings : public ole32::IDispatch {
    virtual int32_t __stdcall get_isAvailable(ole32::BSTR bstrItem, int32_t* pIsAvailable) = 0;
    virtual int32_t __stdcall get_autoStart(int32_t* pfAutoStart) = 0;
    virtual int32_t __stdcall put_autoStart(int32_t fAutoStart) = 0;
    virtual int32_t __stdcall get_baseURL(ole32::BSTR* pbstrBaseURL) = 0;
    virtual int32_t __stdcall put_baseURL(ole32::BSTR bstrBaseURL) = 0;
    virtual int32_t __stdcall get_defaultFrame(ole32::BSTR* pbstrDefaultFrame) = 0;
    virtual int32_t __stdcall put_defaultFrame(ole32::BSTR bstrDefaultFrame) = 0;
    virtual int32_t __stdcall get_invokeURLs(int32_t* pfInvokeURLs) = 0;
    virtual int32_t __stdcall put_invokeURLs(int32_t fInvokeURLs) = 0;
    virtual int32_t __stdcall get_enableErrorDialogs(int32_t* pfEnableErrorDialogs) = 0;
    virtual int32_t __stdcall put_enableErrorDialogs(int32_t fEnableErrorDialogs) = 0;
    virtual int32_t __stdcall get_mode(ole32::BSTR bstrMode, int32_t* pvarfMode) = 0;
    virtual int32_t __stdcall setMode(ole32::BSTR bstrMode, int32_t varfMode) = 0;
    virtual int32_t __stdcall get_volume(int32_t* plVolume) = 0;
    virtual int32_t __stdcall put_volume(int32_t lVolume) = 0;
    virtual int32_t __stdcall get_balance(int32_t* plBalance) = 0;
    virtual int32_t __stdcall put_balance(int32_t lBalance) = 0;
    virtual int32_t __stdcall get_playCount(int32_t* plCount) = 0;
    virtual int32_t __stdcall put_playCount(int32_t lCount) = 0;
    virtual int32_t __stdcall get_rate(double* pdRate) = 0;
    virtual int32_t __stdcall put_rate(double dRate) = 0;
};

struct IWMPCore : public ole32::IDispatch {
    virtual int32_t __stdcall close() = 0;
    virtual int32_t __stdcall get_URL(ole32::BSTR* pbstrURL) = 0;
    virtual int32_t __stdcall put_URL(ole32::BSTR bstrURL) = 0;
    virtual int32_t __stdcall get_openState(WMPOpenState* pwmpos) = 0;
    virtual int32_t __stdcall get_playState(WMPPlayState* pwmpps) = 0;
    virtual int32_t __stdcall get_controls(IWMPControls** ppControl) = 0;
    virtual int32_t __stdcall get_settings(IWMPSettings** ppSettings) = 0;
    virtual int32_t __stdcall get_currentMedia(IWMPMedia** ppMedia) = 0;
    virtual int32_t __stdcall put_currentMedia(IWMPMedia* pMedia) = 0;
    virtual int32_t __stdcall get_mediaCollection(IWMPMediaCollection** ppMediaCollection) = 0;
    virtual int32_t __stdcall get_playlistCollection(IWMPPlaylistCollection** ppPlaylistCollection) = 0;
    virtual int32_t __stdcall get_versionInfo(ole32::BSTR* pbstrVersionInfo) = 0;
    virtual int32_t __stdcall launchURL(ole32::BSTR bstrURL) = 0;
    virtual int32_t __stdcall get_network(ole32::IDispatch** ppNetwork) = 0;
    virtual int32_t __stdcall get_currentPlaylist(IWMPPlaylist** ppPlaylist) = 0;
    virtual int32_t __stdcall put_currentPlaylist(IWMPPlaylist* pPlaylist) = 0;
    virtual int32_t __stdcall get_cdromCollection(IWMPCdromCollection** ppCdromCollection) = 0;
    virtual int32_t __stdcall get_closedCaption(IWMPClosedCaption** ppClosedCaption) = 0;
};

struct IWMPPlayer : public IWMPCore {
    virtual int32_t __stdcall get_enabled(int32_t* pbEnabled) = 0;
    virtual int32_t __stdcall put_enabled(int32_t bEnabled) = 0;
    virtual int32_t __stdcall get_fullScreen(int32_t* pbFullScreen) = 0;
    virtual int32_t __stdcall put_fullScreen(int32_t bFullScreen) = 0;
    virtual int32_t __stdcall get_enableContextMenu(int32_t* pbEnableContextMenu) = 0;
    virtual int32_t __stdcall put_enableContextMenu(int32_t bEnableContextMenu) = 0;
    virtual int32_t __stdcall get_uiMode(ole32::BSTR* pbstrMode) = 0;
    virtual int32_t __stdcall put_uiMode(ole32::BSTR bstrMode) = 0;
};

struct IWMPPlayer4 : public IWMPPlayer {
    virtual int32_t __stdcall get_playerApplication(ole32::IDispatch** ppIDispatch) = 0;
    virtual int32_t __stdcall get_status(ole32::BSTR* pbstrStatus) = 0;
};

struct IWMPEvents : public ole32::IUnknown {
    virtual void __stdcall OpenStateChange(int32_t NewState) = 0;
    virtual void __stdcall PlayStateChange(int32_t NewState) = 0;
    virtual void __stdcall AudioLanguageChange(int32_t LangID) = 0;
    virtual void __stdcall StatusChange() = 0;
    virtual void __stdcall ScriptCommand(ole32::BSTR scType, ole32::BSTR Param) = 0;
    virtual void __stdcall NewStream() = 0;
    virtual void __stdcall Disconnect(int32_t Result) = 0;
    virtual void __stdcall Buffering(int32_t Start) = 0;
    virtual void __stdcall Error() = 0;
    virtual void __stdcall Warning(int32_t WarningType, int32_t Param, ole32::BSTR Description) = 0;
    virtual void __stdcall EndOfStream(int32_t Result) = 0;
    virtual void __stdcall PositionChange(double oldPosition, double newPosition) = 0;
    virtual void __stdcall MarkerHit(int32_t MarkerNum) = 0;
    virtual void __stdcall DurationUnitChange(int32_t NewDurationUnit) = 0;
    virtual void __stdcall CdromMediaChange(int32_t CdromNum) = 0;
    virtual void __stdcall PlaylistChange(ole32::IDispatch* Playlist, int32_t change) = 0;
    virtual void __stdcall CurrentPlaylistChange(int32_t change) = 0;
    virtual void __stdcall CurrentPlaylistItemAvailable(ole32::BSTR bstrItemName) = 0;
    virtual void __stdcall MediaChange(ole32::IDispatch* Item) = 0;
    virtual void __stdcall CurrentMediaItemAvailable(ole32::BSTR bstrItemName) = 0;
    virtual void __stdcall CurrentItemChange(ole32::IDispatch* pdispMedia) = 0;
    virtual void __stdcall MediaCollectionChange() = 0;
    virtual void __stdcall MediaCollectionAttributeStringAdded(ole32::BSTR bstrAttribName, ole32::BSTR bstrAttribVal) = 0;
    virtual void __stdcall MediaCollectionAttributeStringRemoved(ole32::BSTR bstrAttribName, ole32::BSTR bstrAttribVal) = 0;
    virtual void __stdcall MediaCollectionAttributeStringChanged(ole32::BSTR bstrAttribName, ole32::BSTR bstrOldAttribVal, ole32::BSTR bstrNewAttribVal) = 0;
    virtual void __stdcall PlaylistCollectionChange() = 0;
    virtual void __stdcall PlaylistCollectionPlaylistAdded(ole32::BSTR bstrPlaylistName) = 0;
    virtual void __stdcall PlaylistCollectionPlaylistRemoved(ole32::BSTR bstrPlaylistName) = 0;
    virtual void __stdcall PlaylistCollectionPlaylistSetAsDeleted(ole32::BSTR bstrPlaylistName, int32_t varfIsDeleted) = 0;
    virtual void __stdcall ModeChange(ole32::BSTR ModeName, int32_t NewValue) = 0;
    virtual void __stdcall MediaError(ole32::IDispatch* pMediaObject) = 0;
    virtual void __stdcall OpenPlaylistSwitch(ole32::IDispatch* pItem) = 0;
    virtual void __stdcall DomainChange(ole32::BSTR strDomain) = 0;
    virtual void __stdcall SwitchedToPlayerApplication() = 0;
    virtual void __stdcall SwitchedToControl() = 0;
    virtual void __stdcall PlayerDockedStateChange() = 0;
    virtual void __stdcall PlayerReconnect() = 0;
    virtual void __stdcall Click(int16_t nButton, int16_t nShiftState, int32_t fX, int32_t fY) = 0;
    virtual void __stdcall DoubleClick(int16_t nButton, int16_t nShiftState, int32_t fX, int32_t fY) = 0;
    virtual void __stdcall KeyDown(int16_t nKeyCode, int16_t nShiftState) = 0;
    virtual void __stdcall KeyPress(int16_t nKeyAscii) = 0;
    virtual void __stdcall KeyUp(int16_t nKeyCode, int16_t nShiftState) = 0;
    virtual void __stdcall MouseDown(int16_t nButton, int16_t nShiftState, int32_t fX, int32_t fY) = 0;
    virtual void __stdcall MouseMove(int16_t nButton, int16_t nShiftState, int32_t fX, int32_t fY) = 0;
    virtual void __stdcall MouseUp(int16_t nButton, int16_t nShiftState, int32_t fX, int32_t fY) = 0;
};

// ============================================================================
// 4. ActiveMovie Multimedia Stream Interfaces
// ============================================================================

struct IMultiMediaStream : public ole32::IUnknown {
    virtual int32_t __stdcall GetInformation(uint32_t* pdwFlags, STREAM_TYPE* pStreamType) = 0;
    virtual int32_t __stdcall GetMediaStream(const GUID& idPurpose, IMediaStream** ppMediaStream) = 0;
    virtual int32_t __stdcall EnumMediaStreams(int32_t Index, IMediaStream** ppMediaStream) = 0;
    virtual int32_t __stdcall GetState(STREAM_STATE* pCurrentState) = 0;
    virtual int32_t __stdcall SetState(STREAM_STATE NewState) = 0;
    virtual int32_t __stdcall GetTime(int64_t* pCurrentTime) = 0;
    virtual int32_t __stdcall Seek(int64_t SeekTime) = 0;
};

struct IAMMultiMediaStream : public IMultiMediaStream {
    virtual int32_t __stdcall Initialize(STREAM_TYPE StreamType, uint32_t dwFlags, void* pFilterGraph) = 0;
    virtual int32_t __stdcall GetFilterGraph(void** ppGraphBuilder) = 0;
    virtual int32_t __stdcall GetFilter(void** ppFilter) = 0;
    virtual int32_t __stdcall AddMediaStream(ole32::IUnknown* pStreamObject, const GUID* PurposeId, uint32_t dwFlags, IMediaStream** ppNewStream) = 0;
    virtual int32_t __stdcall OpenFile(const wchar_t* pszFileName, uint32_t dwFlags) = 0;
    virtual int32_t __stdcall OpenMoniker(void* pMoniker, uint32_t dwFlags) = 0;
    virtual int32_t __stdcall Render(uint32_t dwFlags) = 0;
};

struct IMediaStream : public ole32::IUnknown {
    virtual int32_t __stdcall GetMultiMediaStream(IMultiMediaStream** ppMultiMediaStream) = 0;
    virtual int32_t __stdcall GetInformation(GUID* pPurposeId, STREAM_TYPE* pType) = 0;
    virtual int32_t __stdcall SendEndOfStream() = 0;
};

struct IStreamSample : public ole32::IUnknown {
    virtual int32_t __stdcall GetMediaStream(IMediaStream** ppMediaStream) = 0;
    virtual int32_t __stdcall GetSampleTimes(int64_t* pStartTime, int64_t* pEndTime, int64_t* pCurrentTime) = 0;
    virtual int32_t __stdcall SetSampleTimes(const int64_t* pStartTime, const int64_t* pEndTime) = 0;
    virtual int32_t __stdcall Update(uint32_t dwFlags, uintptr_t hEvent, void* pfnAPC, uintptr_t dwAPCData) = 0;
    virtual int32_t __stdcall CompletionStatus(uint32_t dwFlags, uint32_t dwMilliseconds) = 0;
};

// ============================================================================
// 5. Concrete Implementation: CWMPMedia
// ============================================================================

class CWMPMedia : public IWMPMedia {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_sourceUrl;
    std::wstring m_name;
    double m_duration{ 180.0 }; // Default 3 minutes
    int32_t m_imageWidth{ 1920 };
    int32_t m_imageHeight{ 1080 };
    std::unordered_map<std::wstring, std::wstring> m_attributes;
    mutable std::mutex m_mutex;

public:
    CWMPMedia(std::wstring url, std::wstring name, double duration = 180.0)
        : m_sourceUrl(std::move(url)), m_name(std::move(name)), m_duration(duration) {
        m_attributes[L"Title"] = m_name;
        m_attributes[L"Author"] = L"MicaNT Soundworks";
        m_attributes[L"Album"] = L"Titan OST";
        m_attributes[L"Bitrate"] = L"320000";
        m_attributes[L"Duration"] = std::to_wstring(static_cast<uint64_t>(m_duration));
        m_attributes[L"MediaType"] = L"Audio";
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == ole32::IID_IDispatch || riid == IID_IWMPMedia) {
            *ppvObject = static_cast<IWMPMedia*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IDispatch stub
    int32_t __stdcall GetTypeInfoCount(uint32_t* pctinfo) override { if (pctinfo) *pctinfo = 0; return ole32::S_OK; }
    int32_t __stdcall GetTypeInfo(uint32_t, ole32::LCID, ole32::ITypeInfo**) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall GetIDsOfNames(ole32::REFIID, ole32::LPOLESTR*, uint32_t, ole32::LCID, ole32::DISPID*) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall Invoke(ole32::DISPID, ole32::REFIID, ole32::LCID, uint16_t, ole32::DISPPARAMS*, ole32::VARIANT*, ole32::EXCEPINFO*, uint32_t*) override { return ole32::E_NOTIMPL; }

    // IWMPMedia
    int32_t __stdcall get_isIdentical(IWMPMedia* pIWMPMedia, int32_t* pvbool) override {
        if (!pvbool) return ole32::E_POINTER;
        *pvbool = (pIWMPMedia == static_cast<IWMPMedia*>(this)) ? 1 : 0;
        return ole32::S_OK;
    }

    int32_t __stdcall get_sourceURL(ole32::BSTR* pbstrSourceURL) override {
        if (!pbstrSourceURL) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbstrSourceURL = oleaut32::SysAllocString(m_sourceUrl.c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall get_name(ole32::BSTR* pbstrName) override {
        if (!pbstrName) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbstrName = oleaut32::SysAllocString(m_name.c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall put_name(ole32::BSTR bstrName) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (bstrName) m_name = bstrName;
        return ole32::S_OK;
    }

    int32_t __stdcall get_imageSourceWidth(int32_t* pWidth) override {
        if (!pWidth) return ole32::E_POINTER;
        *pWidth = m_imageWidth;
        return ole32::S_OK;
    }

    int32_t __stdcall get_imageSourceHeight(int32_t* pHeight) override {
        if (!pHeight) return ole32::E_POINTER;
        *pHeight = m_imageHeight;
        return ole32::S_OK;
    }

    int32_t __stdcall get_duration(double* pDuration) override {
        if (!pDuration) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pDuration = m_duration;
        return ole32::S_OK;
    }

    int32_t __stdcall get_durationString(ole32::BSTR* pbstrDuration) override {
        if (!pbstrDuration) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t totalSec = static_cast<uint64_t>(m_duration);
        uint64_t mins = totalSec / 60;
        uint64_t secs = totalSec % 60;
        std::wostringstream oss;
        oss << std::setfill(L'0') << std::setw(2) << mins << L":" << std::setw(2) << secs;
        *pbstrDuration = oleaut32::SysAllocString(oss.str().c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall get_attributeCount(int32_t* plCount) override {
        if (!plCount) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *plCount = static_cast<int32_t>(m_attributes.size());
        return ole32::S_OK;
    }

    int32_t __stdcall getAttributeName(int32_t lIndex, ole32::BSTR* pbstrItemName) override {
        if (!pbstrItemName) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (lIndex < 0 || static_cast<size_t>(lIndex) >= m_attributes.size()) {
            return ole32::E_INVALIDARG;
        }
        auto it = m_attributes.begin();
        std::advance(it, lIndex);
        *pbstrItemName = oleaut32::SysAllocString(it->first.c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall getItemInfo(ole32::BSTR bstrItemName, ole32::BSTR* pbstrVal) override {
        if (!bstrItemName || !pbstrVal) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_attributes.find(bstrItemName);
        if (it != m_attributes.end()) {
            *pbstrVal = oleaut32::SysAllocString(it->second.c_str());
            return ole32::S_OK;
        }
        *pbstrVal = oleaut32::SysAllocString(L"");
        return ole32::S_OK;
    }

    int32_t __stdcall setItemInfo(ole32::BSTR bstrItemName, ole32::BSTR bstrVal) override {
        if (!bstrItemName) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_attributes[bstrItemName] = bstrVal ? bstrVal : L"";
        return ole32::S_OK;
    }

    int32_t __stdcall getItemInfoByType(ole32::BSTR, ole32::BSTR, int32_t, ole32::VARIANT*) override {
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall isMemberOf(IWMPPlaylist*, int32_t* pvarf) override {
        if (pvarf) *pvarf = 1;
        return ole32::S_OK;
    }

    int32_t __stdcall isReadOnlyItem(ole32::BSTR, int32_t* pvarf) override {
        if (pvarf) *pvarf = 0;
        return ole32::S_OK;
    }
};

// ============================================================================
// 6. Concrete Implementation: CWMPPlaylist
// ============================================================================

class CWMPPlaylist : public IWMPPlaylist {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_name;
    std::vector<IWMPMedia*> m_items;
    std::unordered_map<std::wstring, std::wstring> m_attributes;
    mutable std::mutex m_mutex;

public:
    explicit CWMPPlaylist(std::wstring name = L"Now Playing")
        : m_name(std::move(name)) {
        m_attributes[L"Title"] = m_name;
        m_attributes[L"Author"] = L"MicaNT User";
    }

    ~CWMPPlaylist() override {
        for (auto* m : m_items) if (m) m->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == ole32::IID_IDispatch || riid == IID_IWMPPlaylist) {
            *ppvObject = static_cast<IWMPPlaylist*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IDispatch stub
    int32_t __stdcall GetTypeInfoCount(uint32_t* pctinfo) override { if (pctinfo) *pctinfo = 0; return ole32::S_OK; }
    int32_t __stdcall GetTypeInfo(uint32_t, ole32::LCID, ole32::ITypeInfo**) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall GetIDsOfNames(ole32::REFIID, ole32::LPOLESTR*, uint32_t, ole32::LCID, ole32::DISPID*) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall Invoke(ole32::DISPID, ole32::REFIID, ole32::LCID, uint16_t, ole32::DISPPARAMS*, ole32::VARIANT*, ole32::EXCEPINFO*, uint32_t*) override { return ole32::E_NOTIMPL; }

    // IWMPPlaylist
    int32_t __stdcall get_count(int32_t* plCount) override {
        if (!plCount) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *plCount = static_cast<int32_t>(m_items.size());
        return ole32::S_OK;
    }

    int32_t __stdcall get_name(ole32::BSTR* pbstrName) override {
        if (!pbstrName) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbstrName = oleaut32::SysAllocString(m_name.c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall put_name(ole32::BSTR bstrName) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (bstrName) m_name = bstrName;
        return ole32::S_OK;
    }

    int32_t __stdcall get_attributeCount(int32_t* plCount) override {
        if (!plCount) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *plCount = static_cast<int32_t>(m_attributes.size());
        return ole32::S_OK;
    }

    int32_t __stdcall get_attributeName(int32_t lIndex, ole32::BSTR* pbstrAttributeName) override {
        if (!pbstrAttributeName) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (lIndex < 0 || static_cast<size_t>(lIndex) >= m_attributes.size()) {
            return ole32::E_INVALIDARG;
        }
        auto it = m_attributes.begin();
        std::advance(it, lIndex);
        *pbstrAttributeName = oleaut32::SysAllocString(it->first.c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall get_Item(int32_t lIndex, IWMPMedia** ppIWMPMedia) override {
        if (!ppIWMPMedia) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (lIndex < 0 || static_cast<size_t>(lIndex) >= m_items.size()) {
            *ppIWMPMedia = nullptr;
            return ole32::E_INVALIDARG;
        }
        *ppIWMPMedia = m_items[lIndex];
        (*ppIWMPMedia)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall getItemInfo(ole32::BSTR bstrName, ole32::BSTR* pbstrVal) override {
        if (!bstrName || !pbstrVal) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_attributes.find(bstrName);
        if (it != m_attributes.end()) {
            *pbstrVal = oleaut32::SysAllocString(it->second.c_str());
            return ole32::S_OK;
        }
        *pbstrVal = oleaut32::SysAllocString(L"");
        return ole32::S_OK;
    }

    int32_t __stdcall setItemInfo(ole32::BSTR bstrName, ole32::BSTR bstrValue) override {
        if (!bstrName) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_attributes[bstrName] = bstrValue ? bstrValue : L"";
        return ole32::S_OK;
    }

    int32_t __stdcall get_isIdentical(IWMPPlaylist* pIWMPPlaylist, int32_t* pvbool) override {
        if (!pvbool) return ole32::E_POINTER;
        *pvbool = (pIWMPPlaylist == static_cast<IWMPPlaylist*>(this)) ? 1 : 0;
        return ole32::S_OK;
    }

    int32_t __stdcall clear() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto* m : m_items) if (m) m->Release();
        m_items.clear();
        return ole32::S_OK;
    }

    int32_t __stdcall insertItem(int32_t lIndex, IWMPMedia* pIWMPMedia) override {
        if (!pIWMPMedia) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        pIWMPMedia->AddRef();
        if (lIndex < 0 || static_cast<size_t>(lIndex) >= m_items.size()) {
            m_items.push_back(pIWMPMedia);
        } else {
            m_items.insert(m_items.begin() + lIndex, pIWMPMedia);
        }
        return ole32::S_OK;
    }

    int32_t __stdcall appendItem(IWMPMedia* pIWMPMedia) override {
        if (!pIWMPMedia) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        pIWMPMedia->AddRef();
        m_items.push_back(pIWMPMedia);
        return ole32::S_OK;
    }

    int32_t __stdcall removeItem(IWMPMedia* pIWMPMedia) override {
        if (!pIWMPMedia) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find(m_items.begin(), m_items.end(), pIWMPMedia);
        if (it != m_items.end()) {
            (*it)->Release();
            m_items.erase(it);
            return ole32::S_OK;
        }
        return ole32::E_INVALIDARG;
    }

    int32_t __stdcall moveItem(int32_t lIndexOld, int32_t lIndexNew) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (lIndexOld < 0 || static_cast<size_t>(lIndexOld) >= m_items.size() ||
            lIndexNew < 0 || static_cast<size_t>(lIndexNew) >= m_items.size()) {
            return ole32::E_INVALIDARG;
        }
        auto* item = m_items[lIndexOld];
        m_items.erase(m_items.begin() + lIndexOld);
        m_items.insert(m_items.begin() + lIndexNew, item);
        return ole32::S_OK;
    }
};

// ============================================================================
// 7. Concrete Implementation: CWMPSettings
// ============================================================================

class CWMPSettings : public IWMPSettings {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    int32_t m_autoStart{ 1 };
    std::wstring m_baseUrl;
    std::wstring m_defaultFrame;
    int32_t m_invokeUrls{ 1 };
    int32_t m_errorDialogs{ 0 };
    int32_t m_volume{ 75 };
    int32_t m_balance{ 0 };
    int32_t m_playCount{ 1 };
    double m_rate{ 1.0 };
    std::unordered_map<std::wstring, int32_t> m_modes;
    mutable std::mutex m_mutex;

public:
    CWMPSettings() {
        m_modes[L"shuffle"] = 0;
        m_modes[L"loop"] = 0;
        m_modes[L"showFrame"] = 1;
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == ole32::IID_IDispatch || riid == IID_IWMPSettings) {
            *ppvObject = static_cast<IWMPSettings*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IDispatch stub
    int32_t __stdcall GetTypeInfoCount(uint32_t* pctinfo) override { if (pctinfo) *pctinfo = 0; return ole32::S_OK; }
    int32_t __stdcall GetTypeInfo(uint32_t, ole32::LCID, ole32::ITypeInfo**) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall GetIDsOfNames(ole32::REFIID, ole32::LPOLESTR*, uint32_t, ole32::LCID, ole32::DISPID*) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall Invoke(ole32::DISPID, ole32::REFIID, ole32::LCID, uint16_t, ole32::DISPPARAMS*, ole32::VARIANT*, ole32::EXCEPINFO*, uint32_t*) override { return ole32::E_NOTIMPL; }

    // IWMPSettings
    int32_t __stdcall get_isAvailable(ole32::BSTR, int32_t* pIsAvailable) override {
        if (pIsAvailable) *pIsAvailable = 1;
        return ole32::S_OK;
    }

    int32_t __stdcall get_autoStart(int32_t* pfAutoStart) override {
        if (!pfAutoStart) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pfAutoStart = m_autoStart;
        return ole32::S_OK;
    }

    int32_t __stdcall put_autoStart(int32_t fAutoStart) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_autoStart = fAutoStart;
        return ole32::S_OK;
    }

    int32_t __stdcall get_baseURL(ole32::BSTR* pbstrBaseURL) override {
        if (!pbstrBaseURL) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbstrBaseURL = oleaut32::SysAllocString(m_baseUrl.c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall put_baseURL(ole32::BSTR bstrBaseURL) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (bstrBaseURL) m_baseUrl = bstrBaseURL;
        return ole32::S_OK;
    }

    int32_t __stdcall get_defaultFrame(ole32::BSTR* pbstrDefaultFrame) override {
        if (!pbstrDefaultFrame) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbstrDefaultFrame = oleaut32::SysAllocString(m_defaultFrame.c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall put_defaultFrame(ole32::BSTR bstrDefaultFrame) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (bstrDefaultFrame) m_defaultFrame = bstrDefaultFrame;
        return ole32::S_OK;
    }

    int32_t __stdcall get_invokeURLs(int32_t* pfInvokeURLs) override {
        if (!pfInvokeURLs) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pfInvokeURLs = m_invokeUrls;
        return ole32::S_OK;
    }

    int32_t __stdcall put_invokeURLs(int32_t fInvokeURLs) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_invokeUrls = fInvokeURLs;
        return ole32::S_OK;
    }

    int32_t __stdcall get_enableErrorDialogs(int32_t* pfEnableErrorDialogs) override {
        if (!pfEnableErrorDialogs) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pfEnableErrorDialogs = m_errorDialogs;
        return ole32::S_OK;
    }

    int32_t __stdcall put_enableErrorDialogs(int32_t fEnableErrorDialogs) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_errorDialogs = fEnableErrorDialogs;
        return ole32::S_OK;
    }

    int32_t __stdcall get_mode(ole32::BSTR bstrMode, int32_t* pvarfMode) override {
        if (!bstrMode || !pvarfMode) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_modes.find(bstrMode);
        *pvarfMode = (it != m_modes.end()) ? it->second : 0;
        return ole32::S_OK;
    }

    int32_t __stdcall setMode(ole32::BSTR bstrMode, int32_t varfMode) override {
        if (!bstrMode) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_modes[bstrMode] = varfMode;
        return ole32::S_OK;
    }

    int32_t __stdcall get_volume(int32_t* plVolume) override {
        if (!plVolume) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *plVolume = m_volume;
        return ole32::S_OK;
    }

    int32_t __stdcall put_volume(int32_t lVolume) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_volume = std::clamp(lVolume, 0, 100);
        return ole32::S_OK;
    }

    int32_t __stdcall get_balance(int32_t* plBalance) override {
        if (!plBalance) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *plBalance = m_balance;
        return ole32::S_OK;
    }

    int32_t __stdcall put_balance(int32_t lBalance) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_balance = std::clamp(lBalance, -100, 100);
        return ole32::S_OK;
    }

    int32_t __stdcall get_playCount(int32_t* plCount) override {
        if (!plCount) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *plCount = m_playCount;
        return ole32::S_OK;
    }

    int32_t __stdcall put_playCount(int32_t lCount) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_playCount = std::max(1, lCount);
        return ole32::S_OK;
    }

    int32_t __stdcall get_rate(double* pdRate) override {
        if (!pdRate) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pdRate = m_rate;
        return ole32::S_OK;
    }

    int32_t __stdcall put_rate(double dRate) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (dRate > 0.0) m_rate = dRate;
        return ole32::S_OK;
    }
};

// ============================================================================
// 8. Concrete Implementation: CWMPControls
// ============================================================================

class CWindowsMediaPlayer;

class CWMPControls : public IWMPControls {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    CWindowsMediaPlayer* m_pPlayer{ nullptr };
    double m_currentPosition{ 0.0 };
    int32_t m_currentMarker{ 0 };
    mutable std::mutex m_mutex;

public:
    explicit CWMPControls(CWindowsMediaPlayer* pPlayer);

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == ole32::IID_IDispatch || riid == IID_IWMPControls) {
            *ppvObject = static_cast<IWMPControls*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IDispatch stub
    int32_t __stdcall GetTypeInfoCount(uint32_t* pctinfo) override { if (pctinfo) *pctinfo = 0; return ole32::S_OK; }
    int32_t __stdcall GetTypeInfo(uint32_t, ole32::LCID, ole32::ITypeInfo**) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall GetIDsOfNames(ole32::REFIID, ole32::LPOLESTR*, uint32_t, ole32::LCID, ole32::DISPID*) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall Invoke(ole32::DISPID, ole32::REFIID, ole32::LCID, uint16_t, ole32::DISPPARAMS*, ole32::VARIANT*, ole32::EXCEPINFO*, uint32_t*) override { return ole32::E_NOTIMPL; }

    // IWMPControls
    int32_t __stdcall get_isAvailable(ole32::BSTR, int32_t* pIsAvailable) override {
        if (pIsAvailable) *pIsAvailable = 1;
        return ole32::S_OK;
    }

    int32_t __stdcall play() override;
    int32_t __stdcall stop() override;
    int32_t __stdcall pause() override;
    int32_t __stdcall fastForward() override;
    int32_t __stdcall fastReverse() override;

    int32_t __stdcall get_currentPosition(double* pdCurrentPosition) override {
        if (!pdCurrentPosition) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pdCurrentPosition = m_currentPosition;
        return ole32::S_OK;
    }

    int32_t __stdcall put_currentPosition(double dCurrentPosition) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentPosition = std::max(0.0, dCurrentPosition);
        return ole32::S_OK;
    }

    int32_t __stdcall get_currentPositionString(ole32::BSTR* pbstrCurrentPosition) override {
        if (!pbstrCurrentPosition) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t totalSec = static_cast<uint64_t>(m_currentPosition);
        uint64_t mins = totalSec / 60;
        uint64_t secs = totalSec % 60;
        std::wostringstream oss;
        oss << std::setfill(L'0') << std::setw(2) << mins << L":" << std::setw(2) << secs;
        *pbstrCurrentPosition = oleaut32::SysAllocString(oss.str().c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall next() override;
    int32_t __stdcall previous() override;
    int32_t __stdcall get_currentItem(IWMPMedia** ppIWMPMedia) override;
    int32_t __stdcall put_currentItem(IWMPMedia* pIWMPMedia) override;

    int32_t __stdcall get_currentMarker(int32_t* plMarker) override {
        if (!plMarker) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *plMarker = m_currentMarker;
        return ole32::S_OK;
    }

    int32_t __stdcall put_currentMarker(int32_t lMarker) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentMarker = lMarker;
        return ole32::S_OK;
    }

    int32_t __stdcall playItem(IWMPMedia* pIWMPMedia) override {
        put_currentItem(pIWMPMedia);
        return play();
    }
};

// ============================================================================
// 9. Concrete Implementation: CWindowsMediaPlayer (IWMPPlayer4 & IWMPCore)
// ============================================================================

class CWindowsMediaPlayer : public IWMPPlayer4, public ole32::IConnectionPointContainer {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_url;
    WMPOpenState m_openState{ wmposUndefined };
    WMPPlayState m_playState{ wmppsStopped };
    CWMPControls* m_pControls{ nullptr };
    CWMPSettings* m_pSettings{ nullptr };
    IWMPMedia* m_pCurrentMedia{ nullptr };
    CWMPPlaylist* m_pPlaylist{ nullptr };
    int32_t m_currentPlaylistIndex{ 0 };
    int32_t m_enabled{ 1 };
    int32_t m_fullScreen{ 0 };
    int32_t m_enableContextMenu{ 1 };
    std::wstring m_uiMode{ L"full" };
    std::wstring m_status{ L"Ready" };
    mutable std::mutex m_mutex;

public:
    CWindowsMediaPlayer() {
        m_pControls = new CWMPControls(this);
        m_pSettings = new CWMPSettings();
        m_pPlaylist = new CWMPPlaylist(L"MicaNT Default Playlist");
    }

    ~CWindowsMediaPlayer() override {
        if (m_pControls) m_pControls->Release();
        if (m_pSettings) m_pSettings->Release();
        if (m_pCurrentMedia) m_pCurrentMedia->Release();
        if (m_pPlaylist) m_pPlaylist->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == ole32::IID_IDispatch ||
            riid == IID_IWMPCore || riid == IID_IWMPPlayer || riid == IID_IWMPPlayer4) {
            *ppvObject = static_cast<IWMPPlayer4*>(this);
            AddRef();
            return ole32::S_OK;
        }
        if (riid == ole32::IID_IConnectionPointContainer) {
            *ppvObject = static_cast<ole32::IConnectionPointContainer*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IDispatch stub
    int32_t __stdcall GetTypeInfoCount(uint32_t* pctinfo) override { if (pctinfo) *pctinfo = 0; return ole32::S_OK; }
    int32_t __stdcall GetTypeInfo(uint32_t, ole32::LCID, ole32::ITypeInfo**) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall GetIDsOfNames(ole32::REFIID, ole32::LPOLESTR*, uint32_t, ole32::LCID, ole32::DISPID*) override { return ole32::E_NOTIMPL; }
    int32_t __stdcall Invoke(ole32::DISPID, ole32::REFIID, ole32::LCID, uint16_t, ole32::DISPPARAMS*, ole32::VARIANT*, ole32::EXCEPINFO*, uint32_t*) override { return ole32::E_NOTIMPL; }

    // IConnectionPointContainer stub
    int32_t __stdcall EnumConnectionPoints(ole32::IEnumConnectionPoints** ppEnum) override {
        if (ppEnum) *ppEnum = nullptr;
        return ole32::E_NOTIMPL;
    }
    int32_t __stdcall FindConnectionPoint(const GUID&, ole32::IConnectionPoint** ppCP) override {
        if (ppCP) *ppCP = nullptr;
        return ole32::E_NOTIMPL;
    }

    // Internal State Management
    void SetInternalPlayState(WMPPlayState s) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_playState = s;
        m_status = std::wstring(L"Playback State: ") + std::wstring(WMPPlayStateToString(s), WMPPlayStateToString(s) + strlen(WMPPlayStateToString(s)));
    }

    WMPPlayState GetInternalPlayState() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_playState;
    }

    // IWMPCore
    int32_t __stdcall close() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_playState = wmppsStopped;
        m_openState = wmposUndefined;
        m_status = L"Closed";
        return ole32::S_OK;
    }

    int32_t __stdcall get_URL(ole32::BSTR* pbstrURL) override {
        if (!pbstrURL) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbstrURL = oleaut32::SysAllocString(m_url.c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall put_URL(ole32::BSTR bstrURL) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_url = bstrURL ? bstrURL : L"";
        if (!m_url.empty()) {
            m_openState = wmposMediaOpen;
            if (m_pCurrentMedia) m_pCurrentMedia->Release();
            m_pCurrentMedia = new CWMPMedia(m_url, m_url, 210.0);
            m_pPlaylist->appendItem(m_pCurrentMedia);
            m_currentPlaylistIndex = 0;
            int32_t autoStart = 1;
            m_pSettings->get_autoStart(&autoStart);
            if (autoStart) {
                m_playState = wmppsPlaying;
                m_status = L"Playing";
            } else {
                m_playState = wmppsReady;
                m_status = L"Ready";
            }
        }
        return ole32::S_OK;
    }

    int32_t __stdcall get_openState(WMPOpenState* pwmpos) override {
        if (!pwmpos) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pwmpos = m_openState;
        return ole32::S_OK;
    }

    int32_t __stdcall get_playState(WMPPlayState* pwmpps) override {
        if (!pwmpps) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pwmpps = m_playState;
        return ole32::S_OK;
    }

    int32_t __stdcall get_controls(IWMPControls** ppControl) override {
        if (!ppControl) return ole32::E_POINTER;
        *ppControl = m_pControls;
        (*ppControl)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall get_settings(IWMPSettings** ppSettings) override {
        if (!ppSettings) return ole32::E_POINTER;
        *ppSettings = m_pSettings;
        (*ppSettings)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall get_currentMedia(IWMPMedia** ppMedia) override {
        if (!ppMedia) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *ppMedia = m_pCurrentMedia;
        if (*ppMedia) (*ppMedia)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall put_currentMedia(IWMPMedia* pMedia) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pCurrentMedia) m_pCurrentMedia->Release();
        m_pCurrentMedia = pMedia;
        if (m_pCurrentMedia) m_pCurrentMedia->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall get_mediaCollection(IWMPMediaCollection** ppMediaCollection) override {
        if (ppMediaCollection) *ppMediaCollection = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall get_playlistCollection(IWMPPlaylistCollection** ppPlaylistCollection) override {
        if (ppPlaylistCollection) *ppPlaylistCollection = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall get_versionInfo(ole32::BSTR* pbstrVersionInfo) override {
        if (!pbstrVersionInfo) return ole32::E_POINTER;
        *pbstrVersionInfo = oleaut32::SysAllocString(L"12.0.26100.1");
        return ole32::S_OK;
    }

    int32_t __stdcall launchURL(ole32::BSTR) override { return ole32::S_OK; }
    int32_t __stdcall get_network(ole32::IDispatch** ppNetwork) override { if (ppNetwork) *ppNetwork = nullptr; return ole32::E_NOTIMPL; }

    int32_t __stdcall get_currentPlaylist(IWMPPlaylist** ppPlaylist) override {
        if (!ppPlaylist) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *ppPlaylist = m_pPlaylist;
        if (*ppPlaylist) (*ppPlaylist)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall put_currentPlaylist(IWMPPlaylist* pPlaylist) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pPlaylist) m_pPlaylist->Release();
        m_pPlaylist = static_cast<CWMPPlaylist*>(pPlaylist);
        if (m_pPlaylist) m_pPlaylist->AddRef();
        m_currentPlaylistIndex = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall get_cdromCollection(IWMPCdromCollection** ppCdromCollection) override {
        if (ppCdromCollection) *ppCdromCollection = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall get_closedCaption(IWMPClosedCaption** ppClosedCaption) override {
        if (ppClosedCaption) *ppClosedCaption = nullptr;
        return ole32::E_NOTIMPL;
    }

    // IWMPPlayer
    int32_t __stdcall get_enabled(int32_t* pbEnabled) override {
        if (!pbEnabled) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbEnabled = m_enabled;
        return ole32::S_OK;
    }

    int32_t __stdcall put_enabled(int32_t bEnabled) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enabled = bEnabled;
        return ole32::S_OK;
    }

    int32_t __stdcall get_fullScreen(int32_t* pbFullScreen) override {
        if (!pbFullScreen) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbFullScreen = m_fullScreen;
        return ole32::S_OK;
    }

    int32_t __stdcall put_fullScreen(int32_t bFullScreen) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_fullScreen = bFullScreen;
        return ole32::S_OK;
    }

    int32_t __stdcall get_enableContextMenu(int32_t* pbEnableContextMenu) override {
        if (!pbEnableContextMenu) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbEnableContextMenu = m_enableContextMenu;
        return ole32::S_OK;
    }

    int32_t __stdcall put_enableContextMenu(int32_t bEnableContextMenu) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableContextMenu = bEnableContextMenu;
        return ole32::S_OK;
    }

    int32_t __stdcall get_uiMode(ole32::BSTR* pbstrMode) override {
        if (!pbstrMode) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbstrMode = oleaut32::SysAllocString(m_uiMode.c_str());
        return ole32::S_OK;
    }

    int32_t __stdcall put_uiMode(ole32::BSTR bstrMode) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (bstrMode) m_uiMode = bstrMode;
        return ole32::S_OK;
    }

    // IWMPPlayer4
    int32_t __stdcall get_playerApplication(ole32::IDispatch** ppIDispatch) override {
        if (ppIDispatch) *ppIDispatch = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall get_status(ole32::BSTR* pbstrStatus) override {
        if (!pbstrStatus) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pbstrStatus = oleaut32::SysAllocString(m_status.c_str());
        return ole32::S_OK;
    }

    // Playlist Navigation Helpers for Controls
    void StepNext() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_pPlaylist) return;
        int32_t count = 0;
        m_pPlaylist->get_count(&count);
        if (count == 0) return;
        m_currentPlaylistIndex = (m_currentPlaylistIndex + 1) % count;
        if (m_pCurrentMedia) m_pCurrentMedia->Release();
        m_pPlaylist->get_Item(m_currentPlaylistIndex, &m_pCurrentMedia);
        m_playState = wmppsPlaying;
    }

    void StepPrevious() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_pPlaylist) return;
        int32_t count = 0;
        m_pPlaylist->get_count(&count);
        if (count == 0) return;
        m_currentPlaylistIndex = (m_currentPlaylistIndex + count - 1) % count;
        if (m_pCurrentMedia) m_pCurrentMedia->Release();
        m_pPlaylist->get_Item(m_currentPlaylistIndex, &m_pCurrentMedia);
        m_playState = wmppsPlaying;
    }
};

// ============================================================================
// CWMPControls Implementation (deferred inline)
// ============================================================================

inline CWMPControls::CWMPControls(CWindowsMediaPlayer* pPlayer)
    : m_pPlayer(pPlayer) {}

inline int32_t __stdcall CWMPControls::play() {
    if (m_pPlayer) m_pPlayer->SetInternalPlayState(wmppsPlaying);
    return ole32::S_OK;
}

inline int32_t __stdcall CWMPControls::stop() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_currentPosition = 0.0;
    if (m_pPlayer) m_pPlayer->SetInternalPlayState(wmppsStopped);
    return ole32::S_OK;
}

inline int32_t __stdcall CWMPControls::pause() {
    if (m_pPlayer) m_pPlayer->SetInternalPlayState(wmppsPaused);
    return ole32::S_OK;
}

inline int32_t __stdcall CWMPControls::fastForward() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_currentPosition += 10.0;
    if (m_pPlayer) m_pPlayer->SetInternalPlayState(wmppsScanForward);
    return ole32::S_OK;
}

inline int32_t __stdcall CWMPControls::fastReverse() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_currentPosition = std::max(0.0, m_currentPosition - 10.0);
    if (m_pPlayer) m_pPlayer->SetInternalPlayState(wmppsScanReverse);
    return ole32::S_OK;
}

inline int32_t __stdcall CWMPControls::next() {
    if (m_pPlayer) m_pPlayer->StepNext();
    return ole32::S_OK;
}

inline int32_t __stdcall CWMPControls::previous() {
    if (m_pPlayer) m_pPlayer->StepPrevious();
    return ole32::S_OK;
}

inline int32_t __stdcall CWMPControls::get_currentItem(IWMPMedia** ppIWMPMedia) {
    if (m_pPlayer) return m_pPlayer->get_currentMedia(ppIWMPMedia);
    if (ppIWMPMedia) *ppIWMPMedia = nullptr;
    return ole32::E_FAIL;
}

inline int32_t __stdcall CWMPControls::put_currentItem(IWMPMedia* pIWMPMedia) {
    if (m_pPlayer) return m_pPlayer->put_currentMedia(pIWMPMedia);
    return ole32::E_FAIL;
}

// ============================================================================
// 10. ActiveMovie Multimedia Stream Concrete Implementation
// ============================================================================

class CAMMediaStream;

class CAMStreamSample : public IStreamSample {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    CAMMediaStream* m_pStream{ nullptr };
    int64_t m_startTime{ 0 };
    int64_t m_endTime{ 0 };

public:
    CAMStreamSample(CAMMediaStream* pStream, int64_t start, int64_t end);

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IStreamSample) {
            *ppvObject = static_cast<IStreamSample*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall GetMediaStream(IMediaStream** ppMediaStream) override;

    int32_t __stdcall GetSampleTimes(int64_t* pStartTime, int64_t* pEndTime, int64_t* pCurrentTime) override {
        if (pStartTime) *pStartTime = m_startTime;
        if (pEndTime) *pEndTime = m_endTime;
        if (pCurrentTime) *pCurrentTime = m_startTime;
        return ole32::S_OK;
    }

    int32_t __stdcall SetSampleTimes(const int64_t* pStartTime, const int64_t* pEndTime) override {
        if (pStartTime) m_startTime = *pStartTime;
        if (pEndTime) m_endTime = *pEndTime;
        return ole32::S_OK;
    }

    int32_t __stdcall Update(uint32_t, uintptr_t, void*, uintptr_t) override {
        return ole32::S_OK;
    }

    int32_t __stdcall CompletionStatus(uint32_t, uint32_t) override {
        return ole32::S_OK;
    }
};

class CAMMediaStream : public IMediaStream {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IMultiMediaStream* m_pMMStream{ nullptr };
    GUID m_purposeId{ MSPID_PrimaryVideo };
    STREAM_TYPE m_type{ STREAMTYPE_READ };

public:
    CAMMediaStream(IMultiMediaStream* pMMStream, GUID purposeId, STREAM_TYPE type)
        : m_pMMStream(pMMStream), m_purposeId(purposeId), m_type(type) {}

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMediaStream) {
            *ppvObject = static_cast<IMediaStream*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall GetMultiMediaStream(IMultiMediaStream** ppMultiMediaStream) override {
        if (!ppMultiMediaStream) return ole32::E_POINTER;
        *ppMultiMediaStream = m_pMMStream;
        if (*ppMultiMediaStream) (*ppMultiMediaStream)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetInformation(GUID* pPurposeId, STREAM_TYPE* pType) override {
        if (pPurposeId) *pPurposeId = m_purposeId;
        if (pType) *pType = m_type;
        return ole32::S_OK;
    }

    int32_t __stdcall SendEndOfStream() override { return ole32::S_OK; }

    IStreamSample* CreateSample(int64_t start, int64_t end) {
        return new CAMStreamSample(this, start, end);
    }
};

inline CAMStreamSample::CAMStreamSample(CAMMediaStream* pStream, int64_t start, int64_t end)
    : m_pStream(pStream), m_startTime(start), m_endTime(end) {}

inline int32_t __stdcall CAMStreamSample::GetMediaStream(IMediaStream** ppMediaStream) {
    if (!ppMediaStream) return ole32::E_POINTER;
    *ppMediaStream = m_pStream;
    if (*ppMediaStream) (*ppMediaStream)->AddRef();
    return ole32::S_OK;
}

class CAMMultiMediaStream : public IAMMultiMediaStream {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    STREAM_TYPE m_streamType{ STREAMTYPE_READ };
    uint32_t m_flags{ 0 };
    STREAM_STATE m_state{ STREAMSTATE_STOP };
    int64_t m_currentTime{ 0 };
    std::vector<CAMMediaStream*> m_streams;
    std::wstring m_openFile;
    mutable std::mutex m_mutex;

public:
    CAMMultiMediaStream() = default;

    ~CAMMultiMediaStream() override {
        for (auto* s : m_streams) if (s) s->Release();
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMultiMediaStream || riid == IID_IAMMultiMediaStream) {
            *ppvObject = static_cast<IAMMultiMediaStream*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    // IMultiMediaStream
    int32_t __stdcall GetInformation(uint32_t* pdwFlags, STREAM_TYPE* pStreamType) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (pdwFlags) *pdwFlags = m_flags;
        if (pStreamType) *pStreamType = m_streamType;
        return ole32::S_OK;
    }

    int32_t __stdcall GetMediaStream(const GUID& idPurpose, IMediaStream** ppMediaStream) override {
        if (!ppMediaStream) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *ppMediaStream = nullptr;
        for (auto* s : m_streams) {
            GUID pid{};
            STREAM_TYPE st{};
            s->GetInformation(&pid, &st);
            if (pid == idPurpose) {
                *ppMediaStream = s;
                (*ppMediaStream)->AddRef();
                return ole32::S_OK;
            }
        }
        return MS_E_NOSTREAM;
    }

    int32_t __stdcall EnumMediaStreams(int32_t Index, IMediaStream** ppMediaStream) override {
        if (!ppMediaStream) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (Index < 0 || static_cast<size_t>(Index) >= m_streams.size()) {
            *ppMediaStream = nullptr;
            return ole32::S_FALSE;
        }
        *ppMediaStream = m_streams[Index];
        (*ppMediaStream)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetState(STREAM_STATE* pCurrentState) override {
        if (!pCurrentState) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pCurrentState = m_state;
        return ole32::S_OK;
    }

    int32_t __stdcall SetState(STREAM_STATE NewState) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = NewState;
        return ole32::S_OK;
    }

    int32_t __stdcall GetTime(int64_t* pCurrentTime) override {
        if (!pCurrentTime) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pCurrentTime = m_currentTime;
        return ole32::S_OK;
    }

    int32_t __stdcall Seek(int64_t SeekTime) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentTime = std::max<int64_t>(0, SeekTime);
        return ole32::S_OK;
    }

    // IAMMultiMediaStream
    int32_t __stdcall Initialize(STREAM_TYPE StreamType, uint32_t dwFlags, void*) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_streamType = StreamType;
        m_flags = dwFlags;
        return ole32::S_OK;
    }

    int32_t __stdcall GetFilterGraph(void** ppGraphBuilder) override {
        if (ppGraphBuilder) *ppGraphBuilder = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall GetFilter(void** ppFilter) override {
        if (ppFilter) *ppFilter = nullptr;
        return ole32::E_NOTIMPL;
    }

    int32_t __stdcall AddMediaStream(ole32::IUnknown*, const GUID* PurposeId, uint32_t, IMediaStream** ppNewStream) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        GUID pid = PurposeId ? *PurposeId : MSPID_PrimaryVideo;
        auto* stream = new CAMMediaStream(this, pid, m_streamType);
        m_streams.push_back(stream);
        if (ppNewStream) {
            *ppNewStream = stream;
            (*ppNewStream)->AddRef();
        }
        return ole32::S_OK;
    }

    int32_t __stdcall OpenFile(const wchar_t* pszFileName, uint32_t) override {
        if (!pszFileName) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_openFile = pszFileName;
        // Auto-add primary video and audio streams
        if (m_streams.empty()) {
            m_streams.push_back(new CAMMediaStream(this, MSPID_PrimaryVideo, m_streamType));
            m_streams.push_back(new CAMMediaStream(this, MSPID_PrimaryAudio, m_streamType));
        }
        return ole32::S_OK;
    }

    int32_t __stdcall OpenMoniker(void*, uint32_t) override { return ole32::E_NOTIMPL; }

    int32_t __stdcall Render(uint32_t) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = STREAMSTATE_RUN;
        return ole32::S_OK;
    }
};

// ============================================================================
// 11. Class Factories & Dynamic Loader Exports
// ============================================================================

template <typename T>
class CSimpleClassFactory : public ole32::IClassFactory {
private:
    std::atomic<uint32_t> m_refCount{ 1 };

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == ole32::IID_IClassFactory) {
            *ppvObject = static_cast<ole32::IClassFactory*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return m_refCount.fetch_add(1) + 1; }
    uint32_t __stdcall Release() override {
        uint32_t r = m_refCount.fetch_sub(1) - 1;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall CreateInstance(ole32::IUnknown* pUnkOuter, const GUID& riid, void** ppvObject) override {
        if (pUnkOuter) return ole32::CLASS_E_NOAGGREGATION;
        auto* instance = new T();
        int32_t hr = instance->QueryInterface(riid, ppvObject);
        instance->Release();
        return hr;
    }

    int32_t __stdcall LockServer(int32_t) override { return ole32::S_OK; }
};

inline int32_t __stdcall DllCanUnloadNow() {
    return ole32::S_OK;
}

inline void InitializeWmpExports() {
    auto& loader = ldr::DynamicLoader::get();

    // wmp.dll exports
    loader.registerExport("wmp.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&DllCanUnloadNow));

    // amstream.dll exports
    loader.registerExport("amstream.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&DllCanUnloadNow));

    // Register COM Class Factories in ComRuntime
    auto& com = ole32::ComRuntime::get();
    uint32_t regCookie = 0;

    auto* wmpFact = new CSimpleClassFactory<CWindowsMediaPlayer>();
    com.RegisterClassObject(CLSID_WindowsMediaPlayer, wmpFact, 1, 1, &regCookie);
    wmpFact->Release();

    auto* amsFact = new CSimpleClassFactory<CAMMultiMediaStream>();
    com.RegisterClassObject(CLSID_AMMultiMediaStream, amsFact, 1, 1, &regCookie);
    amsFact->Release();
}

} // namespace micant::wmp
