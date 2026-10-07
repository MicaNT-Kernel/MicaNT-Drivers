// ============================================================================
// Standalone Driver Verification Test: hdaudio (TitanHDA / NexusHDA)
// Subsystem: Intel High Definition Audio (HDA 1.0a) & USB Audio 2.0 Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/hdaudio.hpp"

using namespace micant;

static int g_PassedTests = 0;
static int g_FailedTests = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "  [FAIL] " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            g_FailedTests++; \
            return; \
        } \
    } while (0)

#define RUN_TEST(fn) \
    do { \
        std::cout << "[RUNNING] " << #fn << "...\n" << std::flush; \
        int before = g_FailedTests; \
        fn(); \
        if (g_FailedTests == before) { \
            std::cout << "  [PASS] " << #fn << "\n" << std::flush; \
            g_PassedTests++; \
        } \
    } while (0)

void Test_IntelHighDefinitionAudio_USBAudio_Subsystem() {
    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 155: Intel High Definition Audio (HDA 1.0a) & USB Audio 2.0     \n";
    std::cout << "========================================================================\n";

    // Initialize HDA Subsystem defensively
    hda::InitializeHdaSubsystem();
    auto& hdaSub = hda::TitanHdaSubsystem::Instance();
    TEST_ASSERT(hdaSub.isInitialized(), "TitanHdaSubsystem must be initialized");

    // Stage 1: PCI Device Discovery (00:05.0 Vendor 0x8086 Device 0x7AD0)
    auto pciAudio = pci::TitanPciSubsystem::Instance().findDeviceByVendorDevice(0x8086, 0x7AD0);
    TEST_ASSERT(pciAudio != nullptr, "PrismAudio HDA PCI device (00:05.0) must be discovered in PCI bus tree");
    TEST_ASSERT(pciAudio->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Multimedia), "PrismAudio device class must be Multimedia (0x04)");
    TEST_ASSERT(pciAudio->getSubClass() == 0x03, "PrismAudio subclass must be Audio Device (0x03)");
    TEST_ASSERT(hdaSub.getMmioBaseAddress() != 0, "HDA controller MMIO Base Address must be allocated non-zero");

    // Stage 2: Hardware Controller Reset & CRST State
    hdaSub.resetController();
    TEST_ASSERT(hda::HdaControllerReset() == win32::TRUE, "HdaControllerReset C ABI export must succeed");

    // Stage 3: Onboard Audio Codec Discovery (Address 0, Realtek ALC887 / Sovereign HDA)
    auto codec0 = hdaSub.getCodec(0);
    TEST_ASSERT(codec0 != nullptr, "Primary audio codec must be present at link address 0");
    TEST_ASSERT(codec0->getVendorId() == 0x10EC, "Codec vendor ID must be Realtek/Sovereign (0x10EC)");
    TEST_ASSERT(codec0->getDeviceId() == 0x0887, "Codec device ID must be ALC887 (0x0887)");
    TEST_ASSERT(codec0->getRevision() == 0x00010003, "Codec revision must be 0x00010003");

    uint16_t cVend = 0, cDev = 0;
    uint32_t cRev = 0;
    TEST_ASSERT(hda::HdaGetCodecInfo(0, &cVend, &cDev, &cRev) == win32::TRUE, "HdaGetCodecInfo export must succeed");
    TEST_ASSERT(cVend == 0x10EC && cDev == 0x0887, "Exported codec vendor/device must match ALC887");

    // Stage 4: Audio Function Group (Node 1) Enumeration
    uint32_t fgType = 0;
    hda::HdaSendVerb(0, 1, hda::HDA_VERB_GET_PARAM, hda::HDA_PARAM_FUNC_GROUP_TYPE, &fgType);
    TEST_ASSERT(fgType == 0x01, "Node 1 Function Group Type must be Audio (0x01)");

    uint32_t subNodeCount = 0;
    hda::HdaSendVerb(0, 1, hda::HDA_VERB_GET_PARAM, hda::HDA_PARAM_SUB_NODE_COUNT, &subNodeCount);
    uint16_t startNode = static_cast<uint16_t>(subNodeCount >> 16);
    uint16_t totalNodes = static_cast<uint16_t>(subNodeCount & 0xFFFF);
    TEST_ASSERT(startNode == 2 && totalNodes == 24, "AFG sub-nodes must start at 2 with 24 total widgets");

    // Stage 5: Audio Output Converter (DAC 0, Node 0x02) Capabilities & Formats
    uint32_t dacCaps = 0;
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_GET_PARAM, hda::HDA_PARAM_AUDIO_WIDGET_CAPS, &dacCaps);
    auto widgetType = static_cast<hda::HdaWidgetType>(dacCaps >> 20);
    TEST_ASSERT(widgetType == hda::HdaWidgetType::AudioOutput, "Node 0x02 widget type must be Audio Output (DAC)");

    uint32_t dacFmts = 0;
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_GET_PARAM, hda::HDA_PARAM_SUPPORTED_FORMATS, &dacFmts);
    TEST_ASSERT((dacFmts & 0x01) != 0, "DAC 0 must support 44.1 kHz PCM");
    TEST_ASSERT((dacFmts & 0x02) != 0, "DAC 0 must support 48.0 kHz PCM");

    // Stage 6: Codec Verb Execution (Stream/Channel, Amp Gain & Mute)
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_SET_STREAM_CHANNEL, (4 << 4) | 0, nullptr);
    uint32_t scResp = 0;
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_GET_STREAM_CHANNEL, 0, &scResp);
    TEST_ASSERT(((scResp >> 4) & 0x0F) == 4, "DAC 0 stream tag must be set to 4");
    TEST_ASSERT((scResp & 0x0F) == 0, "DAC 0 channel index must be 0");

    // Set Amp Gain to 0x7F (100% volume, unmuted)
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_SET_AMP_GAIN_MUTE, (1 << 13) | (1 << 12) | 0x7F, nullptr);
    uint32_t ampResp = 0;
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_GET_AMP_GAIN_MUTE, 0, &ampResp);
    TEST_ASSERT((ampResp & 0x7F) == 0x7F, "Amp gain must report 0x7F (0 dB)");
    TEST_ASSERT((ampResp & (1 << 7)) == 0, "Amp must report unmuted");

    // Stage 7: Pin Complex & Jack Detection Sense (Nodes 0x14 Front HP & 0x15 Rear Line-Out)
    int32_t hpConnected = 0;
    TEST_ASSERT(hda::HdaGetJackStatus(0, 0x14, &hpConnected) == win32::TRUE, "HdaGetJackStatus Node 0x14 must succeed");
    TEST_ASSERT(hpConnected == win32::TRUE, "Headphone jack (Node 0x14) must report connected");

    int32_t micConnected = 0;
    hda::HdaGetJackStatus(0, 0x18, &micConnected);
    TEST_ASSERT(micConnected == win32::FALSE, "Mic jack (Node 0x18) must report disconnected initially");

    // Simulate Jack Insertion on Mic (Unsolicited Event)
    codec0->setJackConnected(0x18, true);
    hda::HdaGetJackStatus(0, 0x18, &micConnected);
    TEST_ASSERT(micConnected == win32::TRUE, "Mic jack (Node 0x18) must report connected after insertion event");

    // Stage 8: Hardware Stream Descriptor Allocation & Format Encoding
    auto streamOut4 = hdaSub.getStream(4);
    TEST_ASSERT(streamOut4 != nullptr, "Output Stream 4 must exist");
    TEST_ASSERT(streamOut4->isOutput() == true, "Stream 4 direction must be Output");

    uint16_t fmt48k = hda::HdaEncodeFormat(48000, 2, 16);
    TEST_ASSERT((fmt48k & (1 << 14)) == 0, "48kHz format must have bit 14 clear (48k base)");
    TEST_ASSERT((fmt48k & 0x0F) == 1, "2-channel format must have channel bits = 1");

    uint16_t fmt44k = hda::HdaEncodeFormat(44100, 2, 16);
    TEST_ASSERT((fmt44k & (1 << 14)) != 0, "44.1kHz format must have bit 14 set (44.1k base)");

    // Stage 9: Buffer Descriptor List (BDL) & Cyclic DMA Buffer Programming
    int32_t bdlRes = hda::HdaSetupStream(4, win32::TRUE, 48000, 2, 16, 0x78000000ULL, 8192);
    TEST_ASSERT(bdlRes == win32::TRUE, "HdaSetupStream for Stream 4 must succeed");
    TEST_ASSERT(streamOut4->getBufferLength() == 8192, "Stream 4 cyclic buffer length must be 8192 bytes");

    // Stage 10: Stream DMA Engine Lifecycle & Position Advancement
    TEST_ASSERT(hda::HdaStartStream(4) == win32::TRUE, "HdaStartStream must start DMA engine");
    TEST_ASSERT(streamOut4->isActive() == true, "Stream 4 must report active status");

    streamOut4->advanceDma(2048);
    uint32_t curPos = 0;
    TEST_ASSERT(hda::HdaGetStreamPosition(4, &curPos) == win32::TRUE, "HdaGetStreamPosition must succeed");
    TEST_ASSERT(curPos == 2048, "Stream 4 position must advance to 2048 bytes");

    streamOut4->advanceDma(8192); // Wrap around cyclic buffer
    hda::HdaGetStreamPosition(4, &curPos);
    TEST_ASSERT(curPos == 2048, "Cyclic buffer must wrap around modulo 8192");

    TEST_ASSERT(hda::HdaStopStream(4) == win32::TRUE, "HdaStopStream must stop stream");
    TEST_ASSERT(streamOut4->isActive() == false, "Stream 4 must report stopped status");

    // Stage 11: Realtime Hardware Tone DMA Synthesis & PrismAudio Integration
    int32_t toneRes = hda::HdaSynthesizeTone(4, 880.0f, 50, 0.7f); // 880 Hz A5 tone
    TEST_ASSERT(toneRes == win32::TRUE, "HdaSynthesizeTone must successfully write PCM samples and arm DMA");
    TEST_ASSERT(streamOut4->getVirtualBuffer().size() > 0, "Stream virtual buffer must contain synthesized PCM data");

    // USB Audio Class 2.0 (UAC2) Device Bridge
    auto& uac = hdaSub.getUsbAudio();
    TEST_ASSERT(uac.getSampleRate() == 48000, "UAC2 device must support 48000 Hz");
    TEST_ASSERT(uac.getBitsPerSample() == 24, "UAC2 device must support 24-bit studio resolution");
    uac.startStreaming();
    TEST_ASSERT(uac.isStreaming() == true, "UAC2 device must be actively streaming");
    uac.stopStreaming();

    // Stage 12: Driver Exports in hdaudio.sys & SCM Driver Registrations
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaControllerReset") != nullptr, "hdaudio.sys HdaControllerReset export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaSendVerb") != nullptr, "hdaudio.sys HdaSendVerb export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaSetupStream") != nullptr, "hdaudio.sys HdaSetupStream export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaStartStream") != nullptr, "hdaudio.sys HdaStartStream export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaStopStream") != nullptr, "hdaudio.sys HdaStopStream export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaGetStreamPosition") != nullptr, "hdaudio.sys HdaGetStreamPosition export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaGetCodecInfo") != nullptr, "hdaudio.sys HdaGetCodecInfo export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaGetJackStatus") != nullptr, "hdaudio.sys HdaGetJackStatus export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaSynthesizeTone") != nullptr, "hdaudio.sys HdaSynthesizeTone export must exist");

    auto hdaSvc = scm::ServiceControlManager::get().getServiceRecord(L"hdaudio");
    TEST_ASSERT(hdaSvc != nullptr, "hdaudio service record must exist in SCM");
    TEST_ASSERT(hdaSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "hdaudio service type must be kernel driver");
    TEST_ASSERT(hdaSvc->startType == scm::SERVICE_BOOT_START, "hdaudio service start type must be boot start");

    auto uacSvc = scm::ServiceControlManager::get().getServiceRecord(L"usbaudio2");
    TEST_ASSERT(uacSvc != nullptr, "usbaudio2 service record must exist in SCM");

    auto hdaVer = version::VersionDatabase::Instance().GetModuleInfo("hdaudio.sys");
    TEST_ASSERT(hdaVer != nullptr, "hdaudio.sys must be registered in Version Database");
    TEST_ASSERT(hdaVer->stringTable.count("FileVersion") > 0, "hdaudio.sys FileVersion must exist");

    std::cout << "[TEST] Suite 155: Intel High Definition Audio & USB Audio PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Intel High Definition Audio (HDA 1.0a) & USB Audio 2.0 Subsystem\n";
    std::cout << "       Codename: TitanHDA / NexusHDA | Binary: hdaudio.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_IntelHighDefinitionAudio_USBAudio_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
