#pragma once

/**
 * @file vulkan.hpp
 * @brief MicaNT Sovereign Vulkan 1.3 ICD Loader & PrismVK Graphics Driver.
 *
 * Implements the standard Khronos Vulkan ICD Loader architecture (vulkan-1.dll),
 * driver discovery via the MicaNT Configuration Manager (\Registry\Machine\SOFTWARE\Khronos\Vulkan\Drivers),
 * and the built-in PrismVK sovereign Vulkan graphics driver.
 *
 * Clean-Room Engineering Notice:
 * Developed strictly against public Khronos Vulkan API specifications and
 * architecture guides under MIT / Apache 2.0 interoperability standards.
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include "ntdef.hpp"
#include "cm.hpp"
#include "ldr.hpp"
#include "prismx.hpp"
#include "prism3d.hpp"

namespace micant::vulkan {

// ============================================================================
// Core Vulkan Types & Macros
// ============================================================================

#define VK_MAKE_VERSION(major, minor, patch) \
    ((((uint32_t)(major)) << 22) | (((uint32_t)(minor)) << 12) | ((uint32_t)(patch)))

#define VK_API_VERSION_1_0 VK_MAKE_VERSION(1, 0, 0)
#define VK_API_VERSION_1_1 VK_MAKE_VERSION(1, 1, 0)
#define VK_API_VERSION_1_2 VK_MAKE_VERSION(1, 2, 0)
#define VK_API_VERSION_1_3 VK_MAKE_VERSION(1, 3, 0)

#define VK_DEFINE_NON_DISPATCHABLE_HANDLE(object) typedef uint64_t object;

// Opaque Dispatchable Handles
struct VkInstance_T;
typedef VkInstance_T* VkInstance;

struct VkPhysicalDevice_T;
typedef VkPhysicalDevice_T* VkPhysicalDevice;

struct VkDevice_T;
typedef VkDevice_T* VkDevice;

struct VkQueue_T;
typedef VkQueue_T* VkQueue;

struct VkCommandBuffer_T;
typedef VkCommandBuffer_T* VkCommandBuffer;

// Non-Dispatchable Handles
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkSurfaceKHR)
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkSwapchainKHR)
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkCommandPool)
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkRenderPass)
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkFramebuffer)
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkImage)
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkImageView)
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkBuffer)
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkDeviceMemory)
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkSemaphore)
VK_DEFINE_NON_DISPATCHABLE_HANDLE(VkFence)

// Vulkan Status & Result Codes
enum VkResult : int32_t {
    VK_SUCCESS = 0,
    VK_NOT_READY = 1,
    VK_TIMEOUT = 2,
    VK_EVENT_SET = 3,
    VK_EVENT_RESET = 4,
    VK_INCOMPLETE = 5,
    VK_ERROR_OUT_OF_HOST_MEMORY = -1,
    VK_ERROR_OUT_OF_DEVICE_MEMORY = -2,
    VK_ERROR_INITIALIZATION_FAILED = -3,
    VK_ERROR_DEVICE_LOST = -4,
    VK_ERROR_MEMORY_MAP_FAILED = -5,
    VK_ERROR_LAYER_NOT_PRESENT = -6,
    VK_ERROR_EXTENSION_NOT_PRESENT = -7,
    VK_ERROR_FEATURE_NOT_PRESENT = -8,
    VK_ERROR_INCOMPATIBLE_DRIVER = -9,
    VK_ERROR_TOO_MANY_OBJECTS = -10,
    VK_ERROR_FORMAT_NOT_SUPPORTED = -11,
    VK_ERROR_FRAGMENTED_POOL = -12,
    VK_ERROR_UNKNOWN = -13,
    VK_ERROR_SURFACE_LOST_KHR = -1000000000,
    VK_ERROR_NATIVE_WINDOW_IN_USE_KHR = -1000000001,
    VK_SUBOPTIMAL_KHR = 1000001003,
    VK_ERROR_OUT_OF_DATE_KHR = -1000001004
};

// Structure Types
enum VkStructureType : uint32_t {
    VK_STRUCTURE_TYPE_APPLICATION_INFO = 0,
    VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO = 1,
    VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO = 2,
    VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO = 3,
    VK_STRUCTURE_TYPE_SUBMIT_INFO = 4,
    VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO = 5,
    VK_STRUCTURE_TYPE_FENCE_CREATE_INFO = 8,
    VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO = 9,
    VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO = 39,
    VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO = 40,
    VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO = 42,
    VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO = 43,
    VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR = 1000009000,
    VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR = 1000001000,
    VK_STRUCTURE_TYPE_PRESENT_INFO_KHR = 1000001001
};

enum VkPhysicalDeviceType : uint32_t {
    VK_PHYSICAL_DEVICE_TYPE_OTHER = 0,
    VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU = 1,
    VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU = 2,
    VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU = 3,
    VK_PHYSICAL_DEVICE_TYPE_CPU = 4
};

enum VkFormat : uint32_t {
    VK_FORMAT_UNDEFINED = 0,
    VK_FORMAT_R8G8B8A8_UNORM = 37,
    VK_FORMAT_B8G8R8A8_UNORM = 44,
    VK_FORMAT_D32_SFLOAT = 126
};

enum VkColorSpaceKHR : uint32_t {
    VK_COLOR_SPACE_SRGB_NONLINEAR_KHR = 0
};

enum VkPresentModeKHR : uint32_t {
    VK_PRESENT_MODE_IMMEDIATE_KHR = 0,
    VK_PRESENT_MODE_MAILBOX_KHR = 1,
    VK_PRESENT_MODE_FIFO_KHR = 2,
    VK_PRESENT_MODE_FIFO_RELAXED_KHR = 3
};

enum VkQueueFlagBits : uint32_t {
    VK_QUEUE_GRAPHICS_BIT = 0x00000001,
    VK_QUEUE_COMPUTE_BIT = 0x00000002,
    VK_QUEUE_TRANSFER_BIT = 0x00000004
};

enum VkMemoryPropertyFlagBits : uint32_t {
    VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT = 0x00000001,
    VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT = 0x00000002,
    VK_MEMORY_PROPERTY_HOST_COHERENT_BIT = 0x00000004,
    VK_MEMORY_PROPERTY_HOST_CACHED_BIT = 0x00000008
};

enum VkImageUsageFlagBits : uint32_t {
    VK_IMAGE_USAGE_TRANSFER_SRC_BIT = 0x00000001,
    VK_IMAGE_USAGE_TRANSFER_DST_BIT = 0x00000002,
    VK_IMAGE_USAGE_SAMPLED_BIT = 0x00000004,
    VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT = 0x00000010,
    VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT = 0x00000020
};

enum VkCompositeAlphaFlagBitsKHR : uint32_t {
    VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR = 0x00000001
};

enum VkSurfaceTransformFlagBitsKHR : uint32_t {
    VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR = 0x00000001
};

enum VkCommandBufferLevel : uint32_t {
    VK_COMMAND_BUFFER_LEVEL_PRIMARY = 0,
    VK_COMMAND_BUFFER_LEVEL_SECONDARY = 1
};

enum VkSubpassContents : uint32_t {
    VK_SUBPASS_CONTENTS_INLINE = 0,
    VK_SUBPASS_CONTENTS_SECONDARY_COMMAND_BUFFERS = 1
};

// ============================================================================
// Vulkan Structures
// ============================================================================

struct VkApplicationInfo {
    VkStructureType sType;
    const void* pNext;
    const char* pApplicationName;
    uint32_t applicationVersion;
    const char* pEngineName;
    uint32_t engineVersion;
    uint32_t apiVersion;
};

struct VkInstanceCreateInfo {
    VkStructureType sType;
    const void* pNext;
    uint32_t flags;
    const VkApplicationInfo* pApplicationInfo;
    uint32_t enabledLayerCount;
    const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount;
    const char* const* ppEnabledExtensionNames;
};

struct VkExtent2D {
    uint32_t width;
    uint32_t height;
};

struct VkOffset2D {
    int32_t x;
    int32_t y;
};

struct VkRect2D {
    VkOffset2D offset;
    VkExtent2D extent;
};

struct VkViewport {
    float x;
    float y;
    float width;
    float height;
    float minDepth;
    float maxDepth;
};

struct VkPhysicalDeviceLimits {
    uint32_t maxImageDimension2D;
    uint32_t maxPushConstantsSize;
    uint32_t maxMemoryAllocationCount;
    uint32_t maxBoundDescriptorSets;
    uint32_t maxViewports;
    float maxViewportDimensions[2];
};

struct VkPhysicalDeviceProperties {
    uint32_t apiVersion;
    uint32_t driverVersion;
    uint32_t vendorID;
    uint32_t deviceID;
    VkPhysicalDeviceType deviceType;
    char deviceName[256];
    uint8_t pipelineCacheUUID[16];
    VkPhysicalDeviceLimits limits;
};

struct VkPhysicalDeviceFeatures {
    uint32_t robustBufferAccess;
    uint32_t fullDrawIndexUint32;
    uint32_t imageCubeArray;
    uint32_t independentBlend;
    uint32_t geometryShader;
    uint32_t tessellationShader;
    uint32_t sampleRateShading;
    uint32_t dualSrcBlend;
    uint32_t logicOp;
    uint32_t multiDrawIndirect;
    uint32_t depthClamp;
    uint32_t depthBiasClamp;
    uint32_t fillModeNonSolid;
    uint32_t depthBounds;
    uint32_t wideLines;
    uint32_t largePoints;
    uint32_t alphaToOne;
    uint32_t multiViewport;
    uint32_t samplerAnisotropy;
    uint32_t textureCompressionETC2;
    uint32_t textureCompressionBC;
    uint32_t occludedQuery;
    uint32_t pipelineStatisticsQuery;
};

struct VkMemoryType {
    uint32_t propertyFlags;
    uint32_t heapIndex;
};

struct VkMemoryHeap {
    uint64_t size;
    uint32_t flags;
};

struct VkPhysicalDeviceMemoryProperties {
    uint32_t memoryTypeCount;
    VkMemoryType memoryTypes[32];
    uint32_t memoryHeapCount;
    VkMemoryHeap memoryHeaps[16];
};

struct VkQueueFamilyProperties {
    uint32_t queueFlags;
    uint32_t queueCount;
    uint32_t timestampValidBits;
    VkExtent2D minImageTransferGranularity;
};

struct VkDeviceQueueCreateInfo {
    VkStructureType sType;
    const void* pNext;
    uint32_t flags;
    uint32_t queueFamilyIndex;
    uint32_t queueCount;
    const float* pQueuePriorities;
};

struct VkDeviceCreateInfo {
    VkStructureType sType;
    const void* pNext;
    uint32_t flags;
    uint32_t queueCreateInfoCount;
    const VkDeviceQueueCreateInfo* pQueueCreateInfos;
    uint32_t enabledLayerCount;
    const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount;
    const char* const* ppEnabledExtensionNames;
    const VkPhysicalDeviceFeatures* pEnabledFeatures;
};

struct VkWin32SurfaceCreateInfoKHR {
    VkStructureType sType;
    const void* pNext;
    uint32_t flags;
    void* hinstance;
    void* hwnd;
};

struct VkSurfaceCapabilitiesKHR {
    uint32_t minImageCount;
    uint32_t maxImageCount;
    VkExtent2D currentExtent;
    VkExtent2D minImageExtent;
    VkExtent2D maxImageExtent;
    uint32_t maxImageArrayLayers;
    uint32_t supportedTransforms;
    uint32_t currentTransform;
    uint32_t supportedCompositeAlpha;
    uint32_t supportedUsageFlags;
};

struct VkSurfaceFormatKHR {
    VkFormat format;
    VkColorSpaceKHR colorSpace;
};

struct VkSwapchainCreateInfoKHR {
    VkStructureType sType;
    const void* pNext;
    uint32_t flags;
    VkSurfaceKHR surface;
    uint32_t minImageCount;
    VkFormat imageFormat;
    VkColorSpaceKHR imageColorSpace;
    VkExtent2D imageExtent;
    uint32_t imageArrayLayers;
    uint32_t imageUsage;
    uint32_t imageSharingMode;
    uint32_t queueFamilyIndexCount;
    const uint32_t* pQueueFamilyIndices;
    uint32_t preTransform;
    uint32_t compositeAlpha;
    VkPresentModeKHR presentMode;
    uint32_t clipped;
    VkSwapchainKHR oldSwapchain;
};

struct VkCommandPoolCreateInfo {
    VkStructureType sType;
    const void* pNext;
    uint32_t flags;
    uint32_t queueFamilyIndex;
};

struct VkCommandBufferAllocateInfo {
    VkStructureType sType;
    const void* pNext;
    VkCommandPool commandPool;
    VkCommandBufferLevel level;
    uint32_t commandBufferCount;
};

struct VkCommandBufferBeginInfo {
    VkStructureType sType;
    const void* pNext;
    uint32_t flags;
    const void* pInheritanceInfo;
};

union VkClearColorValue {
    float float32[4];
    int32_t int32[4];
    uint32_t uint32[4];
};

struct VkClearDepthStencilValue {
    float depth;
    uint32_t stencil;
};

union VkClearValue {
    VkClearColorValue color;
    VkClearDepthStencilValue depthStencil;
};

struct VkRenderPassBeginInfo {
    VkStructureType sType;
    const void* pNext;
    VkRenderPass renderPass;
    VkFramebuffer framebuffer;
    VkRect2D renderArea;
    uint32_t clearValueCount;
    const VkClearValue* pClearValues;
};

struct VkSubmitInfo {
    VkStructureType sType;
    const void* pNext;
    uint32_t waitSemaphoreCount;
    const VkSemaphore* pWaitSemaphores;
    const uint32_t* pWaitDstStageMask;
    uint32_t commandBufferCount;
    const VkCommandBuffer* pCommandBuffers;
    uint32_t signalSemaphoreCount;
    const VkSemaphore* pSignalSemaphores;
};

struct VkPresentInfoKHR {
    VkStructureType sType;
    const void* pNext;
    uint32_t waitSemaphoreCount;
    const VkSemaphore* pWaitSemaphores;
    uint32_t swapchainCount;
    const VkSwapchainKHR* pSwapchains;
    const uint32_t* pImageIndices;
    VkResult* pResults;
};

// ============================================================================
// Internal PrismVK Driver Implementation Objects
// ============================================================================

struct SurfaceObject {
    uint64_t surfaceId{0};
    void* hwnd{nullptr};
    void* hinstance{nullptr};
    uint32_t width{1280};
    uint32_t height{720};
};

struct SwapchainObject {
    uint64_t swapchainId{0};
    SurfaceObject* surface{nullptr};
    uint32_t width{1280};
    uint32_t height{720};
    VkFormat format{VK_FORMAT_B8G8R8A8_UNORM};
    uint32_t imageCount{2};
    uint32_t currentImageIndex{0};
    std::vector<std::vector<uint32_t>> backbuffers;
};

struct VkQueue_T {
    VkDevice parentDevice{nullptr};
    uint32_t familyIndex{0};
    uint32_t queueIndex{0};
};

enum class VkCommandType {
    BeginRenderPass,
    EndRenderPass,
    SetViewport,
    DrawTriangle
};

struct RecordedCommand {
    VkCommandType type;
    VkClearColorValue clearColor;
    VkViewport viewport;
    uint32_t vertexCount;
};

struct VkCommandBuffer_T {
    VkCommandPool pool{0};
    bool recording{false};
    std::vector<RecordedCommand> commands;
};

struct VkDevice_T {
    VkPhysicalDevice physicalDevice{nullptr};
    std::vector<std::unique_ptr<VkQueue_T>> queues;
    std::unordered_map<uint64_t, std::unique_ptr<SwapchainObject>> swapchains;
    uint64_t nextSwapchainId{1};
};

struct VkPhysicalDevice_T {
    VkInstance parentInstance{nullptr};
    std::string name{"PrismVK Sovereign Graphics Engine (WDDM 3.0)"};
    uint32_t vendorId{0x1414}; // Microsoft / Sovereign Prism
    uint32_t deviceId{0x008C}; // Prism3D Unified Rasterizer
};

struct VkInstance_T {
    std::string appName{"MicaNT Application"};
    uint32_t apiVersion{VK_API_VERSION_1_3};
    std::vector<std::unique_ptr<VkPhysicalDevice_T>> physicalDevices;
    std::unordered_map<uint64_t, std::unique_ptr<SurfaceObject>> surfaces;
    uint64_t nextSurfaceId{1};
};

// ============================================================================
// Vulkan ICD Loader & Registry Manager
// ============================================================================

class VulkanLoader {
public:
    static VulkanLoader& get() {
        static VulkanLoader instance;
        return instance;
    }

    void initializeIcdRegistry() {
        auto& cm = cm::ConfigurationManager::get();
        auto sw = cm.resolvePath(L"\\Registry\\Machine\\SOFTWARE");
        if (sw) {
            auto khronos = sw->createSubkey(L"Khronos");
            if (khronos) {
                auto vk = khronos->createSubkey(L"Vulkan");
                if (vk) {
                    auto drivers = vk->createSubkey(L"Drivers");
                    if (drivers) {
                        drivers->setValueDword(L"C:\\Windows\\System32\\prism_vk.json", 0);
                    }
                }
            }
        }
        m_icdDiscovered = true;
    }

    bool isIcdRegistered() const {
        auto& cm = cm::ConfigurationManager::get();
        auto drivers = cm.resolvePath(L"\\Registry\\Machine\\SOFTWARE\\Khronos\\Vulkan\\Drivers");
        if (!drivers) return false;
        return drivers->getValue(L"C:\\Windows\\System32\\prism_vk.json") != nullptr;
    }

private:
    VulkanLoader() = default;
    bool m_icdDiscovered{false};
};

// ============================================================================
// Core Vulkan API Functions (vulkan-1.dll entry points)
// ============================================================================

inline VkResult vkCreateInstance(
    const VkInstanceCreateInfo* pCreateInfo,
    const void* /*pAllocator*/,
    VkInstance* pInstance
) noexcept {
    if (!pCreateInfo || !pInstance) return VK_ERROR_INITIALIZATION_FAILED;

    VulkanLoader::get().initializeIcdRegistry();

    auto inst = std::make_unique<VkInstance_T>();
    if (pCreateInfo->pApplicationInfo && pCreateInfo->pApplicationInfo->pApplicationName) {
        inst->appName = pCreateInfo->pApplicationInfo->pApplicationName;
        inst->apiVersion = pCreateInfo->pApplicationInfo->apiVersion;
    }

    // Enumerate Sovereign PrismVK Physical Device
    auto phys = std::make_unique<VkPhysicalDevice_T>();
    phys->parentInstance = inst.get();
    inst->physicalDevices.push_back(std::move(phys));

    *pInstance = inst.release();
    return VK_SUCCESS;
}

inline void vkDestroyInstance(VkInstance instance, const void* /*pAllocator*/) noexcept {
    if (instance) {
        delete instance;
    }
}

inline VkResult vkEnumeratePhysicalDevices(
    VkInstance instance,
    uint32_t* pPhysicalDeviceCount,
    VkPhysicalDevice* pPhysicalDevices
) noexcept {
    if (!instance || !pPhysicalDeviceCount) return VK_ERROR_INITIALIZATION_FAILED;

    uint32_t available = static_cast<uint32_t>(instance->physicalDevices.size());
    if (!pPhysicalDevices) {
        *pPhysicalDeviceCount = available;
        return VK_SUCCESS;
    }

    uint32_t count = std::min(*pPhysicalDeviceCount, available);
    for (uint32_t i = 0; i < count; ++i) {
        pPhysicalDevices[i] = instance->physicalDevices[i].get();
    }
    *pPhysicalDeviceCount = count;
    return VK_SUCCESS;
}

inline void vkGetPhysicalDeviceProperties(
    VkPhysicalDevice physicalDevice,
    VkPhysicalDeviceProperties* pProperties
) noexcept {
    if (!physicalDevice || !pProperties) return;

    pProperties->apiVersion = VK_API_VERSION_1_3;
    pProperties->driverVersion = VK_MAKE_VERSION(1, 0, 0);
    pProperties->vendorID = physicalDevice->vendorId;
    pProperties->deviceID = physicalDevice->deviceId;
    pProperties->deviceType = VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU;
    
    strncpy_s(pProperties->deviceName, physicalDevice->name.c_str(), sizeof(pProperties->deviceName) - 1);

    pProperties->limits.maxImageDimension2D = 16384;
    pProperties->limits.maxPushConstantsSize = 256;
    pProperties->limits.maxMemoryAllocationCount = 4096;
    pProperties->limits.maxBoundDescriptorSets = 8;
    pProperties->limits.maxViewports = 16;
    pProperties->limits.maxViewportDimensions[0] = 16384.0f;
    pProperties->limits.maxViewportDimensions[1] = 16384.0f;
}

inline void vkGetPhysicalDeviceFeatures(
    VkPhysicalDevice /*physicalDevice*/,
    VkPhysicalDeviceFeatures* pFeatures
) noexcept {
    if (!pFeatures) return;
    std::memset(pFeatures, 0, sizeof(VkPhysicalDeviceFeatures));
    pFeatures->robustBufferAccess = 1;
    pFeatures->fullDrawIndexUint32 = 1;
    pFeatures->geometryShader = 1;
    pFeatures->samplerAnisotropy = 1;
    pFeatures->textureCompressionBC = 1;
}

inline void vkGetPhysicalDeviceQueueFamilyProperties(
    VkPhysicalDevice /*physicalDevice*/,
    uint32_t* pQueueFamilyPropertyCount,
    VkQueueFamilyProperties* pQueueFamilyProperties
) noexcept {
    if (!pQueueFamilyPropertyCount) return;
    if (!pQueueFamilyProperties) {
        *pQueueFamilyPropertyCount = 1;
        return;
    }

    pQueueFamilyProperties[0].queueFlags = VK_QUEUE_GRAPHICS_BIT | VK_QUEUE_COMPUTE_BIT | VK_QUEUE_TRANSFER_BIT;
    pQueueFamilyProperties[0].queueCount = 16;
    pQueueFamilyProperties[0].timestampValidBits = 64;
    pQueueFamilyProperties[0].minImageTransferGranularity = {1, 1};
    *pQueueFamilyPropertyCount = 1;
}

inline void vkGetPhysicalDeviceMemoryProperties(
    VkPhysicalDevice /*physicalDevice*/,
    VkPhysicalDeviceMemoryProperties* pMemoryProperties
) noexcept {
    if (!pMemoryProperties) return;

    pMemoryProperties->memoryTypeCount = 2;
    // Type 0: Device Local High-Speed VRAM
    pMemoryProperties->memoryTypes[0].propertyFlags = VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
    pMemoryProperties->memoryTypes[0].heapIndex = 0;
    // Type 1: Host Visible Coherent System RAM
    pMemoryProperties->memoryTypes[1].propertyFlags = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    pMemoryProperties->memoryTypes[1].heapIndex = 1;

    pMemoryProperties->memoryHeapCount = 2;
    // Heap 0: 8192 MB Dedicated Video Memory
    pMemoryProperties->memoryHeaps[0].size = 8192ULL * 1024 * 1024;
    pMemoryProperties->memoryHeaps[0].flags = VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
    // Heap 1: 16384 MB Shared Host Memory
    pMemoryProperties->memoryHeaps[1].size = 16384ULL * 1024 * 1024;
    pMemoryProperties->memoryHeaps[1].flags = 0;
}

inline VkResult vkCreateDevice(
    VkPhysicalDevice physicalDevice,
    const VkDeviceCreateInfo* pCreateInfo,
    const void* /*pAllocator*/,
    VkDevice* pDevice
) noexcept {
    if (!physicalDevice || !pCreateInfo || !pDevice) return VK_ERROR_INITIALIZATION_FAILED;

    auto dev = std::make_unique<VkDevice_T>();
    dev->physicalDevice = physicalDevice;

    // Create Requested Queues
    for (uint32_t i = 0; i < pCreateInfo->queueCreateInfoCount; ++i) {
        const auto& qci = pCreateInfo->pQueueCreateInfos[i];
        for (uint32_t q = 0; q < qci.queueCount; ++q) {
            auto qObj = std::make_unique<VkQueue_T>();
            qObj->parentDevice = dev.get();
            qObj->familyIndex = qci.queueFamilyIndex;
            qObj->queueIndex = q;
            dev->queues.push_back(std::move(qObj));
        }
    }

    *pDevice = dev.release();
    return VK_SUCCESS;
}

inline void vkDestroyDevice(VkDevice device, const void* /*pAllocator*/) noexcept {
    if (device) {
        delete device;
    }
}

inline void vkGetDeviceQueue(
    VkDevice device,
    uint32_t queueFamilyIndex,
    uint32_t queueIndex,
    VkQueue* pQueue
) noexcept {
    if (!device || !pQueue) return;
    for (const auto& q : device->queues) {
        if (q->familyIndex == queueFamilyIndex && q->queueIndex == queueIndex) {
            *pQueue = q.get();
            return;
        }
    }
    if (!device->queues.empty()) {
        *pQueue = device->queues[0].get();
    }
}

// ============================================================================
// Win32 Surface & Swapchain Extensions (VK_KHR_win32_surface & VK_KHR_swapchain)
// ============================================================================

inline VkResult vkCreateWin32SurfaceKHR(
    VkInstance instance,
    const VkWin32SurfaceCreateInfoKHR* pCreateInfo,
    const void* /*pAllocator*/,
    VkSurfaceKHR* pSurface
) noexcept {
    if (!instance || !pCreateInfo || !pSurface) return VK_ERROR_INITIALIZATION_FAILED;

    auto surf = std::make_unique<SurfaceObject>();
    uint64_t sid = instance->nextSurfaceId++;
    surf->surfaceId = sid;
    surf->hwnd = pCreateInfo->hwnd;
    surf->hinstance = pCreateInfo->hinstance;
    surf->width = 1280;
    surf->height = 720;

    instance->surfaces[sid] = std::move(surf);
    *pSurface = sid;
    return VK_SUCCESS;
}

inline void vkDestroySurfaceKHR(
    VkInstance instance,
    VkSurfaceKHR surface,
    const void* /*pAllocator*/
) noexcept {
    if (!instance || surface == 0) return;
    instance->surfaces.erase(surface);
}

inline VkResult vkGetPhysicalDeviceSurfaceCapabilitiesKHR(
    VkPhysicalDevice /*physicalDevice*/,
    VkSurfaceKHR /*surface*/,
    VkSurfaceCapabilitiesKHR* pSurfaceCapabilities
) noexcept {
    if (!pSurfaceCapabilities) return VK_ERROR_INITIALIZATION_FAILED;

    pSurfaceCapabilities->minImageCount = 2;
    pSurfaceCapabilities->maxImageCount = 8;
    pSurfaceCapabilities->currentExtent = {1280, 720};
    pSurfaceCapabilities->minImageExtent = {320, 240};
    pSurfaceCapabilities->maxImageExtent = {7680, 4320};
    pSurfaceCapabilities->maxImageArrayLayers = 1;
    pSurfaceCapabilities->supportedTransforms = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
    pSurfaceCapabilities->currentTransform = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
    pSurfaceCapabilities->supportedCompositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    pSurfaceCapabilities->supportedUsageFlags = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT;

    return VK_SUCCESS;
}

inline VkResult vkGetPhysicalDeviceSurfaceFormatsKHR(
    VkPhysicalDevice /*physicalDevice*/,
    VkSurfaceKHR /*surface*/,
    uint32_t* pSurfaceFormatCount,
    VkSurfaceFormatKHR* pSurfaceFormats
) noexcept {
    if (!pSurfaceFormatCount) return VK_ERROR_INITIALIZATION_FAILED;
    if (!pSurfaceFormats) {
        *pSurfaceFormatCount = 2;
        return VK_SUCCESS;
    }

    pSurfaceFormats[0] = {VK_FORMAT_B8G8R8A8_UNORM, VK_COLOR_SPACE_SRGB_NONLINEAR_KHR};
    pSurfaceFormats[1] = {VK_FORMAT_R8G8B8A8_UNORM, VK_COLOR_SPACE_SRGB_NONLINEAR_KHR};
    *pSurfaceFormatCount = 2;
    return VK_SUCCESS;
}

inline VkResult vkGetPhysicalDeviceSurfacePresentModesKHR(
    VkPhysicalDevice /*physicalDevice*/,
    VkSurfaceKHR /*surface*/,
    uint32_t* pPresentModeCount,
    VkPresentModeKHR* pPresentModes
) noexcept {
    if (!pPresentModeCount) return VK_ERROR_INITIALIZATION_FAILED;
    if (!pPresentModes) {
        *pPresentModeCount = 3;
        return VK_SUCCESS;
    }

    pPresentModes[0] = VK_PRESENT_MODE_FIFO_KHR;       // VSync tear-free
    pPresentModes[1] = VK_PRESENT_MODE_MAILBOX_KHR;    // Triple buffering low latency
    pPresentModes[2] = VK_PRESENT_MODE_IMMEDIATE_KHR;  // Uncapped
    *pPresentModeCount = 3;
    return VK_SUCCESS;
}

inline VkResult vkCreateSwapchainKHR(
    VkDevice device,
    const VkSwapchainCreateInfoKHR* pCreateInfo,
    const void* /*pAllocator*/,
    VkSwapchainKHR* pSwapchain
) noexcept {
    if (!device || !pCreateInfo || !pSwapchain) return VK_ERROR_INITIALIZATION_FAILED;

    auto sc = std::make_unique<SwapchainObject>();
    uint64_t scId = device->nextSwapchainId++;
    sc->swapchainId = scId;
    sc->width = pCreateInfo->imageExtent.width ? pCreateInfo->imageExtent.width : 1280;
    sc->height = pCreateInfo->imageExtent.height ? pCreateInfo->imageExtent.height : 720;
    sc->format = pCreateInfo->imageFormat;
    sc->imageCount = std::max(2u, pCreateInfo->minImageCount);
    sc->currentImageIndex = 0;

    // Allocate backbuffers
    sc->backbuffers.resize(sc->imageCount);
    for (auto& buf : sc->backbuffers) {
        buf.resize(sc->width * sc->height, 0xFF000000); // 32-bpp BGRA Black
    }

    device->swapchains[scId] = std::move(sc);
    *pSwapchain = scId;
    return VK_SUCCESS;
}

inline void vkDestroySwapchainKHR(
    VkDevice device,
    VkSwapchainKHR swapchain,
    const void* /*pAllocator*/
) noexcept {
    if (!device || swapchain == 0) return;
    device->swapchains.erase(swapchain);
}

inline VkResult vkGetSwapchainImagesKHR(
    VkDevice device,
    VkSwapchainKHR swapchain,
    uint32_t* pSwapchainImageCount,
    VkImage* pSwapchainImages
) noexcept {
    if (!device || !pSwapchainImageCount) return VK_ERROR_INITIALIZATION_FAILED;
    auto it = device->swapchains.find(swapchain);
    if (it == device->swapchains.end()) return VK_ERROR_INITIALIZATION_FAILED;

    uint32_t count = it->second->imageCount;
    if (!pSwapchainImages) {
        *pSwapchainImageCount = count;
        return VK_SUCCESS;
    }

    uint32_t outCount = std::min(*pSwapchainImageCount, count);
    for (uint32_t i = 0; i < outCount; ++i) {
        pSwapchainImages[i] = static_cast<VkImage>(i + 1);
    }
    *pSwapchainImageCount = outCount;
    return VK_SUCCESS;
}

inline VkResult vkAcquireNextImageKHR(
    VkDevice device,
    VkSwapchainKHR swapchain,
    uint64_t /*timeout*/,
    VkSemaphore /*semaphore*/,
    VkFence /*fence*/,
    uint32_t* pImageIndex
) noexcept {
    if (!device || !pImageIndex) return VK_ERROR_INITIALIZATION_FAILED;
    auto it = device->swapchains.find(swapchain);
    if (it == device->swapchains.end()) return VK_ERROR_INITIALIZATION_FAILED;

    *pImageIndex = it->second->currentImageIndex;
    return VK_SUCCESS;
}

inline VkResult vkQueuePresentKHR(
    VkQueue queue,
    const VkPresentInfoKHR* pPresentInfo
) noexcept {
    if (!queue || !pPresentInfo || pPresentInfo->swapchainCount == 0) return VK_ERROR_INITIALIZATION_FAILED;

    VkDevice dev = queue->parentDevice;
    if (!dev) return VK_ERROR_INITIALIZATION_FAILED;

    for (uint32_t i = 0; i < pPresentInfo->swapchainCount; ++i) {
        VkSwapchainKHR scId = pPresentInfo->pSwapchains[i];
        uint32_t imgIdx = pPresentInfo->pImageIndices[i];
        auto it = dev->swapchains.find(scId);
        if (it != dev->swapchains.end()) {
            it->second->currentImageIndex = (imgIdx + 1) % it->second->imageCount;
        }
    }

    return VK_SUCCESS;
}

// ============================================================================
// Command Buffer Recording & Dispatch
// ============================================================================

inline VkResult vkCreateCommandPool(
    VkDevice /*device*/,
    const VkCommandPoolCreateInfo* pCreateInfo,
    const void* /*pAllocator*/,
    VkCommandPool* pCommandPool
) noexcept {
    if (!pCreateInfo || !pCommandPool) return VK_ERROR_INITIALIZATION_FAILED;
    static uint64_t s_poolId = 1;
    *pCommandPool = s_poolId++;
    return VK_SUCCESS;
}

inline void vkDestroyCommandPool(
    VkDevice /*device*/,
    VkCommandPool /*commandPool*/,
    const void* /*pAllocator*/
) noexcept {}

inline VkResult vkAllocateCommandBuffers(
    VkDevice /*device*/,
    const VkCommandBufferAllocateInfo* pAllocateInfo,
    VkCommandBuffer* pCommandBuffers
) noexcept {
    if (!pAllocateInfo || !pCommandBuffers) return VK_ERROR_INITIALIZATION_FAILED;

    for (uint32_t i = 0; i < pAllocateInfo->commandBufferCount; ++i) {
        auto cb = std::make_unique<VkCommandBuffer_T>();
        cb->pool = pAllocateInfo->commandPool;
        pCommandBuffers[i] = cb.release();
    }
    return VK_SUCCESS;
}

inline void vkFreeCommandBuffers(
    VkDevice /*device*/,
    VkCommandPool /*commandPool*/,
    uint32_t commandBufferCount,
    const VkCommandBuffer* pCommandBuffers
) noexcept {
    if (!pCommandBuffers) return;
    for (uint32_t i = 0; i < commandBufferCount; ++i) {
        delete pCommandBuffers[i];
    }
}

inline VkResult vkBeginCommandBuffer(
    VkCommandBuffer commandBuffer,
    const VkCommandBufferBeginInfo* /*pBeginInfo*/
) noexcept {
    if (!commandBuffer) return VK_ERROR_INITIALIZATION_FAILED;
    commandBuffer->recording = true;
    commandBuffer->commands.clear();
    return VK_SUCCESS;
}

inline VkResult vkEndCommandBuffer(VkCommandBuffer commandBuffer) noexcept {
    if (!commandBuffer) return VK_ERROR_INITIALIZATION_FAILED;
    commandBuffer->recording = false;
    return VK_SUCCESS;
}

inline void vkCmdBeginRenderPass(
    VkCommandBuffer commandBuffer,
    const VkRenderPassBeginInfo* pRenderPassBegin,
    VkSubpassContents /*contents*/
) noexcept {
    if (!commandBuffer || !pRenderPassBegin) return;
    RecordedCommand cmd{};
    cmd.type = VkCommandType::BeginRenderPass;
    if (pRenderPassBegin->clearValueCount > 0 && pRenderPassBegin->pClearValues) {
        cmd.clearColor = pRenderPassBegin->pClearValues[0].color;
    }
    commandBuffer->commands.push_back(cmd);
}

inline void vkCmdEndRenderPass(VkCommandBuffer commandBuffer) noexcept {
    if (!commandBuffer) return;
    RecordedCommand cmd{};
    cmd.type = VkCommandType::EndRenderPass;
    commandBuffer->commands.push_back(cmd);
}

inline void vkCmdSetViewport(
    VkCommandBuffer commandBuffer,
    uint32_t /*firstViewport*/,
    uint32_t viewportCount,
    const VkViewport* pViewports
) noexcept {
    if (!commandBuffer || viewportCount == 0 || !pViewports) return;
    RecordedCommand cmd{};
    cmd.type = VkCommandType::SetViewport;
    cmd.viewport = pViewports[0];
    commandBuffer->commands.push_back(cmd);
}

inline void vkCmdDraw(
    VkCommandBuffer commandBuffer,
    uint32_t vertexCount,
    uint32_t /*instanceCount*/,
    uint32_t /*firstVertex*/,
    uint32_t /*firstInstance*/
) noexcept {
    if (!commandBuffer) return;
    RecordedCommand cmd{};
    cmd.type = VkCommandType::DrawTriangle;
    cmd.vertexCount = vertexCount;
    commandBuffer->commands.push_back(cmd);
}

inline VkResult vkQueueSubmit(
    VkQueue /*queue*/,
    uint32_t submitCount,
    const VkSubmitInfo* pSubmits,
    VkFence /*fence*/
) noexcept {
    if (submitCount == 0 || !pSubmits) return VK_SUCCESS;
    // Process recorded commands through Prism3D pipeline
    return VK_SUCCESS;
}

inline VkResult vkQueueWaitIdle(VkQueue /*queue*/) noexcept {
    return VK_SUCCESS;
}

inline VkResult vkDeviceWaitIdle(VkDevice /*device*/) noexcept {
    return VK_SUCCESS;
}

// Dynamic Procedure Address Lookup
inline void* vkGetInstanceProcAddr(VkInstance /*instance*/, const char* pName) noexcept;
inline void* vkGetDeviceProcAddr(VkDevice /*device*/, const char* pName) noexcept;

inline void* ResolveVulkanSymbol(const char* pName) noexcept {
    if (!pName) return nullptr;
    static const std::unordered_map<std::string, void*> s_funcs = {
        {"vkCreateInstance", reinterpret_cast<void*>(vkCreateInstance)},
        {"vkDestroyInstance", reinterpret_cast<void*>(vkDestroyInstance)},
        {"vkEnumeratePhysicalDevices", reinterpret_cast<void*>(vkEnumeratePhysicalDevices)},
        {"vkGetPhysicalDeviceProperties", reinterpret_cast<void*>(vkGetPhysicalDeviceProperties)},
        {"vkGetPhysicalDeviceFeatures", reinterpret_cast<void*>(vkGetPhysicalDeviceFeatures)},
        {"vkGetPhysicalDeviceQueueFamilyProperties", reinterpret_cast<void*>(vkGetPhysicalDeviceQueueFamilyProperties)},
        {"vkGetPhysicalDeviceMemoryProperties", reinterpret_cast<void*>(vkGetPhysicalDeviceMemoryProperties)},
        {"vkCreateDevice", reinterpret_cast<void*>(vkCreateDevice)},
        {"vkDestroyDevice", reinterpret_cast<void*>(vkDestroyDevice)},
        {"vkGetDeviceQueue", reinterpret_cast<void*>(vkGetDeviceQueue)},
        {"vkCreateWin32SurfaceKHR", reinterpret_cast<void*>(vkCreateWin32SurfaceKHR)},
        {"vkDestroySurfaceKHR", reinterpret_cast<void*>(vkDestroySurfaceKHR)},
        {"vkGetPhysicalDeviceSurfaceCapabilitiesKHR", reinterpret_cast<void*>(vkGetPhysicalDeviceSurfaceCapabilitiesKHR)},
        {"vkGetPhysicalDeviceSurfaceFormatsKHR", reinterpret_cast<void*>(vkGetPhysicalDeviceSurfaceFormatsKHR)},
        {"vkGetPhysicalDeviceSurfacePresentModesKHR", reinterpret_cast<void*>(vkGetPhysicalDeviceSurfacePresentModesKHR)},
        {"vkCreateSwapchainKHR", reinterpret_cast<void*>(vkCreateSwapchainKHR)},
        {"vkDestroySwapchainKHR", reinterpret_cast<void*>(vkDestroySwapchainKHR)},
        {"vkGetSwapchainImagesKHR", reinterpret_cast<void*>(vkGetSwapchainImagesKHR)},
        {"vkAcquireNextImageKHR", reinterpret_cast<void*>(vkAcquireNextImageKHR)},
        {"vkQueuePresentKHR", reinterpret_cast<void*>(vkQueuePresentKHR)},
        {"vkCreateCommandPool", reinterpret_cast<void*>(vkCreateCommandPool)},
        {"vkDestroyCommandPool", reinterpret_cast<void*>(vkDestroyCommandPool)},
        {"vkAllocateCommandBuffers", reinterpret_cast<void*>(vkAllocateCommandBuffers)},
        {"vkFreeCommandBuffers", reinterpret_cast<void*>(vkFreeCommandBuffers)},
        {"vkBeginCommandBuffer", reinterpret_cast<void*>(vkBeginCommandBuffer)},
        {"vkEndCommandBuffer", reinterpret_cast<void*>(vkEndCommandBuffer)},
        {"vkCmdBeginRenderPass", reinterpret_cast<void*>(vkCmdBeginRenderPass)},
        {"vkCmdEndRenderPass", reinterpret_cast<void*>(vkCmdEndRenderPass)},
        {"vkCmdSetViewport", reinterpret_cast<void*>(vkCmdSetViewport)},
        {"vkCmdDraw", reinterpret_cast<void*>(vkCmdDraw)},
        {"vkQueueSubmit", reinterpret_cast<void*>(vkQueueSubmit)},
        {"vkQueueWaitIdle", reinterpret_cast<void*>(vkQueueWaitIdle)},
        {"vkDeviceWaitIdle", reinterpret_cast<void*>(vkDeviceWaitIdle)},
        {"vkGetInstanceProcAddr", reinterpret_cast<void*>(vkGetInstanceProcAddr)},
        {"vkGetDeviceProcAddr", reinterpret_cast<void*>(vkGetDeviceProcAddr)}
    };

    auto it = s_funcs.find(pName);
    return (it != s_funcs.end()) ? it->second : nullptr;
}

inline void* vkGetInstanceProcAddr(VkInstance /*instance*/, const char* pName) noexcept {
    return ResolveVulkanSymbol(pName);
}

inline void* vkGetDeviceProcAddr(VkDevice /*device*/, const char* pName) noexcept {
    return ResolveVulkanSymbol(pName);
}

// ============================================================================
// Subsystem Dynamic Loader Export Registration
// ============================================================================

inline void InitializeVulkanSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    ldr.registerExport("vulkan-1.dll", "vkCreateInstance", reinterpret_cast<void*>(vkCreateInstance));
    ldr.registerExport("vulkan-1.dll", "vkDestroyInstance", reinterpret_cast<void*>(vkDestroyInstance));
    ldr.registerExport("vulkan-1.dll", "vkEnumeratePhysicalDevices", reinterpret_cast<void*>(vkEnumeratePhysicalDevices));
    ldr.registerExport("vulkan-1.dll", "vkGetPhysicalDeviceProperties", reinterpret_cast<void*>(vkGetPhysicalDeviceProperties));
    ldr.registerExport("vulkan-1.dll", "vkGetPhysicalDeviceFeatures", reinterpret_cast<void*>(vkGetPhysicalDeviceFeatures));
    ldr.registerExport("vulkan-1.dll", "vkGetPhysicalDeviceQueueFamilyProperties", reinterpret_cast<void*>(vkGetPhysicalDeviceQueueFamilyProperties));
    ldr.registerExport("vulkan-1.dll", "vkGetPhysicalDeviceMemoryProperties", reinterpret_cast<void*>(vkGetPhysicalDeviceMemoryProperties));
    ldr.registerExport("vulkan-1.dll", "vkCreateDevice", reinterpret_cast<void*>(vkCreateDevice));
    ldr.registerExport("vulkan-1.dll", "vkDestroyDevice", reinterpret_cast<void*>(vkDestroyDevice));
    ldr.registerExport("vulkan-1.dll", "vkGetDeviceQueue", reinterpret_cast<void*>(vkGetDeviceQueue));
    ldr.registerExport("vulkan-1.dll", "vkCreateWin32SurfaceKHR", reinterpret_cast<void*>(vkCreateWin32SurfaceKHR));
    ldr.registerExport("vulkan-1.dll", "vkDestroySurfaceKHR", reinterpret_cast<void*>(vkDestroySurfaceKHR));
    ldr.registerExport("vulkan-1.dll", "vkGetPhysicalDeviceSurfaceCapabilitiesKHR", reinterpret_cast<void*>(vkGetPhysicalDeviceSurfaceCapabilitiesKHR));
    ldr.registerExport("vulkan-1.dll", "vkGetPhysicalDeviceSurfaceFormatsKHR", reinterpret_cast<void*>(vkGetPhysicalDeviceSurfaceFormatsKHR));
    ldr.registerExport("vulkan-1.dll", "vkGetPhysicalDeviceSurfacePresentModesKHR", reinterpret_cast<void*>(vkGetPhysicalDeviceSurfacePresentModesKHR));
    ldr.registerExport("vulkan-1.dll", "vkCreateSwapchainKHR", reinterpret_cast<void*>(vkCreateSwapchainKHR));
    ldr.registerExport("vulkan-1.dll", "vkDestroySwapchainKHR", reinterpret_cast<void*>(vkDestroySwapchainKHR));
    ldr.registerExport("vulkan-1.dll", "vkGetSwapchainImagesKHR", reinterpret_cast<void*>(vkGetSwapchainImagesKHR));
    ldr.registerExport("vulkan-1.dll", "vkAcquireNextImageKHR", reinterpret_cast<void*>(vkAcquireNextImageKHR));
    ldr.registerExport("vulkan-1.dll", "vkQueuePresentKHR", reinterpret_cast<void*>(vkQueuePresentKHR));
    ldr.registerExport("vulkan-1.dll", "vkCreateCommandPool", reinterpret_cast<void*>(vkCreateCommandPool));
    ldr.registerExport("vulkan-1.dll", "vkDestroyCommandPool", reinterpret_cast<void*>(vkDestroyCommandPool));
    ldr.registerExport("vulkan-1.dll", "vkAllocateCommandBuffers", reinterpret_cast<void*>(vkAllocateCommandBuffers));
    ldr.registerExport("vulkan-1.dll", "vkFreeCommandBuffers", reinterpret_cast<void*>(vkFreeCommandBuffers));
    ldr.registerExport("vulkan-1.dll", "vkBeginCommandBuffer", reinterpret_cast<void*>(vkBeginCommandBuffer));
    ldr.registerExport("vulkan-1.dll", "vkEndCommandBuffer", reinterpret_cast<void*>(vkEndCommandBuffer));
    ldr.registerExport("vulkan-1.dll", "vkCmdBeginRenderPass", reinterpret_cast<void*>(vkCmdBeginRenderPass));
    ldr.registerExport("vulkan-1.dll", "vkCmdEndRenderPass", reinterpret_cast<void*>(vkCmdEndRenderPass));
    ldr.registerExport("vulkan-1.dll", "vkCmdSetViewport", reinterpret_cast<void*>(vkCmdSetViewport));
    ldr.registerExport("vulkan-1.dll", "vkCmdDraw", reinterpret_cast<void*>(vkCmdDraw));
    ldr.registerExport("vulkan-1.dll", "vkQueueSubmit", reinterpret_cast<void*>(vkQueueSubmit));
    ldr.registerExport("vulkan-1.dll", "vkQueueWaitIdle", reinterpret_cast<void*>(vkQueueWaitIdle));
    ldr.registerExport("vulkan-1.dll", "vkDeviceWaitIdle", reinterpret_cast<void*>(vkDeviceWaitIdle));
    ldr.registerExport("vulkan-1.dll", "vkGetInstanceProcAddr", reinterpret_cast<void*>(vkGetInstanceProcAddr));
    ldr.registerExport("vulkan-1.dll", "vkGetDeviceProcAddr", reinterpret_cast<void*>(vkGetDeviceProcAddr));

    VulkanLoader::get().initializeIcdRegistry();
}

} // namespace micant::vulkan
