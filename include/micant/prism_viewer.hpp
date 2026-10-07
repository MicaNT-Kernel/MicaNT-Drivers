// ============================================================================
// MicaNT: PrismX Interactive 3D Real-Time Model & Scene Viewer
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Combines User32 Window Management, Direct3D 11 Software Rasterizer,
// DXGI SwapChain Presentation, and Interactive Multi-Axis Camera Controls.
// ============================================================================

#pragma once

#include "prismx.hpp"
#include "prism3d.hpp"
#include "user32.hpp"
#include "dinput.hpp"
#include "xinput.hpp"
#include <vector>
#include <memory>
#include <string>
#include <string_view>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <numbers>

namespace micant::viewer {

using namespace micant::prism3d;
using namespace micant::prismx;

// ============================================================================
// 1. Interactive Orbit Camera
// ============================================================================

class ViewerCamera {
public:
    float radius{4.0f};
    float minRadius{1.0f};
    float maxRadius{25.0f};
    float yaw{0.785f};     // 45 degrees
    float pitch{0.45f};    // ~26 degrees
    Vector3 target{0.0f, 0.0f, 0.0f};
    Vector3 up{0.0f, 1.0f, 0.0f};

    void rotate(float dYaw, float dPitch) noexcept {
        yaw += dYaw;
        // Keep yaw in [-2pi, 2pi]
        if (yaw > std::numbers::pi_v<float> * 2.0f) yaw -= std::numbers::pi_v<float> * 2.0f;
        if (yaw < -std::numbers::pi_v<float> * 2.0f) yaw += std::numbers::pi_v<float> * 2.0f;

        // Clamp pitch to avoid gimbal singularity
        pitch = std::clamp(pitch + dPitch, -1.45f, 1.45f);
    }

    void zoom(float dRadius) noexcept {
        radius = std::clamp(radius + dRadius, minRadius, maxRadius);
    }

    void pan(float dX, float dY) noexcept {
        target.x += dX;
        target.y += dY;
    }

    [[nodiscard]] Vector3 getEyePosition() const noexcept {
        float cosPitch = std::cos(pitch);
        float sinPitch = std::sin(pitch);
        float sinYaw = std::sin(yaw);
        float cosYaw = std::cos(yaw);

        return Vector3{
            target.x + radius * cosPitch * sinYaw,
            target.y + radius * sinPitch,
            target.z - radius * cosPitch * cosYaw
        };
    }

    [[nodiscard]] Matrix4x4 getViewMatrix() const noexcept {
        return Matrix4x4::LookAtLH(getEyePosition(), target, up);
    }

    [[nodiscard]] Matrix4x4 getProjectionMatrix(float fovY, float aspect, float nearZ, float farZ) const noexcept {
        return Matrix4x4::PerspectiveFovLH(fovY, aspect, nearZ, farZ);
    }
};

// ============================================================================
// 2. 3D Model Types & Procedural Mesh Generators
// ============================================================================

enum class ViewerModelType : uint32_t {
    Crystal = 0, // DEC PRISM Diamond Gemstone
    Torus   = 1, // Parametric 3D Donut with lighting
    Cube    = 2  // Shaded 3D Box
};

struct MeshData {
    std::vector<VertexPositionColor> vertices;
    std::vector<uint16_t> indices;
};

class MeshGenerator {
public:
    // ------------------------------------------------------------------------
    // Model 0: PrismX Crystal Core (DEC PRISM tribute)
    // ------------------------------------------------------------------------
    static MeshData createCrystal() {
        MeshData mesh;

        // Top Apex & Bottom Apex
        VertexPositionColor topApex{ 0.0f,  1.6f, 0.0f,  1.0f, 1.0f, 1.0f, 1.0f }; // Pure White Apex Highlight
        VertexPositionColor btmApex{ 0.0f, -1.6f, 0.0f,  0.08f, 0.05f, 0.35f, 1.0f }; // Deep Cobalt Bottom

        mesh.vertices.push_back(topApex); // 0
        mesh.vertices.push_back(btmApex); // 1

        constexpr int kSegments = 8;
        constexpr float kUpperY = 0.5f;
        constexpr float kUpperR = 0.85f;
        constexpr float kLowerY = -0.5f;
        constexpr float kLowerR = 0.85f;

        // Facet colors palette (Cyan, Electric Blue, Violet, Purple)
        const float palette[kSegments][3] = {
            { 0.05f, 0.75f, 1.00f }, // Cyan
            { 0.15f, 0.45f, 0.95f }, // Blue
            { 0.35f, 0.20f, 0.92f }, // Indigo
            { 0.65f, 0.15f, 0.95f }, // Purple
            { 0.85f, 0.20f, 0.75f }, // Magenta
            { 0.50f, 0.15f, 0.85f }, // Violet
            { 0.15f, 0.45f, 0.95f }, // Blue
            { 0.05f, 0.85f, 0.90f }  // Bright Cyan
        };

        // Upper Ring Vertices (Indices 2 .. 9)
        for (int i = 0; i < kSegments; ++i) {
            float angle = (i * 2.0f * std::numbers::pi_v<float>) / kSegments;
            float vx = std::cos(angle) * kUpperR;
            float vz = std::sin(angle) * kUpperR;
            mesh.vertices.push_back({ vx, kUpperY, vz, palette[i][0], palette[i][1], palette[i][2], 1.0f });
        }

        // Lower Ring Vertices (Indices 10 .. 17)
        for (int i = 0; i < kSegments; ++i) {
            float angle = (i * 2.0f * std::numbers::pi_v<float>) / kSegments;
            float vx = std::cos(angle) * kLowerR;
            float vz = std::sin(angle) * kLowerR;
            mesh.vertices.push_back({ vx, kLowerY, vz, palette[i][0] * 0.7f, palette[i][1] * 0.7f, palette[i][2] * 0.7f, 1.0f });
        }

        // Indices:
        // Top cap triangles: (0, i+2, next+2)
        for (int i = 0; i < kSegments; ++i) {
            uint16_t curr = static_cast<uint16_t>(2 + i);
            uint16_t next = static_cast<uint16_t>(2 + ((i + 1) % kSegments));
            mesh.indices.push_back(0);
            mesh.indices.push_back(curr);
            mesh.indices.push_back(next);
        }

        // Mid belt quads: (currUp, currLow, nextLow), (currUp, nextLow, nextUp)
        for (int i = 0; i < kSegments; ++i) {
            uint16_t currUp  = static_cast<uint16_t>(2 + i);
            uint16_t nextUp  = static_cast<uint16_t>(2 + ((i + 1) % kSegments));
            uint16_t currLow = static_cast<uint16_t>(10 + i);
            uint16_t nextLow = static_cast<uint16_t>(10 + ((i + 1) % kSegments));

            mesh.indices.push_back(currUp);
            mesh.indices.push_back(currLow);
            mesh.indices.push_back(nextLow);

            mesh.indices.push_back(currUp);
            mesh.indices.push_back(nextLow);
            mesh.indices.push_back(nextUp);
        }

        // Bottom cap triangles: (1, nextLow, currLow)
        for (int i = 0; i < kSegments; ++i) {
            uint16_t currLow = static_cast<uint16_t>(10 + i);
            uint16_t nextLow = static_cast<uint16_t>(10 + ((i + 1) % kSegments));
            mesh.indices.push_back(1);
            mesh.indices.push_back(nextLow);
            mesh.indices.push_back(currLow);
        }

        return mesh;
    }

    // ------------------------------------------------------------------------
    // Model 1: Parametric 3D Torus with Dynamic Lighting
    // ------------------------------------------------------------------------
    static MeshData createTorus(float majorR = 1.1f, float minorR = 0.45f, int ringSegments = 16, int tubeSegments = 12) {
        MeshData mesh;

        // Light direction (from upper right front)
        float lx = 0.5f, ly = 0.8f, lz = -0.6f;
        float lLen = std::sqrt(lx * lx + ly * ly + lz * lz);
        lx /= lLen; ly /= lLen; lz /= lLen;

        for (int i = 0; i < ringSegments; ++i) {
            float u = (i * 2.0f * std::numbers::pi_v<float>) / ringSegments;
            float cosU = std::cos(u);
            float sinU = std::sin(u);

            for (int j = 0; j < tubeSegments; ++j) {
                float v = (j * 2.0f * std::numbers::pi_v<float>) / tubeSegments;
                float cosV = std::cos(v);
                float sinV = std::sin(v);

                float x = (majorR + minorR * cosV) * cosU;
                float y = minorR * sinV;
                float z = (majorR + minorR * cosV) * sinU;

                // Surface normal
                float nx = cosV * cosU;
                float ny = sinV;
                float nz = cosV * sinU;

                // Simple Lambertian Diffuse + Ambient
                float nDotL = std::max(0.0f, nx * lx + ny * ly + nz * lz);
                float intensity = 0.25f + 0.75f * nDotL;

                // Vibrant emerald to teal color gradient
                float r = std::clamp(0.05f * intensity, 0.0f, 1.0f);
                float g = std::clamp(0.95f * intensity, 0.0f, 1.0f);
                float b = std::clamp(0.70f * intensity, 0.0f, 1.0f);

                mesh.vertices.push_back({ x, y, z, r, g, b, 1.0f });
            }
        }

        for (int i = 0; i < ringSegments; ++i) {
            int nextI = (i + 1) % ringSegments;
            for (int j = 0; j < tubeSegments; ++j) {
                int nextJ = (j + 1) % tubeSegments;

                uint16_t i0 = static_cast<uint16_t>(i * tubeSegments + j);
                uint16_t i1 = static_cast<uint16_t>(nextI * tubeSegments + j);
                uint16_t i2 = static_cast<uint16_t>(nextI * tubeSegments + nextJ);
                uint16_t i3 = static_cast<uint16_t>(i * tubeSegments + nextJ);

                mesh.indices.push_back(i0);
                mesh.indices.push_back(i1);
                mesh.indices.push_back(i2);

                mesh.indices.push_back(i0);
                mesh.indices.push_back(i2);
                mesh.indices.push_back(i3);
            }
        }

        return mesh;
    }

    // ------------------------------------------------------------------------
    // Model 2: Shaded 3D Box / Cube
    // ------------------------------------------------------------------------
    static MeshData createCube(float size = 0.9f) {
        MeshData mesh;

        // 8 Vertices
        mesh.vertices = {
            { -size, -size, -size,  1.0f, 0.1f, 0.1f, 1.0f }, // 0: Red
            { -size,  size, -size,  0.1f, 1.0f, 0.1f, 1.0f }, // 1: Green
            {  size,  size, -size,  0.1f, 0.2f, 1.0f, 1.0f }, // 2: Blue
            {  size, -size, -size,  1.0f, 1.0f, 0.1f, 1.0f }, // 3: Yellow
            { -size, -size,  size,  1.0f, 0.1f, 1.0f, 1.0f }, // 4: Magenta
            { -size,  size,  size,  0.1f, 1.0f, 1.0f, 1.0f }, // 5: Cyan
            {  size,  size,  size,  1.0f, 1.0f, 1.0f, 1.0f }, // 6: White
            {  size, -size,  size,  0.4f, 0.4f, 0.4f, 1.0f }  // 7: Grey
        };

        // 36 Indices (12 triangles)
        mesh.indices = {
            0, 1, 2,  0, 2, 3,  // Front
            4, 6, 5,  4, 7, 6,  // Back
            4, 5, 1,  4, 1, 0,  // Left
            3, 2, 6,  3, 6, 7,  // Right
            1, 5, 6,  1, 6, 2,  // Top
            4, 0, 3,  4, 3, 7   // Bottom
        };

        return mesh;
    }
};

// ============================================================================
// 3. Interactive Viewer Session
// ============================================================================

struct ViewerStats {
    uint32_t        frameCount{0};
    float           averageFps{0.0f};
    float           lastFrameTimeMs{0.0f};
    uint32_t        triangleCount{0};
    uint32_t        vertexCount{0};
    bool            wireframe{false};
    bool            autoRotate{true};
    ViewerModelType currentModel{ViewerModelType::Crystal};
    float           cameraYaw{0.0f};
    float           cameraPitch{0.0f};
    float           cameraDistance{0.0f};
};

class ViewerSession {
public:
    ViewerSession(uint32_t width = 800, uint32_t height = 600)
        : width_(width), height_(height) {}

    ~ViewerSession() {
        cleanup();
    }

    bool initialize(const wchar_t* title = L"MicaNT PrismX 3D Interactive Viewer") {
        user32::InitializeUser32SubsystemExports();

        // 1. Create Native User32 Window
        user32::WNDCLASSEXW wcex{};
        wcex.cbSize = sizeof(user32::WNDCLASSEXW);
        wcex.lpszClassName = L"MicaNT_Prism3DViewerClass";
        wcex.lpfnWndProc = viewerWndProc;
        user32::RegisterClassExW(&wcex);

        hwnd_ = user32::CreateWindowExW(
            user32::WS_EX_APPWINDOW,
            L"MicaNT_Prism3DViewerClass",
            title,
            user32::WS_OVERLAPPEDWINDOW | user32::WS_VISIBLE,
            100, 100, width_, height_,
            nullptr, nullptr, nullptr, nullptr
        );

        if (!hwnd_) return false;

        // Store session pointer in window user data
        user32::SetWindowLongPtrW(hwnd_, user32::GWLP_USERDATA, reinterpret_cast<uintptr_t>(this));

        // 2. Initialize Direct3D 11 Device and SwapChain bound to HWND
        DXGI_SWAP_CHAIN_DESC scDesc{};
        scDesc.BufferDesc.Width = width_;
        scDesc.BufferDesc.Height = height_;
        scDesc.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        scDesc.BufferCount = 1;
        scDesc.OutputWindow = hwnd_;
        scDesc.Windowed = 1;
        scDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        int32_t hr = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            nullptr, 0, 7, &scDesc, &swapChain_, &device_, nullptr, &context_
        );

        if (hr != 0 || !device_ || !context_ || !swapChain_) {
            return false;
        }

        // 3. Create RTV from SwapChain BackBuffer
        IDXGISurface* surface = nullptr;
        swapChain_->GetBuffer(0, IID_IDXGISurface, reinterpret_cast<void**>(&surface));
        device_->CreateRenderTargetView(reinterpret_cast<ID3D11Resource*>(surface), nullptr, &rtv_);
        if (surface) surface->Release();

        // 4. Create Depth Stencil View
        device_->CreateDepthStencilView(nullptr, nullptr, &dsv_);

        // 5. Create Viewport
        D3D11_VIEWPORT vp{ 0.0f, 0.0f, static_cast<float>(width_), static_cast<float>(height_), 0.0f, 1.0f };
        context_->RSSetViewports(1, &vp);
        context_->OMSetRenderTargets(1, &rtv_, dsv_);

        // 6. Create Rasterizer States (Solid & Wireframe)
        D3D11_RASTERIZER_DESC rsSolidDesc{};
        rsSolidDesc.FillMode = D3D11_FILL_SOLID;
        rsSolidDesc.CullMode = D3D11_CULL_NONE; // Double sided for crystals
        device_->CreateRasterizerState(&rsSolidDesc, &solidRS_);

        D3D11_RASTERIZER_DESC rsWireDesc{};
        rsWireDesc.FillMode = D3D11_FILL_WIREFRAME;
        rsWireDesc.CullMode = D3D11_CULL_NONE;
        device_->CreateRasterizerState(&rsWireDesc, &wireframeRS_);

        context_->RSSetState(solidRS_);

        // 7. Create Constant Buffer for MVP Matrix (Slot 0)
        D3D11_BUFFER_DESC cbDesc{};
        cbDesc.ByteWidth = sizeof(Matrix4x4);
        cbDesc.Usage = D3D11_USAGE_DEFAULT;
        cbDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        device_->CreateBuffer(&cbDesc, nullptr, &constantBuffer_);
        context_->VSSetConstantBuffers(0, 1, &constantBuffer_);

        // 8. Generate and upload procedural meshes
        loadModel(ViewerModelType::Crystal);
        loadModel(ViewerModelType::Torus);
        loadModel(ViewerModelType::Cube);

        activeModel_ = ViewerModelType::Crystal;

        return true;
    }

    void setWireframe(bool wireframe) noexcept {
        isWireframe_ = wireframe;
        if (context_) {
            context_->RSSetState(isWireframe_ ? wireframeRS_ : solidRS_);
        }
    }

    void setModel(ViewerModelType model) noexcept {
        activeModel_ = model;
    }

    void setAutoRotate(bool autoRotate) noexcept {
        autoRotate_ = autoRotate;
    }

    ViewerCamera& getCamera() noexcept { return camera_; }
    win32::HWND getHwnd() const noexcept { return hwnd_; }

    void renderFrame(float deltaTime = 0.016f) {
        if (!context_ || !rtv_ || !dsv_) return;

        // Auto rotation
        if (autoRotate_) {
            modelRotationY_ += 0.85f * deltaTime;
            if (modelRotationY_ > std::numbers::pi_v<float> * 2.0f) {
                modelRotationY_ -= std::numbers::pi_v<float> * 2.0f;
            }
        }

        // Clear Buffers (Midnight Deep Blue background)
        const float clearColor[4] = { 0.02f, 0.04f, 0.09f, 1.0f };
        context_->ClearRenderTargetView(rtv_, clearColor);
        context_->ClearDepthStencilView(dsv_, D3D11_CLEAR_DEPTH, 1.0f, 0);

        // Compute Transform Matrices
        Matrix4x4 world = Matrix4x4::RotationY(modelRotationY_);
        if (modelRotationX_ != 0.0f) {
            world = Matrix4x4::Multiply(Matrix4x4::RotationX(modelRotationX_), world);
        }

        Matrix4x4 view = camera_.getViewMatrix();
        Matrix4x4 proj = camera_.getProjectionMatrix(
            0.785f, // 45 deg FOV
            static_cast<float>(width_) / static_cast<float>(height_),
            0.1f, 100.0f
        );

        // MVP = World * View * Proj
        Matrix4x4 mvp = Matrix4x4::Multiply(world, Matrix4x4::Multiply(view, proj));

        // Update Constant Buffer
        context_->UpdateSubresource(constantBuffer_, 0, &mvp, 0, 0);

        // Bind Active Mesh
        auto& mesh = meshes_[static_cast<size_t>(activeModel_)];
        if (mesh.vertexBuffer && mesh.indexBuffer) {
            uint32_t stride = sizeof(VertexPositionColor);
            uint32_t offset = 0;
            context_->IASetVertexBuffers(0, 1, &mesh.vertexBuffer, &stride, &offset);
            context_->IASetIndexBuffer(mesh.indexBuffer, DXGI_FORMAT_R16_UINT, 0);
            context_->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

            context_->DrawIndexed(mesh.indexCount, 0, 0);
        }

        // Present Frame (dispatches to window surface)
        swapChain_->Present(1, 0);

        frameCount_++;
    }

    void pumpMessages() {
        user32::MSG msg{};
        while (user32::PeekMessageW(&msg, hwnd_, 0, 0, user32::PM_REMOVE)) {
            user32::TranslateMessage(&msg);
            user32::DispatchMessageW(&msg);
        }
    }

    ViewerStats run(uint32_t numFrames = 10) {
        auto startTime = std::chrono::high_resolution_clock::now();

        for (uint32_t i = 0; i < numFrames; ++i) {
            pumpMessages();
            renderFrame(0.016f);
        }

        auto endTime = std::chrono::high_resolution_clock::now();
        std::chrono::duration<float, std::milli> duration = endTime - startTime;

        ViewerStats stats{};
        stats.frameCount = frameCount_;
        stats.lastFrameTimeMs = duration.count() / static_cast<float>(numFrames);
        stats.averageFps = (duration.count() > 0.0f) ? (static_cast<float>(numFrames) * 1000.0f / duration.count()) : 0.0f;

        auto& mesh = meshes_[static_cast<size_t>(activeModel_)];
        stats.triangleCount = mesh.indexCount / 3;
        stats.vertexCount = mesh.vertexCount;
        stats.wireframe = isWireframe_;
        stats.autoRotate = autoRotate_;
        stats.currentModel = activeModel_;
        stats.cameraYaw = camera_.yaw;
        stats.cameraPitch = camera_.pitch;
        stats.cameraDistance = camera_.radius;

        return stats;
    }

    // ------------------------------------------------------------------------
    // User Interactive Input Injection / Hooks
    // ------------------------------------------------------------------------
    void onMouseMove(int32_t dx, int32_t dy, bool leftDrag) {
        if (leftDrag) {
            camera_.rotate(dx * 0.015f, dy * 0.015f);
        }
    }

    void onMouseWheel(int32_t delta) {
        camera_.zoom(-delta * 0.005f);
    }

    void onKeyDown(uint32_t vKey) {
        switch (vKey) {
            case 0x25: // Left Arrow
                camera_.rotate(-0.08f, 0.0f);
                break;
            case 0x27: // Right Arrow
                camera_.rotate(0.08f, 0.0f);
                break;
            case 0x26: // Up Arrow
                camera_.rotate(0.0f, 0.08f);
                break;
            case 0x28: // Down Arrow
                camera_.rotate(0.0f, -0.08f);
                break;
            case 0x57: // 'W' key: toggle wireframe
                setWireframe(!isWireframe_);
                break;
            case 0x4D: // 'M' key: cycle model
                activeModel_ = static_cast<ViewerModelType>((static_cast<uint32_t>(activeModel_) + 1) % 3);
                break;
            case 0x20: // Space: toggle auto rotate
                autoRotate_ = !autoRotate_;
                break;
            default:
                break;
        }
    }

    void onGamepad(float lx, float ly, float triggers) {
        if (std::abs(lx) > 0.1f || std::abs(ly) > 0.1f) {
            camera_.rotate(lx * 0.05f, ly * 0.05f);
        }
        if (std::abs(triggers) > 0.1f) {
            camera_.zoom(-triggers * 0.1f);
        }
    }

private:
    struct ModelResource {
        ID3D11Buffer* vertexBuffer{nullptr};
        ID3D11Buffer* indexBuffer{nullptr};
        uint32_t      vertexCount{0};
        uint32_t      indexCount{0};
    };

    void loadModel(ViewerModelType type) {
        MeshData data;
        switch (type) {
            case ViewerModelType::Crystal: data = MeshGenerator::createCrystal(); break;
            case ViewerModelType::Torus:   data = MeshGenerator::createTorus();   break;
            case ViewerModelType::Cube:    data = MeshGenerator::createCube();    break;
        }

        ModelResource res{};
        res.vertexCount = static_cast<uint32_t>(data.vertices.size());
        res.indexCount = static_cast<uint32_t>(data.indices.size());

        // Vertex buffer
        D3D11_BUFFER_DESC vbDesc{};
        vbDesc.ByteWidth = static_cast<uint32_t>(data.vertices.size() * sizeof(VertexPositionColor));
        vbDesc.Usage = D3D11_USAGE_DEFAULT;
        vbDesc.BindFlags = D3D11_BIND_VERTEX_BUFFER;
        vbDesc.StructureByteStride = sizeof(VertexPositionColor);

        D3D11_SUBRESOURCE_DATA vbInit{};
        vbInit.pSysMem = data.vertices.data();
        device_->CreateBuffer(&vbDesc, &vbInit, &res.vertexBuffer);

        // Index buffer
        D3D11_BUFFER_DESC ibDesc{};
        ibDesc.ByteWidth = static_cast<uint32_t>(data.indices.size() * sizeof(uint16_t));
        ibDesc.Usage = D3D11_USAGE_DEFAULT;
        ibDesc.BindFlags = D3D11_BIND_INDEX_BUFFER;

        D3D11_SUBRESOURCE_DATA ibInit{};
        ibInit.pSysMem = data.indices.data();
        device_->CreateBuffer(&ibDesc, &ibInit, &res.indexBuffer);

        meshes_[static_cast<size_t>(type)] = res;
    }

    void cleanup() {
        for (auto& m : meshes_) {
            if (m.vertexBuffer) { m.vertexBuffer->Release(); m.vertexBuffer = nullptr; }
            if (m.indexBuffer)  { m.indexBuffer->Release();  m.indexBuffer = nullptr; }
        }
        if (constantBuffer_) { constantBuffer_->Release(); constantBuffer_ = nullptr; }
        if (solidRS_)        { solidRS_->Release();        solidRS_ = nullptr; }
        if (wireframeRS_)    { wireframeRS_->Release();    wireframeRS_ = nullptr; }
        if (dsv_)            { dsv_->Release();            dsv_ = nullptr; }
        if (rtv_)            { rtv_->Release();            rtv_ = nullptr; }
        if (swapChain_)      { swapChain_->Release();      swapChain_ = nullptr; }
        if (context_)        { context_->Release();        context_ = nullptr; }
        if (device_)         { device_->Release();         device_ = nullptr; }

        if (hwnd_) {
            user32::DestroyWindow(hwnd_);
            hwnd_ = nullptr;
        }
    }

    static user32::LRESULT viewerWndProc(win32::HWND hwnd, user32::UINT uMsg, user32::WPARAM wParam, user32::LPARAM lParam) {
        auto* session = reinterpret_cast<ViewerSession*>(user32::GetWindowLongPtrW(hwnd, user32::GWLP_USERDATA));
        if (session) {
            switch (uMsg) {
                case user32::WM_KEYDOWN:
                    session->onKeyDown(static_cast<uint32_t>(wParam));
                    return 0;
                case user32::WM_MOUSEWHEEL:
                    session->onMouseWheel(static_cast<int16_t>((wParam >> 16) & 0xFFFF));
                    return 0;
                default:
                    break;
            }
        }
        return user32::DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }

    uint32_t width_{800};
    uint32_t height_{600};
    win32::HWND hwnd_{nullptr};

    ID3D11Device*        device_{nullptr};
    ID3D11DeviceContext* context_{nullptr};
    IDXGISwapChain*      swapChain_{nullptr};
    ID3D11RenderTargetView*   rtv_{nullptr};
    ID3D11DepthStencilView*   dsv_{nullptr};
    ID3D11Buffer*        constantBuffer_{nullptr};
    ID3D11RasterizerState* solidRS_{nullptr};
    ID3D11RasterizerState* wireframeRS_{nullptr};

    std::array<ModelResource, 3> meshes_{};
    ViewerModelType activeModel_{ViewerModelType::Crystal};
    bool isWireframe_{false};
    bool autoRotate_{true};
    float modelRotationY_{0.0f};
    float modelRotationX_{0.2f};

    ViewerCamera camera_{};
    uint32_t frameCount_{0};
};

} // namespace micant::viewer
