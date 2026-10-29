// Native DXMT DXBC/Draw probe. This source alone is not build/run evidence.
// Interface declarations come from the unmodified native DXMT headers:
//   3Shain/dxmt@d162ea44a31fbf9089ea09977337f0beb30bd082
//   misyltoad/mingw-directx-headers@9df86f2341616ef1888ae59919feaa6d4fad693d
// Compile with DXMT's include/native/{windows,directx} include directories and
// link its native d3d11 library. No private COM layout or Metal fallback is used.
// Scope: native DXBC VS/PS + Draw + readback; no window, PE, or guest ABI.
// --skip-draw is a real GPU negative control: magenta must not pass green checks.

#include <sys/types.h>
#include <sys/sysctl.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "shaders/draw_shaders.h"
#include <d3d11.h>

namespace {
constexpr UINT kWidth = 32;
constexpr UINT kHeight = 32;
constexpr unsigned kTolerance = 1; // Absolute UNORM8 error per channel.
constexpr unsigned kExpected[4] = {0, 255, 0, 255};
constexpr FLOAT kClear[4] = {1.0f, 0.0f, 1.0f, 1.0f};
static_assert(sizeof(HRESULT) == 4);

#if defined(__arm64__) || defined(__aarch64__)
constexpr const char *kArchitecture = "arm64";
constexpr bool kArm64 = true;
#elif defined(__x86_64__)
constexpr const char *kArchitecture = "x86_64";
constexpr bool kArm64 = false;
#else
constexpr const char *kArchitecture = "other";
constexpr bool kArm64 = false;
#endif

const char *boolean(bool value) { return value ? "true" : "false"; }

struct HResult {
  bool attempted = false;
  HRESULT value = 0;
  bool record(HRESULT result) {
    attempted = true;
    value = result;
    return SUCCEEDED(result);
  }
  void print(const char *name) const {
    std::printf("\"%s\":", name);
    if (!attempted) {
      std::printf("null");
      return;
    }
    std::printf("{\"signed\":%d,\"hex\":\"0x%08x\",\"succeeded\":%s}",
                static_cast<int>(value), static_cast<unsigned>(value),
                boolean(SUCCEEDED(value)));
  }
};

// Own exactly the application reference returned through each output parameter.
// A nonzero Release result is allowed: DXMT may retain internal references.
template <typename T> struct OwnedCom {
  T *pointer = nullptr;
  OwnedCom() = default;
  OwnedCom(const OwnedCom &) = delete;
  OwnedCom &operator=(const OwnedCom &) = delete;
  ~OwnedCom() { release(); }
  bool release() {
    if (!pointer) return false;
    pointer->Release();
    pointer = nullptr;
    return true;
  }
  T *operator->() const { return pointer; }
};
} // namespace

int main(int argc, char **argv) {
  const bool skip_draw = argc == 2 && std::strcmp(argv[1], "--skip-draw") == 0;
  if (argc != 1 && !skip_draw) return 64;
  // ENOENT is Apple's documented native-process case for this optional sysctl.
  // Preserve its errno, and never turn an unexpected query failure into PASS.
  int translated = -1;
  std::size_t translated_size = sizeof(translated);
  errno = 0;
  const int query_result = sysctlbyname("sysctl.proc_translated", &translated,
                                       &translated_size, nullptr, 0);
  const int query_errno = query_result == 0 ? 0 : errno;
  const bool query_valid = query_result == 0 && translated_size == sizeof(int) &&
                           (translated == 0 || translated == 1);
  const bool translation_known = query_valid ||
                                  (query_result == -1 && query_errno == ENOENT);
  const bool using_rosetta = query_valid && translated == 1;
  const bool native_arm64 = kArm64 && translation_known && !using_rosetta;

  OwnedCom<ID3D11Device> device;
  OwnedCom<ID3D11DeviceContext> context;
  OwnedCom<ID3D11Texture2D> target;
  OwnedCom<ID3D11RenderTargetView> rtv;
  OwnedCom<ID3D11Texture2D> staging;
  OwnedCom<ID3D11VertexShader> vertex_shader;
  OwnedCom<ID3D11PixelShader> pixel_shader;
  OwnedCom<ID3D11RasterizerState> rasterizer;
  HResult create_device, create_target, create_rtv, create_staging, map, removed;
  HResult create_vs, create_ps, create_rasterizer;
  D3D_FEATURE_LEVEL feature_level = static_cast<D3D_FEATURE_LEVEL>(0);
  const D3D_FEATURE_LEVEL requested[] = {D3D_FEATURE_LEVEL_11_0};
  D3D11_MAPPED_SUBRESOURCE mapped = {};
  const char *failure = native_arm64 ? "not_started" : "native_arm64_unverified";
  bool map_active = false;
  bool unmap_called = false;
  bool clear_called = false;
  bool copy_called = false;
  bool pipeline_bound = false;
  bool draw_called = false;
  bool clear_state_called = false;
  unsigned pixels_checked = 0;
  unsigned channels_checked = 0;
  unsigned mismatched_pixels = 0;
  unsigned mismatched_channels = 0;
  unsigned max_error = 0;
  unsigned first_x = 0, first_y = 0, first_channel = 0, first_actual = 0;
  bool pixels_pass = false;

  do {
    if (!native_arm64) break;
    failure = "D3D11CreateDevice";
    if (!create_device.record(D3D11CreateDevice(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, requested, 1,
            D3D11_SDK_VERSION, &device.pointer, &feature_level,
            &context.pointer))) break;
    failure = "device_outputs_or_feature_level";
    if (!device.pointer || !context.pointer || feature_level != requested[0]) break;

    D3D11_TEXTURE2D_DESC description = {};
    description.Width = kWidth;
    description.Height = kHeight;
    description.MipLevels = 1;
    description.ArraySize = 1;
    description.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    description.SampleDesc.Count = 1;
    description.Usage = D3D11_USAGE_DEFAULT;
    description.BindFlags = D3D11_BIND_RENDER_TARGET;
    failure = "CreateTexture2D_render_target";
    if (!create_target.record(device->CreateTexture2D(
            &description, nullptr, &target.pointer)) || !target.pointer) break;
    failure = "CreateRenderTargetView";
    if (!create_rtv.record(device->CreateRenderTargetView(
            target.pointer, nullptr, &rtv.pointer)) || !rtv.pointer) break;

    description.Usage = D3D11_USAGE_STAGING;
    description.BindFlags = 0;
    description.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    failure = "CreateTexture2D_staging";
    if (!create_staging.record(device->CreateTexture2D(
            &description, nullptr, &staging.pointer)) || !staging.pointer) break;

    failure = "CreateVertexShader";
    if (!create_vs.record(device->CreateVertexShader(
            kTriangleVsDxbc, sizeof(kTriangleVsDxbc), nullptr,
            &vertex_shader.pointer)) || !vertex_shader.pointer) break;
    failure = "CreatePixelShader";
    if (!create_ps.record(device->CreatePixelShader(
            kTrianglePsDxbc, sizeof(kTrianglePsDxbc), nullptr,
            &pixel_shader.pointer)) || !pixel_shader.pointer) break;
    D3D11_RASTERIZER_DESC rasterizer_description = {};
    rasterizer_description.FillMode = D3D11_FILL_SOLID;
    rasterizer_description.CullMode = D3D11_CULL_NONE;
    rasterizer_description.DepthClipEnable = TRUE;
    failure = "CreateRasterizerState";
    if (!create_rasterizer.record(device->CreateRasterizerState(
            &rasterizer_description, &rasterizer.pointer)) || !rasterizer.pointer) break;

    // Vertex positions come from SV_VertexID; no input layout or buffer exists.
    // Explicit cull-none avoids depending on projected triangle winding.
    D3D11_VIEWPORT viewport = {};
    viewport.Width = static_cast<FLOAT>(kWidth);
    viewport.Height = static_cast<FLOAT>(kHeight);
    viewport.MinDepth = 0.0f;
    viewport.MaxDepth = 1.0f;
    context->IASetInputLayout(nullptr);
    context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context->RSSetState(rasterizer.pointer);
    context->RSSetViewports(1, &viewport);
    context->OMSetRenderTargets(1, &rtv.pointer, nullptr);
    context->VSSetShader(vertex_shader.pointer, nullptr, 0);
    context->PSSetShader(pixel_shader.pointer, nullptr, 0);
    pipeline_bound = true;

    // These methods return void. Do not invent HRESULT success for them.
    // Map(READ, flags=0) provides the blocking synchronization for CPU readback.
    context->ClearRenderTargetView(rtv.pointer, kClear);
    clear_called = true;
    if (!skip_draw) {
      context->Draw(3, 0);
      draw_called = true;
    }
    context->CopyResource(staging.pointer, target.pointer);
    copy_called = true;
    failure = "Map";
    if (!map.record(context->Map(staging.pointer, 0, D3D11_MAP_READ, 0, &mapped))) break;
    map_active = true;
    failure = "mapped_pointer_or_row_pitch";
    if (!mapped.pData || mapped.RowPitch < kWidth * 4) break;

    const auto *bytes = static_cast<const std::uint8_t *>(mapped.pData);
    for (UINT y = 0; y < kHeight; ++y) {
      // Use the API's row pitch, not an assumed contiguous width * height buffer.
      const auto *row = bytes + static_cast<std::size_t>(y) * mapped.RowPitch;
      for (UINT x = 0; x < kWidth; ++x) {
        bool bad_pixel = false;
        for (unsigned channel = 0; channel < 4; ++channel) {
          const unsigned actual = row[x * 4 + channel];
          const unsigned expected = kExpected[channel];
          const unsigned error = actual > expected ? actual - expected : expected - actual;
          if (error > max_error) max_error = error;
          if (error > kTolerance) {
            if (mismatched_channels == 0) {
              first_x = x; first_y = y; first_channel = channel; first_actual = actual;
            }
            ++mismatched_channels;
            bad_pixel = true;
          }
          ++channels_checked;
        }
        mismatched_pixels += bad_pixel ? 1 : 0;
        ++pixels_checked;
      }
    }
    failure = "pixel_mismatch";
    pixels_pass = pixels_checked == kWidth * kHeight &&
                  channels_checked == kWidth * kHeight * 4 &&
                  mismatched_channels == 0;
  } while (false);

  // All paths after successful Map, including a malformed mapping, Unmap once.
  if (map_active) {
    context->Unmap(staging.pointer, 0);
    map_active = false;
    unmap_called = true;
  }
  if (context.pointer) {
    context->ClearState();
    clear_state_called = true;
  }
  if (device.pointer) removed.record(device->GetDeviceRemovedReason());
  const bool passed = native_arm64 && pipeline_bound && draw_called &&
                      clear_state_called && pixels_pass && unmap_called &&
                      removed.attempted && removed.value == S_OK;
  if (pixels_pass && !passed) failure = "GetDeviceRemovedReason";

  // Cleanup precedes the result. This confirms application-reference release,
  // not a claim about DXMT's internal asynchronous allocations or leak freedom.
  unsigned released_objects = 0;
  released_objects += rasterizer.release();
  released_objects += pixel_shader.release();
  released_objects += vertex_shader.release();
  released_objects += rtv.release();
  released_objects += staging.release();
  released_objects += target.release();
  released_objects += context.release();
  released_objects += device.release();

  std::printf("{\"schema\":1,\"probe\":\"native_dxmt_d3d11_dxbc_draw\","
              "\"status\":\"%s\",\"failure_stage\":",
              passed ? "PASS" : native_arm64 ? "FAIL" : "ENVIRONMENT_UNVERIFIED");
  if (passed) std::printf("null"); else std::printf("\"%s\"", failure);
  std::printf(
      ",\"scope\":{\"shader\":true,\"triangle\":true,\"window\":false,\"guest\":false},"
      "\"compile_arch\":\"%s\",\"native_arm64\":%s,"
      "\"translation\":{\"sysctl_return\":%d,\"errno\":%d,\"raw_value\":%d,"
      "\"known\":%s,\"rosetta\":", kArchitecture, boolean(native_arm64),
      query_result, query_errno, translated, boolean(translation_known));
  if (translation_known) std::printf("%s", boolean(using_rosetta));
  else std::printf("null");
  std::printf("},\"feature_level\":%u,\"feature_level_hex\":\"0x%04x\",\"hresult\":{",
              static_cast<unsigned>(feature_level), static_cast<unsigned>(feature_level));
  create_device.print("D3D11CreateDevice"); std::printf(",");
  create_target.print("CreateTexture2D_render_target"); std::printf(",");
  create_rtv.print("CreateRenderTargetView"); std::printf(",");
  create_staging.print("CreateTexture2D_staging"); std::printf(",");
  create_vs.print("CreateVertexShader"); std::printf(",");
  create_ps.print("CreatePixelShader"); std::printf(",");
  create_rasterizer.print("CreateRasterizerState"); std::printf(",");
  map.print("Map"); std::printf(",");
  removed.print("GetDeviceRemovedReason");
  std::printf(
      "},\"clear_called\":%s,\"copy_called\":%s,\"unmap_called\":%s,"
      "\"format\":\"R8G8B8A8_UNORM\",\"width\":%u,\"height\":%u,"
      "\"row_pitch\":%u,\"depth_pitch\":%u,\"expected_rgba8\":[0,255,0,255],"
      "\"tolerance_per_channel\":%u,\"pixels_checked\":%u,\"channels_checked\":%u,"
      "\"mismatched_pixels\":%u,\"mismatched_channels\":%u,\"max_absolute_error\":%u,"
      "\"first_mismatch\":", boolean(clear_called), boolean(copy_called), boolean(unmap_called),
      kWidth, kHeight, mapped.RowPitch, mapped.DepthPitch, kTolerance,
      pixels_checked, channels_checked, mismatched_pixels, mismatched_channels, max_error);
  if (mismatched_channels) {
    std::printf("{\"x\":%u,\"y\":%u,\"channel\":%u,\"expected\":%u,\"actual\":%u}",
                first_x, first_y, first_channel, kExpected[first_channel], first_actual);
  } else {
    std::printf("null");
  }
  std::printf(
      ",\"skip_draw\":%s,\"draw_called\":%s,\"pipeline_bound\":%s,"
      "\"clear_state_called\":%s,\"vertex_count\":%u,\"start_vertex\":0,"
      "\"vertex_shader_bytes\":%zu,\"pixel_shader_bytes\":%zu,"
      "\"clear_rgba8\":[255,0,255,255],\"cull_mode\":\"NONE\","
      "\"topology\":\"TRIANGLELIST\",\"input_layout\":null,\"vertex_buffers\":0",
      boolean(skip_draw), boolean(draw_called), boolean(pipeline_bound),
      boolean(clear_state_called), draw_called ? 3u : 0u,
      sizeof(kTriangleVsDxbc), sizeof(kTrianglePsDxbc));
  std::printf(
      ",\"released_application_objects\":%u,\"all_application_references_released\":true}\n",
      released_objects);
  return passed ? 0 : native_arm64 ? 1 : 2;
}
