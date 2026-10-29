#ifndef PE_AOT_DRAW_NATIVE_BACKEND_H
#define PE_AOT_DRAW_NATIVE_BACKEND_H
#include <stdint.h>
/* These pointers exist only in trusted host storage. Never serialize them into
 * guest memory or expose them as guest COM pointers / mapped pData. */
typedef struct { void *data; uint32_t row_pitch,depth_pitch; } AotD3DNativeMap;
#ifdef __cplusplus
extern "C" {
#endif
uint32_t aot_d3d_native_create_device(void **device,void **context,uint32_t *level);
uint32_t aot_d3d_native_create_texture(void *device,const uint32_t desc[11],void **texture);
uint32_t aot_d3d_native_create_rtv(void *device,void *texture,void **view);
uint32_t aot_d3d_native_get_removed(void *device);
void aot_d3d_native_clear(void *context,void *view,const float color[4]);
void aot_d3d_native_copy(void *context,void *destination,void *source);
uint32_t aot_d3d_native_map(void *context,void *texture,AotD3DNativeMap *result);
void aot_d3d_native_unmap(void *context,void *texture);
uint32_t aot_d3d_native_create_shader(uint32_t kind,void *device,const uint8_t *bytes,uint64_t size,void **shader);
uint32_t aot_d3d_native_create_raster(void *device,const uint32_t desc[10],void **raster);
void aot_d3d_native_om_set(void *context,void *rtv);
void aot_d3d_native_rs_set(void *context,void *raster);
void aot_d3d_native_viewport(void *context,const uint32_t bits[6]);
void aot_d3d_native_topology(void *context);
void aot_d3d_native_shader_set(uint32_t kind,void *context,void *shader);
void aot_d3d_native_draw(void *context);
uint32_t aot_d3d_native_release(uint32_t kind,void *object);
#ifdef __cplusplus
}
#endif
#endif
