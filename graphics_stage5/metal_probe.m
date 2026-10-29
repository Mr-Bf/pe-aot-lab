/* Native GPU preflight only: no DirectX, guest code or window integration. */
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    @autoreleasepool {
        int translated=-1,query_errno=0;size_t length=sizeof translated;
        if(sysctlbyname("sysctl.proc_translated",&translated,&length,NULL,0)) {
            query_errno=errno;if(errno==ENOENT)translated=0;
        }
        id<MTLDevice> device=MTLCreateSystemDefaultDevice();
        if(!device){puts("{\"status\":\"FAIL\",\"reason\":\"no Metal device available\"}");return 2;}
        id<MTLCommandQueue> queue=[device newCommandQueue];
        MTLTextureDescriptor *description=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
            width:32 height:32 mipmapped:NO];
        description.storageMode=MTLStorageModeShared;description.usage=MTLTextureUsageRenderTarget;
        id<MTLTexture> texture=[device newTextureWithDescriptor:description];
        id<MTLCommandBuffer> command=[queue commandBuffer];
        if(!queue || !texture || !command){puts("{\"status\":\"FAIL\",\"reason\":\"Metal allocation failed\"}");return 3;}
        MTLRenderPassDescriptor *pass=[MTLRenderPassDescriptor renderPassDescriptor];
        pass.colorAttachments[0].texture=texture;pass.colorAttachments[0].loadAction=MTLLoadActionClear;
        pass.colorAttachments[0].storeAction=MTLStoreActionStore;
        pass.colorAttachments[0].clearColor=MTLClearColorMake(0.25,0.5,0.75,1.0);
        id<MTLRenderCommandEncoder> encoder=[command renderCommandEncoderWithDescriptor:pass];
        if(!encoder){puts("{\"status\":\"FAIL\",\"reason\":\"Metal encoder failed\"}");return 4;}
        [encoder endEncoding];[command commit];[command waitUntilCompleted];
        if(command.status!=MTLCommandBufferStatusCompleted){
            fprintf(stderr,"Metal error: %s\n",command.error.description.UTF8String);
            puts("{\"status\":\"FAIL\",\"reason\":\"GPU command failed\"}");return 5;
        }
        uint8_t pixels[32*32*4];memset(pixels,0,sizeof pixels);
        [texture getBytes:pixels bytesPerRow:32*4 fromRegion:MTLRegionMake2D(0,0,32,32) mipmapLevel:0];
        const unsigned expected[]={64,128,191,255};unsigned mismatches=0;
        for(unsigned i=0;i<32*32;i++)for(unsigned c=0;c<4;c++) {
            int delta=(int)pixels[4*i+c]-(int)expected[c];
            if(delta<-1 || delta>1)mismatches++;
        }
        NSDictionary *report=@{@"status":mismatches?@"FAIL":@"PASS",@"device":device.name,
            @"pixel_count":@1024,@"mismatched_channels":@(mismatches),
            @"pixel_rgba":@[@(pixels[0]),@(pixels[1]),@(pixels[2]),@(pixels[3])],
            @"rosetta_query":@(translated),@"rosetta_query_errno":@(query_errno),
            @"command_status":@(command.status),@"directx_executed":@NO,@"guest_executed":@NO,
            @"scope":@"native Metal clear and texture readback; not DXMT, shaders, triangle or GUI"};
        NSData *data=[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:nil];
        fwrite(data.bytes,1,data.length,stdout);putchar('\n');return mismatches?6:0;
    }
}
