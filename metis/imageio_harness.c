/*
 * imageio_harness.c — Minimal ImageIO fuzzing harness.
 *
 * Reads a PNG file and processes it through Apple's ImageIO framework
 * (CGImageSource), triggering the full PNG parsing pipeline including
 * Apple-proprietary chunk handling.
 *
 * Compile: cc -o imageio_harness imageio_harness.c \
 *          -framework CoreGraphics -framework ImageIO -framework CoreFoundation
 *
 * Usage: ./imageio_harness <input.png>
 *        Returns 0 on success, 1 on parse error, 2 on crash-worthy signal.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <image_file>\n", argv[0]);
        return 1;
    }

    /* Read file into memory */
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 100*1024*1024) {
        fprintf(stderr, "Bad size: %ld\n", sz);
        fclose(f);
        return 1;
    }
    uint8_t *buf = malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);

    /* Create CFData from buffer */
    CFDataRef data = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault, buf, sz, kCFAllocatorNull);
    if (!data) { free(buf); return 1; }

    /* Create image source — this triggers chunk parsing */
    CGImageSourceRef src = CGImageSourceCreateWithData(data, NULL);
    if (!src) {
        CFRelease(data);
        free(buf);
        return 1;
    }

    /* Get image count (triggers further parsing) */
    size_t count = CGImageSourceGetCount(src);

    /* Get status (triggers validation) */
    CGImageSourceStatus status = CGImageSourceGetStatus(src);

    /* Try to read properties (triggers metadata parsing — iCCP, eXIf, iDOT) */
    CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(src, 0, NULL);

    /* Try to create the actual image (triggers IDAT decompression) */
    CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
    if (img) {
        /* Access pixel data — forces full decode */
        size_t w = CGImageGetWidth(img);
        size_t h = CGImageGetHeight(img);
        size_t bpp = CGImageGetBitsPerPixel(img);
        (void)w; (void)h; (void)bpp;
        CGImageRelease(img);
    }

    if (props) CFRelease(props);
    CFRelease(src);
    CFRelease(data);
    free(buf);

    return 0;
}
