/*
 * imageio_harness_afl.c — AFL++ compatible ImageIO fuzzing harness.
 * Reads image data from stdin (AFL++ mode) or from a file (standalone).
 *
 * Compile: afl-clang-fast -o imageio_harness_afl imageio_harness_afl.c \
 *          -framework CoreGraphics -framework ImageIO -framework CoreFoundation
 */
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

int process_image(const uint8_t *buf, size_t sz) {
    if (sz < 8 || sz > 50*1024*1024) return 1;

    CFDataRef data = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault, buf, sz, kCFAllocatorNull);
    if (!data) return 1;

    CGImageSourceRef src = CGImageSourceCreateWithData(data, NULL);
    if (!src) { CFRelease(data); return 1; }

    /* Trigger metadata parsing */
    CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(src, 0, NULL);

    /* Trigger full decode */
    CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
    if (img) {
        /* Force pixel access */
        size_t w = CGImageGetWidth(img);
        size_t h = CGImageGetHeight(img);
        (void)w; (void)h;
        CGImageRelease(img);
    }

    if (props) CFRelease(props);
    CFRelease(src);
    CFRelease(data);
    return 0;
}

int main(int argc, const char *argv[]) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        process_image(buf, len);
    }
#else
    /* Standalone mode — read from file */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <image_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);
    int rc = process_image(buf, sz);
    free(buf);
    return rc;
#endif
    return 0;
}
