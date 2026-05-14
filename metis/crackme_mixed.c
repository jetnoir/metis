/*
 * crackme_mixed.c — Binary with MIXED path hardness for benchmarking.
 *
 * Key insight: the hardness technique needs paths with DIFFERENT
 * backbone fractions coexisting in the active set. This binary
 * creates that by having:
 *   - Easy paths: simple range checks (low backbone, many solutions)
 *   - Hard paths: tight arithmetic constraints (high backbone, few solutions)
 *   - Trap paths: unsatisfiable constraints (backbone=1.0, waste of time)
 *
 * The technique should defer the hard/trap paths and explore easy ones first.
 *
 * Compile: cc -o crackme_mixed crackme_mixed.c -arch x86_64
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Gate function: type of challenge depends on first byte */
int verify(const uint8_t *input) {
    uint8_t gate = input[0];

    if (gate < 0x40) {
        /* EASY PATH: just check if bytes are printable ASCII
         * Low backbone — most of each byte is free */
        for (int i = 1; i < 8; i++) {
            if (input[i] < 0x20 || input[i] > 0x7e)
                return 0;
        }
        /* Easy final check */
        if (input[1] + input[2] > 0xC0)
            return 1;  /* WIN: easy path */
        return 0;

    } else if (gate < 0x80) {
        /* MEDIUM PATH: XOR chain with some freedom */
        if ((input[1] ^ input[2]) != 0x37)
            return 0;
        if ((input[3] ^ input[4]) != 0x42)
            return 0;
        /* But bytes 5-7 are free — mixed backbone */
        if (input[5] > 0x40 && input[6] > 0x40 && input[7] > 0x40)
            return 2;  /* WIN: medium path */
        return 0;

    } else if (gate < 0xC0) {
        /* HARD PATH: tight arithmetic, most variables forced */
        uint32_t v = (uint32_t)input[1] << 24 |
                     (uint32_t)input[2] << 16 |
                     (uint32_t)input[3] << 8  |
                     (uint32_t)input[4];
        if (v * 7 + 13 != 0xDEADBEEF)
            return 0;
        /* Bytes 5-7 also constrained */
        if (input[5] + input[6] + input[7] != 200)
            return 0;
        if (input[5] != input[6])
            return 0;
        return 3;  /* WIN: hard path */

    } else {
        /* TRAP PATH: contradictory constraints (unsatisfiable)
         * A solver will waste time proving these UNSAT */
        if (input[1] > 100 && input[1] < 50)  /* impossible */
            return 4;
        if (input[2] == input[3] && input[2] != input[3])  /* impossible */
            return 4;
        /* Fall through to more traps */
        uint8_t x = input[4];
        if (x > 200) {
            if (x < 100)  /* impossible given x > 200 */
                return 4;
        }
        /* Give up — unreachable win */
        if (input[5] * input[6] == 0 && input[5] > 0 && input[6] > 0)
            return 4;  /* impossible */
        return 0;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2 || strlen(argv[1]) < 8) {
        printf("Usage: %s <8-byte-key>\n", argv[0]);
        return 1;
    }

    int r = verify((const uint8_t *)argv[1]);
    switch (r) {
        case 1: printf("WIN (easy path)\n"); break;
        case 2: printf("WIN (medium path)\n"); break;
        case 3: printf("WIN (hard path)\n"); break;
        case 4: printf("WIN (trap — should be impossible)\n"); break;
        default: printf("FAIL\n"); break;
    }
    return r == 0;
}
