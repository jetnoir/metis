/*
 * crackme_explosion.c — Binary designed to cause path explosion in angr.
 *
 * Each byte of the 8-byte input independently branches into 2+ paths,
 * and BOTH paths continue executing (no early exits). This creates
 * 2^N forking where N = number of branches.
 *
 * The hardness technique should shine here: paths where most variables
 * are forced (high backbone) can be deferred, allowing angr to focus
 * on the easier exploratory paths first.
 *
 * Compile: cc -o crackme_explosion crackme_explosion.c -arch x86_64
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Accumulator — both branches always continue */
static int score = 0;

void check_byte(uint8_t b, int pos) {
    /* Each byte creates 2 paths, both continue */
    if (b & 0x80) {
        score += pos * 3;
        if (b & 0x40) {
            score += 7;
        } else {
            score -= 2;
        }
    } else {
        score += pos;
        if (b & 0x01) {
            score += 13;
        } else {
            score -= 5;
        }
    }
}

/* Interdependent check — creates constraints across bytes */
void cross_check(const uint8_t *input) {
    int i;
    for (i = 0; i < 7; i++) {
        if (input[i] > input[i+1]) {
            score += 100;
        } else {
            score -= 50;
        }
    }
}

/* Nested branches over pairs — more forking */
void pair_check(const uint8_t *input) {
    int i;
    for (i = 0; i < 8; i += 2) {
        uint16_t pair = (input[i] << 8) | input[i+1];
        if (pair > 0x4000) {
            if (pair < 0x8000) {
                score += 200;
            } else {
                score += 50;
            }
        } else {
            if (pair > 0x2000) {
                score += 150;
            } else {
                score += 10;
            }
        }
    }
}

int verify(const uint8_t *input) {
    int i;
    score = 0;

    /* Phase 1: Independent byte checks — 2^8 = 256 paths minimum */
    for (i = 0; i < 8; i++) {
        check_byte(input[i], i);
    }

    /* Phase 2: Cross-byte dependencies — more forking */
    cross_check(input);

    /* Phase 3: Pair checks — 4 more binary branches */
    pair_check(input);

    /* Final: score must be exactly 777 */
    return (score == 777) ? 1 : 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2 || strlen(argv[1]) < 8) {
        printf("Usage: %s <8-byte-key>\n", argv[0]);
        return 1;
    }

    if (verify((const uint8_t *)argv[1]))
        printf("WINNER!\n");
    else
        printf("score=%d (need 777)\n", score);

    return 0;
}
