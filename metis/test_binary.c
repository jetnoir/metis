/*
 * test_binary.c — Small binary with branching paths for angr testing.
 * Multiple constraint difficulty levels to validate hardness scoring.
 *
 * Compile: cc -o test_binary test_binary.c -arch x86_64
 * (x86_64 for best angr compatibility on ARM Mac via Rosetta)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_password(const char *input) {
    /* Easy path: simple byte comparison */
    if (input[0] != 'S')
        return 0;
    if (input[1] != 'E')
        return 0;
    if (input[2] != 'C')
        return 0;

    /* Medium path: arithmetic constraint */
    int sum = input[3] + input[4] + input[5];
    if (sum != 300)
        return 0;

    /* Hard path: XOR chain */
    if ((input[3] ^ input[4]) != 0x15)
        return 0;
    if ((input[4] ^ input[5]) != 0x23)
        return 0;

    /* Very hard path: multi-variable constraint */
    unsigned int v = (unsigned char)input[6] << 24 |
                     (unsigned char)input[7] << 16 |
                     (unsigned char)input[8] << 8  |
                     (unsigned char)input[9];
    if (v * 7 + 13 != 0xDEADBEEF)
        return 0;

    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    if (strlen(argv[1]) < 10) {
        printf("Too short.\n");
        return 1;
    }

    if (check_password(argv[1]))
        printf("ACCESS GRANTED\n");
    else
        printf("ACCESS DENIED\n");

    return 0;
}
