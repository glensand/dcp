#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "raw_socket_protocol_xor.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <key_file>\n", argv[0]);
        printf("Generates a random %d-byte key file for XOR encryption\n", XOR_KEY_SIZE);
        return 1;
    }

    // Initialize random number generator
    srand(time(NULL));

    // Generate random key
    unsigned char key[XOR_KEY_SIZE];
    for (int i = 0; i < XOR_KEY_SIZE; i++) {
        key[i] = rand() & 0xFF;
    }

    // Write key to file
    FILE *f = fopen(argv[1], "wb");
    if (!f) {
        perror("Could not open key file for writing");
        return 1;
    }

    if (fwrite(key, 1, XOR_KEY_SIZE, f) != XOR_KEY_SIZE) {
        perror("Could not write key to file");
        fclose(f);
        return 1;
    }

    fclose(f);
    printf("Generated %d-byte XOR key in file: %s\n", XOR_KEY_SIZE, argv[1]);
    return 0;
} 