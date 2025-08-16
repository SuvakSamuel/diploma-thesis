#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// Premeni znaky na bajt
unsigned char chars_to_byte(const char *hex) {
    unsigned char byte = 0;
    for (int i = 0; i < 2; i++) {
        char c = tolower(hex[i]);
        byte <<= 4;
        if (c >= '0' && c <= '9')
            byte |= (c - '0');
        else if (c >= 'a' && c <= 'f')
            byte |= (c - 'a' + 10);
        else {
            fprintf(stderr, "Nepodporovany znak: %c\n", c);
            exit(1);
        }
    }
    return byte;
}

// Base62 - teda alfanumericke znaky
const char base62_chars[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void base62_encode(const unsigned char *data, size_t len, char *out) {
    unsigned long long value = 0;
    int out_index = 0;

    // kazdy bajt sa spracuje samostatne
    for (size_t i = 0; i < len; i++) {
        unsigned char b = data[i];
        // rozdel bajt na dve 6-bitove kusky
        out[out_index++] = base62_chars[b / 62];
        out[out_index++] = base62_chars[b % 62];
    }
    out[out_index] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Pouzitie: %s <string1> <string2>\n", argv[0]);
        return 1;
    }

    const char *hex1 = argv[1];
    const char *hex2 = argv[2];

    if (strlen(hex1) != 64 || strlen(hex2) != 64) {
        fprintf(stderr, "Obidve stringy musia mat 64 alfanumerickych znakov.\n");
        return 1;
    }

    unsigned char bytes1[32];
    unsigned char bytes2[32];
    unsigned char result[32];

    // Premeni znaky v obidvoch castiach kluca na bajty a XORne ich dokopy
    for (int i = 0; i < 32; i++) {
        bytes1[i] = chars_to_byte(&hex1[i * 2]);
        bytes2[i] = chars_to_byte(&hex2[i * 2]);
        result[i] = bytes1[i] ^ bytes2[i];
    }

    // Zakodovanie na Base62 string
    char encoded[32 * 2 + 1]; // kazdy byte su dve znaky
    base62_encode(result, 32, encoded);

    printf("%s\n", encoded);

    return 0;
}