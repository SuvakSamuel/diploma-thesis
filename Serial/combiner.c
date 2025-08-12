#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <string1> <string2>\n", argv[0]);
        return 1;
    }

    const char *str1 = argv[1];
    const char *str2 = argv[2];

    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);

    // Allocate result string (plus 1 byte for null terminator)
    char result[64];

    for (size_t i = 0; i < 64; ++i) {
        result[i] = str1[i] ^ str2[i];
    }

    printf("%s\n", result);

    return 0;
}