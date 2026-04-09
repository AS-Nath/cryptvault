#include "vault_io.h"
#include <string.h>
#include <stdlib.h>

int cv_write_str(FILE* f, const char* s, uint32_t len) {
    if (fwrite(&len, sizeof(len), 1, f) != 1) return -1;
    if (len > 0 && fwrite(s, 1, len, f) != len) return -1;
    return 0;
}

int cv_read_str(FILE* f, char** out, uint32_t* out_len) {
    uint32_t len = 0;
    if (fread(&len, sizeof(len), 1, f) != 1) return -1;

    /* allocate len + 1 so the result is always null-terminated */
    char* buf = (char*)malloc(len + 1);
    if (!buf) return -1;

    if (len > 0 && fread(buf, 1, len, f) != len) {
        free(buf);
        return -1;
    }

    buf[len] = '\0';
    *out     = buf;
    *out_len = len;
    return 0;
}

int cv_write_bytes(FILE* f, const uint8_t* data, uint32_t len) {
    if (fwrite(&len, sizeof(len), 1, f) != 1) return -1;
    if (len > 0 && fwrite(data, 1, len, f) != len) return -1;
    return 0;
}

int cv_read_bytes(FILE* f, uint8_t** out, uint32_t* out_len) {
    uint32_t len = 0;
    if (fread(&len, sizeof(len), 1, f) != 1) return -1;

    uint8_t* buf = (uint8_t*)malloc(len == 0 ? 1 : len);
    if (!buf) return -1;

    if (len > 0 && fread(buf, 1, len, f) != len) {
        free(buf);
        return -1;
    }

    *out     = buf;
    *out_len = len;
    return 0;
}