#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Write a length-prefixed string: [uint32 len][bytes] */
int cv_write_str(FILE* f, const char* s, uint32_t len);

/* Read a length-prefixed string into a heap-allocated buffer.
 * On success, *out points to a null-terminated string the caller must free().
 * *out_len is set to the string length (excluding null terminator). */
int cv_read_str(FILE* f, char** out, uint32_t* out_len);

/* Write a length-prefixed byte array: [uint32 len][bytes] */
int cv_write_bytes(FILE* f, const uint8_t* data, uint32_t len);

/* Read a length-prefixed byte array into a heap-allocated buffer.
 * On success, *out points to the buffer the caller must free().
 * *out_len is set to the number of bytes read. */
int cv_read_bytes(FILE* f, uint8_t** out, uint32_t* out_len);

#ifdef __cplusplus
}
#endif