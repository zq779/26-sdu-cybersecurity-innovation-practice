#include "sm3.h"

#include <stdio.h>
#include <stdlib.h>

static int read_file(const char *path, uint8_t **data, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        perror(path);
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    const long end = ftell(fp);
    if (end < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    *len = (size_t)end;
    *data = malloc(*len == 0u ? 1u : *len);
    if (*data == NULL) {
        fclose(fp);
        return -1;
    }
    if (*len != 0u && fread(*data, 1u, *len, fp) != *len) {
        free(*data);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE...\n", argv[0]);
        return 2;
    }
    const size_t count = (size_t)(argc - 1);
    uint8_t **owned = calloc(count, sizeof(*owned));
    const uint8_t **msg = calloc(count, sizeof(*msg));
    size_t *len = calloc(count, sizeof(*len));
    uint8_t (*out)[32] = calloc(count, sizeof(*out));
    if (owned == NULL || msg == NULL || len == NULL || out == NULL) {
        fprintf(stderr, "allocation failure\n");
        return 1;
    }

    for (size_t i = 0; i < count; ++i) {
        if (read_file(argv[i + 1u], &owned[i], &len[i]) != 0) {
            fprintf(stderr, "failed to read %s\n", argv[i + 1u]);
            return 1;
        }
        msg[i] = owned[i];
    }

    if (sm3_hash_many(SM3_BACKEND_AUTO, msg, len, out, count) != 0) {
        fprintf(stderr, "hashing failed\n");
        return 1;
    }
    for (size_t i = 0; i < count; ++i) {
        for (size_t j = 0; j < 32u; ++j) {
            printf("%02x", out[i][j]);
        }
        printf("  %s\n", argv[i + 1u]);
    }
    fprintf(stderr, "backend=%s\n", sm3_backend_name(sm3_best_backend()));

    for (size_t i = 0; i < count; ++i) {
        free(owned[i]);
    }
    free(owned); free(msg); free(len); free(out);
    return 0;
}
