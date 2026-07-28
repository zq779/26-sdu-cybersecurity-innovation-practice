#ifndef SM3_OPTIMIZED_INTERNAL_H
#define SM3_OPTIMIZED_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SM3_IV0 UINT32_C(0x7380166f)
#define SM3_IV1 UINT32_C(0x4914b2b9)
#define SM3_IV2 UINT32_C(0x172442d7)
#define SM3_IV3 UINT32_C(0xda8a0600)
#define SM3_IV4 UINT32_C(0xa96f30bc)
#define SM3_IV5 UINT32_C(0x163138aa)
#define SM3_IV6 UINT32_C(0xe38dee4d)
#define SM3_IV7 UINT32_C(0xb0fb0e4e)

static inline uint32_t sm3_rotl32(uint32_t x, unsigned n)
{
    n &= 31u;
    return n == 0u ? x : (uint32_t)((x << n) | (x >> (32u - n)));
}

static inline uint32_t sm3_p0(uint32_t x)
{
    return x ^ sm3_rotl32(x, 9u) ^ sm3_rotl32(x, 17u);
}

static inline uint32_t sm3_p1(uint32_t x)
{
    return x ^ sm3_rotl32(x, 15u) ^ sm3_rotl32(x, 23u);
}

static inline uint32_t sm3_load_be32(const uint8_t p[4])
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static inline void sm3_store_be32(uint8_t p[4], uint32_t x)
{
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static inline void sm3_store_be64(uint8_t p[8], uint64_t x)
{
    for (unsigned i = 0; i < 8u; ++i) {
        p[7u - i] = (uint8_t)(x >> (i * 8u));
    }
}

static inline uint32_t sm3_t_rot(unsigned j)
{
    const uint32_t t = (j < 16u) ? UINT32_C(0x79cc4519) : UINT32_C(0x7a879d8a);
    return sm3_rotl32(t, j & 31u);
}

static inline size_t sm3_build_tail(const uint8_t *msg, size_t len,
                                    uint8_t tail[128])
{
    const size_t rem = len & 63u;
    const size_t blocks = (rem <= 55u) ? 1u : 2u;
    memset(tail, 0, 128u);
    if (rem != 0u) {
        memcpy(tail, msg + (len - rem), rem);
    }
    tail[rem] = 0x80u;
    sm3_store_be64(tail + blocks * 64u - 8u, (uint64_t)len * UINT64_C(8));
    return blocks;
}

#endif
