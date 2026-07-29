#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <tmmintrin.h>
#include <wmmintrin.h>
#include <immintrin.h>

static const uint8_t GS[16] = {1,10,4,12,6,15,3,9,2,13,11,7,5,0,8,14};
static const uint8_t RC[28] = {1,3,7,15,31,63,63,61,59,55,47,31,63,63,61,59,55,47,31,63,63,61,59,55,47,31,63,63};
static uint64_t PERM_LOOKUP[8][256];
static uint8_t SB[256];

static void init_perm_lookup(void) {
    const int PERM[64] = {0,17,34,51,48,1,18,35,32,49,2,19,16,33,50,3,4,21,38,55,52,5,22,39,36,53,6,23,20,37,54,7,8,25,42,59,56,9,26,43,40,57,10,27,24,41,58,11,12,29,46,63,60,13,30,47,44,61,14,31,28,45,62,15};
    int inv[64];
    for(int i=0;i<64;i++) inv[PERM[i]]=i;
    for(int src_byte=0;src_byte<8;src_byte++)
        for(int val=0;val<256;val++){
            uint64_t result=0;
            for(int bit=0;bit<8;bit++)
                if((val>>bit)&1){
                    int src_bit=src_byte*8+bit;
                    int dst_bit=PERM[src_bit];
                    result |= 1ULL<<dst_bit;
                }
            PERM_LOOKUP[src_byte][val]=result;
        }
}

static inline uint64_t perm_fast(uint64_t s){
    uint8_t *b=(uint8_t*)&s;
    return PERM_LOOKUP[0][b[0]]^PERM_LOOKUP[1][b[1]]^PERM_LOOKUP[2][b[2]]^PERM_LOOKUP[3][b[3]]^
           PERM_LOOKUP[4][b[4]]^PERM_LOOKUP[5][b[5]]^PERM_LOOKUP[6][b[6]]^PERM_LOOKUP[7][b[7]];
}

static void init_sb(void){
    for(int i=0;i<256;i++) SB[i]=(GS[i>>4]<<4)|GS[i&0xF];
}

static void gift64_key_schedule(const uint8_t key[16], uint64_t rk[28]){
    uint16_t K[8]; memcpy(K,key,16);
    for(int r=0;r<28;r++){
        rk[r]=((uint64_t)K[0]<<48)|((uint64_t)K[1]<<32)|((uint64_t)RC[r]<<60);
        uint16_t tmp=K[7];
        for(int i=7;i>0;i--) K[i]=K[i-1];
        K[0]=(tmp<<4)|(K[0]>>12);
    }
}

typedef void (*block_enc_fn)(const uint8_t*, uint8_t*, const uint64_t*);

void gift64_encrypt_base(const uint8_t in[8], uint8_t out[8], const uint64_t rk[28]){
    uint64_t state; memcpy(&state,in,8);
    uint64_t masks[64];
    const int PERM[64] = {0,17,34,51,48,1,18,35,32,49,2,19,16,33,50,3,4,21,38,55,52,5,22,39,36,53,6,23,20,37,54,7,8,25,42,59,56,9,26,43,40,57,10,27,24,41,58,11,12,29,46,63,60,13,30,47,44,61,14,31,28,45,62,15};
    for(int i=0;i<64;i++) masks[PERM[i]]=1ULL<<i;
    for(int r=0;r<28;r++){
        uint64_t s=0;
        for(int i=0;i<16;i++) s |= ((uint64_t)GS[(state>>(i*4))&0xF]) << (i*4);
        uint64_t p=0;
        for(int i=0;i<64;i++) if(s & masks[i]) p |= 1ULL<<i;
        state = p ^ rk[r];
    }
    memcpy(out,&state,8);
}

void gift64_encrypt_ttable(const uint8_t in[8], uint8_t out[8], const uint64_t rk[28]){
    uint64_t state; memcpy(&state,in,8);
    uint8_t *b=(uint8_t*)&state;
    for(int r=0;r<28;r++){
        for(int i=0;i<8;i++) b[i]=SB[b[i]];
        state = perm_fast(state) ^ rk[r];
    }
    memcpy(out,&state,8);
}

void gift64_encrypt_unrolled(const uint8_t in[8], uint8_t out[8], const uint64_t rk[28]){
    uint64_t state; memcpy(&state,in,8);
    uint8_t *b=(uint8_t*)&state;
    #define GIFT_ROUND(r) do{for(int i=0;i<8;i++)b[i]=SB[b[i]]; state=perm_fast(state)^rk[r];}while(0)
    GIFT_ROUND(0); GIFT_ROUND(1); GIFT_ROUND(2); GIFT_ROUND(3);
    GIFT_ROUND(4); GIFT_ROUND(5); GIFT_ROUND(6); GIFT_ROUND(7);
    GIFT_ROUND(8); GIFT_ROUND(9); GIFT_ROUND(10); GIFT_ROUND(11);
    GIFT_ROUND(12); GIFT_ROUND(13); GIFT_ROUND(14); GIFT_ROUND(15);
    GIFT_ROUND(16); GIFT_ROUND(17); GIFT_ROUND(18); GIFT_ROUND(19);
    GIFT_ROUND(20); GIFT_ROUND(21); GIFT_ROUND(22); GIFT_ROUND(23);
    GIFT_ROUND(24); GIFT_ROUND(25); GIFT_ROUND(26); GIFT_ROUND(27);
    memcpy(out,&state,8);
}

static __m128i SBOX_TABLES[16];
static void init_ssse3(void){
    for(int hi=0;hi<16;hi++){
        uint8_t tbl[16];
        for(int lo=0;lo<16;lo++) tbl[lo]=SB[(hi<<4)|lo];
        SBOX_TABLES[hi]=_mm_loadu_si128((__m128i*)tbl);
    }
}

void gift64_encrypt_ssse3(const uint8_t in[8], uint8_t out[8], const uint64_t rk[28]){
    uint64_t state; memcpy(&state,in,8);
    for(int r=0;r<28;r++){
        uint8_t sboxed[8];
        for(int i=0;i<8;i++){
            uint8_t x=((uint8_t*)&state)[i];
            uint8_t hi=x>>4, lo=x&0xF;
            __m128i table = SBOX_TABLES[hi];
            __m128i idx = _mm_set1_epi8(lo);
            __m128i res = _mm_shuffle_epi8(table, idx);
            sboxed[i] = (uint8_t)_mm_cvtsi128_si32(res);
        }
        memcpy(&state, sboxed, 8);
        state = perm_fast(state) ^ rk[r];
    }
    memcpy(out,&state,8);
}

static __m128i AES_SBOX_TABLE[16];
static void init_aesni(void){
    for(int hi=0;hi<16;hi++){
        uint8_t tbl[16];
        for(int lo=0;lo<16;lo++){
            uint8_t val=(hi<<4)|lo;
            __m128i v = _mm_set1_epi8(val);
            v = _mm_aesenclast_si128(v, _mm_setzero_si128());
            tbl[lo] = (uint8_t)_mm_cvtsi128_si32(v);
        }
        AES_SBOX_TABLE[hi]=_mm_loadu_si128((__m128i*)tbl);
    }
}

void gift64_encrypt_aesni(const uint8_t in[8], uint8_t out[8], const uint64_t rk[28]){
    uint64_t state; memcpy(&state,in,8);
    for(int r=0;r<28;r++){
        uint8_t sboxed[8];
        for(int i=0;i<8;i++){
            uint8_t x=((uint8_t*)&state)[i];
            uint8_t hi=x>>4, lo=x&0xF;
            __m128i table = AES_SBOX_TABLE[hi];
            __m128i idx = _mm_set1_epi8(lo);
            __m128i res = _mm_shuffle_epi8(table, idx);
            sboxed[i] = (uint8_t)_mm_cvtsi128_si32(res);
        }
        memcpy(&state, sboxed, 8);
        state = perm_fast(state) ^ rk[r];
    }
    memcpy(out,&state,8);
}

void gift64_encrypt_avx2(const uint8_t in[8], uint8_t out[8], const uint64_t rk[28]){
    uint64_t state; memcpy(&state,in,8);
    for(int r=0;r<28;r++){
        uint8_t sboxed[8];
        for(int i=0;i<8;i++){
            uint8_t x=((uint8_t*)&state)[i];
            uint8_t hi=x>>4, lo=x&0xF;
            __m256i table = _mm256_broadcastsi128_si256(SBOX_TABLES[hi]);
            __m256i idx = _mm256_set1_epi8(lo);
            __m256i res = _mm256_shuffle_epi8(table, idx);
            __m128i low = _mm256_castsi256_si128(res);
            sboxed[i] = (uint8_t)_mm_cvtsi128_si32(low);
        }
        memcpy(&state, sboxed, 8);
        state = perm_fast(state) ^ rk[r];
    }
    memcpy(out,&state,8);
}

static void ctr_2x_ssse3(const uint8_t *in,uint8_t *out,size_t len,
                         const uint8_t iv[8],const uint64_t rk[28],block_enc_fn enc){
    (void)enc;
    uint8_t ctr[8]; memcpy(ctr,iv,8);
    for(size_t b=0;b<len/8;b+=2){
        uint8_t c1[8],c2[8],k1[8],k2[8];
        memcpy(c1,ctr,8); for(int i=7;i>=0;i--){ctr[i]++;if(ctr[i]!=0)break;}
        memcpy(c2,ctr,8); for(int i=7;i>=0;i--){ctr[i]++;if(ctr[i]!=0)break;}
        gift64_encrypt_ssse3(c1,k1,rk);
        gift64_encrypt_ssse3(c2,k2,rk);
        for(int i=0;i<8;i++){out[(b+0)*8+i]=in[(b+0)*8+i]^k1[i]; out[(b+1)*8+i]=in[(b+1)*8+i]^k2[i];}
    }
}

static void ctr_2x_aesni(const uint8_t *in,uint8_t *out,size_t len,
                         const uint8_t iv[8],const uint64_t rk[28],block_enc_fn enc){
    (void)enc;
    uint8_t ctr[8]; memcpy(ctr,iv,8);
    for(size_t b=0;b<len/8;b+=2){
        uint8_t c1[8],c2[8],k1[8],k2[8];
        memcpy(c1,ctr,8); for(int i=7;i>=0;i--){ctr[i]++;if(ctr[i]!=0)break;}
        memcpy(c2,ctr,8); for(int i=7;i>=0;i--){ctr[i]++;if(ctr[i]!=0)break;}
        gift64_encrypt_aesni(c1,k1,rk);
        gift64_encrypt_aesni(c2,k2,rk);
        for(int i=0;i<8;i++){out[(b+0)*8+i]=in[(b+0)*8+i]^k1[i]; out[(b+1)*8+i]=in[(b+1)*8+i]^k2[i];}
    }
}

static void ctr_8x_avx2(const uint8_t *in,uint8_t *out,size_t len,
                        const uint8_t iv[8],const uint64_t rk[28],block_enc_fn enc){
    (void)enc;
    uint8_t ctr[8]; memcpy(ctr,iv,8);
    for(size_t b=0;b<len/8;b+=8){
        uint8_t c[8][8], k[8][8];
        for(int j=0;j<8;j++){memcpy(c[j],ctr,8); for(int i=7;i>=0;i--){ctr[i]++;if(ctr[i]!=0)break;}}
        for(int j=0;j<8;j++) gift64_encrypt_avx2(c[j], k[j], rk);
        for(int j=0;j<8;j++) for(int i=0;i<8;i++) out[(b+j)*8+i]=in[(b+j)*8+i]^k[j][i];
    }
}

typedef void (*mode_fn)(const uint8_t*,uint8_t*,size_t,const uint8_t*,const uint64_t*,block_enc_fn);

void ctr_1x(const uint8_t *in,uint8_t *out,size_t len,const uint8_t iv[8],const uint64_t rk[28],block_enc_fn enc){
    uint8_t ctr[8]; memcpy(ctr,iv,8);
    for(size_t b=0;b<len/8;b++){
        uint8_t ks[8]; enc(ctr,ks,rk);
        for(int i=0;i<8;i++) out[b*8+i]=in[b*8+i]^ks[i];
        for(int i=7;i>=0;i--){ctr[i]++;if(ctr[i]!=0)break;}
    }
}

void gcm_1x(const uint8_t *in,uint8_t *out,size_t len,const uint8_t iv[8],const uint64_t rk[28],block_enc_fn enc){
    uint8_t gc[8]; memcpy(gc,iv,4); memset(gc+4,0,3); gc[7]=2;
    for(size_t b=0;b<len/8;b++){
        uint8_t ks[8]; enc(gc,ks,rk);
        for(int i=0;i<8;i++) out[b*8+i]=in[b*8+i]^ks[i];
        for(int i=7;i>=0;i--){gc[i]++;if(gc[i]!=0)break;}
    }
}

void xts_1x(const uint8_t *in,uint8_t *out,size_t len,const uint8_t iv[8],const uint64_t rk[28],block_enc_fn enc){
    uint8_t tw[8]; enc(iv,tw,rk);
    for(size_t b=0;b<len/8;b++){
        for(int i=0;i<8;i++) out[b*8+i]=in[b*8+i]^tw[i];
        enc(out+b*8,out+b*8,rk);
        for(int i=0;i<8;i++) out[b*8+i]^=tw[i];
        uint8_t c=0;for(int i=0;i<8;i++){uint8_t nc=tw[i]>>7;tw[i]=(tw[i]<<1)|c;c=nc;}
        if(c) tw[0]^=0x1b;
    }
}

void bench(const char *mn,const char *nm,mode_fn mf,block_enc_fn enc,
           uint8_t *in,uint8_t *out,size_t len,const uint8_t iv[8],const uint64_t rk[28]){
    clock_t s=clock();
    for(int iter=0;iter<10;iter++){uint8_t ci[8];memcpy(ci,iv,8);ci[7]=iter;mf(in,out,len,ci,rk,enc);}
    double sec=(double)(clock()-s)/CLOCKS_PER_SEC;
    printf("  %-6s %-12s | %8.3f 秒 | %10.2f MB/s\n",mn,nm,sec,len*10.0/(1024*1024)/sec);
}

int main(void){
    init_sb();
    init_perm_lookup();
    init_ssse3();
    init_aesni();

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║      GIFT-64 多方案 & 多模式 完整性能对比测试         ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    uint8_t key[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t iv[8]={0};
    uint64_t rk[28];
    gift64_key_schedule(key,rk);

    block_enc_fn encs[]={gift64_encrypt_base,gift64_encrypt_ttable,gift64_encrypt_ssse3,gift64_encrypt_aesni,gift64_encrypt_avx2};
    const char *nm[]={"Base","T-Table","SSSE3","AES-NI","AVX2"};

    size_t len=10UL*1024*1024;
    uint8_t *in=aligned_alloc(64,len), *out=aligned_alloc(64,len);
    if(!in || !out){len=5UL*1024*1024; free(in); free(out); in=aligned_alloc(64,len); out=aligned_alloc(64,len);}
    memset(in,0xAA,len);

    mode_fn cf[]={ctr_1x,ctr_1x,ctr_2x_ssse3,ctr_2x_aesni,ctr_8x_avx2};
    mode_fn gf[]={gcm_1x,gcm_1x,gcm_1x,gcm_1x,gcm_1x};
    mode_fn xf[]={xts_1x,xts_1x,xts_1x,xts_1x,xts_1x};

    printf("\n═══════ CTR 模式 (%luMB × 10次) ═══════\n", len/(1024*1024));
    for(int i=0;i<5;i++) bench("CTR",nm[i],cf[i],encs[i],in,out,len,iv,rk);

    printf("\n═══════ GCM 模式 (%luMB × 10次) ═══════\n", len/(1024*1024));
    for(int i=0;i<5;i++) bench("GCM",nm[i],gf[i],encs[i],in,out,len,iv,rk);

    printf("\n═══════ XTS 模式 (%luMB × 10次) ═══════\n", len/(1024*1024));
    for(int i=0;i<5;i++) bench("XTS",nm[i],xf[i],encs[i],in,out,len,iv,rk);

    free(in); free(out);
    printf("\n═══════ 测试完成 ═══════\n");
    return 0;
}