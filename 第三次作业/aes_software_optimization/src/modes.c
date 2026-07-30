#include "aes_internal.h"
#include <stdlib.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

static void inc128_be(uint8_t c[16]){for(int i=15;i>=0;i--){c[i]++;if(c[i])break;}}
static void inc32_be(uint8_t c[16]){for(int i=15;i>=12;i--){c[i]++;if(c[i])break;}}

void aes_ctr_crypt(const aes_backend_t *be,const aes_key_t *key,uint8_t counter[16],const uint8_t *in,uint8_t *out,size_t len){
    uint8_t ctrs[16*64],ks[16*64];
    while(len){
        size_t blocks=(len+15)/16;if(blocks>64)blocks=64;
        for(size_t i=0;i<blocks;i++){memcpy(ctrs+16*i,counter,16);inc128_be(counter);}be->encrypt_blocks(key,ctrs,ks,blocks);
        size_t take=len<blocks*16?len:blocks*16;for(size_t i=0;i<take;i++)out[i]=in[i]^ks[i];in+=take;out+=take;len-=take;
    }
}

static void xor16(uint8_t a[16],const uint8_t b[16]){for(int i=0;i<16;i++)a[i]^=b[i];}
static void shift_right1(uint8_t x[16]){
    uint8_t lsb=(uint8_t)(x[15]&1),carry=0;
    for(int i=0;i<16;i++){uint8_t n=(uint8_t)(x[i]&1);x[i]=(uint8_t)((x[i]>>1)|(carry<<7));carry=n;}
    if(lsb)x[0]^=0xe1;
}

#if defined(__x86_64__) || defined(__i386__)
#if defined(__GNUC__) || defined(__clang__)
#define TARGET_PCLMUL __attribute__((target("pclmul,ssse3,sse2")))
#else
#define TARGET_PCLMUL
#endif
static int pclmul_available(void){
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("pclmul") && __builtin_cpu_supports("ssse3");
#else
    return 0;
#endif
}
TARGET_PCLMUL static void ghash_mul_pclmul(uint8_t x[16], const uint8_t H[16]){
    const __m128i lut = _mm_setr_epi8(0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15);
    const __m128i m = _mm_set1_epi8(0x0f);
    __m128i ax = _mm_loadu_si128((const __m128i *)x);
    __m128i bx = _mm_loadu_si128((const __m128i *)H);
    __m128i ar = _mm_or_si128(_mm_slli_epi16(_mm_shuffle_epi8(lut,_mm_and_si128(ax,m)),4),
                               _mm_shuffle_epi8(lut,_mm_and_si128(_mm_srli_epi16(ax,4),m)));
    __m128i br = _mm_or_si128(_mm_slli_epi16(_mm_shuffle_epi8(lut,_mm_and_si128(bx,m)),4),
                               _mm_shuffle_epi8(lut,_mm_and_si128(_mm_srli_epi16(bx,4),m)));
    __m128i a = ar;
    __m128i b = br;
    __m128i p00 = _mm_clmulepi64_si128(a,b,0x00);
    __m128i p11 = _mm_clmulepi64_si128(a,b,0x11);
    __m128i mid = _mm_xor_si128(_mm_clmulepi64_si128(a,b,0x01),
                                _mm_clmulepi64_si128(a,b,0x10));
    __m128i lo = _mm_xor_si128(p00,_mm_slli_si128(mid,8));
    __m128i hi = _mm_xor_si128(p11,_mm_srli_si128(mid,8));
    uint64_t w[4];
    _mm_storeu_si128((__m128i *)&w[0],lo);
    _mm_storeu_si128((__m128i *)&w[2],hi);
    /* Fold x^128 as x^7+x^2+x+1, then fold the remaining top seven bits. */
    uint64_t q0=w[2], q1=w[3];
    uint64_t f0=q0^(q0<<1)^(q0<<2)^(q0<<7);
    uint64_t f1=q1^((q1<<1)|(q0>>63))^((q1<<2)|(q0>>62))^((q1<<7)|(q0>>57));
    uint64_t ov=(q1>>63)^(q1>>62)^(q1>>57);
    f0^=ov^(ov<<1)^(ov<<2)^(ov<<7);
    w[0]^=f0; w[1]^=f1;
    __m128i r = _mm_loadu_si128((const __m128i *)&w[0]);
    r = _mm_or_si128(_mm_slli_epi16(_mm_shuffle_epi8(lut,_mm_and_si128(r,m)),4),
                     _mm_shuffle_epi8(lut,_mm_and_si128(_mm_srli_epi16(r,4),m)));
    _mm_storeu_si128((__m128i *)x,r);
}
#else
static int pclmul_available(void){return 0;}
#endif

static void ghash_table_init(uint8_t tab[16][16],const uint8_t H[16]){
    memset(tab,0,16*16);uint8_t v[16];memcpy(v,H,16);
    for(int bit=0;bit<4;bit++){
        int mask=8>>bit;
        for(int n=0;n<16;n++)if(n&mask)xor16(tab[n],v);
        shift_right1(v);
    }
}
static void ghash_mul4(uint8_t x[16],uint8_t tab[16][16]){
    uint8_t z[16]={0};
    for(int pos=31;pos>=0;pos--){
        if(pos!=31)for(int j=0;j<4;j++)shift_right1(z);
        uint8_t nib=(pos&1)?(uint8_t)(x[pos/2]&0x0f):(uint8_t)(x[pos/2]>>4);
        xor16(z,tab[nib]);
    }
    memcpy(x,z,16);
}
static void ghash_multiply(uint8_t y[16], const uint8_t H[16], uint8_t tab[16][16], int use_pclmul){
#if defined(__x86_64__) || defined(__i386__)
    if(use_pclmul){ghash_mul_pclmul(y,H);return;}
#else
    (void)H; (void)use_pclmul;
#endif
    ghash_mul4(y,tab);
}
static void ghash_update(uint8_t y[16],const uint8_t H[16],uint8_t tab[16][16],int use_pclmul,const uint8_t *data,size_t len){
    while(len>=16){xor16(y,data);ghash_multiply(y,H,tab,use_pclmul);data+=16;len-=16;}
    if(len){uint8_t last[16]={0};memcpy(last,data,len);xor16(y,last);ghash_multiply(y,H,tab,use_pclmul);}
}
static void store64_be(uint8_t out[8],uint64_t x){for(int i=7;i>=0;i--){out[i]=(uint8_t)x;x>>=8;}}
static void gcm_ctr(const aes_backend_t *be,const aes_key_t *key,uint8_t ctr[16],const uint8_t *in,uint8_t *out,size_t len){
    uint8_t ctrs[16*64],ks[16*64];
    while(len){size_t blocks=(len+15)/16;if(blocks>64)blocks=64;for(size_t i=0;i<blocks;i++){memcpy(ctrs+16*i,ctr,16);inc32_be(ctr);}be->encrypt_blocks(key,ctrs,ks,blocks);size_t take=len<blocks*16?len:blocks*16;for(size_t i=0;i<take;i++)out[i]=in[i]^ks[i];in+=take;out+=take;len-=take;}
}
static void gcm_tag(const aes_backend_t *be,const aes_key_t *key,const uint8_t iv[12],const uint8_t *aad,size_t aad_len,const uint8_t *ct,size_t len,uint8_t tag[16]){
    uint8_t H[16]={0},tab[16][16],y[16]={0},lens[16],J0[16]={0},e0[16];
    be->encrypt_block(key,H,H);ghash_table_init(tab,H);int use_pclmul=pclmul_available();ghash_update(y,H,tab,use_pclmul,aad,aad_len);ghash_update(y,H,tab,use_pclmul,ct,len);
    store64_be(lens,(uint64_t)aad_len*8);store64_be(lens+8,(uint64_t)len*8);xor16(y,lens);ghash_multiply(y,H,tab,use_pclmul);
    memcpy(J0,iv,12);J0[15]=1;be->encrypt_block(key,J0,e0);for(int i=0;i<16;i++)tag[i]=e0[i]^y[i];
}
int aes_gcm_encrypt(const aes_backend_t *be,const aes_key_t *key,const uint8_t iv[12],const uint8_t *aad,size_t aad_len,const uint8_t *pt,uint8_t *ct,size_t len,uint8_t tag[16]){
    if(!be||!key||!iv||(!pt&&len)||(!ct&&len)||!tag)return -1;
    uint8_t ctr[16]={0};
    memcpy(ctr,iv,12);
    ctr[15]=2;
    gcm_ctr(be,key,ctr,pt,ct,len);
    gcm_tag(be,key,iv,aad,aad_len,ct,len,tag);
    return 0;
}
int aes_gcm_decrypt(const aes_backend_t *be,const aes_key_t *key,const uint8_t iv[12],const uint8_t *aad,size_t aad_len,const uint8_t *ct,uint8_t *pt,size_t len,const uint8_t tag[16]){
    if(!be||!key||!iv||(!pt&&len)||(!ct&&len)||!tag)return -1;
    uint8_t expected[16];
    gcm_tag(be,key,iv,aad,aad_len,ct,len,expected);
    uint8_t diff=0;
    for(int i=0;i<16;i++)diff|=(uint8_t)(expected[i]^tag[i]);
    if(diff){
        if(pt&&len)memset(pt,0,len);
        return -2;
    }
    uint8_t ctr[16]={0};
    memcpy(ctr,iv,12);
    ctr[15]=2;
    gcm_ctr(be,key,ctr,ct,pt,len);
    return 0;
}

static void xts_mul_alpha(uint8_t t[16]){
    uint8_t carry=0;
    for(int i=0;i<16;i++){uint8_t next=(uint8_t)(t[i]>>7);t[i]=(uint8_t)((t[i]<<1)|carry);carry=next;}
    if(carry)t[0]^=0x87;
}
static void xts_crypt_block(const aes_backend_t *be,const aes_key_t *key,const uint8_t tweak[16],const uint8_t in[16],uint8_t out[16],int decrypt){
    uint8_t x[16];for(int i=0;i<16;i++)x[i]=in[i]^tweak[i];if(decrypt)be->decrypt_block(key,x,x);else be->encrypt_block(key,x,x);for(int i=0;i<16;i++)out[i]=x[i]^tweak[i];
}
static void xts_crypt_normal(const aes_backend_t *be,const aes_key_t *key,uint8_t tweak[16],const uint8_t *in,uint8_t *out,size_t blocks,int decrypt){
    uint8_t x[16*64],tw[16*64];
    while(blocks){
        size_t n=blocks>64?64:blocks;
        for(size_t b=0;b<n;b++){
            memcpy(tw+16*b,tweak,16);
            for(int j=0;j<16;j++)x[16*b+j]=in[16*b+j]^tweak[j];
            xts_mul_alpha(tweak);
        }
        if(decrypt)be->decrypt_blocks(key,x,x,n);else be->encrypt_blocks(key,x,x,n);
        for(size_t b=0;b<n;b++)for(int j=0;j<16;j++)out[16*b+j]=x[16*b+j]^tw[16*b+j];
        in+=16*n;out+=16*n;blocks-=n;
    }
}
int aes_xts_encrypt(const aes_backend_t *be,const aes_key_t *key1,const aes_key_t *key2,const uint8_t tweak_in[16],const uint8_t *in,uint8_t *out,size_t len){
    if(!be||!key1||!key2||!tweak_in||!in||!out||len<16)return -1;
    uint8_t t[16];be->encrypt_block(key2,tweak_in,t);size_t full=len/16,rem=len%16;
    size_t normal=rem?full-1:full;xts_crypt_normal(be,key1,t,in,out,normal,0);if(!rem)return 0;
    uint8_t cc[16],pp[16],tn[16];xts_crypt_block(be,key1,t,in+16*(full-1),cc,0);memcpy(out+16*full,cc,rem);memcpy(pp,in+16*full,rem);memcpy(pp+rem,cc+rem,16-rem);memcpy(tn,t,16);xts_mul_alpha(tn);xts_crypt_block(be,key1,tn,pp,out+16*(full-1),0);return 0;
}
int aes_xts_decrypt(const aes_backend_t *be,const aes_key_t *key1,const aes_key_t *key2,const uint8_t tweak_in[16],const uint8_t *in,uint8_t *out,size_t len){
    if(!be||!key1||!key2||!tweak_in||!in||!out||len<16)return -1;
    uint8_t t[16];be->encrypt_block(key2,tweak_in,t);size_t full=len/16,rem=len%16;size_t normal=rem?full-1:full;
    xts_crypt_normal(be,key1,t,in,out,normal,1);if(!rem)return 0;
    uint8_t pp[16],cc[16],tn[16];memcpy(tn,t,16);xts_mul_alpha(tn);xts_crypt_block(be,key1,tn,in+16*(full-1),pp,1);memcpy(out+16*full,pp,rem);memcpy(cc,in+16*full,rem);memcpy(cc+rem,pp+rem,16-rem);xts_crypt_block(be,key1,t,cc,out+16*(full-1),1);return 0;
}
