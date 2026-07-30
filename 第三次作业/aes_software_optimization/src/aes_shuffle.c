#include "aes_internal.h"

#if defined(__x86_64__) || defined(__i386__)
#include <tmmintrin.h>

#if defined(__GNUC__) || defined(__clang__)
#define TARGET_SSSE3 __attribute__((target("ssse3")))
#else
#define TARGET_SSSE3
#endif

int aes_shuffle_available(void){
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init(); return __builtin_cpu_supports("ssse3");
#else
    return 1;
#endif
}

TARGET_SSSE3 static __m128i lookup_16x16(__m128i x, const uint8_t table[256]){
    const __m128i lo_mask=_mm_set1_epi8(0x0f), hi_mask=_mm_set1_epi8((char)0xf0);
    __m128i lo=_mm_and_si128(x,lo_mask), hi=_mm_and_si128(x,hi_mask), y=_mm_setzero_si128();
    for(int h=0;h<16;h++){
        __m128i row=_mm_loadu_si128((const __m128i*)(table+16*h));
        __m128i val=_mm_shuffle_epi8(row,lo);
        __m128i mask=_mm_cmpeq_epi8(hi,_mm_set1_epi8((char)(h<<4)));
        y=_mm_or_si128(y,_mm_and_si128(val,mask));
    }
    return y;
}
TARGET_SSSE3 static __m128i xtime_vec(__m128i x){
    __m128i carry=_mm_cmpgt_epi8(_mm_setzero_si128(),x);
    return _mm_xor_si128(_mm_add_epi8(x,x),_mm_and_si128(carry,_mm_set1_epi8(0x1b)));
}
TARGET_SSSE3 static __m128i mix_columns_vec(__m128i s){
    const __m128i r1m=_mm_setr_epi8(1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12);
    const __m128i r2m=_mm_setr_epi8(2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13);
    const __m128i r3m=_mm_setr_epi8(3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14);
    __m128i r1=_mm_shuffle_epi8(s,r1m),r2=_mm_shuffle_epi8(s,r2m),r3=_mm_shuffle_epi8(s,r3m);
    return _mm_xor_si128(_mm_xor_si128(xtime_vec(s),_mm_xor_si128(xtime_vec(r1),r1)),_mm_xor_si128(r2,r3));
}
TARGET_SSSE3 static void inv_mix_scalar(uint8_t s[16]){
    for(int c=0;c<4;c++){
        uint8_t *a=s+4*c,a0=a[0],a1=a[1],a2=a[2],a3=a[3];
        a[0]=(uint8_t)(aes_gfmul(a0,14)^aes_gfmul(a1,11)^aes_gfmul(a2,13)^aes_gfmul(a3,9));
        a[1]=(uint8_t)(aes_gfmul(a0,9)^aes_gfmul(a1,14)^aes_gfmul(a2,11)^aes_gfmul(a3,13));
        a[2]=(uint8_t)(aes_gfmul(a0,13)^aes_gfmul(a1,9)^aes_gfmul(a2,14)^aes_gfmul(a3,11));
        a[3]=(uint8_t)(aes_gfmul(a0,11)^aes_gfmul(a1,13)^aes_gfmul(a2,9)^aes_gfmul(a3,14));
    }
}
TARGET_SSSE3 void aes_shuffle_encrypt_block(const aes_key_t *k,const uint8_t in[16],uint8_t out[16]){
    const __m128i sr=_mm_setr_epi8(0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11);
    __m128i s=_mm_xor_si128(_mm_loadu_si128((const __m128i*)in),_mm_loadu_si128((const __m128i*)k->round_keys));
    for(int r=1;r<k->rounds;r++){
        s=lookup_16x16(s,aes_sbox); s=_mm_shuffle_epi8(s,sr); s=mix_columns_vec(s);
        s=_mm_xor_si128(s,_mm_loadu_si128((const __m128i*)(k->round_keys+16*r)));
    }
    s=lookup_16x16(s,aes_sbox);s=_mm_shuffle_epi8(s,sr);
    s=_mm_xor_si128(s,_mm_loadu_si128((const __m128i*)(k->round_keys+16*k->rounds)));
    _mm_storeu_si128((__m128i*)out,s);
}
TARGET_SSSE3 void aes_shuffle_decrypt_block(const aes_key_t *k,const uint8_t in[16],uint8_t out[16]){
    const __m128i isr=_mm_setr_epi8(0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3);
    __m128i s=_mm_xor_si128(_mm_loadu_si128((const __m128i*)in),_mm_loadu_si128((const __m128i*)(k->round_keys+16*k->rounds)));
    uint8_t tmp[16];
    for(int r=k->rounds-1;r>0;r--){
        s=_mm_shuffle_epi8(s,isr);s=lookup_16x16(s,aes_inv_sbox);
        s=_mm_xor_si128(s,_mm_loadu_si128((const __m128i*)(k->round_keys+16*r)));
        _mm_storeu_si128((__m128i*)tmp,s);inv_mix_scalar(tmp);s=_mm_loadu_si128((const __m128i*)tmp);
    }
    s=_mm_shuffle_epi8(s,isr);s=lookup_16x16(s,aes_inv_sbox);
    s=_mm_xor_si128(s,_mm_loadu_si128((const __m128i*)k->round_keys));_mm_storeu_si128((__m128i*)out,s);
}
#else
int aes_shuffle_available(void){return 0;}
void aes_shuffle_encrypt_block(const aes_key_t*k,const uint8_t i[16],uint8_t o[16]){aes_baseline_encrypt_block(k,i,o);} 
void aes_shuffle_decrypt_block(const aes_key_t*k,const uint8_t i[16],uint8_t o[16]){aes_baseline_decrypt_block(k,i,o);} 
#endif
