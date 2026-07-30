#include "aes_internal.h"

static void add_round_key(uint8_t s[16], const uint8_t *rk) {
    for (int i=0;i<16;i++) s[i] ^= rk[i];
}
static void sub_bytes(uint8_t s[16]) { for(int i=0;i<16;i++) s[i]=aes_sbox[s[i]]; }
static void inv_sub_bytes(uint8_t s[16]) { for(int i=0;i<16;i++) s[i]=aes_inv_sbox[s[i]]; }
static void shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    for(int r=0;r<4;r++) for(int c=0;c<4;c++) t[4*c+r]=s[4*((c+r)&3)+r];
    memcpy(s,t,16);
}
static void inv_shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    for(int r=0;r<4;r++) for(int c=0;c<4;c++) t[4*c+r]=s[4*((c-r)&3)+r];
    memcpy(s,t,16);
}
static void mix_columns(uint8_t s[16]) {
    for(int c=0;c<4;c++) {
        uint8_t *a=s+4*c, a0=a[0],a1=a[1],a2=a[2],a3=a[3];
        a[0]=(uint8_t)(aes_xtime(a0)^aes_xtime(a1)^a1^a2^a3);
        a[1]=(uint8_t)(a0^aes_xtime(a1)^aes_xtime(a2)^a2^a3);
        a[2]=(uint8_t)(a0^a1^aes_xtime(a2)^aes_xtime(a3)^a3);
        a[3]=(uint8_t)(aes_xtime(a0)^a0^a1^a2^aes_xtime(a3));
    }
}
static void inv_mix_columns(uint8_t s[16]) {
    for(int c=0;c<4;c++) {
        uint8_t *a=s+4*c, a0=a[0],a1=a[1],a2=a[2],a3=a[3];
        a[0]=(uint8_t)(aes_gfmul(a0,14)^aes_gfmul(a1,11)^aes_gfmul(a2,13)^aes_gfmul(a3,9));
        a[1]=(uint8_t)(aes_gfmul(a0,9)^aes_gfmul(a1,14)^aes_gfmul(a2,11)^aes_gfmul(a3,13));
        a[2]=(uint8_t)(aes_gfmul(a0,13)^aes_gfmul(a1,9)^aes_gfmul(a2,14)^aes_gfmul(a3,11));
        a[3]=(uint8_t)(aes_gfmul(a0,11)^aes_gfmul(a1,13)^aes_gfmul(a2,9)^aes_gfmul(a3,14));
    }
}
void aes_baseline_encrypt_block(const aes_key_t *k,const uint8_t in[16],uint8_t out[16]) {
    uint8_t s[16]; memcpy(s,in,16); add_round_key(s,k->round_keys);
    for(int r=1;r<k->rounds;r++){sub_bytes(s);shift_rows(s);mix_columns(s);add_round_key(s,k->round_keys+16*r);} 
    sub_bytes(s);shift_rows(s);add_round_key(s,k->round_keys+16*k->rounds);memcpy(out,s,16);
}
void aes_baseline_decrypt_block(const aes_key_t *k,const uint8_t in[16],uint8_t out[16]) {
    uint8_t s[16]; memcpy(s,in,16); add_round_key(s,k->round_keys+16*k->rounds);
    for(int r=k->rounds-1;r>0;r--){inv_shift_rows(s);inv_sub_bytes(s);add_round_key(s,k->round_keys+16*r);inv_mix_columns(s);} 
    inv_shift_rows(s);inv_sub_bytes(s);add_round_key(s,k->round_keys);memcpy(out,s,16);
}
