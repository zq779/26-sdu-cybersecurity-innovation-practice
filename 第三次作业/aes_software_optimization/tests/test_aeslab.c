#include "aeslab.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex2bin(const char *hex,uint8_t *out,size_t n){
    if(strlen(hex)!=2*n)return -1;
    for(size_t i=0;i<n;i++){
        unsigned x;
        if(sscanf(hex+2*i,"%2x",&x)!=1)return -1;
        out[i]=(uint8_t)x;
    }
    return 0;
}
static int check(const char *what,const uint8_t *got,const uint8_t *exp,size_t n){
    if(!memcmp(got,exp,n))return 0;
    fprintf(stderr,"FAIL: %s\n got: ",what);
    for(size_t i=0;i<n;i++)fprintf(stderr,"%02x",got[i]);
    fprintf(stderr,"\n exp: ");
    for(size_t i=0;i<n;i++)fprintf(stderr,"%02x",exp[i]);
    fprintf(stderr,"\n");
    return -1;
}
static int test_backend(const aes_backend_t *be){
    uint8_t key128[16],key256[32],pt[16],ct[16],exp[16],back[16];aes_key_t k;
    hex2bin("000102030405060708090a0b0c0d0e0f",key128,16);hex2bin("00112233445566778899aabbccddeeff",pt,16);hex2bin("69c4e0d86a7b0430d8cdb78070b4c55a",exp,16);aes_set_encrypt_key(&k,key128,128);be->encrypt_block(&k,pt,ct);if(check("AES-128 encrypt",ct,exp,16))return -1;be->decrypt_block(&k,ct,back);if(check("AES-128 decrypt",back,pt,16))return -1;
    hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",key256,32);hex2bin("8ea2b7ca516745bfeafc49904b496089",exp,16);aes_set_encrypt_key(&k,key256,256);be->encrypt_block(&k,pt,ct);if(check("AES-256 encrypt",ct,exp,16))return -1;be->decrypt_block(&k,ct,back);if(check("AES-256 decrypt",back,pt,16))return -1;
    return 0;
}
static int test_ctr(const aes_backend_t *be){
    uint8_t key[16],ctr[16],pt[64],ct[64],exp[64],back[64],ctr2[16];aes_key_t k;
    hex2bin("2b7e151628aed2a6abf7158809cf4f3c",key,16);hex2bin("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",ctr,16);
    hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",pt,64);
    hex2bin("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",exp,64);
    aes_set_encrypt_key(&k,key,128);memcpy(ctr2,ctr,16);aes_ctr_crypt(be,&k,ctr2,pt,ct,64);if(check("CTR encrypt",ct,exp,64))return -1;memcpy(ctr2,ctr,16);aes_ctr_crypt(be,&k,ctr2,ct,back,64);return check("CTR decrypt",back,pt,64);
}
static int test_gcm(const aes_backend_t *be){
    uint8_t key[16]={0},iv[12]={0},pt[16]={0},ct[16],tag[16],expct[16],exptag[16],back[16];aes_key_t k;
    hex2bin("0388dace60b6a392f328c2b971b2fe78",expct,16);hex2bin("ab6e47d42cec13bdf53a67b21257bddf",exptag,16);aes_set_encrypt_key(&k,key,128);aes_gcm_encrypt(be,&k,iv,NULL,0,pt,ct,16,tag);if(check("GCM ciphertext",ct,expct,16)||check("GCM tag",tag,exptag,16))return -1;if(aes_gcm_decrypt(be,&k,iv,NULL,0,ct,back,16,tag))return -1;return check("GCM decrypt",back,pt,16);
}
static int test_xts(const aes_backend_t *be){
    uint8_t key[32],tweak[16],pt[37],ct[37],exp[37],back[37];aes_key_t k1,k2;for(int i=0;i<32;i++)key[i]=(uint8_t)i;for(int i=0;i<16;i++)tweak[i]=(uint8_t)i;for(int i=0;i<37;i++)pt[i]=(uint8_t)i;
    hex2bin("b62412371f8d7cf1e27c05af1a83d9b9c681842cc10c39d1de4a89e9ff974605ec410e71eb",exp,37);aes_set_encrypt_key(&k1,key,128);aes_set_encrypt_key(&k2,key+16,128);if(aes_xts_encrypt(be,&k1,&k2,tweak,pt,ct,37))return -1;if(check("XTS CTS encrypt",ct,exp,37))return -1;if(aes_xts_decrypt(be,&k1,&k2,tweak,ct,back,37))return -1;return check("XTS CTS decrypt",back,pt,37);
}
int main(void){
    int failed=0;aes_list_backends();for(int i=0;i<AES_BACKEND_COUNT;i++){const aes_backend_t *be=aes_get_backend((aes_backend_id_t)i);if(!be->available()){printf("[SKIP] %s\n",be->name);continue;}printf("[TEST] %s\n",be->name);if(test_backend(be)||test_ctr(be)||test_gcm(be)||test_xts(be)){failed=1;break;}printf("[ OK ] %s\n",be->name);}return failed?1:0;
}
