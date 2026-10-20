// Synthetic public real-WASM fixture; not a real root/Account unlock.
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
static int check(const char*name,const char*expected){
 const char pass[]="synthetic-only-master",salt[]="AwMDAwMDAwMDAwMDAwMDAw==";
 uint32_t lanes=1,threads=1,iter=3,memcost=65536,version=0x13;
 OSSL_PARAM params[]={OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,(void*)pass,strlen(pass)),OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,(void*)salt,strlen(salt)),OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS,&threads),OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES,&lanes),OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER,&iter),OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST,&memcost),OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION,&version),OSSL_PARAM_END};
 EVP_KDF*kdf=EVP_KDF_fetch(NULL,name,NULL);if(!kdf){printf("FAIL %s provider unavailable\n",name);return 0;}EVP_KDF_CTX*ctx=EVP_KDF_CTX_new(kdf);unsigned char out[32];char hex[65];int ok=ctx&&EVP_KDF_derive(ctx,out,sizeof(out),params)>0;
 if(ok){for(int i=0;i<32;i++)sprintf(hex+i*2,"%02x",out[i]);ok=strcmp(hex,expected)==0;}
 OPENSSL_cleanse(out,sizeof(out));OPENSSL_cleanse(hex,sizeof(hex));EVP_KDF_CTX_free(ctx);EVP_KDF_free(kdf);printf("%s %s matches exact real-WASM public master fixture; textual UTF8 base64 salt\n",ok?"PASS":"FAIL",name);return ok;
}
int main(void){return !(check("ARGON2D","5564f7006653f1592f41f5cc70074135d716c2f4967be0f18ee869412ebfbe34")&&check("ARGON2ID","b890ec8c8f2b3217ced9eb117fa46330b80d0795d1ee6e44bf3d10320283cb45"));}
