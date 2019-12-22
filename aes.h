#ifndef _AES_h_
#define _AES_h_
#include <stdint.h>

struct aes_ctx
{
  unsigned Nk, Nb, Nr, ver;
  uint8_t roundKey[240];
  uint8_t iv[16];
};

void ctx_init(struct aes_ctx* ctx, const uint8_t* key, unsigned aes_version);
void ctx_init_iv(struct aes_ctx* ctx, const uint8_t* key, const uint8_t* iv, unsigned aes_version);

void AES_ECB_encrypt(const struct aes_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct aes_ctx* ctx, uint8_t* buf);

#endif // _AES_h_