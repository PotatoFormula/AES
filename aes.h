#ifndef _AES_h_
#define _AES_h_
#include <stdint.h>
#include <stdio.h>

typedef enum {ECB, CBC, CTR, OFB, CFB} MODE;
typedef enum {enc, dec} WORK;

struct aes_ctx
{
  unsigned Nk, Nb, Nr, ver;
  MODE mode;
  WORK work;
  uint8_t roundKey[240];
  uint8_t iv[16];
  FILE * infile;
  FILE * outfile;
  void (*AES_crypt)(struct aes_ctx *, uint8_t *, uint32_t);
};

void ctx_init(struct aes_ctx* ctx, const uint8_t* key);
void ctx_init_iv(struct aes_ctx* ctx, const uint8_t* key, const uint8_t* iv);

void AES_ECB_encrypt_buffer(struct aes_ctx* ctx, uint8_t* buf, uint32_t buf_len);
void AES_ECB_decrypt_buffer(struct aes_ctx* ctx, uint8_t* buf, uint32_t buf_len);

void AES_CBC_encrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len);
void AES_CBC_decrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len);

void AES_CTR_xcrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len);

void AES_OFB_xcrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len);

void AES_CFB_encrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len);
void AES_CFB_decrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len);

void AES_CFB8_encrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len);
void AES_CFB8_decrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len);
#endif // _AES_h_