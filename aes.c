/*************/
/* Includes: */
/*************/
#include <stdio.h>  // printf for debug
#include <stdint.h> // uint8_t
#include <string.h> // memtest
#include "aes.h"

/**********************/
/* Private variables: */
/**********************/
//State lengh, in AES is 16
#define AES_BLOCKLEN 16
typedef uint8_t state_t[4][4];

static const uint8_t sbox[256] = {
  //0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  //0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

static const uint8_t Rcon[15] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d };

/**********************/
/* Private Functions: */
/**********************/

#define getsbox(num) (sbox[num])
#define getrsbox(num) (rsbox[num])
#define rotword(word) uint8_t __tmp = word[0];\
                              word[0] = word[1];\
                              word[1] = word[2];\
                              word[2] = word[3];\
                              word[3] = __tmp

static void keyExpansion(struct aes_ctx* ctx, const uint8_t* key)
{
  unsigned i, j, k;
  uint8_t preRoundKey[4];
  unsigned Nb = ctx->Nb, Nk = ctx->Nk, Nr = ctx->Nr;
  uint8_t *roundKey = ctx->roundKey;

  //first round key is key itself
  memcpy(roundKey, key, Nk * 4);
  
  for(i = Nk; i < Nb * (Nr + 1); ++i)
  {
    memcpy(preRoundKey, roundKey + (i - 1) * 4, 4);
    
    if (i % Nk == 0)
    {
      rotword(preRoundKey);
      
      for(int index = 0; index < 4; ++index)
        preRoundKey[index] = getsbox(preRoundKey[index]);
      
      preRoundKey[0] = preRoundKey[0] ^ Rcon[i/Nk];
    }

    if ((ctx->ver == 256) && (i % Nk == 4))
    {
      for(int index = 0; index < 4; ++index)
        preRoundKey[index] = getsbox(preRoundKey[index]);
    }

    j = i * 4; k = (i- Nk) * 4;
    for(int index = 0; index < 4; ++index)
      roundKey[j + index] = roundKey[k + index] ^ preRoundKey[index];
  }

  // for(int index = 0; index < 240; ++index)
  //   printf("%x ", roundKey[index]);
  // printf("\n");
}

static void addRoundKey(uint8_t round, state_t* state, const uint8_t* roundKey)
{
  unsigned i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= roundKey[(round * AES_BLOCKLEN) + (i * 4) + j];
    }
  }
}

static void subByte(state_t* state)
{
  unsigned i, j;
  for(i = 0; i < 4; ++i)
    for(j = 0; j < 4; ++j)
      (*state)[i][j] = getsbox((*state)[i][j]);
}

static void shiftRow(state_t* state)
{
  uint8_t u8tmp;

  // Rotate first row 1 columns to left
  u8tmp          = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = u8tmp;

  // Rotate second row 2 columns to left
  u8tmp          = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = u8tmp;

  u8tmp          = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = u8tmp;

  // Rotate third row 3 columns to left
  u8tmp          = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = u8tmp;
}

static uint8_t xtime(uint8_t x)
{
  return (x<<1) ^ (((x>>7) & 1) * 0x1b);
}
// TODO: mixColumn()
static void mixColumn(state_t* state)
{
  uint8_t i;
  uint8_t tmp, tm, t;

  for(i = 0; i < 4; ++i)
  {
    t   = (*state)[i][0];
    tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
    tm  = (*state)[i][0] ^ (*state)[i][1]; tm = xtime(tm); (*state)[i][0] ^= tm ^ tmp;
    tm  = (*state)[i][1] ^ (*state)[i][2]; tm = xtime(tm); (*state)[i][1] ^= tm ^ tmp;
    tm  = (*state)[i][2] ^ (*state)[i][3]; tm = xtime(tm); (*state)[i][2] ^= tm ^ tmp;
    tm  = (*state)[i][3] ^ t;              tm = xtime(tm); (*state)[i][3] ^= tm ^ tmp;
  }
}

#define multiply(x, y)                         \
(                                              \
     ((y & 1) * x) ^                           \
  ((y>>1 & 1) * xtime(x)) ^                    \
  ((y>>2 & 1) * xtime(xtime(x))) ^             \
  ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^      \
  ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))) \
)

static void invMixColumn(state_t* state)
{
  unsigned i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  {
    a = (*state)[i][0]; b = (*state)[i][1]; c = (*state)[i][2]; d = (*state)[i][3];
    (*state)[i][0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
    (*state)[i][1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
    (*state)[i][2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
    (*state)[i][3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
  }
}

static void invSubByte(state_t* state)
{
  unsigned i, j;
  for (i = 0; i < 4; ++i)
    for(j = 0; j < 4; ++j)
      (*state)[i][j] = getrsbox((*state)[i][j]);
}

static void invShiftRow(state_t* state)
{
  uint8_t u8tmp;
  
  // Rotate first row 1 columns to right
  u8tmp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = u8tmp;

  // Rotate second row 2 columns to right
  u8tmp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = u8tmp;

  u8tmp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = u8tmp;

  // Rotate third row 3 columns to right
  u8tmp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = u8tmp;
}

static void cipher(state_t* state, const struct aes_ctx* ctx)
{
  unsigned Nr = ctx->Nr, round = 0;
  
  addRoundKey(round, state, ctx->roundKey);
  for(round = 1; round < Nr; ++round)
  {
    subByte(state);
    shiftRow(state);
    mixColumn(state);
    addRoundKey(round, state, ctx->roundKey);
  }
  subByte(state);
  shiftRow(state);
  addRoundKey(Nr, state, ctx->roundKey);
}

static void invCipher(state_t* state, const struct aes_ctx* ctx)
{
  unsigned Nr = ctx->Nr, round;

  addRoundKey(Nr, state, ctx->roundKey);
  for(round = (Nr - 1); round > 0; --round)
  {
    invShiftRow(state);
    invSubByte(state);
    addRoundKey(round, state, ctx->roundKey);
    invMixColumn(state);
  }
  invShiftRow(state);
  invSubByte(state);
  addRoundKey(0, state, ctx->roundKey);
}

static void xorWithIv(uint8_t* buf, const uint8_t* iv)
{
  unsigned i;
  for (i = 0; i < AES_BLOCKLEN; ++i)
    buf[i] = buf[i] ^ iv[i];
}

static void xorWithIv8(uint8_t* buf, const uint8_t *iv)
{
  buf[0] = buf[0] ^ iv[0];
}

static void xorWithIv1(uint8_t *buf, const uint8_t *iv, int bits)
{
  uint8_t leftmostiv = iv[0] & 0x80;
  leftmostiv = leftmostiv >> bits;
  *buf ^= leftmostiv;
}

static void shiftIv8(uint8_t* iv)
{
  for(int i = 0; i < 15; ++i)
  {
    iv[i] = iv[i+1];
  }
  iv[15] = 0;
}

static void shiftIv1(uint8_t *iv)
{
  uint8_t leftmostbit[AES_BLOCKLEN];
  memcpy(leftmostbit, iv, AES_BLOCKLEN);
  for(int i = 0; i < AES_BLOCKLEN; ++i)
  {
    leftmostbit[i] = leftmostbit[i] >> 7;
  }

  for(int i = 0; i < AES_BLOCKLEN; ++i)
  {
    iv[i] = iv[i] << 1;
  }

  for(int i = 0; i < (AES_BLOCKLEN - 1); ++i)
  {
    iv[i] = iv[i] + leftmostbit[i+1];
  }
}

static void rotIv8(uint8_t *iv)
{
  uint8_t u8tmp;
  u8tmp = iv[0];
  shiftIv8(iv);
  iv[15] = u8tmp;
}

static void rotIv1(uint8_t *iv)
{
  uint8_t leftmostbit;
  leftmostbit = (iv[0] >> 7);
  shiftIv1(iv);
  iv[15] += leftmostbit;
}

/*********************/
/* Public Functions: */
/*********************/

void ctx_init(struct aes_ctx* ctx, const uint8_t* key)
{
  ctx->Nb = 4;
  switch (ctx->ver)
  {
    case 128 :
      ctx->Nk = 4;
      ctx->Nr = 10;
      break;
    case 192 :
      ctx->Nk = 6;
      ctx->Nr = 12;
      break;
    case 256 :
      ctx->Nk = 8;
      ctx->Nr = 14;
      break;
    default :
      printf("Error in aes.c: ctx_init(), can't pharse aes_version. Please check you pass 128, 192 or 256 to this function\n");
      return;
  }
  keyExpansion(ctx, key);
}

void ctx_init_iv(struct aes_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  ctx->Nb = 4;
  switch (ctx->ver)
  {
    case 128 :
      ctx->Nk = 4;
      ctx->Nr = 10;
      break;
    case 192 :
      ctx->Nk = 6;
      ctx->Nr = 12;
      break;
    case 256 :
      ctx->Nk = 8;
      ctx->Nr = 14;
      break;
    default :
      printf("Error in aes.c: ctx_init_iv(), can't pharse aes_version.\nPlease check you pass 128, 192 or 256 to this function\n");
      return;
  }
  keyExpansion(ctx, key);
  memcpy(ctx->iv, iv, AES_BLOCKLEN);
}

void AES_ECB_encrypt_buffer(struct aes_ctx* ctx, uint8_t* buf, uint32_t buf_len)
{
  for (int i = 0; i < buf_len; i += AES_BLOCKLEN)
  {
    cipher((state_t*)buf, ctx);
    buf += AES_BLOCKLEN;
  }
}

void AES_ECB_decrypt_buffer(struct aes_ctx* ctx, uint8_t* buf, uint32_t buf_len)
{
  for (int i = 0; i < buf_len; i += AES_BLOCKLEN)
  {
    invCipher((state_t*)buf, ctx);
    buf += AES_BLOCKLEN;
  }
}

void AES_CBC_encrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len)
{
  uint32_t i;
  uint8_t *iv = ctx->iv;

  for (i = 0; i < buf_len; i += AES_BLOCKLEN)
  {
    xorWithIv(buf, iv);
    cipher((state_t*)buf, ctx);
    iv = buf;
    buf += AES_BLOCKLEN;
  }

  //Store iv in aes_ctx
  memcpy(ctx->iv, iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len)
{
  uint32_t i;
  uint8_t storedIv[AES_BLOCKLEN];

  for (i = 0; i < buf_len; i += AES_BLOCKLEN)
  {
    memcpy(storedIv, buf, AES_BLOCKLEN);
    invCipher((state_t*)buf, ctx);
    xorWithIv(buf, ctx->iv);
    memcpy(ctx->iv, storedIv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }
}

//Symmetric cipher, encrypt and decrypt use same function
void AES_CTR_xcrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len)
{
  uint8_t counter[AES_BLOCKLEN];

  uint32_t i;
  uint8_t ctri;

  for (i = 0, ctri = AES_BLOCKLEN; i < buf_len; ++i, ++ctri)
  {
    //need regen counter
    if (ctri == AES_BLOCKLEN)
    {
      memcpy(counter, ctx->iv, AES_BLOCKLEN);
      cipher((state_t*)counter, ctx);

      //Increase iv
      for(ctri = (AES_BLOCKLEN - 1); ctri >= 0; --ctri)
      {
        if(ctx->iv[ctri] == 255)
        {
          ctx->iv[ctri] = 0;
          continue;
        }

        ctx->iv[ctri] += 1;
        break;
      }
      ctri = 0;
    }
    buf[i] = (buf[i] ^ counter[ctri]);
  }
}

//Symmetric cipher encrypt and decrypt use same function
void AES_OFB_xcrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len)
{
  uint8_t *iv = ctx->iv;
  uint32_t i;

  for(i = 0; i < buf_len; i += AES_BLOCKLEN)
  {
    cipher((state_t*)iv, ctx);
    xorWithIv(buf, iv);
    buf += AES_BLOCKLEN;
  }
}

void AES_OFB8_xcrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len)
{
  uint8_t *iv = ctx->iv;
  uint32_t i;

  for(i = 0; i < buf_len; ++i)
  {
    cipher((state_t*)iv, ctx);
    xorWithIv8(buf, iv);
    buf += 1;
    rotIv8(iv);
  }
}

void AES_OFB1_xcrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len)
{
  uint8_t *iv = ctx->iv;
  uint32_t i;

  //byte level operation
  for(i = 0; i < buf_len; ++i)
  {
    //bit level operation
    for(uint8_t bits = 0; bits < 8; ++bits)
    {
      cipher((state_t*)iv, ctx);
      xorWithIv1(buf, iv, bits);
      rotIv1(iv);
    }
    buf += 1;
  }
}

void AES_CFB_encrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len)
{
  uint8_t *iv = ctx->iv;
  uint32_t i;

  for (i = 0; i < buf_len; i += AES_BLOCKLEN)
  {
    cipher((state_t*)iv, ctx);
    xorWithIv(buf, iv);
    memcpy(iv, buf, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }
}

void AES_CFB_decrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len)
{
  uint8_t *iv = ctx->iv;
  uint8_t stored_next_iv[AES_BLOCKLEN];
  uint32_t i;

  for (i = 0; i < buf_len; i += AES_BLOCKLEN)
  {
    memcpy(stored_next_iv, buf, AES_BLOCKLEN);
    cipher((state_t*)iv, ctx);
    xorWithIv(buf, iv);
    buf += AES_BLOCKLEN;
    memcpy(iv, stored_next_iv, AES_BLOCKLEN);
  }
}

void AES_CFB8_encrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len)
{
  uint8_t *iv = ctx->iv;
  uint32_t i;

  for (i = 0; i < buf_len; i += 1)
  {
    cipher((state_t*)iv, ctx);
    xorWithIv8(buf, iv);
    shiftIv8(iv);
    memcpy(iv + 15, buf, 1);
    buf += 1;
  }
}

void AES_CFB8_decrypt_buffer(struct aes_ctx *ctx, uint8_t *buf, uint32_t buf_len)
{
  uint8_t *iv = ctx->iv;
  uint8_t stored_next_iv[1];
  uint32_t i;

  for (i = 0; i < buf_len; i += 1)
  {
    memcpy(stored_next_iv, buf, 1);
    cipher((state_t*)iv, ctx);
    xorWithIv8(buf, iv);
    shiftIv8(iv);
    buf += 1;
    memcpy(iv + 15, stored_next_iv, 1);
  }
}