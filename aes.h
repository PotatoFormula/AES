#ifndef _AES_h_
#define _AES_h_
#include <stdint.h>

struct aes_ctx
{
  unsigned Nk, Nb, Nr, ver;
  uint8_t roundKey[240];
  uint8_t iv[16];
};

#endif // _AES_h_