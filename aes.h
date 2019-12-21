#ifndef _AES_h_
#define _AES_h_
#include <stdint.h>

struct aes_ctx
{
  unsigned Nk, Nb, Nr;
  uint8_t roundKey[240];
  uint8_t iv[16];
};

void keyExpansion(uint8_t* roundKey, uint8_t* key);
#endif // _AES_h_