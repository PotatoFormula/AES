#include <stdio.h>
#include <string.h> //memtest
#include <getopt.h> //subcommand parser
#include "aes.h"

//TODO: Padding


static int test_xcrypt_ctr(const char* xcrypt);
static int test_encrypt_ctr(void)
{
  return test_xcrypt_ctr("encrypt");
}

static int test_decrypt_ctr(void)
{
  return test_xcrypt_ctr("decrypt");
}

static int test_xcrypt_ctr(const char* xcrypt)
{

  uint8_t key[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
  uint8_t in[64]  = { 0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28, 
                      0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5, 
                      0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d, 
                      0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };

  uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
  uint8_t out[64] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
  struct aes_ctx ctx;
  ctx.ver = 256;
  ctx_init_iv(&ctx, key, iv);
  AES_CTR_xcrypt_buffer(&ctx, in, 64);
  
  printf("CTR %s: ", xcrypt);
  
  if (0 == memcmp((char *) out, (char *) in, 64)) {
    printf("SUCCESS!\n");
    return(0);
  } else {
    printf("FAILURE!\n");
    return(1);
  }
}

static int test_encrypt_cbc(void)
{
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t out[] = { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
                      0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
                      0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
                      0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b };

    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    struct aes_ctx ctx;
    ctx.ver = 256;
    ctx_init_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 64);

    printf("CBC encrypt: ");

    if (0 == memcmp((char*) out, (char*) in, 64)) {
        printf("SUCCESS!\n");
	return(0);
    } else {
        printf("FAILURE!\n");
	return(1);
    }
}

static int test_decrypt_cbc(void)
{

    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t in[]  = { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
                      0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
                      0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
                      0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b };

    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
//  uint8_t buffer[64];
    struct aes_ctx ctx;
    ctx.ver = 256;
    ctx_init_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, in, 64);

    printf("CBC decrypt: ");

    if (0 == memcmp((char*) out, (char*) in, 64)) {
        printf("SUCCESS!\n");
	return(0);
    } else {
        printf("FAILURE!\n");
	return(1);
    }
}

static int test_encrypt_ecb(void)
{
  uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
  uint8_t out[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };

  uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
  struct aes_ctx ctx;
  ctx.ver = 256;
  ctx_init(&ctx, key);
  AES_ECB_encrypt_buffer(&ctx, in, 16);
  printf("ECB encrypt: ");
  if (0 == memcmp((char*) out, (char*) in, 16)) {
    printf("SUCCESS!\n");
	  return(0);
  } else {
    printf("FAILURE!\n");
	  return(1);
  }
}

static int test_decrypt_ecb(void)
{

    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t in[]  = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };


    uint8_t out[]   = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    struct aes_ctx ctx;
    ctx.ver = 256;
    ctx_init(&ctx, key);
    AES_ECB_decrypt_buffer(&ctx, in, 16);

    printf("ECB decrypt: ");

    if (0 == memcmp((char*) out, (char*) in, 16)) {
        printf("SUCCESS!\n");
	return(0);
    } else {
        printf("FAILURE!\n");
	return(1);
    }
}

void test_all()
{
  test_encrypt_cbc();
  test_decrypt_cbc();
  test_encrypt_ctr();
  test_decrypt_ctr();
  test_encrypt_ecb();
  test_decrypt_ecb();
}

int set_ctx(int argc, char *argv[], struct aes_ctx *ctx)
{

  struct option long_options[] = {

    {"enc", no_argument, NULL, 'e'},
    {"dec", no_argument, NULL, 'd'},
    {"128", no_argument, NULL, '1'}, 
    {"192", no_argument, NULL, '2'}, 
    {"256", no_argument, NULL, '3'},
    {"ECB", no_argument, NULL, 'C'},
    {"CBC", no_argument, NULL, 'B'},
    {"CTR", no_argument, NULL, 'T'},
    {"OFB", no_argument, NULL, 'O'},
    {"OFB8", no_argument, NULL, '6'},
    {"OFB1", no_argument, NULL, '7'},
    {"CFB", no_argument, NULL, 'F'},
    {"CFB8", no_argument, NULL, '8'},
    {"CFB1", no_argument, NULL, '9'},
    {"iv", required_argument, NULL, 'i'},
    {"kfile", required_argument, NULL, 'f'},
    {"K", required_argument, NULL, 'K'},
    {"in", required_argument, NULL, 'n'},
    {"out", required_argument, NULL, 'o'},


    {0, 0, 0, 0}

  };


  char c;
  int size;
  uint8_t key[32] = {0};
  FILE * kfile = NULL;
  //init iv to zero
  for(int i = 0; i < 16; ++i)
  {
    ctx->iv[i] = 0;
  }
  
  while( (c = getopt_long (argc, argv, "ed123456789i:f:K:n:o:", long_options, NULL)) != -1)
  {
    switch (c)
    {
      case 'e':
        ctx->work = enc;
        break; 
      case 'd':
        ctx->work = dec;
        break; 
      case '1':
        ctx->ver = 128;
        break; 
      case '2':
        ctx->ver = 192;
        break; 
      case '3':
        ctx->ver = 256;
        break;
      case 'C':
        ctx->mode = ECB;
        break;
      case 'B':
        ctx->mode = CBC;
        break;
      case 'T':
        ctx->mode = CTR;
        break;
      case 'O':
        ctx->mode = OFB;
        break;
      case 'F':
        ctx->mode = CFB;
        break;
      case '6':
        ctx->mode = OFB8;
        break;
      case '7':
        ctx->mode = OFB1;
        break;
      case '8':
        ctx->mode = CFB8;
        break;
      case '9':
        ctx->mode = CFB1;
        break;
      case 'i':
        memcpy(ctx->iv, optarg, 16);
        break;
      case 'f':
        size = strlen(optarg);
        if (size > 255) 
        {
          printf("kfile name too long\n");
          return -1;
        }        
        kfile = fopen(optarg, "rb+");
        if (kfile == NULL)
        {
          printf("Can't open kfile: %s\n", optarg);
          return -1;
        }
        break;
      case 'K':
        size = strlen(optarg);
        if (size > 32)
        {
          printf("This key is too long, only take first 32bytes\n");
          memcpy(key, optarg, 32);
        } else {
          memcpy(key, optarg, size);
        }
        break;
      case 'n':
        size = strlen(optarg);
        if (size > 255)
        {
          printf("in file name too long\n");
          return -1;
        }
        else if ((ctx->infile = fopen(optarg, "rb+")) == NULL)
        {
          printf("Can't open infile: %s\n", optarg);
        }
        break;
      case 'o':
        size = strlen(optarg);
        if (size > 255)
        {
          printf("out file name too long\n");
          return -1;
        }
        else if ((ctx->outfile = fopen(optarg, "wb")) == NULL)
        {
          printf("Can't open outfile: %s\n", optarg);
        }
        break;
    }
  }

  //read key from kfile
  if (kfile != NULL)
  {
    switch (ctx->ver)
    {
    case 128:
      if (fread(key, 1, 16, kfile) < 16)
        printf("The key in the kfile file is too short, remaining key will be 0\n");
      break;

    case 192:
      if (fread(key, 1, 24, kfile) < 24)
        printf("The key in the kfile file is too short, remaining key will be 0\n");
      break;

    case 256:
      if (fread(key, 1, 32, kfile) < 32)
        printf("The key in the kfile file is too short, remaining key will be 0\n");
      break;

    default:
      printf("Unknow Error in get_ctx:kfile to key\n");
      break;
    }
    fclose(kfile);
  }

  switch (ctx->work)
  {
  case enc:
    switch (ctx->mode)
    {
    case ECB: ctx->AES_crypt = AES_ECB_encrypt_buffer; break;
    case CBC: ctx->AES_crypt = AES_CBC_encrypt_buffer; break;
    case CTR: ctx->AES_crypt = AES_CTR_xcrypt_buffer; break;
    case OFB: ctx->AES_crypt = AES_OFB_xcrypt_buffer; break;
    case OFB8: ctx->AES_crypt = AES_OFB8_xcrypt_buffer; break;
    case OFB1: ctx->AES_crypt = AES_OFB1_xcrypt_buffer; break;
    case CFB: ctx->AES_crypt = AES_CFB_encrypt_buffer; break;
    case CFB8: ctx->AES_crypt = AES_CFB8_encrypt_buffer; break;
    case CFB1: ctx->AES_crypt = AES_CFB1_encrypt_buffer; break;
    }
    break;
  case dec:
    switch (ctx->mode)
    {
    case ECB: ctx->AES_crypt = AES_ECB_decrypt_buffer; break;
    case CBC: ctx->AES_crypt = AES_CBC_decrypt_buffer; break;
    case CTR: ctx->AES_crypt = AES_CTR_xcrypt_buffer; break;
    case OFB: ctx->AES_crypt = AES_OFB_xcrypt_buffer; break;
    case OFB8: ctx->AES_crypt = AES_OFB8_xcrypt_buffer; break;
    case OFB1: ctx->AES_crypt = AES_OFB1_xcrypt_buffer; break;
    case CFB: ctx->AES_crypt = AES_CFB_decrypt_buffer; break;
    case CFB8: ctx->AES_crypt = AES_CFB8_decrypt_buffer; break;
    case CFB1: ctx->AES_crypt = AES_CFB1_decrypt_buffer; break;
    }
    break;
  default:
    printf("--enc or --dec is requied\n");
    break;
  }

  ctx_init(ctx, key);
  return 0;
}

void encrypt_file(struct aes_ctx *ctx)
{
  unsigned buf_len = 4096;
  unsigned padding_len;
  uint8_t buffer[buf_len];
  size_t size;

  // switch (ctx->mode)
  // {
  //   case ECB: ctx->AES_crypt = AES_ECB_encrypt_buffer; break;
  //   case CBC: ctx->AES_crypt = AES_CBC_encrypt_buffer; break;
  //   case CTR: ctx->AES_crypt = AES_CTR_xcrypt_buffer; break;
  // }

  while (!feof(ctx->infile))
  {
    size = fread(buffer, 1, buf_len, ctx->infile);

    //Padding if reach end of file
    if (size < buf_len)
    {
      padding_len = 16 - (size % 16);

      for (int i = 0; i < padding_len; ++i)
      {
        buffer[size] = padding_len;
        ++size;
      }
    }

    ctx->AES_crypt(ctx, buffer, size);
    //write to file
    fwrite(buffer, 1, size, ctx->outfile);
  }
}

void decrypt_file(struct aes_ctx *ctx)
{
  unsigned buf_len = 4096;
  unsigned padding_len;
  uint8_t buffer[buf_len];
  size_t size;
  void (*cipher) (struct aes_ctx *, uint8_t *, uint32_t);

  // switch (ctx->mode)
  // {
  //   case ECB: ctx->AES_crypt = AES_ECB_decrypt_buffer; break;
  //   case CBC: ctx->AES_crypt = AES_CBC_decrypt_buffer; break;
  //   case CTR: ctx->AES_crypt = AES_CTR_xcrypt_buffer; break;
  // }

  while (!feof(ctx->infile))
  {
    size = fread(buffer, 1, buf_len, ctx->infile);
    
    ctx->AES_crypt(ctx, buffer, size);

    //Depadding if reach end of file
    if (size < buf_len)
    {
      padding_len = buffer[size - 1];
      
      //debug print
      printf("depadding: %d\n", padding_len);

      size -= padding_len;
    }

    //write to file
    fwrite(buffer, 1, size, ctx->outfile);
  }
}

int main(int argc, char *argv[])
{
  struct aes_ctx ctx;
  set_ctx(argc, argv, &ctx);
  if (ctx.work == enc) encrypt_file(&ctx);
  else if(ctx.work == dec) decrypt_file(&ctx);

  //print key
  printf("Key:\n");
  for(int i = 0; i < 240; ++i)
  {
    printf("%x ", ctx.roundKey[i]);
  }
  printf("\n");

  //printf iv
  printf("iv:\n");
  for(int i = 0; i < 16; ++i)
  {
    printf("%x ", ctx.iv[i]);
  }
  printf("\n");
  return 0;
}