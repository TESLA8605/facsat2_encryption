 #include <openssl/evp.h>
 #include <openssl/err.h>
 #include <openssl/aes.h>
 #include <openssl/rand.h>

#define ERR_EVP_CIPHER_INIT     -1
#define ERR_EVP_CIPHER_UPDATE   -2
#define ERR_EVP_CIPHER_FINAL    -3
#define ERR_EVP_CTX_NEW         -4

#define AES_256_KEY_SIZE        32
#define AES_BLOCK_SIZE          16
#define BUFSIZE               1024
#define KEY_POS_SIZE             1

typedef struct _cipher_params_t
{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
} cipher_params_t;

void file_encrypt_decrypt(cipher_params_t *params, FILE *f_input, FILE *f_enc);