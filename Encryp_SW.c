#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "encrypt_decrypt.h"

int main(int argc, char *argv[])
{
    FILE *f_input, *f_enc, *f_mrg;

    /* Temporal variable for input file name */
    char *name_temp = argv[1];    
    
    /* Key to use for encrpytion and decryption */
    unsigned char key[AES_256_KEY_SIZE];

    /* Initialization Vector */
    unsigned char iv[AES_BLOCK_SIZE];

    /* Storage the position for Key used from the keystore.txt */
    unsigned char keypos[KEY_POS_SIZE];

    int key_pos=0, pos_init=0;

    /* Make sure user provides the input file */
    if (argc != 3)
    {
        printf("Usage: %s /path/to/file  cryptokey_number\n", argv[0]);
        return -1;
    }

    /* Make sure user provides the input position key between 1 and 30 */
    key_pos = atoi(argv[2]);

    if (key_pos >= 1 && key_pos <= 30)
    {
        keypos[0] = (unsigned char) key_pos;
        pos_init = (key_pos*33) - 33;
    } else 
    {
        printf("ERROR: The key position must be a number between 1 and 30\n");
        return -1;
    }

    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
    if (!params)
    {
        /* Unable to allocate memory on heap*/
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return errno;
    }

    /* Generate cryptographically strong pseudo-random bytes for IV */
    if (!RAND_bytes(iv, sizeof(iv)))
    {
        /* OpenSSL reports a failure, act accordingly */
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
    }

    /* Open the key file for reading in binary ("rb" mode) */
    f_input = fopen("keystore.txt", "rb");
    if (!f_input)
    {
        /* Unable to open file for reading */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    fseek(f_input, pos_init, SEEK_SET);

    for (size_t i = 0; i < AES_256_KEY_SIZE; ++i)
    {
        uint8_t v = fgetc(f_input);
        if (feof(f_input))
        {
            fprintf(stderr, "ERROR: keystore file EOF!");
            return -1;
        }
        key[i] = v;
    }

    fclose(f_input);

    params->key = key;
    params->iv = iv;

    /* Indicate that we want to encrypt */
    params->encrypt = 1;

    /* Set the cipher type you want for encryption-decryption */
    params->cipher_type = EVP_aes_256_ctr();

    /* Open the input file for reading in binary ("rb" mode) */
    f_input = fopen(argv[1], "rb");
    if (!f_input)
    {
        /* Unable to open file for reading */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    /* Open and truncate file to zero length or create ciphertext file for writing */
    f_enc = fopen(strcat(name_temp,"_Encryp"), "wb");
    if (!f_enc)
    {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    /* Encrypt the given file */
    file_encrypt_decrypt(params, f_input, f_enc);

    /* Encryption done, close the file descriptors */
    fclose(f_input);
    fclose(f_enc);

    f_mrg = fopen(name_temp, "a+");
    if (!f_mrg)
    {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    fwrite(keypos, sizeof(unsigned char), KEY_POS_SIZE, f_mrg);
    if (ferror(f_mrg))
    {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
    }

    fwrite(iv, sizeof(unsigned char), AES_BLOCK_SIZE, f_mrg);
    if (ferror(f_mrg))
    {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
    }

    fclose(f_mrg);

    free(params);

    return 0;
}