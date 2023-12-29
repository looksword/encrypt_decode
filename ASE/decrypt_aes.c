#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

void handleErrors() {
    printf("Error occurred\n");
    exit(0);
}

unsigned char* decryptAES(const unsigned char* content, const char* password) {
    AES_KEY aesKey;
    char iv[AES_BLOCK_SIZE];
    char* keyData = (char*)password;
    int inputLength = strlen((char*)content);
    unsigned char temp[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)keyData, strlen(keyData), temp);
    AES_set_decrypt_key(temp, 128, &aesKey);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char* plaintext = (unsigned char*)malloc(inputLength);
    int len;

    // Set encryption key and initialization vector
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, temp, iv);

    // Perform decryption
    EVP_DecryptUpdate(ctx, plaintext, &len, content, inputLength);
    int plaintextLength = len;

    // Finalize the decryption
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintextLength += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

int main() {
    //unsigned char content[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
	char* content = "encrypted text";
    char* password = "encrypt password";
    unsigned char* result = decryptAES(content, password);
    printf("decryptAES: %s\n", result);

    return 0;
}