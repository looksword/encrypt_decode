#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>

void handleErrors() {
    printf("Error occurred\n");
    exit(0);
}

unsigned char* encryptAES(const char* content, const char* password) {
    AES_KEY aesKey;
    char iv[AES_BLOCK_SIZE];
    char* keyData = (char*)password;
    unsigned char* input = (unsigned char*)content;
    int inputLength = strlen(content) + 1; // include null terminator
    int len;

    // Generate AES 128-bit key
    unsigned char temp[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)keyData, strlen(keyData), temp);
    AES_set_encrypt_key(temp, 128, &aesKey);

    // Set the encryption key
    RAND_pseudo_bytes((unsigned char*)&iv, AES_BLOCK_SIZE);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, temp, iv);

    // Allocate memory for the ciphertext
    unsigned char* ciphertext = (unsigned char*)malloc(inputLength + 16);
    if (!ciphertext) {
        handleErrors();
    }

    // Perform the encryption
    EVP_EncryptUpdate(ctx, ciphertext, &len, input, inputLength);
    int ciphertextLen = len;

    // Finalize the encryption
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertextLen += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

int main() {
    char* content = "This is a test message.";
    char* password = "encrypt password";
    unsigned char* result = encryptAES(content, password);

    // Print result
	printf("encryptAES: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", result[i]);
    }
	printf("\n");

    return 0;
}