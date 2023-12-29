#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

typedef struct {
    char* publicKey;
    char* privateKey;
} RSAKeyPair;

RSAKeyPair* generateKeyPair() {
    RSA* rsa = RSA_generate_key(1024, RSA_F4, NULL, NULL);
    
    // 获取私钥字符串
    BIO* bioPrivate = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bioPrivate, rsa, NULL, NULL, 0, NULL, NULL);
    BUF_MEM* bufferPrivate;
    BIO_get_mem_ptr(bioPrivate, &bufferPrivate);
    char* privateKey = (char*)malloc(bufferPrivate->length + 1);
    strncpy(privateKey, bufferPrivate->data, bufferPrivate->length);
    privateKey[bufferPrivate->length] = '\0';
    
    // 获取公钥字符串
    BIO* bioPublic = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bioPublic, rsa);
    BUF_MEM* bufferPublic;
    BIO_get_mem_ptr(bioPublic, &bufferPublic);
    char* publicKey = (char*)malloc(bufferPublic->length + 1);
    strncpy(publicKey, bufferPublic->data, bufferPublic->length);
    publicKey[bufferPublic->length] = '\0';

    RSAKeyPair* keyPair = (RSAKeyPair*)malloc(sizeof(RSAKeyPair));
    keyPair->publicKey = publicKey;
    keyPair->privateKey = privateKey;

    RSA_free(rsa);
    BIO_free(bioPrivate);
    BIO_free(bioPublic);

    return keyPair;
}

void testRSAKeyPair() {
    RSAKeyPair* keyPair = generateKeyPair();
    printf("Public Key:\n%s\n", keyPair->publicKey);
    printf("Private Key:\n%s\n", keyPair->privateKey);
    free(keyPair->publicKey);
    free(keyPair->privateKey);
    free(keyPair);
}

int main() {
    testRSAKeyPair();
    ERR_print_errors_fp(stderr);
    return 0;
}
