#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

char *rsa_pri_encrypt(char *clearText, char *pubKey)
{
    char* strRet = NULL;  
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pubKey, -1);
    RSA *rsa = RSA_new();
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        BIO_free_all(keybio);
        return strRet;
    }

    int len = RSA_size(rsa);
    char *encryptedText = (char *)malloc(len + 1);
    memset(encryptedText, 0, len + 1);

    // 加密
    int ret = RSA_private_encrypt(strlen(clearText), (unsigned char *)clearText, (unsigned char *)encryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)  
    {
        strRet = (char*)malloc(ret + 1);
        memcpy(strRet, encryptedText, ret);
        strRet[ret] = '\0';
    }

    // 释放内存
    free(encryptedText);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return strRet;
}

char* rsa_pub_decrypt(const char* clearText,  char* pubKey)  
{  
    char* strRet = NULL;  
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pubKey, -1);  
    RSA* rsa = RSA_new();
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
		BIO_free_all(keybio);
		return strRet;
    }

    int len = RSA_size(rsa);  
    char *encryptedText = (char *)malloc(len + 1);  
    memset(encryptedText, 0, len + 1);  
  
    int ret = RSA_public_decrypt(strlen(clearText), (const unsigned char*)clearText, (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);  
    if (ret >= 0)  
    {
        strRet = (char*)malloc(ret + 1);
        memcpy(strRet, encryptedText, ret);
        strRet[ret] = '\0';
    }

    free(encryptedText);  
    BIO_free_all(keybio);  
    RSA_free(rsa);  
  
    return strRet;  
}

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

int main() {
	RSAKeyPair* keyPair = generateKeyPair();
    printf("Public Key:\n%s\n", keyPair->publicKey);
    printf("Private Key:\n%s\n", keyPair->privateKey);
	char* text = "looksword test";
	char* encryptedText = rsa_pri_encrypt(text, keyPair->privateKey);
	printf("encrypted Text:\n%s\n", encryptedText);
	char* decryptedText = rsa_pub_decrypt(encryptedText, keyPair->publicKey);
	printf("decrypted Text:\n%s\n", decryptedText);
	
    free(keyPair->publicKey);
    free(keyPair->privateKey);
    free(keyPair);
}
