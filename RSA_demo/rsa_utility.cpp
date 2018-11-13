#include "rsa_utility.h"
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

RSA_Utility::RSA_Utility()
{

}

RSA_Utility::~RSA_Utility()
{

}

bool RSA_Utility::rsa_pub_encrypt_byPath(int len, const char *str, char *str_en, const char *key_path)
{
    /// 打开 公钥 文件
    FILE *_file;
    _file = fopen(key_path, "rb");
    if(_file == nullptr) {
        perror("open public file failed !!! \n");
        return false;
    }

    /// 从文件中获取 公钥
    RSA  *p_rsa = nullptr;
    p_rsa = PEM_read_RSA_PUBKEY(_file, NULL, NULL, NULL);
    if(p_rsa == nullptr) {
        perror("PEM_read_RSA_PUBKEY failed !!! \n");
        return false;
    }

    /// 对内容进行加密
    int _ret = RSA_public_encrypt(len,
                                  (uint8_t *)str,
                                  (uint8_t *)str_en,
                                  p_rsa,
                                  RSA_PKCS1_PADDING);
    if(_ret < 0) {
        perror("RSA_public_encrypt failed !!! \n");
        return false;
    }

    if(p_rsa)    RSA_free(p_rsa);
    if(_file)     fclose(_file);

    return true;
}

bool RSA_Utility::rsa_pri_decrypt_byPath(int len, const char *str, char *str_de, const char *key_path)
{
    /// 打开 私钥 文件
    FILE *_file;
    _file = fopen(key_path, "rb");
    if(_file == nullptr) {
        perror("open private file failed !!! \n");
        return false;
    }

    /// 从文件中获取 私钥
    RSA  *p_rsa = nullptr;
    p_rsa = PEM_read_RSAPrivateKey(_file, NULL, NULL, NULL);
    if(p_rsa == nullptr) {
        perror("PEM_read_RSAPrivateKey failed !!! \n");
        return false;
    }

    /// 对内容进行解密
    int _ret = RSA_private_decrypt(len,
                                   (uint8_t *)str,
                                   (uint8_t *)str_de,
                                   p_rsa,
                                   RSA_PKCS1_PADDING);
    if(_ret < 0) {
        perror("RSA_private_decrypt failed !!! \n");
        return false;
    }

    if(p_rsa)    RSA_free(p_rsa);
    if(_file)     fclose(_file);

    return true;
}
