#include "rsa2_utility.h"
#include <memory.h>


RSA2_Utility::RSA2_Utility()
{
    printf("RSA2_Utility \n");
}

RSA2_Utility::~RSA2_Utility()
{
    printf("~RSA2_Utility \n");
}

bool RSA2_Utility::generate_rsa_key()
{

    /// 自动生成一组 pub_key & pri_key
    m_test = RSA_generate_key(RSA_KEY_LENGTH, RSA_F4, NULL, NULL);

    /// 打印
    RSA_print_fp(stdout, m_test,10);

    /// 写入文件
    FILE * fp = fopen("./new_key", "w");
    if(fp == NULL) {
        return false;
    }
    RSA_print_fp(stdout, m_test, 0);

    fclose(fp);

    return true;
}

/// openssl 1.1.x 以上，结构体不可直接获取

bool RSA2_Utility::open_prikey_pubkey()
{
    printf("open_prikey_pubkey \n");
    m_prikey = RSA_new();
    BIGNUM* _e = BN_new();
    BIGNUM* _d = BN_new();
    BIGNUM* _n = BN_new();
    _e = BN_bin2bn(m_pubexpd, m_publen, _e);
    _d = BN_bin2bn(m_priexpd, m_prilen, _d);
    _n = BN_bin2bn(m_module, m_modlen, _n);
    int _ret = RSA_set0_key(m_prikey, _n, _e, _d);
    if(_ret < 0) {
        printf("RSA_set0_key failed \n");
        return false;
    }
    RSA_print_fp(stdout, m_prikey, 10);
    return true;
}

bool RSA2_Utility::open_prikey()
{
    printf("open_prikey \n");
    m_prikey = RSA_new();
    BIGNUM* _e = BN_new();
    BIGNUM* _d = BN_new();
    BIGNUM* _n = BN_new();
    _d = BN_bin2bn(m_priexpd, m_prilen, _d);
    _n = BN_bin2bn(m_module, m_modlen, _n);
    int _ret = RSA_set0_key(m_prikey, _n, _e, _d);
    if(_ret < 0) {
        printf("RSA_set0_key failed \n");
        return false;
    }
    RSA_print_fp(stdout, m_prikey, 10);
    return true;
}

bool RSA2_Utility::open_pubkey()
{
    printf("open_pubkey \n");
    m_pubkey = RSA_new();
    BIGNUM* _e = BN_new();
    BIGNUM* _d = BN_new();
    BIGNUM* _n = BN_new();
    _e = BN_bin2bn(m_pubexpd, m_publen, _e);
    _n = BN_bin2bn(m_module, m_modlen, _n);
    int _ret = RSA_set0_key(m_pubkey, _n, _e, _d);
    if(_ret < 0) {
        printf("RSA_set0_key failed \n");
        return false;
    }
    RSA_print_fp(stdout, m_pubkey, 10);
    printf("open_pubkey %d \n", RSA_size(m_pubkey));
    return true;
}

int RSA2_Utility::prikey_encrypt(int len, const uint8_t* str, uint8_t** str_en)
{
    printf("prikey_encrypt \n");
    RSA_print_fp(stdout, m_prikey, 10);
    int _outLen = RSA_size(m_prikey);

    *str_en = (uint8_t*)malloc(_outLen);
    if( *str_en == NULL ) {
        printf("prikey_encrypt malloc error !!! \n");
        return -1;
    }
    memset((void*)*str_en, 0, _outLen);
    return RSA_private_encrypt(len, (uint8_t *)str, (uint8_t *)str_en, m_prikey, RSA_PKCS1_PADDING);
}

int RSA2_Utility::pubkey_decrypt(int len, const uint8_t *str, uint8_t **str_de)
{
    printf("pubkey_decrypt \n");
//    printf("pubkey_decrypt mallocxxxx !!! \n");
//    if(m_pubkey == nullptr) {
//        printf("pubkey_decrypt aaaaa !!! \n");
//    } else {
//        printf("pubkey_decrypt cccc !!! \n");
//        int _deLen = RSA_size(m_pubkey);
//        printf("pubkey_decrypt bbbb !!! \n");
//    }
//    RSA_print_fp(stdout, m_prikey, 10);

    printf("pubkey_decrypt malloc0000 !!! \n");
    int _deLen = RSA_size(m_pubkey);
    *str_de = (uint8_t*)malloc(_deLen);
    if( *str_de == NULL ) {
        printf("pubkey_decrypt malloc error !!! \n");
        return -1;
    }
    memset((void*)*str_de, 0, _deLen);

    printf("pubkey_decrypt malloc 11111 !!! \n");
    int ret = RSA_public_decrypt(len+1, (uint8_t *)str, (uint8_t *)str_de, m_pubkey, RSA_PKCS1_PADDING);
    printf("pubkey_decrypt malloc 2222 !!! \n");

    for(int i = 0; i<len; i++) {
        printf("de_out + %X \n",str_de[i]);
    }
    return ret;
}
