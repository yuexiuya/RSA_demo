#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "rsa2_utility.h"
#include "rsa_utility.h"


#define OPENSSLKEY "./test.key"
#define PUBLICKEY  "./test_pub.key"
#define BUFFSIZE   1024


int main(void)
{

    const char text[] = "I LOVE RSA";
    char en_text[1024] = {0};
    char de_text[1024] = {0};
//    char *ptf_en, *ptf_de;

//    printf("source is   :%s\n", source);

//    RSA_Utility rsa;

//    rsa.rsa_pub_encrypt_byPath(sizeof(text), text, en_text, PUBLICKEY);
//    printf("======> %X \n",en_text);
//    rsa.rsa_pri_decrypt_byPath(128, en_text, de_text, OPENSSLKEY);

//    printf("======> %s \n",de_text);



    /////////////////////////////////////////////////////////////////////
    ///  加密仅需要 公钥或者私钥
    ///   解密 是必须需要 私钥的！！！
    RSA2_Utility rsa2;
    rsa2.open_pubkey();
    rsa2.open_prikey_pubkey();

    rsa2.pubkey_encrypt(sizeof(text), text, en_text);

    rsa2.prikey_decrypt(strlen(en_text), en_text, de_text);

    while(1);
    return 0;

}
