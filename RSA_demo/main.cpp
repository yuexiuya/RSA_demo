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
    char *ptf_en, *ptf_de;

//    printf("source is   :%s\n", source);

    RSA_Utility rsa;

    rsa.rsa_pub_encrypt_byPath(sizeof(text), text, en_text, PUBLICKEY);
    printf("======> %X \n",en_text);
    rsa.rsa_pri_decrypt_byPath(128, en_text, de_text, OPENSSLKEY);

    printf("======> %s \n",de_text);



    /////////////////////////////////////////////////////////////////////
//    RSA2_Utility rsa2;
//    RSA2_Utility rsa3;
////    rsa2.generate_rsa_key();
//    rsa2.open_prikey();
//    rsa3.open_pubkey();

//    uint8_t* en_out = nullptr;
//    int enLen = 0;
//    uint8_t* de_out = nullptr;
//    const char text[] = "I Love RSA";
//    int text_len = sizeof(text);

//    enLen = rsa2.prikey_encrypt(text_len, (uint8_t *)text, (uint8_t **)&en_out);
//    printf("en_text + %X \n",en_out);
//    printf("en_len + %d \n",enLen);

//    rsa3.pubkey_decrypt(enLen, (uint8_t *)en_out, (uint8_t **)&de_out);

////    for(int i = 0; i<enLen; i++) {
////        printf("de_out + %X \n",de_out[i]);
////    }
////    std::string de_str = de_out;
////    printf("de_str = %s \n",de_str.c_str());
    while(1);
    return 0;

}
