#ifndef RSA_UTILITY_H
#define RSA_UTILITY_H


/**
 * @brief The RSA_Utility class
 *      工具类，用于 RSA 的加密和解密
 */
class RSA_Utility
{
public:
    RSA_Utility();
    ~RSA_Utility();
    RSA_Utility(const RSA_Utility& rhs)=delete;
    RSA_Utility& operator=(const RSA_Utility& rhs)=delete;

    /// 根据 公钥\私钥 文件路径 进行加密\解密
    bool rsa_pub_encrypt_byPath(int len,
                                const char* str,
                                char* str_en,
                                const char* key_path);

    bool rsa_pri_decrypt_byPath(int len,
                                const char* str,
                                char* str_de,
                                const char* key_path);
};

#endif // RSA_UTILITY_H
