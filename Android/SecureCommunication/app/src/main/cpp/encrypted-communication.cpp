#include <jni.h>
#include <vector>
#include <string>

#include <mbedtls/gcm.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/base64.h>
#include "mbedtls/pk.h"

constexpr size_t SALT_SIZE = 16;
constexpr size_t IV_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
constexpr size_t KEY_SIZE = 32;
constexpr size_t ASYMMETRIC_PASSWORD_SIZE = 32;
constexpr uint32_t PBKDF2_ITERATIONS = 100000;

bool generateRandomBytes(unsigned char *output,
                         size_t length,
                         const char *personalization = "secure_random")
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);

    int ret = mbedtls_ctr_drbg_seed(
            &ctr,
            mbedtls_entropy_func,
            &entropy,
            reinterpret_cast<const unsigned char *>(personalization),
            strlen(personalization));

    if (ret == 0) {
        ret = mbedtls_ctr_drbg_random(&ctr, output, length);
    }

    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);

    return ret == 0;
}

bool deriveKey(const std::string &password,
               const unsigned char *salt,
               size_t saltLen,
               unsigned char *key,
               size_t keyLen = KEY_SIZE)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t *md =
            mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md == nullptr ||
        mbedtls_md_setup(&ctx, md, 1) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    int ret = mbedtls_pkcs5_pbkdf2_hmac(
            &ctx,
            reinterpret_cast<const unsigned char *>(password.data()),
            password.size(),
            salt,
            saltLen,
            PBKDF2_ITERATIONS,
            keyLen,
            key);

    mbedtls_md_free(&ctx);

    return ret == 0;
}

std::string base64Encode(const unsigned char *data, size_t len)
{
    size_t outLen = 0;

    mbedtls_base64_encode(
            nullptr,
            0,
            &outLen,
            data,
            len);

    std::string result(outLen, '\0');

    if (mbedtls_base64_encode(
            reinterpret_cast<unsigned char *>(result.data()),
            result.size(),
            &outLen,
            data,
            len) != 0) {
        return "";
    }

    result.resize(outLen);
    return result;
}

std::vector<unsigned char> base64Decode(const std::string &input)
{
    size_t outLen = 0;

    mbedtls_base64_decode(
            nullptr,
            0,
            &outLen,
            reinterpret_cast<const unsigned char *>(input.data()),
            input.size());

    std::vector<unsigned char> output(outLen);

    if (mbedtls_base64_decode(
            output.data(),
            output.size(),
            &outLen,
            reinterpret_cast<const unsigned char *>(input.data()),
            input.size()) != 0) {
        return {};
    }

    output.resize(outLen);
    return output;
}

std::string encrypt(const std::string &plaintext,
                            const std::string &password)
{
    unsigned char salt[SALT_SIZE];
    if (!generateRandomBytes(salt, sizeof(salt)))
        return "";

    unsigned char key[KEY_SIZE];
    if (!deriveKey(password, salt, sizeof(salt), key))
        return "";

    unsigned char iv[IV_SIZE];
    if (!generateRandomBytes(iv, sizeof(iv)))
        return "";

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(
            &gcm,
            MBEDTLS_CIPHER_ID_AES,
            key,
            KEY_SIZE * 8);

    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return "";
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    unsigned char tag[TAG_SIZE];

    ret = mbedtls_gcm_crypt_and_tag(
            &gcm,
            MBEDTLS_GCM_ENCRYPT,
            plaintext.size(),
            iv,
            sizeof(iv),
            nullptr,
            0,
            reinterpret_cast<const unsigned char *>(plaintext.data()),
            ciphertext.data(),
            sizeof(tag),
            tag);

    mbedtls_gcm_free(&gcm);

    if (ret != 0)
        return "";

    std::vector<unsigned char> combined;
    combined.reserve(
            IV_SIZE + ciphertext.size() + TAG_SIZE);

    combined.insert(
            combined.end(),
            iv,
            iv + IV_SIZE);

    combined.insert(
            combined.end(),
            ciphertext.begin(),
            ciphertext.end());

    combined.insert(
            combined.end(),
            tag,
            tag + TAG_SIZE);

    return base64Encode(
            combined.data(),
            combined.size()) +
           ":" +
           base64Encode(
                   salt,
                   sizeof(salt));
}

std::string decrypt(const std::string &encrypted,
                    const std::string &password)
{
    size_t pos = encrypted.find(':');
    if (pos == std::string::npos)
        return "";

    std::string combinedB64 = encrypted.substr(0, pos);
    std::string saltB64 = encrypted.substr(pos + 1);

    std::vector<unsigned char> combined =
            base64Decode(combinedB64);

    std::vector<unsigned char> salt =
            base64Decode(saltB64);

    if (combined.empty() ||
        salt.empty() ||
        combined.size() < IV_SIZE + TAG_SIZE)
        return "";

    unsigned char key[KEY_SIZE];
    if (!deriveKey(
            password,
            salt.data(),
            salt.size(),
            key))
        return "";

    const unsigned char *iv = combined.data();

    size_t ciphertextLen =
            combined.size() - IV_SIZE - TAG_SIZE;

    const unsigned char *ciphertext =
            combined.data() + IV_SIZE;

    const unsigned char *tag =
            combined.data() + IV_SIZE + ciphertextLen;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(
            &gcm,
            MBEDTLS_CIPHER_ID_AES,
            key,
            KEY_SIZE * 8);

    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return "";
    }

    std::vector<unsigned char> plaintext(ciphertextLen);

    ret = mbedtls_gcm_auth_decrypt(
            &gcm,
            ciphertextLen,
            iv,
            IV_SIZE,
            nullptr,
            0,
            tag,
            TAG_SIZE,
            ciphertext,
            plaintext.data());

    mbedtls_gcm_free(&gcm);

    if (ret != 0)
        return "";

    return {reinterpret_cast<char *>(plaintext.data()),
            plaintext.size()};
}

std::string encryptAsymmetric(
        const std::string& plaintext,
        const std::string& rsaPublicKeyPem)
{
    // Generate random password
    unsigned char password[ASYMMETRIC_PASSWORD_SIZE];
    if (!generateRandomBytes(password, sizeof(password)))
        return "";

    // Encrypt the plaintext with the generated password
    std::string encryptedData = encrypt(
            plaintext,
            std::string(
                    reinterpret_cast<const char*>(password),
                    sizeof(password)));

    if (encryptedData.empty())
        return "";

    // Parse RSA public key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_public_key(
            &pk,
            reinterpret_cast<const unsigned char*>(rsaPublicKeyPem.data()),
            rsaPublicKeyPem.size() + 1); // +1 for terminating '\0'

    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return "";
    }

    // Seed DRBG (required for RSA-OAEP/PKCS#1 v1.5 encryption)
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char* pers = "rsa_encrypt";

    ret = mbedtls_ctr_drbg_seed(
            &ctr_drbg,
            mbedtls_entropy_func,
            &entropy,
            reinterpret_cast<const unsigned char*>(pers),
            strlen(pers));

    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_pk_free(&pk);
        return "";
    }

    // Encrypt the random password
    std::vector<unsigned char> encryptedPassword(
            mbedtls_pk_get_len(&pk));

    size_t encryptedLen = 0;

    ret = mbedtls_pk_encrypt(
            &pk,
            password,
            sizeof(password),
            encryptedPassword.data(),
            &encryptedLen,
            encryptedPassword.size(),
            mbedtls_ctr_drbg_random,
            &ctr_drbg);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);

    if (ret != 0)
        return "";

    encryptedPassword.resize(encryptedLen);

    // Base64 encode the RSA-encrypted password
    std::string encryptedPasswordB64 =
            base64Encode(
                    encryptedPassword.data(),
                    encryptedPassword.size());

    // Payload:
    // Base64(RSA_ENCRYPTED_PASSWORD) : AES_PAYLOAD
    return encryptedPasswordB64 + ":" + encryptedData;
}

std::string decryptAsymmetric(
        const std::string& encrypted,
        const std::string& rsaPrivateKeyPem)
{
    // Split "encryptedPassword:aesPayload"
    size_t pos = encrypted.find(':');
    if (pos == std::string::npos)
        return "";

    std::string encryptedPasswordB64 = encrypted.substr(0, pos);
    std::string encryptedData = encrypted.substr(pos + 1);

    // Decode RSA-encrypted password
    std::vector<unsigned char> encryptedPassword =
            base64Decode(encryptedPasswordB64);

    if (encryptedPassword.empty())
        return "";

    // Parse private key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_key(
            &pk,
            reinterpret_cast<const unsigned char*>(
                    rsaPrivateKeyPem.c_str()),
            rsaPrivateKeyPem.size() + 1,
            nullptr,
            0,
            mbedtls_ctr_drbg_random,
            nullptr);

    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return "";
    }

    // Create DRBG
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char* pers = "rsa_decrypt";

    ret = mbedtls_ctr_drbg_seed(
            &ctr_drbg,
            mbedtls_entropy_func,
            &entropy,
            reinterpret_cast<const unsigned char*>(pers),
            strlen(pers));

    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_pk_free(&pk);
        return "";
    }

    // Decrypt password
    unsigned char password[ASYMMETRIC_PASSWORD_SIZE];
    size_t passwordLen = 0;

    ret = mbedtls_pk_decrypt(
            &pk,
            encryptedPassword.data(),
            encryptedPassword.size(),
            password,
            &passwordLen,
            sizeof(password),
            mbedtls_ctr_drbg_random,
            &ctr_drbg);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);

    if (ret != 0)
        return "";

    // Use the recovered password to decrypt the payload
    return decrypt(
            encryptedData,
            std::string(
                    reinterpret_cast<char*>(password),
                    passwordLen));
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_rafaeldiascampos_securecommunication_EncryptedNativeRequestInterceptor_encrypt(
        JNIEnv *env,
        jobject,
        jstring text,
        jstring password) {
    const char* textChars = env->GetStringUTFChars(text, nullptr);
    const char* passChars = env->GetStringUTFChars(password, nullptr);

    std::string result = encrypt(textChars, passChars);

    env->ReleaseStringUTFChars(text, textChars);
    env->ReleaseStringUTFChars(password, passChars);

    return env->NewStringUTF(result.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_rafaeldiascampos_securecommunication_EncryptedNativeRequestInterceptor_decrypt(
        JNIEnv *env,
        jobject,
        jstring encryptedBase64,
        jstring password) {
    const char* encryptedBase64Chars = env->GetStringUTFChars(encryptedBase64, nullptr);
    const char* passChars = env->GetStringUTFChars(password, nullptr);

    std::string result = decrypt(encryptedBase64Chars, passChars);

    env->ReleaseStringUTFChars(encryptedBase64, encryptedBase64Chars);
    env->ReleaseStringUTFChars(password, passChars);

    return env->NewStringUTF(result.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_rafaeldiascampos_securecommunication_EncryptedAsymmetricRequestInterceptor_encryptAsymmetric(
        JNIEnv *env,
        jobject,
        jstring text,
        jstring publicKey)
{
    const char *textChars =
            env->GetStringUTFChars(text, nullptr);

    const char *publicKeyChars =
            env->GetStringUTFChars(publicKey, nullptr);

    std::string result =
            encryptAsymmetric(
                    textChars,
                    publicKeyChars);

    env->ReleaseStringUTFChars(
            text,
            textChars);

    env->ReleaseStringUTFChars(
            publicKey,
            publicKeyChars);

    return env->NewStringUTF(result.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_rafaeldiascampos_securecommunication_EncryptedAsymmetricRequestInterceptor_decryptAsymmetric(
        JNIEnv *env,
        jobject,
        jstring encryptedBase64,
        jstring privateKey)
{
    const char *encryptedChars =
            env->GetStringUTFChars(
                    encryptedBase64,
                    nullptr);

    const char *privateKeyChars =
            env->GetStringUTFChars(
                    privateKey,
                    nullptr);

    std::string result =
            decryptAsymmetric(
                    encryptedChars,
                    privateKeyChars);

    env->ReleaseStringUTFChars(
            encryptedBase64,
            encryptedChars);

    env->ReleaseStringUTFChars(
            privateKey,
            privateKeyChars);

    return env->NewStringUTF(result.c_str());
}