#ifndef RSA_ENCRYPTOR_DECRYPTOR_H
#define RSA_ENCRYPTOR_DECRYPTOR_H

#include <string>
#include <rsa.h>

class RSAEncryptorDecryptor {
public:
    RSAEncryptorDecryptor();
    std::string getPublicKeyString() const;
    std::string encrypt(const std::string& plainText);
    bool savePrivateKeyToFile(const std::string& filename) const;
    bool loadPrivateKeyFromFile(const std::string& filename);
    std::string decrypt(const std::string& cipherText);
    void hexify(const unsigned char* buffer, unsigned int length);
	

private:
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;
    std::string publicKeyString;
    void generateKeys();
};
#endif // RSA_ENCRYPTOR_DECRYPTOR_H

