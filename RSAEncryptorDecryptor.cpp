
#include "RSAEncryptorDecryptor.hpp"

#include <files.h>
#include <osrng.h>
#include <base64.h>
#include <iomanip>
/*

RSAEncryptorDecryptor::RSAEncryptorDecryptor() {
    generateKeys();
}

void RSAEncryptorDecryptor::generateKeys() {
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1024); // Example private key size in bits

    privateKey = CryptoPP::RSA::PrivateKey(params);
    publicKey.Initialize(params.GetModulus(), params.GetPublicExponent());
}

std::string RSAEncryptorDecryptor::getPublicKeyString() {
    std::string publicKeyString;
    {
        CryptoPP::ByteQueue queue;
        publicKey.Save(queue);
        queue.MessageEnd();
        publicKeyString.resize(160); // 160 bytes
        queue.Get((unsigned char*)&publicKeyString[0], publicKeyString.size());
    }
    return publicKeyString;
}

std::string RSAEncryptorDecryptor::encrypt(const std::string& plainText) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string cipherText;

    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    CryptoPP::StringSource(plainText, true, new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::StringSink(cipherText)));

    return cipherText;
}

bool RSAEncryptorDecryptor::savePrivateKeyToFile(const std::string& filename) {
    try {
        privateKey.Save(CryptoPP::FileSink(filename.c_str(), true ).Ref());
        return true;
    }
    catch (...) {
        return false;
    }
}

bool RSAEncryptorDecryptor::loadPrivateKeyFromFile(const std::string& filename) {
    try {
        CryptoPP::FileSource file(filename.c_str(), true );
        privateKey.Load(file);
        return true;
    }
    catch (...) {
        return false;
    }
}

std::string RSAEncryptorDecryptor::decrypt(const std::string& cipherText) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string decryptedText;

    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    CryptoPP::StringSource(cipherText, true, new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decryptedText)));

    return decryptedText;
}



#include "RSAEncryptorDecryptor.hpp"
#include <files.h>
#include <osrng.h>
#include <base64.h>



RSAEncryptorDecryptor::RSAEncryptorDecryptor() {
    generateKeys();
}

//RSAEncryptorDecryptor::~RSAEncryptorDecryptor() {
//    // Destructor
//}

//RSAEncryptorDecryptor& RSAEncryptorDecryptor::getInstance() {
//    static RSAEncryptorDecryptor instance; // Static instance of the class
//    return instance;
//}
/*
void RSAEncryptorDecryptor::generateKeys() {
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1024); // Example private key size in bits

    privateKey = CryptoPP::RSA::PrivateKey(params);
    publicKey.Initialize(params.GetModulus(), params.GetPublicExponent());
}

std::string RSAEncryptorDecryptor::getPublicKeyString() {
    return m_publicKeyString;
}

void RSAEncryptorDecryptor::setPublicKeyString(const std::string& publicKey) {
    m_publicKeyString = publicKey;
}

std::string RSAEncryptorDecryptor::encrypt(const std::string& plainText) {
    if (plainText.size() > 86) { // Ensure plaintext size is within bounds (86 bytes for OAEP padding with SHA-1)
        throw std::invalid_argument("Plain text is too long for encryption with this key size");
    }

    CryptoPP::AutoSeededRandomPool rng;
    std::string cipherText;

    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    CryptoPP::StringSource(plainText, true, new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::StringSink(cipherText)));

    return cipherText;
}

bool RSAEncryptorDecryptor::savePrivateKeyToFile(const std::string& filename) {
    try {
        privateKey.Save(CryptoPP::FileSink(filename.c_str(), true).Ref());
        return true;
    }
    catch (...) {
        return false;
    }
}

bool RSAEncryptorDecryptor::loadPrivateKeyFromFile(const std::string& filename) {
    try {
        CryptoPP::FileSource file(filename.c_str(), true );
        privateKey.Load(file);
        return true;
    }
    catch (...) {
        return false;
    }
}

std::string RSAEncryptorDecryptor::decrypt(const std::string& cipherText) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string decryptedText;

    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    CryptoPP::StringSource(cipherText, true, new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decryptedText)));

    return decryptedText;
}
*/


RSAEncryptorDecryptor::RSAEncryptorDecryptor() {
    generateKeys();
}

void RSAEncryptorDecryptor::generateKeys() {
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1024); // Example private key size in bits

    privateKey = CryptoPP::RSA::PrivateKey(params);
    publicKey.Initialize(params.GetModulus(), params.GetPublicExponent());

    // Serialize public key to string
    CryptoPP::ByteQueue queue;
    publicKey.Save(queue);
    queue.MessageEnd();
    publicKeyString.resize(160); // 160 bytes
    queue.Get((unsigned char*)&publicKeyString[0], publicKeyString.size());
}

std::string RSAEncryptorDecryptor::getPublicKeyString() const {
    return publicKeyString;
}

std::string RSAEncryptorDecryptor::encrypt(const std::string& plainText) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string cipherText;

    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    CryptoPP::StringSource(plainText, true, new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::StringSink(cipherText)));

    return cipherText;
}

bool RSAEncryptorDecryptor::savePrivateKeyToFile(const std::string& filename) const {
    try {
        privateKey.Save(CryptoPP::FileSink(filename.c_str(), true /*binary*/).Ref());
        return true;
    }
    catch (...) {
        return false;
    }
}

bool RSAEncryptorDecryptor::loadPrivateKeyFromFile(const std::string& filename) {
    try {
        CryptoPP::FileSource file(filename.c_str(), true /*binary*/);
        privateKey.Load(file);
        return true;
    }
    catch (...) {
        return false;
    }
}

std::string RSAEncryptorDecryptor::decrypt(const std::string& cipherText) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string decryptedText;

    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    CryptoPP::StringSource(cipherText, true, new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decryptedText)));

    return decryptedText;
}


void RSAEncryptorDecryptor::hexify(const unsigned char* buffer, unsigned int length)
{
    std::ios::fmtflags f(std::cout.flags());
    std::cout << std::hex;
    for (size_t i = 0; i < length; i++)
        std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
    std::cout << std::endl;
    std::cout.flags(f);
}