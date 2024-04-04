#include "SendPublicKeyMessageState.hpp"
#include <iostream>
#include <vector>
#include "Base64Wrapper.h"
#include "AESWrapper.h"

void SendPublicKeyMessageState::hexify(const unsigned char* buffer, unsigned int length)
{
    std::ios::fmtflags f(std::cout.flags());
    std::cout << std::hex;
    for (size_t i = 0; i < length; i++)
        std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
    std::cout << std::endl;
    std::cout.flags(f);
}


void SendPublicKeyMessageState::createCryptoKeys(std::string& pubkeyOut, std::string& privkeyOut) {
    // Assuming _rsapriv is an instance of a class that has getPublicKey() and getPrivateKey() methods
    std::string pubkey = _rsapriv.getPublicKey();
    // Base64 encode the private key
    std::string base64key = Base64Wrapper::encode(_rsapriv.getPrivateKey());
    // Assign the keys to the output parameters
    pubkeyOut = pubkey;
    privkeyOut = base64key;
}

std::string SendPublicKeyMessageState::createMessage(const std::string& payload) {
    unsigned short messageCode = getMessageCode();
    unsigned short payloadSize = 255+160;// payload.size();
    unsigned long long clientIDHigh = getClientIDHigh();
    unsigned long long clientIDLow = getClientIDLow();
    unsigned int version = getVersion();
    int keyLength = 160;
    std::vector<unsigned char> buffer;

    std::string pubkeyOut;
    std::string privkeyOut;
    createCryptoKeys(pubkeyOut, privkeyOut);//now public key and private key

    // Helper lambda to append data in little-endian order
    auto appendLittleEndian = [&buffer](auto value, size_t numBytes) {
        for (size_t i = 0; i < numBytes; i++) {
            if (i < sizeof(value)) {
                buffer.push_back((value >> (i * 8)) & 0xFF);
            }
            else {
                buffer.push_back(0); // Append zeros if beyond the size of value
            }
        }
        };

    // Append fields in little-endian order
    appendLittleEndian(clientIDHigh, 8);
    appendLittleEndian(clientIDLow, 8);
    appendLittleEndian(version, 1);
    appendLittleEndian(messageCode, 2);
    appendLittleEndian(payloadSize, 4);

    // Append payload(Name)

    buffer.insert(buffer.end(), payload.begin(), payload.end());
    
    //create public key and private key with cpp,put in a function inside the class
    //change the parsing in the python? not sure
    buffer.insert(buffer.end(), pubkeyOut.begin(), pubkeyOut.end());

    std::string res = std::string(buffer.begin(), buffer.end());
    // Convert to std::string (assuming payload is text; adjust if handling binary data)
    return res;
}
