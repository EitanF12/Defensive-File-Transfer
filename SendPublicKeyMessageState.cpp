#include "SendPublicKeyMessageState.hpp"
#include <iostream>
#include <fstream> // Include the <fstream> header for file operations
#include <vector>
#include <iomanip> // Include the <iomanip> header for std::hex, std::setfill, and std::setw
#include "Base64Wrapper.h"
#include "AESWrapper.h"
/*
//implement setter and getter for public key
void SendPublicKeyMessageState::setPublicKeyAsBytes( char* publicKey) {
    for (int i = 0; i < 160; i++) {
		_publicKey_bytes[i] = publicKey[i];
	}
}

unsigned char* SendPublicKeyMessageState::getPublicKeyAsBytes() {
	return _publicKey_bytes;
}
*/

void SendPublicKeyMessageState::createCryptoKeys(std::string& pubkeyOut, std::string& privkeyOut) {
    // Assuming _rsapriv is an instance of a class that has getPublicKey() and getPrivateKey() methods
    std::string pubkey = _rsapriv.getPublicKey();
    // Base64 encode the private key
    std::string base64key = Base64Wrapper::encode(_rsapriv.getPrivateKey());
    // Assign the keys to the output parameters
    pubkeyOut = pubkey;
    privkeyOut = base64key;


}

void SendPublicKeyMessageState::writeMeFileData(std::string& Name, std::string& uuid) {
    //read private key from priv.key.txt it is on the first line
    std::ifstream fileRead("priv.key.txt");//read private key from file
    std::string privateKey;
    if (fileRead.is_open()) {
		std::getline(fileRead, privateKey);
		fileRead.close();
	}
    else {
		std::cout << "Failed to open file for reading." << std::endl;
	}

    std::ofstream fileWrite("info.me.txt");
    if (fileWrite.is_open()) {
        fileWrite << Name << std::endl;
        fileWrite << uuid << std::endl;
        fileWrite << privateKey << std::endl;
        fileWrite.close();
    }
    else {
        std::cout << "Failed to open file for writing." << std::endl;
    }
}

void SendPublicKeyMessageState::writePrivateKeyToFile(const std::string& privateKey) {
    std::ofstream file("priv.key.txt");//write private key to file
    if (file.is_open()) {
        file << privateKey;
        file.close();
    }
    else {
        std::cout << "Failed to open file for writing." << std::endl;
    }
}

std::string SendPublicKeyMessageState::createMessage(const std::string& payload) {
    unsigned short messageCode = getMessageCode();
    int keyLength = 160;
    unsigned short payloadSize = 255 + keyLength; // payload.size();
    //unsigned long long clientIDHigh = getClientIDHigh();
    //unsigned long long clientIDLow = getClientIDLow();
    std::vector<unsigned char> buffer = getClientID();
    unsigned int version = getVersion();
   
    //std::vector<unsigned char> buffer;

    std::string pubkeyOut;
    std::string privkeyOut;
    //createCryptoKeys(pubkeyOut, privkeyOut); // now public key and private key
    //create file with private key
    //writePrivateKeyToFile(privkeyOut);
    /*
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
    */
    // Append fields in little-endian order
    //appendLittleEndian(clientIDHigh, 8);
    //appendLittleEndian(clientIDLow, 8);
    appendLE2Buffer(buffer,version,1);
    //appendLittleEndian(version, 1);
    appendLE2Buffer(buffer, messageCode, 2);
    //appendLittleEndian(messageCode, 2);
    appendLE2Buffer(buffer, payloadSize, 4);
    //appendLittleEndian(payloadSize, 4);

    // Append payload(Name)
    buffer.insert(buffer.end(), payload.begin(), payload.end());

    // create public key and private key with cpp, put in a function inside the class
    // change the parsing in the python? not sure
    buffer.insert(buffer.end(), _publicKey.begin(), _publicKey.end());

    std::string res = std::string(buffer.begin(), buffer.end());
    // Convert to std::string (assuming payload is text; adjust if handling binary data)
    //writeMeFileData(Name, uuid);
    return res;
}

// set publi
void SendPublicKeyMessageState::setPublicKey(const std::string& publicKey) {
    _publicKey = publicKey;
}

// get public key
std::string SendPublicKeyMessageState::getPublicKeyAsStr()
{
    return _publicKey;
}