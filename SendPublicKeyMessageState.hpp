#ifndef SENDPUBLICKEYMESSAGESTATE_HPP
#define SENDPUBLICKEYMESSAGESTATE_HPP

#include "State.hpp"
#include <string>
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include <iostream>


class SendPublicKeyMessageState : public State {

private:
    RSAPrivateWrapper _rsapriv;//for crypto

    std::string _publicKey;
    char _publicKey_bytes[160];

public:
    //void hexify(const unsigned char* buffer, unsigned int length);
    SendPublicKeyMessageState() { _state_name = STATE_NAME::SEND_PUBLIC_KEY;};
    void createCryptoKeys(std::string& pubkeyOut, std::string& privkeyOut);
    std::string createMessage(const std::string& payload) override;     
    void writePrivateKeyToFile(const std::string& privateKey);
    void writeMeFileData(std::string& Name, std::string& uuid);
    // getters and setters of public key
    void setPublicKey(const std::string& publicKey);
    std::string getPublicKeyAsStr();
    //unsigned char* getPublicKeyAsBytes();
    //void setPublicKeyAsBytes(  char* publicKey);
    
};

#endif // SENDPUBLICKEYMESSAGESTATE_HPP
