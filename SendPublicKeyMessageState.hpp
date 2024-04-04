#ifndef SENDPUBLICKEYMESSAGESTATE_HPP
#define SENDPUBLICKEYMESSAGESTATE_HPP

#include "State.hpp"
#include <string>
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include <iostream>
#include <iomanip>

class SendPublicKeyMessageState : public State {
public:
    void hexify(const unsigned char* buffer, unsigned int length);
    SendPublicKeyMessageState() { _state_name = STATE_NAME::SEND_PUBLIC_KEY;};
    void createCryptoKeys(std::string& pubkeyOut, std::string& privkeyOut);
    std::string createMessage(const std::string& payload) override; 
    RSAPrivateWrapper _rsapriv;//for crypto



};

#endif // SENDPUBLICKEYMESSAGESTATE_HPP
