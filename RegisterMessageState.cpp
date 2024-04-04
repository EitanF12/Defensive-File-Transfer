#include "RegisterMessageState.hpp"
#include <iostream>
#include <vector>
#include <boost/asio.hpp>

RegisterMessageState::RegisterMessageState() {
    // Constructor implementation
    _state_name = STATE_NAME::REGISTER;
}

std::string RegisterMessageState::createMessage(const std::string& payload) {
    unsigned short messageCode = getMessageCode();
    unsigned short payloadSize = payload.size();
    unsigned long long clientIDHigh = getClientIDHigh();
    unsigned long long clientIDLow = getClientIDLow();
    unsigned int version = getVersion();
    std::vector<unsigned char> buffer;

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
   /*
    appendLittleEndian(buffer,clientIDHigh,8);
    appendLittleEndian(buffer,clientIDLow,8);
    appendLittleEndian(buffer,version,1);
    appendLittleEndian(buffer,messageCode,2);
    appendLittleEndian(buffer,payloadSize,4);
    */
    appendLittleEndian(clientIDHigh, 8);
    appendLittleEndian(clientIDLow, 8);
    appendLittleEndian(version, 1);
    appendLittleEndian(messageCode, 2);
    appendLittleEndian(payloadSize, 4);

    // Append payload
    buffer.insert(buffer.end(), payload.begin(), payload.end());
    std::string res = std::string(buffer.begin(), buffer.end());
    // Convert to std::string (assuming payload is text; adjust if handling binary data)
    return res;
}