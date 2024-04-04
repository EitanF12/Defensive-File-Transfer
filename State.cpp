#include "State.hpp"
#include <boost/asio.hpp>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include "ClientInfo.hpp"
#include "ConfigData.hpp"

#include "WinSockSingleton.hpp"

#pragma comment(lib, "Ws2_32.lib")


// Setters
void State::setClientIDHigh(unsigned long long clientIDHigh) {
    this->clientIDHigh = clientIDHigh;
}

void State::setClientIDLow(unsigned long long clientIDLow) {
    this->clientIDLow = clientIDLow;
}

void State::setVersion(unsigned char version) {
    this->version = version;
}

void State::setMessageCode(unsigned short messageCode) {
    this->messageCode = messageCode;
}

// Getters
unsigned long long State::getClientIDHigh() const {
    return clientIDHigh;
}

unsigned long long State::getClientIDLow() const {
    return clientIDLow;
}

unsigned char State::getVersion() const {
    return version;
}

unsigned short State::getMessageCode() const {
    return messageCode;
}

struct Message {
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
    std::vector<uint8_t> payload;
};


ResponseContent State::unpackMessage(const std::vector<uint8_t>& data) {
    if (data.size() < 7) { // Minimum size for version, code, and payloadSize
        throw std::runtime_error("Data too short.");
    }

    ResponseContent response;
    size_t offset_0 = 0;

    // Unpack version (1 byte)
    response.version = data[offset_0];
    //offset += 1;// sizeof(uint8_t);

    // Ensure little-endian for code and payloadSize
    // Unpack code (2 bytes)
    response.code = data[offset_0 +1] | (data[offset_0 + 2] << 8);
    //offset += sizeof(uint16_t);

    // Unpack payloadSize (4 bytes)
    response.payloadSize = data[offset_0 +3] |
        (data[offset_0 + 4] << 8) |
        (data[offset_0 + 5] << 16) |
        (data[offset_0 + 6] << 24);
    //offset += sizeof(uint32_t);

    // Verify that the remaining data matches payloadSize
    if (data.size() - (offset_0 +7) != response.payloadSize) {
        throw std::runtime_error("Payload size mismatch.");
    }

    // Unpack payload
    response.payload.insert(response.payload.end(), data.begin() + (offset_0 + 7), data.end());

    return response;
}


int State::sendMessage(std::string message)
{
    WinsockSingleton& client = WinsockSingleton::getInstance();
    return client.send(message.c_str(), message.size());

}

int State::getAnswer(char* buffer, unsigned int* buffer_real_size)
{
    //char buffer[2048];
    //unsigned int max_size = 2048;
    WinsockSingleton& client = WinsockSingleton::getInstance();
    int bytesReceived = client.receive(buffer, MAX_BUFFER_SIZE);

    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0'; // Ensure null-termination
        std::cout << "Received from server: " << buffer << std::endl;
        *buffer_real_size = bytesReceived;
        return true;
    }
    else if (bytesReceived == 0) {
        std::cout << "Connection closed by server." << std::endl;
    }
    else {
        std::cerr << "Receive failed." << std::endl;
    }
    return false;
}


void State::appendLE2Buffer(std::vector<unsigned char>& buffer, unsigned char value, size_t numBytes) {
    for (size_t i = 0; i < numBytes; i++) {
        if (i < sizeof(value)) {
            buffer.push_back((value >> (i * 8)) & 0xFF);
        }
        else {
            buffer.push_back(0); // Append zeros if beyond the size of value
        }
    }
}

/*
using boost::asio::ip::tcp;
int State::sendMessage(std::string message)
{
    boost::asio::io_context io_context;

    tcp::resolver resolver(io_context);
    std::string strIp = ConfigData::getInstance().getTransferFileData().serverAddress;
    std::string strPort = ConfigData::getInstance().getTransferFileData().serverPort;
    auto endpoints = resolver.resolve(strIp, strPort);

    tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);
    boost::asio::write(socket, boost::asio::buffer(message));

    return 0;

}

int State::getAnswer()
{
   
    int len;
    try {
        boost::asio::io_context io_context;

        tcp::resolver resolver(io_context);
        std::string strIp = ConfigData::getInstance().getTransferFileData().serverAddress;
        std::string strPort = ConfigData::getInstance().getTransferFileData().serverPort;
        auto endpoints = resolver.resolve(strIp, strPort);
        
        tcp::socket socket(io_context);
        boost::asio::connect(socket, endpoints);

        // Read welcome message
        boost::asio::streambuf receive_buffer;
        boost::asio::read_until(socket, receive_buffer, "\n");
        std::string message(boost::asio::buffer_cast<const char*>(receive_buffer.data()));
        std::cout << message;
        len = message.size();
        // Send message to server
        //std::string msg = "Hello from Client!\n";
        //boost::asio::write(socket, boost::asio::buffer(msg));

        // Wait and read the echo message
        //boost::asio::read_until(socket, receive_buffer, "\n");
        //message = std::string(boost::asio::buffer_cast<const char*>(receive_buffer.data()), receive_buffer.size());
        //std::cout << "Server echoed: " << message;
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return len;
}
*/