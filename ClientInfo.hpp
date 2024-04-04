#ifndef CLIENT_INFO_HPP
#define CLIENT_INFO_HPP

#include <string>

// Structure to hold client information
struct ClientInfo {
    std::string name;
    std::string uniqueId;
    std::string privateKey;
};

// Structure to hold transfer information
struct TransferInfo {
    std::string serverAddress;
    int serverPort;
    std::string clientName;
    std::string filePath;
};

// Declaration of function to read client information
ClientInfo readClientInfo(const std::string& basePath);

// Declaration of function to read transfer information
TransferInfo readTransferInfo(const std::string& basePath);

#endif // CLIENT_INFO_HPP
