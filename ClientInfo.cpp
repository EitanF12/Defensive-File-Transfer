#include "ClientInfo.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>

ClientInfo readClientInfo(const std::string& basePath) {
    std::string filePath = basePath + "\\me.info";
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filePath);
    }

    ClientInfo info;
    std::getline(file, info.name);
    std::getline(file, info.uniqueId);
    std::getline(file, info.privateKey);
    return info;
}

TransferInfo readTransferInfo(const std::string& basePath) {
    std::string filePath = basePath + "\\info.transfer";
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filePath);
    }

    TransferInfo info;
    std::string line;
    std::getline(file, line);
    std::size_t colonPos = line.find(':');
    if (colonPos == std::string::npos) {
        throw std::runtime_error("Server address and port must be separated by a colon.");
    }
    info.serverAddress = line.substr(0, colonPos);
    info.serverPort = std::stoi(line.substr(colonPos + 1));
    std::getline(file, info.clientName);
    std::getline(file, info.filePath);
    return info;
}
