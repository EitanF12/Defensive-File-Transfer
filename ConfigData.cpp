#include "ConfigData.hpp"
#include <fstream>
#include <stdexcept>

ConfigData& ConfigData::getInstance() {
    static ConfigData instance;
    return instance;
}

void ConfigData::LoadTransferFileData(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }

    std::string line;
    std::getline(file, line);
    std::size_t colonPos = line.find(':');
    if (colonPos == std::string::npos) {
        throw std::runtime_error("Server address and port must be separated by a colon.");
    }
    transferData.serverAddress = line.substr(0, colonPos);
    transferData.serverPort =  line.substr(colonPos + 1);

    std::getline(file, transferData.clientName);
    std::getline(file, transferData.filePath);
}

void ConfigData::LoadMeFileData(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }

    std::getline(file, meData.name);
    std::getline(file, meData.sequenceOne);
    std::getline(file, meData.sequenceTwo);
}

TransferFileData ConfigData::getTransferFileData() const {
    return transferData;
}

MeFileData ConfigData::getMeFileData() const {
    return meData;
}

