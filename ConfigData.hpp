#pragma once
#ifndef CONFIG_DATA_HPP
#define CONFIG_DATA_HPP

#include <string>

// Struct for Transfer File data
struct TransferFileData {
    std::string serverAddress;
    std::string serverPort;
    std::string clientName;
    std::string filePath;
};

// Struct for Me File data
struct MeFileData {
    std::string name;
    std::string sequenceOne;
    std::string sequenceTwo;
};

class ConfigData {
public:
    ConfigData(const ConfigData&) = delete;
    ConfigData& operator=(const ConfigData&) = delete;
    static ConfigData& getInstance();

    // New method to load data for transfer file
    void LoadTransferFileData(const std::string& filename);
    // New method to load data for "me" file
    void LoadMeFileData(const std::string& filename);

    // Getters for the data
    TransferFileData getTransferFileData() const;
    MeFileData getMeFileData() const;

private:
    ConfigData() = default;

    TransferFileData transferData;
    MeFileData meData;
};

#endif // CONFIG_DATA_HPP


