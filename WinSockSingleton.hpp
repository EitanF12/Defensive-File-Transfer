#pragma once
#ifndef WINSOCKSINGLETON_H
#define WINSOCKSINGLETON_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

class WinsockSingleton {
private:
    WSADATA wsaData;
    SOCKET ConnectSocket;
    bool isInitialized;

    // Private constructor for the singleton pattern
    WinsockSingleton();

    // Non-copyable and non-movable to enforce singleton
    WinsockSingleton(const WinsockSingleton&) = delete;
    WinsockSingleton& operator=(const WinsockSingleton&) = delete;
    WinsockSingleton(WinsockSingleton&&) = delete;
    WinsockSingleton& operator=(WinsockSingleton&&) = delete;

public:
    static WinsockSingleton& getInstance();
    ~WinsockSingleton();

    bool initialize(const std::string& ipAddress, const std::string& port);
    bool send(const char* buf, int len);
    int receive(char* buf, int len);
    void cleanup();
};

#endif // WINSOCKSINGLETON_H
