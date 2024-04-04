#include "WinsockSingleton.hpp"
#include <iostream>

// Private constructor
WinsockSingleton::WinsockSingleton() : ConnectSocket(INVALID_SOCKET), isInitialized(false) {
    // Initialize Winsock
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed with error: " << result << std::endl;
    }
    else {
        isInitialized = true;
    }
}

// Destructor
WinsockSingleton::~WinsockSingleton() {
    cleanup();
}

// Singleton instance accessor
WinsockSingleton& WinsockSingleton::getInstance() {
    static WinsockSingleton instance;
    return instance;
}

// Initialize socket connection
bool WinsockSingleton::initialize(const std::string& ipAddress, const std::string& port) {
    if (!isInitialized) {
        return false;
    }

    struct addrinfo* result = nullptr, hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    int iResult = getaddrinfo(ipAddress.c_str(), port.c_str(), &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed with error: " << iResult << std::endl;
        WSACleanup();
        return false;
    }

    // Create a SOCKET for connecting to the server
    ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

    // Attempt to connect to an address until one succeeds
    for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            std::cerr << "socket failed with error: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return false;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        std::cerr << "Unable to connect to server!" << std::endl;
        WSACleanup();
        return false;
    }

    return true;
}

// Send data
bool WinsockSingleton::send(const char* buf, int len) {
    int bytesSent = ::send(ConnectSocket, buf, len, 0);
    if (bytesSent == SOCKET_ERROR) {
        std::cerr << "Send failed: " << WSAGetLastError() << std::endl;
        return false;
    }
    return true;
}


// Receive data
int WinsockSingleton::receive(char* buf, int len) {
    int bytesReceived = recv(ConnectSocket, buf, len, 0);
    if (bytesReceived == SOCKET_ERROR) {
        std::cerr << "Receive failed: " << WSAGetLastError() << std::endl;
        return -1;
    }
    else if (bytesReceived == 0) {
        std::cout << "Connection closed by the server." << std::endl;
        return 0;
    }
    return bytesReceived;
}

// Cleanup resources
void WinsockSingleton::cleanup() {
    if (ConnectSocket != INVALID_SOCKET) {
        closesocket(ConnectSocket);
    }
    if (isInitialized) {
        WSACleanup();
        isInitialized = false;
    }
}
