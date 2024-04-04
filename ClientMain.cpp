//#include <boost/asio.hpp>
#include <iostream>
#include <vector>
#include <cstring>
#include <direct.h>

#include "RegisterMessageState.hpp"
#include "SendPublicKeyMessageState.hpp"
#include "MessageHandler.hpp"
#include "InitState.hpp"
#include "ConfigData.hpp"
#include <filesystem>
#include <boost/asio/buffer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/detail/throws.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/placeholders.hpp>
#include "WinSockSingleton.hpp"

namespace fs = std::filesystem;

void printPayloadAsChars(const std::vector<unsigned char>& payload) {
    for (unsigned char c : payload) {
        std::cout << c;
    }
    std::cout << std::endl;
}

int main() {

    //I should read the connection info from a file, do this function in a utilitis file with many more function as needed(create)
    try {

        bool success;
        char buffer[MAX_BUFFER_SIZE];
        unsigned int realSize = 0;
        char buff[_MAX_PATH];
        char* ch = _getcwd(buff, _MAX_PATH);
        std::cout << "Current working directory: " << buff << std::endl;


        //create message for the first state which is register
        ConfigData& config = ConfigData::getInstance();
        config.LoadTransferFileData("x64\\Debug\\transfer.info.txt");
        //config.LoadMeFileData("x64\\Debug\\me.info.txt");

        WinsockSingleton& client = WinsockSingleton::getInstance();

        client.initialize(config.getInstance().getTransferFileData().serverAddress, config.getInstance().getTransferFileData().serverPort);

        std::string Name = config.getInstance().getTransferFileData().clientName;

        MessageHandler* mh = new MessageHandler();

        State* registerMessageState = new RegisterMessageState();
        registerMessageState->setClientIDHigh(0x0000000000000000LL); // High part of 128-bit value set to 0
        registerMessageState->setClientIDLow(0x0000000000000000LL);  // Low part of 128-bit value set to 0

        registerMessageState->setVersion(3);
        registerMessageState->setMessageCode(1025);

        std::string payload(255, '0');
        payload.back() = '\0';//the last char is \0 now

        // Check if the name is less than 255 characters
        if (Name.length() < 255) {
            // Copy 'name' into the beginning of 'payload'
            // Replace from index 0, replace 'name.length()' characters in 'payload' with 'name'
            payload.replace(0, Name.length(), Name);
        }
        else {
            std::cerr << "Error: Name must be less than 255 characters." << std::endl;
            return -1; // Or handle error as appropriate
        }

        std::string msg_str = registerMessageState->createMessage(payload);
        std::cout << "created message: " << msg_str << std::endl;

        mh->setState(registerMessageState);
        registerMessageState->sendMessage(msg_str);
        //until here it works
        int iteration = 0;

        while (1)
        {
            if (iteration == 3)
            {
                break;
            }
            success = mh->getState()->getAnswer(buffer, &realSize);//each state have his own get answer, it will work for all of them
            // unpack buffer

            std::vector<unsigned char> vecWithNull(buffer, buffer + realSize);

            ResponseContent response = mh->getState()->unpackMessage(vecWithNull);
            //for debug
            std::cout << "code in client" << response.code << std::endl;
            std::cout << "payload: " << std::endl;
            printPayloadAsChars(response.payload);
            std::cout << "payloadSIze in client" << response.payloadSize << std::endl;
            std::cout << "version in client" << response.version << std::endl;

            if (response.code == 1601)
            {
                //if(mh->getState()->GetStateName()==STATE_NAME::REGISTER)
                std::cout << "error an with responded server " << std::endl;
            }
            else if (response.code == 1600)
            {
                if (mh->getState()->GetStateName() == STATE_NAME::REGISTER)
                {
                    std::cout << "received answer from server for register" << std::endl;

                    // transit to SendPublicKey state
                    State* sendPublicKeyMsgState = new SendPublicKeyMessageState();
                    sendPublicKeyMsgState->setClientIDHigh(0x0000000000000000LL); // High part of 128-bit value set to 0
                    sendPublicKeyMsgState->setClientIDLow(0x0000000000000000LL);  // Low part of 128-bit value set to 0

                    sendPublicKeyMsgState->setVersion(3);
                    sendPublicKeyMsgState->setMessageCode(1026);

                    std::cout << "IDHIGH in client" << 0x0000000000000000LL << std::endl;
                    std::cout << "IDLOW in client" << 0x0000000000000000LL << std::endl;
                    std::cout << "version in client" << 3 << std::endl;
                    std::cout << "Code in client" << 1026 << std::endl;

                    msg_str = sendPublicKeyMsgState->createMessage(payload);//name is payload, public key is created inside
                    //state change
                    mh->setState(sendPublicKeyMsgState);
                    sendPublicKeyMsgState->sendMessage(msg_str);
                }

            }
            iteration++;
        }
    }
    catch (const std::exception& e) {
            std::cerr << "Standard exception: " << e.what() << std::endl;
            return -1;
    }
        

    return 0;
}
