//#include <boost/asio.hpp>
#include <iostream>
#include <vector>
#include <cstring>
#include <direct.h>

#include "RegisterMessageState.hpp"
#include "SendPublicKeyMessageState.hpp"
#include "EncryptedFileSender.hpp"  
#include "MessageHandler.hpp"
#include "InitState.hpp"
#include "ConfigData.hpp"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include "RSAEncryptorDecryptor.hpp"
#include <filesystem>
#include <boost/asio/buffer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/detail/throws.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/placeholders.hpp>
#include "WinSockSingleton.hpp"



const unsigned int KEY_SIZE = 2048;
const unsigned int BLOCK_SIZE = KEY_SIZE / 8; // 256 bytes for a 2048-bit key

//#include <iostream>
//#include <string>
#include <rsa.h>
#include <osrng.h>
#include <fstream>

namespace fs = std::filesystem;

void printPayloadAsChars(const std::vector<unsigned char>& payload) {
    for (unsigned char c : payload) {
        std::cout << c;
    }
    std::cout << std::endl;
}



void hexify(const unsigned char* buffer, unsigned int length)
{
    std::ios::fmtflags f(std::cout.flags());
    std::cout << std::hex;
    for (size_t i = 0; i < length; i++)
        std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
    std::cout << std::endl;
    std::cout.flags(f);
}

//read from priv.key.txt and write in in info.me.txt in the next order: first Name then then uuid from the file then private key from priv.key



int main() {
    

    //I should read the connection info from a file, do this function in a utilitis file with many more function as needed(create)
    try {

        bool success;
        char buffer[MAX_BUFFER_SIZE];
        unsigned int realSize = 0;
        char buff[_MAX_PATH];
        char* ch = _getcwd(buff, _MAX_PATH);
        std::cout << "Current working directory: " << buff << std::endl;
        //RSAEncryptorDecryptor* rsa = new RSAEncryptorDecryptor(); 

        // 1. Create an RSA decryptor. this is done here to generate a new private/public key pair
        RSAPrivateWrapper rsapriv;

        // 2. get the public key
        std::string pubkey = rsapriv.getPublicKey();
        ResponseContent response;
        char pubkeybuff[RSAPublicWrapper::KEYSIZE]; // public key as char buffer  
        rsapriv.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);

        hexify(reinterpret_cast<const unsigned char*>(pubkeybuff), RSAPublicWrapper::KEYSIZE);


        

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
       

        // Check if the name is less than 255 characters
        if (Name.length() < 255) {
            //add null terminated character to name
            Name.push_back('\0');// Ensure the string is null-terminated
           
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
        std::cout << "msg_str:" << std::endl;
        hexify(reinterpret_cast<const unsigned char*>(msg_str.c_str()), msg_str.length());
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

            response = mh->getState()->unpackMessage(vecWithNull);
            //for debug
            std::cout << "code in client" << response.code << std::endl;
            std::cout << "payload: ";
            printPayloadAsChars(response.payload);

            std::string str_payload = std::string(response.payload.begin(), response.payload.end());
            std::cout << "payload in client" << str_payload << std::endl;
            std::cout << "payload hexifyed: ";
            mh->getState()->hexify(response.payload.data(), response.payload.size());

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
                    
                    //sendPublicKeyMsgState->setClientIDHigh(0x0000000000000000LL); // High part of 128-bit value set to 0
                    //sendPublicKeyMsgState->setClientIDLow(0x0000000000000000LL);  // Low part of 128-bit value set to 0
                    //put in little endian order the response.payload which is the uuid from the server in ClientIDHigh and ClientIDLow in 4 lines
                    //std::string uuid(response.payload.begin(), response.payload.end());
                    //sendPublicKeyMsgState->setClientIDLow(std::stoull(uuid.substr(16, 16), nullptr, 16));
                    //sendPublicKeyMsgState->setClientIDHigh(std::stoull(uuid.substr(0, 16), nullptr, 16));
                    sendPublicKeyMsgState->setClientID(response.payload);
                    sendPublicKeyMsgState->setVersion(3);
                    sendPublicKeyMsgState->setMessageCode(1026);
                    //make response.payload a string
                    //std::string str_uuid(response.payload.begin(), response.payload.end());
                    dynamic_cast<SendPublicKeyMessageState*>(sendPublicKeyMsgState)->setPublicKey(pubkey);
                    std::cout << "public key in client before sending to server: " <<  pubkey << std::endl;
                    std::string pub64key = Base64Wrapper::encode(pubkey);
                    std::cout << "public key in client before sending to server in base64: " << pub64key << std::endl;

                    std::string priv64key = Base64Wrapper::encode(rsapriv.getPrivateKey());
                    std::cout << "private key in client before sending to server in base64: " << priv64key << std::endl;

                    mh->getState()->hexify(reinterpret_cast<const unsigned char*>(pubkeybuff), RSAPublicWrapper::KEYSIZE);

//write public key to file

                    std::ofstream publicKeyFile("public.txt");
                    if (publicKeyFile.is_open()) {
                        publicKeyFile << pubkey;
                        publicKeyFile.close();
                        std::cout << "Public key saved to 'public.txt'." << std::endl;
                    }
                    else {
                        std::cerr << "Unable to open public key file for writing." << std::endl;
                        return 1;
                    }
                    std::ofstream privKeyFile("priv.key.txt");
                    if (privKeyFile.is_open()) {
                        privKeyFile << rsapriv.getPrivateKey();
                        privKeyFile.close();
                        std::cout << "Private key saved to 'priv.key.txt'." << std::endl;
                    }
                    else {
                        std::cerr << "Unable to open private key file for writing." << std::endl;
                        return 1;
                    }
                    //rsa->savePrivateKeyToFile("priv.key.txt");
                    msg_str = sendPublicKeyMsgState->createMessage(payload);//name is payload, public key is created inside
                    std::cout << "msg_str:" << std::endl;
                    hexify(reinterpret_cast<const unsigned char*>(msg_str.c_str()), msg_str.length());
                    //state change
                    mh->setState(sendPublicKeyMsgState);
                    sendPublicKeyMsgState->sendMessage(msg_str);
                    //Name, response.uuid, response.privateKey

                    //use writeMeFileData with Name as Name and uuid as uuid
                    
                }
            }

            else if (response.code == 1602)
            {
                std::cout << "message with id  1602 was accepted!" << std::endl;
                if (mh->getState()->GetStateName() == STATE_NAME::SEND_PUBLIC_KEY)
                {
                    std::string msg_str_efs;
                    std::cout << "received answer from server for send public key" << std::endl;
                    // transit to Init state
                    State* encryptedFileSender = new EncryptedFileSender();                   
                    encryptedFileSender->setVersion(3);
                    encryptedFileSender->setMessageCode(1028);
                    
                    // retrieve private key and decrypt payload (encrypted with public AES symmetric key)
                    //bool success = rsa->loadPrivateKeyFromFile("priv.key.txt");
                    //make the first 16 bytes of the payload the uuid and the rest the encrypted AES key
                    std::vector<unsigned char> uuid(response.payload.begin(), response.payload.begin() + 16);
                    encryptedFileSender->setClientID(uuid);

                    /*
                    msg_str_efs = encryptedFileSender->createMessage(payload); // create payload according to _current_packet class member
                    mh->setState(encryptedFileSender);
                    std::cout << "msg_str_efs:" << std::endl;
                    hexify(reinterpret_cast<const unsigned char*>(msg_str_efs.c_str()), msg_str_efs.length());
                    encryptedFileSender->sendMessage(msg_str_efs);
                    */
                    
                    std::vector<unsigned char> encryptedAESKey(response.payload.begin() + 16, response.payload.end());
                    //response gets 16+128 bytes, first 16 are uuid and 128 are encrypted AES key
                                                        
                    std::string strEncryptedAESKey(encryptedAESKey.begin(), encryptedAESKey.end());
                    std::string base64key = Base64Wrapper::encode(rsapriv.getPrivateKey());

                    // 5. create another RSA decryptor using an existing private key (decode the base64 key to an std::string first)
                    RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(base64key));
                    std::cout << "cipher:" << std::endl;
                    //mh->getState()->hexify((unsigned char*)strEncryptedAESKey.c_str(), strEncryptedAESKey.length());	// print binary data nicely
                    std::string decrypted = rsapriv_other.decrypt(strEncryptedAESKey);		// 6. you can decrypt an std::string or a const char* buffer
                    std::cout << "decrypted:" << std::endl;
                    mh->getState()->hexify((unsigned char*)decrypted.c_str(), decrypted.length());	// print binary data nicely

                    dynamic_cast<EncryptedFileSender*>(encryptedFileSender)->encryptFile(config.getTransferFileData().filePath, decrypted);  
                                        
                    // set current state to encryptedFileSender and send first part of file  
                    msg_str_efs = encryptedFileSender->createMessage(payload); // create payload according to _current_packet class member
                    mh->setState(encryptedFileSender);
                    encryptedFileSender->sendMessage(msg_str_efs);
                     
                    while (dynamic_cast<EncryptedFileSender*>(encryptedFileSender)->isAllPacketsSent()) {
                        msg_str_efs = encryptedFileSender->createMessage(payload); // create payload according to _current_packet class member
                        encryptedFileSender->sendMessage(msg_str_efs);
                        //msg_str_efs = "";
                    }
                    std::cout << "at the end of 1028 message" << std::endl;
                }
            }
            else if (response.code == 1603)
            {
                std::cout << "message with id  1603 was accepted!" << std::endl;
                if (mh->getState()->GetStateName() == STATE_NAME::SEND_ENCRYPTED_FILE)
                {
                    //accept the checksum accepted from the server
                    std::cout << "SEND_ENCRYPTED_FILE state" << std::endl;

                    // extract checksum from response.payload
                    // checksum begins at (16+4 +255)th byte, 4 bytes long
                    std::vector<unsigned char> checksum(response.payload.begin() + 16 + 4 + 255, response.payload.begin() + 16 + 4 + 255 + 4);
                    unsigned long checksumValue = *(unsigned long*)checksum.data();
                    std::cout << "Checksum: " << checksumValue << std::endl;

                    //compare with checksum on the client
                    unsigned long clientChecksum = dynamic_cast<EncryptedFileSender*>(mh->getState())->getCheckSum();
                    std::cout << "Client checksum: " << clientChecksum << std::endl;
                    //compare checksums
                    if (checksumValue == clientChecksum) {
						std::cout << "Checksums match." << std::endl;
					}
                    else {
						std::cout << "Checksums do not match." << std::endl;
					}
                    // if the same, send confirmation OK message

                    // else, if count of resends is 3 - send abort message
                    // else resend the encrypted file, count of resends ++                    
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

