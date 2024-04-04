#ifndef STATE_HPP
#define STATE_HPP

#include <string>
#include <vector>

#define MAX_BUFFER_SIZE 2048

//for unpack
struct ResponseContent {
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
    std::vector<uint8_t> payload;
};

//states ids enum
enum STATE_NAME{REGISTER, SEND_PUBLIC_KEY};

class State {
public:
    virtual ~State() = default;

    // Setters
    void setClientIDHigh(unsigned long long clientIDHigh);
    void setClientIDLow(unsigned long long clientIDLow);
    void setVersion(unsigned char version);
    void setMessageCode(unsigned short messageCode);

    // Getters
    unsigned long long getClientIDHigh() const;
    unsigned long long getClientIDLow() const;
    unsigned char getVersion() const;
    unsigned short getMessageCode() const;

    virtual std::string createMessage(const std::string& payload) = 0;

    int sendMessage(std::string message);

    int getAnswer(char* buffer, unsigned int* buffer_real_size);

    //template<typename T>
    void appendLE2Buffer(std::vector<unsigned char>& buffer, unsigned char value, size_t numBytes);

    STATE_NAME GetStateName()
    {
        return _state_name;
    }
   

    // Function prototype
    ResponseContent unpackMessage(const std::vector<uint8_t>& data);

private:
    unsigned long long clientIDHigh = 0; // Defaults to 0
    unsigned long long clientIDLow = 0; // Defaults to 0
    unsigned char version = 0; // Defaults to 0
    unsigned short messageCode = 0; // Defaults to 0
protected:
    unsigned short _payloadSize;
    STATE_NAME  _state_name;//should exist for each state, look at the ENUM
};

#endif // STATE_HPP
