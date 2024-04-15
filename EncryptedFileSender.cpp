#include "EncryptedFileSender.hpp"
#include <fstream>
#include <iostream>
#include <vector>

EncryptedFileSender::EncryptedFileSender() 
{
    _state_name = STATE_NAME::SEND_ENCRYPTED_FILE;
    _current_packet = 0;
    _partSize = 1024;
};


// implementation of isAllPacketsSent
bool EncryptedFileSender::isAllPacketsSent() {
    return (_current_packet < _packets_total_number);
}


std::string EncryptedFileSender::extractPart(int i) {
    int startIndex = i * _partSize;
    int endIndex = std::min((unsigned int)((i + 1) * _partSize), _encrypted_file_size);
    return _encrypted_file_data.substr(startIndex, endIndex - startIndex);
}

// implement get for check_sum
unsigned long EncryptedFileSender::getCheckSum() {	
    return _check_sum;
}

unsigned long EncryptedFileSender::memcrc(char* b, size_t n) {
    unsigned int v = 0, c = 0;
    unsigned long s = 0;
    unsigned int tabidx;

    for (int i = 0; i < n; i++) {
        tabidx = (s >> 24) ^ (unsigned char)b[i];
        s = UNSIGNED((s << 8)) ^ crctab[tabidx];
    }

    while (n) {
        c = n & 0377;
        n = n >> 8;
        s = UNSIGNED(s << 8) ^ crctab[(s >> 24) ^ c];
    }
    _check_sum = (unsigned long)UNSIGNED(~s);
    return _check_sum;
}


void EncryptedFileSender::encryptFile(const std::string& filename, std::string aes_key_str)
{
    std::vector<unsigned char> fileData = fileToByteArray(filename);
	std::string fileDataString(fileData.begin(), fileData.end());
    
    memcrc((char*)fileData.data(), (size_t)fileData.size());
   
    //save to file fileDataString as hexified string
    std::ofstream ofstr("fileDataString.txt");   
    hexify(reinterpret_cast<const unsigned char*>(fileDataString.c_str()), fileDataString.size(), ofstr);

    AESWrapper aes_key((const unsigned char*)aes_key_str.c_str(), aes_key_str.size());
    //setAesKey(aes_key);
    // 2. encrypt a message (plain text)
    _encrypted_file_data = aes_key.encrypt(fileDataString.c_str(), fileDataString.size());
   // std::cout << "Cipher:" << std::endl;
    _encrypted_file_size = _encrypted_file_data.size();
    // get the number of packets
    _packets_total_number = (_encrypted_file_size + _partSize - 1) / _partSize;
    //hexify(reinterpret_cast<const unsigned char*>(_encrypted_file_data.c_str()), _encrypted_file_size); 
    // check sum calculation

   

    // test
    // save decrypted data to file in hexified form
    std::ofstream ofstr3("decrypted.txt");
    hexify(reinterpret_cast<const unsigned char*>(_encrypted_file_data.c_str()), _encrypted_file_data.size(), ofstr3);

    // decrypt and save to file in hexified form
    std::string decrypted_file_data= aes_key.decrypt(_encrypted_file_data.c_str(), _encrypted_file_data.size());
    std::ofstream ofstr2("fileDataString2.txt");
    //ofstr2 << decrypted_file_data;
    hexify(reinterpret_cast<const unsigned char*>(decrypted_file_data.c_str()), decrypted_file_data.size(), ofstr2);
}


std::string EncryptedFileSender::getPrivateKey(const std::string& filename) 
{
    	std::ifstream ifstr(filename);
        if (!ifstr) {
            std::cerr << "Failed to open the file." << filename<<std::endl;
            return "Failed to open the file." + filename;
        }
        std::string privateKey;

        ifstr >> privateKey;
        ifstr.close();
        return privateKey;
}


std::vector<unsigned char> EncryptedFileSender::fileToByteArray(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return std::vector<unsigned char>(); // Return an empty vector
    }

    std::streamsize size = file.tellg(); // Get file size
    file.seekg(0, std::ios::beg); // Move file pointer back to the beginning

    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "Error reading file: " << filename << std::endl;
        return std::vector<unsigned char>(); // Return an empty vector
    }
    _init_file_size = size;
    return buffer;
}

// implement get current payload size
unsigned int EncryptedFileSender::GetCurrentPyloadSize() {
    unsigned int current_payload_size = 0;
    current_payload_size += 4;// ContentSize
    current_payload_size += 4;// Orig File Size
    current_payload_size += 4;// Packet number (2 bytes) + (2 bytes)
    current_payload_size += 255;// Name
    if (_current_packet == _packets_total_number - 1) {
        current_payload_size += (_encrypted_file_data.size() - _current_packet * _partSize);
    }
    else {
        current_payload_size += _partSize;
    }
    return current_payload_size;
}


std::string EncryptedFileSender::createMessage(const std::string& user_name) {

	unsigned short messageCode = getMessageCode();    
    unsigned int version = getVersion();
    unsigned int payloadSize = GetCurrentPyloadSize();

    // Append fields in little-endian order 
    // header
    std::vector<unsigned char> buffer = getClientID(); // client ID, size =16
    appendLE2Buffer(buffer, version,1);
    appendLE2Buffer(buffer, messageCode, 2);
    appendLE2Buffer(buffer, payloadSize, 4);
    // header size 16+ 1 + 2 + 4 = 23

    unsigned int contentSize = 0;
    //create payload
    appendLE2Buffer(buffer, _encrypted_file_size, 4);    
    contentSize += 4;
    appendLE2Buffer(buffer, _init_file_size, 4);
contentSize += 4;
    appendLE2Buffer(buffer, _current_packet, 2);
contentSize += 2;
    appendLE2Buffer(buffer, _packets_total_number, 2);
contentSize += 2;
    appendStringLE2Buffer(buffer, user_name, 255);
contentSize += 255;
    std::string currentPart = extractPart(_current_packet);
    appendStringLE2Buffer(buffer, currentPart, currentPart.size());
 //contentSize += currentPart.size();

    //convert buffer to string   
    std::string res = std::string(buffer.begin(), buffer.end());
    _current_packet++;
    return res;	
}
