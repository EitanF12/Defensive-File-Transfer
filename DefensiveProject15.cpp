#include <boost/asio.hpp>
#include <iostream>
#include <string>

using boost::asio::ip::tcp;

int main() {
    try {
        boost::asio::io_context io_context;

        tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve("127.0.0.1", "40000");

        tcp::socket socket(io_context);
        boost::asio::connect(socket, endpoints);

        // Prepare a message: 1 integer ID and a 24-char string
        unsigned int id = 1;
        std::string msg = "Hello from C++!";
        msg.resize(24, '\0');  // Ensure the string is exactly 24 chars long

        // Combine ID and message into a buffer
        std::vector<unsigned char> buffer(sizeof(id) + msg.size());
        memcpy(buffer.data(), &id, sizeof(id));
        memcpy(buffer.data() + sizeof(id), msg.data(), msg.size());

        // Send the structured message
        boost::asio::write(socket, boost::asio::buffer(buffer));

        // Receive echo
        size_t len = socket.read_some(boost::asio::buffer(buffer));
        std::cout << "Echo received: " << std::string(buffer.begin() + sizeof(id), buffer.begin() + len) << std::endl;
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}
