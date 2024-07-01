Defensive File Transfer System
A file transfer system using a binary protocol, featuring a Python server and C++ clients. Supports multiple parallel connections, each with unique encryption keys, and includes checksum verification for data integrity.

The system utilizes Winsock for communication within a singleton object to manage connections efficiently. Additionally, the factory design pattern is employed to simplify the main function and ensure that each instruction behaves differently while using the same function names.

Features
Supports file transfer in any format up to 512 MB
Binary protocol for efficient communication
Python server handling multiple parallel connections
C++ clients with unique encryption keys for each connection
Checksum verification for data integrity
Winsock communication managed by a singleton object
Factory design pattern for simplified main function and distinct instruction behavior
SQL database support for allowing reconnections
Defensive programming to prevent buffer overflows
Vulnerability research of the protocol conducted at the end of the project
Usage

1.Ensure the following files are deleted on the client:
me.info
defensive.db

2.Run the server:
 in bash
python server.py

3.Run the client:
in bash
./client

4.To test reconnection, close the client and run it again:
in bash
./client
