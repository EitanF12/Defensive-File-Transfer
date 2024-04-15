# PythonServer.py
from atexit import register
from cgi import print_directory
from re import U
import socket
import threading
from dataUtilities import *
from filesUtilitis import read_port_from_file
import os
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import binascii
from binascii import unhexlify


name_dict_lock = threading.Lock()
NameDictionary = dict() 

messageSize = 32


def convert_to_bytes(input_data):
    if isinstance(input_data, str):  # Check if input_data is a string
        return input_data.encode('utf-8')  # Convert string to bytes using UTF-8 encoding
    elif isinstance(input_data, bytes):  # Check if input_data is already bytes
        return input_data
    else:
        raise TypeError("Input data must be a string or bytes array")

def print_string_in_hex_format(input_string):
    hex_string = ""
    for i in range(0, len(input_string), 2):
        hex_string += input_string[i:i+2] + " "
        if (i + 2) % (16 * 2) == 0:  # Check if 116 pairs have been processed
            hex_string += "\n"
    print(hex_string.strip())  # Remove trailing space
    

def write_bytes_in_hex_format(input_bytes, file):
    hex_string = ""
    for i in range(0, len(input_bytes)):
        hex_string += "{:02x} ".format(input_bytes[i])
        if (i + 1) % 16 == 0:  # Check if 16 bytes have been processed
            hex_string += "\n"
    file.write(hex_string.strip() + "\n")  # Remove trailing space and write to file



def extract_string_from_buffer(data):
    string = b""
    index = 0
    limit = len(data)
    # Iterate through the buffer until a null terminator is found
    while index < limit and data[index:index+1] != b'\0':
        string += data[index:index+1]
        index += 1
    
    return string.decode('utf-8')  # Decode bytes to string



def add_name(uuid, name):#safe from deadlock adding to Name Dictonary
    global NameDictionary
    with name_dict_lock:  # Ensure thread-safe write access
        modified_name = name #.decode('utf-8').rstrip('0')#encode to utf-8 and remove trailing zeros
        NameDictionary[modified_name] = uuid


def get_uuid_by_name(name):
    with name_dict_lock:  # Ensure thread-safe read access
        # Check if name is bytes and decode if necessary
        if isinstance(name, bytes):
            name = name.decode('utf-8')
        # Remove trailing zeros
        modified_name = name.rstrip('0')
        # Return the UUID associated with the modified name
        return NameDictionary.get(modified_name, "")
    return NameDictionary.get(modified_name, "")


def encrypt_message(public_key, message):
    # Construct RSA public key
    modulus = public_key // (2 ** 128)
    exponent = public_key % (2 ** 128)
    rsa_key = RSA.construct((modulus, exponent))

    # Create cipher using the public key
    cipher = PKCS1_OAEP.new(rsa_key)

    # Encrypt the padded message
    encrypted_message = cipher.encrypt(message, messageSize)

    return encrypted_message

    
def handle_client(connection):
    iteration = 1
    encrypted_file = []
    try:        
        #it is not true it is sequential for each client

        while True:
            print("iteration number: ",iteration)
            #if iteration == 100:#currentely this is my way 
            #    break
            
            header = connection.recv(23)#at the second iteration it recieves nothing
            if not header:
                print("Connection closed by the client")
                break
            
            response = bytes()
            handler = StateHandler()

            parts = handler.unpack_message(header)#unpacks only header
            payload_size = parts['PayloadSize']
            payload = b''
            while len(payload) < payload_size:
                # Receive the remaining payload bytes
                chunk = connection.recv(payload_size - len(payload))
                if not chunk:
                    raise Exception("Connection lost while receiving the payload")
                payload += chunk
            
            print("recieved payload ",payload)
            print("Unpack suceeded parts are:\n", parts,"\nunpacked recieved message\n")
            code_value = parts['Code']
            if code_value == 1025:
                # extract from payload the name, name is found at he beginning and null terminated
                Name = extract_string_from_buffer(payload)
                #do something with name

                uuid = 0#init of uuid
                #if Name doesn't exist
                if get_uuid_by_name(Name) == "":
                    uuid = handler.getUUID()
                    add_name(uuid,Name)#adds to name dictonary
                    response = handler.pack_message(parts['Version'],1600,16,uuid)#response 
                    print("pack parts before sent are:\n","version: ", parts['Version'],"code: ",1600,"payloadSize: ",16,"uuid: ",uuid)
                    #print_string_in_hex_format(str(uuid).hex())
                    # output uuid as char array
                                                    
                else:#fail maybe it will be for reconnect
                    response = handler.pack_message(parts['Version'],1601,0,"")#there is no payload
                    print("pack parts before sent are:\n","version: ", parts['Version'],"code: ",1601,"payloadSize: ",0,"no payload")
                    
                # create registerData
                connection.sendall(response)  # Echo back received data (modify as needed)
                print("server responded to 1025 message")
                
            elif code_value == 1026:
                parts_payload = unpack_payload_Public_Key(payload)#parses to {"Name": name, "publicKey": public_key_hex}
                Name = extract_string_from_buffer(parts_payload["Name"].encode('utf-8'))
                print("Name in parsed send public key", Name)
                
                public_key_pem = parts_payload["publicKey"]                
                
                print("public key in server", public_key_pem)
                public_key_2 = public_key_pem.hex();
                print_string_in_hex_format(public_key_pem.hex())
                # Load the public key
                
                #public_key_2 = str(public_key_2) 
                #encodedutfpublic_key = public_key_pem.encode('utf-8')
                #print("encodedutfpublic_key",encodedutfpublic_key)
                
                #encoded64public_key = base64.b64decode(encodedutfpublic_key)
                #print("encoded64public_key",encoded64public_key)
                public_key_pem=str(public_key_pem)
                #public_key_pem = "-----BEGIN PUBLIC KEY-----\n"+public_key_2 +"\n-----END PUBLIC KEY-----\n"
                #key_bytes = bytes.fromhex(public_key_2)
                key_bytes = public_key_2
                #print_string_in_hex_format(key_bytes.hex())
                #public_key = RSA.import_key(public_key_pem)

                public_key_der = unhexlify(public_key_2)
                public_key = RSA.import_key(public_key_der)
                                
                # Encrypt the AES key with the RSA public key
                aes_key = get_random_bytes(messageSize)#create some aes key of messageSize bytes             
                print("aes_key =")
                print_string_in_hex_format(aes_key.hex())
                # Load the public key
                
                # Encrypt the AES key with the RSA public key
                cipher_rsa = PKCS1_OAEP.new(public_key)
                encrypted_aes_key = cipher_rsa.encrypt(aes_key)

                # Optionally, you can base64 encode the encrypted key for transmission
                encoded_aes_key = base64.b64encode(encrypted_aes_key)
                encoded_aes_key = encrypted_aes_key
                uuid = get_uuid_by_name(Name)
                version = parts['Version']
                # Convert uuid to bytes with little endian byte order and 16 bytes size
                uuid_bytes = uuid.to_bytes(16, 'little')#converts to bytes in little endian format
                #calc length of uuid and encoded_aes_key
                payloadSize = len(encoded_aes_key) + len(uuid_bytes)

                # Concatenate uuid_bytes and encoded_aes_key
                payloadContent = uuid_bytes + encoded_aes_key
                #send uuid in little endian format and then the encrypted aes key
                response = handler.pack_message(version,1602,len(payloadContent), payloadContent)#code 1602 look at the protocol
                #there is no creation still from the example in the client

                print("Encrypted and encoded AES key:", encoded_aes_key)
                print_string_in_hex_format(encoded_aes_key.hex())

                connection.sendall(response)  # Echo back received data (modify as needed)
                print("server responded to 1026 message")
                
            elif code_value == 1028:
                print("1028")
                #response = handler.pack_message(version,1603,0, "")#code 1603 look at the protocol
                #connection.sendall(response) 
                payload_data = unpack_payload_Encrypted_Message(payload)
                encrypted_file.append(payload_data['encryptedFileData'])
                bencrypted = convert_to_bytes(payload_data['encryptedFileData'])
                with open("pyencrypt.txt", "a") as file:
                        write_bytes_in_hex_format(bencrypted, file)   

                if(payload_data['currentFilePart'] == payload_data['totalFileParts'] - 1):
                   # decrypt file

                   decrypted_file = decrypt_aes(encrypted_file,aes_key) 
                   with open("pydecrypt.txt", "w") as file:
                        write_bytes_in_hex_format(decrypted_file, file)                  
                   #print(decrypted_file)
                   # calculate checksum
                   chksum = memcrc(decrypted_file)
                   # create message with the checksum
                   uuid_val = parts['ClientIDHigh'] + parts['ClientIDLow']
                   payloadContent = uuid_val.to_bytes(16, 'little')
                   dec_file_size = len(decrypted_file)
                   bytes_file_size = dec_file_size.to_bytes(4, 'little')
                   payloadContent = payloadContent + bytes_file_size
                   payloadContent = payloadContent + payload_data['fileName']
                   payloadContent = payloadContent + chksum.to_bytes(4, 'little')
                   #response = handler.pack_message(version,1603,0, "")#code 1603 look at the protocol
                   response = handler.pack_message(version,1603,len(payloadContent), payloadContent)#code 1603 look at the protocol
                   connection.sendall(response)  # Echo back received data (modify as needed)
                   print("server responded to 1028 message")
                   # send the message to client 
               
            else:
                print("wrong code: "+ str(code_value))
            #I need to understand if I want to check that with the set state and how to make it work,
            #in the right stage I should start reading the file
            #print("send to client")
            #connection.sendall(registerData)  # Echo back received data (modify as needed)
            #print("server responded")
            #iteration = iteration + 1
                 
    finally:
        connection.close()

def start_server(host='127.0.0.1', port = 1256):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port}")
        while True:
            client, addr = server_socket.accept()
            print(f"Connection from {addr}")
            #threading.Thread(target=handle_client, args=(client,)).start()
            handle_client(client)

if __name__ == '__main__':
    
    portFromFile = read_port_from_file()
    start_server(port = portFromFile)
