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

name_dict_lock = threading.Lock()
NameDictionary = dict() 

def add_name(uuid, name):#safe from deadlock adding to Name Dictonary
    global NameDictionary
    with name_dict_lock:  # Ensure thread-safe write access
        NameDictionary[name] = uuid

def get_uuid_by_name(name):
    with name_dict_lock:  # Ensure thread-safe read access
        # Return "" if name is not found
        return NameDictionary.get(name, "")
    
def handle_client(connection):
    iteration = 1
    try:
        
        #it is not true it is sequential for each client
        while True:
            print("iteration number: ",iteration)
            if iteration == 3:#currentely this is my way 
                break
            
            header = connection.recv(23)
            if not header:
                print("Connection closed by the client")
                break
            
            response = bytes()
            handler = StateHandler()
            payload = b''
            
            parts = handler.unpack_message(header)#unpacks only header
            payload_size = parts['PayloadSize']
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
                Name = handler.remove_trailing_zeros(payload)
                #do something with name

                uuid = 0#init of uuid
                #if Name doesn't exist
                if get_uuid_by_name(Name) == "":
                    uuid = handler.getUUID()
                    add_name(uuid,Name)#adds to name dictonary
                    response = handler.pack_message(parts['Version'],1600,16,uuid)#response 
                    print("pack parts before sent are:\n","version: ", parts['Version'],"code: ",1600,"payloadSize: ",16,"uuid: ",uuid)
                else:#fail maybe it will be for reconnect
                    response = handler.pack_message(parts['Version'],1601,0,"")#there is no payload
                    print("pack parts before sent are:\n","version: ", parts['Version'],"code: ",1601,"payloadSize: ",0,"no payload")
                    
                # create registerData
                connection.sendall(response)  # Echo back received data (modify as needed)
                print("server responded to 1025 message")
                
            elif code_value == 1026:#no register here, register is in 1025 I just check if the UUID exists in memory
                parts = unpack_payload_Public_Key(payload)#parses to {"Name": name, "publicKey": public_key_hex}
                Name = handler.remove_trailing_zeros(parts["Name"])#cleans the zeroes from the end of 255 bytes of the name
                print("Name in parsed send public key", Name)
                
                public_key_pem = parts["publicKey"]
                aes_key = get_random_bytes(32)#create some aes key of 32 bytes
                print("public key", public_key_pem)
                # Load the public key
                public_key = RSA.import_key(public_key_pem)
                # Encrypt the AES key with the RSA public key
                cipher_rsa = PKCS1_OAEP.new(public_key)
                encrypted_aes_key = cipher_rsa.encrypt(aes_key)
                # Optionally, you can base64 encode the encrypted key for transmission
                encoded_aes_key = base64.b64encode(encrypted_aes_key)
                response = handler.pack_message(parts['Version'],1602,16,get_uuid_by_name[Name])#code 1602 look at the protocol
                #there is no creation still from the example in the client

                print("Encrypted and encoded AES key:", encoded_aes_key)

                connection.sendall(response)  # Echo back received data (modify as needed)
                print("server responded to 1026 message")

            else:
                print("wrong code")
            #I need to understand if I want to check that with the set state and how to make it work,
            #in the right stage I should start reading the file
            #print("send to client")
            #connection.sendall(registerData)  # Echo back received data (modify as needed)
            #print("server responded")
            iteration = iteration + 1
            
            

        
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
