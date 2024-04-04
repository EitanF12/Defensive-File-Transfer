#read file with all of the input in the output for the main of the server...
from msilib.schema import Directory
import os
from pathlib import Path

def read_port_from_file(filename="port.info.txt", default_port=1256):
    try:

        if not os.path.exists(filename):
            print(f"Warning: '{filename}' not found. Using default port {default_port}.")
            return default_port
        
        # Read the file
        with open(filename, 'r') as file:
            port_str = file.read().strip()
            # Try to convert the string to an integer
            port = int(port_str)
            if 1 <= port <= 65535:
                return port
            else:
                print(f"Warning: Port number in '{filename}' is out of valid range. Using default port {default_port}.")
                return default_port
    except Exception as e:
        print(f"Warning: An error occurred while reading '{filename}': {e}. Using default port {default_port}.")
        return default_port