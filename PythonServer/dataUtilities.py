import struct
from enum import Enum
import uuid
from Crypto.Cipher import AES
import sys




crctab = [ 0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc,
        0x17c56b6b, 0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f,
        0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a,
        0x384fbdbd, 0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
        0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8,
        0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
        0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e,
        0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
        0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84,
        0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027,
        0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022,
        0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
        0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077,
        0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c,
        0x2e003dc5, 0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1,
        0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
        0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb,
        0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
        0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d,
        0x40d816ba, 0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
        0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f,
        0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044,
        0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689,
        0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
        0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683,
        0xd1799b34, 0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59,
        0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c,
        0x774bb0eb, 0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
        0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e,
        0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
        0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48,
        0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
        0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2,
        0xe6ea3d65, 0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601,
        0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604,
        0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
        0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6,
        0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad,
        0x81b02d74, 0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7,
        0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
        0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd,
        0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
        0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b,
        0x0fdc1bec, 0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
        0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679,
        0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12,
        0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af,
        0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
        0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5,
        0x9e7d9662, 0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06,
        0xa6322bdf, 0xa2f33668, 0xbcb4666d, 
        0xb8757bda, 0xb5365d03,
        0xb1f740b4 ]

UNSIGNED = lambda n: n & 0xffffffff



# Define request and answer codes
class RequestCode(Enum):
    Register = 1025
    SendPublicKey = 1026
    ReRegister = 1027
    SendFile = 1028
    OkCRC = 1029
    FailCRC = 1030
    FinalFailCRC = 1031


# Message Header Class (defined once correctly)
class MessageHeader:
    HEADER_FORMAT = "<16sBHI"  # Correctly includes the format for network byte order
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    
    @staticmethod
    def unpack_header(binary_data):
        # Unpacks the first part of the binary data according to the HEADER_FORMAT
        return struct.unpack(MessageHeader.HEADER_FORMAT, binary_data[:MessageHeader.HEADER_SIZE])

# State Design Pattern Implementation
class MessageState:

    def __init__(self,binary_data):
        # Use MessageHeader to unpack the header portion of the message
        client_id, version, message_code, payload_size = MessageHeader.unpack_header(binary_data)#same unpack for everyone
        self.client_id = client_id
        self.version = version
        self.message_code = message_code
        self.payload_size = payload_size
        
        payload_data = binary_data[MessageHeader.HEADER_SIZE:]#everything left to the end (size header)
        
        # Use the current state to unpack the payload
        #self.state.unpack_payload(payload_data)

    def unpack_payload(self, payload_data):#implement the special unpack funciton
        raise NotImplementedError

class RegisterState(MessageState):
    def __init__(self, binary_data):
    # Call the superclass __init__ to handle common header processing
        super().__init__(binary_data)
        
    def unpack_payload(self, payload_data):#debug if it is implemented right
        # Assuming the payload for a Register message is a UTF-8 encoded string
        # that fits within the specified payload_size from the header.
        # Here, we decode it to a Python string.
        
        try:
            # Decode the payload as a UTF-8 string
            decoded_payload = payload_data.decode('utf-8').rstrip('\x00')
            
            # Process the decoded payload as needed for your application
            # For example, you could validate the content here
            
            # Return a structured representation of the payload
            # or any relevant information extracted from it
            return {
                "action": "Register",
                "data": decoded_payload #curentelly AAAAAA
            }
        
        except UnicodeDecodeError as e:
            # Handle potential decoding errors
            print(f"Error decoding payload: {e}")
            return None


"""
class SendPublicKeyState(MessageState):
    def __init__(self, binary_data):
     #Call the superclass __init__ to handle common header processing
       super().__init__(binary_data)
        
    def unpack_payload(self, payload_data):#
        # Your logic here
        return {"action": "SendPublicKey", "data": "..."}
"""
def little_endian_to_int(bytes_data):
    return int.from_bytes(bytes_data, byteorder='little')


def unpack_payload_Public_Key(payload_data):
    # Assuming the first 255 bytes are for Name and are encoded in UTF-8
    name_bytes = payload_data[:255]
    # Decode the name bytes to a string, stripping null bytes if any
    name = name_bytes.decode('utf-8').rstrip('\x00')

    # The next 160 bytes are for the public key
    public_key_bytes = payload_data[255:255+160]
    # Convert the public key bytes to a hex string or keep as bytes depending on your use case
    #public_key_hex = public_key_bytes.hex()
    public_key_hex = public_key_bytes
    return {"Name": name, "publicKey": public_key_hex}

def unpack_payload_Encrypted_Message(payload_data):
    # first 4 bytes are for the encrypted file size
    encrypted_file_size = little_endian_to_int(payload_data[:4])
    # next 4 bytes are for the original file size   
    original_file_size = little_endian_to_int(payload_data[4:8])
    # next 2 bytes are for number of the current file part
    current_file_part = little_endian_to_int(payload_data[8:10])
    # next 2 bytes are for the total number of file parts
    total_file_parts = little_endian_to_int(payload_data[10:12])
    
    # next 255 bytes are for the file name
    file_name_data = payload_data[12:267]
    # remaining bytes are for the  encrypted file data part
    encrypted_file_data = payload_data[267:]
    # return the all extracted parts
    return {"encryptedFileSize": encrypted_file_size, "originalFileSize": original_file_size, 
            "currentFilePart": current_file_part, "totalFileParts": total_file_parts,
            "fileName": file_name_data, "encryptedFileData": encrypted_file_data}
    

def decrypt_aes_cbc(ciphertext, key):
    iv = bytes([0] * AES.block_size)  # Create an all-zero IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.rstrip(b'\0')  # Remove padding

def decrypt_aes(encrypted_file,aes_key):
    # encrypted_file - list of encrypted parts
    # aes_key - key to decrypt the parts
    # decrypt the encrypted file parts using the AES key
    # return the decrypted file
    decrypted_file = b''
    for part in encrypted_file:
        # Decrypt each part using the AES key
        decrypted_part = decrypt_aes_cbc(part, aes_key)
        # Append the decrypted part to the decrypted file
        decrypted_file = decrypted_file + decrypted_part
    return decrypted_file



def memcrc(b):
    n = len(b)
    i = c = s = 0
    for ch in b:
        tabidx = (s>>24)^ch
        s = UNSIGNED((s << 8)) ^ crctab[tabidx]

    while n:
        c = n & 0o377
        n = n >> 8
        s = UNSIGNED(s << 8) ^ crctab[(s >> 24) ^ c]
    return UNSIGNED(~s)



# Context Manager for State Switching
class StateHandler:
    def remove_trailing_zeros(self,byte_data):
        """
        This function takes a bytes object and removes all trailing zeros (0x00 bytes) from the end
        until a byte that is different from zero is encountered.
    
        :param byte_data: The bytes object from which to remove trailing zeros.
        :return: The modified bytes object with trailing zeros removed.
        """
        # Find the index of the last non-zero byte
        last_non_zero_index = len(byte_data) - 1
        while last_non_zero_index >= 0 and byte_data[last_non_zero_index] == 0:
            last_non_zero_index -= 1
    
        # Slice the bytes object to remove trailing zeros
        return byte_data[:last_non_zero_index + 1]

    def __init__(self):
            self.uuidSet = set()
            #self.state = None#not usful currentely
            """
            self.state_map = {#not usful currentely
                RequestCode.Register: RegisterState,
                RequestCode.SendPublicKey: SendPublicKeyState,
                RequestCode.ReRegister: ReRegisterState,
                RequestCode.SendFile: SendFileState,
                RequestCode.OkCRC: OkCRCState,
                RequestCode.FailCRC: FailCRCState,
                RequestCode.FinalFailCRC: FinalFailCRCState,
                # Add any additional message types here
            }#this maps between request codes and state
            """
    def pack_message(self, version, code, payload_size, payload):
        # Prefixing with '<' to enforce little-endian byte order
        header_format = '<BHI'

        # Convert integer payload to bytes (adjust according to the expected size of the payload)
        if isinstance(payload, int):
            # Determine the minimum bytes needed for the integer, adjust as necessary
            bytes_needed = (payload.bit_length() + 7) // 8  # Calculate bytes needed for payload
            bytes_needed = max(bytes_needed, 4)  # Ensure at least 4 bytes, adjust this as needed
            payload = payload.to_bytes(bytes_needed, byteorder='little', signed=False)
        elif isinstance(payload, str):
            # If the payload is a string, encode it to bytes
            payload = payload.encode('utf-8')

        # Ensure the bytes payload matches the specified payload_size
        # Truncate or pad with zeros as necessary
        payload = payload[:payload_size] + bytes(max(0, payload_size - len(payload)))

        # Adjust the payload format string based on the actual payload size
        payload_format = f'{len(payload)}s'  # Use the length of the actual payload
        format_string = header_format + payload_format

        # Pack the data as little-endian
        packed_data = struct.pack(format_string, version, code, payload_size, payload)

        return packed_data
        
        
    def getUUID(self):
        while True:
            # Generate a random UUID
            new_uuid = uuid.uuid4()
            # Convert UUID to a 128-bit integer
            int_uuid = new_uuid.int
            
            # Check if this UUID is unique within the set
            if int_uuid not in self.uuidSet:
                self.uuidSet.add(int_uuid)
                return int_uuid

    def unpack_message(self,data):
        # Unpack the fixed-size header
        header_format = '<QQBHI'  # Little-endian: ClientIDHigh, ClientIDLow, Version, Code, PayloadSize
        header_size = struct.calcsize(header_format)
        header = data[:header_size]

        client_id_high, client_id_low, version, code, payload_size = struct.unpack(header_format, header)

        # Ensure the remaining data length matches the specified payload size
        # Process the payload as needed in another function, omitted for brevity
        # process_payload(payload)

        return {
            'ClientIDHigh': client_id_high,
            'ClientIDLow': client_id_low,
            'Version': version,
            'Code': code,
            'PayloadSize': payload_size,
        }
    

"""
    

    def setState(self, stateInstance: MessageState):
        # Retrieve the expected state class for the given instance's message_code
        expectedStateClass = self.state_map.get(stateInstance.message_code)

        # Ensure expectedStateClass is a valid type before using it with isinstance()
        if expectedStateClass and isinstance(stateInstance, expectedStateClass):
            self.state = stateInstance
            print(f"State successfully set to {expectedStateClass.__name__} for code {stateInstance.message_code}.")
        else:
            # This else block now also catches cases where expectedStateClass is None (i.e., no matching type found in state_map)
            print(f"Failed to set state: instance message code {stateInstance.message_code} does not match expected state or state is undefined.")
        
"""
# Implementations of specific states like RegisterState...

"""
    def unpack_message(self,data):
        # Unpack the fixed-size header
        header_format = '<QQBHI'  # Little-endian: ClientIDHigh, ClientIDLow, Version, Code, PayloadSize
        header_size = struct.calcsize(header_format)
        header = data[:header_size]

        client_id_high, client_id_low, version, code, payload_size = struct.unpack(header_format, header)

        # Ensure the remaining data length matches the specified payload size
        payload = data[header_size:]
        if len(payload) != payload_size:
            raise ValueError(f"Actual payload size ({len(payload)}) does not match specified payload size ({payload_size}).")

        # Process the payload as needed in another function, omitted for brevity
        # process_payload(payload)

        return {
            'ClientIDHigh': client_id_high,
            'ClientIDLow': client_id_low,
            'Version': version,
            'Code': code,
            'PayloadSize': payload_size,
            'Payload': payload  # Or the result from process_payload, if you wish to process it here
        }
"""
    
"""
class ReRegisterState(MessageState):
    def __init__(self, binary_data):
    # Call the superclass __init__ to handle common header processing
        super().__init__(binary_data)
        
    def unpack_payload(self, payload_data):
        # Your logic here
        return {"action": "ReRegisterState", "data": "..."}
    
class SendFileState(MessageState):
    def __init__(self, binary_data):
    # Call the superclass __init__ to handle common header processing
        super().__init__(binary_data)
        
    def unpack_payload(self, payload_data):
        # Your logic here
        return {"action": "SendFileState", "data": "..."}
    
class OkCRCState(MessageState):
    def __init__(self, binary_data):
    # Call the superclass __init__ to handle common header processing
        super().__init__(binary_data)
        
    def unpack_payload(self, payload_data):
        # Your logic here
        return {"action": "OkCRCState", "data": "..."}
    
class FailCRCState(MessageState):
    def __init__(self, binary_data):
    # Call the superclass __init__ to handle common header processing
        super().__init__(binary_data)
        
    def unpack_payload(self, payload_data):
        # Your logic here
        return {"action": "FailCRCState", "data": "..."}
    
class FinalFailCRCState(MessageState):
    def __init__(self, binary_data):
    # Call the superclass __init__ to handle common header processing
        super().__init__(binary_data)
        
    def unpack_payload(self, payload_data):
        # Your logic here
        return {"action": "FinalFailCRCState", "data": "..."}
    
"""