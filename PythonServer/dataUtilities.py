import struct
from enum import Enum
import uuid

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

def unpack_payload_Public_Key(payload_data):
    # Assuming the first 255 bytes are for Name and are encoded in UTF-8
    name_bytes = payload_data[:255]
    # Decode the name bytes to a string, stripping null bytes if any
    name = name_bytes.decode('utf-8').rstrip('\x00')

    # The next 160 bytes are for the public key
    public_key_bytes = payload_data[255:255+160]
    # Convert the public key bytes to a hex string or keep as bytes depending on your use case
    public_key_hex = public_key_bytes.hex()

    return {"Name": name, "publicKey": public_key_hex}


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