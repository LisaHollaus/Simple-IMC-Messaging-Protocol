from enum import Enum
from checksum import calculate_checksum16
# change values to match the assignment
MAX_HEADER_SIZE = 39
MESSAGE_TYPE_SIZE = 1
PAYLOAD_SIZE = 4
MAX_STRING_PAYLOAD_SIZE = 256
INT_PAYLOAD_SIZE = 4
FLOAT_PAYLOAD_SIZE = 8


class HeaderType(Enum):
    CONTROL = 1
    CHAT = 2
    UNKNOWN = 0

    def to_bytes(self):
        if self == HeaderType.CONTROL:
            return int(1).to_bytes(1, byteorder='big')
        elif self == HeaderType.CHAT:
            return int(2).to_bytes(1, byteorder='big')
        elif self == HeaderType.UNKNOWN:
            return int(0).to_bytes(1, byteorder='big')


class ErrorCode(Enum):
    OK = 0,
    TYPE_MISMATCH = 1,
    MESSAGE_TOO_SHORT = 2
    MESSAGE_TOO_LONG = 3
    UNKNOWN_MESSAGE = 4
    WRONG_PAYLOAD = 5
    INVALID_USER = 6
    INVALID_OPERATION = 7
    BUSY_DAEMON = 8

    def message(self):
        if self == ErrorCode.OK:
            return "OK"
        elif self == ErrorCode.TYPE_MISMATCH:
            return "Type mismatch"
        elif self == ErrorCode.MESSAGE_TOO_SHORT:
            return "Message too short"
        elif self == ErrorCode.MESSAGE_TOO_LONG:
            return "Message too long"
        elif self == ErrorCode.UNKNOWN_MESSAGE:
            return "Unknown message"
        elif self == ErrorCode.WRONG_PAYLOAD:
            return "Wrong payload"
        elif self == ErrorCode.INVALID_USER:
            return "Invalid user"
        elif self == ErrorCode.INVALID_OPERATION:
            return "Invalid operation"
        elif self == ErrorCode.BUSY_DAEMON:
            return "User already in another chat"


class Operation(Enum):
    # for chat protocol
    CONST = 1
    # for control protocol
    ERR = 1
    SYN = 2
    ACK = 4
    FIN = 8

    def to_bytes(self):
        if self == Operation.CONST:
            return int(1).to_bytes(1, byteorder='big')
        elif self == Operation.ERR:
            return int(1).to_bytes(1, byteorder='big')
        elif self == Operation.SYN:
            return int(2).to_bytes(1, byteorder='big')
        elif self == Operation.ACK:
            return int(4).to_bytes(1, byteorder='big')
        elif self == Operation.FIN:
            return int(8).to_bytes(1, byteorder='big')


class HeaderInfo:
    is_ok = False
    type: HeaderType
    operation: Operation
    code: ErrorCode
    sequence_number: int

    def __init__(self):
        self.is_ok = False
        self.type = HeaderType.OK
        self.code = ErrorCode.OK


class SimpProtocol:
    HEADER_FORMAT = '!BBB32sI'  # Type (1 byte), Operation (1 byte), Sequence (1 byte), User (32 bytes), Length (4 bytes)

    def create_datagram(self, datagram_type, operation, sequence, user, payload):
        """
        Construct a SIMP datagram.
        """

        if isinstance(payload, ErrorCode):
            payload = payload.message().encode('ascii')  # if payload is instance of ErrorCode, convert error code to ascii message

        datagram_type = datagram_type.to_bytes()
        operation = operation.to_bytes()
        sequence = sequence.to_bytes()
        user = user.encode('ascii').ljust(32, b'\x00')  # Pad username to 32 bytes
        payload = payload.encode('ascii') if isinstance(payload, str) else payload # Convert payload to bytes
        length = len(payload)
        length = length.to_bytes(4, byteorder='big') # 4 bytes

        header = b''.join([datagram_type, operation, sequence, user, length])

        # adding checksum to header
        checksum = calculate_checksum16(header + payload)
        datagram = b''.join([header, payload, checksum])

        return datagram

    def parse_datagram(self, data):
        """
        Parse a SIMP datagram.
        """

        header = data[:MAX_HEADER_SIZE]  # 39 bytes
        payload = data[MAX_HEADER_SIZE:-2]  # this excludes checksum bytes

        # validating the header
        if not self.validate_header(header):
            raise ValueError("Invalid header format/fields!")

        # parsing header and payload
        datagram_type = int(header[0])
        operation = int(header[1])
        sequence = int(header[2])
        user = header[3:35].decode('ascii').strip('\x00') # Remove padding
        length = int.from_bytes(header[35:], byteorder='big')
        payload = payload.decode('ascii')

        return {
            "type": datagram_type,
            "operation": operation,
            "sequence": sequence,
            "user": user,
            "length": length,
            "payload": payload
        }

    def get_message_type(self, message):
        """
            Extracts the header type from the message
            :param message: The received message
            :return: The header type (Control or Chat)
        """
        type_byte = int(message[0])
        if type_byte == 1:
            return HeaderType.CONTROL
        elif type_byte == 2:
            return HeaderType.CHAT
        return HeaderType.UNKNOWN

    def get_operation(self, message, header_type):
        """
            Extracts the operation from the message
            :param message: The received message
            :return: The operation
        """
        operation_byte = int(message[1])

        if header_type == HeaderType.CHAT:
            return Operation.CONST
        elif header_type == HeaderType.CONTROL:
            if operation_byte == 1:
                return Operation.ERR
            elif operation_byte == 2:
                return Operation.SYN
            elif operation_byte == 4:
                return Operation.ACK
            elif operation_byte == 8:
                return Operation.FIN

    def get_sequence_number(self, message):
        """
            Extracts the sequence number from the message
            :param message: The received message
            :return: The sequence number
        """
        seq_num = int(message[2])  # 00 or 01
        return seq_num

    def get_payload_size(self, message):
        """
            Extracts the payload size from the message
            :param message: The received message
            :return: The payload size
        """
        payload_size = message[35:39] # extract the payload size from the header (4 bytes)
        return int.from_bytes(payload_size, byteorder='big')
