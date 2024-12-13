from enum import Enum


# change values to match the assignment
MAX_HEADER_SIZE = 39
MESSAGE_TYPE_SIZE = 1
PAYLOAD_SIZE = 4
MAX_STRING_PAYLOAD_SIZE = 256
INT_PAYLOAD_SIZE = 4
FLOAT_PAYLOAD_SIZE = 8


class SimpProtocol:
    HEADER_FORMAT = '!BBB32sI'  # Type (1 byte), Operation (1 byte), Sequence (1 byte), User (32 bytes), Length (4 bytes)

    def __init__(self):
        self.type = None
        self.operation = None
        self.sequence = None
        self.user = None
        self.length = None

    def create_datagram(self, datagram_type, operation, sequence, user, payload):
        """
        Construct a SIMP datagram.
        """
        datagram_type = datagram_type.to_bytes(1, byteorder='big')
        operation = operation.to_bytes(1, byteorder='big')
        sequence = sequence.to_bytes(1, byteorder='big')
        user = user.encode('ascii').ljust(32, b'\x00')  # Pad username to 32 bytes
        payload = payload.encode('ascii')
        length = len(payload)
        length = length.to_bytes(4, byteorder='big')
        header = b''.join([datagram_type, operation, sequence, user, length, payload])
        return header

    def parse_datagram(self, data):
        """
        Parse a SIMP datagram.
        """
        header = data[:39]
        payload = data[39:]
        datagram_type = int(header[0])
        operation = int(header[1])
        sequence = int(header[2])
        user = header[3:35].decode('ascii').strip('\x00') # Remove padding
        length = int.from_bytes(header[35:], byteorder='big')
        payload = payload.decode('ascii')



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

    # not sure we need this
    def get_sequence_number(self, message):
        """
            Extracts the sequence number from the message
            :param message: The received message
            :return: The sequence number
        """
        seq_num = int(message[2])  # 00 or 01


    def get_payload_size(self, message):
        """
            Extracts the payload size from the message
            :param message: The received message
            :return: The payload size
        """
        payload_size = message[1:MAX_HEADER_SIZE]
        return int.from_bytes(payload_size, byteorder='big')


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


class Operation(Enum):
    CONST = 1  # for chat protocol
    # for control protocol
    ERR = 1
    SYN = 2
    ACK = 4
    FIN = 8

    def to_bytes(self):
        if self == Operation.OK:
            return int(0).to_bytes(1, byteorder='big')
        elif self == Operation.ERR:
            return int(1).to_bytes(1, byteorder='big')
        elif self == Operation.SYN:
            return int(2).to_bytes(1, byteorder='big')
        elif self == Operation.ACK:
            return int(4).to_bytes(1, byteorder='big')
        elif self == Operation.FIN:
            return int(8).to_bytes(1, byteorder='big')


class ErrorCode(Enum):
    OK = 0,
    TYPE_MISMATCH = 1,
    MESSAGE_TOO_SHORT = 2
    MESSAGE_TOO_LONG = 3
    UNKNOWN_MESSAGE = 4
    WRONG_PAYLOAD = 5
    INVALID_USER = 6
    INVALID_OPERATION = 7


class HeaderInfo:
    is_ok = False
    type: HeaderType
    code: ErrorCode

    def __init__(self):
        self.is_ok = False
        self.type = HeaderType.OK
        self.code = ErrorCode.OK


# not sure we need this
class SeqNum:
    SEQ_0 = 0
    SEQ_1 = 1

    def to_bytes(self):
        if self == SeqNum.SEQ_0:
            return int(0).to_bytes(1, byteorder='big')
        elif self == SeqNum.SEQ_1:
            return int(1).to_bytes(1, byteorder='big')


