import ipaddress
from simp_protocol import *

# Create an instance of SimpProtocol
protocol = SimpProtocol()


def calculate_checksum16(bytes_data: bytes) -> bytes: # using own checksum function form previous assignment
    """
    Calculates a checksum from a byte array (16 bits).
    Hint: instead of iterating byte per byte, each iteration processes two bytes.
    Bit masks have to be adapted to 16-bit accordingly.
    """
    checksum = 0

    if len(bytes_data) % 2 != 0:
        bytes_data += b'\x00'  # padding with 0 if length is odd

    for i in range(0, len(bytes_data), 2):  # each iteration processes 2 bytes as hinted above
        if i + 1 < len(bytes_data):  # if 2 bytes available, we should combine them into a 16bit
            combined_bytes = (bytes_data[i+1] << 8) + bytes_data[i]  # combining 2 bytes into one 16bit: first byte is shifted 8bits to left, second byte is added to it
        checksum += combined_bytes  # adding 16bit to checksum
        checksum = (checksum & 0xFFFF) + (checksum >> 16)  # if any carry is here, we add it to the checksum

    checksum = (checksum & 0xFFFF) + (checksum >> 16)  # any remaining carry after processing all 16bit should be added to checksum
    checksum = checksum ^ 0xFFFF  # negating the result

    return checksum


def is_valid_ip(ip: str) -> bool | str:
    """
    Check if the given IP address is valid
    :param ip: The IP address to check
    :return: True if the IP is valid, Error message otherwise
    """
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError as e:
        return f"Error: {ip} is not a valid IP address."


def check_header(message: bytes) -> HeaderInfo:
    """
    Checks if header is correctly built
    :param message: The message to check
    :return: HeaderInfo object with the result of the check
    """
    header_info = HeaderInfo()

    if len(message) <= MAX_HEADER_SIZE: # check if the msg is too short
        header_info.code = ErrorCode.MESSAGE_TOO_SHORT
        return header_info

    header_info.type = protocol.get_message_type(message)  # validate and get the message type
    if header_info.type is HeaderType.UNKNOWN:
        header_info.code = ErrorCode.UNKNOWN_MESSAGE

    operation = protocol.get_operation(message, header_info.type)  # validate the operation field
    if operation is None:
        header_info.code = ErrorCode.INVALID_OPERATION

    sequence_number = protocol.get_sequence_number(message)
    if sequence_number not in [0, 1]:
        header_info.code = ErrorCode.INVALID_OPERATION

    user = message[3:35].decode('ascii').strip('\x00')  # validate the user field
    if not user:
        header_info.code = ErrorCode.INVALID_USER

    payload_size = protocol.get_payload_size(message)  # validate and get the payload size
    if payload_size > MAX_STRING_PAYLOAD_SIZE:
        header_info.code = ErrorCode.MESSAGE_TOO_LONG
    elif payload_size == 0:
        header_info.code = ErrorCode.MESSAGE_TOO_SHORT

    header = message[:MAX_HEADER_SIZE]
    payload = message[MAX_HEADER_SIZE:-2]
    received_checksum = message[-2:]

    calculated_checksum = calculate_checksum16(header + payload)
    print(received_checksum, calculated_checksum)

    if received_checksum != calculated_checksum:  # check if the checksum is correct
        header_info.code = ErrorCode.WRONG_PAYLOAD

    # Final check: If no errors were set, mark as OK
    if header_info.code == ErrorCode.OK:
        header_info.is_ok = True

    header_info.operation = operation
    header_info.sequence_number = sequence_number
    return header_info

