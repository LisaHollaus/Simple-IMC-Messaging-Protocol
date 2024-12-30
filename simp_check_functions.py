import ipaddress
from simp_protocol import *
from checksum import calculate_checksum16

# Create an instance of SimpProtocol
protocol = SimpProtocol()


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

    print(f"Checking header: ")
    header_info = HeaderInfo()
    header_info.type = protocol.get_message_type(message)  # validate and get the message type
    operation = protocol.get_operation(message, header_info.type)  # validate the operation field
    sequence_number = protocol.get_sequence_number(message)
    user = message[3:35].decode('ascii').strip('\x00')  # validate the user field
    payload_size = protocol.get_payload_size(message)  # validate and get the payload size


    if len(message) < MAX_HEADER_SIZE: # check if the msg is too short (less than 39 bytes)
        header_info.code = ErrorCode.MESSAGE_TOO_SHORT

    elif header_info.type is HeaderType.UNKNOWN:
        header_info.code = ErrorCode.UNKNOWN_MESSAGE
    
    elif operation is None:
        header_info.code = ErrorCode.INVALID_OPERATION
    
    elif sequence_number not in [0, 1]:
        header_info.code = ErrorCode.INVALID_OPERATION

    elif not user:
        header_info.code = ErrorCode.INVALID_USER

    elif payload_size > MAX_STRING_PAYLOAD_SIZE:
        header_info.code = ErrorCode.MESSAGE_TOO_LONG

    elif payload_size == 0 and header_info.type != HeaderType.CONTROL:
        header_info.code = ErrorCode.MESSAGE_TOO_SHORT

    print(f"Header info code: {header_info.code,}")
    header = message[:MAX_HEADER_SIZE]
    payload = message[MAX_HEADER_SIZE:-2]
    received_checksum = message[-2:]

    calculated_checksum = calculate_checksum16(header + payload)

    if received_checksum != calculated_checksum:  # check if the checksum is correct
        header_info.code = ErrorCode.WRONG_PAYLOAD

    # Final check: If no errors were set, mark as OK
    if header_info.code == ErrorCode.OK:  # ErrorCode.OK is default
        header_info.is_ok = True

    header_info.operation = operation
    header_info.sequence_number = sequence_number
    print("All checks done, header info: ", header_info.code, header_info.operation, header_info.sequence_number)
    return header_info

