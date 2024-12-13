import ipaddress
from simp_protocol import *


def is_valid_ip(ip: str) -> bool | str:
    """
    Check if the given IP address is valid
    :param ip: The IP address to check
    :return: True if the IP is valid, Error message otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError as e:
        return "Error: {ip} is not a valid IP address."


def check_header(message: bytes) -> HeaderInfo:
    """
    Checks if header is correctly built
    :param message: The message to check
    :return: True if header is ok, or False otherwise
    """
    header_info = HeaderInfo()
    pass
    # fill out with error checks
        # create ErrorCodes class for reply in simp_protocol.py
