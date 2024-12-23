
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