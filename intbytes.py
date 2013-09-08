from math import log
from binascii import unhexlify

# everything is the one-true endianness, little endian

def int2bytes(i, length=None):
    """Convert an integer to a string (bytes):

    i: the integer to be converted
    length: (optional) the desired length of the string (in bytes), the default
        is to output the shortest string that can represent the integer
    """
    if length is None:
        length = i.bit_length()
        length += 8 - ((length % 8) or 8)
        assert length % 8 == 0
        assert length >= i.bit_length()
        length //= 8
    elif i != 0 and log(i, 256) >= length:
        raise ValueError("Integer too large to be represented in desired length")

    # Oh BDFL, forgive us our abuses!
    format_string = '%%0%dx' % (length * 2)
    hex_string = format_string % i
    return unhexlify(hex_string)[::-1]

def bytes2int(b):
    """Convert a string (bytes) to an integer:

    b: the string (bytes) to be converted
    """
    return sum(ord(char) << (i * 8) for i, char in enumerate(b))

__all__ = ['int2bytes', 'bytes2int']
