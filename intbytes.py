from binascii import unhexlify

def int2bytes(i, length=None, endian='little'):
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
    elif i.bit_length()/8.0 > length:
        raise ValueError("Integer too large to be represented in desired length")

    # Oh BDFL, forgive us our abuses!
    format_string = '%%0%dx' % (length * 2)
    hex_string = format_string % i

    if endian == 'little':
        return unhexlify(hex_string)[::-1]
    elif endian == 'big':
        return unhexlify(hex_string)
    else:
        raise TypeError('Argument endian must be either \'big\' or \'little\'')

def bytes2int(b, endian='little'):
    """Convert a string (bytes) to an integer:

    b: the string (bytes) to be converted
    """
    if endian == 'little':
        return sum(ord(char) << (i * 8) for i, char in enumerate(b))
    elif endian == 'big':
        return sum(ord(char) << (i * 8) for i, char in enumerate(reversed(b)))
    else:
        raise TypeError('Argument endian must be either \'big\' or \'little\'')

__all__ = ['int2bytes', 'bytes2int']
