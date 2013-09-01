from binascii import unhexlify

# everything is the one-true endianness, little endian

def int2bytes(i, length=None):
    if length is None:
        length = i.bit_length()
        length += 8 - ((length % 8) or 8)
        assert length % 8 == 0
        assert length >= i.bit_length()
        length //= 8

    # Oh BDFL, forgive us our abuses!
    format_string = '%%0%dx' % (length * 2)
    hex_string = format_string % i
    return unhexlify(hex_string)[::-1]

def bytes2int(b):
    assert isinstance(b, bytes)
    return sum(ord(char) << (i * 8) for i, char in enumerate(b))
