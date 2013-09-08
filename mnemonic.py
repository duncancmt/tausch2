import cPickle
from intbytes import int2bytes, bytes2int
from math import log, floor, ceil
from keccak import Keccak
from itertools import izip, count

words = cPickle.Unpickler(open('words.pkl','rb')).load()
rwords = dict(izip(words, count()))

def encode_int(i):
    """Produce a byte encoding of an integer.

    The encoding captures both the value and length of the integer, so appending
    the encoded integer to arbitrary data will not effect the ability to decode
    the integer. In addition, the encoding never produces a string ending in a
    null, so after transforming to and from an int (little endian), the string
    will be unchanged.
    """
    if not isinstance(i, (int, long)):
        raise TypeError("mnemonic.encode_int only encodes int and long")

    # the final byte (most-significant byte little-endian) is never 0x00
    if i+1 < 0xfb:
        return chr(i+1)
    elif i <= 0xff:
        return chr(i) + chr(0xfb)
    elif i <= 0xffff:
        return int2bytes(i,2) + chr(0xfc)
    elif i <= 0xffffffff:
        return int2bytes(i,4) + chr(0xfd)
    elif i <= 0xffffffffffffffff:
        return int2bytes(i,8) + chr(0xfe)
    else:
        l = int(floor(log(i, 0x100) + 1))
        s = int2bytes(i,l)
        assert len(s) == l
        return s + encode_int(l) + chr(0xff)

def decode_int(s):
    """Decode an string produced by mnemonic.encode_int

    returns a 2-tuple of (integer, bytes consumed)
    The bytes consumed indicates how long the encoded integer was. This is
    useful if the integer was appended to some data.
    """
    if not isinstance(s, bytes):
        raise TypeError("mnemonic.decode_int only decodes byte strings")

    t = ord(s[-1])
    if t == 0:
        raise ValueError("this encoding scheme never ends in a null byte")

    if t < 0xfb:
        return (t-1, 1)
    elif t == 0xfb:
        return (ord(s[-2]), 2)
    elif t == 0xfc:
        return (bytes2int(s[-3:-1]), 3)
    elif t == 0xfd:
        return (bytes2int(s[-5:-1]), 5)
    elif t == 0xfe:
        return (bytes2int(s[-9:-1]), 9)
    elif t == 0xff:
        (encoded_length, consumed_length) = decode_int(s[:-1])
        total_length = encoded_length + consumed_length + 1
        s = s[-total_length:-(consumed_length+1)]
        return (bytes2int(s), total_length)

def encode(s, compact=False):
    """From a byte string, produce a list of words that durably encodes the string.

    s: the byte string to be encoded
    compact: instead of using the length encoding scheme, pad by prepending a 1 bit

    The words in the encoding dictionary were chosen to be common and unambiguous.
    The encoding also includes a checksum. The encoding is constructed so that
    common errors are extremely unlikely to produce a valid encoding.
    """
    if not isinstance(s, bytes):
        raise TypeError("mnemonic.encode can only encode byte strings")

    k = Keccak()
    k.soak(s)
    checksum_length = max(1, int(ceil(log(len(s), 2))))
    checksum = k.squeeze(checksum_length)

    length = chr(checksum_length) if compact else encode_int(len(s))

    s += checksum
    s += length

    word_index = 0
    i = bytes2int(s)
    retval = [None] * int(floor(log(i, len(words)) + 1))
    for j in xrange(len(retval)):
        assert i > 0
        word_index += i % len(words)
        word_index %= len(words)
        retval[j] = words[word_index]
        i //= len(words)
    assert i == 0
    return retval

def decode(w, compact=False):
    """From a list of words, or a whitespace-separated string of words, produce
    the original string that was encoded.

    w: the list of words, or whitespace delimited words to be decoded
    compact: compact encoding was used instead of length encoding

    Raises ValueError if the encoding is invalid.
    """
    if isinstance(w, bytes):
        w = w.split()

    try:
        indexes = map(lambda x: rwords[x], w)
    except KeyError:
        raise ValueError('Unrecognized word')
    values = reduce(lambda (last_index, accum), index: (index,
                                                        accum + [(index - last_index) % len(words)]),
                    indexes,
                    (0, []))[1]
    i = sum(mantissa * len(words)**radix for radix, mantissa in enumerate(values))
    s = int2bytes(i)

    if compact:
        checksum_length = ord(s[-1])
        consumed = 1
        length = len(s) - checksum_length - consumed
    else:
        (length, consumed) = decode_int(s)
        checksum_length = max(1, int(ceil(log(length, 2))))

    s = s[:-consumed]
    s, checksum = s[:-checksum_length], s[-checksum_length:]
    if len(s) != length:
        raise ValueError("Invalid length")

    k = Keccak()
    k.soak(s)
    if k.squeeze(checksum_length) != checksum:
        raise ValueError("Invalid checksum")

    return s

__all__ = ['encode', 'decode']
