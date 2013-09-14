import cPickle
from intbytes import int2bytes, bytes2int
from math import log, floor, ceil
from keccak import Keccak
from itertools import izip, count

words = cPickle.Unpickler(open('words.pkl','rb')).load()
rwords = dict(izip(words, count()))

def encode_int(i,endian='little'):
    """Produce a byte encoding of an integer.

    The encoding captures both the value and length of the integer, so appending
    the encoded integer to arbitrary data will not effect the ability to decode
    the integer. In addition, the encoding never produces a string ending in a
    null, so after transforming to and from an int (little endian), the string
    will be unchanged.
    """
    if endian not in ('little', 'big'):
        raise TypeError('Argument endian must be either \'big\' or \'little\'')

    encoded = ''
    # the final byte (most-significant byte little-endian) is never 0x00
    if i+1 < 0xfb:
        signifier = chr(i+1)
    elif i <= 0xff:
        signifier = chr(0xfb)
        encoded = chr(i)
    elif i <= 0xffff:
        signifier = chr(0xfc)
        encoded = int2bytes(i,2,endian=endian)
    elif i <= 0xffffffff:
        signifier = chr(0xfd)
        encoded = int2bytes(i,4,endian=endian)
    elif i <= 0xffffffffffffffff:
        signifier = chr(0xfe)
        encoded = int2bytes(i,8,endian=endian)
    else:
        l = (i.bit_length() - 1) // 8 + 1
        s = int2bytes(i,l)
        assert len(s) == l
        signifier = chr(0xff)
        if endian == 'little':
            encoded = s + encode_int(l,endian=endian)
        else:
            encoded = encode_int(l,endian=endian) + s

    if endian == 'little':
        return encoded + signifier
    else:
        return signifier + encoded
    
def decode_int(s,endian='little'):
    """Decode an string produced by mnemonic.encode_int

    returns a 2-tuple of (integer, bytes consumed)
    The bytes consumed indicates how long the encoded integer was. This is
    useful if the integer was appended to some data.
    """
    if endian not in ('little', 'big'):
        raise TypeError('Argument endian must be either \'big\' or \'little\'')

    if endian == 'little':
        signifier, encoded = s[-1], s[:-1]
    else:
        signifier, encoded = s[0], s[1:]
    signifier = ord(signifier)
    if signifier == 0:
        raise ValueError("this encoding scheme never has a null signifier")

    if signifier < 0xfb:
        return (signifier-1, 1)
    elif signifier == 0xfb:
        return (ord(encoded), 2)
    elif signifier == 0xfc:
        bounds = 2
        consumed = 3
    elif signifier == 0xfd:
        bounds = 4
        consumed = 5
    elif signifier == 0xfe:
        bounds = 8
        consumed = 9
    elif signifier == 0xff:
        (bounds, consumed) = decode_int(encoded, endian=endian)
        if endian == 'little':
            encoded = encoded[:-consumed]
        else:
            encoded = encoded[consumed:]
        consumed += bounds + 1

    if endian == 'little':
        return (bytes2int(encoded[-bounds:], endian=endian), consumed)
    else:
        return (bytes2int(encoded[:bounds], endian=endian), consumed)

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
    k.absorb(s)
    checksum_length = max(1, (len(s)-1).bit_length())
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
        checksum_length = max(1, (len(s)-1).bit_length())

    s = s[:-consumed]
    s, checksum = s[:-checksum_length], s[-checksum_length:]
    if len(s) != length:
        raise ValueError("Invalid length")

    k = Keccak()
    k.absorb(s)
    if k.squeeze(checksum_length) != checksum:
        raise ValueError("Invalid checksum")

    return s

def randomart(s, height=9, width=17, length=64, border=True, tag=''):
    """Produce a easy to compare visual representation of a string.
    Follows the algorithm laid out here http://www.dirk-loss.de/sshvis/drunken_bishop.pdf
    with the substitution of Keccak for MD5.

    s: the string to create a representation of
    height: (optional) the height of the representation to generate, default 9
    width: (optional) the width of the representation to generate, default 17
    length: (optional) the length of the random walk, essentially how many
        points are plotted in the representation, default 64
    border: (optional) whether to put a border around the representation,
        default True
    tag: (optional) a short string to be incorporated into the border,
        does nothing if border is False, defaults to the empty string
    """
    k = Keccak()
    k.absorb(s)
    # we reverse the endianness so that increasing length produces a radically
    # different randomart
    i = bytes2int(reversed(k.squeeze(int(ceil(length / 4.0)))))

    field = [ [0 for _ in xrange(width)]
              for __ in xrange(height) ]
    start = (height // 2,
             width // 2)
    position = start
    directions = ((-1, -1),
                  (-1, 1),
                  (1, -1),
                  (1, 1))
    for j in xrange(length):
        row_off, col_off = directions[(i>>(j*2)) % 4]
        position = (min(max(position[0] + row_off, 0),
                        height - 1),
                    min(max(position[1] + col_off, 0),
                        width - 1))
        field[position[0]][position[1]] += 1

    field[start[0]][start[1]] = 15
    field[position[0]][position[1]] = 16
    chars = ' .o+=*BOX@%&#/^SE'

    if border:
        if len(tag) > width - 2:
            tag = tag[:width-2]
        if tag:
            tag_pad_len = (width - len(tag) - 2) / 2.0
            first_row = '+' + ('-'*int(floor(tag_pad_len))) \
                        + '['+tag+']' \
                        + ('-'*int(ceil(tag_pad_len))) + '+\n'
        else:
            first_row = '+' + ('-'*width) + '+\n'
        last_row = '\n+' + ('-'*width) + '+'
        return first_row \
               + '\n'.join('|'+''.join(chars[cell] for cell in row)+'|'
                           for row in field) \
               + last_row
    else:
        return '\n'.join(''.join(chars[cell] for cell in row)
                         for row in field)

__all__ = ['encode', 'decode', 'randomart']
