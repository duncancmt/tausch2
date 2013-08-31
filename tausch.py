#!/usr/bin/env python

import random
from operator import xor
from itertools import *

from keccak import Keccak
from binascii import hexlify, unhexlify

def oaep_keccak(k0, k1, m, random=random):
    """Perform OAEP with Keccak as the one-way function

    k0: first OAEP parameter (in *bytes* not bits)
    k1: second OAEP parameter (in *bytes* not bits)
    m: message to be padded
    random: entropy source for OAEP
    """
    # pad m with zeroes
    m = m+'\x00'*k1

    # generate r, a k0-byte random string
    r = random.getrandbits(k0*8)
    r = hex(int(r))[2:]
    if r[-1] == 'L':
        r = r[:-1]
    r = '0'*(k0*2 - len(r)) + r
    r = unhexlify(r)

    # expand r to the length of m
    k = Keccak() # TODO: perhaps choose different parameters for G and H
    k.soak(r)
    G = k.squeeze(len(m))

    # XOR the message with the expanded r
    X = ''.join(imap(chr, imap(xor, imap(ord, m),
                                    imap(ord, G))))

    # XOR r with the hash of the XOR'd message
    k = Keccak() # TODO: perhaps choose different parameters for G and H
    k.soak(X)
    H = k.squeeze(len(r))

    Y = ''.join(imap(chr, imap(xor, imap(ord, r),
                                    imap(ord, H))))

    # concatenate the two together
    return X + Y

def unoaep_keccak(k0, k1, XY):
    """Recover a message padded with OAEP with Keccak as the one-way function

    k0: first OAEP parameter (in *bytes* not bits)
    k1: second OAEP parameter (in *bytes* not bits)
    XY: padded message to be recovered
    """
    # split the two parts of the OAEP'd message
    X, Y = XY[:-k0], XY[-k0:]

    # recover r
    k = Keccak()
    k.soak(X)
    H = k.squeeze(len(Y))

    r = ''.join(imap(chr, imap(xor, imap(ord, Y),
                                    imap(ord, H))))

    # recover m
    k = Keccak()
    k.soak(r)
    G = k.squeeze(len(X))

    m = ''.join(imap(chr, imap(xor, imap(ord, X),
                                    imap(ord, G))))

    # trim the zero padding
    assert sum(imap(ord, m[-k1:])) == 0
    return m[:-k1]

if __name__ == "__main__":
    raise NotImplementedError
