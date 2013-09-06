# The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
# Michael Peeters and Gilles Van Assche. For more information, feedback or
# questions, please refer to our website: http://keccak.noekeon.org/
# 
# Implementation by Renaud Bauvin,
# hereby denoted as "the implementer".
# Heavy modifications to make this more idiomatic by Duncan Townsend.
# KeccakRandom written by Duncan Townsend.
#
# To the extent possible under law, the implementer has waived all copyright
# and related or neighboring rights to the source code in this file.
# http://creativecommons.org/publicdomain/zero/1.0/

import math
from binascii import hexlify
from intbytes import int2bytes, bytes2int

class KeccakError(Exception):
    """Class of error used in the Keccak implementation

    Use: raise KeccakError("Text to be displayed")"""


class Keccak(object):
    """
    Class implementing the Keccak sponge function
    """
    def __init__(self, r=1024,c=576,verbose=False):
        """Constructor:

        r: bitrate (default 1024)
        c: capacity (default 576)
        verbose: print the details of computations(default:False)
        r + c must be 25, 50, 100, 200, 400, 800 or 1600 (recommended 1600)
        see http://keccak.noekeon.org/NoteOnKeccakParametersAndUsage.pdf
        """

        self.verbose = verbose
        if (r<0) or (r%8!=0):
            raise KeccakError('r must be a multiple of 8 in this implementation')
        self.r = r
        self.c = c
        self.b = b = r+c
        if b not in [25, 50, 100, 200, 400, 800, 1600]:
            raise KeccakError('b value not supported - use 25, 50, 100, 200, 400, 800 or 1600')
        self.w = w = b//25
        self.l=int(math.log(self.w,2))
        self.nr=12+2*self.l

        if verbose:
            print "Create a Keccak function with (r=%d, c=%d (i.e. w=%d))" % (r,c,(r+c)//25)

        # Initialisation of state
        self.S = [[0,0,0,0,0],
                  [0,0,0,0,0],
                  [0,0,0,0,0],
                  [0,0,0,0,0],
                  [0,0,0,0,0]]
        self.P = ''
        self.output_cache = ''
        self.done_soaking = False

    # Constants

    ## Round constants
    RC=[0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008]

    ## Rotation offsets
    rot_off=[[0,    36,     3,    41,    18]    ,
             [1,    44,    10,    45,     2]    ,
             [62,    6,    43,    15,    61]    ,
             [28,   55,    25,    21,    56]    ,
             [27,   20,    39,     8,    14]    ]

    ## Generic utility functions

    @staticmethod
    def rot(x,n,w):
        """Bitwise rotation (to the left) of n bits considering the \
        string of bits is w bits long"""

        n = n%w
        return ((x>>(w-n))+(x<<n))%(1<<w)

    @staticmethod
    def fromStringToLane(string):
        """Convert a string of bytes to a lane value"""
        return bytes2int(string)

    @staticmethod
    def fromLaneToString(lane, w):
        """Convert a lane value to a string of bytes"""
        return int2bytes(lane, w//8)

    @staticmethod
    def printState(state, info):
        """Print on screen the state of the sponge function preceded by \
        string info

        state: state of the sponge function
        info: a string of characters used as identifier"""

        print "Current value of state: %s" % (info)
        for y in range(5):
            line=[]
            for x in range(5):
                 line.append(hex(state[x][y]))
            print '\t%s' % line

    ### Conversion functions String <-> Table (and vice-versa)

    @classmethod
    def convertStrToTable(cls,string,w,b):
        """Convert a string of bytes to its 5x5 matrix representation

        string: string of bytes"""

        #Check that input paramaters
        if w%8!= 0:
            raise KeccakError("w is not a multiple of 8")
        if len(string)!=b//8:
            raise KeccakError("string can't be divided in 25 blocks of w bits\
            i.e. string must have exactly b bits")

        #Convert
        output=[[0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0]]
        for x in xrange(5):
            for y in xrange(5):
                offset=((5*y+x)*w)//8
                output[x][y]=cls.fromStringToLane(string[offset:offset+(w//8)])
        return output

    @classmethod
    def convertTableToStr(cls, table, w):
        """Convert a 5x5 matrix representation to its string representation"""

        #Check input format
        if w%8!= 0:
            raise KeccakError("w is not a multiple of 8")
        if (len(table)!=5) or (False in [len(row)==5 for row in table]):
            raise KeccakError("table must be 5x5")

        #Convert
        output=[None]*25
        for x in range(5):
            for y in range(5):
                output[5*y+x]=cls.fromLaneToString(table[x][y], w)
        output = ''.join(output)
        return output

    @classmethod
    def Round(cls,A,RCfixed,w):
        """Perform one round of computation as defined in the Keccak-f permutation

        A: current state (5x5 matrix)
        RCfixed: value of round constant to use (integer)
        """

        #Initialisation of temporary variables
        B=[[0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0]]
        C= [0,0,0,0,0]
        D= [0,0,0,0,0]

        #Theta step
        for x in range(5):
            C[x] = A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4]

        for x in range(5):
            D[x] = C[(x-1)%5]^cls.rot(C[(x+1)%5],1,w)

        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y]^D[x]

        #Rho and Pi steps
        for x in range(5):
          for y in range(5):
                B[y][(2*x+3*y)%5] = cls.rot(A[x][y], cls.rot_off[x][y], w)

        #Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y]^((~B[(x+1)%5][y]) & B[(x+2)%5][y])

        #Iota step
        A[0][0] = A[0][0]^RCfixed

        return A

    @classmethod
    def KeccakF(cls, A, nr, w, verbose):
        """Perform Keccak-f function on the state A

        A: 5x5 matrix containing the state
        nr: number of rounds to perform
        w: lane width
        verbose: a boolean flag activating the printing of intermediate computations
        """

        if verbose:
            cls.printState(A,"Before first round")

        for i in range(nr):
            #NB: result is truncated to lane size
            A = cls.Round(A,cls.RC[i]%(1<<w),w)

            if verbose:
                cls.printState(A,"Satus end of round #%d/%d" % (i+1,nr))

        return A

    ### Padding rule

    @staticmethod
    def pad10star1(M, n, M_bit_len=None):
        """Pad M with the pad10*1 padding rule to reach a length multiple of r bits

        M: string to be padded
        n: block length in bits (must be a multiple of 8)
        M_bit_len: length of M (in bits) only supply this argument if M is not an octet stream
        (M_bit_len functionality is unused in this implementation)
        """

        # Check the parameter n
        if n%8!=0:
            raise KeccakError("n must be a multiple of 8")

        if M_bit_len is None:
            M_bit_len = len(M)*8
        elif M_bit_len > len(M)*8:
            raise KeccakError("the string is too short to contain the number of bits announced")

        nr_bytes_filled=M_bit_len//8
        nbr_bits_filled=M_bit_len%8
        l = M_bit_len % n
        if ((n-8) <= l <= (n-2)):
            if (nbr_bits_filled == 0):
                pad_byte = 0
            else:
                pad_byte=ord(M[nr_bytes_filled:nr_bytes_filled+1])
            pad_byte=(pad_byte>>(8-nbr_bits_filled))
            pad_byte=pad_byte+2**(nbr_bits_filled)+2**7
            M=M[0:nr_bytes_filled]+chr(pad_byte)
        else:
            if (nbr_bits_filled == 0):
                pad_byte = 0
            else:
                pad_byte=ord(M[nr_bytes_filled:nr_bytes_filled+1])
            pad_byte=(pad_byte>>(8-nbr_bits_filled))
            pad_byte=pad_byte+2**(nbr_bits_filled)
            M=M[0:nr_bytes_filled]+chr(pad_byte)
            M=M+'\x00'*(n//8-1-len(M)%n)+'\x80'

        return M

    def __call__(self, M):
        """Does the same as soak"""
        self.soak(M)

    def soak(self, M):
        """Perform the soaking phase of Keccak: data is mixed into the internal state
        
        M: the string to be soaked
        """
        r, c, b, w, nr, verbose = self.r, self.c, self.b, self.w, self.nr, self.verbose

        if self.done_soaking:
            raise RuntimeError('Cannot continue soaking once squeezing has begun')

        self.P += M


        for _ in xrange((len(self.P)*8)//r):
            chunk, self.P = self.P[:(r//8)], self.P[(r//8):]
            if verbose:
                print("String ready to be absorbed: %s (will be completed by %d x NUL)" % (hexlify(chunk), c//8))

            chunk += '\x00'*(c//8)
            Pi=self.convertStrToTable(chunk,w,b)
            for y in range(5):
              for x in range(5):
                  self.S[x][y] ^= Pi[x][y]
            self.S = self.KeccakF(self.S, nr, w, verbose)

            if verbose:
                print("Value after absorption : %s" % (hexlify(self.convertTableToStr(self.S, w))))
        assert len(self.P) < r // 8

    def digest(self, n=64):
        """Does the same as squeeze"""
        return self.squeeze(n)

    def hexdigest(self, n=64):
        """Convenience function that returns the hexadecimal version of the digest"""
        return hexlify(self.squeeze(n))

    def squeeze(self, n):
        """Perform the squeezing phase of Keccak: arbitrary-length digest output is produced from the internal state

        n: the length (in bytes) of the output to produce
        (this method can be called many times to produce as much output as needed)
        """
        w, r, nr, verbose = self.w, self.r, self.nr, self.verbose

        # pad the remaining input and add it to the internal state
        if not self.done_soaking:
            assert self.output_cache == ''
            self.P = self.pad10star1(self.P, r)
            assert len(self.P) == r // 8
            self.soak('')
            self.done_soaking = True
            if verbose:
                print("Value after absorption : %s" % (hexlify(self.convertTableToStr(self.S, w))))

        assert self.P == ''

        # if there is any leftover output from a previous squeezing, return it
        retval = ''
        outputLength = n
        if outputLength <= len(self.output_cache):
            retval, self.output_cache = self.output_cache[:outputLength], self.output_cache[outputLength:]
            return retval
        retval += self.output_cache
        outputLength -= len(self.output_cache)
        self.output_cache = ''
        
        # perform the squeezing operation up to within a block boundary of the output
        while outputLength>=r//8:
            string=self.convertTableToStr(self.S, w)
            retval += string[:r//8]
            outputLength -= r//8
            self.S = self.KeccakF(self.S, nr, w, verbose)

        # fill the rest of the output and save the leftovers, if any
        if outputLength > 0:
            string=self.convertTableToStr(self.S, w)
            self.S = self.KeccakF(self.S, nr, w, verbose)
            temp, self.output_cache = string[:outputLength], string[outputLength:]
            retval += temp
            
        if verbose:
            print("Value after squeezing : %s" % (hexlify(self.convertTableToStr(self.S, w))))

        return retval


try:
    from correct_random import CorrectRandom as random_base
except ImportError:
    import warnings
    warnings.warn("Not having correct_random.CorrectRandom makes some of KeccakRandom's methods produce biased output")
    from random import Random as random_base
class KeccakRandom(random_base):
    def __init__(self, seed=None, keccak_args=dict(), _state=None):
        if _state is not None:
            (keccak_args, keccak_P, keccak_S, keccak_output_cache, self._cache, self._cache_len) = _state
            self.k = Keccak(**keccak_args)
            self.keccak_args = keccak_args
            self.k.done_soaking = True
            self.k.P = keccak_P
            self.k.S = keccak_S
            self.k.output_cache = keccak_output_cache
        else:
            self.k = Keccak(**keccak_args)
            self.keccak_args = keccak_args
            self.k.soak(seed)
            self._cache = 0L
            self._cache_len = 0L

    @classmethod
    def from_state(cls, state):
        return cls(seed=None, keccak_args=None, _state=state)

    def getrandbits(self, n):
        bytes_needed = max(int(math.ceil((1.0*n-self._cache_len) / 8)), 0)

        self._cache |= bytes2int(self.k.squeeze(bytes_needed)) << self._cache_len
        self._cache_len += bytes_needed * 8

        result = self._cache & ((1<<n) - 1)
        self._cache >>= n
        self._cache_len -= n
        return result

    def seed(self, seed):
        self.k = Keccak(**self.keccak_args)
        self.k.soak(seed)

        self._cache = 0L
        self._cache_len = 0L

    def getstate(self):
        return (self.keccak_args, self.k.P,
                self.k.P, self.k.output_cache,
                self._cache, self._cache_len)

    def setstate(self, state):
        (self.keccak_args, self.k.P,
         self.k.P, self.k.output_cache,
         self._cache, self._cache_len) = state

    def jumpahead(self, n):
        # clear Keccak cache
        self.k.squeeze(len(self.k.output_cache))

        # iterate Keccak n times
        for _ in xrange(n):
            self.k.squeeze(self.k.r//8)

        # clear our cache
        self._cache = 0L
        self._cache_len = 0L

__all__ = ['Keccak', 'KeccakError', 'KeccakRandom']
