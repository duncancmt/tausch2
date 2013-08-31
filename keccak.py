#! /usr/bin/python2
# The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
# Michael Peeters and Gilles Van Assche. For more information, feedback or
# questions, please refer to our website: http://keccak.noekeon.org/
# 
# Implementation by Renaud Bauvin,
# hereby denoted as "the implementer".
# 
# To the extent possible under law, the implementer has waived all copyright
# and related or neighboring rights to the source code in this file.
# http://creativecommons.org/publicdomain/zero/1.0/

import math
from binascii import hexlify, unhexlify

class KeccakError(Exception):
    """Class of error used in the Keccak implementation

    Use: raise KeccakError("Text to be displayed")"""


class Keccak(object):
    """
    Class implementing the Keccak sponge function
    """
    def __init__(self, b=1600):
        """Constructor:

        b: parameter b, must be 25, 50, 100, 200, 400, 800 or 1600 (default value)"""
        self.setB(b)

    def setB(self,b):
        """Set the value of the parameter b (and thus w,l and nr)

        b: parameter b, must be choosen among [25, 50, 100, 200, 400, 800, 1600]
        """

        if b not in [25, 50, 100, 200, 400, 800, 1600]:
            raise KeccakError('b value not supported - use 25, 50, 100, 200, 400, 800 or 1600')

        # Update all the parameters based on the used value of b
        self.b=b
        self.w=b//25
        self.l=int(math.log(self.w,2))
        self.nr=12+2*self.l

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
    r=[[0,    36,     3,    41,    18]    ,
       [1,    44,    10,    45,     2]    ,
       [62,    6,    43,    15,    61]    ,
       [28,   55,    25,    21,    56]    ,
       [27,   20,    39,     8,    14]    ]

    ## Generic utility functions

    def rot(self,x,n):
        """Bitwise rotation (to the left) of n bits considering the \
        string of bits is w bits long"""

        n = n%self.w
        return ((x>>(self.w-n))+(x<<n))%(1<<self.w)

    def fromStringToLane(self, string):
        """Convert a string of bytes to a lane value"""

        #Perform the modification
        return sum(ord(char) << (j * 8) for j, char in enumerate(string))

    def fromLaneToString(self, lane):
        """Convert a lane value to a string of bytes"""

        #Perform the modification
        h = hex(int(lane))[2:]
        if h[-1] == 'L':
            h = h[:-1]
        h = '0'*(self.w//4 - len(h)) + h
        return unhexlify(h)[::-1]

    def printState(self, state, info):
        """Print on screen the state of the sponge function preceded by \
        string info

        state: state of the sponge function
        info: a string of characters used as identifier"""

        print("Current value of state: %s" % (info))
        for y in range(5):
            line=[]
            for x in range(5):
                 line.append(hex(state[x][y]))
            print('\t%s' % line)

    ### Conversion functions String <-> Table (and vice-versa)

    def convertStrToTable(self,string):
        """Convert a string of bytes to its 5x5 matrix representation

        string: string of bytes"""

        #Check that input paramaters
        if self.w%8!= 0:
            raise KeccakError("w is not a multiple of 8")
        if len(string)!=(self.b)//8:
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
                offset=((5*y+x)*self.w)//8
                output[x][y]=self.fromStringToLane(string[offset:offset+(self.w//8)])
        return output

    def convertTableToStr(self,table):
        """Convert a 5x5 matrix representation to its string representation"""

        #Check input format
        if self.w%8!= 0:
            raise KeccakError("w is not a multiple of 8")
        if (len(table)!=5) or (False in [len(row)==5 for row in table]):
            raise KeccakError("table must be 5x5")

        #Convert
        output=[None]*25
        for x in range(5):
            for y in range(5):
                output[5*y+x]=self.fromLaneToString(table[x][y])
        output = ''.join(output)
        return output

    def Round(self,A,RCfixed):
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
            D[x] = C[(x-1)%5]^self.rot(C[(x+1)%5],1)

        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y]^D[x]

        #Rho and Pi steps
        for x in range(5):
          for y in range(5):
                B[y][(2*x+3*y)%5] = self.rot(A[x][y], self.r[x][y])

        #Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y]^((~B[(x+1)%5][y]) & B[(x+2)%5][y])

        #Iota step
        A[0][0] = A[0][0]^RCfixed

        return A

    def KeccakF(self,A, verbose=False):
        """Perform Keccak-f function on the state A

        A: 5x5 matrix containing the state
        verbose: a boolean flag activating the printing of intermediate computations
        """

        if verbose:
            self.printState(A,"Before first round")

        for i in range(self.nr):
            #NB: result is truncated to lane size
            A = self.Round(A,self.RC[i]%(1<<self.w))

            if verbose:
                  self.printState(A,"Satus end of round #%d/%d" % (i+1,self.nr))

        return A

    ### Padding rule

    def pad10star1(self, M, n, M_bit_len=None):
        """Pad M with the pad10*1 padding rule to reach a length multiple of r bits

        M: string to be padded
        n: block length in bits (must be a multiple of 8)
        M_bit_len: length of M (in bits) only supply this argument if M is not an octet stream
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

    def Keccak(self,M,r=1024,c=576,n=1024,verbose=False):
        """Compute the Keccak[r,c,d] sponge function on message M

        M: string to be hashed
        r: bitrate in bits (default: 1024)
        c: capacity in bits (default: 576)
        n: length of output in bits (default: 1024),
        verbose: print the details of computations(default:False)
        """

        #Check the inputs
        if (r<0) or (r%8!=0):
            raise KeccakError('r must be a multiple of 8 in this implementation')
        if (n%8!=0):
            raise KeccakError('outputLength must be a multiple of 8')
        self.setB(r+c)

        if verbose:
            print("Create a Keccak function with (r=%d, c=%d (i.e. w=%d))" % (r,c,(r+c)//25))

        #Compute lane length (in bits)
        w=(r+c)//25

        # Initialisation of state
        S=[[0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0]]

        #Padding of messages
        P = self.pad10star1(M, r)

        if verbose:
            print("String ready to be absorbed: %s (will be completed by %d x '00')" % (hexlify(P), c//8))

        #Absorbing phase
        for i in range((len(P)*8)//r):
            print 'calling convertStrToTable'
            Pi=self.convertStrToTable(P[i*(r//8):(i+1)*(r//8)]+'\x00'*(c//8))

            for y in range(5):
              for x in range(5):
                  S[x][y] = S[x][y]^Pi[x][y]
            S = self.KeccakF(S, verbose)

        if verbose:
            print("Value after absorption : %s" % (hexlify(self.convertTableToStr(S))))

        #Squeezing phase
        Z = ''
        outputLength = n
        while outputLength>0:
            string=self.convertTableToStr(S)
            Z = Z + string[:r//8]
            outputLength -= r
            if outputLength>0:
                S = self.KeccakF(S, verbose)

            # NB: done by block of length r, could have to be cut if outputLength
            #     is not a multiple of r

        if verbose:
            print("Value after squeezing : %s" % (hexlify(self.convertTableToStr(S))))

        return Z[:n//8]
