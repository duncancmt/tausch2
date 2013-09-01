import random
from math import ceil, floor, log
from fractions import gcd
from numbers import Integral
from primes import gen_prime
from intbytes import int2bytes, bytes2int

try:
    from gmpy2 import mpz, invert
    mpz_type = type(mpz())
    has_gmpy = True
except ImportError:
    try:
        from gmpy import mpz, invert
        mpz_type = type(mpz())
        has_gmpy = True
    except ImportError:
        import warnings
        warnings.warn('Not having gmpy2 or gmpy makes this at least 10x slower')
        has_gmpy = False

def lcm(a,b):
    """Return the least common multiple (LCM) of the arguments"""
    return (a * b) // gcd(a,b)

if not has_gmpy:
    def egcd(a, b):
        """The Extended Euclidean Algorithm
        In addition to finding the greatest common divisor (GCD) of the
        arguments, also find and return the coefficients of the linear
        combination that results in the GCD.
        """
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    def invert(a, m):
        """Return the multiplicative inverse of a, mod m"""
        g, x, y = egcd(a, m)
        if g != 1:
            raise ValueError('modular inverse does not exist')
        else:
            return x % m



class DamgaardJurik(object):
    """
    Class implementing the Damgaard-Jurik family of asymmetric cryptosystems

    The Paillier cryptosystem is a specific instance of this cryptosystem with s=1
    """
    def __init__(self, keylen=None, random=random, _state=None):
        """Constructor:

        keylen: the length (in bits) of the key modulus
            (the key modulus may be a few bits longer than specified, but keylen is the minimum)
        random: (optional) a source of entropy for key generation, the default is python's random
        _state: (do not use) a state tuple to initialize from instead of performing key generation
        """
        if _state is not None:
            # initialize self from given state
            (self.n, self.l) = _state
            self.keylen = int(ceil(log(self.n,2)))
            if has_gmpy:
                self.n = mpz(self.n)
                if self.l is not None:
                    self.l = mpz(self.l)
        else:
            # generate key and initialize self
            assert keylen is not None
            self.keylen = keylen
            self.generate(random)

    def generate(self, random=random):
        """Generate a keypair and initialize this instance with it

        random: (optional) a source of entropy for key generation, the default is python's random
        """
        prime_len = int(ceil(self.keylen / 2.0))
        p = gen_prime(prime_len+1, random=random)
        q = gen_prime(prime_len, random=random)

        self.n = p * q
        if has_gmpy:
            self.n = mpz(self.n)
        self.l = lcm(p-1, q-1)

    def encrypt(self, message, s=1, random=random):
        """Encrypt a message with the public key

        message: the message to be encrypted, may be a bytes, integer type, or DamgaardJurikPlaintext
            (bytes are interpreted as little-endian, least-significant-byte first)
        s: (optional) one less than the exponent of the modulus. Determines the maximum message length.
            The default is 1, which results in Paillier encryption. If s is None, automatically choose the
            minimum s that will fit the message.
        random: (optional) a source of entropy for the generation of r, a parameter for the encryption
            the default is python's random
        """

        # format the message as an integer regardless of how it was given
        if isinstance(message, bytes):
            i = bytes2int(message)
            return_type = bytes
        elif isinstance(message, DamgaardJurikPlaintext):
            i = int(message)
            return_type = DamgaardJurikCiphertext
        elif isinstance(message, (Integral, mpz_type)):
            i = message
            return_type = int
        else:
            raise ValueError('message must be a bytes, DamgaardJurikPlaintext, or number')

        # check/calculate s
        if s is None:
            # determine s from message length
            s = int(ceil(log(i, int(self.n))))
            assert s > 0
        elif i >= self.n**s: # check that the message will fit with the given s
            raise ValueError('message value is too large for the given value of s')

        # utility constants
        ns = self.n**s
        ns1 = ns*self.n

        # generate the random parameter r
        r = 1 << (self.keylen * (s + 1))
        while r >= ns1:
            r = random.getrandbits(self.keylen * (s + 1))

        # perform the encryption
        c = pow((1+self.n), i, ns1)
        c *= pow(r, ns, ns1)
        c %= ns1

        # format the ciphertext to match the type of the plaintext
        if return_type is bytes:
            return int2bytes(c, int(ceil(log(int(self.n), 2)*(s+1)/8.0)))
        elif return_type is DamgaardJurikCiphertext:
            return DamgaardJurikCiphertext(c, ns1)
        elif return_type is int:
            return int(c)
        else:
            raise RuntimeError('Invalid value for return_type')

    def decrypt(self, message):
        """Decrypt and encrypted message. Only works if this instance has a private key available.

        message: the message to be decrypted, may be a bytes, integer type, or DamgaardJurikCiphertext
            (bytes are interpreted as little-endian, least-significant-byte first)
        """
        # check that the private key is available
        if self.l is None:
            raise RuntimeError('This key has no private material for decryption')

        # format the ciphertext as an integer, regardless of the given type
        if isinstance(message, bytes):
            c = bytes2int(message)
            return_type = bytes
        elif isinstance(message, DamgaardJurikCiphertext):
            c = int(message)
            return_type = DamgaardJurikPlaintext
        elif isinstance(message, (Integral, mpz_type)):
            c = message
            return_type = int
        else:
            raise ValueError('message must be a bytes, DamgaardJurikCiphertext, or number')

        # determine s from the message length
        s = int(ceil(log(c, int(self.n)) - 1))
        assert s > 0

        # utility constants
        ns = self.n**s
        ns1 = ns*self.n
        assert c < ns1

        # calculate the decryption key for the given s
        d = invert(self.l, ns) * self.l
        assert d % ns == 1
        assert d % self.l == 0

        # perform the decryption
        c = pow(c, d, ns1)
        i = 0
        for j in xrange(1, s+1):
            nj = self.n**j
            nj1 = nj*self.n
            t1 = ((c % nj1) - 1) / self.n
            t2 = i
            kfac = 1
            for k in xrange(2, j+1):
                kfac *= k
                i -= 1

                t2 *= i
                t2 %= nj
                
                t1 -= (t2 * self.n ** (k - 1)) * invert(kfac, nj)
                t1 %= nj
            i = t1

        # format the plaintext to match the type of the ciphertext
        if return_type is bytes:
            return int2bytes(i, int(floor(self.keylen*s/8.0)))
        elif return_type is DamgaardJurikPlaintext:
            return DamgaardJurikPlaintext(i)
        elif return_type is int:
            return int(i)
        else:
            raise RuntimeError('Invalid value for return_type')

    @property
    def pubkey(self):
        return int(self.n)
    @property
    def privkey(self):
        return (int(self.n), int(self.l))

    @classmethod
    def from_pubkey(cls, pubkey):
        return cls(_state=(pubkey, None))
    @classmethod
    def from_privkey(cls, privkey):
        return cls(_state=privkey)

    def __getstate__(self):
        return self.privkey
    def __setstate__(self, state):
        self.__init__(_state=state)

class DamgaardJurikPlaintext(long):
    """Class representing the plaintext in Damgaard-Jurik"""
    def __repr__(self):
        return 'DamgaardJurikPlaintext(%s)' % str(self)
class DamgaardJurikCiphertext(Integral):
    """Class representing the ciphertext in Damgaard-Jurik. Also represents the homomorphisms of Damgaard-Jurik"""
    def __init__(self, c, ns1, cache_powers=True):
        """Constructor:

        c: the ciphertext, represented as an integer type
        ns1: the exponentiated modulus used in generating this ciphertext
        cache_powers: (optional) if True, we cache the powers of the ciphertext that are powers of two
            this speeds up the square-and-multiply exponentiation used if lots of homomorphic manipulation
            takes place, the default is True
        """
        self.c = c
        self.ns1 = ns1
        self.cache_powers = cache_powers
        if cache_powers:
            self.cache = [None]*int(ceil(log(int(ns1), 2)))
            self.cache[0] = c
            for i in xrange(1, len(self.cache)):
                self.cache[i] = self.cache[i-1]**2
        else:
            self.cache = None

    def __repr__(self):
        return 'DamgaardJurikCiphertext(%s, %s, cache_powers=%s)' % (self.c, self.ns1, self.cache_powers)

    def __add__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            if self.ns1 != other.ns1:
                raise ValueError('Cannot add ciphertexts that belong to different keys')
            return type(self)(self.c * other.c % self.ns1, self.ns1, self.cache_powers)
        else:
            # other is a int or long
            return type(self)(self.c * other % self.ns1, self.ns1, self.cache_powers)
    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            if self.ns1 != other.ns1:
                raise ValueError('Cannot subtract ciphertexts that belong to different keys')
            return type(self)(self.c * invert(other.c, self.ns1) % self.ns1, self.ns1, self.cache_powers)
        else:
            # other is a int or long
            return type(self)(self.c * invert(other, self.ns1) % self.ns1, self.ns1, self.cache_powers)
    def __rsub__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            if self.ns1 != other.ns1:
                raise ValueError('Cannot subtract ciphertexts that belong to different keys')
            return type(self)(other.c * invert(self.c, self.ns1) % self.ns1, self.ns1, self.cache_powers)
        else:
            # other is a int or long
            return type(self)(other * invert(self.c, self.ns1) % self.ns1, self.ns1, self.cache_powers)
        
    def __mul__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            other = other.c
        other %= self.ns1
        if self.cache_powers:
            retval = 1
            garbage = 1
            for i, b in enumerate(reversed(bin(other)[2:])):
                if b == '1':
                    retval *= self.cache[i]
                    retval %= self.ns1
                else:
                    garbage *= self.cache[i]
                    garbage %= self.ns1
                garbage = retval
            return type(self)(retval, self.ns1, self.cache_powers)
        else:
            return type(self)(pow(self.c, other, self.ns1), self.ns1, self.cache_powers)
    def __rmul__(self, other):
        return self * other

    def __div__(self, other):
        raise NotImplementedError
    def __floordiv__(self, other):
        raise NotImplementedError
    def __truediv__(self, other):
        raise NotImplementedError
    def __mod__(self, other):
        raise NotImplementedError
    def __divmod__(self, other):
        raise NotImplementedError
    def __rdiv__(self, other):
        raise NotImplementedError
    def __rfloordiv__(self, other):
        raise NotImplementedError
    def __rtruediv__(self, other):
        raise NotImplementedError
    def __rmod__(self, other):
        raise NotImplementedError
    def __rdivmod__(self, other):
        raise NotImplementedError

    def __neg__(self, other):
        return type(self)(invert(self.c, self.ns1), self.ns1, self.cache_powers)
    def __pos__(self, other):
        return self

    def __lt__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            return self.c < other.c
        else:
            return self.c < other
    def __le__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            return self.c <= other.c
        else:
            return self.c <= other
    def __eq__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            return self.c == other.c
        else:
            return self.c == other
    def __ne__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            return self.c != other.c
        else:
            return self.c != other
    def __gt__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            return self.c > other.c
        else:
            return self.c > other
    def __ge__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            return self.c >= other.c
        else:
            return self.c >= other

    def __trunc__(self):
        return int(self.c)
    def __long__(self):
        return long(self.c)

    def __and__(self, other):
        return NotImplemented
    def __xor__(self, other):
        return NotImplemented
    def __or__(self, other):
        return NotImplemented
    def __pow__(self, other):
        return NotImplemented
    def __lshift__(self, other):
        return NotImplemented
    def __rshift__(self, other):
        return NotImplemented
    def __rand__(self, other):
        return NotImplemented
    def __rxor__(self, other):
        return NotImplemented
    def __ror__(self, other):
        return NotImplemented
    def __rpow__(self, other):
        return NotImplemented
    def __rlshift__(self, other):
        return NotImplemented
    def __rrshift__(self, other):
        return NotImplemented

    def __iadd__(self, other):
        return NotImplemented
    def __isub__(self, other):
        return NotImplemented
    def __imul__(self, other):
        return NotImplemented
    def __idiv__(self, other):
        return NotImplemented
    def __itruediv__(self, other):
        return NotImplemented
    def __ifloordiv__(self, other):
        return NotImplemented
    def __imod__(self, other):
        return NotImplemented
    def __ipow__(self, other):
        return NotImplemented
    def __ilshift__(self, other):
        return NotImplemented
    def __irshift__(self, other):
        return NotImplemented
    def __iand__(self, other):
        return NotImplemented
    def __ixor__(self, other):
        return NotImplemented
    def __ior__(self, other):
        return NotImplemented
    def __abs__(self, other):
        return NotImplemented
    def __invert__(self, other):
        return NotImplemented

__all__ = [ 'DamgaardJurik', 'DamgaardJurikPlaintext', 'DamgaardJurikCiphertext' ]
