import random
from math import ceil, log
from fractions import gcd
from numbers import Integral
from binascii import hexlify, unhexlify
from primes import gen_prime

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
    return (a * b) // gcd(a,b)

if not has_gmpy:
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    def invert(a, m):
        g, x, y = egcd(a, m)
        if g != 1:
            raise ValueError('modular inverse does not exist')
        else:
            return x % m



class DamgaardJurik(object):
    def __init__(self, keylen=None, random=random, _state=None):
        if _state is not None:
            (self.n, self.l) = _state
            self.keylen = int(ceil(log(self.n,2)))
            if has_gmpy:
                self.n = mpz(self.n)
                if self.l is not None:
                    self.l = mpz(self.l)
        else:
            assert keylen is not None
            self.keylen = keylen
            self.generate(random)

    def generate(self, random=random):
        p = gen_prime(self.keylen // 2, random=random)
        q = gen_prime(self.keylen // 2, random=random)
        if has_gmpy:
            p = mpz(p)
            q = mpz(q)
        self.n = p * q
        self.l = lcm(p-1, q-1)

    def encrypt(self, message, s=1, random=random):
        if s is None:
            if isinstance(message, bytes):
                s = int(ceil(8.0 * len(message) / self.keylen))
            elif isinstance(message, (Integral, mpz_type)):
                s = int(ceil(log(int(message), 2**self.keylen)))
        else:
            if isinstance(message, bytes):
                if len(message) < ((self.keylen * s - 1) / 8):
                    raise ValueError('message is too long for the given value of s')
            elif isinstance(message, (Integral, mpz_type)):
                if message >= self.n**s:
                    raise ValueError('message value is too large for the given value of s')

        assert s > 0
        ns = self.n**s
        ns1 = ns*self.n
        if isinstance(message, bytes):
            i = int(hexlify(message), base=16)
            return_type = bytes
        elif isinstance(message, DamgaardJurikPlaintext):
            i = int(message)
            return_type = DamgaardJurikCiphertext
        elif isinstance(message, (Integral, mpz_type)):
            i = message
            return_type = int
        else:
            raise ValueError('message must be a bytes, DamgaardJurikPlaintext, or number')
        
        r = 1 << (self.keylen * (s + 1))
        while r >= ns1:
            r = random.getrandbits(self.keylen * (s + 1))
        
        c = pow((1+self.n), i, ns1)
        c *= pow(r, ns, ns1)
        c %= ns1
        if return_type is bytes:
            h = hex(int(c))[2:]
            if h[-1] == 'L':
                h = h[:-1]
            if len(h) % 2 == 1:
                h = '0'+h
            return unhexlify(h)
        elif return_type is DamgaardJurikCiphertext:
            return DamgaardJurikCiphertext(c, ns1)
        elif return_type is int:
            return int(c)
        else:
            raise RuntimeError('Invalid value for return_type')

    def decrypt(self, message):
        if self.l is None:
            raise RuntimeError('This key has no private material for decryption')
        
        if isinstance(message, bytes):
            s = int(ceil(8.0 * len(message) / self.keylen) - 1)
            c = int(hexlify(message), base=16)
            return_type = bytes
        elif isinstance(message, DamgaardJurikCiphertext):
            s = int(ceil(log(int(message), 2**self.keylen)) - 1)
            c = int(message)
            return_type = DamgaardJurikPlaintext
        elif isinstance(message, (Integral, mpz_type)):
            s = int(ceil(log(int(message), 2**self.keylen)) - 1)
            c = message
            return_type = int
        else:
            raise ValueError('message must be a bytes, DamgaardJurikCiphertext, or number')
        assert s > 0

        ns = self.n**s
        ns1 = ns*self.n
        d = invert(self.l, ns) * self.l
        assert d % ns == 1
        assert d % self.l == 0
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

        if return_type is bytes:
            h = hex(int(i))[2:]
            if h[-1] == 'L':
                h = h[:-1]
            if len(h) % 2 == 1:
                h = '0'+h
            return unhexlify(h)
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
    def __repr__(self):
        return 'DamgaardJurikPlaintext(%s)' % str(self)
class DamgaardJurikCiphertext(Integral):
    def __init__(self, c, ns1, cache_powers=True):
        self.c = c
        self.ns1 = ns1
        self.cache_powers = cache_powers
        self.cache = [None]*int(ceil(log(int(ns1), 2)))

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
        raise NotImplementedError
    def __rsub__(self, other):
        raise NotImplementedError
        
    def __mul__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            other = other.c
        other %= self.ns1
        if self.cache_powers:
            retval = 1
            for i, b in enumerate(reversed(bin(other)[2:])):
                if b == '1':
                    if self.cache[i] is None:
                        self.cache[i] = pow(self.c, 1 << i, self.ns1)
                    retval *= self.cache[i]
                    retval %= self.ns1
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
    def __neg__(self, other):
        return NotImplemented
    def __pos__(self, other):
        return NotImplemented
    def __abs__(self, other):
        return NotImplemented
    def __invert__(self, other):
        return NotImplemented
