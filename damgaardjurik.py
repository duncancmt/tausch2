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
            return_bytes = True
        elif isinstance(message, (Integral, mpz_type)):
            i = message
            return_bytes = False
        else:
            raise ValueError('message must be a bytes or a number')
        
        r = 1 << (self.keylen * (s + 1))
        while r >= ns1:
            r = random.getrandbits(self.keylen * (s + 1))
        
        c = pow((1+self.n), i, ns1)
        c *= pow(r, ns, ns1)
        c %= ns1
        if return_bytes:
            h = hex(int(c))[2:]
            if h[-1] == 'L':
                h = h[:-1]
            if len(h) % 2 == 1:
                h = '0'+h
            return unhexlify(h)
        else:
            return int(c)

    def decrypt(self, message):
        if self.l is None:
            raise RuntimeError('This key has no private material for decryption')
        
        if isinstance(message, bytes):
            s = int(ceil(8.0 * len(message) / self.keylen) - 1)
            c = int(hexlify(message), base=16)
            return_bytes = True
        elif isinstance(message, (Integral, mpz_type)):
            s = int(ceil(log(int(message), 2**self.keylen)) - 1)
            c = message
            return_bytes = False
        else:
            raise ValueError('message must be a bytes or a number')
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

        if return_bytes:
            h = hex(int(i))[2:]
            if h[-1] == 'L':
                h = h[:-1]
            if len(h) % 2 == 1:
                h = '0'+h
            return unhexlify(h)
        else:
            return int(i)

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
