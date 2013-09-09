import os.path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import cPickle
from math import log, ceil
from copy import deepcopy

import keccak
from damgaardjurik import *
from intbytes import *

class KeygenTest(unittest.TestCase):
    longMessage=True
    def __init__(self, keylen, count, seed='', *args, **kwargs):
        self.keylen = keylen
        self.count = count
        self.seed = seed
        super(KeygenTest, self).__init__(*args, **kwargs)
    def setUp(self):
        self.random = keccak.KeccakRandom(self.seed)
    def runTest(self):
        for j in xrange(-3,4):
            for i in xrange(self.count):
                dj = DamgaardJurik(keylen=(self.keylen+j), random=self.random)
                highbits = dj.n >> (self.keylen+j-1)
                self.assertGreater(highbits, 0, 'With keylen=%d, seed=%s, high bit must be set' \
                                                  % (self.keylen, repr(self.seed)))
                self.assertLess(highbits, 4, 'With keylen=%d, seed=%s, only one extra bit is allowed to be set' \
                                               % (self.keylen, repr(self.seed)))

class PlaintextTest(unittest.TestCase):
    longMessage=True
    def __init__(self, bit_len, count, seed='', *args, **kwargs):
        self.bit_len = bit_len
        self.count = count
        self.seed = seed
        super(PlaintextTest, self).__init__(*args, **kwargs)
    def setUp(self):
        self.random = keccak.KeccakRandom(self.seed)
    def runTest(self):
        for _ in xrange(self.count):
            i = self.random.getrandbits(self.bit_len)
            pt = DamgaardJurikPlaintext(i)
            self.assertEqual(i, int(pt), 'With bit_len=%d, seed=%s, plaintext object did not become the same int' \
                                           % (self.bit_len, repr(self.seed)))
            self.assertEqual(pt, DamgaardJurikPlaintext(deepcopy(i)),
                             'With bit_len=%d, seed=%s, plaintext objects were not equal from int' \
                               % (self.bit_len, repr(self.seed)))

            s = int2bytes(i, int(ceil(self.bit_len / 8.0)))
            pt = DamgaardJurikPlaintext(s)
            self.assertEqual(s, str(pt), 'With bit_len=%d, seed=%s, plaintext object did not become the same str' \
                                           % (self.bit_len, repr(self.seed)))
            self.assertEqual(pt, DamgaardJurikPlaintext(deepcopy(s)),
                             'With bit_len=%d, seed=%s, plaintext objects were not equal from str' \
                               % (self.bit_len, repr(self.seed)))

class SimpleEncryptDecryptTest(KeygenTest):
    def setUp(self):
        super(SimpleEncryptDecryptTest, self).setUp()
        self.dj = DamgaardJurik(keylen=self.keylen, random=self.random)
    def runTest(self):
        for j in xrange(self.count):
            i = self.random.getrandbits(self.keylen - 1)
            plain = DamgaardJurikPlaintext(i)
            self.assertEqual(self.dj.decrypt(self.dj.encrypt(plain, random=self.random)), plain,
                             'With keylen=%d, seed=%s, test string was not the same after an encryption/decryption cycle' \
                               % (self.keylen, repr(self.seed)))

            s = int2bytes(self.random.getrandbits(int(ceil((self.keylen - 1) / 8.0)) - 1))
            plain = DamgaardJurikPlaintext(s)

class EncryptVectorTest(unittest.TestCase):
    longMessage = True
    def __init__(self, keylen, seed, output, *args, **kwargs):
        self.keylen = keylen
        self.seed = seed
        self.output = output
        super(EncryptVectorTest, self).__init__(*args, **kwargs)
    def setUp(self):
        self.random = keccak.KeccakRandom(self.seed)
        self.dj = DamgaardJurik(keylen=self.keylen+1, random=self.random)
    def runTest(self):
        plain = DamgaardJurikPlaintext(self.random.getrandbits(self.keylen))
        self.assertEqual(self.dj.encrypt(plain, random=self.random), self.output,
                         'With keylen=%d, seed=%s, encryption did not match expected output' \
                           % (self.keylen, repr(self.seed)))

if __name__ == '__main__':
    keylengths = [512, 768, 1024, 2048, 4096]
    keygen_tests = unittest.TestSuite(map(lambda keylen: KeygenTest(keylen, 10), keylengths))
    plaintext_tests = unittest.TestSuite(map(lambda bit_len: PlaintextTest(bit_len, 128), keylengths))
    simple_tests = unittest.TestSuite(map(lambda keylen: SimpleEncryptDecryptTest(keylen+1, 128), keylengths))
    encryption_tests = unittest.TestSuite(EncryptVectorTest(keylen, seed, output)
                                          for keylen, temp in cPickle.Unpickler(open('dj_encryptions.pkl','rb')).load().iteritems()
                                          for seed, output in temp.iteritems())
    
    all_tests = unittest.TestSuite([keygen_tests, plaintext_tests, simple_tests, encryption_tests])
    unittest.TextTestRunner(verbosity=2).run(all_tests)
