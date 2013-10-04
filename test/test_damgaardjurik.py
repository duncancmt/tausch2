import os.path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import cPickle
from math import ceil
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

class SimpleCiphertextTest(PlaintextTest):
    def runTest(self):
        for _ in xrange(self.count):
            ns1 = self.random.getrandbits(self.bit_len * 2)
            i = self.random.randint(1, ns1-1)
            ct = DamgaardJurikCiphertext(i,ns1)
            self.assertEqual(i, int(ct), 'With bit_len=%d, seed=%s, ciphertext object did not become the same int' \
                                           % (self.bit_len, repr(self.seed)))
            self.assertEqual(ct, DamgaardJurikCiphertext(deepcopy(i),deepcopy(ns1)),
                             'With bit_len=%d, seed=%s, ciphertext objects were not equal from int' \
                               % (self.bit_len, repr(self.seed)))

class CiphertextTest(SimpleCiphertextTest):
    def setUp(self):
        super(SimpleCiphertextTest, self).setUp()
        self.dj = DamgaardJurik(keylen=self.bit_len+1, random=self.random)
    def runTest(self):
        for _ in xrange(self.count):
            p_increment = self.random.getrandbits(32)
            p_decrement = self.random.randrange(32)
            p_multiplier = self.random.getrandbits(32)
            p_divisor = self.random.getrandbits(32)

            start = p_divisor * ceil(float(p_increment) / p_divisor)
            stop = (1<<self.bit_len)-1 # guaranteed to be less than self.dj.n
            stop = min(stop//p_multiplier, stop-p_increment)
            step = p_divisor
            pt = self.random.randrange(start, stop, step)
            pt = DamgaardJurikPlaintext(pt)
            ct = self.dj.encrypt(pt, random=self.random)

            c_increment = self.dj.encrypt(DamgaardJurikPlaintext(p_increment), random=self.random)
            self.assertEqual(self.dj.decrypt(ct + c_increment), pt + p_increment,
                             'With bit_len=%d, seed=%s, \'adding\' ciphertexts did not decrypt to the sum of their plaintexts' \
                               % (self.bit_len, repr(self.seed)))

            c_decrement = self.dj.encrypt(DamgaardJurikPlaintext(p_decrement), random=self.random)
            self.assertEqual(self.dj.decrypt(ct - c_decrement), pt - p_decrement,
                             'With bit_len=%d, seed=%s, \'subtracting\' ciphertexts did not decrypt to the difference of their plaintexts' \
                               % (self.bit_len, repr(self.seed)))

            self.assertEqual(self.dj.decrypt(ct * p_multiplier), pt * p_multiplier,
                             'With bit_len=%d, seed=%s, \'multiplying\' the ciphertext by a constant did not result in the plaintext being multplied by the same constant' \
                               % (self.bit_len, repr(self.seed)))

            self.assertEqual(self.dj.decrypt(ct / p_divisor), pt / p_divisor,
                             'With bit_len=%d, seed=%s, \'dividing\' the ciphertext by a constant did not result in the plaintext being divided by the same constant' \
                               % (self.bit_len, repr(self.seed)))

            pt = -self.random.getrandbits(self.bit_len)
            pt = DamgaardJurikPlaintext(pt)
            ct = self.dj.encrypt(pt, random=self.random)
            self.assertEqual(self.dj.decrypt(-ct), -pt,
                             'With bit_len=%d, seed=%s, \'negation\' of the ciphertext did not result in the negation of the plaintext' \
                               % (self.bit_len, repr(self.seed)))


class SimpleEncryptDecryptTest(KeygenTest):
    longMessage=True
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

class DecryptVectorTest(unittest.TestCase):
    longMessage = True
    def __init__(self, keylen, seed, input, *args, **kwargs):
        self.keylen = keylen
        self.seed = seed
        self.input = input
        super(DecryptVectorTest, self).__init__(*args, **kwargs)
    def setUp(self):
        self.random = keccak.KeccakRandom(self.seed)
        self.dj = DamgaardJurik(keylen=self.keylen+1, random=self.random)
    def runTest(self):
        plain = DamgaardJurikPlaintext(self.random.getrandbits(self.keylen))
        self.assertEqual(self.dj.decrypt(self.input), plain,
                         'With keylen=%d, seed=%s, decryption did not match expected output' \
                           % (self.keylen, repr(self.seed)))

if __name__ == '__main__':
    keylengths = [512, 768, 1024, 2048, 4096]
    keygen_tests = unittest.TestSuite(map(lambda keylen: KeygenTest(keylen, 10), keylengths))
    plaintext_tests = unittest.TestSuite(map(lambda bit_len: PlaintextTest(bit_len, 128), keylengths))
    ciphertext_tests = unittest.TestSuite(map(lambda bit_len: SimpleCiphertextTest(bit_len, 128), keylengths) \
                                          + map(lambda bit_len: CiphertextTest(bit_len, 128), keylengths))
    simple_tests = unittest.TestSuite(map(lambda keylen: SimpleEncryptDecryptTest(keylen+1, 128), keylengths))

    ### Vectors generated by ###
    # import keccak
    # import damgaardjurik
    # data=dict()
    # for keylen in [512, 768, 1024, 2048, 4096]:
    #     data[keylen] = dict()
    #     for seed in ['', 'foo', 'bar', 'baz', 'qux', 'quux', 'corge', 'grault', 'garply', 'waldo', 'fred', 'plugh', 'xyzzy', 'thud' ]:
    #         random = keccak.KeccakRandom(seed)
    #         dj = damgaardjurik.DamgaardJurik(keylen+1, random=random)
    #         plain = damgaardjurik.DamgaardJurikPlaintext(random.getrandbits(keylen))
    #         data[keylen][seed] = dj.encrypt(plain, random=random)
    #         data[keylen][seed].c = int(data[keylen][seed].c)
    #         data[keylen][seed].ns1 = int(data[keylen][seed].ns1)
    test_vectors = cPickle.Unpickler(open('dj_encryptions.pkl','rb')).load()
    encryption_tests = unittest.TestSuite(EncryptVectorTest(keylen, seed, output)
                                          for keylen, temp in test_vectors.iteritems()
                                          for seed, output in temp.iteritems())
    decryption_tests = unittest.TestSuite(DecryptVectorTest(keylen, seed, output)
                                          for keylen, temp in test_vectors.iteritems()
                                          for seed, output in temp.iteritems())
    all_tests = unittest.TestSuite([keygen_tests, plaintext_tests, ciphertext_tests, simple_tests, encryption_tests, decryption_tests])
    unittest.TextTestRunner(verbosity=2).run(all_tests)
