import os.path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import cPickle
import subprocess
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
                self.assertEqual(dj, cPickle.loads(cPickle.dumps(dj)),
                                 'With keylen=%d, seed=%s, key was not equal after pickling and unpickling' \
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

            self.assertEqual(pt, cPickle.loads(cPickle.dumps(pt)),
                             'With bit_len=%d, seed=%s, plaintext objects were not equal after pickling and unpickling' \
                               % (self.bit_len, repr(self.seed)))

class SimpleCiphertextTest(PlaintextTest):
    def setUp(self):
        super(SimpleCiphertextTest, self).setUp()
        self.dj = DamgaardJurik(keylen=self.bit_len+1, random=self.random)
    def runTest(self):
        for _ in xrange(self.count):
            pt = DamgaardJurikPlaintext(self.random.randint(0, self.dj.n - 1))
            ct = self.dj.encrypt(pt, random=self.random)
            self.assertEqual(ct, int(ct), 'With bit_len=%d, seed=%s, ciphertext object did not become the same int' \
                                           % (self.bit_len, repr(self.seed)))
            self.assertEqual(ct, DamgaardJurikCiphertext(int(ct), self.dj),
                             'With bit_len=%d, seed=%s, ciphertext objects were not equal from int' \
                               % (self.bit_len, repr(self.seed)))
            self.assertEqual(ct, DamgaardJurikCiphertext(str(ct), self.dj),
                             'With bit_len=%d, seed=%s, ciphertext objects were not equal from str' \
                               % (self.bit_len, repr(self.seed)))
            self.assertEqual(ct, cPickle.loads(cPickle.dumps(ct)),
                             'With bit_len=%d, seed=%s, ciphertext objects were not equal after pickling and unpickling' \
                               % (self.bit_len, repr(self.seed)))

class CiphertextTest(SimpleCiphertextTest):
    def runTest(self):
        for _ in xrange(self.count):
            p_neg = DamgaardJurikPlaintext(-self.random.getrandbits(self.bit_len))
            c_neg = self.dj.encrypt(p_neg, random=self.random)
            self.assertEqual(self.dj.decrypt(-c_neg), -p_neg,
                             'With bit_len=%d, seed=%s, \'negation\' of the ciphertext did not result in the negation of the plaintext' \
                               % (self.bit_len, repr(self.seed)))

            # TODO: test for s>1
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
            self.assertEqual(self.dj.decrypt(c_increment + ct), p_increment + pt,
                             'With bit_len=%d, seed=%s, \'adding\' ciphertexts in reverse order did not decrypt to the sum of their plaintexts' \
                               % (self.bit_len, repr(self.seed)))
            self.assertEqual(self.dj.decrypt(ct + p_increment), pt + p_increment,
                             'With bit_len=%d, seed=%s, \'adding\' an integer to a ciphertext did not decrypt to the sum of the plaintext and the integer' \
                               % (self.bit_len, repr(self.seed)))
            self.assertEqual(self.dj.decrypt(p_increment + ct), p_increment + pt,
                             'With bit_len=%d, seed=%s, \'adding\' a ciphertext to an integer did not decrypt to the sum of the plaintext and the integer' \
                               % (self.bit_len, repr(self.seed)))

            c_decrement = self.dj.encrypt(DamgaardJurikPlaintext(p_decrement), random=self.random)
            self.assertEqual(self.dj.decrypt(ct - c_decrement), pt - p_decrement,
                             'With bit_len=%d, seed=%s, \'subtracting\' ciphertexts did not decrypt to the difference of their plaintexts' \
                               % (self.bit_len, repr(self.seed)))
            self.assertEqual(self.dj.decrypt(-(c_decrement - ct)), pt - p_decrement,
                             'With bit_len=%d, seed=%s, \'subtracting\' ciphertexts in reverse order did not decrypt to the difference of their plaintexts' \
                               % (self.bit_len, repr(self.seed)))
            self.assertEqual(self.dj.decrypt(ct - p_decrement), pt - p_decrement,
                             'With bit_len=%d, seed=%s, \'subtracting\' an integer from a ciphertext did not decrypt to the difference of the plaintext and the integer' \
                               % (self.bit_len, repr(self.seed)))
            self.assertEqual(self.dj.decrypt(-(p_decrement - ct)), pt - p_decrement,
                             'With bit_len=%d, seed=%s, \'subtracting\' an integer from a ciphertext in reverse order did not decrypt to the difference of the plaintext and the integer' \
                               % (self.bit_len, repr(self.seed)))

            self.assertEqual(self.dj.decrypt(ct * p_multiplier), pt * p_multiplier,
                             'With bit_len=%d, seed=%s, \'multiplying\' the ciphertext by a constant did not result in the plaintext being multplied by the same constant' \
                               % (self.bit_len, repr(self.seed)))
            self.assertEqual(self.dj.decrypt(p_multiplier * ct), pt * p_multiplier,
                             'With bit_len=%d, seed=%s, \'multiplying\' the ciphertext by a constant in reverse order did not result in the plaintext being multplied by the same constant' \
                               % (self.bit_len, repr(self.seed)))

            self.assertEqual(self.dj.decrypt(ct / p_divisor), pt / p_divisor,
                             'With bit_len=%d, seed=%s, \'dividing\' the ciphertext by a constant did not result in the plaintext being divided by the same constant' \
                               % (self.bit_len, repr(self.seed)))
            self.assertEqual(self.dj.decrypt(ct.__div__(p_divisor)), pt / p_divisor,
                             'With bit_len=%d, seed=%s, \'dividing\' the ciphertext by a constant using __div__ did not result in the plaintext being divided by the same constant' \
                               % (self.bit_len, repr(self.seed)))
            self.assertEqual(self.dj.decrypt(ct.__truediv__(p_divisor)), pt / p_divisor,
                             'With bit_len=%d, seed=%s, \'dividing\' the ciphertext by a constant using __truediv__ did not result in the plaintext being divided by the same constant' \
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
    def __init__(self, keylen, seed, key, vectors, *args, **kwargs):
        self.keylen = keylen
        self.seed = seed
        self.key = key
        self.vectors = vectors
        super(EncryptVectorTest, self).__init__(*args, **kwargs)
    def setUp(self):
        self.random = keccak.KeccakRandom(self.seed)
    def runTest(self):
        for s, plain, cipher in self.vectors:
            cipher_ = self.key.encrypt(plain, s=s, random=self.random)
            self.assertEqual(cipher_, cipher,
                             'With keylen=%d, seed=%s, s=%d, key=%s encryption did not match expected output'
                               % (self.keylen, repr(self.seed), s, repr(self.key)))

class DecryptVectorTest(unittest.TestCase):
    longMessage = True
    def __init__(self, keylen, seed, key, vectors, *args, **kwargs):
        self.keylen = keylen
        self.seed = seed
        self.key = key
        self.vectors = vectors
        super(DecryptVectorTest, self).__init__(*args, **kwargs)
    def setUp(self):
        self.random = keccak.KeccakRandom(self.seed)
    def runTest(self):
        for s, plain, cipher in self.vectors:
            plain_ = self.key.decrypt(cipher)
            self.assertEqual(plain_, plain,
                             'With keylen=%d, seed=%s, s=%d, key=%s decryption did not match expected output'
                               % (self.keylen, repr(self.seed), s, repr(self.key)))

if __name__ == '__main__':
    keylengths = [512, 768, 1024, 2048, 4096]
    all_tests = list()
    keygen_tests = unittest.TestSuite(map(lambda keylen: KeygenTest(keylen, 10), keylengths))
    all_tests.append(keygen_tests)
    plaintext_tests = unittest.TestSuite(map(lambda bit_len: PlaintextTest(bit_len, 128), keylengths))
    all_tests.append(plaintext_tests)
    ciphertext_tests = unittest.TestSuite(map(lambda bit_len: SimpleCiphertextTest(bit_len, 128), keylengths) \
                                          + map(lambda bit_len: CiphertextTest(bit_len, 128), keylengths))
    all_tests.append(ciphertext_tests)
    simple_tests = unittest.TestSuite(map(lambda keylen: SimpleEncryptDecryptTest(keylen+1, 128), keylengths))
    all_tests.append(simple_tests)

    if len(sys.argv) >= 2 and sys.argv[1] == 'long':
        print 'loading test vectors'
        bigfiles_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bigfiles')
        f = open(os.path.join(bigfiles_path, 'dj_encryptions.pkl.xz'), 'rb')
        xz = subprocess.Popen(['xz', '-d'], close_fds=True, stdin=f, stdout=subprocess.PIPE)
        p = cPickle.Unpickler(xz.stdout)
        test_vectors = p.load()
        del p
        xz.terminate()
        del xz
        f.close()
        del f
        print 'done loading test vectors'

        print 'creating test cases'
        encryption_tests = unittest.TestSuite(EncryptVectorTest(keylen, seed, key, vectors)
                                              for (keylen, seed), temp0 in test_vectors.iteritems()
                                              for key, vectors in temp0.iteritems())
        all_tests.append(encryption_tests)
        decryption_tests = unittest.TestSuite(DecryptVectorTest(keylen, seed, key, vectors)
                                              for (keylen, seed), temp0 in test_vectors.iteritems()
                                              for key, vectors in temp0.iteritems())
        all_tests.append(decryption_tests)
        print 'done creating test cases'

    all_tests = unittest.TestSuite(all_tests)
    unittest.TextTestRunner(verbosity=2).run(all_tests)
