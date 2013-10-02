import os.path
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(this_dir))

import cPickle
import unittest
from binascii import hexlify, unhexlify

import keccak
from intbytes import int2bytes, bytes2int

# Base class for Keccak tests
class KeccakTestCase(unittest.TestCase):
    longMessage=True
    def __init__(self, keccak_args, input_vector, output_vector):
        self.keccak_args = keccak_args
        self.input_vector = input_vector
        self.output_vector = output_vector
        super(KeccakTestCase,self).__init__()
    def runTest(self):
        k = keccak.Keccak(r=self.keccak_args['r'],
                          c=self.keccak_args['c'],
                          fixed_out=True)
        k.absorb(self.input_vector)
        self.assertEqual(k.squeeze(self.keccak_args['n']), self.output_vector,
                         'input: %s\nparameters r=%d, c=%d, n=%d, fixed_out=True' \
                           % (repr(hexlify(self.input_vector)),
                              self.keccak_args['r'],
                              self.keccak_args['c'],
                              self.keccak_args['n']))

        k = keccak.Keccak(r=self.keccak_args['r'],
                          c=self.keccak_args['c'],
                          fixed_out=False)
        k.absorb(self.input_vector)
        self.assertEqual(k.squeeze(self.keccak_args['n']), self.output_vector,
                         'input: %s\nparameters r=%d, c=%d, n=%d, fixed_out=False' \
                           % (repr(hexlify(self.input_vector)),
                              self.keccak_args['r'],
                              self.keccak_args['c'],
                              self.keccak_args['n']))



########## Non-SHA3 Keccak ##########
class NonstandardKeccakTestSuite(unittest.TestSuite):
    pass

args = ({'r':  40, 'c':160, 'n': 20},
        {'r': 128, 'c':272, 'n': 34},
        {'r': 144, 'c':256, 'n': 32},
        {'r': 256, 'c':544, 'n': 68},
        {'r': 512, 'c':288, 'n': 64},
        {'r': 544, 'c':256, 'n': 68},
        {'r':1344, 'c':256, 'n':512})

p = cPickle.Unpickler(open(os.path.join(this_dir, 'nonstandard_vectors.pkl'),'rb'))
vectors = p.load()

ns_tests = NonstandardKeccakTestSuite(KeccakTestCase(keccak_args, input_vector, output_vector)
                                      for input_vector, output_vectors in vectors
                                      for output_vector, keccak_args in zip(output_vectors, args))





########## SHA3 Keccak and Keccak[] ##########
class StandardKeccakTestSuite(unittest.TestSuite):
    pass

args = ({'r':1024, 'c': 576, 'n':512}, # Keccak[]
        {'r':1152, 'c': 448, 'n': 28}, # SHA3-224
        {'r':1088, 'c': 512, 'n': 32}, # SHA3-256
        {'r': 832, 'c': 768, 'n': 48}, # SHA3-384
        {'r': 576, 'c':1024, 'n': 64}) # SHA3-512

p = cPickle.Unpickler(open(os.path.join(this_dir, 'vectors.pkl'),'rb'))
vectors = p.load()

s_tests = StandardKeccakTestSuite(KeccakTestCase(keccak_args, input_vector, output_vector)
                                  for input_vector, output_vectors in vectors
                                  for output_vector, keccak_args in zip(output_vectors, args))






########## Extremely long test cases ##########
class LongKeccakTestCase(KeccakTestCase):
    def __init__(self, repeats, *args):
        self.repeats = repeats
        super(LongKeccakTestCase, self).__init__(*args)
    def runTest(self):
        k = keccak.Keccak(r=self.keccak_args['r'],
                          c=self.keccak_args['c'],
                          fixed_out=True)
        for _ in xrange(self.repeats):
            k.absorb(self.input_vector)
        self.assertEqual(k.squeeze(self.keccak_args['n']), unhexlify(self.output_vector),
                         'parameters r=%d, c=%d, n=%d, fixed_out=True' \
                           % (self.keccak_args['r'],
                              self.keccak_args['c'],
                              self.keccak_args['n']))

        k = keccak.Keccak(r=self.keccak_args['r'],
                          c=self.keccak_args['c'],
                          fixed_out=False)
        for _ in xrange(self.repeats):
            k.absorb(self.input_vector)
        self.assertEqual(k.squeeze(self.keccak_args['n']), unhexlify(self.output_vector),
                         'parameters r=%d, c=%d, n=%d, fixed_out=False' \
                           % (self.keccak_args['r'],
                              self.keccak_args['c'],
                              self.keccak_args['n']))


class LongKeccakTestSuite(unittest.TestSuite):
    pass

extreme_vector = 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno'
extreme_repeats = 16777216
extreme_outputs = ('EADAF5BA2AD6A2F6F338FCE0E1EFDAD2A61BB38F6BE6068B01093977ACF99E97A5D5827C2729C50D8854FA3998A52DEDE16C590064A430DEB650A1A455DA52EABE9CD9362B42400E0DD9A39161FBF33B7601B2E039AC1C4077E09481FE747CAAA3480776EC86C9FBC09DA23F89BE8B88F26DECF7C5573849691F42FF7258F520A8904A131A3D0B8BDE6D7DF5631CF68C4E4E76976CCD34303D6ACCFD5229EB8333DC83BCCCC1A1602FA60874C8E45B05099F59A5AE79CD89B16435BF035E804BE30870ADC488762C20D2A76E45D443021762B5C5DE395CD67F47AA06126E33E8395DD1559C939F9DD55D89B89378A4DA8F53961CC0F9E7D30A70BFD52240CBB5F7A8AB7BBF903995E1B113C18CFBC2B7E7116A1B0B2DE03EB4C0C35BCC2B0C9EA8415FC3CC3E5C8B0FC63B3CC2FB0027FB827925418067E0854049833294DFD1649F3E87768CDD000FEE68DB3ECED483624E1267ADFD425BAA26168C467BC41357F95E7C50137A845844D694C7787AF6576966E9B56DE0D354127DB32B1223516752FAF09038CFF992DAD08AAF0BEB0B427D0CD874D1C2DB2C83FE9234ED05730D970FD1119AAEF48F3003A7FEDE8DF919C41C91723A0149CAA208AECE2DEC31913BD86E09A6980F545956F9A3C4B9658A1174C6F658A1FFCB235101B7E8138BF1921F3442459F4C57AB2DBE8CCD0388D144C4BBC0776202AF297DED5A10E7B3',
                   'C42E4AEE858E1A8AD2976896B9D23DD187F64436EE15969AFDBC68C5',
                   '5F313C39963DCF792B5470D4ADE9F3A356A3E4021748690A958372E2B06F82A4',
                   '9B7168B4494A80A86408E6B9DC4E5A1837C85DD8FF452ED410F2832959C08C8C0D040A892EB9A755776372D4A8732315',
                   '3E122EDAF37398231CFACA4C7C216C9D66D5B899EC1D7AC617C40C7261906A45FC01617A021E5DA3BD8D4182695B5CB785A28237CBB167590E34718E56D8AAB8')

long_tests = LongKeccakTestSuite(LongKeccakTestCase(extreme_repeats, keccak_args, extreme_vector, output_vector)
                                 for output_vector, keccak_args in zip(extreme_outputs, args))






########## Tests for KeccakRandom ##########
class KeccakRandomTestCase(unittest.TestCase):
    longMessage=True
    def __init__(self, seed, keccak_args, *args, **kwargs):
        self.seed = seed
        self.keccak_args = keccak_args
        super(KeccakRandomTestCase, self).__init__(*args, **kwargs)
    def setUp(self):
        self.bits = self.random().k.r*4
    def random(self):
        return keccak.KeccakRandom(self.seed, keccak_args=self.keccak_args)
    def test_deterministic(self):
        self.assertEqual(self.random().getrandbits(self.bits),
                         self.random().getrandbits(self.bits),
                         'seed: %s\noutput from identical instances should be identical' % repr(self.seed))
    def test_seed(self):
        random = keccak.KeccakRandom('\x00')
        random.seed(self.seed)
        self.assertEqual(self.random().getrandbits(self.bits),
                         random.getrandbits(self.bits),
                         'seed: %s\noutput should be the same if explicitly seeded' % repr(self.seed))
    def test_initial_setstate(self):
        state = self.random().getstate()
        random = self.random()
        random.getrandbits(self.bits)
        random.setstate(state)
        self.assertEqual(self.random().getrandbits(self.bits),
                         random.getrandbits(self.bits),
                         'seed: %s\noutput should be the same if set to initial state' % repr(self.seed))
    def test_initial_from_state(self):
        state = self.random().getstate()
        random = keccak.KeccakRandom.from_state(state)
        self.assertEqual(self.random().getrandbits(self.bits),
                         random.getrandbits(self.bits),
                         'seed: %s\noutput should be the same if initialized from initial state' % repr(self.seed))
    def test_intermediate_setstate(self):
        random = self.random()
        random.getrandbits(self.bits)
        state = random.getstate()
        other_random = self.random()
        other_random.setstate(state)
        self.assertEqual(random.getrandbits(self.bits),
                         other_random.getrandbits(self.bits),
                         'seed: %s\noutput should be the same if set to intermediate state' % repr(self.seed))
    def test_intermediate_from_state(self):
        random = self.random()
        random.getrandbits(self.bits)
        state = random.getstate()
        other_random = keccak.KeccakRandom.from_state(state)
        self.assertEqual(random.getrandbits(self.bits),
                         other_random.getrandbits(self.bits),
                         'seed: %s\noutput should be the same if initialized from intermediate state' % repr(self.seed))
    def test_unaligned_setstate(self):
        random = self.random()
        random.getrandbits(self.bits//3)
        state = random.getstate()
        other_random = self.random()
        other_random.setstate(state)
        self.assertEqual(random.getrandbits(self.bits),
                         other_random.getrandbits(self.bits),
                         'seed: %s\noutput should be the same if set to an unaligned intermediate state' % repr(self.seed))
    def test_unaligned_from_state(self):
        random = self.random()
        random.getrandbits(self.bits/3)
        state = random.getstate()
        other_random = keccak.KeccakRandom.from_state(state)
        self.assertEqual(random.getrandbits(self.bits),
                         other_random.getrandbits(self.bits),
                         'seed: %s\noutput should be the same if initialized from an unaligned intermediate state' % repr(self.seed))
    def test_jumpahead(self):
        random = self.random()
        random.getrandbits(self.bits)
        other_random = self.random()
        other_random.jumpahead(4)
        self.assertEqual(random.getrandbits(self.bits),
                         other_random.getrandbits(self.bits),
                         'seed: %s\noutput should be the same when using jumpahead vs getrandbits' % repr(self.seed))
    def test_unaligned_read(self):
        random = self.random()
        tmp1 = random.getrandbits(self.bits//3)
        tmp2 = (random.getrandbits(self.bits - (self.bits//3)) << (self.bits//3))
        self.assertEqual(self.random().getrandbits(self.bits),
                         tmp1 | tmp2,
                         'seed: %s\noutput should not depend on read size' % repr(self.seed))


class KeccakRandomTestSeed(unittest.TestSuite):
    def __init__(self, seed):
        super(KeccakRandomTestSeed, self).__init__()
        test_methods = [ name
                         for name in KeccakRandomTestCase.__dict__.iterkeys()
                         if name.startswith('test_') ]
        for method in test_methods:
            self.addTest(KeccakRandomTestCase(seed, {}, method))






########## Tests for KeccakCipher ##########
lorem = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut quis ipsum odio. Ut ut commodo justo. Morbi non arcu metus. Vestibulum facilisis aliquet nisl placerat consequat. Morbi vitae enim sit amet neque suscipit commodo eget eget libero. Sed aliquet auctor nunc, nec consequat arcu gravida quis. Ut molestie vulputate volutpat. Nunc ut lorem ultricies, hendrerit metus id, rhoncus enim. Integer euismod mattis tincidunt. Donec condimentum, lacus eleifend egestas lobortis, enim mauris congue erat, quis placerat est metus eu massa. Aenean malesuada, odio id tempus pulvinar, erat dui blandit ante, in scelerisque velit leo id mi. Nam faucibus mauris ut eros pulvinar, vitae pellentesque arcu vehicula. Etiam lacinia eros lorem, vitae condimentum felis hendrerit non. Suspendisse urna sem, convallis sed urna quis, congue fringilla quam. Mauris enim orci, sollicitudin eget eros vitae, dictum faucibus mauris. Curabitur feugiat sapien at eros lobortis, eget dictum risus sodales. Maecenas laoreet metus diam, sed cras amet.'
class KeccakCipherTestCase(unittest.TestCase):
    longMessage=True
    def __init__(self, key):
        self.key = key
        super(KeccakCipherTestCase, self).__init__()
    def setUp(self):
        self.random = keccak.KeccakRandom(self.key)
    def runTest(self):
        for i in xrange(1000):
            ptext_start = self.random.randint(0, len(lorem))
            ptext_end = self.random.randint(ptext_start, len(lorem))
            ptext = lorem[ptext_start:ptext_end]
            nonce = int2bytes(self.random.getrandbits(128), length=128/8)

            ctext = ''
            c = keccak.KeccakCipher(self.key, nonce, encrypt_not_decrypt=True)
            chunk_start = 0
            chunk_end = 0
            while chunk_start < len(ptext):
                chunk_start = chunk_end
                chunk_end = self.random.randint(chunk_start, len(ptext))
                ctext += c.encrypt(ptext[chunk_start:chunk_end])
            ctext += c.emit_mac()

            ptext_ = ''
            d = keccak.KeccakCipher(self.key, nonce, encrypt_not_decrypt=False)
            chunk_start = 0
            chunk_end = 0
            while chunk_start < len(ctext):
                chunk_start = chunk_end
                chunk_end = self.random.randint(chunk_start, len(ctext))
                ptext_ += d.decrypt(ctext[chunk_start:chunk_end])
            ptext_ += d.verify_mac()

            self.assertEqual(ptext, ptext_,
                             'Message was not identical after an encryption/decryption round. key: %s, nonce: %s, round %d' \
                             % (repr(self.key), repr(nonce), i) )

            ptext_ = ''
            d = keccak.KeccakCipher(self.key, nonce, encrypt_not_decrypt=False)
            changed_byte = self.random.randint(0, len(ctext)-1)
            ctext = ctext[:changed_byte] + chr(self.random.randint(1,255) ^ ord(ctext[changed_byte])) + ctext[changed_byte+1:]
            chunk_start = 0
            chunk_end = 0
            while chunk_start < len(ctext):
                chunk_start = chunk_end
                chunk_end = self.random.randint(chunk_start, len(ctext))
                ptext_ += d.decrypt(ctext[chunk_start:chunk_end])

            with self.assertRaises(ValueError):
                ptext_ += d.verify_mac()



if __name__ == '__main__':
    keccak_tests = unittest.TestSuite((ns_tests, s_tests, long_tests))
    keccakrandom_tests = unittest.TestSuite(KeccakRandomTestSeed(seed)
                                            for seed in [ '', 'foo', 'bar', 'baz', 'qux', 'quux', 'corge', 'grault', 'garply', 'waldo', 'fred', 'plugh', 'xyzzy', 'thud' ])
    keccakcipher_tests = unittest.TestSuite(KeccakCipherTestCase(key)
                                            for key in [ '', 'foo', 'bar', 'baz', 'qux', 'quux', 'corge', 'grault', 'garply', 'waldo', 'fred', 'plugh', 'xyzzy', 'thud' ])
    all_tests = unittest.TestSuite((keccak_tests, keccakrandom_tests, keccakcipher_tests))
    unittest.TextTestRunner(verbosity=2).run(all_tests)
