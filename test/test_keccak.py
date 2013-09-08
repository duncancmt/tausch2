import os.path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cPickle
from binascii import hexlify, unhexlify

import keccak

def test_vectors(vectors, keccak_args):
    for i, (inp, outs) in enumerate(vectors,1):
        for expected, (r, c, n) in zip(outs, keccak_args):
            k = keccak.Keccak(r=r,c=c)
            k.soak(inp)
            received = k.squeeze(n)
            if expected != received:
                print "for Keccak parameters r=%d, c=%d, n=%d" % (r,c,n)
                print "given input '%s'" % hexlify(inp)
                print
                print "expected '%s'" % hexlify(expected)
                print
                print "got '%s'" % hexlify(received)
                print
                sys.exit(1)
        print "completed %d of %d test vectors" % (i, len(vectors))

args = (( 40,  160,  20),
        (128,  272,  34),
        (144,  256,  32),
        (256,  544,  68),
        (512,  288,  64),
        (544,  256,  68),
        (1344, 256, 512))

p = cPickle.Unpickler(open('nonstandard_vectors.pkl','rb'))
vectors = p.load()

print "**** TESTING NONSTANDARD KECCAK PARAMETERS ****"
test_vectors(vectors, args)


args = ((1024,  576, 512), # Keccak[]
        (1152,  448,  28), # SHA3-224
        (1088,  512,  32), # SHA3-256
        ( 832,  768,  48), # SHA3-384
        ( 576, 1024,  64)) # SHA3-512

p = cPickle.Unpickler(open('vectors.pkl','rb'))
vectors = p.load()

print "**** TESTING STANDARD KECCAK PARAMETERS ****"
test_vectors(vectors, args)


print "**** TESTING EXTREMELY LONG VECTORS (Ctrl-C to skip) ****"

try:
    extreme_vector = 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno'
    extreme_repeats = 16777216
    progress_interval = 10000
    extreme_outputs = ('EADAF5BA2AD6A2F6F338FCE0E1EFDAD2A61BB38F6BE6068B01093977ACF99E97A5D5827C2729C50D8854FA3998A52DEDE16C590064A430DEB650A1A455DA52EABE9CD9362B42400E0DD9A39161FBF33B7601B2E039AC1C4077E09481FE747CAAA3480776EC86C9FBC09DA23F89BE8B88F26DECF7C5573849691F42FF7258F520A8904A131A3D0B8BDE6D7DF5631CF68C4E4E76976CCD34303D6ACCFD5229EB8333DC83BCCCC1A1602FA60874C8E45B05099F59A5AE79CD89B16435BF035E804BE30870ADC488762C20D2A76E45D443021762B5C5DE395CD67F47AA06126E33E8395DD1559C939F9DD55D89B89378A4DA8F53961CC0F9E7D30A70BFD52240CBB5F7A8AB7BBF903995E1B113C18CFBC2B7E7116A1B0B2DE03EB4C0C35BCC2B0C9EA8415FC3CC3E5C8B0FC63B3CC2FB0027FB827925418067E0854049833294DFD1649F3E87768CDD000FEE68DB3ECED483624E1267ADFD425BAA26168C467BC41357F95E7C50137A845844D694C7787AF6576966E9B56DE0D354127DB32B1223516752FAF09038CFF992DAD08AAF0BEB0B427D0CD874D1C2DB2C83FE9234ED05730D970FD1119AAEF48F3003A7FEDE8DF919C41C91723A0149CAA208AECE2DEC31913BD86E09A6980F545956F9A3C4B9658A1174C6F658A1FFCB235101B7E8138BF1921F3442459F4C57AB2DBE8CCD0388D144C4BBC0776202AF297DED5A10E7B3',
                       'C42E4AEE858E1A8AD2976896B9D23DD187F64436EE15969AFDBC68C5',
                       '5F313C39963DCF792B5470D4ADE9F3A356A3E4021748690A958372E2B06F82A4',
                       '9B7168B4494A80A86408E6B9DC4E5A1837C85DD8FF452ED410F2832959C08C8C0D040A892EB9A755776372D4A8732315',
                       '3E122EDAF37398231CFACA4C7C216C9D66D5B899EC1D7AC617C40C7261906A45FC01617A021E5DA3BD8D4182695B5CB785A28237CBB167590E34718E56D8AAB8')

    for ((r, c, n), expected) in zip(args, extreme_outputs):
        print "testing Keccak with r=%d, c=%d, n=%d" % (r, c, n)
        print "we will print %d periods (.) before the next test" % (extreme_repeats/progress_interval)
        k = keccak.Keccak(r=r,c=c)
        for i in xrange(extreme_repeats):
            k.soak(extreme_vector)
            if i % progress_interval == 0:
                sys.stdout.write('.')
                sys.stdout.flush()

        sys.stdout.write('\n')
        received = k.squeeze(n)
        if unhexlify(expected) != received:
            print "for Keccak parameters r=%d, c=%d, n=%d" % (r,c,n)
            print "expected '%s'" % expected
            print
            print "got '%s'" % hexlify(received)
            print
            sys.exit(1)
except KeyboardInterrupt:
    print '\nSkipping extremely long test vectors'

print '**** TESTING KeccakRandom ****'
seeds = [ '', 'foo', 'bar', 'baz', 'qux', 'quux', 'corge', 'grault', 'garply', 'waldo', 'fred', 'plugh', 'xyzzy', 'thud' ]
for seed in seeds:
    print 'testing KeccakRandom with seed %s' % repr(seed)
    random = keccak.KeccakRandom(seed)
    first_ten_kb = random.getrandbits(10240)
    random = keccak.KeccakRandom(seed)
    try:
        assert first_ten_kb == random.getrandbits(10240)
    except:
        import traceback
        traceback.print_exc()
        print 'for KeccakRandom seed %s, output was not identical between identical instances' % repr(seed)
        sys.exit(1)

    random = keccak.KeccakRandom()
    random.seed(seed)
    try:
        assert first_ten_kb == random.getrandbits(10240)
    except:
        import traceback
        traceback.print_exc()
        print 'for KeccakRandom seed %s, output was not identical after explicitly seeding' % repr(seed)
        sys.exit(1)

    random = keccak.KeccakRandom(seed)
    initial_state = random.getstate()
    random = keccak.KeccakRandom.from_state(initial_state)
    try:
        assert first_ten_kb == random.getrandbits(10240)
    except:
        import traceback
        traceback.print_exc()
        print 'for KeccakRandom seed %s, output was not identical after restoring from initial state' % repr(seed)
        sys.exit(1)

    random = keccak.KeccakRandom(seed)
    random.getrandbits(10240)
    tenkb_state = random.getstate()
    second_ten_kb = random.getrandbits(10240)
    second_tenkb_state = random.getstate()
    random = keccak.KeccakRandom.from_state(tenkb_state)
    try:
        assert tenkb_state == random.getstate()
        assert second_ten_kb == random.getrandbits(10240)
    except:
        import traceback
        traceback.print_exc()
        print 'for KeccakRandom seed %s, output was not identical after restoring from intermediate state' % repr(seed)
        sys.exit(1)

    random = keccak.KeccakRandom(seed)
    random.jumpahead(10)
    try:
        assert second_ten_kb == random.getrandbits(10240)
    except:
        import traceback
        traceback.print_exc()
        print 'for KeccakRandom seed %s, output was not identical after jumping ahead 10 states' % repr(seed)
        sys.exit(1)

    random = keccak.KeccakRandom(seed)
    try:
        assert first_ten_kb == random.getrandbits(5120) | (random.getrandbits(5120) << 5120)
    except:
        import traceback
        traceback.print_exc()
        print 'for KeccakRandom seed %s, output was dependent on read size' % repr(seed)
        sys.exit(1)

    random = keccak.KeccakRandom(seed)
    random.setstate(tenkb_state)
    try:
        assert second_ten_kb == random.getrandbits(10240)
    except:
        import traceback
        traceback.print_exc()
        print 'for KeccakRandom seed %s, output was not identical after explicitly setting state' % repr(seed)
        sys.exit(1)

print "ALL DONE!"
sys.exit(0)
