import os.path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cPickle
import multiprocessing
import subprocess
from itertools import chain, izip, izip_longest

import damgaardjurik
import keccak

damgaardjurik.has_gmpy = False

test_keys = cPickle.Unpickler(open('test_keys.pkl','rb')).load()

def flatten(listOfLists):
    "Flatten one level of nesting"
    return chain.from_iterable(listOfLists)

def do_encrypt((key, seed)):
    random = keccak.KeccakRandom(seed)
    retval = list()
    for s in xrange(1, 5):
        plain = damgaardjurik.DamgaardJurikPlaintext(random.randrange(key.n**s))
        cipher = key.encrypt(plain, s=s, random=random)
        retval.append((s, plain, cipher))
    return tuple(retval)

pool = multiprocessing.Pool()
data = dict()
for (keylen, seed), keys in test_keys.iteritems():
    data[(keylen, seed)] = dict()
    print 'starting keylen=%d, seed=%s' % (keylen, repr(seed))

    data[(keylen, seed)] = dict( izip(keys, pool.imap(do_encrypt,
                                                      izip_longest(keys, (), fillvalue=seed))) )

    print 'finished keylen=%d, seed=%s' % (keylen, repr(seed))

print 'starting pickling'
pickle_filename = 'dj_encryptions.pkl'
f = open(pickle_filename,'wb')
p = cPickle.Pickler(f, -1)
p.dump(data)
f.flush()
f.close()
del p
del f
print 'done pickling'

print 'compressing pickle file'
xz = subprocess.Popen(['xz', '-9', '-e', pickle_filename], close_fds=True)
xz.wait()
print 'done compressing pickle file'
