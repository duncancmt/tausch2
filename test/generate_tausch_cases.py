import os.path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cPickle

import damgaardjurik
import keccak

damgaardjurik.has_gmpy = False
seeds = ['', 'foo', 'bar', 'baz', 'qux', 'quux', 'corge', 'grault', 'garply', 'waldo', 'fred', 'plugh', 'xyzzy', 'thud' ]
keylens = [512, 768, 1024, 2048, 4096]
max_users = 64

users = dict()

for keylen in keylens:
    for seed in seeds:
        users[(keylen, seed)] = list()
        random = keccak.KeccakRandom(seed)
        for _ in xrange(max_users):
            users[(keylen, seed)].append(damgaardjurik.DamgaardJurik(keylen, random=random))
        users[(keylen, seed)] = tuple(users[(keylen, seed)])
        print 'finished seed %s' % repr(seed)
    print 'finished keylen %d' % keylen

f = open('test_keys.pkl','wb')
p = cPickle.Pickler(f, -1)
p.dump(users)
f.flush()
f.close()
del p
del f
