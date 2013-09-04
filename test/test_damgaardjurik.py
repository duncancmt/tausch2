import os.path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from random import SystemRandom
random = SystemRandom()
from math import log

from damgaardjurik import *

print 'testing key generation'
for keylen in [512, 768, 1024, 2048, 4096, 8192]:
    print '\ttesting keylength:', keylen
    for j in xrange(-3, 4):
        for i in xrange(10):
            dj = DamgaardJurik(keylen=(keylen+j), random=random)
            highbits = dj.n >> (keylen+j-1)
            assert highbits > 0 and highbits < 4

