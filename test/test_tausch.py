import os.path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from tausch import *
import keccak
import damgaardjurik as dj

class BasicTauschRouterTest(unittest.TestCase):
    longMessage = True
    def __init__(self, seed, keylen, num_users):
        self.seed = seed
        self.keylen = keylen
        self.num_users = num_users
        super(BasicTauschRouterTest, self).__init__()

    def setUp(self):
        self.random = keccak.KeccakRandom(seed)
        self.users = [ dj.DamgaardJurik(self.keylen, random=self.random)
                       for _ in xrange(self.num_users) ]
        self.random.shuffle(self.users)
        temp = list(self.users)
        self.random.shuffle(temp)
        self.listen_map = dict(zip(self.users, temp))
        self.router = TauschRouter()

    @staticmethod
    def make_callback(me, listen_to, router, connected_users, random):
        connected_users = set(connected_users)
        def callback(add_del, user):
            if add_del == 'add':
                connected_users.add(user)
            elif add_del == 'del':
                connected_users.remove(user)
            else:
                raise ValueError('Unknown operation')
            router.update_subscription(me, dict( (user,
                                                  me.encrypt(dj.DamgaardJurikPlaintext(1 if user is listen_to else 0),
                                                             random=random,
                                                             ciphertext_args={'cache':False}))
                                                for user in connected_users ))
        return callback
            

    def runTest(self):
        for user in self.users:
            callback = self.make_callback(user, self.listen_map[user], self.router, self.router.users, self.random)
            self.router.add_user(user, callback)
        self.router._check_consistency()
        messages = dict( (user, self.random.getrandbits(32))
                         for user in self.users )
        for user, message in messages.iteritems():
            self.router.queue_message(user, message)
        routed = self.router.route_messages()
        for user, message in routed.iteritems():
            expected_message = messages[self.listen_map[user]]
            self.assertEqual(expected_message, user.decrypt(message))


if __name__ == '__main__':
    keylens = [512, 768, 1024, 2048, 4096]
    num_userss = [0, 1, 2, 3, 4, 8, 15, 16, 32]
    seeds = ['', 'foo', 'bar', 'baz', 'qux', 'quux', 'corge', 'grault', 'garply', 'waldo', 'fred', 'plugh', 'xyzzy', 'thud' ]
    basic_tests = list()
    for keylen in keylens:
        for num_users in num_userss:
            for seed in seeds:
                basic_tests.append(BasicTauschRouterTest(seed, keylen, num_users))
    basic_tests = unittest.TestSuite(basic_tests)
    unittest.TextTestRunner(verbosity=2).run(basic_tests)
            
        
        
        
