import os.path
import sys
bigfiles_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bigfiles')
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import cPickle

from tausch import *
import keccak
import damgaardjurik as dj

class BasicTauschRouterTest(unittest.TestCase):
    longMessage = True
    def __init__(self, seed, users):
        self.seed = seed
        self.users = list(users)
        super(BasicTauschRouterTest, self).__init__()

    def setUp(self):
        self.random = keccak.KeccakRandom(seed)
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

        self.assertEqual(self.router.users, frozenset(self.users)) # TODO: message

        messages = dict( (user, self.random.getrandbits(32))
                         for user in self.users )
        for user, message in messages.iteritems():
            self.router.queue_message(user, message)

        routed = self.router.route_messages()
        for user, message in routed.iteritems():
            expected_message = messages[self.listen_map[user]]
            self.assertEqual(expected_message, user.decrypt(message)) # TODO: message

        removal_order = list(self.users)
        self.random.shuffle(removal_order)
        for user in removal_order:
            self.router.del_user(user)


if __name__ == '__main__':
    sample_keys = cPickle.Unpickler(open(os.path.join(bigfiles_path, 'sample_keys.pkl'),'rb')).load()
    num_userss = [0, 1, 2, 3, 4, 8, 15, 16, 32]
    basic_tests = list()
    for (keylen, seed), users in test_keys.iteritems():
        for num_users in num_userss:
            basic_tests.append(BasicTauschRouterTest(seed, users[:num_users]))
    basic_tests = unittest.TestSuite(basic_tests)
    unittest.TextTestRunner(verbosity=2).run(basic_tests)
            
        
        
        
