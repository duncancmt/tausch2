from damgaardjurik import *
from numbers import Integral
from threading import RLock

class TauschRouter(object):
    """Class representing the blinded routing operation that can be performed based on Damgaard Jurik"""
    def __init__(self):
        self.lock = RLock()
        with self.lock:
            self.table = dict()
            self.queue = dict()
            self.modification_callbacks = dict()

    def _check_user(self, user):
        """Given a user (a DamgaardJurik instance) check that the user is participating in this router"""
        if not isinstance(user, DamgaardJurik):
            raise TypeError('user must be a DamgaardJurik instance')
        with self.lock:
            if user not in self.table:
                raise KeyError('Unknown user')
    def _check_subscription(self, subscription):
        """Given a subscription, check that it is well-formed for this particular router"""
        # check types
        for sender, selector in subscription.iteritems():
            if not isinstance(sender, DamgaardJurik) or not isinstance(selector, DamgaardJurikCiphertext):
                raise TypeError('subscription must be a dict DamgaardJurik -> DamgaardJurikCiphertext')
        # check that the users in the subscription are exactly correct
        with self.lock:
            if frozenset(subscription.iterkeys()) != frozenset(self.table.iterkeys()):
                raise KeyError('Mismatch between subscription users and routing table users')
    def _check_consistency(self):
        """Check that all the state of this router is consistent"""
        with self.lock:
            for subscription in self.table.itervalues():
                self._check_subscription(subscription)
            if frozenset(self.modification_callbacks.iterkeys()) != frozenset(self.table.iterkeys()):
                raise KeyError('Mismatch between callbacks users and routing table users')


    def queue_message(self, user, message):
        """Queue a message (an integer) from the given user (a DamgaardJurik instance)
        to be routed on the next round
        """
        if not isinstance(message, Integral):
            raise TypeError('Argument message must be an integer')

        with self.lock:
            self._check_user(user)
            if user in self.queue:
                raise KeyError('User has already submitted a message for this round')
            self.queue[user] = message
            return len(self.queue) == len(self.table)


    def route_messages(self):
        """Perform the routing operation, returning a dict of user -> message
        Where user (a DamgaardJurik instance) is the recipient of the message
        (a DamgaardJurikCiphertext instance)
        """
        with self.lock:
            self._check_consistency()
            for user in self.table.iterkeys():
                if user not in self.queue:
                    raise RuntimeError('Not all users have submitted messages')
            retval = dict()
            for recipient, subscription in self.table.iteritems():
                retval[recipient] = 0
                for sender, selector in subscription.iteritems():
                    retval[recipient] += selector*self.queue[sender]
            self.queue = dict()
            return retval


    def update_subscription(self, user, subscription):
        """Replace the current subscription for the given user with the given subscription"""
        with self.lock:
            self._check_user(user)
            self._check_subscription(subscription)

            self.table[user] = subscription


    def add_user(self, user, callback):
        """Add a new user to the router with the given status update callback"""
        with self.lock:
            try: self._check_user(user)
            except: pass
            else: raise KeyError('User already exists')

            self.modification_callbacks[user] = callback
            self.table[user] = dict()
            callbacks = self.modification_callbacks.values()
        for callback in callbacks:
            callback('add', user)


    def del_user(self, user):
        """Delete a user from the router"""
        with self.lock:
            self._check_user(user)
            self.queue.pop(user, None)
            self.table.pop(user, None)
            self.modification_callbacks.pop(user, None)
            for subscription in self.table.itervalues():
                subscription.pop(user, None)
            callbacks = self.modification_callbacks.values()
        for callback in callbacks:
            callback('del', user)
        # self._check_consistency()

    @property
    def users(self):
        with self.lock:
            return frozenset(self.table.iterkeys())

__all__ = ['TauschRouter']
