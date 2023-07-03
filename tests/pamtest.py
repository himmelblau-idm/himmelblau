import unittest
import pam
import os
from configparser import ConfigParser
from string import ascii_uppercase, digits
from random import choices
import pwd

def split_username(username):
    return tuple(username.split('@'))

class TestPamHimmelblau(unittest.TestCase):
    def setUp(self):
        self.config = ConfigParser()
        self.config.read('/root/tests/test.conf') # config deployed by docker/podman
        self.admin_user = self.config.get('global', 'admin_user')
        self.admin_pass = self.config.get('global', 'admin_pass')
        self.users = self.config.items('users')
        _, self.domain = split_username(self.admin_user)

    def test_auth_users(self):
        for user, password in self.users:
            p = pam.pam()
            p.authenticate(user, password)
            self.assertEqual(p.code, 0, "Failed to authenticate user %s" % user)

    def test_auth_not_a_user(self):
        # Test with fake users, but only do a few (since auths are slow)
        users = [''.join(choices(ascii_uppercase+digits, k=8)) for _ in range(10)]
        for user in users:
            p = pam.pam()
            p.authenticate('%s@%s' % (user, self.domain), user)
            self.assertNotEqual(p.code, 0, "Authenication succeeded for a fake user")

        # Ensure the fake users weren't cached
        for user in users:
            try:
                entry = pwd.getpwnam('%s@%s' % (user, self.domain))
            except KeyError:
                pass
            else:
                self.fail("himmelblaud responded to a nonsense pwent")
