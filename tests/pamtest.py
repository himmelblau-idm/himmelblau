# Unix Azure Entra ID implementation
# Copyright (C) David Mulder <dmulder@samba.org> 2024
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
