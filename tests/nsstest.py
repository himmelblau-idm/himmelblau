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
import pwd, grp
from configparser import ConfigParser
from string import ascii_uppercase, digits
from random import choices

class TestNssHimmelblau(unittest.TestCase):
    def setUp(self):
        self.config = ConfigParser()
        self.config.read('/root/tests/test.conf') # config deployed by docker/podman
        self.admin_user = self.config.get('global', 'admin_user')
        self.admin_pass = self.config.get('global', 'admin_pass')
        self.users = self.config.items('users')

    def test_getent_user(self):
        for user, _ in self.users:
            entry = pwd.getpwnam(user)
            self.assertEqual(user, entry.pw_name, "getpwnam failed for user %s" % user)

    def test_getent_users(self):
        entries = pwd.getpwall()
        pw_names = [p.pw_name for p in entries]
        for user, _ in self.users:
            self.assertIn(user, pw_names, "User %s missing from getgrent" % user)

    def test_getent_fake(self):
        # Ensure himmelblaud doesn't respond to nonsense requests
        users = [''.join(choices(ascii_uppercase+digits, k=8)) for _ in range(100)]
        for user in users:
            try:
                entry = pwd.getpwnam(user)
            except KeyError:
                pass
            else:
                self.fail("himmelblaud responded to a nonsense pwent")
        for group in users:
            try:
                entry = grp.getgrnam(group)
            except KeyError:
                pass
            else:
                self.fail("himmelblaud responded to a nonsense pwent")

    def test_getent_group(self):
        # himmelblau generates a group for each user. Ensure these can be found via nss.
        for group, _ in self.users:
            try:
                entry = grp.getgrnam(group)
            except KeyError:
                self.fail("getgrnam failed for group %s" % group)
            self.assertEqual(group, entry.gr_name, "getgrnam failed for group %s" % group)

    def test_getent_groups(self):
        entries = grp.getgrall()
        gr_names = [g.gr_name for g in entries]
        for group, _ in self.users:
            self.assertIn(group, gr_names, "Group %s missing from getgrent" % group)
