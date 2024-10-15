#!/usr/bin/python3
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
from configparser import ConfigParser, NoOptionError

testconfig = ConfigParser()
testconfig.read('/root/tests/test.conf') # config deployed by docker/podman

himmelblau_config = ConfigParser()
himmelblau_config.add_section('global')
for setting in ['tenant_id', 'app_id']:
    try:
        himmelblau_config.set('global', setting, testconfig.get('global', setting))
    except NoOptionError:
        pass # Ignore when unset, and leave default
pam_allow_groups = []
if testconfig.has_section('users'):
    pam_allow_groups = [u for u, _ in testconfig.items('users')]
    himmelblau_config.set('global', 'pam_allow_groups', ','.join(pam_allow_groups))
himmelblau_config.set('global', 'domains', testconfig.get('global', 'domains'))

with open('/etc/himmelblau/himmelblau.conf', 'w') as w:
    himmelblau_config.write(w)
