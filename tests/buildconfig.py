#!/usr/bin/python3
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

with open('/etc/himmelblau/himmelblau.conf', 'w') as w:
    himmelblau_config.write(w)
