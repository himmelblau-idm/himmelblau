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
import unittest
import pamtest
import nsstest
import signal
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hang", action="store_true",
                        help="Intentionally hang the program to allow exec'ing the container")
    parser.add_argument("--pam-test", action="store_true",
                        help="Only run the pamtest module")
    args = parser.parse_args()

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromModule(pamtest))
    if not args.pam_test:
        suite.addTests(loader.loadTestsFromModule(nsstest))

    runner = unittest.TextTestRunner(verbosity=3, failfast=True)
    runner.run(suite)

    if args.hang:
        while True:
            pass
