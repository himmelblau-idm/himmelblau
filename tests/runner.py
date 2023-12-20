#!/usr/bin/python3
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
