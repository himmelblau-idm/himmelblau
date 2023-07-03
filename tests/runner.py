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
    args = parser.parse_args()

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromModule(pamtest))
    suite.addTests(loader.loadTestsFromModule(nsstest))

    runner = unittest.TextTestRunner(verbosity=3, failfast=True)
    runner.run(suite)

    if args.hang:
        while True:
            pass
