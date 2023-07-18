#!/bin/bash

# Build the test configuration
/root/tests/buildconfig.py

# Start the daemon
/usr/sbin/himmelblaud -d &

# Run the tests
/root/tests/runner.py $@

# Kill the daemon
pkill himmelblaud
