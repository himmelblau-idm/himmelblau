#!/bin/bash

# Build himmelblau
mkdir /root/build
pushd /root/build
tar -xf /root/tests/himmelblau.tar.gz && cargo build
install -m 0755 ./target/debug/libnss_himmelblau.so /usr/lib64/libnss_himmelblau.so.2
ln -s /usr/lib64/libnss_himmelblau.so.2 /usr/lib64/libnss_himmelblau.so
install -m 0755 ./target/debug/libpam_himmelblau.so /usr/lib64/security/pam_himmelblau.so
install -m 0755 ./target/debug/himmelblaud /usr/sbin
install -m 0755 ./target/debug/himmelblaud_tasks /usr/sbin
install -m 0755 ./target/debug/aad-tool /usr/bin
mkdir -p /var/run/himmelblaud
mkdir -p /var/cache/himmelblaud
mkdir -p /var/lib/himmelblaud
popd

# Build the test configuration
/root/tests/buildconfig.py

# Start the daemon
/usr/sbin/himmelblaud -d --skip-root-check &
sleep 5
/usr/sbin/himmelblaud_tasks &

# Run the tests
/root/tests/runner.py $@
RET=`echo $?`

# Kill the daemon
pkill himmelblaud
pkill himmelblaud_tasks

# Restart the daemon, and test authentication when joined
/usr/sbin/himmelblaud -d --skip-root-check &
sleep 5
/usr/sbin/himmelblaud_tasks &

# Run the tests
/root/tests/runner.py --pam-test
RET=`echo $?`

# Kill the daemon
pkill himmelblaud
pkill himmelblaud_tasks

exit $RET
