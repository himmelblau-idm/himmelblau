#!/bin/bash

/usr/sbin/himmelblaud -d &
/root/tests/runner.py $@
pkill himmelblaud
