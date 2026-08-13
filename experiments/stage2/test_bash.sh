#!/bin/bash

echo "AEGIS normal bash telemetry test"

for i in {1..100}; do
    echo "AEGIS test" > /tmp/aegis_bash_test.txt
    cat /tmp/aegis_bash_test.txt > /dev/null
    stat /tmp/aegis_bash_test.txt > /dev/null
    rm -f /tmp/aegis_bash_test.txt
    sleep 0.1
done

sleep 20
