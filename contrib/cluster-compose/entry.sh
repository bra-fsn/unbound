#!/bin/sh
# Supervisor loop: runs unbound in the foreground.
#  /tmp/hold     present: leave unbound down while it exists ("process dead, host alive" tests)
#  /tmp/restart  present: planned restart (config change / cache reset), restarts at once
#  otherwise     unbound exited unexpectedly: logged in /tmp/crashes, harness reports it
# /tmp/starts counts all (re)starts.  The container and its network namespace
# stay, so the MAC/ARP state is not disturbed by a restart of unbound.
rm -f /tmp/starts /tmp/hold /tmp/restart /tmp/crashes
while true; do
    echo start >> /tmp/starts
    /usr/local/sbin/unbound -d -c /etc/unbound-node/unbound.conf
    rc=$?
    if [ -e /tmp/hold ]; then
        while [ -e /tmp/hold ]; do sleep 0.2; done
    elif [ -e /tmp/restart ]; then
        rm -f /tmp/restart
    else
        echo "exit rc=$rc" >> /tmp/crashes
        echo "entry.sh: unbound exited unexpectedly rc=$rc" >&2
        sleep 1
    fi
done
