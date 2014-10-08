#!/bin/env python
# -*- coding: utf-8 -*-
# Inspired by the code in http://www.copyandwaste.com/posts/view/multiprocessing-snmp-with-python/
__author__ = 'eduardo'

from host import SnmpSession
from multiprocessing import Process, Queue, current_process


def make_query(host):
    """This does the actual snmp query

    This is a bit fancy as it accepts both instances
    of SnmpSession and host/ip addresses.  This
    allows a user to customize mass queries with
    subsets of different hostnames and community strings
    """
    if isinstance(host, SnmpSession):
        return host.query()
    else:
        s = SnmpSession(DestHost=host)
        return s.query()


# Function run by worker processes
def worker(inp, output):
    for func in iter(inp.get, 'STOP'):
        result = make_query(func)
        output.put(result)

def main():
    """Runs everything"""

    #clients
    hosts = [
    SnmpSession(DestHost="10.71.1.1", Community="my-pub-community", oid="1.3.6.1.4.1.9.9.42.1.2.10.1.1", iid="1"),
    SnmpSession(DestHost="10.81.1.1", Community="my-pub-community", oid="1.3.6.1.4.1.9.9.42.1.2.10.1.1", iid="123")
    ]
    NUMBER_OF_PROCESSES = len(hosts)

    # Create queues
    task_queue = Queue()
    done_queue = Queue()

    #submit tasks
    for host in hosts:
        task_queue.put(host)

    #Start worker processes
    for i in range(NUMBER_OF_PROCESSES):
        Process(target=worker, args=(task_queue, done_queue)).start()

     # Get and print results
    print 'Unordered results:'
    for i in range(len(hosts)):
        print '\t', done_queue.get().query

    # Tell child processes to stop
    for i in range(NUMBER_OF_PROCESSES):
        task_queue.put('STOP')
        #print "Stopping Process #%s" % i

if __name__ == "__main__":
    main()