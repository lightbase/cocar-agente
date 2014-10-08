#!/bin/env python
# -*- coding: utf-8 -*-
# Inspired by the code in http://www.copyandwaste.com/posts/view/multiprocessing-snmp-with-python/
__author__ = 'eduardo'

import netsnmp



class Host(object):
    """
    Creates a host record
    """

    def __init__(self,
                 hostname=None,
                 query=None):
        self.hostname = hostname
        self.query = query


class SnmpSession():
    """A SNMP Session"""
    def __init__(self,
                 oid=".1.3.6.1.2.1.1.1.0",
                 iid=None,
                 Version=2,
                 DestHost="localhost",
                 Community="public",
                 Verbose=True,
                 ):
        self.oid = oid
        self.Version = Version
        self.DestHost = DestHost
        self.Community = Community
        self.Verbose = Verbose
        self.var = netsnmp.Varbind(oid, iid)
        self.hostrec = Host()
        self.hostrec.hostname = self.DestHost

    def query(self):
        """Creates SNMP query

        Fills out a Host Object and returns result
        """
        try:
            result = netsnmp.snmpget(self.var,
                                Version=self.Version,
                                DestHost=self.DestHost,
                                Community=self.Community)
            self.hostrec.query = result
        except Exception, err:
            if self.Verbose:
                print err
            self.hostrec.query = None
        finally:
            return self.hostrec