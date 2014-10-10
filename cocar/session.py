#!/bin/env python
# -*- coding: utf-8 -*-
# Inspired by the code in http://www.copyandwaste.com/posts/view/multiprocessing-snmp-with-python/
__author__ = 'eduardo'

import netsnmp
import subprocess
import logging
from . import Cocar

log = logging.getLogger()


class Host(object):
    """
    Creates a host record
    """

    def __init__(self,
                 hostname=None,
                 query=None):
        self.hostname = hostname
        self.query = query


class SnmpSession(Cocar):
    """A SNMP Session"""
    def __init__(self,
                 oid=".1.3.6.1.2.1.1.1.0",
                 iid=None,
                 Version=2,
                 DestHost="localhost",
                 Community="public",
                 Verbose=True,
                 ):
        Cocar.__init__(self)
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


class NmapSession(object):
    """
    Realiza busca Nmap num ativo de rede
    Inspirado em https://github.com/c0r3dump3d/pylanos
    """
    def __init__(self,
                 host,
                 full=False,
                 outfile=None
                 ):
        """
        Parâmetros obrigatórios
        """
        self.host = host
        self.full = full
        if outfile is not None:
            self.outfile = outfile
        else:
            self.outfile = str(self.host).replace("/", "-") + ".xml"

    def scan(self):
        """
        Realiza busca Nmap
        :return:
        """
        try:
            if self.full:
                scanv = subprocess.Popen(["sudo",
                                          "nmap",
                                          "-PR",
                                          "-O",
                                          str(self.host),
                                          "-oX",
                                          self.outfile],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE).communicate()[0]
            else:
                scanv = subprocess.Popen(["sudo",
                                          "nmap",
                                          "-PE",
                                          "-PP",
                                          "-PS21,22,23,25,80,443,3306,3389,8080",
                                          "-O",
                                          str(self.host),
                                          "-oX",
                                          self.outfile],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE).communicate()[0]
        except OSError:
            log.error("Install nmap: sudo apt-get install nmap")
            return False

        return True