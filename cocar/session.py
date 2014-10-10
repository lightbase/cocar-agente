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


class SnmpSession(object):
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

        self.status = ['1.3.6.1.2.1.25.3.5.1.1.1']
        self.serial = ['1.3.6.1.2.1.43.5.1.1.17']
        self.model = ['1.3.6.1.2.1.25.3.2.1.3.1']
        self.counter = ['1.3.6.1.2.1.43.10.2.1.4.1.1']
        self.messages = ['1.3.6.1.2.1.43.18.1.1.8']

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

    def printer_full(self):
        """
        Retorna status full da impressora, com todos os atributos
        """
        status = self.query()
        if status is None:
            return None
        else:
            return status.query

    def printer_status(self):
        """
        Retorna status da impressora

        Opções de status:

         1 - unknown
         2 - runnning
         3 - warning
         4 - testing
         5 - down
        """
        status = None
        for elm in self.status:
            self.oid = elm
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status is not None:
                break
        if status is None:
            return None
        else:
            return status.query

    def printer_counter(self):
        """
        Retorna contador da impressora
        """
        status = None
        for elm in self.counter:
            self.oid = elm
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status is not None:
                break

        if status is None:
            return None
        else:
            return status.query

    def printer_model(self):
        """
        Retorna contador da impressora
        """
        status = None
        for elm in self.model:
            self.oid = elm
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status is not None:
                break

        if status is None:
            return None
        else:
            return status.query

    def printer_serial(self):
        """
        Retorna contador da impressora
        """
        status = None
        for elm in self.serial:
            self.oid = elm
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status is not None:
                break

        if status is None:
            return None
        else:
            return status.query

    def printer_dict(self):
        """
        Retorna o status de todos os atributos em um dicionário
        """
        full = self.printer_full()
        serial = self.printer_serial()
        model = self.printer_model()
        counter = self.printer_counter()
        status = self.printer_status()

        return_dict = {
            'description': full[0],
            'serial': serial[0],
            'model': model[0],
            'counter': counter[0],
            'status': status[0],
            'network_ip': self.DestHost
        }

        log.debug(return_dict)

        return return_dict


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
                                          "-PS21,22,23,25,80,443,631,3306,3389,8080,9100",
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