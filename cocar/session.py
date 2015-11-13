#!/bin/env python
# -*- coding: utf-8 -*-
# Inspired by the code in http://www.copyandwaste.com/posts/view/multiprocessing-snmp-with-python/
__author__ = 'eduardo'
import netsnmp
import subprocess
import logging
import re

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
                 Timeout=1000000
                 ):
        """
        Sessão SNMP. Links úteis:
        Lista de MIB's para impressoras: http://www.lprng.com/DISTRIB/SNMPTOOLS/snmp_stuff/test_printer/npstatlib.pm
        Identificação de swicthes e roteadores: http://www.codeproject.com/Questions/642173/OIDs-for-Router-and-SWITCH-identification-using-SN

        :param oid: MIB SNMP
        :param iid: Não sei
        :param Version: Versão do protocolo
        :param DestHost: Endereço para consulta
        :param Community: Community para consulta
        :param Verbose: Verbose
        """
        self.oid = oid
        self.Version = Version
        self.DestHost = DestHost
        self.Community = Community
        self.Verbose = Verbose
        self.Timeout = Timeout
        self.var = netsnmp.Varbind(oid, iid)
        self.var_list = list()
        self.hostrec = Host()
        self.hostrec.hostname = self.DestHost

        self.status = ['.1.3.6.1.2.1.25.3.5.1.1.1']
        self.serial = ['.1.3.6.1.2.1.43.5.1.1.17',
                       '.1.3.6.1.2.1.43.5.1.1.17.1',
                       '.1.3.6.1.4.1.641.2.1.2.1.6.1',
                       '.1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0']
        self.model = ['.1.3.6.1.2.1.25.3.2.1.3.1',
                      '.1.3.6.1.4.1.641.2.1.2.1.2.1']
        self.counter = ['.1.3.6.1.2.1.43.10.2.1.4.1.1']
        self.messages = ['.1.3.6.1.2.1.43.18.1.1.8']

    def query(self):
        """Creates SNMP query

        Fills out a Host Object and returns result
        """
        try:
            result = netsnmp.snmpget(
                self.var,
                Version=self.Version,
                DestHost=self.DestHost,
                Community=self.Community,
                Timeout=int(self.Timeout)
            )
            self.hostrec.query = result
        except Exception as err:
            if self.Verbose:
                log.error("SNMP - Erro na execução do snnmpget")
                log.error(err)
                print err
            self.hostrec.query = None
        finally:
            return self.hostrec

    def getbulk(self):
        """
        Utiliza o método get do SNMP para múltiplas variáveis
        """
        try:
            result = netsnmp.snmpget(
                *self.var_list,
                Version=self.Version,
                DestHost=self.DestHost,
                Community=self.Community,
                Timeout=int(self.Timeout)
            )
            self.hostrec.query = result
        except Exception as err:
            if self.Verbose:
                log.error("SNMP - Erro na execução do snnmpget")
                log.error(err)
                print err
            self.hostrec.query = None
        finally:
            return self.hostrec

    def printer_full(self):
        """
        Retorna status full da impressora, com todos os atributos
        """
        status = self.query()

        if status.query is not None:
            for response in status.query:
                if response is not None:
                    return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

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
        for elm in self.status:
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

    def printer_counter(self):
        """
        Retorna contador da impressora
        """
        for elm in self.counter:
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

    def printer_model(self):
        """
        Retorna contador da impressora
        """
        for elm in self.model:
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

    def printer_serial(self):
        """
        Retorna contador da impressora
        """
        for elm in self.serial:
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

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
            'description': full,
            'serial': serial,
            'model': model,
            'counter': counter,
            'status': status,
            'network_ip': self.DestHost
        }

        log.debug("COLETA DE IMPRESSORAS CONCLUÍDA!!! Retornando dicionário de informações")
        log.debug(return_dict)

        return return_dict

    def get_snmp_attribute(self, attribute):
        """
        Runs SNMP query and return first response

        :param attribute: Attribute to SNMP search
        :return: String returned or None
        """
        # Faz a busca SNMP pelo objeto
        search = getattr(self, attribute)
        if search is None:
            log.error("SNMP Session - Attribute %s not defined", attribute)
            return None

        for elm in search:
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None


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
        log.debug("NMAP: Scanning host %s", self.host)
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


class ArpSession(object):
    """
    Classe para buscar informações de MAC do ativo
    """
    def __init__(self,
                 host,
                 iface='eth0',
                 timeout='10'):
        """
        :param host: Endereço IP do host a ser escaneado
        :param mac: MAC address do host
        :param timeout: Timeout esperando pelo reply da interface
        """
        self.host = host
        self.iface = iface
        self.timeout = timeout

    def scan(self):
        """
        :return: Somente MAc
        """
        log.debug("Iniciando scan para o host %s", self.host)
        try:
            scanv = subprocess.Popen(["sudo",
                                      "arping",
                                      "-I",
                                      self.iface,
                                      "-c",
                                      '1',
                                      "-w",
                                      str(self.timeout),
                                      self.host],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE).communicate()[0]

            match = re.search("(\[)(.*)(\])", scanv)

            if match:
                return match.group(2)
            else:
                return None

        except OSError:
            log.error("Install arping: sudo apt-get install arping")
            return None

    def scan_list(self):
        """

        :return: List com host e MAC
        """
        log.debug("Iniciando scan para o host %s", self.host)
        try:
            scanv = subprocess.Popen(["sudo",
                                      "arping",
                                      "-I",
                                      self.iface,
                                      "-c",
                                      '1',
                                      "-w",
                                      self.timeout,
                                      self.host],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE).communicate()[0]

            match = re.search("(\[)(.*)(\])", scanv)

            if match:
                return [self.host, match.group(2)]

            return [self.host, match]
        except OSError:
            log.error("Install arping: sudo apt-get install arping")
            return None
