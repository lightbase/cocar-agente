#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
from netaddr import IPAddress


class Host(object):
    """
    Classe que define um ativo de rede
    """
    def __init__(self,
                 ip_address,
                 mac_address=None,
                 hostname=None,
                 inclusion_date=None,
                 scantime=None,
                 open_ports=None):
        """
        Método construtor do ativo de rede

        :param ip_address: Endereço Ip
        :param mac_address: MAC
        :param network: Endereço da rede onde o ativo foi encontrado
        :param hostname: Nome do host
        :param inclusion_date: Data de coleta
        :param scantime: Tempo levado na execução
        :param open_ports: Portas abertas
        :return:
        """
        self.ip_address = IPAddress(ip_address)
        self.mac_address = mac_address
        self.hostname = hostname
        self.inclusion_date = inclusion_date
        self.scantime = scantime
        self.open_ports = open_ports