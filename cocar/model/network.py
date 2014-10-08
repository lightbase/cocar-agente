#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import os.path
from .. import Cocar
from netaddr import IPNetwork, IPSet


class Network(Cocar):
    """
    Rede onde a busca será realizada
    """
    def __init__(self,
                 network_ip,
                 netmask=None,
                 prefixlen=None,
                 name=None
                 ):
        """
        :param network_ip: Ip da rede
        :param netmask: Máscara da rede
        :param cidr: CIDR para calcular a máscara da rede
        :param name: Nome da rede
        """
        Cocar.__init__(self)
        self.network_ip = IPNetwork(network_ip)
        self.netmask = netmask
        self.prefixlen = prefixlen
        self.name = name
        self.network_dir = self.cocar_data_dir + "/" + str(self.network_ip.ip)
        # Cria diretório se não existir
        if not os.path.isdir(self.network_dir):
            os.mkdir(self.network_dir)

        if self.netmask is None:
            self.netmask = self.network_ip.netmask
        if self.prefixlen is None:
            self.prefixlen = self.network_ip.prefixlen

    def ip_list(self):
        """
        Método que encontra a lista de IP's da subrede
        :return: Conjunto de IP's para realizar a interação
        """
        return IPSet(self.network_ip)