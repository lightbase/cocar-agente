#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
from iptools.ipv4 import netmask2prefix
from netaddr import IPNetwork, IPSet
from ..model import Base
from sqlalchemy.schema import Column
from sqlalchemy.types import String, Integer


class Network(Base):
    """
    Rede onde a busca será realizada
    """
    __tablename__ = 'network'
    ip_network = Column(String(16), nullable=False, primary_key=True)
    network_file = Column(String)
    netmask = Column(String(16))
    prefixlen = Column(Integer)
    name = Column(String)

    def __init__(self,
                 network_ip,
                 network_file=None,
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
        self.network_ip = network_ip
        self.netmask = netmask
        self.prefixlen = prefixlen
        self.name = name
        self.network_file = network_file
        if self.netmask is None:
            self.netmask = self.network_ip.netmask
        if self.prefixlen is None:
            self.prefixlen = self.network_ip.prefixlen

        # SQLAlchemy attribute
        self.ip_network = str(self.network_ip.ip)

    @property
    def network_ip(self):
        return self._network_ip

    @network_ip.setter
    def network_ip(self, value):
        self._network_ip = IPNetwork(value)
        if self._network_ip.prefixlen == 32:
            if self.netmask is not None:
                prefixlen = netmask2prefix(self.netmask)
                self._network_ip = IPNetwork(str(self._network_ip.ip) + "/" + str(prefixlen))
                self.prefixlen = prefixlen

    def ip_list(self):
        """
        Método que encontra a lista de IP's da subrede
        :return: Conjunto de IP's para realizar a interação
        """
        return IPSet(self.network_ip)