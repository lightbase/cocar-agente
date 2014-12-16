#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
from netaddr import IPAddress
from sqlalchemy.schema import Column, ForeignKeyConstraint, ForeignKey
from sqlalchemy.types import String, Integer
from . import Base
from .network import Network


class Host(Base):
    """
    Classe que define um ativo de rede
    """
    __tablename__ = 'host'
    network_ip = Column(String(16), primary_key=True, nullable=False)
    mac_address = Column(String(18))
    name = Column(String)
    inclusion_date = Column(String(20))
    scantime = Column(Integer)
    ports = Column(String)
    ip_network = Column(String(16), ForeignKey('network.ip_network'), nullable=True)

    def __init__(self,
                 ip_address,
                 mac_address=None,
                 hostname=None,
                 inclusion_date=None,
                 scantime=None,
                 open_ports=None,
                 ip_network=None):
        """
        Método construtor do ativo de rede

        :param ip_address: Endereço Ip
        :param mac_address: MAC
        :param network: Endereço da rede onde o ativo foi encontrado
        :param hostname: Nome do host
        :param inclusion_date: Data de coleta
        :param scantime: Tempo levado na execução
        :param open_ports: Portas abertas
        :param ip_network: Rede cadastrada
        :return:
        """
        self.ip_address = IPAddress(ip_address)
        self.mac_address = mac_address
        self.hostname = hostname
        self.inclusion_date = inclusion_date
        self.scantime = scantime
        self.open_ports = open_ports
        self.ip_network = ip_network

        # Parâmetros do SQLAlchemy
        self.network_ip = str(self.ip_address)
        if self.open_ports is not None:
            self.ports = ','.join(map(str, self.open_ports.keys()))
        else:
            self.ports = None
        if self.hostname is not None:
            if len(self.hostname.values()) > 0:
                self.name = self.hostname.values()[0]
            else:
                self.name = None
        else:
            self.name = None

    def __repr__(self):
        """
        Metodo que passa a lista de parametros da classe
        """
        return "<Host('%s, %s, %s, %s, %s, %s, %s')>" % (
            self.network_ip,
            self.mac_address,
            self.name,
            self.inclusion_date,
            self.scantime,
            self.ports,
            self.ip_network
        )