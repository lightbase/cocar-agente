#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
from netaddr import IPAddress
from sqlalchemy.schema import Column, ForeignKeyConstraint, ForeignKey
from sqlalchemy.types import String, Integer, UnicodeText, Boolean
from .host import Host

log = logging.getLogger()


class NetworkDevice(Host):
    """
    Dispositivo de rede genérico
    """
    __tablename__ = 'network_device'
    network_ip = Column(String(16), ForeignKey("host.network_ip"), nullable=False, primary_key=True)
    service = Column(UnicodeText)
    community = Column(UnicodeText)

    def __init__(self,
                 service=None,
                 community=None,
                 *args,
                 **kwargs):
        """
        :param service: Tipo de serviço fornecido de acordo com a seguinte tabela:
                {
                    1: "repeater",
                    2: "bridge",
                    4: "router",
                    6: "switch",
                    8: "gateway",
                    16: "session",
                    32: "terminal",
                    64: "application"
                }
        :param community: Community do SNMP para buscar
        :param args:
        :param kwargs:
        :return:
        """
        Host.__init__(self,  *args, **kwargs)
        self.service = service
        self.community = community
